use notify::{Watcher, RecommendedWatcher, RecursiveMode, Result as NotifyResult, Event, EventKind};
use std::sync::mpsc::{channel, Receiver};
use std::path::{Path, PathBuf};
use std::collections::{HashSet, HashMap};
use std::time::{SystemTime, Duration};
use std::fs;
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSystemEvent {
    pub path: PathBuf,
    pub event_type: String,
    pub timestamp: SystemTime,
    pub is_suspicious: bool,
    pub reason: String,
    pub file_size: Option<u64>,
    pub file_extension: Option<String>,
}

#[derive(Debug)]
pub struct FileSystemMonitor {
    watcher: Option<RecommendedWatcher>,
    receiver: Option<Receiver<Result<Event, notify::Error>>>,
    suspicious_extensions: HashSet<String>,
    ai_model_paths: Vec<String>,
    monitoring_paths: Vec<String>,
    large_file_threshold: u64,
    recent_events: HashMap<PathBuf, SystemTime>,
}

impl FileSystemMonitor {
    pub fn new() -> Self {
        FileSystemMonitor {
            watcher: None,
            receiver: None,
            suspicious_extensions: Self::init_suspicious_extensions(),
            ai_model_paths: Self::init_ai_model_paths(),
            monitoring_paths: Self::init_monitoring_paths(),
            large_file_threshold: 100 * 1024 * 1024, // 100MB
            recent_events: HashMap::new(),
        }
    }

    fn init_suspicious_extensions() -> HashSet<String> {
        vec![
            ".gguf".to_string(),
            ".bin".to_string(),
            ".pt".to_string(),
            ".pth".to_string(),
            ".safetensors".to_string(),
            ".pkl".to_string(),
            ".h5".to_string(),
            ".onnx".to_string(),
            ".tflite".to_string(),
            ".pb".to_string(),
            ".model".to_string(),
            ".weights".to_string(),
        ].into_iter().collect()
    }

    fn init_ai_model_paths() -> Vec<String> {
        vec![
            "~/.cache/huggingface".to_string(),
            "~/.ollama".to_string(),
            "~/llamacpp".to_string(),
            "~/.cache/torch".to_string(),
            "~/.transformers".to_string(),
            "~/.local/share/oobabooga".to_string(),
            "~/text-generation-webui".to_string(),
            "~/.cache/gpt4all".to_string(),
        ]
    }

    fn init_monitoring_paths() -> Vec<String> {
        vec![
            "/tmp".to_string(),
            "~/Downloads".to_string(),
            "~/Documents".to_string(),
            "~/.local/share".to_string(),
            "~/.cache".to_string(),
            "/var/tmp".to_string(),
        ]
    }

    pub fn start_monitoring(&mut self) -> NotifyResult<()> {
        let (tx, rx) = channel();
        
        let mut watcher = RecommendedWatcher::new(
            tx,
            notify::Config::default(),
        )?;

        // Watch configured directories
        for path_str in &self.monitoring_paths {
            let expanded_path = shellexpand::tilde(path_str);
            let path = Path::new(expanded_path.as_ref());
            
            if path.exists() {
                match watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(_) => info!("Started monitoring: {}", path.display()),
                    Err(e) => warn!("Failed to monitor {}: {}", path.display(), e),
                }
            }
        }

        // Watch AI-specific directories
        for path_str in &self.ai_model_paths {
            let expanded_path = shellexpand::tilde(path_str);
            let path = Path::new(expanded_path.as_ref());
            
            if path.exists() {
                match watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(_) => info!("Started monitoring AI path: {}", path.display()),
                    Err(e) => warn!("Failed to monitor AI path {}: {}", path.display(), e),
                }
            }
        }

        self.watcher = Some(watcher);
        self.receiver = Some(rx);
        Ok(())
    }

    pub fn get_events(&mut self) -> Vec<FileSystemEvent> {
        let mut events = Vec::new();
        
        if let Some(ref receiver) = self.receiver {
            // Process all available events
            let received_results: Vec<Result<Event, notify::Error>> = receiver.try_iter().collect();
            for result in received_results {
                match result {
                    Ok(event) => {
                        if let Some(fs_event) = self.process_event(event) {
                            events.push(fs_event);
                        }
                    }
                    Err(e) => error!("File system watch error: {:?}", e),
                }
            }
        }

        // Clean up old events (older than 1 hour)
        let now = SystemTime::now();
        self.recent_events.retain(|_, &mut timestamp| {
            now.duration_since(timestamp).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(3600)
        });

        events
    }

    fn process_event(&mut self, event: Event) -> Option<FileSystemEvent> {
        let now = SystemTime::now();
        
        for path in &event.paths {
            // Check if we've seen this path recently (debouncing)
            if let Some(&last_seen) = self.recent_events.get(path) {
                if now.duration_since(last_seen).unwrap_or(Duration::from_secs(0)) < Duration::from_millis(500) {
                    continue;
                }
            }
            
            self.recent_events.insert(path.clone(), now);
            
            let file_extension = path.extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| format!(".{}", ext.to_lowercase()));
            
            let file_size = if path.is_file() {
                fs::metadata(path).ok().map(|m| m.len())
            } else {
                None
            };

            let (is_suspicious, reason) = self.analyze_event(&event, path, file_size.as_ref(), file_extension.as_ref());
            
            if is_suspicious {
                return Some(FileSystemEvent {
                    path: path.clone(),
                    event_type: format!("{:?}", event.kind),
                    timestamp: now,
                    is_suspicious,
                    reason,
                    file_size,
                    file_extension,
                });
            }
        }
        
        None
    }

    fn analyze_event(&self, event: &Event, path: &Path, file_size: Option<&u64>, file_extension: Option<&String>) -> (bool, String) {
        // Check for suspicious file extensions
        if let Some(ext) = file_extension {
            if self.suspicious_extensions.contains(ext) {
                return (true, format!("Suspicious AI model file extension: {}", ext));
            }
        }

        // Check for large files
        if let Some(&size) = file_size {
            if size > self.large_file_threshold {
                return (true, format!("Large file created/modified: {} MB", size / (1024 * 1024)));
            }
        }

        // Check for AI-related paths
        let path_str = path.to_string_lossy().to_lowercase();
        let ai_keywords = [
            "huggingface", "ollama", "llama", "gpt", "bert", "transformer",
            "pytorch", "tensorflow", "model", "checkpoint", "weights"
        ];

        for keyword in &ai_keywords {
            if path_str.contains(keyword) {
                return (true, format!("AI-related path keyword detected: {}", keyword));
            }
        }

        // Check for model download patterns
        if let EventKind::Create(_) = event.kind {
            if path_str.contains("download") || path_str.contains("temp") {
                if let Some(ext) = file_extension {
                    if self.suspicious_extensions.contains(ext) {
                        return (true, "AI model file download detected".to_string());
                    }
                }
            }
        }

        // Check for rapid file creation (potential bulk download)
        if let EventKind::Create(_) = event.kind {
            let parent = path.parent().unwrap_or(path);
            let recent_creates = self.recent_events
                .iter()
                .filter(|(p, &timestamp)| {
                    p.parent().unwrap_or(p) == parent &&
                    SystemTime::now().duration_since(timestamp).unwrap_or(Duration::from_secs(0)) < Duration::from_secs(60)
                })
                .count();

            if recent_creates > 10 {
                return (true, "Rapid file creation detected (potential bulk download)".to_string());
            }
        }

        // Check for configuration file modifications
        let filename = path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_lowercase();

        let config_patterns = [
            "config.json", "config.yaml", "config.toml", ".env",
            "requirements.txt", "environment.yml", "docker-compose.yml"
        ];

        for pattern in &config_patterns {
            if filename.contains(pattern) {
                return (true, format!("Configuration file modification: {}", pattern));
            }
        }

        (false, String::new())
    }

    pub fn scan_existing_files(&self) -> Vec<FileSystemEvent> {
        let mut suspicious_files = Vec::new();
        let now = SystemTime::now();

        for path_str in &self.ai_model_paths {
            let expanded_path = shellexpand::tilde(path_str);
            let path = Path::new(expanded_path.as_ref());
            
            if path.exists() {
                self.scan_directory_recursive(path, &mut suspicious_files, now);
            }
        }

        suspicious_files
    }

    fn scan_directory_recursive(&self, dir: &Path, results: &mut Vec<FileSystemEvent>, timestamp: SystemTime) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if path.is_dir() {
                    self.scan_directory_recursive(&path, results, timestamp);
                } else if path.is_file() {
                    if let Ok(metadata) = fs::metadata(&path) {
                        let file_size = Some(metadata.len());
                        let file_extension = path.extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| format!(".{}", ext.to_lowercase()));

                        let fake_event = Event::new(EventKind::Access(notify::event::AccessKind::Close(
                            notify::event::AccessMode::Write
                        )));
                        
                        let (is_suspicious, reason) = self.analyze_event(&fake_event, &path, file_size.as_ref(), file_extension.as_ref());
                        
                        if is_suspicious {
                            results.push(FileSystemEvent {
                                path: path.clone(),
                                event_type: "ExistingFile".to_string(),
                                timestamp,
                                is_suspicious,
                                reason,
                                file_size,
                                file_extension,
                            });
                        }
                    }
                }
            }
        }
    }

    pub fn stop_monitoring(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            drop(watcher);
            info!("File system monitoring stopped");
        }
        self.receiver = None;
    }
}

impl Drop for FileSystemMonitor {
    fn drop(&mut self) {
        self.stop_monitoring();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_suspicious_file_detection() {
        let monitor = FileSystemMonitor::new();
        let temp_dir = TempDir::new().unwrap();
        let suspicious_file = temp_dir.path().join("model.gguf");
        
        File::create(&suspicious_file).unwrap();
        
        let fake_event = Event::new(EventKind::Create(notify::event::CreateKind::File));
        let file_ext = Some(".gguf".to_string());
        
        let (is_suspicious, reason) = monitor.analyze_event(&fake_event, &suspicious_file, None, file_ext.as_ref());
        
        assert!(is_suspicious);
        assert!(reason.contains("Suspicious AI model file extension"));
    }
}
