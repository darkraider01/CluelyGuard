//! Complete Filesystem Monitor with Real-Time Detection

use anyhow::Result;
use chrono::Utc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher, event::CreateKind, event::ModifyKind};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use walkdir::WalkDir;

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
    FilesystemMonitorConfig,
};

#[derive(Clone)]
pub struct FilesystemMonitor {
    config: FilesystemMonitorConfig,
    ai_file_signatures: HashSet<String>,
    suspicious_content_patterns: Vec<String>,
}

impl FilesystemMonitor {
    pub fn new(config: FilesystemMonitorConfig) -> Result<Self> {
        let ai_file_signatures = Self::build_ai_file_signatures();
        let suspicious_content_patterns = Self::build_content_patterns();

        Ok(Self {
            config,
            ai_file_signatures,
            suspicious_content_patterns,
        })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        debug!("Starting filesystem scan...");
        
        for watch_dir in &self.config.watch_directories {
            let path = Path::new(watch_dir);
            if !path.exists() {
                warn!("Watch directory does not exist: {}", watch_dir);
                continue;
            }
            
            events.extend(self.scan_directory_recursive(path).await?);
        }
        
        // Scan specific locations for AI-related files
        if self.config.monitor_downloads {
            if let Some(downloads_dir) = dirs::download_dir() {
                events.extend(self.scan_directory_recursive(&downloads_dir).await?);
            }
        }
        
        if self.config.monitor_temp_files {
            events.extend(self.scan_temp_directories().await?);
        }
        
        debug!("Filesystem scan completed, found {} suspicious files", events.len());
        Ok(events)
    }

    pub async fn start_watching(&self) -> Result<mpsc::Receiver<DetectionEvent>> {
        let (tx, rx) = mpsc::channel(1000);
        let config = self.config.clone();
        let ai_signatures = self.ai_file_signatures.clone();
        let content_patterns = self.suspicious_content_patterns.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::watch_filesystem(config, ai_signatures, content_patterns, tx).await {
                error!("Filesystem watcher failed: {}", e);
            }
        });

        Ok(rx)
    }

    async fn scan_directory_recursive(&self, dir_path: &Path) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        for entry in WalkDir::new(dir_path)
            .max_depth(5) // Limit depth to prevent excessive scanning
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(event) = self.analyze_file(entry.path()).await? {
                    events.push(event);
                }
            }
        }
        
        Ok(events)
    }

    async fn scan_temp_directories(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        let temp_dirs = vec![
            std::env::temp_dir(),
            dirs::cache_dir().unwrap_or_default(),
        ];
        
        for temp_dir in temp_dirs {
            if temp_dir.exists() {
                // Only scan recent files in temp directories (last 24 hours)
                events.extend(self.scan_recent_files(&temp_dir, 86400).await?);
            }
        }
        
        Ok(events)
    }

    async fn scan_recent_files(&self, dir: &Path, max_age_seconds: u64) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        let cutoff_time = std::time::SystemTime::now() - std::time::Duration::from_secs(max_age_seconds);
        
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if modified > cutoff_time {
                            if let Some(event) = self.analyze_file(entry.path()).await? {
                                events.push(event);
                            }
                        }
                    }
                }
            }
        }
        
        Ok(events)
    }

    async fn analyze_file(&self, file_path: &Path) -> Result<Option<DetectionEvent>> {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();
        
        let mut suspicious_indicators = Vec::new();
        let mut threat_level = ThreatLevel::Info;

        // Check file extension
        if let Some(extension) = file_path.extension().and_then(|e| e.to_str()) {
            let ext_lower = format!(".{}", extension.to_lowercase());
            if self.config.suspicious_extensions.contains(&ext_lower) {
                suspicious_indicators.push(format!("Suspicious file extension: {}", ext_lower));
                threat_level = std::cmp::max(threat_level, ThreatLevel::Medium);
            }
        }

        // Check filename patterns
        for suspicious_name in &self.config.suspicious_filenames {
            if file_name.contains(&suspicious_name.to_lowercase()) {
                suspicious_indicators.push(format!("Suspicious filename pattern: {}", suspicious_name));
                threat_level = std::cmp::max(threat_level, ThreatLevel::High);
            }
        }

        // Check against AI file signatures
        for signature in &self.ai_file_signatures {
            if file_name.contains(signature) {
                suspicious_indicators.push(format!("AI-related file signature: {}", signature));
                threat_level = std::cmp::max(threat_level, ThreatLevel::High);
            }
        }

        // Analyze file content for text files
        if self.is_text_file(file_path) {
            if let Ok(content_indicators) = self.analyze_file_content(file_path).await {
                if !content_indicators.is_empty() {
                    suspicious_indicators.extend(content_indicators);
                    threat_level = std::cmp::max(threat_level, ThreatLevel::Critical);
                }
            }
        }

        // Check file size for suspicious patterns
        if let Ok(metadata) = tokio::fs::metadata(file_path).await {
            let file_size = metadata.len();
            
            // Very large text files might be AI conversation logs
            if file_size > 1024 * 1024 && self.is_text_file(file_path) { // > 1MB
                suspicious_indicators.push("Large text file (potential AI conversation log)".to_string());
                threat_level = std::cmp::max(threat_level, ThreatLevel::Medium);
            }
        }

        if !suspicious_indicators.is_empty() {
            Ok(Some(self.create_filesystem_event(
                file_path,
                "detected".to_string(),
                suspicious_indicators,
                threat_level,
            )?))
        } else {
            Ok(None)
        }
    }

    async fn analyze_file_content(&self, file_path: &Path) -> Result<Vec<String>> {
        let mut indicators = Vec::new();
        
        // Read first 64KB of file for analysis
        let content = match tokio::fs::read_to_string(file_path).await {
            Ok(content) => {
                if content.len() > 65536 {
                    content.chars().take(65536).collect()
                } else {
                    content
                }
            }
            Err(_) => return Ok(indicators), // Not a text file or can't read
        };

        let content_lower = content.to_lowercase();

        // Check for AI conversation patterns
        let ai_conversation_patterns = [
            "as an ai", "i'm an ai", "i am an artificial intelligence",
            "openai", "chatgpt", "claude", "anthropic", "gemini",
            "i don't have personal opinions", "i can't browse the internet",
            "as a language model", "i'm not able to", "i cannot provide",
            "regenerate response", "stop generating", "continue generating",
            "```python", "```javascript", "```code", "```sql", // Code blocks
            "human:", "assistant:", "user:", "ai:", "bot:",
        ];

        let mut ai_pattern_count = 0;
        for pattern in &ai_conversation_patterns {
            if content_lower.contains(pattern) {
                ai_pattern_count += 1;
                indicators.push(format!("AI conversation pattern: {}", pattern));
            }
        }

        // High density of AI patterns indicates AI-generated content
        if ai_pattern_count >= 3 {
            indicators.push(format!("High density of AI patterns ({})", ai_pattern_count));
        }

        // Check for API keys or tokens
        let api_key_patterns = [
            "sk-", "pk-", "api_key", "openai_api_key", "anthropic_api_key",
            "bearer ", "authorization:", "x-api-key", "client_secret",
        ];

        for pattern in &api_key_patterns {
            if content_lower.contains(pattern) {
                indicators.push(format!("Potential API key/token: {}", pattern));
            }
        }

        // Check for suspicious file paths or URLs
        let suspicious_urls = [
            "chat.openai.com", "claude.ai", "api.openai.com", "api.anthropic.com",
            "copilot.github.com", "api.github.com/copilot", "gemini.google.com",
        ];

        for url in &suspicious_urls {
            if content_lower.contains(url) {
                indicators.push(format!("AI service URL: {}", url));
            }
        }

        Ok(indicators)
    }

    fn is_text_file(&self, file_path: &Path) -> bool {
        if let Some(extension) = file_path.extension().and_then(|e| e.to_str()) {
            let text_extensions = [
                "txt", "md", "log", "json", "xml", "csv", "yaml", "yml",
                "py", "js", "ts", "rs", "go", "cpp", "c", "h", "java",
                "html", "css", "sql", "sh", "bat", "ps1", "conf", "cfg",
            ];
            text_extensions.contains(&extension.to_lowercase().as_str())
        } else {
            false
        }
    }

    fn build_ai_file_signatures() -> HashSet<String> {
        let mut signatures = HashSet::new();
        
        // AI model files
        signatures.insert("ggml".to_string());
        signatures.insert("gguf".to_string());
        signatures.insert("safetensors".to_string());
        signatures.insert("bin".to_string());
        signatures.insert("pth".to_string());
        signatures.insert("ckpt".to_string());
        
        // AI application signatures
        signatures.insert("chatgpt".to_string());
        signatures.insert("claude".to_string());
        signatures.insert("ollama".to_string());
        signatures.insert("gpt4all".to_string());
        signatures.insert("koboldai".to_string());
        signatures.insert("textgen".to_string());
        signatures.insert("oobabooga".to_string());
        
        // AI-related folders/files
        signatures.insert("models".to_string());
        signatures.insert("conversation".to_string());
        signatures.insert("ai_response".to_string());
        signatures.insert("llm_output".to_string());
        signatures.insert("ai_generated".to_string());
        
        signatures
    }

    fn build_content_patterns() -> Vec<String> {
        vec![
            "I am an AI".to_string(),
            "as an artificial intelligence".to_string(),
            "I'm Claude".to_string(),
            "I'm ChatGPT".to_string(),
            "OpenAI's language model".to_string(),
            "Anthropic's AI assistant".to_string(),
        ]
    }

    async fn watch_filesystem(
        config: FilesystemMonitorConfig,
        ai_signatures: HashSet<String>,
        content_patterns: Vec<String>,
        tx: mpsc::Sender<DetectionEvent>,
    ) -> Result<()> {
        let (notify_tx, mut notify_rx) = mpsc::channel(1000);

        let mut watcher = RecommendedWatcher::new(
            move |result: notify::Result<Event>| {
                if let Ok(event) = result {
                    let _ = notify_tx.try_send(event);
                }
            },
            Config::default(),
        )?;

        // Watch configured directories
        for dir_path in &config.watch_directories {
            let path = Path::new(dir_path);
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    warn!("Failed to watch directory {}: {}", dir_path, e);
                } else {
                    info!("Watching directory: {}", dir_path);
                }
            }
        }

        // Process filesystem events
        while let Some(event) = notify_rx.recv().await {
            if let Some(detection_event) = Self::analyze_filesystem_event(&config, &ai_signatures, event).await {
                let _ = tx.send(detection_event).await;
            }
        }

        Ok(())
    }

    async fn analyze_filesystem_event(
        config: &FilesystemMonitorConfig,
        ai_signatures: &HashSet<String>,
        event: Event,
    ) -> Option<DetectionEvent> {
        match event.kind {
            EventKind::Create(CreateKind::File) | EventKind::Modify(ModifyKind::Data(_)) => {
                for path in &event.paths {
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        let file_name_lower = file_name.to_lowercase();
                        
                        // Quick check for AI-related files
                        for signature in ai_signatures {
                            if file_name_lower.contains(signature) {
                                return Some(DetectionEvent {
                                    id: uuid::Uuid::new_v4(),
                                    detection_type: "Real-time File Activity".to_string(),
                                    module: DetectionModule::FilesystemMonitor,
                                    threat_level: ThreatLevel::High,
                                    description: format!("AI-related file activity: {}", file_name),
                                    details: DetectionDetails::Filesystem {
                                        file_path: path.to_string_lossy().to_string(),
                                        operation: format!("{:?}", event.kind),
                                        file_size: 0, // Will be filled later
                                        file_hash: None,
                                        suspicious_content: vec![format!("AI signature: {}", signature)],
                                    },
                                    timestamp: Utc::now(),
                                    source: Some("Real-time Filesystem Monitor".to_string()),
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                        
                        // Check suspicious extensions
                        if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                            let ext_with_dot = format!(".{}", extension.to_lowercase());
                            if config.suspicious_extensions.contains(&ext_with_dot) {
                                return Some(DetectionEvent {
                                    id: uuid::Uuid::new_v4(),
                                    detection_type: "Suspicious File Extension".to_string(),
                                    module: DetectionModule::FilesystemMonitor,
                                    threat_level: ThreatLevel::Medium,
                                    description: format!("Suspicious file created: {}", file_name),
                                    details: DetectionDetails::Filesystem {
                                        file_path: path.to_string_lossy().to_string(),
                                        operation: format!("{:?}", event.kind),
                                        file_size: 0,
                                        file_hash: None,
                                        suspicious_content: vec![format!("Suspicious extension: {}", ext_with_dot)],
                                    },
                                    timestamp: Utc::now(),
                                    source: Some("Real-time Filesystem Monitor".to_string()),
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        
        None
    }

    fn create_filesystem_event(
        &self,
        file_path: &Path,
        operation: String,
        suspicious_content: Vec<String>,
        threat_level: ThreatLevel,
    ) -> Result<DetectionEvent> {
        let file_size = std::fs::metadata(file_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Filesystem Analysis".to_string(),
            module: DetectionModule::FilesystemMonitor,
            threat_level,
            description: format!("Suspicious file detected: {}", 
                file_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
            ),
            details: DetectionDetails::Filesystem {
                file_path: file_path.to_string_lossy().to_string(),
                operation,
                file_size,
                file_hash: None, // Could implement SHA256 hashing if needed
                suspicious_content,
            },
            timestamp: Utc::now(),
            source: Some("Filesystem Monitor".to_string()),
            metadata: HashMap::new(),
        })
    }

    pub fn update_config(&mut self, config: FilesystemMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }
}