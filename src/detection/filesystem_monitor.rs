//! Filesystem monitoring module for detecting suspicious file activities

use anyhow::Result;
use chrono::Utc;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::{DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel, FilesystemMonitorConfig};

#[derive(Clone)]
pub struct FilesystemMonitor {
    pub config: FilesystemMonitorConfig,
}

impl FilesystemMonitor {
    pub fn new(config: FilesystemMonitorConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // Scan watch directories for existing suspicious files
        for dir_path in &self.config.watch_directories {
            let path = Path::new(dir_path);
            if path.exists() && path.is_dir() {
                events.extend(self.scan_directory(path).await?);
            }
        }

        Ok(events)
    }

    #[allow(dead_code)]
    pub async fn start_watching(&self) -> Result<mpsc::Receiver<DetectionEvent>> {
        let (tx, rx) = mpsc::channel(1000);
        let config = self.config.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::watch_filesystem(config, tx).await {
                error!("Filesystem watcher failed: {}", e);
            }
        });

        Ok(rx)
    }


    #[allow(dead_code)]
    async fn watch_filesystem(
        config: FilesystemMonitorConfig,
        tx: mpsc::Sender<DetectionEvent>,
    ) -> Result<()> {
        let (notify_tx, mut notify_rx) = mpsc::channel(1000);

        // Create filesystem watcher
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
                watcher.watch(path, RecursiveMode::Recursive)?;
                debug!("Watching directory: {}", dir_path);
            }
        }

        // Process filesystem events
        while let Some(event) = notify_rx.recv().await {
            if let Some(detection_event) = Self::analyze_filesystem_event(&config, event).await {
                let _ = tx.send(detection_event).await;
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn analyze_filesystem_event(
        config: &FilesystemMonitorConfig,
        event: Event,
    ) -> Option<DetectionEvent> {
        match event.kind {
            EventKind::Create(_) | EventKind::Modify(_) => {
                for path in &event.paths {
                    if let Some(detection) = Self::check_suspicious_file(config, path, "modified").await {
                        return Some(detection);
                    }
                }
            }
            _ => {}
        }

        None
    }

    async fn scan_directory(&self, dir_path: &Path) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        let entries = match tokio::fs::read_dir(dir_path).await {
            Ok(entries) => entries,
            Err(_) => return Ok(events),
        };

        let mut dir_entries = entries;
        while let Ok(Some(entry)) = dir_entries.next_entry().await {
            let path = entry.path();

            if path.is_file() {
                if let Some(event) = Self::check_suspicious_file(&self.config, &path, "existing").await {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    async fn check_suspicious_file(
        config: &FilesystemMonitorConfig,
        path: &Path,
        operation: &str,
    ) -> Option<DetectionEvent> {
        let file_name = path.file_name()?.to_str()?;
        let file_name_lower = file_name.to_lowercase();

        let mut suspicious_content = Vec::new();

        // Check suspicious extensions
        for ext in &config.suspicious_extensions {
            if file_name_lower.ends_with(ext) {
                suspicious_content.push(format!("Suspicious extension: {}", ext));
            }
        }

        // Check suspicious filenames
        for suspicious_name in &config.suspicious_filenames {
            if file_name_lower.contains(&suspicious_name.to_lowercase()) {
                suspicious_content.push(format!("Suspicious filename pattern: {}", suspicious_name));
            }
        }

        // Check for AI-related keywords in filename
        let ai_keywords = [
            "chatgpt", "claude", "gemini", "openai", "anthropic", "copilot",
            "ai-response", "llm-output", "gpt-", "ai-assistant"
        ];

        for keyword in &ai_keywords {
            if file_name_lower.contains(keyword) {
                suspicious_content.push(format!("AI-related keyword in filename: {}", keyword));
            }
        }

        if suspicious_content.is_empty() {
            return None;
        }

        let file_size = tokio::fs::metadata(path).await.ok()?.len();
        let threat_level = Self::calculate_file_threat_level(&suspicious_content, file_size);

        Some(DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Filesystem Activity".to_string(),
            module: DetectionModule::FilesystemMonitor,
            threat_level,
            description: format!("Suspicious file {}: {}", operation, file_name),
            details: DetectionDetails::Filesystem {
                file_path: path.to_string_lossy().to_string(),
                operation: operation.to_string(),
                file_size,
                file_hash: None, // Could be implemented with file content hashing
                suspicious_content,
            },
            timestamp: Utc::now(),
            source: Some("Filesystem Monitor".to_string()),
            metadata: HashMap::new(),
        })
    }

    fn calculate_file_threat_level(suspicious_content: &[String], file_size: u64) -> ThreatLevel {
        let content_count = suspicious_content.len();
        let has_ai_keyword = suspicious_content
            .iter()
            .any(|content| content.to_lowercase().contains("ai-related keyword"));
        let has_suspicious_extension = suspicious_content
            .iter()
            .any(|content| content.contains("Suspicious extension"));
        let is_large_file = file_size > 1024 * 1024; // > 1MB

        match (content_count, has_ai_keyword, has_suspicious_extension, is_large_file) {
            (_, true, true, true) => ThreatLevel::Critical,
            (_, true, true, false) => ThreatLevel::High,
            (_, true, false, _) => ThreatLevel::Medium,
            (_, false, true, true) => ThreatLevel::Medium,
            (3.., false, _, _) => ThreatLevel::Medium,
            (1..=2, false, _, _) => ThreatLevel::Low,
            _ => ThreatLevel::Info,
        }
    }
}
