//! Browser Tab Analysis Module for detecting AI service usage in browser tabs

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, warn};
use serde_json;

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
};

#[derive(Clone)]
pub struct BrowserTabAnalyzer {
    ai_domains: Vec<String>,
    browser_paths: HashMap<String, Vec<std::path::PathBuf>>,
}

impl BrowserTabAnalyzer {
    pub fn new() -> Self {
        let ai_domains = vec![
            "chat.openai.com".to_string(),
            "claude.ai".to_string(),
            "gemini.google.com".to_string(),
            "perplexity.ai".to_string(),
            "poe.com".to_string(),
            "character.ai".to_string(),
            "you.com".to_string(),
            "copilot.microsoft.com".to_string(),
            "bing.com/chat".to_string(),
        ];

        let browser_paths = Self::get_browser_session_paths();

        Self {
            ai_domains,
            browser_paths,
        }
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        debug!("Analyzing browser tabs for AI services...");

        // Check Chrome tabs
        events.extend(self.analyze_chrome_tabs().await?);
        
        // Check Firefox tabs
        events.extend(self.analyze_firefox_tabs().await?);

        // Check other browsers
        events.extend(self.analyze_other_browser_tabs().await?);

        // Check browser history for recent AI visits
        events.extend(self.analyze_browser_history().await?);

        // Check for browser processes with AI URLs
        events.extend(self.analyze_browser_processes().await?);

        debug!("Found {} AI-related browser activities", events.len());
        Ok(events)
    }

    async fn analyze_chrome_tabs(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        if let Some(home) = dirs::home_dir() {
            let session_paths = [
                home.join(".config/google-chrome/Default/Sessions"),
                home.join(".config/google-chrome/Default/Current Session"),
                home.join(".config/google-chrome/Default/Last Session"),
                home.join(".config/chromium/Default/Sessions"),
                home.join(".config/chromium/Default/Current Session"),
            ];

            for path in &session_paths {
                if path.exists() {
                    // Note: Chrome session files are in a binary format
                    // In a production system, you'd use a proper Chrome session parser
                    // For now, we'll analyze the browser's Preferences file which contains recent tabs
                    let prefs_path = path.parent().unwrap().join("Preferences");
                    if prefs_path.exists() {
                        if let Ok(content) = tokio::fs::read_to_string(&prefs_path).await {
                            events.extend(self.analyze_preferences_content(&content, "Google Chrome"));
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    async fn analyze_firefox_tabs(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        if let Some(home) = dirs::home_dir() {
            let firefox_profile_dir = home.join(".mozilla/firefox");
            
            if firefox_profile_dir.exists() {
                // Find Firefox profiles
                if let Ok(entries) = tokio::fs::read_dir(&firefox_profile_dir).await {
                    let mut entries = entries;
                    while let Some(entry) = entries.next_entry().await? {
                        if entry.file_type().await?.is_dir() {
                            let profile_path = entry.path();
                            
                            // Check sessionstore.jsonlz4 (compressed) or recovery.jsonlz4
                            let session_files = [
                                profile_path.join("sessionstore.jsonlz4"),
                                profile_path.join("recovery.jsonlz4"),
                                profile_path.join("sessionstore-backups/recovery.jsonlz4"),
                            ];

                            for session_file in &session_files {
                                if session_file.exists() {
                                    // Firefox session files are LZ4 compressed JSON
                                    // For simplicity, we'll check the places.sqlite instead
                                    let places_db = profile_path.join("places.sqlite");
                                    if places_db.exists() {
                                        events.extend(self.analyze_firefox_places_db(&places_db).await?);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    async fn analyze_other_browser_tabs(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // Brave Browser
        if let Some(home) = dirs::home_dir() {
            let brave_path = home.join(".config/BraveSoftware/Brave-Browser/Default/Preferences");
            if brave_path.exists() {
                if let Ok(content) = tokio::fs::read_to_string(&brave_path).await {
                    events.extend(self.analyze_preferences_content(&content, "Brave Browser"));
                }
            }
        }

        // Opera
        if let Some(home) = dirs::home_dir() {
            let opera_path = home.join(".config/opera/Preferences");
            if opera_path.exists() {
                if let Ok(content) = tokio::fs::read_to_string(&opera_path).await {
                    events.extend(self.analyze_preferences_content(&content, "Opera"));
                }
            }
        }

        // Vivaldi
        if let Some(home) = dirs::home_dir() {
            let vivaldi_path = home.join(".config/vivaldi/Default/Preferences");
            if vivaldi_path.exists() {
                if let Ok(content) = tokio::fs::read_to_string(&vivaldi_path).await {
                    events.extend(self.analyze_preferences_content(&content, "Vivaldi"));
                }
            }
        }

        Ok(events)
    }

    fn analyze_preferences_content(&self, content: &str, browser_name: &str) -> Vec<DetectionEvent> {
        let mut events = Vec::new();

        if let Ok(prefs) = serde_json::from_str::<serde_json::Value>(content) {
            // Check recent tabs/URLs in preferences
            self.search_json_for_ai_urls(&prefs, browser_name, &mut events);
        }

        events
    }

    fn search_json_for_ai_urls(&self, value: &serde_json::Value, browser_name: &str, events: &mut Vec<DetectionEvent>) {
        match value {
            serde_json::Value::String(s) => {
                for domain in &self.ai_domains {
                    if s.contains(domain) {
                        events.push(DetectionEvent {
                            id: uuid::Uuid::new_v4(),
                            detection_type: "Browser Tab Analysis".to_string(),
                            module: DetectionModule::BrowserExtensions,
                            threat_level: ThreatLevel::Critical,
                            description: format!("AI service detected in {} tab: {}", browser_name, domain),
                            details: DetectionDetails::BrowserExtension {
                                browser: browser_name.to_string(),
                                extension_id: "browser_tab".to_string(),
                                extension_name: format!("Active AI Tab: {}", domain),
                                permissions: vec!["web_access".to_string()],
                                risk_factors: vec![format!("Active tab with AI service: {}", domain)],
                            },
                            timestamp: Utc::now(),
                            source: Some("Browser Tab Analyzer".to_string()),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                for (_, val) in obj {
                    self.search_json_for_ai_urls(val, browser_name, events);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.search_json_for_ai_urls(item, browser_name, events);
                }
            }
            _ => {}
        }
    }

    async fn analyze_firefox_places_db(&self, _db_path: &std::path::Path) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // In a real implementation, you would:
        // 1. Open the SQLite database
        // 2. Query recent history and bookmarks
        // 3. Check for AI domains
        
        // For now, we'll create a placeholder event indicating Firefox analysis
        // This would require the rusqlite crate to properly implement
        
        // Simplified simulation - in real implementation you'd query:
        // SELECT url, title, last_visit_date FROM moz_places WHERE url LIKE '%openai.com%'
        
        warn!("Firefox SQLite analysis not fully implemented - would require rusqlite crate");
        
        Ok(events)
    }

    async fn analyze_browser_history(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // Chrome History
        if let Some(home) = dirs::home_dir() {
            let history_paths = [
                home.join(".config/google-chrome/Default/History"),
                home.join(".config/chromium/Default/History"),
                home.join(".config/BraveSoftware/Brave-Browser/Default/History"),
            ];

            for path in &history_paths {
                if path.exists() {
                    // Chrome History is an SQLite database
                    // We can't easily read it while Chrome is running due to locks
                    // but we can note its presence
                    events.push(DetectionEvent {
                        id: uuid::Uuid::new_v4(),
                        detection_type: "Browser History Analysis".to_string(),
                        module: DetectionModule::BrowserExtensions,
                        threat_level: ThreatLevel::Medium,
                        description: "Browser history contains potential AI service visits".to_string(),
                        details: DetectionDetails::BrowserExtension {
                            browser: "Browser History".to_string(),
                            extension_id: "history_analysis".to_string(),
                            extension_name: "History Analysis".to_string(),
                            permissions: vec!["history_read".to_string()],
                            risk_factors: vec!["Browser history may contain AI service visits".to_string()],
                        },
                        timestamp: Utc::now(),
                        source: Some("Browser History Analyzer".to_string()),
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(events)
    }

    async fn analyze_browser_processes(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // Use ps command to find browser processes with AI URLs
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Ok(output) = tokio::process::Command::new("ps")
                .args(&["aux"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if self.is_browser_process_line(line) {
                        for domain in &self.ai_domains {
                            if line.to_lowercase().contains(&domain.to_lowercase()) {
                                events.push(DetectionEvent {
                                    id: uuid::Uuid::new_v4(),
                                    detection_type: "Browser Process Analysis".to_string(),
                                    module: DetectionModule::BrowserExtensions,
                                    threat_level: ThreatLevel::Critical,
                                    description: format!("Browser process accessing AI service: {}", domain),
                                    details: DetectionDetails::BrowserExtension {
                                        browser: "Browser Process".to_string(),
                                        extension_id: "process_analysis".to_string(),
                                        extension_name: format!("AI Service Access: {}", domain),
                                        permissions: vec!["process_access".to_string()],
                                        risk_factors: vec![format!("Browser process actively connected to {}", domain)],
                                    },
                                    timestamp: Utc::now(),
                                    source: Some("Browser Process Analyzer".to_string()),
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Windows process analysis
        #[cfg(target_os = "windows")]
        {
            if let Ok(output) = tokio::process::Command::new("wmic")
                .args(&["process", "get", "name,commandline", "/format:csv"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if self.is_browser_process_line(line) {
                        for domain in &self.ai_domains {
                            if line.to_lowercase().contains(&domain.to_lowercase()) {
                                events.push(DetectionEvent {
                                    id: uuid::Uuid::new_v4(),
                                    detection_type: "Browser Process Analysis".to_string(),
                                    module: DetectionModule::BrowserExtensions,
                                    threat_level: ThreatLevel::Critical,
                                    description: format!("Browser process accessing AI service: {}", domain),
                                    details: DetectionDetails::BrowserExtension {
                                        browser: "Browser Process".to_string(),
                                        extension_id: "process_analysis".to_string(),
                                        extension_name: format!("AI Service Access: {}", domain),
                                        permissions: vec!["process_access".to_string()],
                                        risk_factors: vec![format!("Browser process actively connected to {}", domain)],
                                    },
                                    timestamp: Utc::now(),
                                    source: Some("Browser Process Analyzer".to_string()),
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    fn is_browser_process_line(&self, line: &str) -> bool {
        let browser_names = [
            "chrome", "chromium", "firefox", "brave", "opera", 
            "vivaldi", "edge", "safari", "arc", "yandex"
        ];
        
        let line_lower = line.to_lowercase();
        browser_names.iter().any(|browser| line_lower.contains(browser))
    }

    fn get_browser_session_paths() -> HashMap<String, Vec<std::path::PathBuf>> {
        let mut paths = HashMap::new();
        
        if let Some(home) = dirs::home_dir() {
            // Chrome
            paths.insert("chrome".to_string(), vec![
                home.join(".config/google-chrome/Default"),
                home.join(".config/chromium/Default"),
            ]);

            // Firefox
            paths.insert("firefox".to_string(), vec![
                home.join(".mozilla/firefox"),
            ]);

            // Brave
            paths.insert("brave".to_string(), vec![
                home.join(".config/BraveSoftware/Brave-Browser/Default"),
            ]);

            // Opera
            paths.insert("opera".to_string(), vec![
                home.join(".config/opera"),
            ]);

            // Vivaldi
            paths.insert("vivaldi".to_string(), vec![
                home.join(".config/vivaldi/Default"),
            ]);
        }

        paths
    }
}

impl Default for BrowserTabAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}