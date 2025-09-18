//! Enhanced Browser extension detection with comprehensive browser support

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use tracing::{debug, warn};
use walkdir::WalkDir;
use serde_json;

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
    BrowserExtensionConfig, DetectionConfig,
};

#[derive(Clone)]
pub struct BrowserExtensionMonitor {
    config: BrowserExtensionConfig,
    detection_config: DetectionConfig,
}

impl BrowserExtensionMonitor {
    pub fn new(config: BrowserExtensionConfig, detection_config: DetectionConfig) -> Result<Self> {
        Ok(Self {
            config,
            detection_config,
        })
    }

    pub fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        debug!("Scanning browser extensions comprehensively...");

        // Scan all supported browsers
        let browsers = self.get_all_browser_configs();
        
        for (browser_name, paths) in browsers {
            events.extend(self.scan_browser_extensions(&browser_name, &paths)?);
        }

        // Check for browser processes with AI tabs
        events.extend(self.scan_browser_processes()?);

        // Check browser bookmarks for AI services
        events.extend(self.scan_browser_bookmarks()?);

        debug!("Found {} suspicious browser extensions and activities.", events.len());
        Ok(events)
    }

    fn get_all_browser_configs(&self) -> HashMap<String, Vec<PathBuf>> {
        let mut browsers = HashMap::new();
        
        // Chrome family
        if self.config.scan_chrome {
            browsers.insert("Google Chrome".to_string(), self.get_chrome_extension_paths());
        }
        
        // Chromium
        browsers.insert("Chromium".to_string(), self.get_chromium_extension_paths());
        
        // Firefox
        if self.config.scan_firefox {
            browsers.insert("Mozilla Firefox".to_string(), self.get_firefox_extension_paths());
        }
        
        // Microsoft Edge
        if self.config.scan_edge {
            browsers.insert("Microsoft Edge".to_string(), self.get_edge_extension_paths());
        }
        
        // Additional browsers
        browsers.insert("Brave Browser".to_string(), self.get_brave_extension_paths());
        browsers.insert("Opera".to_string(), self.get_opera_extension_paths());
        browsers.insert("Vivaldi".to_string(), self.get_vivaldi_extension_paths());
        browsers.insert("Arc Browser".to_string(), self.get_arc_extension_paths());
        browsers.insert("Yandex Browser".to_string(), self.get_yandex_extension_paths());

        // Custom paths
        if !self.config.custom_extension_paths.is_empty() {
            let custom_paths: Vec<PathBuf> = self.config.custom_extension_paths
                .iter()
                .map(|p| PathBuf::from(p))
                .collect();
            browsers.insert("Custom".to_string(), custom_paths);
        }

        browsers
    }

    fn scan_browser_extensions(&self, browser_name: &str, paths: &[PathBuf]) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        for path in paths {
            if !path.exists() {
                debug!("Extension path not found: {:?}", path);
                continue;
            }

            // Scan extensions directory
            for entry in WalkDir::new(path).min_depth(1).max_depth(3) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("Error walking directory {:?}: {}", path, e);
                        continue;
                    }
                };

                if entry.file_type().is_dir() {
                    let manifest_path = entry.path().join("manifest.json");
                    if manifest_path.exists() {
                        if let Some(event) = self.analyze_extension_manifest(browser_name, &manifest_path)? {
                            events.push(event);
                        }
                    }
                }
            }
        }
        Ok(events)
    }

    fn scan_browser_processes(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Use system process monitoring to detect browsers with AI tabs
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Ok(output) = std::process::Command::new("ps")
                .args(&["aux"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                events.extend(self.analyze_process_output(&output_str));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows process analysis would require different approach
            // Could use wmic or PowerShell
            if let Ok(output) = std::process::Command::new("wmic")
                .args(&["process", "get", "name,commandline", "/format:csv"])
                .output()
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                events.extend(self.analyze_process_output(&output_str));
            }
        }

        Ok(events)
    }

    fn analyze_process_output(&self, output: &str) -> Vec<DetectionEvent> {
        let mut events = Vec::new();
        
        let ai_urls = [
            "chat.openai.com", "claude.ai", "gemini.google.com",
            "perplexity.ai", "poe.com", "character.ai", "you.com",
            "copilot.microsoft.com", "bing.com/chat"
        ];

        for line in output.lines() {
            // Check if browser process has AI URLs in command line
            if line.contains("chrome") || line.contains("firefox") || 
               line.contains("brave") || line.contains("edge") {
                for url in &ai_urls {
                    if line.to_lowercase().contains(&url.to_lowercase()) {
                        events.push(DetectionEvent {
                            id: uuid::Uuid::new_v4(),
                            detection_type: "Browser AI Tab".to_string(),
                            module: DetectionModule::BrowserExtensions,
                            threat_level: ThreatLevel::Critical,
                            description: format!("Browser tab open to AI service: {}", url),
                            details: DetectionDetails::BrowserExtension {
                                browser: "Browser Process".to_string(),
                                extension_id: "browser_tab".to_string(),
                                extension_name: format!("AI Tab: {}", url),
                                permissions: vec!["web_access".to_string()],
                                risk_factors: vec![format!("Active AI service tab: {}", url)],
                            },
                            timestamp: chrono::Utc::now(),
                            source: Some("Browser Process Monitor".to_string()),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        events
    }

    fn scan_browser_bookmarks(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        if let Some(home) = dirs::home_dir() {
            let bookmark_paths = [
                // Chrome bookmarks
                home.join(".config/google-chrome/Default/Bookmarks"),
                home.join(".config/chromium/Default/Bookmarks"),
                
                // Firefox bookmarks
                home.join(".mozilla/firefox/*/places.sqlite"),
                
                // Edge bookmarks (Windows-style path for Linux might not exist)
                home.join(".config/microsoft-edge/Default/Bookmarks"),
            ];

            for path in &bookmark_paths {
                if path.exists() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(bookmarks) = serde_json::from_str::<serde_json::Value>(&content) {
                            events.extend(self.analyze_bookmarks(&bookmarks));
                        }
                    }
                }
            }
        }
        
        Ok(events)
    }

    fn analyze_bookmarks(&self, bookmarks: &serde_json::Value) -> Vec<DetectionEvent> {
        let mut events = Vec::new();
        
        let ai_domains = [
            "openai.com", "claude.ai", "gemini.google.com",
            "perplexity.ai", "character.ai", "poe.com"
        ];

        fn search_bookmarks(value: &serde_json::Value, ai_domains: &[&str]) -> Vec<String> {
            let mut found = Vec::new();
            
            match value {
                serde_json::Value::Object(obj) => {
                    if let Some(url) = obj.get("url").and_then(|u| u.as_str()) {
                        for domain in ai_domains {
                            if url.contains(domain) {
                                found.push(url.to_string());
                            }
                        }
                    }
                    
                    for (_, val) in obj {
                        found.extend(search_bookmarks(val, ai_domains));
                    }
                },
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        found.extend(search_bookmarks(item, ai_domains));
                    }
                },
                _ => {}
            }
            
            found
        }

        let found_urls = search_bookmarks(bookmarks, &ai_domains);
        
        for url in found_urls {
            events.push(DetectionEvent {
                id: uuid::Uuid::new_v4(),
                detection_type: "Browser Bookmark".to_string(),
                module: DetectionModule::BrowserExtensions,
                threat_level: ThreatLevel::Medium,
                description: format!("AI service bookmarked: {}", url),
                details: DetectionDetails::BrowserExtension {
                    browser: "Browser Bookmarks".to_string(),
                    extension_id: "bookmark".to_string(),
                    extension_name: format!("Bookmark: {}", url),
                    permissions: vec!["bookmark_access".to_string()],
                    risk_factors: vec![format!("Bookmarked AI service: {}", url)],
                },
                timestamp: chrono::Utc::now(),
                source: Some("Browser Bookmark Scanner".to_string()),
                metadata: HashMap::new(),
            });
        }
        
        events
    }

    fn analyze_extension_manifest(&self, browser_name: &str, manifest_path: &PathBuf) -> Result<Option<DetectionEvent>> {
        let content = std::fs::read_to_string(manifest_path)?;
        let manifest = match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse manifest.json {:?}: {}", manifest_path, e);
                return Ok(None);
            }
        };

        let extension_id = manifest_path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
            
        let extension_name = manifest["name"].as_str()
            .unwrap_or("Unknown Extension").to_string();
            
        let permissions: Vec<String> = manifest["permissions"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|p| p.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        let mut risk_factors = Vec::new();
        let mut threat_level = ThreatLevel::Info;

        // Check against comprehensive AI extensions database
        if let Some(known_name) = self.get_comprehensive_ai_extensions().get(extension_id) {
            risk_factors.push(format!("Known AI extension: {}", known_name));
            threat_level = ThreatLevel::Critical;
        }

        // Check extension name for AI keywords
        let ai_keywords = ["gpt", "ai", "assistant", "chat", "claude", "gemini", "copilot", "bot"];
        for keyword in &ai_keywords {
            if extension_name.to_lowercase().contains(keyword) {
                risk_factors.push(format!("AI-related name: contains '{}'", keyword));
                if threat_level < ThreatLevel::High {
                    threat_level = ThreatLevel::High;
                }
            }
        }

        // Check for suspicious permissions
        let high_risk_permissions = [
            "webRequest", "webRequestBlocking", "tabs", "activeTab",
            "clipboardRead", "clipboardWrite", "nativeMessaging",
            "<all_urls>", "storage", "cookies", "history"
        ];

        for perm_str in permissions.iter().map(|p| p.as_str()) {
            if high_risk_permissions.contains(&perm_str) {
                risk_factors.push(format!("High-risk permission: {}", perm_str));
                if threat_level < ThreatLevel::Medium {
                    threat_level = ThreatLevel::Medium;
                }
            }
        }

        // Check description for AI keywords
        if let Some(description) = manifest["description"].as_str() {
            for keyword in &ai_keywords {
                if description.to_lowercase().contains(keyword) {
                    risk_factors.push(format!("AI-related description: contains '{}'", keyword));
                    if threat_level < ThreatLevel::Medium {
                        threat_level = ThreatLevel::Medium;
                    }
                }
            }
        }

        if !risk_factors.is_empty() || threat_level > ThreatLevel::Info {
            return Ok(Some(DetectionEvent {
                id: uuid::Uuid::new_v4(),
                detection_type: "Browser Extension".to_string(),
                module: DetectionModule::BrowserExtensions,
                threat_level,
                description: format!("Suspicious browser extension detected: {}", extension_name),
                details: DetectionDetails::BrowserExtension {
                    browser: browser_name.to_string(),
                    extension_id: extension_id.to_string(),
                    extension_name,
                    permissions,
                    risk_factors,
                },
                timestamp: chrono::Utc::now(),
                source: Some("Enhanced Browser Extension Monitor".to_string()),
                metadata: HashMap::new(),
            }));
        }

        Ok(None)
    }

    fn get_comprehensive_ai_extensions(&self) -> HashMap<String, String> {
        let mut extensions = self.config.known_ai_extensions.clone();
        
        // Add comprehensive database of AI extensions
        extensions.extend([
            // ChatGPT Extensions (updated IDs)
            ("jflljfpjoagamelhabdhgcohbeaihani".to_string(), "ChatGPT Official".to_string()),
            ("lkgkgndbjcpbnlgidjlhajmgiiodkmdn".to_string(), "WebChatGPT".to_string()),
            ("laookmmifdnliomafblkmiokodbkjbdh".to_string(), "ChatGPT Everywhere".to_string()),
            
            // AI Writing Assistants
            ("kbfnbcaeplbcioakkpcpgfkobkghlhen".to_string(), "Grammarly".to_string()),
            ("ckimpdiaenoiklmhgnbhndehokhjneok".to_string(), "QuillBot".to_string()),
            
            // AI Research Tools
            ("bdfhijgajdopdkidcdejkfncihffeaoi".to_string(), "Elicit".to_string()),
            
            // Code Assistants
            ("fmaigbhjalfhcfjjbjlhohmpekohmjoh".to_string(), "GitHub Copilot".to_string()),
            ("nbahnhbkefhpmgoofjmbeaghjeknmefm".to_string(), "Tabnine".to_string()),
            
            // Other AI Services
            ("ahhgbkdpidddbngojecgnfemoadjmell".to_string(), "Poe AI Chat".to_string()),
            ("bggkbaccbbmmfmhjddnmjfnakpcglhcl".to_string(), "Character.AI".to_string()),
        ]);
        
        extensions
    }

    // Browser-specific path functions (Linux focus, but can be adapted)
    #[cfg(target_os = "linux")]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.extend([
                config_dir.join("google-chrome/Default/Extensions"),
                config_dir.join("google-chrome/Profile 1/Extensions"),
                config_dir.join("google-chrome-beta/Default/Extensions"),
                config_dir.join("google-chrome-unstable/Default/Extensions"),
            ]);
        }
        
        if let Some(home) = dirs::home_dir() {
            paths.extend([
                home.join("snap/chromium/common/chromium/Default/Extensions"),
                home.join("snap/chrome/common/chrome/Default/Extensions"),
                home.join(".local/share/google-chrome/Default/Extensions"),
            ]);
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_chromium_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("chromium/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            if let Ok(profiles_dir) = config_dir.join("firefox/Profiles").read_dir() {
                for entry in profiles_dir.filter_map(|e| e.ok()) {
                    if entry.file_type().map_or(false, |f| f.is_dir()) {
                        paths.push(entry.path().join("extensions"));
                    }
                }
            }
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_edge_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("microsoft-edge/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_brave_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("BraveSoftware/Brave-Browser/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_opera_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("opera/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_vivaldi_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("vivaldi/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_arc_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("arc/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_yandex_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("yandex-browser/Default/Extensions"));
        }
        paths
    }

    // Stub implementations for other operating systems
    #[cfg(not(target_os = "linux"))]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_chromium_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_edge_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_brave_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_opera_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_vivaldi_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_arc_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
    #[cfg(not(target_os = "linux"))]
    fn get_yandex_extension_paths(&self) -> Vec<PathBuf> { Vec::new() }
}