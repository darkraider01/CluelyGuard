//! Browser extension detection module

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
    BrowserExtensionConfig, DetectionConfig,
};

#[derive(Clone)]
pub struct BrowserExtensionMonitor {
    pub config: BrowserExtensionConfig,
    #[allow(dead_code)]
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
        debug!("Scanning browser extensions...");

        // Scan Chrome extensions
        if self.config.scan_chrome {
            events.extend(self.scan_browser_extensions("Google Chrome", &self.get_chrome_extension_paths())?);
        }

        // Scan Firefox extensions
        if self.config.scan_firefox {
            events.extend(self.scan_browser_extensions("Mozilla Firefox", &self.get_firefox_extension_paths())?);
        }

        // Scan Edge extensions
        if self.config.scan_edge {
            events.extend(self.scan_browser_extensions("Microsoft Edge", &self.get_edge_extension_paths())?);
        }

        // Scan custom paths
        for path in &self.config.custom_extension_paths {
            events.extend(self.scan_browser_extensions("Custom", &[PathBuf::from(path)])?);
        }

        debug!("Found {} suspicious browser extensions.", events.len());
        Ok(events)
    }

    fn scan_browser_extensions(&self, browser_name: &str, paths: &[PathBuf]) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        for path in paths {
            if !path.exists() {
                debug!("Extension path not found: {:?}", path);
                continue;
            }

            for entry in WalkDir::new(path).min_depth(2).max_depth(2) {
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

    fn analyze_extension_manifest(&self, browser_name: &str, manifest_path: &PathBuf) -> Result<Option<DetectionEvent>> {
        let content = std::fs::read_to_string(manifest_path)?;
        let manifest = match json::parse(&content) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to parse manifest.json {:?}: {}", manifest_path, e);
                return Ok(None);
            }
        };

        let extension_id = manifest_path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("unknown");
        let extension_name = manifest["name"].as_str().unwrap_or("Unknown Extension").to_string();
        let permissions = manifest["permissions"]
            .members()
            .filter_map(|p| p.as_str().map(|s| s.to_string()))
            .collect::<Vec<String>>();

        let mut risk_factors = Vec::new();
        let mut threat_level = ThreatLevel::Info;

        // Check against known AI extensions
        if let Some(known_name) = self.config.known_ai_extensions.get(extension_id) {
            risk_factors.push(format!("Known AI extension: {}", known_name));
            threat_level = ThreatLevel::High;
        }

        // Check for suspicious permissions
        for suspicious_perm in &self.config.suspicious_permissions {
            if permissions.contains(suspicious_perm) {
                risk_factors.push(format!("Suspicious permission: {}", suspicious_perm));
                if threat_level < ThreatLevel::Medium {
                    threat_level = ThreatLevel::Medium;
                }
            }
        }

        if !risk_factors.is_empty() {
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
                source: Some("Browser Extension Monitor".to_string()),
                metadata: HashMap::new(),
            }));
        }

        Ok(None)
    }

    // Helper functions to get default extension paths
    #[cfg(target_os = "windows")]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::data_local_dir() {
            paths.push(app_data.join("Google\\Chrome\\User Data\\Default\\Extensions"));
            // Add paths for other profiles if needed
        }
        paths
    }

    #[cfg(target_os = "macos")]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::home_dir() {
            paths.push(app_data.join("Library/Application Support/Google/Chrome/Default/Extensions"));
        }
        paths
    }

    #[cfg(target_os = "linux")]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("google-chrome/Default/Extensions"));
        }
        paths
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn get_chrome_extension_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::app_data_dir() {
            // Firefox profiles are complex, this is a simplified path
            if let Some(profiles_dir) = app_data.join("Mozilla\\Firefox\\Profiles").read_dir().ok() {
                for entry in profiles_dir.filter_map(|e| e.ok()) {
                    if entry.file_type().map_or(false, |f| f.is_dir()) {
                        paths.push(entry.path().join("extensions"));
                    }
                }
            }
        }
        paths
    }

    #[cfg(target_os = "macos")]
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::home_dir() {
            if let Some(profiles_dir) = app_data.join("Library/Application Support/Firefox/Profiles").read_dir().ok() {
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
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(config_dir) = dirs::config_dir() {
            if let Some(profiles_dir) = config_dir.join("firefox/Profiles").read_dir().ok() {
                for entry in profiles_dir.filter_map(|e| e.ok()) {
                    if entry.file_type().map_or(false, |f| f.is_dir()) {
                        paths.push(entry.path().join("extensions"));
                    }
                }
            }
        }
        paths
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn get_firefox_extension_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    #[cfg(target_os = "windows")]
    fn get_edge_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::data_local_dir() {
            paths.push(app_data.join("Microsoft\\Edge\\User Data\\Default\\Extensions"));
        }
        paths
    }

    #[cfg(target_os = "macos")]
    fn get_edge_extension_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(app_data) = dirs::home_dir() {
            paths.push(app_data.join("Library/Application Support/Microsoft Edge/Default/Extensions"));
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

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn get_edge_extension_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }
}
