use std::fs;
use std::path::{Path, PathBuf};
use serde_json::Value;
use glob::glob;
use tracing::{info, warn, error};
use crate::config::BrowserConfig;

/// Structure to represent a detected suspicious extension.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuspiciousExtension {
    pub browser: String,
    pub name: String,
    pub id: String,
    pub path: PathBuf,
    pub keyword_match: String,
}

/// Main BrowserMonitor struct.
pub struct BrowserMonitor {
    config: BrowserConfig,
}

impl BrowserMonitor {
    pub fn new(config: BrowserConfig) -> Self {
        Self { config }
    }

    /// Scan all supported browsers for suspicious extensions.
    pub fn scan_all_extensions(&self) -> Vec<SuspiciousExtension> {
        let mut results = Vec::new();
        if !self.config.enabled {
            return results;
        }

        for ext_path in &self.config.extension_paths {
            let expanded_path = shellexpand::tilde(ext_path).to_string();
            for entry in glob(&expanded_path.replace("\\", "/"))
                .expect("Failed to read glob pattern")
            {
                if let Ok(path) = entry {
                    match self.scan_extension_dir(&path) {
                        Ok(mut found) => results.append(&mut found),
                        Err(e) => warn!("Failed to scan {}: {}", path.display(), e),
                    }
                }
            }
        }
        results
    }

    /// Scan a specific extension directory for suspicious extensions.
    pub fn scan_extension_dir(&self, dir: &Path) -> Result<Vec<SuspiciousExtension>, String> {
        let mut found = vec![];
        if dir.is_dir() {
            for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
                let entry = entry.map_err(|e| e.to_string())?;
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    // Each extension directory may have subdirs per version.
                    for version_entry in fs::read_dir(&entry_path).map_err(|e| e.to_string())? {
                        let version_entry = version_entry.map_err(|e| e.to_string())?;
                        let version_path = version_entry.path();
                        let manifest = version_path.join("manifest.json");
                        if manifest.is_file() {
                            if let Ok(meta) = Self::parse_manifest(&manifest) {
                                for keyword in &self.config.suspicious_keywords {
                                    if meta.0.to_lowercase().contains(keyword)
                                        || meta.1.to_lowercase().contains(keyword)
                                    {
                                        let browser = if entry_path.to_string_lossy().contains("Brave") || entry_path.to_string_lossy().contains("brave") {
                                            "brave"
                                        } else if entry_path.to_string_lossy().contains("chrome") {
                                            "chrome"
                                        } else if entry_path.to_string_lossy().contains("firefox") {
                                            "firefox"
                                        } else {
                                            "unknown"
                                        };
                                        found.push(SuspiciousExtension {
                                            browser: browser.to_string(),
                                            name: meta.0.clone(),
                                            id: entry_path.file_name().unwrap().to_string_lossy().to_string(),
                                            path: manifest.clone(),
                                            keyword_match: keyword.clone(),
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(found)
    }

    /// Parse the manifest.json of an extension. Return (name, description).
    fn parse_manifest(manifest_path: &Path) -> Result<(String, String), String> {
        let text = fs::read_to_string(manifest_path).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let name = v.get("name").map(|n| n.as_str().unwrap_or("")).unwrap_or("").to_string();
        let desc = v.get("description").map(|d| d.as_str().unwrap_or("")).unwrap_or("").to_string();
        Ok((name, desc))
    }

    // (Optional) Implement browser history analysis for AI domains.
    // See module outline for URL matching and suspicious domain detection.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BrowserConfig;

    fn create_test_browser_config() -> BrowserConfig {
        BrowserConfig {
            enabled: true,
            suspicious_keywords: vec!["test_ai".to_string()],
            extension_paths: vec![
                "~/.config/google-chrome/Default/Extensions".to_string(),
            ],
        }
    }

    #[test]
    fn test_scan_extensions_disabled() {
        let config = BrowserConfig { enabled: false, ..create_test_browser_config() };
        let monitor = BrowserMonitor::new(config);
        let results = monitor.scan_all_extensions();
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_extensions_with_keywords() {
        // This test requires a mock file system or actual extensions to be present
        // For now, it will just test the logic with a dummy config
        let config = create_test_browser_config();
        let monitor = BrowserMonitor::new(config);
        let results = monitor.scan_all_extensions();
        // Assertions would go here if we had a mock file system setup
        println!("Found {} extensions (mocked): {:?}", results.len(), results);
    }
}
