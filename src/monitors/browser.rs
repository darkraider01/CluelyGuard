use std::fs;
use std::path::{Path, PathBuf};
use serde_json::Value;
use glob::glob;
use tracing::{info, warn, error};

/// List of suspicious extension keywords (may be refined or loaded from config in the future).
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "chatgpt",
    "copilot",
    "claude",
    "bard",
    "openai",
    "gpt",
    "anthropic",
    "llm",
];

/// List of browser history database paths (expand to support more browsers).
const BROWSER_HISTORY_PATHS: &[&str] = &[
    "~/.config/google-chrome/Default/History",
    "~/.config/chromium/Default/History",
    "~/.config/BraveSoftware/Brave-Browser/Default/History",
    "~/.mozilla/firefox/*.default-release/places.sqlite",
];

/// Extension directories to scan.
const EXTENSION_PATHS: &[&str] = &[
    "~/.config/google-chrome/Default/Extensions",
    "~/.config/chromium/Default/Extensions",
    "~/.mozilla/firefox/*.default-release/extensions",
    "~/.mozilla/firefox/*.default/extensions",
    // Brave locations:
    "~/.config/BraveSoftware/Brave-Browser/Default/Extensions",
    "~/.config/brave/Extensions",
    "~/.local/share/brave/Brave-Browser/Default/Extensions",
    // Snap/Flatpak:
    "~/snap/brave/current/.config/BraveSoftware/Brave-Browser/Default/Extensions",
];

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
    suspicious_keywords: Vec<String>,
}

impl BrowserMonitor {
    pub fn new() -> Self {
        Self {
            suspicious_keywords: SUSPICIOUS_KEYWORDS.iter().map(|&s| s.to_string()).collect(),
        }
    }

    /// Scan all supported browsers for suspicious extensions.
    pub fn scan_all_extensions(&self) -> Vec<SuspiciousExtension> {
        let mut results = Vec::new();
        for ext_path in EXTENSION_PATHS {
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
                                for keyword in &self.suspicious_keywords {
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

    #[test]
    fn test_scan_extensions() {
        let monitor = BrowserMonitor::new();
        let results = monitor.scan_all_extensions();
        for ext in results {
            println!("{:?}", ext);
        }
    }
}
