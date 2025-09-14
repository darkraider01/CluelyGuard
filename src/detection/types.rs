//! Common types and structures for detection modules

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    pub id: uuid::Uuid,
    pub detection_type: String,
    pub module: DetectionModule,
    pub threat_level: ThreatLevel,
    pub description: String,
    pub details: DetectionDetails,
    pub timestamp: DateTime<Utc>,
    pub source: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionModule {
    BrowserExtensions,
    ProcessMonitor,
    NetworkMonitor,
    ScreenMonitor,
    FilesystemMonitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionDetails {
    BrowserExtension {
        browser: String,
        extension_id: String,
        extension_name: String,
        permissions: Vec<String>,
        risk_factors: Vec<String>,
    },
    Process {
        pid: u32,
        name: String,
        command_line: String,
        executable_path: String,
        parent_pid: Option<u32>,
        matched_patterns: Vec<String>,
    },
    Network {
        local_addr: String,
        remote_addr: String,
        domain: Option<String>,
        port: u16,
        protocol: String,
        matched_domain: String,
    },
    Screen {
        screenshot_hash: String,
        detected_elements: Vec<String>,
        confidence: f32,
        ai_interface_type: String,
    },
    Filesystem {
        file_path: String,
        operation: String,
        file_size: u64,
        file_hash: Option<String>,
        suspicious_content: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub enabled_modules: HashMap<DetectionModule, bool>,
    pub sensitivity_levels: HashMap<DetectionModule, u8>,
    pub scan_intervals: HashMap<DetectionModule, u64>,
    pub browser_extensions: BrowserExtensionConfig,
    pub process_monitor: ProcessMonitorConfig,
    pub network_monitor: NetworkMonitorConfig,
    pub screen_monitor: ScreenMonitorConfig,
    pub filesystem_monitor: FilesystemMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserExtensionConfig {
    pub scan_interval_ms: u64,
    pub scan_chrome: bool,
    pub scan_firefox: bool,
    pub scan_edge: bool,
    pub custom_extension_paths: Vec<String>,
    pub known_ai_extensions: HashMap<String, String>,
    pub suspicious_permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    pub scan_interval_ms: u64,
    pub ai_process_patterns: Vec<String>,
    pub whitelist: Vec<String>,
    pub monitor_command_line: bool,
    pub monitor_child_processes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    pub scan_interval_ms: u64,
    pub ai_domains: Vec<String>,
    pub blocked_ips: Vec<String>,
    pub monitor_dns: bool,
    pub monitor_websockets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenMonitorConfig {
    pub enabled: bool,
    pub capture_interval_ms: u64,
    pub ai_interface_templates: Vec<String>,
    pub ocr_enabled: bool,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemMonitorConfig {
    pub scan_interval_ms: u64,
    pub watch_directories: Vec<String>,
    pub suspicious_extensions: Vec<String>,
    pub suspicious_filenames: Vec<String>,
    pub monitor_downloads: bool,
    pub monitor_temp_files: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        let mut enabled_modules = HashMap::new();
        enabled_modules.insert(DetectionModule::BrowserExtensions, true);
        enabled_modules.insert(DetectionModule::ProcessMonitor, true);
        enabled_modules.insert(DetectionModule::NetworkMonitor, true);
        enabled_modules.insert(DetectionModule::ScreenMonitor, false);
        enabled_modules.insert(DetectionModule::FilesystemMonitor, true);

        let mut sensitivity_levels = HashMap::new();
        sensitivity_levels.insert(DetectionModule::BrowserExtensions, 8);
        sensitivity_levels.insert(DetectionModule::ProcessMonitor, 9);
        sensitivity_levels.insert(DetectionModule::NetworkMonitor, 6);
        sensitivity_levels.insert(DetectionModule::ScreenMonitor, 5);
        sensitivity_levels.insert(DetectionModule::FilesystemMonitor, 7);

        let mut scan_intervals = HashMap::new();
        scan_intervals.insert(DetectionModule::BrowserExtensions, 10000);
        scan_intervals.insert(DetectionModule::ProcessMonitor, 2000);
        scan_intervals.insert(DetectionModule::NetworkMonitor, 5000);
        scan_intervals.insert(DetectionModule::ScreenMonitor, 30000);
        scan_intervals.insert(DetectionModule::FilesystemMonitor, 1000);

        Self {
            enabled_modules,
            sensitivity_levels,
            scan_intervals,
            browser_extensions: BrowserExtensionConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            network_monitor: NetworkMonitorConfig::default(),
            screen_monitor: ScreenMonitorConfig::default(),
            filesystem_monitor: FilesystemMonitorConfig::default(),
        }
    }
}

impl Default for BrowserExtensionConfig {
    fn default() -> Self {
        let mut known_ai_extensions = HashMap::new();

        // ChatGPT Extensions
        known_ai_extensions.insert("lbneaaedflankmgmfbmaplggbmjjmbae".to_string(), "ChatGPT App".to_string());
        known_ai_extensions.insert("bibjgkidgpfbblifamdlkdlhgihmfohh".to_string(), "AI Assistant - ChatGPT and Gemini".to_string());
        known_ai_extensions.insert("bgejafhieobnfpjlpcjjggoboebonfcg".to_string(), "ChatGPT Assistant - Smart Search".to_string());

        // AI Writing Tools
        known_ai_extensions.insert("befflofjcniongenjmbkgkoljhgliihe".to_string(), "TinaMind - GPT-4 AI Assistant".to_string());
        known_ai_extensions.insert("cedgndijpacnfbdggppddacngjfdkaca".to_string(), "Wayin AI".to_string());
        known_ai_extensions.insert("bbdnohkpnbkdkmnkddobeafboooinpla".to_string(), "Search Copilot AI Assistant".to_string());

        // Grammar/Writing Assistants
        known_ai_extensions.insert("kbfnbcaeplbcioakkpcpgfkobkghlhen".to_string(), "Grammarly".to_string());
        known_ai_extensions.insert("hdokiejnpimakedhajhdlcegeplioahd".to_string(), "Honey".to_string());

        Self {
            scan_interval_ms: 10000,
            scan_chrome: true,
            scan_firefox: true,
            scan_edge: true,
            custom_extension_paths: vec![],
            known_ai_extensions,
            suspicious_permissions: vec![
                "webRequest".to_string(),
                "webRequestBlocking".to_string(),
                "tabs".to_string(),
                "activeTab".to_string(),
                "background".to_string(),
                "cookies".to_string(),
                "storage".to_string(),
                "clipboardRead".to_string(),
                "clipboardWrite".to_string(),
            ],
        }
    }
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 2000,
            ai_process_patterns: vec![
                // AI Desktop Applications
                "chatgpt".to_string(),
                "claude".to_string(),
                "gemini".to_string(),
                "copilot".to_string(),

                // Code Assistants
                "github-copilot".to_string(),
                "codewhisperer".to_string(),
                "tabnine".to_string(),

                // Writing Tools
                "grammarly".to_string(),
                "jasper".to_string(),
                "writesonic".to_string(),

                // Browser processes with AI
                "chrome.exe --app=https://chat.openai.com".to_string(),
                "chrome.exe --app=https://claude.ai".to_string(),
                "chrome.exe --app=https://gemini.google.com".to_string(),
            ],
            whitelist: vec![
                "explorer.exe".to_string(),
                "dwm.exe".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
            ],
            monitor_command_line: true,
            monitor_child_processes: true,
        }
    }
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 5000,
            ai_domains: vec![
                "openai.com".to_string(),
                "chat.openai.com".to_string(),
                "api.openai.com".to_string(),
                "claude.ai".to_string(),
                "anthropic.com".to_string(),
                "gemini.google.com".to_string(),
                "ai.google.dev".to_string(),
                "copilot.github.com".to_string(),
                "api.github.com/copilot".to_string(),
                "tabnine.com".to_string(),
                "api.tabnine.com".to_string(),
                "grammarly.com".to_string(),
                "api.grammarly.com".to_string(),
            ],
            blocked_ips: vec![],
            monitor_dns: true,
            monitor_websockets: true,
        }
    }
}

impl Default for ScreenMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capture_interval_ms: 30000,
            ai_interface_templates: vec![
                "chatgpt_interface".to_string(),
                "claude_interface".to_string(),
                "gemini_interface".to_string(),
            ],
            ocr_enabled: true,
            confidence_threshold: 0.7,
        }
    }
}

impl Default for FilesystemMonitorConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 1000,
            watch_directories: vec![
                dirs::download_dir().unwrap_or_default().to_string_lossy().to_string(),
                dirs::document_dir().unwrap_or_default().to_string_lossy().to_string(),
                dirs::desktop_dir().unwrap_or_default().to_string_lossy().to_string(),
            ],
            suspicious_extensions: vec![
                ".ai".to_string(),
                ".gpt".to_string(),
                ".llm".to_string(),
                ".assistant".to_string(),
            ],
            suspicious_filenames: vec![
                "chatgpt".to_string(),
                "claude".to_string(),
                "ai-response".to_string(),
                "llm-output".to_string(),
            ],
            monitor_downloads: true,
            monitor_temp_files: true,
        }
    }
}

impl ThreatLevel {
    pub fn color(&self) -> egui::Color32 {
        match self {
            ThreatLevel::Critical => egui::Color32::from_rgb(220, 53, 69),   // Red
            ThreatLevel::High => egui::Color32::from_rgb(253, 126, 20),     // Orange-red
            ThreatLevel::Medium => egui::Color32::from_rgb(255, 193, 7),    // Yellow
            ThreatLevel::Low => egui::Color32::from_rgb(40, 167, 69),       // Green
            ThreatLevel::Info => egui::Color32::from_rgb(23, 162, 184),     // Cyan
            ThreatLevel::Unknown => egui::Color32::GRAY,                     // Gray
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            ThreatLevel::Critical => "🚨",
            ThreatLevel::High => "⚠️",
            ThreatLevel::Medium => "⚡",
            ThreatLevel::Low => "ℹ️",
            ThreatLevel::Info => "💡",
            ThreatLevel::Unknown => "❓",
        }
    }
}

impl DetectionModule {
    pub fn name(&self) -> &'static str {
        match self {
            DetectionModule::BrowserExtensions => "Browser Extensions",
            DetectionModule::ProcessMonitor => "Process Monitor",
            DetectionModule::NetworkMonitor => "Network Monitor",
            DetectionModule::ScreenMonitor => "Screen Monitor",
            DetectionModule::FilesystemMonitor => "Filesystem Monitor",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            DetectionModule::BrowserExtensions => "🌐",
            DetectionModule::ProcessMonitor => "⚙️",
            DetectionModule::NetworkMonitor => "🌍",
            DetectionModule::ScreenMonitor => "🖥️",
            DetectionModule::FilesystemMonitor => "📁",
        }
    }
}
