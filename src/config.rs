//! Enhanced Configuration with comprehensive AI service database

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, warn};
use std::collections::HashMap;

use crate::detection::DetectionConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub app: AppConfig,
    pub detection: Option<DetectionConfig>,
    pub logging: LoggingConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub version: String,
    pub auto_start_monitoring: bool,
    pub save_reports: bool,
    pub report_directory: PathBuf,
    pub enhanced_detection: bool,
    pub real_time_alerts: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_enabled: bool,
    pub file_path: PathBuf,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub detailed_logging: bool,
    pub log_detections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub theme: String,
    pub start_minimized: bool,
    pub show_notifications: bool,
    pub notification_duration: u64,
    pub auto_save_interval: u64,
    pub detailed_reports: bool,
    pub real_time_dashboard: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app: AppConfig::default(),
            detection: Some(DetectionConfig::enhanced_default()),
            logging: LoggingConfig::default(),
            ui: UiConfig::default(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            name: "CluelyGuard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            auto_start_monitoring: true, // Changed to true for better UX
            save_reports: true,
            report_directory: dirs::document_dir()
                .unwrap_or_default()
                .join("CluelyGuard")
                .join("Reports"),
            enhanced_detection: true,
            real_time_alerts: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "debug".to_string(), // More verbose for debugging
            file_enabled: true,
            file_path: dirs::data_local_dir()
                .unwrap_or_default()
                .join("CluelyGuard")
                .join("logs")
                .join("cluely-guard.log"),
            max_file_size_mb: 100,
            max_files: 20,
            detailed_logging: true,
            log_detections: true,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            start_minimized: false,
            show_notifications: true,
            notification_duration: 8000, // Longer notifications for important alerts
            auto_save_interval: 180, // 3 minutes for more frequent saves
            detailed_reports: true,
            real_time_dashboard: true,
        }
    }
}

// Enhanced DetectionConfig with comprehensive defaults
impl DetectionConfig {
    pub fn enhanced_default() -> Self {
        let mut enabled_modules = HashMap::new();
        enabled_modules.insert(crate::detection::types::DetectionModule::BrowserExtensions, true);
        enabled_modules.insert(crate::detection::types::DetectionModule::ProcessMonitor, true);
        enabled_modules.insert(crate::detection::types::DetectionModule::NetworkMonitor, true);
        enabled_modules.insert(crate::detection::types::DetectionModule::ScreenMonitor, false); // Keep disabled by default
        enabled_modules.insert(crate::detection::types::DetectionModule::FilesystemMonitor, true);

        let mut sensitivity_levels = HashMap::new();
        sensitivity_levels.insert(crate::detection::types::DetectionModule::BrowserExtensions, 9); // High sensitivity
        sensitivity_levels.insert(crate::detection::types::DetectionModule::ProcessMonitor, 8);
        sensitivity_levels.insert(crate::detection::types::DetectionModule::NetworkMonitor, 9); // High for network
        sensitivity_levels.insert(crate::detection::types::DetectionModule::ScreenMonitor, 5);
        sensitivity_levels.insert(crate::detection::types::DetectionModule::FilesystemMonitor, 7);

        let mut scan_intervals = HashMap::new();
        scan_intervals.insert(crate::detection::types::DetectionModule::BrowserExtensions, 5000); // More frequent
        scan_intervals.insert(crate::detection::types::DetectionModule::ProcessMonitor, 1000); // Every second
        scan_intervals.insert(crate::detection::types::DetectionModule::NetworkMonitor, 2000); // Every 2 seconds
        scan_intervals.insert(crate::detection::types::DetectionModule::ScreenMonitor, 30000);
        scan_intervals.insert(crate::detection::types::DetectionModule::FilesystemMonitor, 500); // Very frequent

        Self {
            enabled_modules,
            sensitivity_levels,
            scan_intervals,
            browser_extensions: crate::detection::types::BrowserExtensionConfig::enhanced_default(),
            process_monitor: crate::detection::types::ProcessMonitorConfig::enhanced_default(),
            network_monitor: crate::detection::types::NetworkMonitorConfig::enhanced_default(),
            screen_monitor: crate::detection::types::ScreenMonitorConfig::default(),
            filesystem_monitor: crate::detection::types::FilesystemMonitorConfig::enhanced_default(),
        }
    }
}

// Enhanced defaults for detection configs
impl crate::detection::types::BrowserExtensionConfig {
    pub fn enhanced_default() -> Self {
        let mut known_ai_extensions = HashMap::new();

        // Comprehensive AI extension database (2024 updated)
        // ChatGPT Extensions
        known_ai_extensions.insert("jflljfpjoagamelhabdhgcohbeaihani".to_string(), "ChatGPT Official Extension".to_string());
        known_ai_extensions.insert("lkgkgndbjcpbnlgidjlhajmgiiodkmdn".to_string(), "WebChatGPT".to_string());
        known_ai_extensions.insert("laookmmifdnliomafblkmionodbkjbdh".to_string(), "ChatGPT Everywhere".to_string());
        known_ai_extensions.insert("bhkddndhajmdhbiagkmlbpmnpjiohpnl".to_string(), "Monica - AI Assistant".to_string());
        known_ai_extensions.insert("bdjnkklgmfgkiakmdhocmaacdcpmacjc".to_string(), "Sider - AI Assistant".to_string());

        // Claude Extensions
        known_ai_extensions.insert("gmdmgklddhflngehkjmlkmdckgafldcm".to_string(), "Claude AI Assistant".to_string());
        
        // Gemini/Bard Extensions  
        known_ai_extensions.insert("jlnbalebiebejbbckcgglghiabbmfkei".to_string(), "Bard AI Assistant".to_string());
        known_ai_extensions.insert("mkjjflmjbpjkmjgdvhhdommocbbgbeal".to_string(), "Gemini Assistant".to_string());

        // GitHub Copilot
        known_ai_extensions.insert("fmaigbhjalfhcfjjbjlhohmpekohmjoh".to_string(), "GitHub Copilot".to_string());

        // AI Writing Tools
        known_ai_extensions.insert("kbfnbcaeplbcioakkpcpgfkobkghlhen".to_string(), "Grammarly".to_string());
        known_ai_extensions.insert("ckimpdiaenoiklmhgnbhndehokhjneok".to_string(), "QuillBot".to_string());
        known_ai_extensions.insert("oldceeleldhonbafppcapldpdifcinji".to_string(), "LanguageTool".to_string());
        known_ai_extensions.insert("bjnhglijjklgcaodbbkodennfimjigmc".to_string(), "ProWritingAid".to_string());

        // Tabnine
        known_ai_extensions.insert("nbahnhbkefhpmgoofjmbeaghjeknmefm".to_string(), "Tabnine".to_string());

        // Perplexity
        known_ai_extensions.insert("hlgddbmiagihmmlndjdkeaihjjgmidlp".to_string(), "Perplexity Assistant".to_string());

        // Character.AI
        known_ai_extensions.insert("bggkbaccbbmmfmhjddnmjfnakpcglhcl".to_string(), "Character.AI".to_string());

        // Poe
        known_ai_extensions.insert("ahhgbkdpidddbngojecgnfemoadjmell".to_string(), "Poe AI Chat".to_string());

        // Research Tools
        known_ai_extensions.insert("bdfhijgajdopdkidcdejkfncihffeaoi".to_string(), "Elicit".to_string());
        known_ai_extensions.insert("ddipiagkbmgfklkejlmjnbfhfdcglklk".to_string(), "Consensus".to_string());
        known_ai_extensions.insert("blmnadmgliclicjkgohahcjdbmboaklh".to_string(), "Scite".to_string());

        // Otter.ai
        known_ai_extensions.insert("dkbofgfhlgkdpfbbkedfhejklfdnmlak".to_string(), "Otter.ai".to_string());

        // Jasper
        known_ai_extensions.insert("lnllmhmlmfdnmaociljkgbcncpngdjmg".to_string(), "Jasper Assistant".to_string());

        // Copy.ai
        known_ai_extensions.insert("dfplgjfjfjejdnlmnmbpdlnbdnadolhk".to_string(), "Copy.ai".to_string());

        // Notion AI
        known_ai_extensions.insert("ldmmifpegigmeammaeckplhnjbbpccmm".to_string(), "Notion Web Clipper".to_string());

        // Additional AI Tools
        known_ai_extensions.insert("ikmfdlgcobgfolcloamiigdpokiefoil".to_string(), "Wordtune".to_string());
        known_ai_extensions.insert("lfmhcpmkbdkbgbmkjoiopeeegenkdikp".to_string(), "Honey".to_string()); // Has AI features now

        Self {
            scan_interval_ms: 3000, // More frequent scanning
            scan_chrome: true,
            scan_firefox: true,
            scan_edge: true,
            custom_extension_paths: vec![
                // Add common Linux browser paths
                "/home/*/.config/google-chrome/Default/Extensions".to_string(),
                "/home/*/.config/chromium/Default/Extensions".to_string(),
                "/home/*/.config/BraveSoftware/Brave-Browser/Default/Extensions".to_string(),
                "/home/*/.config/opera/Default/Extensions".to_string(),
                "/home/*/.config/vivaldi/Default/Extensions".to_string(),
            ],
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
                "nativeMessaging".to_string(),
                "proxy".to_string(),
                "privacy".to_string(),
                "management".to_string(),
                "debugger".to_string(),
                "<all_urls>".to_string(),
                "*://*/*".to_string(),
                "https://*/*".to_string(),
                "http://*/*".to_string(),
            ],
        }
    }
}

impl crate::detection::types::ProcessMonitorConfig {
    pub fn enhanced_default() -> Self {
        Self {
            scan_interval_ms: 1000, // Every second for real-time detection
            ai_process_patterns: vec![
                // AI Desktop Applications
                "chatgpt".to_string(),
                "chatgpt-desktop".to_string(),
                "claude".to_string(),
                "claude-desktop".to_string(),
                "gemini".to_string(),
                "bard".to_string(),
                "copilot".to_string(),
                "perplexity".to_string(),

                // Code Assistants
                "github-copilot".to_string(),
                "codewhisperer".to_string(),
                "tabnine".to_string(),
                "tabnine-language-server".to_string(),
                "cursor".to_string(),
                "cody".to_string(),

                // Writing Tools
                "grammarly".to_string(),
                "grammarly-desktop".to_string(),
                "jasper".to_string(),
                "writesonic".to_string(),
                "notion".to_string(),
                "quillbot".to_string(),

                // AI Research Tools
                "elicit".to_string(),
                "consensus".to_string(),
                "otter".to_string(),
                "fireflies".to_string(),

                // Browser processes with AI URLs
                "chrome.*chat.openai.com".to_string(),
                "chrome.*claude.ai".to_string(),
                "chrome.*gemini.google.com".to_string(),
                "chrome.*perplexity.ai".to_string(),
                "chrome.*poe.com".to_string(),
                "chrome.*character.ai".to_string(),
                "firefox.*chat.openai.com".to_string(),
                "firefox.*claude.ai".to_string(),

                // AI Development
                "python.*openai".to_string(),
                "python.*anthropic".to_string(),
                "python.*transformers".to_string(),
                "python.*langchain".to_string(),
                "node.*openai".to_string(),
                "jupyter.*".to_string(),

                // General AI patterns
                ".*ai.*assistant".to_string(),
                ".*llm.*".to_string(),
                ".*gpt.*".to_string(),
                ".*claude.*".to_string(),
            ],
            whitelist: vec![
                // System processes
                "systemd".to_string(),
                "kernel".to_string(),
                "kthreadd".to_string(),
                "migration".to_string(),
                "ksoftirqd".to_string(),
                "watchdog".to_string(),
                
                // Desktop environment
                "gnome".to_string(),
                "kde".to_string(),
                "xorg".to_string(),
                "wayland".to_string(),
                "pulseaudio".to_string(),
                "networkmanager".to_string(),
                
                // Development tools (non-AI)
                "cargo".to_string(),
                "rustc".to_string(),
                "gcc".to_string(),
                "make".to_string(),
                
                // Browsers (base processes, not AI-specific)
                "chrome --type=gpu-process".to_string(),
                "chrome --type=renderer".to_string(),
                "firefox --type=tab".to_string(),
            ],
            monitor_command_line: true,
            monitor_child_processes: true,
        }
    }
}

impl crate::detection::types::NetworkMonitorConfig {
    pub fn enhanced_default() -> Self {
        Self {
            scan_interval_ms: 2000, // Every 2 seconds
            ai_domains: vec![
                // OpenAI Services
                "openai.com".to_string(),
                "chat.openai.com".to_string(),
                "api.openai.com".to_string(),
                "platform.openai.com".to_string(),
                "chatgpt.com".to_string(),
                "cdn.openai.com".to_string(),
                "auth0.openai.com".to_string(),
                "openaiapi-site.azureedge.net".to_string(),

                // Anthropic (Claude)
                "claude.ai".to_string(),
                "anthropic.com".to_string(),
                "console.anthropic.com".to_string(),
                "api.anthropic.com".to_string(),
                "cdn.anthropic.com".to_string(),

                // Google AI Services
                "gemini.google.com".to_string(),
                "bard.google.com".to_string(),
                "ai.google.dev".to_string(),
                "makersuite.google.com".to_string(),
                "aistudio.google.com".to_string(),
                "generativelanguage.googleapis.com".to_string(),
                "aiplatform.googleapis.com".to_string(),

                // Microsoft AI
                "copilot.microsoft.com".to_string(),
                "bing.com/chat".to_string(),
                "edgeservices.bing.com".to_string(),
                "sydney.bing.com".to_string(),

                // GitHub Copilot
                "copilot.github.com".to_string(),
                "api.github.com/copilot".to_string(),
                "github.com/copilot".to_string(),

                // Perplexity
                "perplexity.ai".to_string(),
                "www.perplexity.ai".to_string(),
                "api.perplexity.ai".to_string(),

                // Character.AI
                "character.ai".to_string(),
                "beta.character.ai".to_string(),
                "plus.character.ai".to_string(),

                // Poe
                "poe.com".to_string(),
                "www.poe.com".to_string(),

                // Other AI Services
                "you.com".to_string(),
                "phind.com".to_string(),
                "codeium.com".to_string(),
                "tabnine.com".to_string(),
                "api.tabnine.com".to_string(),
                "replit.com".to_string(),
                "huggingface.co".to_string(),
                "api.huggingface.co".to_string(),
                "cohere.ai".to_string(),
                "api.cohere.ai".to_string(),
                "together.ai".to_string(),
                "api.together.xyz".to_string(),
                "replicate.com".to_string(),
                "api.replicate.com".to_string(),
                "stability.ai".to_string(),
                "api.stability.ai".to_string(),
                "midjourney.com".to_string(),

                // AI Writing Tools
                "grammarly.com".to_string(),
                "api.grammarly.com".to_string(),
                "jasper.ai".to_string(),
                "app.jasper.ai".to_string(),
                "copy.ai".to_string(),
                "app.copy.ai".to_string(),
                "writesonic.com".to_string(),
                "app.writesonic.com".to_string(),
                "quillbot.com".to_string(),
                "wordtune.com".to_string(),
                "app.wordtune.com".to_string(),

                // AI Research Tools
                "elicit.org".to_string(),
                "elicit.com".to_string(),
                "consensus.app".to_string(),
                "scite.ai".to_string(),
                "semanticscholar.org".to_string(),
                "api.semanticscholar.org".to_string(),

                // AI Code Assistants
                "sourcegraph.com".to_string(),
                "cody.dev".to_string(),
                "cursor.sh".to_string(),
                "cursor.com".to_string(),

                // AI Transcription
                "otter.ai".to_string(),
                "fireflies.ai".to_string(),
                "grain.com".to_string(),

                // Enterprise AI
                "claude.ai".to_string(),
                "poe.com".to_string(),
                "forefront.ai".to_string(),
                "writesonic.com".to_string(),

                // Open Source AI Platforms
                "ollama.ai".to_string(),
                "llamacpp.ai".to_string(),
                "localai.io".to_string(),

                // CDNs and APIs commonly used by AI services
                "cdn.openai.com".to_string(),
                "static.cloudflareinsights.com".to_string(), // Used by many AI sites
                "intercom.io".to_string(), // Chat widgets on AI sites
            ],
            blocked_ips: vec![
                // Known AI service IP ranges (examples)
                "104.18.0.0/15".to_string(), // Cloudflare (used by many AI services)
            ],
            monitor_dns: true,
            monitor_websockets: true,
        }
    }
}

impl crate::detection::types::FilesystemMonitorConfig {
    pub fn enhanced_default() -> Self {
        Self {
            scan_interval_ms: 1000, // Every second
            watch_directories: vec![
                dirs::download_dir().unwrap_or_default().to_string_lossy().to_string(),
                dirs::document_dir().unwrap_or_default().to_string_lossy().to_string(),
                dirs::desktop_dir().unwrap_or_default().to_string_lossy().to_string(),
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "~/.cache".to_string(),
                "~/.local/share".to_string(),
            ],
            suspicious_extensions: vec![
                ".ai".to_string(),
                ".gpt".to_string(),
                ".llm".to_string(),
                ".assistant".to_string(),
                ".openai".to_string(),
                ".anthropic".to_string(),
                ".claude".to_string(),
                ".chatgpt".to_string(),
                ".prompt".to_string(),
                ".conversation".to_string(),
            ],
            suspicious_filenames: vec![
                "chatgpt".to_string(),
                "claude".to_string(),
                "gemini".to_string(),
                "bard".to_string(),
                "ai-response".to_string(),
                "llm-output".to_string(),
                "gpt-conversation".to_string(),
                "ai-generated".to_string(),
                "copilot-suggestion".to_string(),
                "ai-assistant".to_string(),
                "prompt-response".to_string(),
                "api-key".to_string(),
                "openai-key".to_string(),
                "anthropic-key".to_string(),
            ],
            monitor_downloads: true,
            monitor_temp_files: true,
        }
    }
}

impl Config {
    pub async fn load() -> Result<Self> {
        let config_path = Self::get_config_path();

        if config_path.exists() {
            match fs::read_to_string(&config_path).await {
                Ok(content) => {
                    match toml::from_str::<Config>(&content) {
                        Ok(mut config) => {
                            // Ensure we have the enhanced detection config
                            if config.detection.is_none() {
                                config.detection = Some(DetectionConfig::enhanced_default());
                            }
                            debug!("Loaded configuration from {:?}", config_path);
                            return Ok(config);
                        }
                        Err(e) => {
                            warn!("Failed to parse configuration file: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read configuration file: {}", e);
                }
            }
        }

        // Return enhanced default configuration and save it
        let config = Config::default();
        let _ = config.save().await;
        Ok(config)
    }

    pub async fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path();

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&config_path, content).await?;

        debug!("Saved enhanced configuration to {:?}", config_path);
        Ok(())
    }

    fn get_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_default()
            .join("CluelyGuard")
            .join("config.toml")
    }

    pub fn get_data_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_default()
            .join("CluelyGuard")
    }

    pub fn get_log_dir() -> PathBuf {
        Self::get_data_dir().join("logs")
    }

    pub fn get_reports_dir(&self) -> PathBuf {
        self.app.report_directory.clone()
    }
}