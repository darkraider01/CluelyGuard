//! Configuration management for CluelyGuard

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, warn};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_enabled: bool,
    pub file_path: PathBuf,
    pub max_file_size_mb: u64,
    pub max_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub theme: String,
    pub start_minimized: bool,
    pub show_notifications: bool,
    pub notification_duration: u64,
    pub auto_save_interval: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            app: AppConfig::default(),
            detection: Some(DetectionConfig::default()),
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
            auto_start_monitoring: false,
            save_reports: true,
            report_directory: dirs::document_dir()
                .unwrap_or_default()
                .join("CluelyGuard")
                .join("Reports"),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_enabled: true,
            file_path: dirs::data_local_dir()
                .unwrap_or_default()
                .join("CluelyGuard")
                .join("logs")
                .join("cluely-guard.log"),
            max_file_size_mb: 50,
            max_files: 10,
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            start_minimized: false,
            show_notifications: true,
            notification_duration: 5000,
            auto_save_interval: 300, // 5 minutes
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
                        Ok(config) => {
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

        // Return default configuration and save it
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

        debug!("Saved configuration to {:?}", config_path);
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

    #[allow(dead_code)]
    pub fn get_reports_dir(&self) -> PathBuf {
        self.app.report_directory.clone()
    }
}
