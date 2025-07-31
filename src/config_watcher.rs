use crate::config::AppConfig;
use notify::{recommended_watcher, Event, EventKind, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub async fn watch_config(config_path: PathBuf, app_config: Arc<RwLock<AppConfig>>) {
    info!("Starting config file watcher for: {:?}", config_path);

    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = match recommended_watcher(tx) {
        Ok(watcher) => watcher,
        Err(e) => {
            error!("Failed to create config watcher: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(&config_path, RecursiveMode::NonRecursive) {
        error!("Failed to watch config file {:?}: {}", config_path, e);
        return;
    }

    info!("Config watcher started. Waiting for changes...");

    for res in rx {
        match res {
            Ok(event) => {
                if let EventKind::Modify(notify::event::ModifyKind::Data(_)) = event.kind {
                    info!("Config file modified. Reloading configuration...");
                    match AppConfig::load(Some(&config_path)) {
                        Ok(new_config) => {
                            let mut config_guard = app_config.write().await;
                            *config_guard = new_config;
                            info!("Configuration reloaded successfully.");
                        }
                        Err(e) => {
                            error!("Failed to reload configuration: {}", e);
                        }
                    }
                }
            }
            Err(e) => error!("Config watcher error: {:?}", e),
        }
    }
    info!("Config watcher stopped.");
}