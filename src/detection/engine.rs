use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::config::Config;
use crate::detection::browser_extensions::BrowserExtensionMonitor;
use crate::detection::filesystem_monitor::FilesystemMonitor;
use crate::detection::network_monitor::NetworkMonitor;
use crate::detection::process_monitor::ProcessMonitor;
use crate::detection::screen_monitor::ScreenMonitor;
use crate::detection::types::{DetectionEvent, DetectionModule};

pub struct DetectionEngine {
    config: Config,
    browser_extensions_monitor: BrowserExtensionMonitor,
    process_monitor: ProcessMonitor,
    network_monitor: NetworkMonitor,
    screen_monitor: ScreenMonitor,
    filesystem_monitor: FilesystemMonitor,
    event_tx: Sender<DetectionEvent>,
    running_monitors: Arc<RwLock<HashMap<DetectionModule, tokio::task::JoinHandle<()>>>>,
}

impl DetectionEngine {
    pub async fn new(config: Config, event_tx: Sender<DetectionEvent>) -> Result<Self> {
        info!("Initializing DetectionEngine...");

        let browser_extensions_monitor = BrowserExtensionMonitor::new(
            config.detection.as_ref().unwrap().browser_extensions.clone(),
            config.detection.as_ref().unwrap().clone(),
        )?;
        let process_monitor = ProcessMonitor::new(
            config.detection.as_ref().unwrap().process_monitor.clone(),
        )?;
        let network_monitor = NetworkMonitor::new(
            config.detection.as_ref().unwrap().network_monitor.clone(),
        )?;
        let screen_monitor = ScreenMonitor::new(
            config.detection.as_ref().unwrap().screen_monitor.clone(),
        )?;
        let filesystem_monitor = FilesystemMonitor::new(
            config.detection.as_ref().unwrap().filesystem_monitor.clone(),
        )?;

        Ok(Self {
            config,
            browser_extensions_monitor,
            process_monitor,
            network_monitor,
            screen_monitor,
            filesystem_monitor,
            event_tx,
            running_monitors: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        info!("DetectionEngine: Starting monitoring...");
        let mut running_monitors = self.running_monitors.write().await;

        // Browser Extensions Monitor
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::BrowserExtensions] {
            let monitor = self.browser_extensions_monitor.clone();
            let event_tx = self.event_tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    if let Ok(events) = monitor.scan() {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send browser extension event: {}", e);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        monitor.config.scan_interval_ms,
                    )).await;
                }
            });
            running_monitors.insert(DetectionModule::BrowserExtensions, handle);
        }

        // Process Monitor
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::ProcessMonitor] {
            let monitor = self.process_monitor.clone();
            let event_tx = self.event_tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    if let Ok(events) = monitor.scan().await {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send process event: {}", e);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        monitor.config.scan_interval_ms,
                    )).await;
                }
            });
            running_monitors.insert(DetectionModule::ProcessMonitor, handle);
        }

        // Network Monitor
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::NetworkMonitor] {
            let monitor = self.network_monitor.clone();
            let event_tx = self.event_tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    if let Ok(events) = monitor.scan().await {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send network event: {}", e);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        monitor.config.scan_interval_ms,
                    )).await;
                }
            });
            running_monitors.insert(DetectionModule::NetworkMonitor, handle);
        }

        // Screen Monitor
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::ScreenMonitor] {
            let monitor = self.screen_monitor.clone();
            let event_tx = self.event_tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    if let Ok(events) = monitor.scan().await {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send screen event: {}", e);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        monitor.config.capture_interval_ms,
                    )).await;
                }
            });
            running_monitors.insert(DetectionModule::ScreenMonitor, handle);
        }

        // Filesystem Monitor
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::FilesystemMonitor] {
            let monitor = self.filesystem_monitor.clone();
            let event_tx = self.event_tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    if let Ok(events) = monitor.scan().await {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send filesystem event: {}", e);
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        monitor.config.scan_interval_ms,
                    )).await;
                }
            });
            running_monitors.insert(DetectionModule::FilesystemMonitor, handle);
        }

        Ok(())
    }

    pub async fn stop_monitoring(&self) {
        info!("DetectionEngine: Stopping monitoring...");
        let mut running_monitors = self.running_monitors.write().await;
        for (_, handle) in running_monitors.drain() {
            handle.abort();
        }
    }

    pub async fn perform_scan(&mut self) -> Result<()> {
        info!("DetectionEngine: Performing quick scan...");

        let mut events = Vec::new();

        // Perform scan for enabled modules
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::BrowserExtensions] {
            if let Ok(browser_events) = self.browser_extensions_monitor.scan() {
                events.extend(browser_events);
            }
        }
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::ProcessMonitor] {
            if let Ok(process_events) = self.process_monitor.scan().await {
                events.extend(process_events);
            }
        }
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::NetworkMonitor] {
            if let Ok(network_events) = self.network_monitor.scan().await {
                events.extend(network_events);
            }
        }
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::ScreenMonitor] {
            if let Ok(screen_events) = self.screen_monitor.scan().await {
                events.extend(screen_events);
            }
        }
        if self.config.detection.as_ref().unwrap().enabled_modules[&DetectionModule::FilesystemMonitor] {
            if let Ok(fs_events) = self.filesystem_monitor.scan().await {
                events.extend(fs_events);
            }
        }

        for event in events {
            if let Err(e) = self.event_tx.send(event).await {
                error!("Failed to send quick scan event: {}", e);
            }
        }

        Ok(())
    }

}
