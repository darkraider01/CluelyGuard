//! Complete Detection Engine with Real-Time Monitoring

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc::Sender, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info, debug, warn};

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
    running_tasks: Arc<RwLock<HashMap<DetectionModule, JoinHandle<()>>>>,
    monitoring_active: Arc<RwLock<bool>>,
    scan_stats: Arc<RwLock<ScanStatistics>>,
}

#[derive(Debug, Clone)]
pub struct ScanStatistics {
    pub total_scans: u64,
    pub total_detections: u64,
    pub last_scan_duration: Duration,
    pub average_scan_duration: Duration,
    pub detections_per_minute: f64,
    pub scan_errors: u64,
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self {
            total_scans: 0,
            total_detections: 0,
            last_scan_duration: Duration::from_millis(0),
            average_scan_duration: Duration::from_millis(100),
            detections_per_minute: 0.0,
            scan_errors: 0,
        }
    }
}

impl DetectionEngine {
    pub async fn new(config: Config, event_tx: Sender<DetectionEvent>) -> Result<Self> {
        info!("Initializing Advanced Detection Engine...");

        let detection_config = config.detection.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Detection configuration missing"))?;

        let browser_extensions_monitor = BrowserExtensionMonitor::new(
            detection_config.browser_extensions.clone(),
            detection_config.clone(),
        )?;

        let process_monitor = ProcessMonitor::new(
            detection_config.process_monitor.clone(),
        )?;

        let network_monitor = NetworkMonitor::new(
            detection_config.network_monitor.clone(),
        )?;

        let screen_monitor = ScreenMonitor::new(
            detection_config.screen_monitor.clone(),
        )?;

        let filesystem_monitor = FilesystemMonitor::new(
            detection_config.filesystem_monitor.clone(),
        )?;

        info!("All detection modules initialized successfully");

        Ok(Self {
            config,
            browser_extensions_monitor,
            process_monitor,
            network_monitor,
            screen_monitor,
            filesystem_monitor,
            event_tx,
            running_tasks: Arc::new(RwLock::new(HashMap::new())),
            monitoring_active: Arc::new(RwLock::new(false)),
            scan_stats: Arc::new(RwLock::new(ScanStatistics::default())),
        })
    }

    pub async fn start_monitoring(&self) -> Result<()> {
        info!("🚀 Starting comprehensive real-time AI detection monitoring...");
        
        let mut monitoring_active = self.monitoring_active.write().await;
        if *monitoring_active {
            warn!("Monitoring already active");
            return Ok(());
        }
        *monitoring_active = true;
        drop(monitoring_active);

        let mut tasks = self.running_tasks.write().await;
        
        // Start Browser Extension Monitor
        if self.is_module_enabled(DetectionModule::BrowserExtensions).await? {
            let task = self.start_browser_extension_monitoring().await?;
            tasks.insert(DetectionModule::BrowserExtensions, task);
            info!("✅ Browser Extension Monitor started");
        }

        // Start Process Monitor
        if self.is_module_enabled(DetectionModule::ProcessMonitor).await? {
            let task = self.start_process_monitoring().await?;
            tasks.insert(DetectionModule::ProcessMonitor, task);
            info!("✅ Process Monitor started");
        }

        // Start Network Monitor
        if self.is_module_enabled(DetectionModule::NetworkMonitor).await? {
            let task = self.start_network_monitoring().await?;
            tasks.insert(DetectionModule::NetworkMonitor, task);
            info!("✅ Network Monitor started");
        }

        // Start Screen Monitor (if enabled)
        if self.is_module_enabled(DetectionModule::ScreenMonitor).await? {
            let task = self.start_screen_monitoring().await?;
            tasks.insert(DetectionModule::ScreenMonitor, task);
            info!("✅ Screen Monitor started");
        }

        // Start Filesystem Monitor
        if self.is_module_enabled(DetectionModule::FilesystemMonitor).await? {
            let task = self.start_filesystem_monitoring().await?;
            tasks.insert(DetectionModule::FilesystemMonitor, task);
            info!("✅ Filesystem Monitor started");
        }

        info!("🛡️ All enabled detection modules are now running");
        Ok(())
    }

    pub async fn stop_monitoring(&self) {
        info!("🛑 Stopping all detection monitoring...");
        
        *self.monitoring_active.write().await = false;
        
        let mut tasks = self.running_tasks.write().await;
        for (module, task) in tasks.drain() {
            task.abort();
            info!("Stopped {} monitor", module.name());
        }
        
        info!("All detection monitoring stopped");
    }

    pub async fn perform_scan(&self) -> Result<()> {
        info!("🔍 Performing comprehensive AI detection scan...");
        
        let scan_start = Instant::now();
        let mut total_events = 0;
        let mut scan_errors = 0;

        // Browser Extensions Scan
        match self.browser_extensions_monitor.scan() {
            Ok(events) => {
                total_events += events.len();
                for event in events {
                    if let Err(e) = self.event_tx.send(event).await {
                        error!("Failed to send browser extension event: {}", e);
                        scan_errors += 1;
                    }
                }
            }
            Err(e) => {
                error!("Browser extension scan failed: {}", e);
                scan_errors += 1;
            }
        }

        // Process Monitor Scan
        match self.process_monitor.scan().await {
            Ok(events) => {
                total_events += events.len();
                for event in events {
                    if let Err(e) = self.event_tx.send(event).await {
                        error!("Failed to send process event: {}", e);
                        scan_errors += 1;
                    }
                }
            }
            Err(e) => {
                error!("Process monitor scan failed: {}", e);
                scan_errors += 1;
            }
        }

        // Network Monitor Scan
        match self.network_monitor.scan().await {
            Ok(events) => {
                total_events += events.len();
                for event in events {
                    if let Err(e) = self.event_tx.send(event).await {
                        error!("Failed to send network event: {}", e);
                        scan_errors += 1;
                    }
                }
            }
            Err(e) => {
                error!("Network monitor scan failed: {}", e);
                scan_errors += 1;
            }
        }

        // Screen Monitor Scan (if enabled)
        if self.is_module_enabled(DetectionModule::ScreenMonitor).await? {
            match self.screen_monitor.scan().await {
                Ok(events) => {
                    total_events += events.len();
                    for event in events {
                        if let Err(e) = self.event_tx.send(event).await {
                            error!("Failed to send screen event: {}", e);
                            scan_errors += 1;
                        }
                    }
                }
                Err(e) => {
                    error!("Screen monitor scan failed: {}", e);
                    scan_errors += 1;
                }
            }
        }

        // Filesystem Monitor Scan
        match self.filesystem_monitor.scan().await {
            Ok(events) => {
                total_events += events.len();
                for event in events {
                    if let Err(e) = self.event_tx.send(event).await {
                        error!("Failed to send filesystem event: {}", e);
                        scan_errors += 1;
                    }
                }
            }
            Err(e) => {
                error!("Filesystem monitor scan failed: {}", e);
                scan_errors += 1;
            }
        }

        let scan_duration = scan_start.elapsed();
        
        // Update statistics
        let mut stats = self.scan_stats.write().await;
        stats.total_scans += 1;
        stats.total_detections += total_events as u64;
        stats.last_scan_duration = scan_duration;
        stats.scan_errors += scan_errors;
        
        // Update average scan duration (simple moving average)
        let alpha = 0.1; // Smoothing factor
        stats.average_scan_duration = Duration::from_nanos(
            (alpha * scan_duration.as_nanos() as f64 + 
             (1.0 - alpha) * stats.average_scan_duration.as_nanos() as f64) as u64
        );

        info!("✅ Scan completed: {} threats detected in {:?} (errors: {})", 
              total_events, scan_duration, scan_errors);

        Ok(())
    }

    // Individual monitoring task starters
    async fn start_browser_extension_monitoring(&self) -> Result<JoinHandle<()>> {
        let monitor = self.browser_extensions_monitor.clone();
        let event_tx = self.event_tx.clone();
        let monitoring_active = self.monitoring_active.clone();
        let scan_interval = Duration::from_millis(
            self.config.detection.as_ref().unwrap()
                .browser_extensions.scan_interval_ms
        );

        let task = tokio::spawn(async move {
            info!("Browser extension monitoring thread started");
            
            while *monitoring_active.read().await {
                let scan_start = Instant::now();
                
                match monitor.scan() {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send browser extension event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Browser extension scan error: {}", e);
                    }
                }

                let scan_duration = scan_start.elapsed();
                debug!("Browser extension scan completed in {:?}", scan_duration);

                tokio::time::sleep(scan_interval).await;
            }
            
            info!("Browser extension monitoring thread stopped");
        });

        Ok(task)
    }

    async fn start_process_monitoring(&self) -> Result<JoinHandle<()>> {
        let monitor = self.process_monitor.clone();
        let event_tx = self.event_tx.clone();
        let monitoring_active = self.monitoring_active.clone();
        let scan_interval = Duration::from_millis(
            self.config.detection.as_ref().unwrap()
                .process_monitor.scan_interval_ms
        );

        let task = tokio::spawn(async move {
            info!("Process monitoring thread started");
            
            while *monitoring_active.read().await {
                let scan_start = Instant::now();
                
                match monitor.scan().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send process event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Process monitor scan error: {}", e);
                    }
                }

                let scan_duration = scan_start.elapsed();
                debug!("Process scan completed in {:?}", scan_duration);

                tokio::time::sleep(scan_interval).await;
            }
            
            info!("Process monitoring thread stopped");
        });

        Ok(task)
    }

    async fn start_network_monitoring(&self) -> Result<JoinHandle<()>> {
        let monitor = self.network_monitor.clone();
        let event_tx = self.event_tx.clone();
        let monitoring_active = self.monitoring_active.clone();
        let scan_interval = Duration::from_millis(
            self.config.detection.as_ref().unwrap()
                .network_monitor.scan_interval_ms
        );

        let task = tokio::spawn(async move {
            info!("Network monitoring thread started");
            
            while *monitoring_active.read().await {
                let scan_start = Instant::now();
                
                match monitor.scan().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send network event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Network monitor scan error: {}", e);
                    }
                }

                let scan_duration = scan_start.elapsed();
                debug!("Network scan completed in {:?}", scan_duration);

                tokio::time::sleep(scan_interval).await;
            }
            
            info!("Network monitoring thread stopped");
        });

        Ok(task)
    }

    async fn start_screen_monitoring(&self) -> Result<JoinHandle<()>> {
        let monitor = self.screen_monitor.clone();
        let event_tx = self.event_tx.clone();
        let monitoring_active = self.monitoring_active.clone();
        let scan_interval = Duration::from_millis(
            self.config.detection.as_ref().unwrap()
                .screen_monitor.capture_interval_ms
        );

        let task = tokio::spawn(async move {
            info!("Screen monitoring thread started");
            
            while *monitoring_active.read().await {
                let scan_start = Instant::now();
                
                match monitor.scan().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send screen event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Screen monitor scan error: {}", e);
                    }
                }

                let scan_duration = scan_start.elapsed();
                debug!("Screen scan completed in {:?}", scan_duration);

                tokio::time::sleep(scan_interval).await;
            }
            
            info!("Screen monitoring thread stopped");
        });

        Ok(task)
    }

    async fn start_filesystem_monitoring(&self) -> Result<JoinHandle<()>> {
        let monitor = self.filesystem_monitor.clone();
        let event_tx = self.event_tx.clone();
        let monitoring_active = self.monitoring_active.clone();
        let scan_interval = Duration::from_millis(
            self.config.detection.as_ref().unwrap()
                .filesystem_monitor.scan_interval_ms
        );

        let task = tokio::spawn(async move {
            info!("Filesystem monitoring thread started");
            
            while *monitoring_active.read().await {
                let scan_start = Instant::now();
                
                match monitor.scan().await {
                    Ok(events) => {
                        for event in events {
                            if let Err(e) = event_tx.send(event).await {
                                error!("Failed to send filesystem event: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Filesystem monitor scan error: {}", e);
                    }
                }

                let scan_duration = scan_start.elapsed();
                debug!("Filesystem scan completed in {:?}", scan_duration);

                tokio::time::sleep(scan_interval).await;
            }
            
            info!("Filesystem monitoring thread stopped");
        });

        Ok(task)
    }

    async fn is_module_enabled(&self, module: DetectionModule) -> Result<bool> {
        Ok(self.config.detection.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Detection config missing"))?
            .enabled_modules.get(&module)
            .copied()
            .unwrap_or(false))
    }

    pub async fn get_statistics(&self) -> ScanStatistics {
        self.scan_stats.read().await.clone()
    }

    pub async fn is_monitoring_active(&self) -> bool {
        *self.monitoring_active.read().await
    }
}