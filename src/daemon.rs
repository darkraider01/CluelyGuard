use clap::Parser;
use cluelyguard::config::AppConfig;
use cluelyguard::logger::{FileLogger, RamDumpLog};
use cluelyguard::monitors::bam_realtime::BamMonitoringService;
use cluelyguard::monitors::browser::BrowserMonitor;
use cluelyguard::monitors::fs_monitor;
use cluelyguard::monitors::network::NetworkMonitor;
use cluelyguard::monitors::output_analysis::OutputAnalyzer;
use cluelyguard::monitors::process::scan;
use cluelyguard::monitors::screensharing::ScreenSharingMonitor;
use cluelyguard::monitors::syscall_monitor::SyscallMonitor;
use cluelyguard::monitors::user_activity::UserActivityMonitor;
use cluelyguard::monitors::coordinator::MonitoringCoordinator; // New import
use cluelyguard::events::{MonitorEvent, GenericMonitorEvent}; // New import
use cluelyguard::correlation::{CorrelationEngine, CorrelatedEvent}; // New import
use cluelyguard::network::NetworkClient;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc}; // Added mpsc
use tracing::{error, info};
use serde_json::to_string; // Added for serializing events

#[derive(Parser)]
#[command(name = "cluelyguard-daemon")]
#[command(about = "CluelyGuard Daemon")]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config/default.yaml")]
    config: String,
    /// Unique student code for the session
    #[arg(short, long)]
    student_code: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("cluelyguard=info")
        .init();

    info!("Starting CluelyGuard daemon...");

    let cli = Cli::parse();

    // Load configuration
    let config = Arc::new(AppConfig::load(None)?);
    info!("Configuration loaded from: {:?}", config.app.environment);

    // Validate configuration
    if let Err(errors) = config.validate() {
        error!("Configuration validation failed:");
        for error in errors {
            error!("  - {}", error);
        }
        return Err("Configuration validation failed".into());
    }

    // Initialize file logger
    let file_logger = Arc::new(FileLogger::new(config.clone())?);
    info!("File logger initialized");

    // Initialize network client
    #[cfg(not(feature = "local_test"))]
    let network_client = Arc::new(NetworkClient::new(config.app.teacher_pc_port));
    #[cfg(feature = "local_test")]
    let network_client = Arc::new(NetworkClient::new(0));

    // Initialize RAM dumper (now part of file_logger)
    // The `RamDumpLog::new` function is not needed here directly anymore,
    // as `FileLogger::create_ram_dump` handles the construction.
    // Keeping `student_code` for the `file_logger.create_ram_dump` call.
    let student_code = cli.student_code.clone().unwrap_or("local_test".to_string());
    info!("RAM dumper functionality integrated into FileLogger.");

    // Initialize BAM monitoring service (no database)
    let _bam_service = Arc::new(RwLock::new(BamMonitoringService::new(
        config.clone(),
        file_logger.clone(),
        Arc::new(RamDumpLog::new(student_code.clone())), // Pass a dummy RamDumpLog or refactor BamMonitoringService if it truly needs a RamDumpLog instance
    )));
    info!("BAM monitoring service initialized");

    // Start background monitoring tasks
    let file_logger_clone = file_logger.clone();
    let student_code_clone = cli.student_code.clone();
    let config_clone_for_spawn = config.clone(); // Clone config for the tokio::spawn block

    let network_client_for_coordinator: Option<Arc<NetworkClient>>;
    #[cfg(not(feature = "local_test"))]
    {
        network_client_for_coordinator = Some(network_client.clone());
    }
    #[cfg(feature = "local_test")]
    {
        network_client_for_coordinator = None;
    }
    let network_client_clone_for_receiver = network_client_for_coordinator.clone(); // Clone for receiver loop

    // Create an MPSC channel for events
    let (tx, mut rx) = mpsc::channel::<MonitorEvent>(100); // Buffer size of 100

    // Initialize the MonitoringCoordinator
    let mut coordinator = MonitoringCoordinator::new(
        config.clone(), // Clone config for the coordinator
        file_logger.clone(),
        network_client_for_coordinator, // Pass the network_client_for_coordinator
        student_code.clone(),
        tx, // Pass the sender to the coordinator
    );

    // Spawn the monitoring loop in the coordinator
    tokio::spawn(async move {
        coordinator.start_monitoring_loop().await;
    });

    // Event processing loop (receiver side)
    tokio::spawn(async move {
        let correlation_engine = CorrelationEngine::new(); // Instantiate CorrelationEngine

        while let Some(event) = rx.recv().await {
            // Process the event with the correlation engine
            if let Some(correlated_event) = correlation_engine.process_event(event, student_code_clone.as_deref().unwrap_or("local_test")).await {
                let log_entry = format!(
                    r#"{{"type": "{}", "student_code": "{}", "timestamp": "{}", "confidence": {}, "description": "{}", "correlated_events": {}}}"#,
                    correlated_event.event_type,
                    correlated_event.student_code,
                    chrono::Utc::now().to_rfc3339(), // Use current time for logging
                    correlated_event.confidence,
                    correlated_event.description,
                    serde_json::to_string(&correlated_event.correlated_events).unwrap_or_default()
                );

                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log correlated event: {}", e);
                }

                #[cfg(not(feature = "local_test"))]
                if let Some(network_client_arc) = network_client_clone_for_receiver.as_ref() {
                    if let Err(e) = network_client_arc.send_data(log_entry).await {
                        error!("Failed to send correlated event to teacher PC: {}", e);
                    }
                }
            }
        }
    });

    Ok(())
}
