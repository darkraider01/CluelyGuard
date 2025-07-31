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

    #[cfg(not(feature = "local_test"))]
    let network_client_option = Some(network_client.clone());
    #[cfg(feature = "local_test")]
    let network_client_option = None;

    // Create an MPSC channel for events
    let (tx, mut rx) = mpsc::channel::<MonitorEvent>(100); // Buffer size of 100

    // Initialize the MonitoringCoordinator
    let mut coordinator = MonitoringCoordinator::new(
        config.clone(), // Clone config for the coordinator
        file_logger.clone(),
        network_client_option.clone(), // Pass the network_client_option
        student_code.clone(),
        tx, // Pass the sender to the coordinator
    );

    // Spawn the monitoring loop in the coordinator
    tokio::spawn(async move {
        coordinator.start_monitoring_loop().await;
    });

    // Event processing loop (receiver side)
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let event_type_str = match event {
                MonitorEvent::FileSystem(_) => "fs_suspicion",
                MonitorEvent::Browser(_) => "browser_suspicion",
                MonitorEvent::OutputAnalysis(_) => "output_suspicion",
                MonitorEvent::Syscall(_) => "syscall_suspicion",
                MonitorEvent::UserActivity(_) => "user_activity_suspicion",
                MonitorEvent::ScreenSharing(_) => "screensharing_suspicion",
                MonitorEvent::NetworkDomain(_) => "network_suspicion",
                MonitorEvent::ProcessSuspicion(_) => "process_suspicion",
            };

            let log_entry_data = match event {
                MonitorEvent::FileSystem(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::Browser(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::OutputAnalysis(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::Syscall(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::UserActivity(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::ScreenSharing(e) => to_string(&e).unwrap_or_default(),
                MonitorEvent::NetworkDomain(e) => format!("{:?}", e),
                MonitorEvent::ProcessSuspicion(e) => format!("{:?}", e),
            };

            let log_entry = format!(
                r#"{{"type": "{}", "student_code": "{}", "timestamp": "{}", "data": {}}}"#,
                event_type_str,
                student_code_clone.as_deref().unwrap_or("local_test"),
                chrono::Utc::now().to_rfc3339(),
                log_entry_data
            );

            if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                error!("Failed to log {} suspicion: {}", event_type_str, e);
            }

            #[cfg(not(feature = "local_test"))]
            if let Some(network_client_arc) = network_client_option.as_ref() {
                if let Err(e) = network_client_arc.send_data(log_entry).await {
                    error!("Failed to send {} suspicion to teacher PC: {}", event_type_str, e);
                }
            }
        }
    });

    Ok(())
}
