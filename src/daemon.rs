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
use cluelyguard::config_watcher; // New import
use std::path::PathBuf; // Added PathBuf
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
    let initial_config = AppConfig::load(None)?;
    let config_arc = Arc::new(RwLock::new(initial_config));
    info!("Configuration loaded from: {:?}", config_arc.read().await.app.environment);

    // Validate initial configuration
    if let Err(errors) = config_arc.read().await.validate() {
        error!("Configuration validation failed:");
        for error in errors {
            error!("  - {}", error);
        }
        return Err("Configuration validation failed".into());
    }

    // Spawn config watcher
    let config_path = PathBuf::from(&cli.config);
    let config_arc_clone_for_watcher = config_arc.clone(); // Clone for the watcher
    tokio::spawn(async move {
        config_watcher::watch_config(config_path, config_arc_clone_for_watcher).await;
    });

    // Initialize file logger
    let file_logger = Arc::new(FileLogger::new(config_arc.clone()).await?);
    info!("File logger initialized");

    // Initialize network client
    #[cfg(not(feature = "local_test"))]
    let network_client = Arc::new(NetworkClient::new(config_arc.read().await.app.teacher_pc_port));
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
        config_arc.clone(), // Pass the Arc<RwLock<AppConfig>>
        file_logger.clone(),
        Arc::new(RamDumpLog::new(student_code.clone())), // Pass a dummy RamDumpLog or refactor BamMonitoringService if it truly needs a RamDumpLog instance
    )));
    info!("BAM monitoring service initialized");

    // Start background monitoring tasks
    let file_logger_clone = file_logger.clone();
    let student_code_clone = cli.student_code.clone();

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
        config_arc.clone(), // Pass the Arc<RwLock<AppConfig>>
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
        let correlation_engine = CorrelationEngine::new(config_arc.clone()); // Instantiate CorrelationEngine with config

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
            if let Some(network_client_arc) = network_client_clone_for_receiver.as_ref() {
                if let Err(e) = network_client_arc.send_data(log_entry).await {
                    error!("Failed to send {} suspicion to teacher PC: {}", event_type_str, e);
                }
            }
        }
    });

    Ok(())
}
