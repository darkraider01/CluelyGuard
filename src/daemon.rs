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
use cluelyguard::network::NetworkClient;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

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
    #[cfg(not(feature = "local_test"))]
    let network_client_clone = network_client.clone();
    let student_code_clone = cli.student_code.clone();
    let config_clone_for_spawn = config.clone(); // Clone config for the tokio::spawn block

    let network_monitor = NetworkMonitor::new();
    network_monitor.start_monitoring(); // Start the background thread
    let browser_monitor = BrowserMonitor::new();
    // browser_monitor.start_monitoring(); // Start browser monitoring (Removed as it doesn't exist)
    let mut syscall_monitor = SyscallMonitor::new();
    let mut user_activity_monitor = UserActivityMonitor::new();
    let output_analyzer = OutputAnalyzer::new();

    // Start monitoring services that need to run continuously or have internal threads
    if let Err(e) = syscall_monitor.start_monitoring() {
        error!("Failed to start syscall monitor: {}", e);
    }
    if let Err(e) = user_activity_monitor.start_monitoring() {
        error!("Failed to start user activity monitor: {}", e);
    }

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let config = config_clone_for_spawn; // Move the cloned config into this block

        loop {
            interval.tick().await;

            // Check for suspicious file system activity
            let mut fs_monitor = fs_monitor::FileSystemMonitor::new(); // Declare as mutable
            let fs_events = fs_monitor.get_events();
            for suspicion in fs_events {
                let log_entry = format!("{{ \"type\": \"fs_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log FS suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send FS suspicion to teacher PC: {}", e);
                }
            } // End of file system activity

            // Analyze browser activity
            let browser_extensions = browser_monitor.scan_all_extensions();
            for extension in browser_extensions {
                let log_entry = format!("{{ \"type\": \"browser_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), extension);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log browser suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send browser suspicion to teacher PC: {}", e);
                }
            }

            // Simulate output analysis
            let simulated_output = "This is a simulated output. I am a large language model.";
            let analysis_result = output_analyzer.analyze_text(simulated_output);
            if analysis_result.is_suspicious {
                let log_entry = format!("{{ \"type\": \"output_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), analysis_result);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log output suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send output suspicion to teacher PC: {}", e);
                }
            } // End of output analysis

            // Check for suspicious syscall activity
            let syscall_detections = syscall_monitor.analyze_patterns();
            for detection in syscall_detections {
                let log_entry = format!("{{ \"type\": \"syscall_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), detection);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log syscall suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send syscall suspicion to teacher PC: {}", e);
                }
            } // End of syscall activity

            // Check for suspicious user activity
            let user_activities = user_activity_monitor.get_recent_activities(std::time::SystemTime::now() - std::time::Duration::from_secs(60));
            for activity in user_activities {
                if activity.suspicious {
                    let log_entry = format!("{{ \"type\": \"user_activity_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                            student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), activity);
                    if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                        error!("Failed to log user activity suspicion: {}", e);
                    }
                    #[cfg(not(feature = "local_test"))]
                    if let Err(e) = network_client_clone.send_data(log_entry).await {
                        error!("Failed to send user activity suspicion to teacher PC: {}", e);
                    }
                }
            } // End of user activity

            // Check for screensharing activity
            let screensharing_events = ScreenSharingMonitor::new().detect_screen_capture();
            for event in screensharing_events {
                let log_entry = format!("{{ \"type\": \"screensharing_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), event);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log screensharing suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send screensharing suspicion to teacher PC: {}", e);
                }
            } // End of screensharing activity

            // Example of how to retrieve detected LLM domains from the network monitor
            let detected_llm_domains = network_monitor.get_detected_llm_domains();
            if !detected_llm_domains.is_empty() {
                let log_entry = format!("{{ \"type\": \"network_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), detected_llm_domains);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log network suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send network suspicion to teacher PC: {}", e);
                }
            }

            // Periodically scan processes for suspicious AI tools
            let process_scan_result = scan(&config); // Use the config available in this scope
            if !process_scan_result.suspicious_processes.is_empty() {
                let log_entry = format!("{{ \"type\": \"process_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{:?}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), process_scan_result.suspicious_processes);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log process suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send process suspicion to teacher PC: {}", e);
                }
            }
        } // End of loop
    });
    Ok(())
}
