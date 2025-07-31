use clap::Parser;
use cluelyguard::config::AppConfig;
use cluelyguard::logger::{FileLogger, RamDumpLog};
use cluelyguard::monitors::bam_realtime::BamMonitoringService;
use cluelyguard::monitors::browser::BrowserMonitor;
use cluelyguard::monitors::fs_monitor;
use cluelyguard::monitors::network::NetworkMonitor;
use cluelyguard::monitors::output_analysis::analyze_output;
use cluelyguard::monitors::process;
use cluelyguard::monitors::screensharing;
use cluelyguard::monitors::syscall_monitor;
use cluelyguard::monitors::user_activity;
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

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        let network_monitor = NetworkMonitor::new();
        network_monitor.start_monitoring(); // Start the background thread
        let browser_monitor = BrowserMonitor::new();
        browser_monitor.start_monitoring(); // Start browser monitoring
        // let process_monitor = process::ProcessMonitor::new(); // Initialize process monitor

        loop {
            interval.tick().await;

            // Check for suspicious file system activity
            if let Some(suspicion) = fs_monitor::check_file_system_activity() {
                let log_entry = format!("{{ \"type\": \"fs_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log FS suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send FS suspicion to teacher PC: {}", e);
                }
            } // End of file system activity if

            // Simulate output analysis
            let simulated_output = "This is a simulated output. I am a large language model.";
            if let Some(suspicion) = analyze_output(simulated_output) {
                let log_entry = format!("{{ \"type\": \"output_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log output suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send output suspicion to teacher PC: {}", e);
                }
            } // End of output analysis if

            // Check for suspicious syscall activity
            if let Some(suspicion) = syscall_monitor::check_syscall_activity() {
                let log_entry = format!("{{ \"type\": \"syscall_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log syscall suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send syscall suspicion to teacher PC: {}", e);
                }
            } // End of syscall activity if

            // Check for suspicious user activity
            if let Some(suspicion) = user_activity::check_user_activity() {
                let log_entry = format!("{{ \"type\": \"user_activity_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log user activity suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send user activity suspicion to teacher PC: {}", e);
                }
            } // End of user activity if

            // Check for screensharing activity
            if let Some(suspicion) = screensharing::check_screensharing() {
                let log_entry = format!("{{ \"type\": \"screensharing_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log screensharing suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send screensharing suspicion to teacher PC: {}", e);
                }
            } // End of screensharing activity if

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
            let config_clone = config.clone(); // Clone config for use in the async block
            let process_scan_result = process::scan(&config_clone); // Call the standalone function
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

            // Periodically get network usage (example, integrate with checks above)
            // This is now part of the NetworkMonitor's internal logic if implemented to capture all traffic.
            // If you still need periodic usage stats, you'd call a method on `network_monitor` here.
            // For now, removing the direct `get_network_usage` call as it's replaced by packet capture.
            // match network_monitor.get_network_usage() { // Assuming you add this method back to NetworkMonitor if needed
            //     Ok(usage) => {
            //         let log_entry = format!("{{ \"type\": \"network_usage\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
            //                                 student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), usage.replace("\n", " "));
            //         if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
            //             error!("Failed to log network usage: {}", e);
            //         }
            //         #[cfg(not(feature = "local_test"))]
            //         if let Err(e) = network_client_clone.send_data(log_entry).await {
            //             error!("Failed to send network usage to teacher PC: {}", e);
            //         }
            //     }
            //     Err(e) => {
            //         error!("Failed to get network usage: {}", e);
            //     }
            // }
        } // End of loop
    }); // End of tokio::spawn block
    Ok(())
}
