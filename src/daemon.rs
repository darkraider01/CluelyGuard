use clap::Parser;
use cluelyguard::config::AppConfig;
use cluelyguard::logger::{FileLogger, RamDumpLog};
use cluelyguard::monitors::bam_realtime::BamMonitoringService;
use cluelyguard::monitors::network::NetworkMonitor;
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
        loop {
            interval.tick().await;

            // Check for suspicious DNS queries
            if let Some(suspicion) = NetworkMonitor::check_dns_queries() {
                let log_entry = format!("{{ \"type\": \"dns_suspicion\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                        student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), suspicion);
                if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                    error!("Failed to log DNS suspicion: {}", e);
                }
                #[cfg(not(feature = "local_test"))]
                if let Err(e) = network_client_clone.send_data(log_entry).await {
                    error!("Failed to send DNS suspicion to teacher PC: {}", e);
                }
            } // End of DNS queries if
            
            // Simulate output analysis
            let simulated_output = "This is a simulated output. I am a large language model.";
            if let Some(suspicion) = cluelyguard::monitors::output_analysis::analyze_output(simulated_output) {
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

            // Check for suspicious file system activity
            if let Some(suspicion) = cluelyguard::monitors::fs_monitor::check_file_system_activity() {
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

            // Check for suspicious syscall activity
            if let Some(suspicion) = cluelyguard::monitors::syscall_monitor::check_syscall_activity() {
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
            if let Some(suspicion) = cluelyguard::monitors::user_activity::check_user_activity() {
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
            if let Some(suspicion) = cluelyguard::monitors::screensharing::check_screensharing() {
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

            match NetworkMonitor::get_network_usage() {
                Ok(usage) => {
                    let log_entry = format!("{{ \"type\": \"network_usage\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": \"{}\" }}",
                                            student_code_clone.as_deref().unwrap_or("local_test"), chrono::Utc::now().to_rfc3339(), usage.replace("\n", " "));
                    if let Err(e) = file_logger_clone.append_to_log_file(&log_entry) {
                        error!("Failed to log network usage: {}", e);
                    }
                    #[cfg(not(feature = "local_test"))]
                    if let Err(e) = network_client_clone.send_data(log_entry).await {
                        error!("Failed to send network usage to teacher PC: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to get network usage: {}", e);
                }
            } // End of NetworkMonitor match
        } // End of loop
    }); // End of tokio::spawn block

    // Keep the daemon running
    info!("CluelyGuard daemon is running. Press Ctrl+C to stop.");
    
    tokio::signal::ctrl_c().await?;
    info!("Shutting down CluelyGuard daemon...");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    // Daemon tests are currently skipped due to complexity in mocking global statics and external dependencies.
    // Comprehensive testing of the daemon's behavior would require significant refactoring for dependency injection
    // or a more advanced testing harness that can simulate system interactions.
    // These tests would ideally cover:
    // - Daemon startup with valid/invalid configurations.
    // - Background monitoring loop and its interaction with various monitors.
    // - Graceful shutdown.
    // - Verification of logging and network communication (with mocked FileLogger and NetworkClient).
    // For now, relying on higher-level integration tests for daemon functionality.
}
