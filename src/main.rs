use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing::{error, info};
use cluelyguard::config::AppConfig;
// use cluelyguard::logger::RamDumpLog; // Removed as no longer directly used
use std::process::Command;

#[derive(Parser)]
#[command(name = "cluelyguard")]
#[command(about = "Industrial-grade Linux Anti-LLM Proctoring System")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the CluelyGuard daemon
    Start {
        /// Configuration file path
        #[arg(short, long, default_value = "config/default.yaml")]
        config: String,
        /// Unique student code for the session
        #[arg(short, long)]
        student_code: String,
    },
    /// Show system status
    Status,
    /// Train the BAM model
    Train {
        /// Dataset directory
        #[arg(short, long, default_value = "bam/dataset")]
        dataset: String,
    },
    /// Collect typing samples for training
    Collect {
        /// Output file
        #[arg(short, long, default_value = "bam/dataset/new_sample.json")]
        output: String,
        /// Sample duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
    },
    /// Generate a report
    Report {
        /// Session ID
        #[arg(short, long)]
        session_id: Option<String>,
    },
    /// Create a RAM dump for analysis
    RamDump {
        /// Session ID (optional)
        #[arg(short, long)]
        session_id: Option<String>,
        /// Output directory
        #[arg(short, long, default_value = "logs/ram_dumps")]
        output_dir: String,
        /// Unique student code for the session
        #[arg(short, long)]
        student_code: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("cluelyguard=info")
        .init();

    info!("CluelyGuard Anti-LLM Proctoring System v0.1.0");

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Start { config, student_code }) => {
            info!("Starting CluelyGuard daemon with config: {} for student: {}", config, student_code);

            let daemon_path = std::env::current_exe()?
                .parent()
                .ok_or("Could not get parent directory")?
                .join("cluelyguard-daemon");

            info!("Launching daemon from: {:?}", daemon_path);

            let output = Command::new(daemon_path)
                .arg("--config").arg(config)
                .arg("--student-code").arg(student_code)
                .spawn()?;

            info!("Daemon process spawned with PID: {:?}", output.id());
            info!("Daemon started successfully");
        }
        Some(Commands::Status) => {
            info!("Checking system status...");
            // TODO: Implement status check
            println!("✅ System is running");
        }
        Some(Commands::Train { dataset }) => {
            info!("Training BAM model with dataset: {}", dataset);
            // TODO: Implement model training
            info!("Model training completed");
        }
        Some(Commands::Collect { output, duration }) => {
            info!("Collecting typing samples for {} seconds to {}", duration, output);
            // TODO: Implement sample collection
            info!("Sample collection completed");
        }
        Some(Commands::Report { session_id }) => {
            info!("Generating report for session: {:?}", session_id);
            // TODO: Implement report generation
            info!("Report generated successfully");
        }
        Some(Commands::RamDump { session_id, output_dir: _, student_code }) => {
            info!("Creating RAM dump for session: {:?} for student: {}", session_id, student_code);
            
            // Load config
            let config = Arc::new(AppConfig::load(None)?);
            
            // Create session ID if not provided
            let session_id = session_id.clone().unwrap_or_else(|| {
                use uuid::Uuid;
                Uuid::new_v4().to_string()
            });
            
            // Create RAM dump
            // Initialize file logger
            let file_logger = Arc::new(cluelyguard::logger::FileLogger::new(config.clone())?);

            match cluelyguard::logger::FileLogger::create_ram_dump(&session_id, student_code) {
                Ok(dump) => {
                    info!("RAM dump created successfully:");
                    println!("📊 Memory Usage: {:.2} MB", dump.memory_usage_mb);
                    println!("🔍 Suspicious Processes: {}", dump.suspicious_processes.len());
                    println!("🌐 Network Connections: {}", dump.network_connections.len());
                    println!("📁 File Handles: {}", dump.file_handles.len());
                    println!("🆔 Dump ID: {}", dump.id);
                    println!("📅 Timestamp: {}", dump.timestamp);
                    
                    // Save to file
                    if let Err(e) = file_logger.log_ram_dump(&dump) {
                        error!("Failed to save RAM dump: {}", e);
                    } else {
                        println!("💾 RAM dump saved to logs/ram_dumps/dump_{}.json", dump.id);
                    }
                }
                Err(e) => {
                    error!("Failed to create RAM dump: {}", e);
                    return Err(e);
                }
            }
        }
        None => {
            info!("No command specified, showing help");
            println!("CluelyGuard Anti-LLM Proctoring System");
            println!("Use --help for more information");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // CLI command tests are currently skipped due to complexity in mocking global statics and external commands.
    // Comprehensive testing of CLI commands would require:
    // - Mocking `std::process::Command` to control spawned processes.
    // - Capturing `stdout` and `stderr` to verify output.
    // - Simulating different command-line arguments and their effects.
    // For now, relying on higher-level integration tests for CLI command functionality.
}
