//! Logging configuration and initialization

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing_appender;

pub fn init() -> Result<()> {
    // Create logs directory
    let log_dir = crate::config::Config::get_log_dir();
    std::fs::create_dir_all(&log_dir)?;

    // Configure file appender
    let file_appender = tracing_appender::rolling::daily(log_dir, "cluely-guard.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Create filter
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("cluely_guard=debug,info"))
        .unwrap();

    // Initialize subscriber
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_target(false)
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_target(false)
                .with_ansi(false)
        )
        .init();

    Ok(())
}
