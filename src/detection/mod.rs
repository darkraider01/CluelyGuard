//! Detection engine and coordinating modules

pub mod engine;
pub mod browser_extensions;
pub mod process_monitor;
pub mod network_monitor;
pub mod screen_monitor;
pub mod filesystem_monitor;
pub mod types;

pub use engine::DetectionEngine;
pub use types::*;
