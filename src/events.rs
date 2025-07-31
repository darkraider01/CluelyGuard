use serde::{Serialize, Deserialize};
use std::time::SystemTime;
use std::path::PathBuf;
use crate::monitors::browser::SuspiciousExtension;
use crate::monitors::fs_monitor::FileSystemEvent;
use crate::monitors::output_analysis::AnalysisResult;
use crate::monitors::screensharing::ScreenCaptureEvent;
use crate::monitors::syscall_monitor::AIDetection;
use crate::monitors::user_activity::UserActivityEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorEvent {
    FileSystem(FileSystemEvent),
    Browser(SuspiciousExtension),
    OutputAnalysis(AnalysisResult),
    Syscall(AIDetection),
    UserActivity(UserActivityEvent),
    ScreenSharing(ScreenCaptureEvent),
    NetworkDomain(String), // For suspicious network domains
    ProcessSuspicion(Vec<String>), // For suspicious processes (just names for now)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericMonitorEvent {
    pub event_type: String,
    pub timestamp: SystemTime,
    pub student_code: String,
    pub data: String, // JSON string of the specific monitor event
}

impl GenericMonitorEvent {
    pub fn new(event_type: &str, student_code: &str, data: &str) -> Self {
        GenericMonitorEvent {
            event_type: event_type.to_string(),
            timestamp: SystemTime::now(),
            student_code: student_code.to_string(),
            data: data.to_string(),
        }
    }
}