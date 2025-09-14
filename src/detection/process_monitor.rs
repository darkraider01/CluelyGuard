//! Process monitoring module for detecting AI-related processes

use anyhow::Result;
use chrono::Utc;
use sysinfo::{ProcessRefreshKind, System};
use std::collections::HashMap;
use tracing::debug;

use super::{DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel, ProcessMonitorConfig};

#[derive(Clone)]
pub struct ProcessMonitor {
    pub config: ProcessMonitorConfig,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::new()); // Refresh process list

        debug!("Scanning {} processes", system.processes().len());

        for (pid, process) in system.processes() {
            let process_name = process.name().to_lowercase();
            let command_line = process.cmd().join(" ").to_lowercase();

            // Skip whitelisted processes
            if self.config.whitelist.iter().any(|w| process_name.contains(w)) {
                continue;
            }

            let mut matched_patterns = Vec::new();
            let mut threat_level = ThreatLevel::Info;

            // Check against AI process patterns
            for pattern in &self.config.ai_process_patterns {
                if process_name.contains(&pattern.to_lowercase()) || 
                   (self.config.monitor_command_line && command_line.contains(&pattern.to_lowercase())) {
                    matched_patterns.push(pattern.clone());
                    threat_level = threat_level.max(ThreatLevel::High);
                }
            }

            // Check for suspicious child processes (simplified)
            if self.config.monitor_child_processes {
                // In a real scenario, this would involve more complex parent-child relationship analysis
                // For now, we'll just check if the process name itself is suspicious
                if matched_patterns.is_empty() && self.is_suspicious_process_name(&process_name) {
                    matched_patterns.push(format!("Suspicious process name: {}", process_name));
                    threat_level = threat_level.max(ThreatLevel::Medium);
                }
            }

            if !matched_patterns.is_empty() {
                events.push(self.create_process_event(
                    *pid,
                    process.name().to_string(),
                    process.cmd().join(" "),
                    process.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                    process.parent().map(|p| p.as_u32()),
                    matched_patterns,
                    threat_level,
                ));
            }
        }

        debug!("Found {} suspicious processes", events.len());
        Ok(events)
    }

    pub fn update_config(&mut self, config: ProcessMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn is_suspicious_process_name(&self, process_name: &str) -> bool {
        let suspicious_keywords = [
            "ai", "ml", "gpt", "llm", "bot", "agent", "daemon", "service",
            "hidden", "stealth", "monitor", "hook", "inject", "proxy",
        ];
        suspicious_keywords.iter().any(|k| process_name.contains(k))
    }

    fn create_process_event(
        &self,
        pid: sysinfo::Pid,
        name: String,
        command_line: String,
        executable_path: String,
        parent_pid: Option<u32>,
        matched_patterns: Vec<String>,
        threat_level: ThreatLevel,
    ) -> DetectionEvent {
        DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Process Activity".to_string(),
            module: DetectionModule::ProcessMonitor,
            threat_level,
            description: format!("Suspicious process detected: {} (PID: {})", name, pid),
            details: DetectionDetails::Process {
                pid: pid.as_u32(),
                name,
                command_line,
                executable_path,
                parent_pid,
                matched_patterns,
            },
            timestamp: Utc::now(),
            source: Some("Process Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }
}
