use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration};
use std::process::Command;
use std::fs;
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};
use crate::config::{SyscallConfig, SyscallPatternConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_name: String,
    pub syscall_number: u32,
    pub arguments: Vec<String>,
    pub timestamp: SystemTime,
    pub process_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPattern {
    pub name: String,
    pub syscalls: Vec<String>,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIDetection {
    pub pattern_name: String,
    pub confidence: f64,
    pub pid: u32,
    pub process_name: String,
    pub matching_syscalls: Vec<String>,
    pub timestamp: SystemTime,
}

pub struct SyscallMonitor {
    config: SyscallConfig,
    monitoring_active: bool,
    ai_patterns: Vec<SyscallPatternConfig>, // Changed type to SyscallPatternConfig
    process_syscall_history: HashMap<u32, VecDeque<SyscallEvent>>,
    history_limit: usize,
    detection_window: Duration,
}

impl SyscallMonitor {
    pub fn new(config: SyscallConfig) -> Self {
        let ai_patterns = config.ai_patterns.clone(); // Clone patterns before moving config
        SyscallMonitor {
            config,
            monitoring_active: false,
            ai_patterns,
            process_syscall_history: HashMap::new(),
            history_limit: 1000,
            detection_window: Duration::from_secs(30),
        }
    }

    pub fn start_monitoring(&mut self) -> Result<(), String> {
        if !self.config.enabled {
            info!("Syscall monitoring is disabled in configuration.");
            return Ok(());
        }

        if self.monitoring_active {
            return Ok(());
        }

        // Check if we can use strace for syscall monitoring
        if !self.check_strace_available() {
            return Err("strace not available for syscall monitoring".to_string());
        }

        self.monitoring_active = true;
        info!("Syscall monitoring started");
        Ok(())
    }

    fn check_strace_available(&self) -> bool {
        Command::new("which")
            .arg("strace")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    pub fn monitor_process(&mut self, pid: u32) -> Result<Vec<SyscallEvent>, String> {
        if !self.monitoring_active {
            return Err("Monitoring not active".to_string());
        }

        let output = Command::new("strace")
            .args(&["-p", &pid.to_string(), "-e", "trace=all", "-f", "-q", "-o", "/dev/stdout"])
            .arg("-T")  // Show time spent in syscalls
            .arg("-tt") // Show time with microseconds
            .output()
            .map_err(|e| format!("Failed to run strace: {}", e))?;

        if !output.status.success() {
            return Err(format!("strace failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_strace_output(&stdout, pid)
    }

    pub fn monitor_new_processes(&mut self) -> Vec<SyscallEvent> {
        let mut events = Vec::new();
        
        // Monitor new process creation via /proc
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    // Skip if we're already monitoring this process
                    if self.process_syscall_history.contains_key(&pid) {
                        continue;
                    }

                    // Check if this is a potentially interesting process
                    if let Some(process_info) = self.get_process_info(pid) {
                        if self.is_suspicious_process(&process_info) {
                            // Start monitoring this process
                            match self.monitor_process(pid) {
                                Ok(mut proc_events) => events.append(&mut proc_events),
                                Err(e) => warn!("Failed to monitor process {}: {}", pid, e),
                            }
                        }
                    }
                }
            }
        }

        events
    }

    fn parse_strace_output(&mut self, output: &str, pid: u32) -> Result<Vec<SyscallEvent>, String> {
        let mut events = Vec::new();
        let process_name = self.get_process_name(pid).unwrap_or_else(|| format!("pid_{}", pid));

        for line in output.lines() {
            if let Some(event) = self.parse_syscall_line(line, pid, &process_name) {
                events.push(event.clone());
                
                // Add to process history
                let history = self.process_syscall_history
                    .entry(pid)
                    .or_insert_with(VecDeque::new);
                
                history.push_back(event);
                
                // Limit history size
                if history.len() > self.history_limit {
                    history.pop_front();
                }
            }
        }

        Ok(events)
    }

    fn parse_syscall_line(&self, line: &str, pid: u32, process_name: &str) -> Option<SyscallEvent> {
        // Parse strace output format: "12:34:56.789 syscall(args) = result"
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return None;
        }

        // Extract syscall name and arguments
        let syscall_part = parts[1];
        let paren_pos = syscall_part.find('(')?;
        let syscall_name = syscall_part[..paren_pos].to_string();
        
        let args_end = syscall_part.rfind(')')?;
        let args_str = &syscall_part[paren_pos + 1..args_end];
        let arguments: Vec<String> = args_str
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Get syscall number (simplified - in reality, this would need a lookup table)
        let syscall_number = self.get_syscall_number(&syscall_name);

        Some(SyscallEvent {
            pid,
            syscall_name,
            syscall_number,
            arguments,
            timestamp: SystemTime::now(),
            process_name: process_name.to_string(),
        })
    }

    fn get_syscall_number(&self, syscall_name: &str) -> u32 {
        // Simplified syscall number mapping
        // In a real implementation, this would use the actual syscall table
        match syscall_name {
            "read" => 0,
            "write" => 1,
            "open" => 2,
            "openat" => 257,
            "close" => 3,
            "stat" => 4,
            "fstat" => 5,
            "mmap" => 9,
            "munmap" => 11,
            "brk" => 12,
            "ioctl" => 16,
            "access" => 21,
            "socket" => 41,
            "connect" => 42,
            "sendto" => 44,
            "recvfrom" => 45,
            "execve" => 59,
            "mprotect" => 10,
            "madvise" => 28,
            _ => 999, // Unknown
        }
    }

    pub fn analyze_patterns(&self) -> Vec<AIDetection> {
        let mut detections = Vec::new();
        let now = SystemTime::now();

        if !self.config.enabled {
            return detections;
        }

        for (&pid, history) in &self.process_syscall_history {
            // Only analyze recent events
            let recent_events: Vec<&SyscallEvent> = history
                .iter()
                .filter(|event| {
                    now.duration_since(event.timestamp)
                        .unwrap_or(Duration::from_secs(0)) < self.detection_window
                })
                .collect();

            if recent_events.is_empty() {
                continue;
            }

            let process_name = recent_events[0].process_name.clone();

            for pattern in &self.config.ai_patterns { // Use config for patterns
                let matching_syscalls = self.find_pattern_matches(&recent_events, pattern);
                
                if !matching_syscalls.is_empty() {
                    let confidence = self.calculate_pattern_confidence(pattern, &matching_syscalls, &recent_events);
                    
                    if confidence > 0.5 {
                        detections.push(AIDetection {
                            pattern_name: pattern.name.clone(),
                            confidence,
                            pid,
                            process_name: process_name.clone(),
                            matching_syscalls,
                            timestamp: now,
                        });
                    }
                }
            }
        }

        detections
    }

    fn find_pattern_matches(&self, events: &[&SyscallEvent], pattern: &SyscallPatternConfig) -> Vec<String> { // Changed pattern type
        let mut matches = Vec::new();
        let event_syscalls: Vec<&str> = events.iter().map(|e| e.syscall_name.as_str()).collect();

        for required_syscall in &pattern.syscalls {
            if event_syscalls.contains(&required_syscall.as_str()) {
                matches.push(required_syscall.clone());
            }
        }

        matches
    }

    fn calculate_pattern_confidence(&self, pattern: &SyscallPatternConfig, matches: &[String], events: &[&SyscallEvent]) -> f64 { // Changed pattern type
        let base_confidence = pattern.confidence;
        let match_ratio = matches.len() as f64 / pattern.syscalls.len() as f64;
        
        // Boost confidence based on frequency of matching syscalls
        let mut frequency_bonus = 0.0;
        for syscall in matches {
            let count = events.iter().filter(|e| &e.syscall_name == syscall).count();
            frequency_bonus += (count as f64).log10().max(0.0) * 0.1;
        }

        // Boost confidence for specific patterns
        let mut pattern_bonus = 0.0;
        if pattern.name == "GPU_Computing" {
            // Look for GPU-specific file paths in arguments
            for event in events {
                for arg in &event.arguments {
                    if arg.contains("/dev/dri") || arg.contains("/dev/nvidia") {
                        pattern_bonus += 0.2;
                        break;
                    }
                }
            }
        }

        (base_confidence * match_ratio + frequency_bonus + pattern_bonus).min(1.0)
    }

    fn get_process_info(&self, pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/comm", pid)).ok()
            .map(|s| s.trim().to_string())
    }

    fn get_process_name(&self, pid: u32) -> Option<String> {
        self.get_process_info(pid)
    }

    fn is_suspicious_process(&self, process_name: &str) -> bool {
        let suspicious_names = [
            "python", "python3", "node", "java", 
            "ollama", "llamacpp", "gpt4all", "oobabooga",
            "torch", "tensorflow", "transformers"
        ];

        let name_lower = process_name.to_lowercase();
        suspicious_names.iter().any(|&suspicious| name_lower.contains(suspicious))
    }

    pub fn cleanup_old_history(&mut self) {
        let now = SystemTime::now();
        let cleanup_threshold = Duration::from_secs(3600); // 1 hour

        self.process_syscall_history.retain(|_pid, history| {
            history.retain(|event| {
                now.duration_since(event.timestamp)
                    .unwrap_or(Duration::from_secs(0)) < cleanup_threshold
            });
            !history.is_empty()
        });
    }

    pub fn stop_monitoring(&mut self) {
        self.monitoring_active = false;
        info!("Syscall monitoring stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyscallConfig;

    fn create_test_config() -> SyscallConfig {
        SyscallConfig {
            enabled: true,
            ai_patterns: vec![
                SyscallPatternConfig {
                    name: "GPU_Computing".to_string(),
                    syscalls: vec!["openat".to_string(), "ioctl".to_string()],
                    confidence: 0.7,
                    description: "Test GPU pattern".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_pattern_matching() {
        let config = create_test_config();
        let monitor = SyscallMonitor::new(config);
        let events = vec![
            SyscallEvent {
                pid: 123,
                syscall_name: "openat".to_string(),
                syscall_number: 257,
                arguments: vec!["/dev/nvidia0".to_string()],
                timestamp: SystemTime::now(),
                process_name: "python".to_string(),
            },
            SyscallEvent {
                pid: 123,
                syscall_name: "ioctl".to_string(),
                syscall_number: 16,
                arguments: vec!["GPU_COMMAND".to_string()],
                timestamp: SystemTime::now(),
                process_name: "python".to_string(),
            },
        ];

        let event_refs: Vec<&SyscallEvent> = events.iter().collect();
        let gpu_pattern = &monitor.config.ai_patterns[0]; // GPU_Computing pattern
        
        let matches = monitor.find_pattern_matches(&event_refs, gpu_pattern);
        assert!(!matches.is_empty());
        
        let confidence = monitor.calculate_pattern_confidence(gpu_pattern, &matches, &event_refs);
        assert!(confidence > 0.5);
    }
}
