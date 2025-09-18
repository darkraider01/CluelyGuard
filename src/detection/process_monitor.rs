//! Enhanced Process monitoring module with comprehensive AI detection

use anyhow::Result;
use chrono::Utc;
use sysinfo::{ProcessRefreshKind, System, Process, Pid};
use std::collections::{HashMap, HashSet};
use tracing::{debug};
use regex::Regex;

use super::{DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel, ProcessMonitorConfig};

#[derive(Clone)]
pub struct ProcessMonitor {
    pub config: ProcessMonitorConfig,
    known_ai_processes: HashSet<String>,
    suspicious_patterns: Vec<Regex>,
}

impl ProcessMonitor {
    pub fn new(config: ProcessMonitorConfig) -> Result<Self> {
        let known_ai_processes = Self::build_ai_process_database();
        let suspicious_patterns = Self::build_regex_patterns()?;
        
        Ok(Self { 
            config,
            known_ai_processes,
            suspicious_patterns,
        })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessRefreshKind::new());

        debug!("Scanning {} processes with enhanced AI detection", system.processes().len());

        // First pass: collect all processes for analysis
        #[allow(unused_variables)]
        let mut process_tree = HashMap::new();
        let mut browser_processes = Vec::new();
        
        for (pid, process) in system.processes() {
            process_tree.insert(*pid, process);
            
            // Identify browser processes for special handling
            if self.is_browser_process(process) {
                browser_processes.push((*pid, process));
            }
        }

        // Analyze each process
        for (pid, process) in system.processes() {
            // Skip whitelisted processes
            if self.is_whitelisted_process(process) {
                continue;
            }

            let mut detection_results = Vec::new();
            // Multiple detection methods
            detection_results.extend(self.detect_known_ai_processes(process));
            detection_results.extend(self.detect_ai_patterns(process));
            detection_results.extend(self.detect_suspicious_behavior(process, &process_tree));
            
            // Special analysis for browser processes
            if self.is_browser_process(process) {
                detection_results.extend(self.analyze_browser_process(process).await);
            }

            // Analyze command line arguments
            if self.config.monitor_command_line {
                detection_results.extend(self.analyze_command_line(process));
            }

            // Analyze child processes
            if self.config.monitor_child_processes {
                detection_results.extend(self.analyze_child_processes(*pid, process, &process_tree));
            }

            // Determine threat level
            let threat_level = if !detection_results.is_empty() {
                detection_results.iter()
                    .map(|(level, _)| *level) // Dereference the threat level
                    .max()
                    .unwrap_or(ThreatLevel::Info)
            } else {
                ThreatLevel::Info // Default if no detections
            };

            let matched_patterns: Vec<String> = detection_results
                .iter()
                .map(|(_, pattern)| pattern.clone())
                .collect();
 
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

        // Additional system-wide analysis
        events.extend(self.analyze_system_wide_patterns(&system).await);

        debug!("Found {} suspicious processes", events.len());
        Ok(events)
    }

    fn build_ai_process_database() -> HashSet<String> {
        let mut db = HashSet::new();
        
        // Direct AI application names
        let ai_apps = [
            // ChatGPT Desktop Apps
            "chatgpt", "chatgpt.exe", "chatgpt-desktop",
            
            // Claude Desktop
            "claude", "claude.exe", "claude-desktop",
            
            // AI Coding Assistants
            "github-copilot", "copilot", "copilot.exe",
            "tabnine", "tabnine.exe", "tabnine-language-server",
            "codewhisperer", "amazon-codewhisperer",
            
            // AI Writing Tools
            "grammarly", "grammarly.exe", "grammarly-desktop",
            "jasper", "jasper.exe",
            "writesonic", "writesonic.exe",
            "notion-ai", "notion.exe",
            
            // AI Research Tools
            "elicit", "elicit.exe",
            "consensus", "consensus.exe",
            
            // Other AI Applications
            "otter", "otter.exe", "otter.ai",
            "fireflies", "fireflies.exe",
            "character-ai", "character.ai",
            
            // AI Development Tools
            "jupyter", "jupyter-lab", "jupyter-notebook",
            "python", "python3", "python.exe", // When running AI scripts
            "node", "nodejs", // For AI web apps
            
            // Browser apps running AI services
            "chrome --app=https://chat.openai.com",
            "chrome --app=https://claude.ai",
            "chrome --app=https://gemini.google.com",
        ];
        
        for app in &ai_apps {
            db.insert(app.to_lowercase());
        }
        
        db
    }

    fn build_regex_patterns() -> Result<Vec<Regex>> {
        let patterns = [
            // AI-related process names
            r"(?i)(gpt|claude|gemini|bard|copilot|ai|assistant|bot|llm|ml)",
            
            // URLs in command lines
            r"(?i)(openai\.com|claude\.ai|gemini\.google\.com|perplexity\.ai|character\.ai)",
            
            // AI development patterns
            r"(?i)(transformers|langchain|openai|anthropic|huggingface)",
            
            // Suspicious AI-related arguments
            r"(?i)(--api[_-]key|--openai|--anthropic|--model[_-]name)",
        ];

        let mut regexes = Vec::new();
        for pattern in &patterns {
            regexes.push(Regex::new(pattern)?);
        }
        
        Ok(regexes)
    }

    fn detect_known_ai_processes(&self, process: &Process) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        let process_name = process.name().to_lowercase();
        
        if self.known_ai_processes.contains(&process_name) {
            results.push((
                ThreatLevel::Critical, 
                format!("Known AI application: {}", process.name())
            ));
        }
        
        // Check if process name contains AI keywords
        let ai_keywords = ["gpt", "claude", "gemini", "copilot", "ai", "assistant", "bot"];
        for keyword in &ai_keywords {
            if process_name.contains(keyword) && !self.is_false_positive(&process_name, keyword) {
                results.push((
                    ThreatLevel::High,
                    format!("AI-related process name contains '{}'", keyword)
                ));
            }
        }
        
        results
    }

    fn detect_ai_patterns(&self, process: &Process) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        let full_command = process.cmd().join(" ");
        
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(&full_command) {
                results.push((
                    ThreatLevel::Medium,
                    format!("Suspicious AI pattern in command: {}", pattern.as_str())
                ));
            }
        }
        
        results
    }

    fn detect_suspicious_behavior(&self, process: &Process, _process_tree: &HashMap<Pid, &Process>) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        
        // High CPU usage (potential AI computation)
        if process.cpu_usage() > 80.0 {
            results.push((
                ThreatLevel::Low,
                "High CPU usage - potential AI computation".to_string()
            ));
        }
        
        // High memory usage
        if process.memory() > 1_000_000_000 { // 1GB
            results.push((
                ThreatLevel::Low,
                "High memory usage - potential AI model loading".to_string()
            ));
        }
        
        // Check for Python processes running AI libraries
        if process.name().to_lowercase().contains("python") {
            let cmd = process.cmd().join(" ");
            let ai_libraries = ["torch", "tensorflow", "transformers", "openai", "anthropic"];
            for lib in &ai_libraries {
                if cmd.to_lowercase().contains(lib) {
                    results.push((
                        ThreatLevel::High,
                        format!("Python process using AI library: {}", lib)
                    ));
                }
            }
        }
        
        results
    }

    async fn analyze_browser_process(&self, process: &Process) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        let cmd = process.cmd().join(" ");
        
        // Check for AI service URLs in browser command line
        let ai_urls = [
            "chat.openai.com", "claude.ai", "gemini.google.com",
            "perplexity.ai", "poe.com", "character.ai", "you.com",
            "copilot.microsoft.com", "bing.com/chat"
        ];
        
        for url in &ai_urls {
            if cmd.to_lowercase().contains(&url.to_lowercase()) {
                results.push((
                    ThreatLevel::Critical,
                    format!("Browser accessing AI service: {}", url)
                ));
            }
        }

        // Check for browser extensions in command line
        if cmd.contains("extension") || cmd.contains("load-extension") {
            results.push((
                ThreatLevel::Medium,
                "Browser running with extensions - potential AI extensions".to_string()
            ));
        }
        
        results
    }

    fn analyze_command_line(&self, process: &Process) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        let cmd = process.cmd().join(" ");
        
        // Look for API keys in command line
        let api_patterns = [
            "sk-", "ak_", "api_key", "apikey", "--api-key"
        ];
        
        for pattern in &api_patterns {
            if cmd.to_lowercase().contains(pattern) {
                results.push((
                    ThreatLevel::High,
                    format!("Potential API key in command line: {}", pattern)
                ));
            }
        }
        
        // Look for AI service endpoints
        let endpoints = [
            "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"
        ];
        
        for endpoint in &endpoints {
            if cmd.to_lowercase().contains(endpoint) {
                results.push((
                    ThreatLevel::Critical,
                    format!("AI API endpoint in command: {}", endpoint)
                ));
            }
        }
        
        results
    }

    fn analyze_child_processes(&self, parent_pid: Pid, parent: &Process, process_tree: &HashMap<Pid, &Process>) -> Vec<(ThreatLevel, String)> {
        let mut results = Vec::new();
        
        // Find child processes
        let child_pids: Vec<_> = process_tree.iter()
            .filter(|(_, proc)| proc.parent() == Some(parent_pid))
            .map(|(pid, _)| *pid)
            .collect();
        
        if child_pids.len() > 5 {
            results.push((
                ThreatLevel::Low,
                format!("Process spawned {} child processes", child_pids.len())
            ));
        }
        
        // Check if parent is browser and children are suspicious
        if self.is_browser_process(parent) {
            for child_pid in &child_pids {
                if let Some(child) = process_tree.get(child_pid) {
                    let child_name = child.name().to_lowercase();
                    if child_name.contains("python") || child_name.contains("node") {
                        results.push((
                            ThreatLevel::Medium,
                            format!("Browser spawned suspicious child process: {}", child.name())
                        ));
                    }
                }
            }
        }
        
        results
    }

    async fn analyze_system_wide_patterns(&self, system: &System) -> Vec<DetectionEvent> {
        let mut events = Vec::new();
        
        // Count AI-related processes
        let ai_process_count = system.processes()
            .values()
            .filter(|p| self.is_potential_ai_process(p))
            .count();
        
        if ai_process_count >= 3 {
            events.push(DetectionEvent {
                id: uuid::Uuid::new_v4(),
                detection_type: "System-wide Analysis".to_string(),
                module: DetectionModule::ProcessMonitor,
                threat_level: ThreatLevel::High,
                description: format!("{} AI-related processes detected simultaneously", ai_process_count),
                details: DetectionDetails::Process {
                    pid: 0,
                    name: "System Analysis".to_string(),
                    command_line: format!("{} concurrent AI processes", ai_process_count),
                    executable_path: "system_analysis".to_string(),
                    parent_pid: None,
                    matched_patterns: vec![format!("High AI process count: {}", ai_process_count)],
                },
                timestamp: Utc::now(),
                source: Some("System-wide Process Analyzer".to_string()),
                metadata: HashMap::new(),
            });
        }
        
        events
    }

    fn is_browser_process(&self, process: &Process) -> bool {
        let name = process.name().to_lowercase();
        let browsers = [
            "chrome", "chromium", "firefox", "safari", "edge", 
            "brave", "opera", "vivaldi", "arc", "yandex"
        ];
        
        browsers.iter().any(|browser| name.contains(browser))
    }

    fn is_whitelisted_process(&self, process: &Process) -> bool {
        let name = process.name().to_lowercase();
        
        // System processes
        let system_processes = [
            "systemd", "kernel", "kthreadd", "init", "explorer.exe",
            "dwm.exe", "winlogon.exe", "csrss.exe", "services.exe"
        ];
        
        if system_processes.iter().any(|sys_proc| name.contains(sys_proc)) {
            return true;
        }
        
        // User-defined whitelist
        self.config.whitelist.iter().any(|w| name.contains(&w.to_lowercase()))
    }

    fn is_potential_ai_process(&self, process: &Process) -> bool {
        let name = process.name().to_lowercase();
        let cmd = process.cmd().join(" ").to_lowercase();
        
        let indicators = [
            "gpt", "claude", "gemini", "ai", "copilot", "assistant",
            "openai", "anthropic", "chat", "bot"
        ];
        
        indicators.iter().any(|indicator| 
            name.contains(indicator) || cmd.contains(indicator)
        )
    }

    fn is_false_positive(&self, process_name: &str, keyword: &str) -> bool {
        // Common false positives
        let false_positives = HashMap::from([
            ("ai", vec!["aio", "kwayland", "plasmoidviewer"]),
            ("bot", vec!["robot", "bluetooth"]),
        ]);
        
        if let Some(fps) = false_positives.get(keyword) {
            return fps.iter().any(|fp| process_name.contains(fp));
        }
        
        false
    }

    fn create_process_event(
        &self,
        pid: Pid,
        name: String,
        command_line: String,
        executable_path: String,
        parent_pid: Option<u32>,
        matched_patterns: Vec<String>,
        threat_level: ThreatLevel,
    ) -> DetectionEvent {
        DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "AI Process Activity".to_string(),
            module: DetectionModule::ProcessMonitor,
            threat_level,
            description: format!("AI-related process detected: {} (PID: {})", name, pid),
            details: DetectionDetails::Process {
                pid: pid.as_u32(),
                name,
                command_line,
                executable_path,
                parent_pid,
                matched_patterns,
            },
            timestamp: Utc::now(),
            source: Some("Enhanced Process Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }

    pub fn update_config(&mut self, config: ProcessMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }
}