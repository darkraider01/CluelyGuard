use crate::config::AppConfig;
use procfs::process::all_processes;
use std::collections::HashMap;
use tracing::{info, warn};

/// Result of a process scan operation
#[derive(Debug, Clone)]
pub struct ProcessScanResult {
    pub suspicious_processes: Vec<SuspiciousProcess>,
    pub total_processes_scanned: usize,
    pub scan_duration_ms: u64,
}

/// Represents a suspicious process detected during scanning
#[derive(Debug, Clone)]
pub struct SuspiciousProcess {
    pub pid: i32,
    pub name: String,
    pub path: String,
    pub reason: SuspicionReason,
    pub confidence: f64,
}

/// Different reasons why a process was flagged as suspicious
#[derive(Debug, Clone)]
pub enum SuspicionReason {
    /// Process name/path matches a configured suspicious binary
    MatchesConfiguredBinary(String),
    /// Process matches a known AI tool pattern
    MatchesAiPattern(String),
    /// Process contains AI-related keywords
    HasAiKeywords(Vec<String>),
    /// Process has suspicious command line arguments
    SuspiciousCommandLine(Vec<String>),
    /// Process shows suspicious behavior patterns (new AI tools, stealth tools)
    SuspiciousBehavior(SuspiciousBehaviorType),
    /// Process memory contains patterns indicative of LLM usage
    MemoryPatternMatch(String),
    /// Process accesses files indicative of LLM usage
    FileAccessPattern(String),
}

/// Types of suspicious behavior that might indicate AI tool usage
#[derive(Debug, Clone)]
pub enum SuspiciousBehaviorType {
    /// Process with unusual network activity (API calls to AI services)
    UnusualNetworkActivity,
    /// Process with high CPU usage but low user interaction
    HighCpuLowInteraction,
    /// Process with suspicious file access patterns
    SuspiciousFileAccess,
    /// Process with unusual memory patterns
    UnusualMemoryPatterns,
    /// Process that appears to be a stealth AI tool
    StealthAiTool,
    /// Process with suspicious timing patterns
    SuspiciousTiming,
}

/// Scans all running processes for suspicious AI tools
/// 
/// This function uses multiple detection methods:
/// 
/// 1. **Configured Binary Matching** (90% confidence)
///    - Checks against user-defined suspicious_binaries in config
///    - Example: "chatgpt", "claude", "my-custom-ai-tool"
/// 
/// 2. **AI Pattern Recognition** (50-95% confidence)
///    - Built-in patterns for known AI tools
///    - Example: "chatgpt" -> 95%, "assistant" -> 70%
/// 
/// 3. **Keyword Analysis** (70% confidence)
///    - Searches process names/paths for AI-related terms
///    - Example: "artificial intelligence", "gpt-4", "voice-to-text"
/// 
/// 4. **Command Line Analysis** (60% confidence)
///    - Detects AI tools launched with suspicious arguments
///    - Example: "python3 -m openai.chat", "./ai-tool --model=gpt-4"
/// 
/// # Examples
///
/// // Detects ChatGPT desktop app
/// // Process: "ChatGPT.exe" -> 95% confidence (MatchesAiPattern)
///
/// // Detects custom AI tool
/// // Process: "my-homework-helper" -> 90% confidence (MatchesConfiguredBinary)
///
/// // Detects AI tool with suspicious args
/// // Process: "python3" with args ["-m", "openai.chat"] -> 60% confidence (SuspiciousCommandLine)
///
/// // Detects process with AI keywords
/// // Process: "voice-to-text-assistant" -> 70% confidence (HasAiKeywords)
pub fn scan(config: &AppConfig) -> ProcessScanResult {
    let start_time = std::time::Instant::now();
    
    info!("🔍 Scanning processes for suspicious AI tools...");
    
    let mut suspicious_processes = Vec::new();
    let mut total_scanned = 0;

    // Get configured suspicious binaries from user config
    let configured_binaries = &config.monitoring.process.suspicious_binaries;
    
    // Get built-in AI patterns and keywords
    let ai_patterns = get_ai_patterns();
    let ai_keywords = get_ai_keywords();

    match all_processes() {
        Ok(processes) => {
            for proc_result in processes {
                if let Ok(proc) = proc_result {
                    total_scanned += 1;
                    
                    if let Some(suspicious) = analyze_process(&proc, configured_binaries.as_slice(), &ai_patterns, &ai_keywords) {
                        suspicious_processes.push(suspicious);
                    }
                }
            }
        }
        Err(e) => {
            warn!("❌ Failed to enumerate processes: {}", e);
        }
    }

    let scan_duration = start_time.elapsed().as_millis() as u64;

    if suspicious_processes.is_empty() {
        info!("✅ No suspicious processes found (scanned {} processes in {}ms)", total_scanned, scan_duration);
    } else {
        warn!("🚨 Found {} suspicious processes (scanned {} processes in {}ms)", 
              suspicious_processes.len(), total_scanned, scan_duration);
        
        for proc in &suspicious_processes {
            log_suspicious_process(proc);
        }
    }

    ProcessScanResult {
        suspicious_processes,
        total_processes_scanned: total_scanned,
        scan_duration_ms: scan_duration,
    }
}

/// Analyzes a single process to determine if it's suspicious
/// 
/// Uses multiple detection methods in order of confidence:
/// 1. Configured binary matching (highest confidence)
/// 2. AI pattern matching (high confidence)
/// 3. Keyword analysis (medium confidence)
/// 4. Command line analysis (lower confidence)
fn analyze_process(
    proc: &procfs::process::Process,
    configured_binaries: &[String],
    ai_patterns: &HashMap<String, f64>,
    ai_keywords: &[String],
) -> Option<SuspiciousProcess> {
    let pid = proc.pid();
    
    // Get executable path
    let exe_path = match proc.exe() {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(_) => return None,
    };
    
    // Get process name
    let process_name = match proc.stat() {
        Ok(stat) => stat.comm,
        Err(_) => return None,
    };
    
    // Get command line arguments
    let cmdline = proc.cmdline().ok().unwrap_or_default();
    
    // Method 1: Check against configured binaries (90% confidence)
    for binary in configured_binaries {
        if exe_path.to_lowercase().contains(&binary.to_lowercase()) || 
           process_name.to_lowercase().contains(&binary.to_lowercase()) {
            return Some(SuspiciousProcess {
                pid,
                name: process_name.clone(),
                path: exe_path.clone(),
                reason: SuspicionReason::MatchesConfiguredBinary(binary.clone()),
                confidence: 0.9,
            });
        }
    }
    
    // Method 2: Check against AI patterns (50-95% confidence)
    for (pattern, confidence) in ai_patterns {
        if exe_path.to_lowercase().contains(&pattern.to_lowercase()) || 
           process_name.to_lowercase().contains(&pattern.to_lowercase()) {
            return Some(SuspiciousProcess {
                pid,
                name: process_name.clone(),
                path: exe_path.clone(),
                reason: SuspicionReason::MatchesAiPattern(pattern.clone()),
                confidence: *confidence,
            });
        }
    }
    
    // Method 3: Check for AI keywords in process name or path (70% confidence)
    let mut found_keywords = Vec::new();
    let search_text = format!("{} {}", process_name, exe_path).to_lowercase();
    
    for keyword in ai_keywords {
        if search_text.contains(&keyword.to_lowercase()) {
            found_keywords.push(keyword.clone());
        }
    }
    
    if !found_keywords.is_empty() {
        return Some(SuspiciousProcess {
            pid,
            name: process_name.clone(),
            path: exe_path.clone(),
            reason: SuspicionReason::HasAiKeywords(found_keywords),
            confidence: 0.7,
        });
    }
    
    // Method 4: Check command line for suspicious arguments (60% confidence)
    let mut suspicious_args = Vec::new();
    for arg in &cmdline {
        let arg_lower = arg.to_lowercase();
        if ai_keywords.iter().any(|keyword| arg_lower.contains(&keyword.to_lowercase())) {
            suspicious_args.push(arg.clone());
        }
    }
    
    if !suspicious_args.is_empty() {
        return Some(SuspiciousProcess {
            pid,
            name: process_name.clone(),
            path: exe_path.clone(),
            reason: SuspicionReason::SuspiciousCommandLine(suspicious_args),
            confidence: 0.6,
        });
    }
    
    // Method 5: Check for suspicious memory patterns (75% confidence)
    if let Some(pattern) = check_memory_patterns(pid) {
        return Some(SuspiciousProcess {
            pid,
            name: process_name.clone(),
            path: exe_path.clone(),
            reason: SuspicionReason::MemoryPatternMatch(pattern),
            confidence: 0.75,
        });
    }

    // Method 6: Check for suspicious file access patterns (75% confidence)
    if let Some(file_path) = check_file_access(pid) {
        return Some(SuspiciousProcess {
            pid,
            name: process_name.clone(),
            path: exe_path.clone(),
            reason: SuspicionReason::FileAccessPattern(file_path),
            confidence: 0.75,
        });
    }

    // Method 7: Behavioral analysis for unknown/stealth AI tools (40-70% confidence)
    if let Some(behavior) = analyze_suspicious_behavior(&proc, &process_name, &exe_path) {
        return Some(SuspiciousProcess {
            pid,
            name: process_name.clone(),
            path: exe_path.clone(),
            reason: SuspicionReason::SuspiciousBehavior(behavior),
            confidence: 0.5, // Lower confidence for behavioral detection
        });
    }
    
    None
}

/// Analyzes process behavior to detect unknown or stealth AI tools
/// 
/// This method looks for suspicious behavior patterns that might indicate
/// AI tool usage even when the process doesn't match known patterns.
fn analyze_suspicious_behavior(
    proc: &procfs::process::Process,
    process_name: &str,
    exe_path: &str,
) -> Option<SuspiciousBehaviorType> {
    let pid = proc.pid();
    
    // Check for stealth AI tool indicators
    if is_stealth_ai_tool(process_name, exe_path) {
        return Some(SuspiciousBehaviorType::StealthAiTool);
    }
    
    // Check for unusual network activity (API calls to AI services)
    if has_unusual_network_activity(pid) {
        return Some(SuspiciousBehaviorType::UnusualNetworkActivity);
    }
    
    // Check for high CPU usage with low user interaction
    if has_high_cpu_low_interaction(proc) {
        return Some(SuspiciousBehaviorType::HighCpuLowInteraction);
    }
    
    // Check for suspicious file access patterns
    if has_suspicious_file_access(proc) {
        return Some(SuspiciousBehaviorType::SuspiciousFileAccess);
    }
    
    // Check for unusual memory patterns
    if has_unusual_memory_patterns(proc) {
        return Some(SuspiciousBehaviorType::UnusualMemoryPatterns);
    }
    
    // Check for suspicious timing patterns
    if has_suspicious_timing(proc) {
        return Some(SuspiciousBehaviorType::SuspiciousTiming);
    }
    
    None
}

/// Detects stealth AI tools that try to avoid detection
fn is_stealth_ai_tool(process_name: &str, exe_path: &str) -> bool {
    let stealth_indicators = [
        // Generic names that might hide AI tools
        "helper", "assistant", "tool", "utility", "service", "daemon",
        "background", "worker", "task", "process", "app", "program",
        
        // Names that might indicate AI tools in disguise
        "text", "writing", "compose", "generate", "create", "suggest",
        "complete", "predict", "analyze", "process", "transform",
        
        // Suspicious naming patterns
        "ai_", "ml_", "gpt_", "claude_", "openai_", "anthropic_",
        "_ai", "_ml", "_gpt", "_claude", "_openai", "_anthropic",
    ];
    
    let search_text = format!("{} {}", process_name, exe_path).to_lowercase();
    
    // Check for stealth indicators
    for indicator in &stealth_indicators {
        if search_text.contains(indicator) {
            // Additional checks to reduce false positives
            if !is_legitimate_system_process(process_name, exe_path) {
                return true;
            }
        }
    }
    
    false
}

/// Checks if a process is a legitimate system process (to reduce false positives)
fn is_legitimate_system_process(process_name: &str, exe_path: &str) -> bool {
    let legitimate_processes = [
        // System processes
        "systemd", "init", "kthreadd", "ksoftirqd", "kworker",
        "migration", "watchdog", "cpuhp", "kdevtmpfs", "netns",
        "rcu_gp", "rcu_par_gp", "kworker", "kcompactd", "kswapd",
        "kthrotld", "acpi_thermal_pm", "kblockd", "ata_sff",
        "md", "edac-poller", "devfreq_wq", "watchdogd", "netdev",
        "kworker", "kmpath_rdacd", "kmpathd", "kmpath_handlerd",
        "bioset", "cryptd", "md_misc", "dm_bufio", "kdmflush",
        "bioset", "kdmflush", "kcryptd_io", "kcryptd", "dmcrypt_write",
        "dm-0", "dm-1", "dm-2", "dm-3", "dm-4", "dm-5", "dm-6", "dm-7",
        
        // Common legitimate applications
        "chrome", "firefox", "safari", "edge", "brave", "opera",
        "code", "vscode", "sublime", "vim", "emacs", "nano",
        "terminal", "gnome-terminal", "konsole", "xterm",
        "explorer", "finder", "nautilus", "dolphin", "thunar",
        "calculator", "calc", "gnome-calculator", "kcalc",
        "notepad", "gedit", "kate", "mousepad", "leafpad",
        "libreoffice", "openoffice", "microsoft", "office",
        "adobe", "photoshop", "illustrator", "indesign",
        "vlc", "mpv", "mplayer", "ffmpeg", "gstreamer",
        "spotify", "rhythmbox", "amarok", "clementine",
        "steam", "wine", "proton", "lutris", "playonlinux",
    ];
    
    let search_text = format!("{} {}", process_name, exe_path).to_lowercase();
    
    for legitimate in &legitimate_processes {
        if search_text.contains(legitimate) {
            return true;
        }
    }
    
    false
}

/// Checks for unusual network activity that might indicate AI API calls
fn has_unusual_network_activity(_pid: i32) -> bool {
    // This would require additional system monitoring
    // For now, return false to avoid false positives
    // In a real implementation, you'd check:
    // - Network connections to AI service domains
    // - Unusual API call patterns
    // - Large data transfers
    false
}

/// Checks for high CPU usage with low user interaction
fn has_high_cpu_low_interaction(_proc: &procfs::process::Process) -> bool {
    // This would require monitoring CPU usage over time
    // For now, return false to avoid false positives
    // In a real implementation, you'd check:
    // - CPU usage patterns
    // - User interaction (mouse/keyboard activity)
    // - Process priority and scheduling
    false
}

/// Checks for suspicious file access patterns
fn has_suspicious_file_access(_proc: &procfs::process::Process) -> bool {
    // This would require monitoring file system activity
    // For now, return false to avoid false positives
    // In a real implementation, you'd check:
    // - Access to AI model files
    // - Unusual file read/write patterns
    // - Access to configuration files
    false
}

/// Checks for unusual memory patterns
fn has_unusual_memory_patterns(_proc: &procfs::process::Process) -> bool {
    // This would require monitoring memory usage
    // For now, return false to avoid false positives
    // In a real implementation, you'd check:
    // - Memory allocation patterns
    // - Memory usage spikes
    // - Unusual memory access patterns
    false
}

/// Checks for suspicious timing patterns
fn has_suspicious_timing(_proc: &procfs::process::Process) -> bool {
    // This would require monitoring process timing
    // For now, return false to avoid false positives
    // In a real implementation, you'd check:
    // - Process start/stop timing
    // - Execution patterns
    // - Scheduling patterns
    false
}

/// Returns built-in AI tool patterns with confidence scores
/// 
/// These patterns are based on known AI tools and their common naming conventions.
/// The confidence scores reflect how likely a process matching this pattern is actually an AI tool.
fn get_ai_patterns() -> HashMap<String, f64> {
    let mut patterns = HashMap::new();
    
    // High confidence patterns (known AI tools) - 85-95% confidence
    patterns.insert("chatgpt".to_string(), 0.95);
    patterns.insert("claude".to_string(), 0.95);
    patterns.insert("bard".to_string(), 0.95);
    patterns.insert("gpt".to_string(), 0.9);
    patterns.insert("openai".to_string(), 0.9);
    patterns.insert("anthropic".to_string(), 0.9);
    patterns.insert("copilot".to_string(), 0.9);
    patterns.insert("github copilot".to_string(), 0.9);
    patterns.insert("tabnine".to_string(), 0.85);
    patterns.insert("kite".to_string(), 0.85);
    patterns.insert("intellicode".to_string(), 0.8);
    patterns.insert("ai assistant".to_string(), 0.8);
    patterns.insert("ai helper".to_string(), 0.8);
    
    // Medium confidence patterns (potential AI tools) - 50-80% confidence
    patterns.insert("assistant".to_string(), 0.7);
    patterns.insert("helper".to_string(), 0.6);
    patterns.insert("ai".to_string(), 0.5);
    patterns.insert("bot".to_string(), 0.5);
    patterns.insert("gpt-".to_string(), 0.8);
    patterns.insert("claude-".to_string(), 0.8);
    
    patterns
}

/// Returns comprehensive list of AI-related keywords for detection
/// 
/// These keywords are used to identify processes that might be AI tools
/// even if they don't match exact patterns. This includes:
/// - AI model names (GPT-4, Claude-3, etc.)
/// - AI-related terms (machine learning, neural, etc.)
/// - Development tools with AI features
/// - Voice and speech processing tools
fn get_ai_keywords() -> Vec<String> {
    vec![
        // Popular AI models and services
        "chatgpt".to_string(), "claude".to_string(), "bard".to_string(), "gpt".to_string(), "openai".to_string(), "anthropic".to_string(), "copilot".to_string(),
        "gpt-3".to_string(), "gpt-4".to_string(), "claude-2".to_string(), "claude-3".to_string(), "palm".to_string(), "llama".to_string(), "mistral".to_string(), 
        "falcon".to_string(), "cohere".to_string(), "huggingface".to_string(),
        
        // AI and ML terminology
        "ai".to_string(), "artificial intelligence".to_string(), "machine learning".to_string(), "ml".to_string(), "llm".to_string(),
        "large language model".to_string(), "neural".to_string(), "transformer".to_string(), "bert".to_string(), "t5".to_string(),
        
        // AI assistant terms
        "assistant".to_string(), "helper".to_string(), "bot".to_string(), "autocomplete".to_string(), "suggestion".to_string(), 
        "prediction".to_string(), "generation".to_string(), "completion".to_string(),
        
        // Development AI tools
        "github copilot".to_string(), "tabnine".to_string(), "kite".to_string(), "intellicode".to_string(), "codeium".to_string(),
        "cursor".to_string(), "replit".to_string(), "codespaces".to_string(), "gitpod".to_string(), "stackblitz".to_string(),
        
        // AI frameworks and libraries
        "transformers".to_string(), "torch".to_string(), "tensorflow".to_string(), "keras".to_string(), "scikit-learn".to_string(),
        "jupyter".to_string(), "notebook".to_string(), "colab".to_string(), "kaggle".to_string(), "databricks".to_string(),
        
        // Voice and speech processing
        "voice-to-text".to_string(), "speech-to-text".to_string(), "dictation".to_string(), "transcription".to_string(),
        "whisper".to_string(), "speech".to_string(), "voice".to_string(), "audio".to_string(), "recognition".to_string(),
        
        // Code completion and IDE features
        "code completion".to_string(), "intellisense".to_string(), "autocomplete".to_string(), "snippets".to_string(),
        
        // Development and testing
        "playground".to_string(), "sandbox".to_string(), "demo".to_string(), "test".to_string(), "experiment".to_string(),
        
        // API and integration terms
        "api".to_string(), "endpoint".to_string(), "client".to_string(), "sdk".to_string(), "library".to_string(), "framework".to_string(),
        
        // Model-related terms
        "model".to_string(), "weights".to_string(), "checkpoint".to_string(), "fine-tuned".to_string(), "training".to_string(),
        "inference".to_string(), "prediction".to_string(), "generation".to_string(), "completion".to_string(),
    ]
}

/// Checks for suspicious memory patterns indicative of LLM usage.
fn check_memory_patterns(_pid: i32) -> Option<String> {
    // This is a placeholder. Real implementation would involve:
    // - Reading process memory (requires elevated privileges)
    // - Searching for known LLM-related strings (e.g., "llama.cpp", "transformers", "pytorch", "tensorflow")
    // - Identifying specific memory allocation patterns or loaded libraries
    None
}

/// Checks for suspicious file access patterns indicative of LLM usage.
fn check_file_access(_pid: i32) -> Option<String> {
    // This is a placeholder. Real implementation would involve:
    // - Monitoring file system events for the process (requires elevated privileges)
    // - Checking for access to common LLM model file extensions (.bin, .gguf, .pt, .safetensors)
    // - Identifying access to known LLM library directories
    None
}

/// Logs a suspicious process with an appropriate warning message.
fn log_suspicious_process(proc: &SuspiciousProcess) {
    match &proc.reason {
        SuspicionReason::MatchesConfiguredBinary(binary) => {
            warn!("⚠️  Suspicious process: PID {} → {} (matches configured binary: {})", 
                  proc.pid, proc.path, binary);
        }
        SuspicionReason::MatchesAiPattern(pattern) => {
            warn!("⚠️  Suspicious process: PID {} → {} (matches AI pattern: {})", 
                  proc.pid, proc.path, pattern);
        }
        SuspicionReason::HasAiKeywords(keywords) => {
            warn!("⚠️  Suspicious process: PID {} → {} (contains AI keywords: {:?})", 
                  proc.pid, proc.path, keywords);
        }
        SuspicionReason::SuspiciousCommandLine(args) => {
            warn!("⚠️  Suspicious process: PID {} → {} (suspicious command line: {:?})", 
                  proc.pid, proc.path, args);
        }
        SuspicionReason::SuspiciousBehavior(behavior) => {
            warn!("⚠️  Suspicious process: PID {} → {} (suspicious behavior: {:?})", 
                  proc.pid, proc.path, behavior);
        }
        SuspicionReason::MemoryPatternMatch(pattern) => {
            warn!("⚠️  Suspicious process: PID {} → {} (memory pattern match: {})", 
                  proc.pid, proc.path, pattern);
        }
        SuspicionReason::FileAccessPattern(file_path) => {
            warn!("⚠️  Suspicious process: PID {} → {} (file access pattern: {})", 
                  proc.pid, proc.path, file_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, MonitoringConfig, ProcessConfig};

    fn create_test_config() -> AppConfig {
        AppConfig {
            app: crate::config::AppSettings {
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                environment: "test".to_string(),
                log_level: "info".to_string(),
                teacher_pc_port: 8081,
            },
            web: crate::config::WebConfig {
                enabled: false,
                host: "localhost".to_string(),
                port: 8080,
                cors: crate::config::CorsConfig {
                    allowed_origins: vec![],
                    allowed_methods: vec![],
                    allowed_headers: vec![],
                },
            },
            monitoring: MonitoringConfig {
                bam: crate::config::BamConfig {
                    enabled: true,
                    check_interval_seconds: 5,
                    typing_sample_size: 100,
                    anomaly_threshold: 0.7,
                    model_path: "bam_model.joblib".to_string(),
                },
                process: ProcessConfig {
                    enabled: true,
                    scan_interval_seconds: 30,
                    suspicious_binaries: vec!["test_ai_tool".to_string()],
                },
                audio: crate::config::AudioConfig {
                    enabled: true,
                    check_interval_seconds: 10,
                    pulse_audio_timeout_ms: 1000,
                },
            },
            alerts: crate::config::AlertConfig {
                enabled: false,
                webhook_url: None,
                email: crate::config::EmailConfig {
                    smtp_server: "localhost".to_string(),
                    smtp_port: 587,
                    username: "test".to_string(),
                    password: "test".to_string(),
                    recipients: vec![],
                },
                thresholds: crate::config::AlertThresholds {
                    bam_anomaly_score: 0.8,
                    suspicious_process_count: 1,
                    mic_usage_duration_seconds: 30,
                },
            },
            security: crate::config::SecurityConfig {
                api_key_required: false,
                jwt_secret: "test".to_string(),
                session_timeout_minutes: 60,
                rate_limit: crate::config::RateLimitConfig {
                    requests_per_minute: 100,
                    burst_size: 10,
                },
            },
            storage: crate::config::StorageConfig {
                logs_dir: "/tmp".to_string(),
                data_dir: "/tmp".to_string(),
                max_log_size_mb: 100,
                log_retention_days: 30,
            },
            integrations: crate::config::IntegrationConfig {
                prometheus: crate::config::PrometheusConfig {
                    enabled: false,
                    port: 9090,
                },
                siem: crate::config::SiemConfig {
                    enabled: false,
                    endpoint: "".to_string(),
                    api_key: "".to_string(),
                },
                cloudwatch: crate::config::CloudWatchConfig {
                    enabled: false,
                    region: "us-east-1".to_string(),
                    log_group: "cluelyguard".to_string(),
                },
            },
        }
    }

    #[test]
    fn test_ai_patterns() {
        let patterns = get_ai_patterns();
        assert!(patterns.contains_key("chatgpt"));
        assert!(patterns.contains_key("claude"));
        assert!(patterns.contains_key("gpt"));
    }

    #[test]
    fn test_ai_keywords() {
        let keywords = get_ai_keywords();
        assert!(keywords.contains(&"chatgpt".to_string()));
        assert!(keywords.contains(&"ai".to_string()));
        assert!(keywords.contains(&"assistant".to_string()));
    }

    #[test]
    fn test_scan_with_config() {
        let config = create_test_config();
        let result = scan(&config);
        
        // Should complete without error
        assert!(result.scan_duration_ms > 0);
        assert!(result.total_processes_scanned > 0);
    }
}