use std::collections::{VecDeque, HashMap};
use std::time::{SystemTime, Duration};
use std::fs;
use std::process::Command;
use std::thread;
use std::sync::{Arc, Mutex};
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserActivityEvent {
    pub activity_type: ActivityType,
    pub timestamp: SystemTime,
    pub details: String,
    pub confidence: f64,
    pub suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityType {
    ClipboardAccess,
    KeystrokePattern,
    CommandExecution,
    LoginActivity,
    SessionChange,
    FileAccess,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeystrokeEvent {
    pub timestamp: SystemTime,
    pub is_typed: bool, // true for typed, false for pasted
    pub text_length: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommandEvent {
    pub timestamp: SystemTime,
    pub command: String,
    pub user: String,
    pub working_directory: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TypingAnalysis {
    pub typing_speed: f64,      // characters per minute
    pub paste_ratio: f64,        // ratio of pasted vs typed content
    pub burst_patterns: Vec<Duration>, // time gaps between bursts
    pub consistency_score: f64,  // how consistent the typing rhythm is
}

pub struct UserActivityMonitor {
    keystroke_patterns: Arc<Mutex<VecDeque<KeystrokeEvent>>>,
    command_history: Arc<Mutex<Vec<CommandEvent>>>,
    suspicious_clipboard_content: Vec<String>,
    suspicious_commands: Vec<String>,
    monitoring_active: bool,
    history_limit: usize,
}

impl UserActivityMonitor {
    pub fn new() -> Self {
        UserActivityMonitor {
            keystroke_patterns: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            command_history: Arc::new(Mutex::new(Vec::new())),
            suspicious_clipboard_content: Self::init_suspicious_clipboard_patterns(),
            suspicious_commands: Self::init_suspicious_commands(),
            monitoring_active: false,
            history_limit: 1000,
        }
    }

    fn init_suspicious_clipboard_patterns() -> Vec<String> {
        vec![
            "api_key".to_string(),
            "openai".to_string(),
            "anthropic".to_string(),
            "chatgpt".to_string(),
            "claude".to_string(),
            "gpt-".to_string(),
            "sk-".to_string(),         // OpenAI API key prefix
            "Bearer ".to_string(),     // Common API token format
            "Authorization:".to_string(),
            "prompt:".to_string(),
            "system:".to_string(),
            "assistant:".to_string(),
            "human:".to_string(),
        ]
    }

    fn init_suspicious_commands() -> Vec<String> {
        vec![
            "pip install openai".to_string(),
            "pip install anthropic".to_string(),
            "pip install transformers".to_string(),
            "pip install torch".to_string(),
            "git clone".to_string(),
            "curl -X POST".to_string(),
            "wget".to_string(),
            "ollama".to_string(),
            "llamacpp".to_string(),
            "gpt4all".to_string(),
            "conda install".to_string(),
        ]
    }

    pub fn start_monitoring(&mut self) -> Result<(), String> {
        if self.monitoring_active {
            return Ok(());
        }

        self.monitoring_active = true;
        
        // Start clipboard monitoring
        self.start_clipboard_monitoring()?;
        
        // Start command history monitoring
        self.start_command_monitoring()?;
        
        // Start keystroke pattern analysis
        self.start_keystroke_monitoring()?;

        info!("User activity monitoring started");
        Ok(())
    }

    fn start_clipboard_monitoring(&self) -> Result<(), String> {
        let suspicious_patterns = self.suspicious_clipboard_content.clone();
        
        thread::spawn(move || {
            let mut last_clipboard_content = String::new();
            
            loop {
                if let Ok(current_content) = Self::get_clipboard_content() {
                    if current_content != last_clipboard_content && !current_content.is_empty() {
                        Self::analyze_clipboard_content(&current_content, &suspicious_patterns);
                        last_clipboard_content = current_content;
                    }
                }
                
                thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(())
    }

    fn get_clipboard_content() -> Result<String, String> {
        // Try different clipboard tools
        let clipboard_tools = ["xclip", "xsel", "wl-paste"];
        
        for tool in &clipboard_tools {
            let output = match tool {
                &"xclip" => Command::new("xclip")
                    .args(&["-selection", "clipboard", "-out"])
                    .output(),
                &"xsel" => Command::new("xsel")
                    .args(&["--clipboard", "--output"])
                    .output(),
                &"wl-paste" => Command::new("wl-paste")
                    .output(),
                _ => continue,
            };

            if let Ok(output) = output {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                }
            }
        }
        
        Err("No clipboard tool available".to_string())
    }

    fn analyze_clipboard_content(content: &str, suspicious_patterns: &[String]) {
        for pattern in suspicious_patterns {
            if content.to_lowercase().contains(&pattern.to_lowercase()) {
                warn!("Suspicious clipboard content detected: pattern '{}' found", pattern);
                
                // Log the event (in a real implementation, this would go to the event system)
                info!("Clipboard analysis: suspicious pattern detected");
                break;
            }
        }

        // Check for potential AI-generated content characteristics
        if Self::analyze_for_ai_content(content) {
            warn!("Clipboard content shows AI-generated characteristics");
        }
    }

    fn analyze_for_ai_content(content: &str) -> bool {
        let ai_indicators = [
            "as an ai", "i don't have personal", "i cannot provide",
            "based on my training", "as of my last update",
            "i'm just an ai", "according to my knowledge"
        ];

        let content_lower = content.to_lowercase();
        ai_indicators.iter().any(|&indicator| content_lower.contains(indicator))
    }

    fn start_command_monitoring(&self) -> Result<(), String> {
        let command_history = Arc::clone(&self.command_history);
        let suspicious_commands = self.suspicious_commands.clone();
        
        thread::spawn(move || {
            let mut last_history_size = 0;
            
            loop {
                // Monitor bash history
                if let Ok(history) = Self::read_bash_history() {
                    if history.len() > last_history_size {
                        let new_commands = &history[last_history_size..];
                        
                        for command in new_commands {
                            Self::analyze_command(command, &suspicious_commands);
                            
                            // Store in history
                            if let Ok(mut hist) = command_history.lock() {
                                hist.push(CommandEvent {
                                    timestamp: SystemTime::now(),
                                    command: command.clone(),
                                    user: Self::get_current_user(),
                                    working_directory: Self::get_current_directory(),
                                });
                                
                                // Limit history size
                                if hist.len() > 1000 {
                                    hist.remove(0);
                                }
                            }
                        }
                        
                        last_history_size = history.len();
                    }
                }
                
                thread::sleep(Duration::from_secs(5));
            }
        });

        Ok(())
    }

    fn read_bash_history() -> Result<Vec<String>, String> {
        let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
        let history_path = format!("{}/.bash_history", home);
        
        let content = fs::read_to_string(&history_path)
            .map_err(|_| "Could not read bash history")?;
        
        Ok(content.lines().map(|s| s.to_string()).collect())
    }

    fn analyze_command(command: &str, suspicious_commands: &[String]) {
        let command_lower = command.to_lowercase();
        
        for suspicious in suspicious_commands {
            if command_lower.contains(&suspicious.to_lowercase()) {
                warn!("Suspicious command detected: {}", command);
                break;
            }
        }

        // Check for potential AI tool usage patterns
        if Self::is_ai_related_command(command) {
            warn!("AI-related command detected: {}", command);
        }
    }

    fn is_ai_related_command(command: &str) -> bool {
        let ai_patterns = [
            r"curl.*openai\.com",
            r"curl.*anthropic\.com",
            r"python.*gpt",
            r"python.*llm",
            r"docker.*ollama",
            r"git.*huggingface",
        ];

        ai_patterns.iter().any(|pattern| {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(command))
                .unwrap_or(false)
        })
    }

    fn get_current_user() -> String {
        std::env::var("USER").unwrap_or_else(|_| "unknown".to_string())
    }

    fn get_current_directory() -> String {
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }

    fn start_keystroke_monitoring(&self) -> Result<(), String> {
        let patterns = Arc::clone(&self.keystroke_patterns);
        
        // Note: Actual keystroke monitoring would require root privileges
        // and use tools like evdev on Linux. This is a simplified implementation.
        thread::spawn(move || {
            loop {
                // Simulate keystroke pattern detection
                // In a real implementation, this would interface with the input system
                if let Ok(typing_events) = Self::detect_typing_patterns() {
                    if let Ok(mut patterns_guard) = patterns.lock() {
                        for event in typing_events {
                            patterns_guard.push_back(event);
                            
                            // Limit history size
                            if patterns_guard.len() > 1000 {
                                patterns_guard.pop_front();
                            }
                        }
                    }
                }
                
                thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(())
    }

    fn detect_typing_patterns() -> Result<Vec<KeystrokeEvent>, String> {
        // This is a placeholder - real implementation would monitor actual keystrokes
        // For demonstration purposes only
        Ok(vec![])
    }

    pub fn analyze_typing_patterns(&self) -> Option<TypingAnalysis> {
        let patterns = self.keystroke_patterns.lock().ok()?;
        
        if patterns.len() < 10 {
            return None;
        }

        let total_chars: usize = patterns.iter().map(|e| e.text_length).sum();
        let typed_chars: usize = patterns.iter()
            .filter(|e| e.is_typed)
            .map(|e| e.text_length)
            .sum();

        let time_span = patterns.back()?.timestamp
            .duration_since(patterns.front()?.timestamp)
            .ok()?;

        let typing_speed = if time_span.as_secs() > 0 {
            (total_chars as f64 * 60.0) / time_span.as_secs() as f64
        } else {
            0.0
        };

        let paste_ratio = if total_chars > 0 {
            (total_chars - typed_chars) as f64 / total_chars as f64
        } else {
            0.0
        };

        // Calculate burst patterns
        let mut burst_patterns = Vec::new();
        for window in patterns.iter().collect::<Vec<_>>().windows(2) {
            if let Ok(gap) = window[1].timestamp.duration_since(window[0].timestamp) {
                burst_patterns.push(gap);
            }
        }

        // Calculate consistency score
        let consistency_score = if burst_patterns.len() > 1 {
            let mean_gap = burst_patterns.iter().sum::<Duration>().as_millis() as f64 / burst_patterns.len() as f64;
            let variance = burst_patterns.iter()
                .map(|gap| (gap.as_millis() as f64 - mean_gap).powi(2))
                .sum::<f64>() / burst_patterns.len() as f64;
            
            let std_dev = variance.sqrt();
            
            if mean_gap > 0.0 {
                1.0 - (std_dev / mean_gap).min(1.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        Some(TypingAnalysis {
            typing_speed,
            paste_ratio,
            burst_patterns,
            consistency_score,
        })
    }

    pub fn get_recent_activities(&self, since: SystemTime) -> Vec<UserActivityEvent> {
        let mut activities = Vec::new();

        // Analyze typing patterns
        if let Some(analysis) = self.analyze_typing_patterns() {
            if analysis.paste_ratio > 0.7 {
                activities.push(UserActivityEvent {
                    activity_type: ActivityType::KeystrokePattern,
                    timestamp: SystemTime::now(),
                    details: format!("High paste ratio detected: {:.2}", analysis.paste_ratio),
                    confidence: 0.8,
                    suspicious: true,
                });
            }

            if analysis.typing_speed > 300.0 {
                activities.push(UserActivityEvent {
                    activity_type: ActivityType::KeystrokePattern,
                    timestamp: SystemTime::now(),
                    details: format!("Unusually high typing speed: {:.0} CPM", analysis.typing_speed),
                    confidence: 0.6,
                    suspicious: true,
                });
            }
        }

        // Analyze recent commands
        if let Ok(history) = self.command_history.lock() {
            for command_event in history.iter() {
                if command_event.timestamp >= since {
                    let is_suspicious = self.suspicious_commands.iter()
                        .any(|sus| command_event.command.to_lowercase().contains(&sus.to_lowercase()));

                    if is_suspicious {
                        activities.push(UserActivityEvent {
                            activity_type: ActivityType::CommandExecution,
                            timestamp: command_event.timestamp,
                            details: format!("Suspicious command: {}", command_event.command),
                            confidence: 0.9,
                            suspicious: true,
                        });
                    }
                }
            }
        }

        activities
    }

    pub fn stop_monitoring(&mut self) {
        self.monitoring_active = false;
        info!("User activity monitoring stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_content_detection() {
        let content = "As an AI language model, I don't have personal experiences.";
        assert!(UserActivityMonitor::analyze_for_ai_content(content));
        
        let normal_content = "Hey, how are you doing today?";
        assert!(!UserActivityMonitor::analyze_for_ai_content(normal_content));
    }

    #[test]
    fn test_ai_command_detection() {
        assert!(UserActivityMonitor::is_ai_related_command("curl -X POST https://api.openai.com/v1/chat/completions"));
        assert!(UserActivityMonitor::is_ai_related_command("python run_gpt.py"));
        assert!(!UserActivityMonitor::is_ai_related_command("ls -la"));
    }
}
