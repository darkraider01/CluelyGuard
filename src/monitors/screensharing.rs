use std::process::Command;
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use tracing::{warn, error};
use serde::{Serialize, Deserialize};
use crate::config::ScreenSharingConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenCaptureEvent {
    pub application: String,
    pub capture_type: CaptureType,
    pub timestamp: SystemTime,
    pub process_id: u32,
    pub command_line: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CaptureType {
    ScreenRecording,
    ScreenSharing,
    WindowCapture,
    WebcamAccess,
    Unknown,
}

pub struct ScreenSharingMonitor {
    config: ScreenSharingConfig,
    wayland_session: bool,
    last_scan: Option<SystemTime>,
    scan_interval: Duration,
    running_processes: HashMap<u32, String>,
}

impl ScreenSharingMonitor {
    pub fn new(config: ScreenSharingConfig) -> Self {
        let wayland_session = std::env::var("WAYLAND_DISPLAY").is_ok();
        
        ScreenSharingMonitor {
            config,
            wayland_session,
            last_scan: None,
            scan_interval: Duration::from_secs(5),
            running_processes: HashMap::new(),
        }
    }

    pub fn detect_screen_capture(&mut self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();
        if !self.config.enabled {
            return events;
        }

        let now = SystemTime::now();
        
        // Rate limit scanning
        if let Some(last) = self.last_scan {
            if now.duration_since(last).unwrap_or(Duration::from_secs(0)) < self.scan_interval {
                return Vec::new();
            }
        }
        
        self.last_scan = Some(now);
        
        if self.wayland_session {
            events.extend(self.detect_wayland_capture());
        } else {
            events.extend(self.detect_x11_capture());
        }
        
        events.extend(self.detect_process_based_capture());
        events.extend(self.detect_pipewire_capture());
        events.extend(self.detect_gpu_encoding());
        
        events
    }

    fn detect_wayland_capture(&self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();
        
        // Check PipeWire for screen capture streams
        if let Ok(output) = Command::new("pactl")
            .args(&["list", "sources"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("monitor") && output_str.contains("RUNNING") {
                events.push(ScreenCaptureEvent {
                    application: "PipeWire Screen Capture".to_string(),
                    capture_type: CaptureType::ScreenRecording,
                    timestamp: SystemTime::now(),
                    process_id: 0,
                    command_line: None,
                    confidence: 0.7,
                });
            }
        }

        // Check for xdg-desktop-portal screen sharing
        if let Ok(output) = Command::new("busctl")
            .args(&["--user", "call", "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop", "org.freedesktop.portal.ScreenCast", "CreateSession"])
            .output()
        {
            if output.status.success() {
                events.push(ScreenCaptureEvent {
                    application: "Desktop Portal".to_string(),
                    capture_type: CaptureType::ScreenSharing,
                    timestamp: SystemTime::now(),
                    process_id: 0,
                    command_line: None,
                    confidence: 0.8,
                });
            }
        }

        // Check wlr-randr for screen capture
        if let Ok(output) = Command::new("wlr-randr")
            .args(&["--json"])
            .output()
        {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                if output_str.contains("transform") {
                    // This is a weak indicator, but worth noting
                    events.push(ScreenCaptureEvent {
                        application: "Wayland Compositor".to_string(),
                        capture_type: CaptureType::Unknown,
                        timestamp: SystemTime::now(),
                        process_id: 0,
                        command_line: None,
                        confidence: 0.3,
                    });
                }
            }
        }

        events
    }

    fn detect_x11_capture(&self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();

        // Check for active X11 screen capture using xwininfo
        if let Ok(output) = Command::new("xwininfo")
            .args(&["-root", "-tree"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            // Look for windows that might be capturing
            if output_str.contains("record") || output_str.contains("capture") {
                events.push(ScreenCaptureEvent {
                    application: "X11 Screen Capture".to_string(),
                    capture_type: CaptureType::ScreenRecording,
                    timestamp: SystemTime::now(),
                    process_id: 0,
                    command_line: None,
                    confidence: 0.6,
                });
            }
        }

        // Check for VNC servers
        if let Ok(output) = Command::new("netstat")
            .args(&["-tlnp"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains(":5900") || output_str.contains(":5901") {
                events.push(ScreenCaptureEvent {
                    application: "VNC Server".to_string(),
                    capture_type: CaptureType::ScreenSharing,
                    timestamp: SystemTime::now(),
                    process_id: 0,
                    command_line: None,
                    confidence: 0.9,
                });
            }
        }

        events
    }

    fn detect_process_based_capture(&mut self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();
        
        if let Ok(output) = Command::new("ps")
            .args(&["aux"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            
            for line in output_str.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 11 {
                    continue;
                }
                
                let command = fields[10..].join(" ");
                let pid: u32 = fields[1].parse().unwrap_or(0);
                
                // Check against known screen capture applications
                for app in &self.config.known_screen_apps {
                    if command.to_lowercase().contains(&app.to_lowercase()) {
                        let capture_type = self.determine_capture_type(&command);
                        let confidence = self.calculate_confidence(&command, app);
                        
                        // Check if this is a new process or has changed
                        let should_report = if let Some(existing_cmd) = self.running_processes.get(&pid) {
                            existing_cmd != &command
                        } else {
                            true
                        };
                        
                        if should_report {
                            self.running_processes.insert(pid, command.clone());
                            
                            events.push(ScreenCaptureEvent {
                                application: app.clone(),
                                capture_type,
                                timestamp: SystemTime::now(),
                                process_id: pid,
                                command_line: Some(command.clone()),
                                confidence,
                            });
                        }
                    }
                }
                
                // Check for suspicious ffmpeg/gstreamer usage
                if command.contains("ffmpeg") && (command.contains(":0.0") || command.contains("x11grab")) {
                    events.push(ScreenCaptureEvent {
                        application: "ffmpeg".to_string(),
                        capture_type: CaptureType::ScreenRecording,
                        timestamp: SystemTime::now(),
                        process_id: pid,
                        command_line: Some(command.clone()),
                        confidence: 0.9,
                    });
                }
            }
        }

        // Clean up processes that are no longer running
        self.cleanup_dead_processes();
        
        events
    }

    fn detect_pipewire_capture(&self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();
        
        // Check PipeWire for active screen sharing sessions
        if let Ok(output) = Command::new("pw-dump")
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("screen-share") || output_str.contains("monitor") {
                events.push(ScreenCaptureEvent {
                    application: "PipeWire".to_string(),
                    capture_type: CaptureType::ScreenSharing,
                    timestamp: SystemTime::now(),
                    process_id: 0,
                    command_line: None,
                    confidence: 0.8,
                });
            }
        }

        events
    }

    fn detect_gpu_encoding(&self) -> Vec<ScreenCaptureEvent> {
        let mut events = Vec::new();
        
        // Check GPU usage for video encoding (NVIDIA)
        if let Ok(output) = Command::new("nvidia-smi")
            .args(&["--query-gpu=utilization.gpu,utilization.memory", "--format=csv,noheader,nounits"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    if let (Ok(gpu), Ok(mem)) = (parts[0].trim().parse::<i32>(), parts[1].trim().parse::<i32>()) {
                        if gpu > 50 && mem > 30 {
                            events.push(ScreenCaptureEvent {
                                application: "GPU Encoder".to_string(),
                                capture_type: CaptureType::ScreenRecording,
                                timestamp: SystemTime::now(),
                                process_id: 0,
                                command_line: None,
                                confidence: 0.6,
                            });
                            break;
                        }
                    }
                }
            }
        }

        // Check for high GPU usage via /proc
        if let Ok(gpu_usage) = std::fs::read_to_string("/sys/class/drm/card0/device/gpu_busy_percent") {
            if let Ok(usage) = gpu_usage.trim().parse::<i32>() {
                if usage > 70 {
                    events.push(ScreenCaptureEvent {
                        application: "GPU Activity".to_string(),
                        capture_type: CaptureType::Unknown,
                        timestamp: SystemTime::now(),
                        process_id: 0,
                        command_line: None,
                        confidence: 0.4,
                    });
                }
            }
        }

        events
    }

    fn determine_capture_type(&self, command: &str) -> CaptureType {
        let cmd_lower = command.to_lowercase();
        
        if cmd_lower.contains("record") || cmd_lower.contains("ffmpeg") || cmd_lower.contains("obs") {
            CaptureType::ScreenRecording
        } else if cmd_lower.contains("share") || cmd_lower.contains("vnc") || cmd_lower.contains("rdp") {
            CaptureType::ScreenSharing
        } else if cmd_lower.contains("window") || cmd_lower.contains("capture") {
            CaptureType::WindowCapture
        } else if cmd_lower.contains("webcam") || cmd_lower.contains("camera") {
            CaptureType::WebcamAccess
        } else {
            CaptureType::Unknown
        }
    }

    fn calculate_confidence(&self, command: &str, app: &str) -> f64 {
        let mut confidence = 0.5;
        
        // Higher confidence for exact matches
        if command.contains(app) {
            confidence += 0.3;
        }
        
        // Higher confidence for screen-related keywords
        let screen_keywords = ["screen", "display", "capture", "record", "share"];
        for keyword in &screen_keywords {
            if command.to_lowercase().contains(keyword) {
                confidence += 0.1;
            }
        }
        
        // Higher confidence for video-related arguments
        let video_keywords = ["mp4", "mkv", "avi", "h264", "x264"];
        for keyword in &video_keywords {
            if command.to_lowercase().contains(keyword) {
                confidence += 0.1;
            }
        }
        
        (confidence as f32).min(1.0f32) as f64
    }

    fn cleanup_dead_processes(&mut self) {
        let mut dead_pids = Vec::new();
        
        for &pid in self.running_processes.keys() {
            if !self.is_process_running(pid) {
                dead_pids.push(pid);
            }
        }
        
        for pid in dead_pids {
            self.running_processes.remove(&pid);
        }
    }

    fn is_process_running(&self, pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScreenSharingConfig;

    fn create_test_config() -> ScreenSharingConfig {
        ScreenSharingConfig {
            enabled: true,
            known_screen_apps: vec!["test_app".to_string()],
        }
    }

    #[test]
    fn test_capture_type_detection() {
        let config = create_test_config();
        let monitor = ScreenSharingMonitor::new(config);
        
        assert!(matches!(
            monitor.determine_capture_type("ffmpeg -f x11grab -i :0.0 output.mp4"),
            CaptureType::ScreenRecording
        ));
        
        assert!(matches!(
            monitor.determine_capture_type("x11vnc -display :0"),
            CaptureType::ScreenSharing
        ));
    }

    #[test]
    fn test_confidence_calculation() {
        let config = create_test_config();
        let monitor = ScreenSharingMonitor::new(config);
        
        let confidence = monitor.calculate_confidence("obs --startrecording", "obs");
        assert!(confidence > 0.7);
        
        let low_confidence = monitor.calculate_confidence("some random process", "obs");
        assert!(low_confidence < 0.6);
    }
}
