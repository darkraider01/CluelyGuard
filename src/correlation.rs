use crate::events::{MonitorEvent, GenericMonitorEvent};
use tracing::{info, warn, error};
use std::collections::VecDeque;
use std::time::{SystemTime, Duration};
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::Utc;
use serde_json::to_string;

const CORRELATION_WINDOW_SECONDS: u64 = 60; // Events within this window are considered for correlation

#[derive(Debug, Clone)]
pub struct CorrelatedEvent {
    pub event_type: String,
    pub timestamp: SystemTime,
    pub student_code: String,
    pub confidence: f64,
    pub description: String,
    pub correlated_events: Vec<GenericMonitorEvent>, // Store the original events that triggered this
}

pub struct CorrelationEngine {
    event_buffer: Arc<Mutex<VecDeque<GenericMonitorEvent>>>,
    min_confidence_for_alert: f64,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        CorrelationEngine {
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            min_confidence_for_alert: 0.75, // Default threshold
        }
    }

    pub async fn process_event(&self, event: MonitorEvent, student_code: &str) -> Option<CorrelatedEvent> {
        let mut buffer = self.event_buffer.lock().await;
        let now = SystemTime::now();

        // Convert MonitorEvent to GenericMonitorEvent
        let generic_event = self.convert_to_generic_event(event, student_code).await;

        // Add new event to buffer
        buffer.push_back(generic_event.clone());

        // Clean up old events
        buffer.retain(|e| {
            now.duration_since(e.timestamp)
                .unwrap_or(Duration::from_secs(0)) < Duration::from_secs(CORRELATION_WINDOW_SECONDS)
        });

        // Apply correlation rules
        self.apply_rules(&buffer, &generic_event)
    }

    async fn convert_to_generic_event(&self, event: MonitorEvent, student_code: &str) -> GenericMonitorEvent {
        match event {
            MonitorEvent::FileSystem(e) => {
                GenericMonitorEvent::new("fs_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::Browser(e) => {
                GenericMonitorEvent::new("browser_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::OutputAnalysis(e) => {
                GenericMonitorEvent::new("output_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::Syscall(e) => {
                GenericMonitorEvent::new("syscall_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::UserActivity(e) => {
                GenericMonitorEvent::new("user_activity_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::ScreenSharing(e) => {
                GenericMonitorEvent::new("screensharing_suspicion", student_code, &to_string(&e).unwrap_or_default())
            },
            MonitorEvent::NetworkDomain(e) => {
                GenericMonitorEvent::new("network_suspicion", student_code, &format!("{:?}", e))
            },
            MonitorEvent::ProcessSuspicion(e) => {
                GenericMonitorEvent::new("process_suspicion", student_code, &format!("{:?}", e))
            },
        }
    }

    fn apply_rules(&self, buffer: &VecDeque<GenericMonitorEvent>, new_event: &GenericMonitorEvent) -> Option<CorrelatedEvent> {
        // Rule 1: High confidence AI tool usage + suspicious output
        if new_event.event_type == "output_suspicion" {
            // Check for recent process suspicion events
            let recent_process_suspicion = buffer.iter().any(|e| {
                e.event_type == "process_suspicion" &&
                e.timestamp > SystemTime::now() - Duration::from_secs(30) // within 30 seconds
            });

            if recent_process_suspicion {
                return Some(CorrelatedEvent {
                    event_type: "AI_Usage_High_Confidence".to_string(),
                    timestamp: SystemTime::now(),
                    student_code: new_event.student_code.clone(),
                    confidence: 0.9,
                    description: "High confidence AI tool usage detected (process + output)".to_string(),
                    correlated_events: buffer.iter().cloned().collect(),
                });
            }
        }

        // Rule 2: Multiple suspicious activities within a short timeframe
        let suspicious_events_count = buffer.iter().filter(|e| {
            e.event_type.contains("suspicion") || e.event_type.contains("AI")
        }).count();

        if suspicious_events_count >= 3 {
            return Some(CorrelatedEvent {
                event_type: "Multiple_Suspicious_Activities".to_string(),
                timestamp: SystemTime::now(),
                student_code: new_event.student_code.clone(),
                confidence: 0.8,
                description: "Multiple distinct suspicious activities detected in a short period.".to_string(),
                correlated_events: buffer.iter().cloned().collect(),
            });
        }

        // Rule 3: Suspicious network activity followed by suspicious file system activity
        if new_event.event_type == "fs_suspicion" {
            let recent_network_suspicion = buffer.iter().any(|e| {
                e.event_type == "network_suspicion" &&
                e.timestamp > SystemTime::now() - Duration::from_secs(10) // within 10 seconds
            });

            if recent_network_suspicion {
                return Some(CorrelatedEvent {
                    event_type: "Data_Exfiltration_Attempt".to_string(),
                    timestamp: SystemTime::now(),
                    student_code: new_event.student_code.clone(),
                    confidence: 0.95,
                    description: "Suspicious network activity followed by suspicious file system activity (potential data exfiltration).".to_string(),
                    correlated_events: buffer.iter().cloned().collect(),
                });
            }
        }

        None
    }
}