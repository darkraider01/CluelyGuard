use crate::config::AppConfig;
use crate::logger::{FileLogger, RamDumpLog, AlertLog};
use chrono::Utc;
use serde_json;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use tokio::sync::RwLock; // Added RwLock

#[derive(Error, Debug)]
pub enum BamError {
    #[error("Python BAM execution failed: {0}")]
    PythonExecution(String),
    #[error("JSON parsing error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("File logging error: {0}")]
    FileLogging(String),
    #[error("Channel error: {0}")]
    Channel(String),
}

pub type BamResult<T> = Result<T, BamError>;

#[derive(Debug, Clone)]
pub struct BamMonitor {
    config: Arc<RwLock<AppConfig>>, // Changed to Arc<RwLock<AppConfig>>
    file_logger: Arc<FileLogger>,
    _ram_dumper: Arc<RamDumpLog>,
    session_id: String,
    stop_signal: Arc<AtomicBool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BamDetectionResult {
    pub ai_detected: bool,
    pub confidence: f64,
    pub anomaly_score: f64,
    pub status: String,
    pub latencies: Vec<f64>,
    pub mean_latency: f64,
}

#[derive(Debug, Clone)]
pub struct BamAlert {
    pub session_id: String,
    pub anomaly_score: f64,
    pub confidence: f64,
    pub is_ai_like: bool,
    pub timestamp: chrono::DateTime<Utc>,
}

impl BamMonitor {
    pub fn new(
        config: Arc<RwLock<AppConfig>>, // Changed to Arc<RwLock<AppConfig>>
        file_logger: Arc<FileLogger>,
        ram_dumper: Arc<RamDumpLog>,
        session_id: String,
    ) -> Self {
        Self {
            config,
            file_logger,
            _ram_dumper: ram_dumper,
            session_id,
            stop_signal: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start_monitoring(&self) -> BamResult<()> {
        info!("Starting real-time BAM monitoring for session: {}", self.session_id);
        
        let config_guard = self.config.read().await; // Acquire read lock
        let check_interval = Duration::from_secs(config_guard.monitoring.bam.check_interval_seconds);
        let bam_anomaly_score_threshold = config_guard.alerts.thresholds.bam_anomaly_score;
        drop(config_guard); // Release lock
        
        let mut last_check = Instant::now();
        
        loop {
            if self.stop_signal.load(std::sync::atomic::Ordering::Relaxed) {
                info!("BAM monitoring stopped for session: {}", self.session_id);
                break;
            }

            // Check if it's time for the next BAM check
            if last_check.elapsed() >= check_interval {
                match self.perform_bam_check().await {
                    Ok(result) => {
                        debug!("BAM check completed: AI detected = {}", result.ai_detected);
                        
                        // Check if we should trigger an alert
                        if result.ai_detected && result.confidence >= bam_anomaly_score_threshold {
                            if let Err(e) = self.create_ai_alert(&result).await {
                                error!("Failed to create AI alert: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("BAM check failed: {}", e);
                    }
                }
                
                last_check = Instant::now();
            }
            
            // Sleep for a short interval to prevent busy waiting
            sleep(Duration::from_millis(100)).await;
        }
        
        Ok(())
    }

    async fn perform_bam_check(&self) -> BamResult<BamDetectionResult> {
        debug!("Performing BAM check...");
        
        // Run the Python BAM script
        let output = Command::new("python3")
            .arg("bam/bam.py")
            .output()
            .map_err(|e| BamError::PythonExecution(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BamError::PythonExecution(format!(
                "BAM script failed with status {}: {}",
                output.status, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse the BAM output to find the log file path
        let log_path = stdout
            .lines()
            .rev()
            .find(|line| line.contains("bam_") && line.contains(".json"))
            .and_then(|line| line.split_whitespace().last().map(|s| s.to_string()))
            .ok_or_else(|| BamError::PythonExecution("No BAM log file found in output".to_string()))?;

        // Read and parse the BAM result
        let bam_data = std::fs::read_to_string(&log_path)
            .map_err(|e| BamError::PythonExecution(format!("Failed to read BAM log: {}", e)))?;

        let bam_json: serde_json::Value = serde_json::from_str(&bam_data)?;
        
        // Extract detection results
        let detection = bam_json.get("detection")
            .ok_or_else(|| BamError::PythonExecution("No detection data in BAM result".to_string()))?;
        
        let latencies = bam_json.get("latencies")
            .and_then(|l| l.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_f64()).collect())
            .unwrap_or_default();

        let mean_latency = bam_json.get("mean_latency")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let ai_detected = detection.get("ai_detected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let confidence = detection.get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let anomaly_score = detection.get("anomaly_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let status = detection.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(BamDetectionResult {
            ai_detected,
            confidence,
            anomaly_score,
            status,
            latencies,
            mean_latency,
        })
    }

    async fn create_ai_alert(&self, result: &BamDetectionResult) -> BamResult<()> {
        let alert = AlertLog {
            id: Uuid::new_v4().to_string(),
            session_id: self.session_id.clone(),
            alert_type: "ai_detection".to_string(),
            severity: if result.confidence > 0.9 { "critical" } else { "warning" }.to_string(),
            message: format!(
                "AI-like typing behavior detected with confidence {:.2} (anomaly score: {:.2})",
                result.confidence, result.anomaly_score
            ),
            metadata: serde_json::json!({
                "ai_detected": result.ai_detected,
                "confidence": result.confidence,
                "anomaly_score": result.anomaly_score,
                "mean_latency": result.mean_latency,
                "latency_count": result.latencies.len(),
                "status": result.status
            }),
            created_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
        };

        self.file_logger.log_alert(&alert)
            .map_err(|e| BamError::FileLogging(e.to_string()))?;
        
        warn!(
            "AI detection alert created: confidence={:.2}, anomaly_score={:.2}",
            result.confidence, result.anomaly_score
        );
        
        Ok(())
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

// Background BAM monitoring service
#[derive(Debug)]
pub struct BamMonitoringService {
    config: Arc<RwLock<AppConfig>>, // Changed to Arc<RwLock<AppConfig>>
    file_logger: Arc<FileLogger>,
    ram_dumper: Arc<RamDumpLog>,
    monitors: std::collections::HashMap<String, BamMonitor>,
}

impl BamMonitoringService {
    pub fn new(
        config: Arc<RwLock<AppConfig>>, // Changed to Arc<RwLock<AppConfig>>
        file_logger: Arc<FileLogger>,
        ram_dumper: Arc<RamDumpLog>,
    ) -> Self {
        Self {
            config,
            file_logger,
            ram_dumper,
            monitors: std::collections::HashMap::new(),
        }
    }

    pub async fn start_session_monitoring(&mut self, session_id: String) -> BamResult<()> {
        if self.monitors.contains_key(&session_id) {
            warn!("BAM monitoring already active for session: {}", session_id);
            return Ok(());
        }

        let monitor = BamMonitor::new(
            self.config.clone(),
            self.file_logger.clone(),
            self.ram_dumper.clone(),
            session_id.clone(),
        );

        let monitor_clone = monitor.clone();
        let session_id_clone = session_id.clone();

        // Spawn monitoring task
        tokio::spawn(async move {
            if let Err(e) = monitor_clone.start_monitoring().await {
                error!("BAM monitoring failed for session {}: {}", session_id_clone, e);
            }
        });

        self.monitors.insert(session_id.clone(), monitor);
        info!("Started BAM monitoring for session: {}", session_id);
        
        Ok(())
    }

    pub fn stop_session_monitoring(&mut self, session_id: &str) {
        if let Some(monitor) = self.monitors.get(session_id) {
            monitor.stop();
            self.monitors.remove(session_id);
            info!("Stopped BAM monitoring for session: {}", session_id);
        }
    }

    pub fn is_monitoring(&self, session_id: &str) -> bool {
        self.monitors.contains_key(session_id)
    }

    pub fn get_active_sessions(&self) -> Vec<String> {
        self.monitors.keys().cloned().collect()
    }
} 

#[cfg(test)]
mod tests {
    // These tests are currently skipped due to complexity in mocking external process execution (`std::process::Command`)
    // and global filesystem operations. Comprehensive testing would require:
    // - Mocking `std::process::Command` to control the output of `bam/bam.py`.
    // - Mocking `std::fs::read_to_string` to control the content of the JSON log file.
    // - Setting up a virtual filesystem for isolated log file operations.
    // For now, relying on higher-level integration tests for BAM functionality.
}