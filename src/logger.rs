use crate::config::AppConfig;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionLog {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub status: String,
    pub mic_usage_detected: bool,
    pub suspicious_processes: Vec<String>,
    pub bam_anomaly_score: Option<f64>,
    pub bam_is_ai_like: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AlertLog {
    pub id: String,
    pub session_id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BamResultLog {
    pub id: String,
    pub session_id: String,
    pub latencies: Vec<f64>,
    pub mean_latency: f64,
    pub anomaly_score: f64,
    pub is_ai_like: bool,
    pub confidence: f64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RamDumpLog {
    pub id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub memory_usage_mb: f64,
    pub suspicious_processes: Vec<SuspiciousProcessInfo>,
    pub network_connections: Vec<NetworkConnection>,
    pub file_handles: Vec<FileHandle>,
    pub created_at: DateTime<Utc>,
}

impl RamDumpLog {
    pub fn new() -> Self {
        Self {
            id: String::new(),
            session_id: String::new(),
            timestamp: Utc::now(),
            memory_usage_mb: 0.0,
            suspicious_processes: Vec::new(),
            network_connections: Vec::new(),
            file_handles: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuspiciousProcessInfo {
    pub pid: i32,
    pub name: String,
    pub memory_mb: f64,
    pub cpu_percent: f64,
    pub command_line: Vec<String>,
    pub reason: String,
    pub confidence: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkConnection {
    pub local_address: String,
    pub remote_address: String,
    pub protocol: String,
    pub state: String,
    pub pid: i32,
    pub process_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileHandle {
    pub path: String,
    pub pid: i32,
    pub process_name: String,
    pub access_mode: String,
}

#[derive(Debug)]
pub struct FileLogger {
    logs_dir: String,
}

impl FileLogger {
    pub fn new(_config: Arc<AppConfig>) -> Result<Self, std::io::Error> {
        let logs_dir = "logs".to_string();
        fs::create_dir_all(&logs_dir)?;
        
        // Create subdirectories
        fs::create_dir_all(format!("{}/sessions", logs_dir))?;
        fs::create_dir_all(format!("{}/alerts", logs_dir))?;
        fs::create_dir_all(format!("{}/bam_results", logs_dir))?;
        fs::create_dir_all(format!("{}/ram_dumps", logs_dir))?;
        
        Ok(Self { logs_dir })
    }

    fn write_json_file<T: Serialize>(&self, path: &str, data: &T) -> Result<(), std::io::Error> {
        let file = std::fs::File::create(path)?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn read_json_files<T: for<'de> Deserialize<'de>>(&self, dir: &str) -> Result<Vec<T>, std::io::Error> {
        let mut results = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                let file = std::fs::File::open(&path)?;
                let reader = std::io::BufReader::new(file);
                let data = serde_json::from_reader(reader)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                results.push(data);
            }
        }
        Ok(results)
    }

    pub fn log_session(&self, session: &SessionLog) -> Result<(), std::io::Error> {
        let filename = format!("{}/sessions/session_{}.json", self.logs_dir, session.id);
        self.write_json_file(&filename, session)
    }

    pub fn log_alert(&self, alert: &AlertLog) -> Result<(), std::io::Error> {
        let filename = format!("{}/alerts/alert_{}.json", self.logs_dir, alert.id);
        self.write_json_file(&filename, alert)
    }

    pub fn log_bam_result(&self, result: &BamResultLog) -> Result<(), std::io::Error> {
        let filename = format!("{}/bam_results/result_{}.json", self.logs_dir, result.id);
        self.write_json_file(&filename, result)
    }

    pub fn log_ram_dump(&self, dump: &RamDumpLog) -> Result<(), std::io::Error> {
        let filename = format!("{}/ram_dumps/dump_{}.json", self.logs_dir, dump.id);
        self.write_json_file(&filename, dump)
    }

    pub fn get_sessions(&self) -> Result<Vec<SessionLog>, std::io::Error> {
        let sessions_dir = format!("{}/sessions", self.logs_dir);
        self.read_json_files(&sessions_dir)
    }

    pub fn get_alerts(&self) -> Result<Vec<AlertLog>, std::io::Error> {
        let alerts_dir = format!("{}/alerts", self.logs_dir);
        self.read_json_files(&alerts_dir)
    }

    pub fn get_bam_results(&self) -> Result<Vec<BamResultLog>, std::io::Error> {
        let results_dir = format!("{}/bam_results", self.logs_dir);
        self.read_json_files(&results_dir)
    }

    pub fn get_ram_dumps(&self) -> Result<Vec<RamDumpLog>, std::io::Error> {
        let dumps_dir = format!("{}/ram_dumps", self.logs_dir);
        self.read_json_files(&dumps_dir)
    }

    pub fn get_session_alerts(&self, session_id: &str) -> Result<Vec<AlertLog>, std::io::Error> {
        let alerts = self.get_alerts()?;
        Ok(alerts.into_iter().filter(|a| a.session_id == session_id).collect())
    }

    pub fn get_session_bam_results(&self, session_id: &str) -> Result<Vec<BamResultLog>, std::io::Error> {
        let results = self.get_bam_results()?;
        Ok(results.into_iter().filter(|r| r.session_id == session_id).collect())
    }

    pub fn get_session_ram_dumps(&self, session_id: &str) -> Result<Vec<RamDumpLog>, std::io::Error> {
        let dumps = self.get_ram_dumps()?;
        Ok(dumps.into_iter().filter(|d| d.session_id == session_id).collect())
    }
}