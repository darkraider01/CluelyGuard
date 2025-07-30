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
    pub fn new(session_id: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            session_id,
            timestamp: Utc::now(),
            memory_usage_mb: 0.0,
            suspicious_processes: Vec::new(),
            network_connections: Vec::new(),
            file_handles: Vec::new(),
            created_at: Utc::now(),
        }
    }
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

    pub fn append_to_log_file(&self, log_entry: &str) -> Result<(), std::io::Error> {
        use std::io::Write;
        let log_file_path = format!("{}/cluelyguard.log", self.logs_dir);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file_path)?;
        writeln!(file, "{}", log_entry)?;
        Ok(())
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

    pub fn create_ram_dump(session_id: &str, _student_code: &str) -> Result<RamDumpLog, Box<dyn std::error::Error>> {
        use procfs::process::{all_processes};
        use sysinfo::{System, SystemExt, ProcessExt, Pid};

        let mut sys = System::new_all();
        sys.refresh_all();

        #[allow(unused_assignments)] // memory_usage_mb is assigned later
        let mut memory_usage_mb = 0.0;
        #[allow(unused_variables)] // suspicious_processes, network_connections, file_handles are used but not always in every branch
        let mut suspicious_processes: Vec<SuspiciousProcessInfo> = Vec::new();
        #[allow(unused_variables)]
        let mut network_connections: Vec<NetworkConnection> = Vec::new();
        #[allow(unused_variables)]
        let mut file_handles: Vec<FileHandle> = Vec::new();

        // Get total memory usage
        memory_usage_mb = sys.used_memory() as f64 / (1024.0 * 1024.0);

        // Process information
        for proc_result in all_processes()? {
            if let Ok(proc) = proc_result {
                let pid = proc.pid();
                let name = proc.stat()?.comm;
                let cmdline = proc.cmdline()?;
                
                let process_sysinfo = sys.process(Pid::from(pid as usize)); // Corrected Pid creation
                let memory_mb_sysinfo = process_sysinfo.map_or(0.0, |p| p.memory() as f64 / (1024.0 * 1024.0));
                let cpu_percent_sysinfo = process_sysinfo.map_or(0.0, |p| p.cpu_usage() as f64);


                // Simulate suspicious process detection
                if name.contains("llm_tool") || cmdline.join(" ").contains("ai_script.py") {
                    suspicious_processes.push(SuspiciousProcessInfo {
                        pid,
                        name: name.clone(),
                        memory_mb: memory_mb_sysinfo,
                        cpu_percent: cpu_percent_sysinfo,
                        command_line: cmdline,
                        reason: "Detected suspicious AI tool name or command line".to_string(),
                        confidence: 0.9,
                    });
                }

                // Network connections (simplified, real impl would need more detail)
                if let Ok(net_connections) = proc.tcp() {
                    for conn in net_connections {
                        network_connections.push(NetworkConnection {
                            local_address: conn.local_address.to_string(),
                            remote_address: conn.remote_address.to_string(),
                            protocol: "TCP".to_string(),
                            state: format!("{:?}", conn.state),
                            pid,
                            process_name: name.clone(),
                        });
                    }
                }
                if let Ok(net_connections) = proc.tcp6() {
                    for conn in net_connections {
                        network_connections.push(NetworkConnection {
                            local_address: conn.local_address.to_string(),
                            remote_address: conn.remote_address.to_string(),
                            protocol: "TCP6".to_string(),
                            state: format!("{:?}", conn.state),
                            pid,
                            process_name: name.clone(),
                        });
                    }
                }
            }
        }

        // File handles (simplified, real impl would need lsof or similar)
        // This is a placeholder as procfs doesn't directly give open file handles in an easy way
        // You'd typically use lsof or similar tools for this.
        file_handles.push(FileHandle {
            path: "/tmp/some_temp_file.txt".to_string(),
            pid: 1234, // Dummy PID
            process_name: "dummy_process".to_string(),
            access_mode: "rw".to_string(),
        });


        Ok(RamDumpLog {
            id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.to_string(),
            timestamp: Utc::now(),
            memory_usage_mb,
            suspicious_processes,
            network_connections,
            file_handles,
            created_at: Utc::now(),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    // use std::io::Read; // Removed unused import
    // use chrono::Duration; // Removed unused import

    // Helper function to create a dummy config for tests
    fn create_test_config() -> AppConfig {
        AppConfig::default()
    }

    #[test]
    fn test_file_logger_new() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        
        // Mock AppConfig to use the temporary directory
        let mut config = create_test_config();
        config.storage.logs_dir = logs_dir_path.to_str().unwrap().to_string();

        let logger = FileLogger::new(Arc::new(config)).unwrap();
        
        assert!(fs::metadata(&logger.logs_dir).unwrap().is_dir());
        assert!(fs::metadata(format!("{}/sessions", logger.logs_dir)).unwrap().is_dir());
        assert!(fs::metadata(format!("{}/alerts", logger.logs_dir)).unwrap().is_dir());
        assert!(fs::metadata(format!("{}/bam_results", logger.logs_dir)).unwrap().is_dir());
        assert!(fs::metadata(format!("{}/ram_dumps", logger.logs_dir)).unwrap().is_dir());
    }

    #[test]
    fn test_write_and_read_json_file() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test.json");
        
        let logger = FileLogger { logs_dir: temp_dir.path().to_str().unwrap().to_string() };
        
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            name: String,
            value: u32,
        }
        
        let data = TestData { name: "test".to_string(), value: 123 };
        logger.write_json_file(file_path.to_str().unwrap(), &data).unwrap();
        
        let read_data: TestData = serde_json::from_str(&fs::read_to_string(&file_path).unwrap()).unwrap();
        assert_eq!(data, read_data);
    }

    #[test]
    fn test_log_and_get_session() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();
        fs::create_dir_all(format!("{}/sessions", logs_dir_path.to_str().unwrap())).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        
        let session = SessionLog {
            id: "test_session_1".to_string(),
            started_at: Utc::now(),
            ended_at: None,
            status: "active".to_string(),
            mic_usage_detected: false,
            suspicious_processes: vec![],
            bam_anomaly_score: None,
            bam_is_ai_like: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        logger.log_session(&session).unwrap();
        
        let sessions = logger.get_sessions().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "test_session_1");
    }

    #[test]
    fn test_log_and_get_alert() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();
        fs::create_dir_all(format!("{}/alerts", logs_dir_path.to_str().unwrap())).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        
        let alert = AlertLog {
            id: "test_alert_1".to_string(),
            session_id: "test_session_1".to_string(),
            alert_type: "test_type".to_string(),
            severity: "low".to_string(),
            message: "Test alert message".to_string(),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            acknowledged_at: None,
            acknowledged_by: None,
        };
        
        logger.log_alert(&alert).unwrap();
        
        let alerts = logger.get_alerts().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].id, "test_alert_1");
    }

    #[test]
    fn test_log_and_get_bam_result() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();
        fs::create_dir_all(format!("{}/bam_results", logs_dir_path.to_str().unwrap())).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        
        let bam_result = BamResultLog {
            id: "test_bam_1".to_string(),
            session_id: "test_session_1".to_string(),
            latencies: vec![0.1, 0.2, 0.3],
            mean_latency: 0.2,
            anomaly_score: 0.5,
            is_ai_like: false,
            confidence: 0.6,
            created_at: Utc::now(),
        };
        
        logger.log_bam_result(&bam_result).unwrap();
        
        let results = logger.get_bam_results().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "test_bam_1");
    }

    #[test]
    fn test_log_and_get_ram_dump() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();
        fs::create_dir_all(format!("{}/ram_dumps", logs_dir_path.to_str().unwrap())).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        
        let ram_dump = RamDumpLog {
            id: "test_dump_1".to_string(),
            session_id: "test_session_1".to_string(),
            timestamp: Utc::now(),
            memory_usage_mb: 100.0,
            suspicious_processes: vec![],
            network_connections: vec![],
            file_handles: vec![],
            created_at: Utc::now(),
        };
        
        logger.log_ram_dump(&ram_dump).unwrap();
        
        let dumps = logger.get_ram_dumps().unwrap();
        assert_eq!(dumps.len(), 1);
        assert_eq!(dumps[0].id, "test_dump_1");
    }

    #[test]
    fn test_get_session_alerts() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();
        fs::create_dir_all(format!("{}/alerts", logs_dir_path.to_str().unwrap())).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        
        let alert1 = AlertLog { id: "alert1".to_string(), session_id: "session1".to_string(), alert_type: "type1".to_string(), severity: "high".to_string(), message: "msg1".to_string(), metadata: serde_json::json!({}), created_at: Utc::now(), acknowledged_at: None, acknowledged_by: None };
        let alert2 = AlertLog { id: "alert2".to_string(), session_id: "session2".to_string(), alert_type: "type2".to_string(), severity: "low".to_string(), message: "msg2".to_string(), metadata: serde_json::json!({}), created_at: Utc::now(), acknowledged_at: None, acknowledged_by: None };
        let alert3 = AlertLog { id: "alert3".to_string(), session_id: "session1".to_string(), alert_type: "type3".to_string(), severity: "medium".to_string(), message: "msg3".to_string(), metadata: serde_json::json!({}), created_at: Utc::now(), acknowledged_at: None, acknowledged_by: None };

        logger.log_alert(&alert1).unwrap();
        logger.log_alert(&alert2).unwrap();
        logger.log_alert(&alert3).unwrap();

        let session1_alerts = logger.get_session_alerts("session1").unwrap();
        assert_eq!(session1_alerts.len(), 2);
        assert!(session1_alerts.iter().any(|a| a.id == "alert1"));
        assert!(session1_alerts.iter().any(|a| a.id == "alert3"));
    }

    #[test]
    fn test_append_to_log_file() {
        let temp_dir = tempdir().unwrap();
        let logs_dir_path = temp_dir.path().join("logs");
        fs::create_dir_all(&logs_dir_path).unwrap();

        let logger = FileLogger { logs_dir: logs_dir_path.to_str().unwrap().to_string() };
        let log_entry1 = "First log entry.";
        let log_entry2 = "Second log entry.";

        logger.append_to_log_file(log_entry1).unwrap();
        logger.append_to_log_file(log_entry2).unwrap();

        let log_file_content = fs::read_to_string(format!("{}/cluelyguard.log", logs_dir_path.to_str().unwrap())).unwrap();
        assert!(log_file_content.contains(log_entry1));
        assert!(log_file_content.contains(log_entry2));
    }

    // Mocking for create_ram_dump is complex due to procfs and sysinfo.
    // A basic test to ensure it runs without immediate errors.
    #[test]
    fn test_create_ram_dump_basic() {
        // This test relies on procfs and sysinfo, which interact with the actual system.
        // It's more of an integration test for the function's execution flow.
        // Mocking these dependencies would require a more advanced mocking framework.
        let session_id = "mock_session";
        let student_code = "mock_student";
        
        let result = FileLogger::create_ram_dump(session_id, student_code);
        assert!(result.is_ok(), "create_ram_dump failed: {:?}", result.err());
        let dump = result.unwrap();
        assert_eq!(dump.session_id, session_id);
        assert!(!dump.id.is_empty());
        assert!(dump.memory_usage_mb > 0.0); // Should be non-zero on a running system
    }
}