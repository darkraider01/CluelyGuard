use crate::config::AppConfig;
use crate::logger::{FileLogger, RamDumpLog};
use crate::monitors::bam_realtime::BamMonitoringService;
use crate::monitors::browser::BrowserMonitor;
use crate::monitors::fs_monitor::FileSystemMonitor;
use crate::monitors::network::NetworkMonitor;
use crate::monitors::output_analysis::OutputAnalyzer;
use crate::monitors::process::scan as process_scan; // Alias to avoid name collision
use crate::monitors::screensharing::ScreenSharingMonitor;
use crate::monitors::syscall_monitor::SyscallMonitor;
use crate::monitors::user_activity::UserActivityMonitor;
use crate::network::NetworkClient;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};
use chrono::Utc;

pub struct MonitoringCoordinator {
    config: Arc<AppConfig>,
    file_logger: Arc<FileLogger>,
    network_client: Option<Arc<NetworkClient>>,
    student_code: String,
    network_monitor: NetworkMonitor,
    browser_monitor: BrowserMonitor,
    syscall_monitor: SyscallMonitor,
    user_activity_monitor: UserActivityMonitor,
    output_analyzer: OutputAnalyzer,
}

impl MonitoringCoordinator {
    pub fn new(
        config: Arc<AppConfig>,
        file_logger: Arc<FileLogger>,
        network_client: Option<Arc<NetworkClient>>,
        student_code: String,
    ) -> Self {
        let network_monitor = NetworkMonitor::new();
        network_monitor.start_monitoring(); // Start the background thread

        let browser_monitor = BrowserMonitor::new();
        // browser_monitor.start_monitoring(); // No such method

        let mut syscall_monitor = SyscallMonitor::new();
        if let Err(e) = syscall_monitor.start_monitoring() {
            error!("Failed to start syscall monitor: {}", e);
        }

        let mut user_activity_monitor = UserActivityMonitor::new();
        if let Err(e) = user_activity_monitor.start_monitoring() {
            error!("Failed to start user activity monitor: {}", e);
        }

        let output_analyzer = OutputAnalyzer::new();

        MonitoringCoordinator {
            config,
            file_logger,
            network_client,
            student_code,
            network_monitor,
            browser_monitor,
            syscall_monitor,
            user_activity_monitor,
            output_analyzer,
        }
    }

    pub async fn start_monitoring_loop(&mut self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        loop {
            interval.tick().await;

            // Check for suspicious file system activity
            let mut fs_monitor = FileSystemMonitor::new();
            let fs_events = fs_monitor.get_events();
            for suspicion in fs_events {
                self.log_and_send_event("fs_suspicion", &format!("{:?}", suspicion)).await;
            }

            // Analyze browser activity
            let browser_extensions = self.browser_monitor.scan_all_extensions();
            for extension in browser_extensions {
                self.log_and_send_event("browser_suspicion", &format!("{:?}", extension)).await;
            }

            // Simulate output analysis
            let simulated_output = "This is a simulated output. I am a large language model.";
            let analysis_result = self.output_analyzer.analyze_text(simulated_output);
            if analysis_result.is_suspicious {
                self.log_and_send_event("output_suspicion", &format!("{:?}", analysis_result)).await;
            }

            // Check for suspicious syscall activity
            let syscall_detections = self.syscall_monitor.analyze_patterns();
            for detection in syscall_detections {
                self.log_and_send_event("syscall_suspicion", &format!("{:?}", detection)).await;
            }

            // Check for suspicious user activity
            let user_activities = self.user_activity_monitor.get_recent_activities(std::time::SystemTime::now() - std::time::Duration::from_secs(60));
            for activity in user_activities {
                if activity.suspicious {
                    self.log_and_send_event("user_activity_suspicion", &format!("{:?}", activity)).await;
                }
            }

            // Check for screensharing activity
            let screensharing_events = ScreenSharingMonitor::new().detect_screen_capture();
            for event in screensharing_events {
                self.log_and_send_event("screensharing_suspicion", &format!("{:?}", event)).await;
            }

            // Retrieve detected LLM domains from the network monitor
            let detected_llm_domains = self.network_monitor.get_detected_llm_domains();
            if !detected_llm_domains.is_empty() {
                self.log_and_send_event("network_suspicion", &format!("{:?}", detected_llm_domains)).await;
            }

            // Periodically scan processes for suspicious AI tools
            let process_scan_result = process_scan(&self.config);
            if !process_scan_result.suspicious_processes.is_empty() {
                self.log_and_send_event("process_suspicion", &format!("{:?}", process_scan_result.suspicious_processes)).await;
            }
        }
    }

    async fn log_and_send_event(&self, event_type: &str, data: &str) {
        let log_entry = format!(
            "{{ \"type\": \"{}\", \"student_code\": \"{}\", \"timestamp\": \"{}\", \"data\": {} }}",
            event_type,
            self.student_code,
            Utc::now().to_rfc3339(),
            data
        );

        if let Err(e) = self.file_logger.append_to_log_file(&log_entry) {
            error!("Failed to log {} suspicion: {}", event_type, e);
        }

        #[cfg(not(feature = "local_test"))]
        if let Some(network_client) = &self.network_client {
            if let Err(e) = network_client.send_data(log_entry).await {
                error!("Failed to send {} suspicion to teacher PC: {}", event_type, e);
            }
        }
    }
}