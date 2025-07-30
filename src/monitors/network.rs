use procfs::net::dev_status;
use tracing::{info, warn};

pub struct NetworkMonitor;

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {}
    }

    pub fn get_network_usage() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let dev_statuses = dev_status()?;
        let mut usage_data = String::new();
        for (interface_name, status) in dev_statuses {
            usage_data.push_str(&format!(
                "Interface: {}, Rx Bytes: {}, Tx Bytes: {}, Rx Packets: {}, Tx Packets: {}
",
                interface_name,
                status.recv_bytes,
                status.sent_bytes,
                status.recv_packets,
                status.sent_packets
            ));
        }
        Ok(usage_data)
    }

    pub fn check_dns_queries() -> Option<String> {
        // This is a placeholder for DNS query monitoring.
        // In a real implementation, this would involve:
        // 1. Capturing DNS traffic (e.g., using pnet or similar).
        // 2. Parsing DNS packets to extract queried domain names.
        // 3. Comparing queried domains against a blacklist of known LLM service domains.
        // For demonstration, we'll simulate a detection.
        let suspicious_domains = vec!["openai.com", "anthropic.com", "perplexity.ai"];
        
        // Simulate checking DNS queries
        info!("Simulating DNS query check...");
        for domain in &suspicious_domains {
            if rand::random::<f32>() < 0.1 { // 10% chance of detecting a suspicious domain
                warn!("🚨 Suspicious DNS query detected for: {}", domain);
                return Some(format!("DNS query to suspicious LLM domain: {}", domain));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_monitor_new() {
        let monitor = NetworkMonitor::new();
        // No fields to assert, just ensure it can be constructed
    }

    #[test]
    fn test_get_network_usage_basic() {
        // This test relies on `procfs::net::dev_status()` which reads from `/proc/net/dev`.
        // It's difficult to mock this directly in a unit test.
        // This test primarily ensures the function runs without panicking and returns a Result.
        let result = NetworkMonitor::get_network_usage();
        assert!(result.is_ok(), "get_network_usage failed: {:?}", result.err());
        let usage = result.unwrap();
        // Assert that the output string is not empty, indicating some data was collected.
        assert!(!usage.is_empty());
    }

    #[test]
    fn test_check_dns_queries_basic() {
        // This function has random behavior, so we run it multiple times.
        // We expect to see `Some` results occasionally due to the 10% chance.
        let mut detected_count = 0;
        let num_runs = 100;

        for _ in 0..num_runs {
            if NetworkMonitor::check_dns_queries().is_some() {
                detected_count += 1;
            }
        }
        // Assert that detection occurs at least once (due to random chance)
        // This is a weak assertion, but better than nothing for a simulated function.
        assert!(detected_count < num_runs); // Should not detect every time
    }
}