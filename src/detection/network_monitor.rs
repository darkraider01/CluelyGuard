//! Network monitoring module for detecting AI service connections

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, warn, error};
use trust_dns_resolver::TokioAsyncResolver;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
    NetworkMonitorConfig,
};

#[derive(Clone)]
pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    resolver: Option<TokioAsyncResolver>,
}

impl NetworkMonitor {
    pub fn new(config: NetworkMonitorConfig) -> Result<Self> {
        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => Some(r),
            Err(e) => {
                warn!("Failed to initialize DNS resolver: {}", e);
                None
            }
        };

        Ok(Self { config, resolver })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        debug!("Scanning network connections...");

        // Get active network connections
        let address_family = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let protocol_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        match get_sockets_info(address_family, protocol_flags) {
            Ok(sockets) => {
                for socket in sockets {
                    let (local_addr_str, remote_addr_str, remote_port) = match socket.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(tcp_info) => {
                            let local_addr = tcp_info.local_addr;
                            let remote_addr = tcp_info.remote_addr;
                            let remote_port = tcp_info.remote_port; // Get port directly from tcp_info
                            (local_addr.to_string(), remote_addr.to_string(), remote_port)
                        },
                        ProtocolSocketInfo::Udp(udp_info) => {
                            // UdpSocketInfo does not have a remote_addr field directly.
                            // Skipping analysis for UDP sockets that require a remote address.
                            continue;
                        },
                        _ => {
                            continue; // Ignore other protocols for now
                        }
                    };

                    // Check if connection is to a known AI service
                    if let Some(event) = self.analyze_connection(&local_addr_str, &remote_addr_str, remote_port).await? {
                        events.push(event);
                    }
                }
            }
            Err(e) => {
                error!("Failed to get network connections: {}", e);
            }
        }

        // Check DNS queries if monitoring is enabled
        if self.config.monitor_dns {
            // Note: Real DNS monitoring would require privileged access
            // This is a simplified implementation
            events.extend(self.check_dns_activity().await?);
        }

        debug!("Found {} suspicious network connections", events.len());
        Ok(events)
    }

    async fn analyze_connection(&self, local_addr: &str, remote_addr: &str, remote_port: u16) -> Result<Option<DetectionEvent>> {
        // Check against blocked IPs
        if self.config.blocked_ips.iter().any(|ip| remote_addr.contains(ip)) {
            return Ok(Some(self.create_network_event(
                local_addr,
                remote_addr,
                None,
                remote_port,
                "TCP",
                "Blocked IP detected".to_string(),
                ThreatLevel::High,
            )));
        }

        // Resolve IP to domain if possible
        let domain = self.resolve_ip_to_domain(remote_addr).await;

        // Check against known AI domains
        if let Some(ref domain_name) = domain {
            for ai_domain in &self.config.ai_domains {
                if domain_name.contains(ai_domain) {
                    return Ok(Some(self.create_network_event(
                        local_addr,
                        remote_addr,
                        domain.clone(),
                        remote_port,
                        "TCP",
                        ai_domain.clone(),
                        ThreatLevel::Critical,
                    )));
                }
            }
        }

        // Check for suspicious ports
        let suspicious_ports = [443, 80, 8080, 8443]; // HTTPS, HTTP, common proxy ports
        if suspicious_ports.contains(&remote_port) && domain.is_some() {
            // Additional analysis could be done here for suspicious HTTPS connections
        }

        Ok(None)
    }

    async fn resolve_ip_to_domain(&self, ip_addr: &str) -> Option<String> {
        if let Some(ref resolver) = self.resolver {
            if let Ok(ip) = ip_addr.parse::<std::net::IpAddr>() {
                match resolver.reverse_lookup(ip).await {
                    Ok(names) => {
                        if let Some(name) = names.iter().next() {
                            return Some(name.to_string());
                        }
                    }
                    Err(_) => {
                        // Reverse DNS lookup failed, which is common
                    }
                }
            }
        }
        None
    }

    async fn check_dns_activity(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Note: This is a simplified implementation
        // Real DNS monitoring would require capturing DNS packets or monitoring system DNS cache
        
        // For demonstration, we'll check if any AI domains are in the system's DNS cache
        // This would need platform-specific implementation
        
        #[cfg(target_os = "windows")]
        {
            // On Windows, you could use `ipconfig /displaydns` and parse the output
            events.extend(self.check_windows_dns_cache().await?);
        }
        
        #[cfg(target_os = "linux")]
        {
            // On Linux, you could monitor /etc/hosts or use systemd-resolve
            events.extend(self.check_linux_dns_activity().await?);
        }
        
        #[cfg(target_os = "macos")]
        {
            // On macOS, you could use `dscacheutil -cachedump -entries Host`
            events.extend(self.check_macos_dns_cache().await?);
        }

        Ok(events)
    }

    #[cfg(target_os = "windows")]
    async fn check_windows_dns_cache(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Execute ipconfig /displaydns and parse output
        match tokio::process::Command::new("ipconfig")
            .args(&["/displaydns"])
            .output()
            .await
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for ai_domain in &self.config.ai_domains {
                    if output_str.contains(ai_domain) {
                        events.push(self.create_network_event(
                            "localhost",
                            "DNS Cache",
                            Some(ai_domain.clone()),
                            53,
                            "DNS",
                            ai_domain.clone(),
                            ThreatLevel::Medium,
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to check DNS cache: {}", e);
            }
        }
        
        Ok(events)
    }

    #[cfg(target_os = "linux")]
    async fn check_linux_dns_activity(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Check systemd-resolve statistics
        match tokio::process::Command::new("systemd-resolve")
            .args(&["--statistics"])
            .output()
            .await
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                // Parse for AI-related domains in recent queries
                for ai_domain in &self.config.ai_domains {
                    if output_str.contains(ai_domain) {
                        events.push(self.create_network_event(
                            "localhost",
                            "DNS",
                            Some(ai_domain.clone()),
                            53,
                            "DNS",
                            ai_domain.clone(),
                            ThreatLevel::Medium,
                        ));
                    }
                }
            }
            Err(_) => {
                // systemd-resolve not available, try other methods
            }
        }
        
        Ok(events)
    }

    #[cfg(target_os = "macos")]
    async fn check_macos_dns_cache(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Use dscacheutil to check DNS cache
        match tokio::process::Command::new("dscacheutil")
            .args(&["-cachedump", "-entries", "Host"])
            .output()
            .await
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for ai_domain in &self.config.ai_domains {
                    if output_str.contains(ai_domain) {
                        events.push(self.create_network_event(
                            "localhost",
                            "DNS Cache",
                            Some(ai_domain.clone()),
                            53,
                            "DNS",
                            ai_domain.clone(),
                            ThreatLevel::Medium,
                        ));
                    }
                }
            }
            Err(e) => {
                debug!("Failed to check DNS cache: {}", e);
            }
        }
        
        Ok(events)
    }

    fn create_network_event(
        &self,
        local_addr: &str,
        remote_addr: &str,
        domain: Option<String>,
        port: u16,
        protocol: &str,
        matched_domain: String,
        threat_level: ThreatLevel,
    ) -> DetectionEvent {
        DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Network Connection".to_string(),
            module: DetectionModule::NetworkMonitor,
            threat_level,
            description: format!("Suspicious network connection to: {}", 
                domain.as_ref().unwrap_or(&remote_addr.to_string())),
            details: DetectionDetails::Network {
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                domain,
                port,
                protocol: protocol.to_string(),
                matched_domain,
            },
            timestamp: Utc::now(),
            source: Some("Network Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }

    pub fn update_config(&mut self, config: NetworkMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }
}