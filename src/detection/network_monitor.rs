//! Network monitoring module for detecting AI service connections

use anyhow::Result;
use chrono::Utc;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, SocketInfo, ProtocolSocketInfo};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tracing::{debug, error, warn};
use trust_dns_resolver::TokioAsyncResolver;

use super::{DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel, NetworkMonitorConfig};

#[derive(Clone)]
pub struct NetworkMonitor {
    pub config: NetworkMonitorConfig,
    resolver: Option<TokioAsyncResolver>,
    ai_domain_set: HashSet<String>,
    blocked_ip_set: HashSet<IpAddr>,
}

impl NetworkMonitor {
    pub fn new(config: NetworkMonitorConfig) -> Result<Self> {
        // Initialize DNS resolver
        let resolver: Option<TokioAsyncResolver> = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => Some(r),
            Err(e) => {
                warn!("Failed to initialize DNS resolver from system config: {}", e);
                None
            }
        };

        let ai_domain_set = config.ai_domains.iter().cloned().collect();
        let blocked_ip_set = config
            .blocked_ips
            .iter()
            .filter_map(|ip_str| ip_str.parse().ok())
            .collect();

        Ok(Self {
            config,
            resolver,
            ai_domain_set,
            blocked_ip_set,
        })
    }

    pub async fn scan(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();

        // Get network connections
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        match get_sockets_info(af_flags, proto_flags) {
            Ok(sockets) => {
                debug!("Scanning {} network connections", sockets.len());

                for socket in sockets {
                    if let Some(event) = self.analyze_connection(&socket).await {
                        events.push(event);
                    }
                }
            }
            Err(e) => {
                error!("Failed to get socket information: {}", e);
            }
        }

        debug!("Found {} suspicious network connections", events.len());
        Ok(events)
    }

    pub fn update_config(&mut self, config: NetworkMonitorConfig) -> Result<()> {
        self.ai_domain_set = config.ai_domains.iter().cloned().collect();
        self.blocked_ip_set = config
            .blocked_ips
            .iter()
            .filter_map(|ip_str| ip_str.parse().ok())
            .collect();
        self.config = config;
        Ok(())
    }

    async fn analyze_connection(&self, socket: &SocketInfo) -> Option<DetectionEvent> {
        let (local_ip, local_port, remote_ip_option, remote_port_option, protocol_str) = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(info) => (info.local_addr, info.local_port, Some(info.remote_addr), Some(info.remote_port), "TCP"),
            ProtocolSocketInfo::Udp(info) => (info.local_addr, info.local_port, None, None, "UDP"),
        };

        let local_addr = SocketAddr::new(local_ip, local_port);
        let remote_ip = remote_ip_option.unwrap_or_else(|| "0.0.0.0".parse().unwrap());
        let remote_port = remote_port_option.unwrap_or(0); // Default to 0 for UDP remote port if not available

        let remote_addr = SocketAddr::new(remote_ip, remote_port);

        // Skip localhost connections
        if self.is_localhost(&remote_ip) {
            return None;
        }

        // Check blocked IPs
        if self.blocked_ip_set.contains(&remote_ip) {
            return Some(self.create_network_event(
                local_addr,
                remote_addr,
                protocol_str.to_string(),
                None,
                "Blocked IP".to_string(),
                ThreatLevel::High,
            ));
        }

        // Perform reverse DNS lookup to get domain
        if let Some(domain) = self.reverse_dns_lookup(&remote_ip).await {
            // Check against AI domains
            for ai_domain in &self.config.ai_domains {
                if domain.ends_with(ai_domain) || domain.contains(ai_domain) {
                    return Some(self.create_network_event(
                        local_addr,
                        remote_addr,
                        protocol_str.to_string(),
                        Some(domain),
                        ai_domain.clone(),
                        self.calculate_domain_threat_level(ai_domain),
                    ));
                }
            }

            // Check for suspicious patterns in domain
            if self.is_suspicious_domain(&domain) {
                return Some(self.create_network_event(
                    local_addr,
                    remote_addr,
                    protocol_str.to_string(),
                    Some(domain.clone()),
                    "Suspicious domain pattern".to_string(),
                    ThreatLevel::Medium,
                ));
            }
        }

        // Check for suspicious ports
        if self.is_suspicious_port(remote_port) {
            return Some(self.create_network_event(
                local_addr,
                remote_addr,
                protocol_str.to_string(),
                None,
                format!("Suspicious port: {}", remote_port),
                ThreatLevel::Low,
            ));
        }

        None
    }

    async fn reverse_dns_lookup(&self, ip: &IpAddr) -> Option<String> {
        if let Some(resolver) = &self.resolver {
            match resolver.reverse_lookup(*ip).await {
                Ok(lookup) => lookup.iter().next().map(|name| name.to_string()),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    fn is_localhost(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_loopback() ||
                ipv4.is_private() ||
                *ipv4 == Ipv4Addr::new(0, 0, 0, 0)
            }
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        }
    }

    fn is_suspicious_domain(&self, domain: &str) -> bool {
        let suspicious_patterns = [
            "ai-", "-ai", "chatgpt", "claude", "gemini", "openai",
            "anthropic", "gpt-", "llm-", "assistant", "copilot"
        ];

        let domain_lower = domain.to_lowercase();
        suspicious_patterns
            .iter()
            .any(|pattern| domain_lower.contains(pattern))
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        // Common AI/ML service ports
        matches!(port, 8080 | 8888 | 9000 | 11434 | 1337)
    }

    fn calculate_domain_threat_level(&self, domain: &str) -> ThreatLevel {
        let critical_domains = ["openai.com", "chat.openai.com", "claude.ai", "anthropic.com"];
        let high_domains = ["gemini.google.com", "copilot.github.com"];

        if critical_domains.contains(&domain) {
            ThreatLevel::Critical
        } else if high_domains.contains(&domain) {
            ThreatLevel::High
        } else {
            ThreatLevel::Medium
        }
    }

    fn create_network_event(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol: String,
        domain: Option<String>,
        matched_domain: String,
        threat_level: ThreatLevel,
    ) -> DetectionEvent {

        DetectionEvent {
            id: uuid::Uuid::new_v4(),
            detection_type: "Network Connection".to_string(),
            module: DetectionModule::NetworkMonitor,
            threat_level,
            description: format!("Suspicious network connection to {}",
                                domain.as_deref().unwrap_or(&remote_addr.ip().to_string())),
            details: DetectionDetails::Network {
                local_addr: local_addr.to_string(),
                remote_addr: remote_addr.to_string(),
                domain,
                port: remote_addr.port(),
                protocol,
                matched_domain,
            },
            timestamp: Utc::now(),
            source: Some("Network Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }
}
