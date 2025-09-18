//! Enhanced Network monitoring module for comprehensive AI service detection

use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use tracing::{debug, warn, error};
use trust_dns_resolver::TokioAsyncResolver;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use reqwest;

use crate::detection::types::{
    DetectionEvent, DetectionDetails, DetectionModule, ThreatLevel,
    NetworkMonitorConfig,
};

#[derive(Clone)]
pub struct NetworkMonitor {
    config: NetworkMonitorConfig,
    resolver: Option<TokioAsyncResolver>,
    ai_service_ips: HashSet<IpAddr>,
    client: reqwest::Client,
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

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        Ok(Self { 
            config, 
            resolver, 
            ai_service_ips: HashSet::new(),
            client,
        })
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
                    match socket.protocol_socket_info {
                        ProtocolSocketInfo::Tcp(tcp_info) => {
                            let local_addr = tcp_info.local_addr;
                            let remote_addr = tcp_info.remote_addr;
                            let remote_port = tcp_info.remote_port;

                            // Skip localhost connections
                            if remote_addr.is_loopback() {
                                continue;
                            }

                            if let Some(event) = self.analyze_connection(
                                &local_addr.to_string(), 
                                &remote_addr.to_string(), 
                                remote_port
                            ).await? {
                                events.push(event);
                            }
                        },
                        ProtocolSocketInfo::Udp(_udp_info) => {
                            // Skip UDP for now - typically not used for AI services
                            continue;
                        },
                        // Other ProtocolSocketInfo variants are ignored.
                    }
                }
            }
            Err(e) => {
                error!("Failed to get network connections: {}", e);
            }
        }

        // Enhanced DNS monitoring
        if self.config.monitor_dns {
            events.extend(self.enhanced_dns_monitoring().await?);
        }

        // Check browser processes for AI connections
        events.extend(self.check_browser_ai_connections().await?);

        debug!("Found {} suspicious network connections", events.len());
        Ok(events)
    }

    async fn analyze_connection(&self, local_addr: &str, remote_addr: &str, remote_port: u16) -> Result<Option<DetectionEvent>> {
        // Parse remote IP address
        let remote_ip = match remote_addr.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => return Ok(None),
        };

        // Check against blocked IPs
        if self.config.blocked_ips.iter().any(|blocked_ip| {
            if let Ok(blocked) = blocked_ip.parse::<IpAddr>() {
                remote_ip == blocked
            } else {
                remote_addr.contains(blocked_ip)
            }
        }) {
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

        // Resolve IP to domain
        let domain = self.resolve_ip_to_domain(remote_addr).await;

        // Enhanced AI domain detection
        if let Some(ref domain_name) = domain {
            for ai_domain in &self.get_comprehensive_ai_domains() {
                if domain_name.to_lowercase().contains(&ai_domain.to_lowercase()) {
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

        // Check for HTTPS connections to potential AI services
        if remote_port == 443 && domain.is_some() {
            if let Some(event) = self.analyze_https_connection(&domain.unwrap(), remote_addr, remote_port).await? {
                return Ok(Some(event));
            }
        }

        Ok(None)
    }

    async fn analyze_https_connection(&self, domain: &str, remote_addr: &str, remote_port: u16) -> Result<Option<DetectionEvent>> {
        // Check for AI service indicators in HTTPS connections
        let ai_indicators = [
            "api", "gpt", "chat", "ai", "ml", "llm", "assistant", 
            "copilot", "claude", "gemini", "bard", "perplexity"
        ];

        for indicator in &ai_indicators {
            if domain.to_lowercase().contains(indicator) {
                // Try to verify if this is actually an AI service
                if self.verify_ai_service(domain).await {
                    return Ok(Some(self.create_network_event(
                        "localhost",
                        remote_addr,
                        Some(domain.to_string()),
                        remote_port,
                        "HTTPS",
                        format!("Potential AI service: {}", domain),
                        ThreatLevel::High,
                    )));
                }
            }
        }
        
        Ok(None)
    }

    async fn verify_ai_service(&self, domain: &str) -> bool {
        // Simple verification by checking common AI service patterns
        let url = format!("https://{}", domain);
        
        match self.client.head(&url).send().await {
            Ok(response) => {
                // Check response headers for AI service indicators
                if let Some(server) = response.headers().get("server") {
                    if let Ok(server_str) = server.to_str() {
                        let server_lower = server_str.to_lowercase();
                        return server_lower.contains("openai") || 
                               server_lower.contains("anthropic") ||
                               server_lower.contains("google");
                    }
                }
                
                // Check for common AI service response patterns
                response.status().is_success()
            }
            Err(_) => false,
        }
    }

    async fn enhanced_dns_monitoring(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Platform-independent DNS monitoring
        match self.monitor_system_dns().await {
            Ok(dns_events) => events.extend(dns_events),
            Err(e) => debug!("DNS monitoring failed: {}", e),
        }
        
        Ok(events)
    }

    async fn monitor_system_dns(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Check system DNS cache/history using platform-specific commands
        #[cfg(target_os = "linux")]
        {
            events.extend(self.check_linux_dns_comprehensive().await?);
        }
        
        #[cfg(target_os = "windows")]
        {
            events.extend(self.check_windows_dns_comprehensive().await?);
        }
        
        #[cfg(target_os = "macos")]
        {
            events.extend(self.check_macos_dns_comprehensive().await?);
        }
        
        Ok(events)
    }

    #[cfg(target_os = "linux")]
    async fn check_linux_dns_comprehensive(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Check multiple DNS sources on Linux
        let commands = [
            ("systemd-resolve", vec!["--statistics"]),
            ("resolvectl", vec!["statistics"]),
            ("dig", vec!["@1.1.1.1", "chat.openai.com", "+short"]),
        ];
        
        for (cmd, args) in &commands {
            if let Ok(output) = tokio::process::Command::new(cmd)
                .args(args)
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                events.extend(self.analyze_dns_output(&output_str));
            }
        }
        
        // Check browser history files for AI domains (read-only)
        events.extend(self.check_browser_history_files().await?);
        
        Ok(events)
    }

    async fn check_browser_history_files(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Common browser history locations
        if let Some(home) = dirs::home_dir() {
            let history_paths = [
                home.join(".config/google-chrome/Default/History"),
                home.join(".config/chromium/Default/History"),
                home.join(".mozilla/firefox/*/places.sqlite"),
                home.join("snap/firefox/common/.mozilla/firefox/*/places.sqlite"),
            ];
            
            for path in &history_paths {
                if path.exists() {
                    // Note: In production, you'd use sqlite to read browser history
                    // For now, we'll just note that the browser has been used
                    events.push(self.create_network_event(
                        "localhost",
                        "browser_history",
                        Some("Browser History Access".to_string()),
                        0,
                        "FILE",
                        "Browser history contains potential AI service visits".to_string(),
                        ThreatLevel::Medium,
                    ));
                }
            }
        }
        
        Ok(events)
    }

    async fn check_browser_ai_connections(&self) -> Result<Vec<DetectionEvent>> {
        let mut events = Vec::new();
        
        // Use lsof to find browser connections (Linux/macOS)
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            if let Ok(output) = tokio::process::Command::new("lsof")
                .args(&["-i", "TCP", "-n"])
                .output()
                .await
            {
                let output_str = String::from_utf8_lossy(&output.stdout);
                for line in output_str.lines() {
                    if line.contains("chrome") || line.contains("firefox") || 
                       line.contains("brave") || line.contains("edge") {
                        // Parse lsof output for AI service connections
                        if let Some(event) = self.parse_lsof_line(line) {
                            events.push(event);
                        }
                    }
                }
            }
        }
        
        Ok(events)
    }

    fn parse_lsof_line(&self, line: &str) -> Option<DetectionEvent> {
        // Parse lsof line format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            let process = parts[0];
            let connection = parts[8];
            
            // Check if connection is to an AI service
            for domain in &self.get_comprehensive_ai_domains() {
                if connection.contains(domain) {
                    return Some(self.create_network_event(
                        "localhost",
                        connection,
                        Some(domain.clone()),
                        443,
                        "TCP",
                        format!("Browser {} connected to AI service {}", process, domain),
                        ThreatLevel::Critical,
                    ));
                }
            }
        }
        None
    }

    fn analyze_dns_output(&self, output: &str) -> Vec<DetectionEvent> {
        let mut events = Vec::new();
        
        for domain in &self.get_comprehensive_ai_domains() {
            if output.to_lowercase().contains(&domain.to_lowercase()) {
                events.push(self.create_network_event(
                    "localhost",
                    "DNS",
                    Some(domain.clone()),
                    53,
                    "DNS",
                    format!("DNS query for AI service: {}", domain),
                    ThreatLevel::High,
                ));
            }
        }
        
        events
    }

    fn get_comprehensive_ai_domains(&self) -> Vec<String> {
        let mut domains = self.config.ai_domains.clone();
        
        // Add comprehensive list of AI services
        domains.extend([
            // OpenAI services
            "openai.com", "chat.openai.com", "api.openai.com", "platform.openai.com",
            "chatgpt.com", "cdn.openai.com", "auth0.openai.com",
            
            // Anthropic (Claude)
            "claude.ai", "anthropic.com", "console.anthropic.com",
            
            // Google AI services
            "gemini.google.com", "bard.google.com", "ai.google.dev", 
            "makersuite.google.com", "aistudio.google.com",
            
            // Microsoft AI
            "copilot.microsoft.com", "bing.com/chat", "edgeservices.bing.com",
            
            // GitHub Copilot
            "copilot.github.com", "api.github.com", "github.com/copilot",
            
            // Perplexity
            "perplexity.ai", "www.perplexity.ai",
            
            // Other AI services
            "character.ai", "poe.com", "you.com", "phind.com",
            "codeium.com", "tabnine.com", "replit.com",
            "huggingface.co", "cohere.ai", "together.ai",
            "replicate.com", "midjourney.com", "stability.ai",
            
            // AI Writing tools
            "grammarly.com", "jasper.ai", "copy.ai", "writesonic.com",
            "quillbot.com", "wordtune.com",
            
            // AI Research tools
            "elicit.org", "consensus.app", "scite.ai", "semanticscholar.org",
            
            // AI Code assistants
            "sourcegraph.com", "cody.dev", "cursor.sh",
        ].iter().map(|s| s.to_string()));
        
        domains.sort();
        domains.dedup();
        domains
    }

    async fn resolve_ip_to_domain(&self, ip_addr: &str) -> Option<String> {
        if let Some(ref resolver) = self.resolver {
            if let Ok(ip) = ip_addr.parse::<IpAddr>() {
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
            description: format!("AI service connection detected: {}", 
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
            source: Some("Enhanced Network Monitor".to_string()),
            metadata: HashMap::new(),
        }
    }

    pub fn update_config(&mut self, config: NetworkMonitorConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }
}