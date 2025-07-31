use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

// A simple DNS packet structure for parsing
struct DnsPacket<'a> {
    _header: DnsHeader,
    questions: Vec<DnsQuestion<'a>>,
}

struct DnsHeader {
    _id: u16,
    _flags: u16,
    qdcount: u16,
    _ancount: u16,
    _nscount: u16,
    _arcount: u16,
}

struct DnsQuestion<'a> {
    qname: String,
    _qtype: u16,
    _qclass: u16,
    _phantom: std::marker::PhantomData<&'a ()>, // To satisfy lifetime requirements
}

impl<'a> DnsPacket<'a> {
    fn from_bytes(packet: &'a [u8]) -> Option<Self> {
        if packet.len() < 12 {
            return None; // Not enough bytes for DNS header
        }
        let header = DnsHeader {
            _id: u16::from_be_bytes([packet[0], packet[1]]),
            _flags: u16::from_be_bytes([packet[2], packet[3]]),
            qdcount: u16::from_be_bytes([packet[4], packet[5]]),
            _ancount: u16::from_be_bytes([packet[6], packet[7]]),
            _nscount: u16::from_be_bytes([packet[8], packet[9]]),
            _arcount: u16::from_be_bytes([packet[10], packet[11]]),
        };

        let mut offset = 12;
        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let mut qname_parts = Vec::new();
            loop {
                if offset >= packet.len() {
                    return None; // Malformed packet
                }
                let len = packet[offset] as usize;
                offset += 1;
                if len == 0 {
                    break;
                }
                if offset + len > packet.len() {
                    return None; // Malformed packet
                }
                qname_parts.push(String::from_utf8_lossy(&packet[offset..offset + len]).to_string());
                offset += len;
            }
            if offset + 4 > packet.len() {
                return None; // Malformed packet (qtype and qclass missing)
            }
            let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
            offset += 4;

            questions.push(DnsQuestion {
                qname: qname_parts.join("."),
                _qtype: qtype,
                _qclass: qclass,
                _phantom: std::marker::PhantomData,
            });
        }
        Some(DnsPacket { _header: header, questions })
    }
}

pub struct NetworkMonitor {
    // Add fields for network monitoring here
    stop_signal: Arc<AtomicBool>,
    detected_domains: Arc<Mutex<HashSet<String>>>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        NetworkMonitor {
            stop_signal: Arc::new(AtomicBool::new(false)),
            detected_domains: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn start_monitoring(&self) {
        info!("Starting network monitoring...");
        let interfaces = datalink::interfaces();
        let default_interface = interfaces
            .into_iter()
            .filter(|iface: &NetworkInterface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .next()
            .expect("No active network interface found!");

        info!("Monitoring on interface: {}", default_interface.name);

        let (_, mut rx) = match datalink::channel(&default_interface, datalink::Config::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error creating datalink channel: {}", e),
        };

        let stop_signal = self.stop_signal.clone();
        let detected_domains = self.detected_domains.clone();
        let suspicious_llm_domains: HashSet<String> = [
            "openai.com",
            "anthropic.com",
            "perplexity.ai",
            "cohere.ai",
            "huggingface.co",
            "deepmind.com",
            "nvidia.com",
            "replicate.com",
            "ai.google.com",
            "aws.amazon.com", // AWS AI/ML services
            "azure.microsoft.com", // Azure AI/ML services
            "cloud.google.com", // Google Cloud AI/ML services
        ]
        .iter()
        .map(|&s| s.to_string())
        .collect();

        thread::spawn(move || {
            while !stop_signal.load(Ordering::Relaxed) {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ethernet) = EthernetPacket::new(packet) {
                            match ethernet.get_ethertype() {
                                EtherTypes::Ipv4 => {
                                    if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                                // Check for DNS (port 53)
                                                if udp.get_destination() == 53 || udp.get_source() == 53 {
                                                    if let Some(dns_packet) = DnsPacket::from_bytes(udp.payload()) {
                                                        for question in dns_packet.questions {
                                                            let domain = question.qname;
                                                            info!("DNS Query: {}", domain);
                                                            if suspicious_llm_domains.contains(&domain) {
                                                                warn!("🚨 Suspicious DNS query to LLM domain detected: {}", domain);
                                                                detected_domains.lock().unwrap().insert(domain);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error receiving packet: {}", e);
                        // Consider breaking or more robust error handling
                    }
                }
            }
            info!("Network monitoring stopped.");
        });
    }

    pub fn stop_monitoring(&self) {
        info!("Stopping network monitoring...");
        self.stop_signal.store(true, Ordering::Relaxed);
    }

    pub fn get_detected_llm_domains(&self) -> Vec<String> {
        let domains = self.detected_domains.lock().unwrap();
        domains.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_network_monitor_new() {
        let monitor = NetworkMonitor::new();
        assert!(!monitor.stop_signal.load(Ordering::Relaxed));
        assert!(monitor.detected_domains.lock().unwrap().is_empty());
    }

    // This test requires root privileges to run `pnet::datalink::channel`,
    // so it might fail in CI/CD environments without proper setup.
    // It's also non-deterministic due to real network traffic.
    // To make it more robust, you'd need to mock the pnet library.
    #[test]
    #[ignore = "Requires root privileges and real network traffic"]
    fn test_network_monitor_start_and_stop() {
        let monitor = NetworkMonitor::new();
        monitor.start_monitoring();
        thread::sleep(Duration::from_secs(2)); // Let it monitor for a bit
        monitor.stop_monitoring();
        thread::sleep(Duration::from_secs(1)); // Give thread time to shut down

        // You might assert on logs or specific side effects if mocked
        // For now, just ensure it doesn't panic.
        info!("Test network monitor started and stopped successfully.");
    }

    #[test]
    fn test_get_detected_llm_domains() {
        let monitor = NetworkMonitor::new();
        {
            let mut domains = monitor.detected_domains.lock().unwrap();
            domains.insert("test.openai.com".to_string());
            domains.insert("test.anthropic.com".to_string());
        }
        let detected = monitor.get_detected_llm_domains();
        assert_eq!(detected.len(), 2);
        assert!(detected.contains(&"test.openai.com".to_string()));
        assert!(detected.contains(&"test.anthropic.com".to_string()));
    }

    // Basic test for DNS packet parsing (without real network capture)
    #[test]
    fn test_dns_packet_from_bytes() {
        // Example of a simple DNS query for "example.com"
        // This is a simplified mock, a real DNS query packet is more complex
        let dns_query_bytes: [u8; 29] = [ // Corrected size to 29
            0x00, 0x01, // ID
            0x01, 0x00, // Flags (Standard query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // 7-byte label "example"
            0x03, b'c', b'o', b'm', // 3-byte label "com"
            0x00, // Null terminator
            0x00, 0x01, // QTYPE (A record)
            0x00, 0x01, // QCLASS (IN)
        ];

        let dns_packet = DnsPacket::from_bytes(&dns_query_bytes).unwrap();
        assert_eq!(dns_packet.questions.len(), 1);
        assert_eq!(dns_packet.questions[0].qname, "example.com");

        // Test with malformed packet (too short)
        assert!(DnsPacket::from_bytes(&dns_query_bytes[0..10]).is_none());
    }
}