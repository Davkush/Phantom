use igd::aio::search_gateway;
use igd::PortMappingProtocol;
use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::time::Duration;

/// Phase 10: Production Hardening - NAT Traversal
/// Handles UPnP and NAT-PMP mapping to ensure Relay nodes are publicly accessible.
pub struct PortMapper {
    external_addr: Option<SocketAddr>,
}

impl PortMapper {
    pub fn new() -> Self {
        Self { external_addr: None }
    }

    /// Attempts to map a local port to an external port via UPnP.
    /// Addressing accessibility for home-based relays.
    pub async fn map_port(&mut self, local_port: u16) -> anyhow::Result<SocketAddr> {
        println!("NAT: Searching for UPnP gateway (5s timeout)...");
        
        // Use a 5s search timeout
        let gateway = match tokio::time::timeout(
            Duration::from_secs(5), 
            search_gateway(Default::default())
        ).await {
            Ok(Ok(g)) => g,
            Ok(Err(e)) => anyhow::bail!("UPnP Search Error: {}", e),
            Err(_) => anyhow::bail!("UPnP Search Timeout (No gateway found)"),
        };

        // Standard IP for local bind (in a real node, we'd use the local NIC IP)
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), local_port);
        
        println!("NAT: Mapping external UDP port {} to local {}...", local_port, local_port);
        
        // Phantom uses UDP for the QUIC physical transport
        gateway.add_port(
            PortMappingProtocol::UDP,
            local_port,
            local_addr,
            0, // Lifetime (0 = permanent/automatic)
            "Phantom Node",
        ).await?;

        let ext_ip = gateway.get_external_ip().await?;
        let ext_addr = SocketAddr::new(ext_ip, local_port);
        self.external_addr = Some(ext_addr);
        
        println!("NAT: Port mapping SUCCESS! External Address: {}", ext_addr);
        Ok(ext_addr)
    }

    pub fn external_address(&self) -> Option<SocketAddr> {
        self.external_addr
    }
}
