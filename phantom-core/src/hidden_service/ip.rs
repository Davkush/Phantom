use crate::packet::{SphinxPacket, NodeId};
use tokio::sync::mpsc::Sender;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct IntroduceData {
    pub rendezvous_node: NodeId,
    pub rendezvous_cookie: [u8; 32],
    pub client_ephemeral_key: [u8; 32], // For E2E handshake with service
}

/// Phase 10: Introduction Point (IP) Handler
/// A relay node acting as an IP facilitates the initial handshake 
/// without knowing the service's physical location.
pub struct IntroductionHandler {
    /// Channel to the service (pre-established introduction circuit)
    pub service_tx: Sender<SphinxPacket>,
}

impl IntroductionHandler {
    pub fn new(service_tx: Sender<SphinxPacket>) -> Self {
        Self { service_tx }
    }

    /// Handles an incoming INTRODUCE packet from a client.
    /// The packet is forwarded through the existing circuit to the hidden service.
    pub async fn handle_introduce(&self, packet: SphinxPacket) -> anyhow::Result<()> {
        println!("IP: Received INTRODUCE request. Forwarding to Hidden Service...");
        
        // Forward the encapsulated introduction to the service
        if let Err(e) = self.service_tx.send(packet).await {
            anyhow::bail!("IP: Failed to forward to service: {}", e);
        }
        
        Ok(())
    }
}
