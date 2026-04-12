use crate::packet::{SphinxPacket};
use crate::intro_point::{IntroPointState, IntroRequest};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use std::sync::Arc;

/// Phase 10: Introduction Point (IP) Handler
pub struct IntroductionHandler {
    /// Channel to the service (pre-established introduction circuit)
    pub service_tx: Sender<SphinxPacket>,
    /// MED-05: Adaptive DoS protection state
    pub state: Arc<Mutex<IntroPointState>>,
}

impl IntroductionHandler {
    pub fn new(service_tx: Sender<SphinxPacket>, base_difficulty: u32) -> Self {
        Self { 
            service_tx,
            state: Arc::new(Mutex::new(IntroPointState::new(base_difficulty))),
        }
    }

    /// Handles an incoming INTRODUCE packet from a client.
    pub async fn handle_introduce(&self, packet: SphinxPacket) -> anyhow::Result<()> {
        // 1. Record hit and get difficulty
        let mut state = self.state.lock().await;
        state.record_request();
        let difficulty = state.get_dynamic_difficulty();
        
        // 2. Deserialize IntroRequest from payload
        let request: IntroRequest = bincode::deserialize(&packet.payload)
            .map_err(|_| anyhow::anyhow!("IP: Invalid IntroRequest payload"))?;

        // 3. Verify Adaptive PoW (MED-05)
        // Challenge is the service_id from the request
        if !crate::pow::verify_static_pow(&request.service_id, &request.pow_nonce, difficulty) {
            anyhow::bail!("IP: Dropping request due to insufficient PoW (difficulty {})", difficulty);
        }

        println!("IP: Valid INTRODUCE request (diff {}). Forwarding to service...", difficulty);
        
        // 4. Forward the encapsulated introduction to the service
        if let Err(e) = self.service_tx.send(packet).await {
            anyhow::bail!("IP: Failed to forward to service: {}", e);
        }
        
        Ok(())
    }
}
