use std::collections::HashMap;
use tokio::sync::mpsc::Sender;
use crate::packet::SphinxPacket;
use std::time::{Instant, Duration};

/// Phase 10: Rendezvous Point (RP) Splicer
/// The RP is the central node where the Service circuit and Client circuit 
/// meet in the double-blind handshake.
pub struct RendezvousSplicer {
    /// Maps Cookie -> (Sender to one side, Expiry)
    /// Side A: Client, Side B: Service
    pending: HashMap<[u8; 32], (Sender<SphinxPacket>, Instant)>,
}

impl RendezvousSplicer {
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    /// Attempts to splice two sides of a rendezvous connection.
    /// Returns the Sender for the 'other half' if the cookie matches.
    pub async fn splice(
        &mut self, 
        cookie: [u8; 32], 
        tx: Sender<SphinxPacket>
    ) -> anyhow::Result<Option<Sender<SphinxPacket>>> {
        // 1. Cleanup expired handshakes (30s timeout)
        self.pending.retain(|_, (_, expiry)| *expiry > Instant::now());

        // 2. Check for matching cookie
        if let Some((other_tx, _)) = self.pending.remove(&cookie) {
            println!("RP: Handshake match! Splicing bidirectional streams for cookie {:x?}...", &cookie[0..8]);
            Ok(Some(other_tx))
        } else {
            // 3. First arrival - store and wait
            println!("RP: Received first half of rendezvous. Waiting for second half...");
            self.pending.insert(cookie, (tx, Instant::now() + Duration::from_secs(30)));
            Ok(None)
        }
    }
}
