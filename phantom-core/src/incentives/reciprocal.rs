use std::collections::HashMap;
use tokio::sync::RwLock;

/// Phase 11: Reciprocal Routing (Tit-for-Tat Engine)
/// Addressing INFO-02: Nodes prioritize traffic from peers with high successful interaction counts.
/// This prevents 'free-rider' nodes from consuming mixnet bandwidth without contributing.
pub struct ReciprocalTracker {
    /// Maps NodeID -> Successful Interaction Count
    pub scores: RwLock<HashMap<[u8; 32], u64>>,
}

impl ReciprocalTracker {
    pub fn new() -> Self {
        Self {
            scores: RwLock::new(HashMap::new()),
        }
    }

    /// Records a successful packet hand-off or processing for a peer.
    /// Peers that route traffic for us earn credits in our local ledger.
    pub async fn record_success(&self, node_id: [u8; 32]) {
        let mut scores = self.scores.write().await;
        let entry = scores.entry(node_id).or_insert(0);
        *entry = entry.saturating_add(1);
        
        // Log milestone periodically to the Sentinel TUI
        if *entry % 1000 == 0 {
            println!("Incentives: Node {:x?} reached {} successful interactions. Priority Lane active.", &node_id[0..4], *entry);
        }
    }

    /// Returns the priority boost (0-10) for a peer based on their Tit-for-Tat history.
    /// This boost is used by the Mix Processor to prioritize packet publication for this peer.
    pub async fn get_priority_boost(&self, node_id: [u8; 32]) -> u32 {
        let scores = self.scores.read().await;
        let score = scores.get(&node_id).copied().unwrap_or(0);
        
        // Priority boost logic: +1 for every 500 successful packets, max 10.
        // This ensures established, reliable nodes get low-latency 'Priority Lane' status.
        (score / 500).min(10) as u32
    }
}
