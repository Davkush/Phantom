use serde::{Deserialize, Serialize};

pub mod lookup;
pub mod store;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeReputation {
    pub first_seen_epoch: u32,
    pub successful_interactions: u64,
    pub last_audit_status: bool,
}

impl NodeReputation {
    /// Calculates the 'Trust Score' (0.0 to 1.0).
    /// Favors nodes that have been stable for at least 3 epochs (3 hours).
    pub fn trust_multiplier(&self, current_epoch: u32) -> f64 {
        let age = current_epoch.saturating_sub(self.first_seen_epoch);
        let stability_bonus = (age as f64 / 24.0).min(1.0); // Max bonus after 24 hours
        let reliability = if self.successful_interactions == 0 { 0.5 } else { 1.0 };
        
        stability_bonus * reliability
    }
}

pub struct DhtNode {
    // Phase 0 stub wrapper for DHT context operations
}
