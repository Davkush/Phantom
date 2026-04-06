use serde::{Deserialize, Serialize};

/// Phase 4 MED-05 & LOW-03: Introduction Point DoS resistance and SURB padding.

#[derive(Clone, Serialize, Deserialize)]
pub struct IntroRequest {
    pub service_id: [u8; 32],
    
    // Address LOW-03: The SURB payload is now padded to a uniform 512 bytes
    // regardless of actual reply block size to prevent ISP side-channel tracking.
    pub padded_surb: [u8; 512],
    
    pub pow_nonce: [u8; 16],
}

pub struct IntroPointState {
    pub connection_rate_per_minute: u32,
    pub base_pow_difficulty: u32,
}

impl IntroPointState {
    /// Address MED-05: Dynamic intra-epoch PoW difficulty adjustment.
    /// If an adversary floods the intro point mid-epoch, raising the local difficulty
    /// autonomously chokes out the GPU farm before the next formal descriptor update.
    pub fn current_difficulty(&self) -> u32 {
        if self.connection_rate_per_minute > 5000 {
            // Under severe DoS conditions, drastically increase required work.
            self.base_pow_difficulty + 8
        } else if self.connection_rate_per_minute > 1000 {
            // Moderate flood detection
            self.base_pow_difficulty + 4
        } else {
            self.base_pow_difficulty
        }
    }
}
