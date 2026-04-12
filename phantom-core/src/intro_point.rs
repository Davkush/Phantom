use serde::{Deserialize, Serialize};

/// Phase 4 MED-05 & LOW-03: Introduction Point DoS resistance and SURB padding.

use std::time::{Instant, Duration};

#[derive(Clone, Serialize, Deserialize)]
pub struct IntroRequest {
    pub service_id: [u8; 32],
    
    // Address LOW-03: The SURB payload is now padded to a uniform 512 bytes
    pub padded_surb: [u8; 512],
    
    pub pow_nonce: [u8; 16],
}

pub struct IntroPointState {
    pub last_window_reset: Instant,
    pub window_hits: u32,
    pub base_pow_difficulty: u32,
}

impl IntroPointState {
    pub fn new(base_difficulty: u32) -> Self {
        Self {
            last_window_reset: Instant::now(),
            window_hits: 0,
            base_pow_difficulty: base_difficulty,
        }
    }

    /// Address MED-05: Dynamic intra-epoch PoW difficulty adjustment.
    pub fn record_request(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_window_reset) > Duration::from_secs(60) {
            self.last_window_reset = now;
            self.window_hits = 1;
        } else {
            self.window_hits += 1;
        }
    }

    pub fn get_dynamic_difficulty(&self) -> u32 {
        if self.window_hits > 10000 {
            self.base_pow_difficulty + 8
        } else if self.window_hits > 5000 {
            self.base_pow_difficulty + 4
        } else if self.window_hits > 1000 {
            self.base_pow_difficulty + 2
        } else {
            self.base_pow_difficulty
        }
    }
}
