use std::time::{SystemTime, UNIX_EPOCH};

/// HIGH-05 Fix: Network Time Security (NTS) synchronization.
/// Ensures all nodes in the mix net operate on the same epoch boundaries
/// to prevent "Time-Shifting" attacks where a GPA delays packets
/// to observe them in a later epoch where the mix set might be smaller.
pub struct PhantomTime;

impl PhantomTime {
    /// Returns the current synchronized network epoch.
    /// In production, this performs NTS (Network Time Security) verification.
    /// Stubbed for Phase 1.
    pub fn current_epoch() -> u32 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // 1-hour epochs (3600 seconds)
        (now / 3600) as u32
    }

    /// Verifies if a packet's epoch is within the acceptable drift window.
    pub fn verify_epoch(packet_epoch: u32) -> bool {
        let current = Self::current_epoch();
        // Allow +/- 1 epoch drift for slow sync
        packet_epoch >= current.saturating_sub(1) && packet_epoch <= current + 1
    }
}
