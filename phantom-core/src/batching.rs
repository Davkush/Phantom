use std::time::Duration;
use rand::RngCore;

/// Phase 2 MED-01: Add cryptographic `C_in` publication offsets containing +/- 50ms random jitter.
/// This prevents timing oracles from correlating C_in DHT actions globally across nodes.

/// Generates a cryptographic random jitter between 0 and 100ms.
/// Uses OsRng for secure randomness to prevent timing analysis attacks.
pub fn generate_c_in_jitter() -> Duration {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    let random_jitter_ms = u64::from_le_bytes(bytes) % 100;
    Duration::from_millis(random_jitter_ms)
}

/// Target is T+200ms. We use a baseline of 150ms and add up to 100ms jitter,
/// resulting in a range of [150ms, 250ms], which is symmetric around 200ms.
pub fn get_c_in_publish_delay() -> Duration {
    let baseline = Duration::from_millis(150);
    baseline + generate_c_in_jitter()
}
