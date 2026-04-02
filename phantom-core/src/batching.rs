use std::time::Duration;

/// Phase 2 MED-01: Add deterministic `C_in` publication offsets containing +/- 50ms random jitter.
/// This prevents timing oracles from correlating C_in DHT actions globally across nodes.

pub fn generate_c_in_jitter(rng_seed: u64) -> Duration {
    // Phase 0 simulation of random: deterministic pseudorandom offset between 0 and 100ms
    let random_jitter_ms = rng_seed % 100;
    Duration::from_millis(random_jitter_ms)
}

pub fn get_c_in_publish_delay(rng_seed: u64) -> Duration {
    // Target is T+200ms. We use a baseline of 150ms and add up to 100ms jitter,
    // resulting in a range of [150ms, 250ms], which is symmetric around 200ms.
    let baseline = Duration::from_millis(150); 
    baseline + generate_c_in_jitter(rng_seed)
}
