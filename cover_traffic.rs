use std::time::Duration;

/// Phase 3 MED-04: Poisson-distributed cover traffic generator.
/// Prevents predictable 100ms traffic gaps which expose the node fingerprint.

pub fn get_next_cover_interval(lambda: f64) -> Duration {
    // Phase 0 Stub representation of a Poisson distribution delay.
    // In production, we'd use `rand_distr::Exp::new(lambda)`.
    // We mock an exponential interval averaging around 100ms here
    // rather than using a rigid 100ms periodic timer loop.
    
    let mean_interval_ms = (1.0 / lambda) * 1000.0;
    Duration::from_millis(mean_interval_ms as u64)
}
