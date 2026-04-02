use rand_distr::{Distribution, Exp};
use std::time::Duration;
use rand::thread_rng;

pub struct PoissonTimer {
    distribution: Exp<f64>,
    avg_interval_ms: f64,
}

impl PoissonTimer {
    /// avg_interval: The target 'mean' delay (e.g., 100.0ms)
    pub fn new(avg_interval_ms: f64) -> Self {
        // Lambda for Exponential Distribution is 1/mean
        let lambda = 1.0 / avg_interval_ms;
        Self {
            distribution: Exp::new(lambda).unwrap(),
            avg_interval_ms,
        }
    }

    /// Returns the Duration to wait before sending the next packet.
    pub fn next_delay(&self) -> Duration {
        let mut rng = thread_rng();
        let sample = self.distribution.sample(&mut rng);
        
        // Clamp to prevent extreme outliers (0.1x to 5.0x mean)
        let clamped = sample.max(self.avg_interval_ms * 0.1)
                            .min(self.avg_interval_ms * 5.0);
                            
        Duration::from_secs_f64(clamped / 1000.0)
    }
}
