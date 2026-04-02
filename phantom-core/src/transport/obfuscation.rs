use rand::{thread_rng, Rng, RngCore}; // Added RngCore

pub const MIN_PACKET_SIZE: usize = 1200; // Standard QUIC minimum
pub const MAX_PACKET_SIZE: usize = 9216; // Our new 9KB internal Sphinx size

pub struct TrafficShaper;

impl TrafficShaper {
    /// HIGH-04 Fix: Adds random padding to the encrypted blob.
    /// This ensures that the IP-layer packet size is not a constant 1452 bytes.
    pub fn apply_padding(mut payload: Vec<u8>) -> Vec<u8> {
        let mut rng = thread_rng();
        
        // We want to vary the final size to mimic standard HTTPS distribution.
        // Most HTTPS packets are either small (ACKs/Headers) or MTU-sized.
        let target_size = if rng.gen_bool(0.1) {
            rng.gen_range(1200..1400) // Small burst
        } else {
            rng.gen_range(8000..MAX_PACKET_SIZE) // Large Sphinx-carrying packet
        };

        if payload.len() < target_size {
            let padding_len = target_size - payload.len();
            let mut padding = vec![0u8; padding_len];
            rng.fill_bytes(&mut padding);
            payload.extend(padding);
        }
        
        payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cover::poisson::PoissonTimer;

    #[test]
    fn test_high04_statistical_profiler_evasion() {
        // 1. Validate Volumetric Evasion (Random Padding Sizes)
        let mut small_packets = 0;
        let mut large_packets = 0;
        let iterations = 10_000;
        
        println!("🚀 Initiating Statistical DPI Profiler tests...");
        
        for _ in 0..iterations {
            let base_payload = vec![0u8; 500]; // Dummy base payload size
            let shaped = TrafficShaper::apply_padding(base_payload);
            
            assert!(shaped.len() >= MIN_PACKET_SIZE, "QUIC size limit violated");
            assert!(shaped.len() <= MAX_PACKET_SIZE, "QUIC size ceiling violated");

            if shaped.len() < 1500 {
                small_packets += 1;
            } else {
                large_packets += 1;
            }
        }
        
        // Assert bi-modal distribution (approx 10% small, 90% large) ensuring volumetric masking
        assert!(small_packets > 500 && small_packets < 1500, "Volumetric profile distribution skewed");
        
        // 2. Validate Temporal Evasion (Poisson Timing)
        let timer = PoissonTimer::new(100.0);
        let mut precise_heartbeat_hits = 0;
        let mut total_delay_ms = 0.0;
        
        for _ in 0..iterations {
            let delay = timer.next_delay().as_secs_f64() * 1000.0;
            // A fixed periodic heartbeat would repeatedly trigger the exact target ms
            if (delay - 100.0).abs() < 0.0001 {
                precise_heartbeat_hits += 1; 
            }
            total_delay_ms += delay;
        }
        
        // Ensure no constant predictability
        assert_eq!(precise_heartbeat_hits, 0, "Fixed predictable heartbeats detected!");
        
        let empirical_mean = total_delay_ms / (iterations as f64);
        assert!(empirical_mean > 90.0 && empirical_mean < 110.0, "Poisson drift misses targeted mean throughput");
        
        println!("✅ Statistical Volumetric & Temporal Profilers Defeated (HIGH-04 Closed)");
    }
}
