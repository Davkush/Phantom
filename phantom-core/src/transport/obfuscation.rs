use crate::cover::poisson::PoissonTimer;
use crate::packet::SphinxPacket;
use quinn::SendStream;

pub const MIN_PACKET_SIZE: usize = 1200; // Standard QUIC minimum
pub const MAX_PACKET_SIZE: usize = 9216; // Our new 9KB internal Sphinx size

pub struct TrafficShaper {
    pub poisson_timer: PoissonTimer,
}

impl TrafficShaper {
    /// HIGH-04 Fix: Adds random padding to the encrypted blob.
    /// Deprecated in favor of 9KB fixed-size for all packet types.
    pub fn apply_padding(payload: Vec<u8>) -> Vec<u8> {
        let mut buffer = vec![0u8; MAX_PACKET_SIZE];
        let copy_len = std::cmp::min(payload.len(), MAX_PACKET_SIZE);
        buffer[..copy_len].copy_from_slice(&payload[..copy_len]);
        buffer
    }

    /// Applies Poisson-distributed delay and pads to exactly 9KB.
    /// This is the primary physical dispatch hook for Ghost nodes.
    pub async fn shape_and_send(
        &self, 
        mut stream: SendStream, 
        packet: SphinxPacket
    ) -> anyhow::Result<()> {
        // 1. Fixed-size serialization (9KB)
        let data = packet.serialize_to_9kb(); 
        
        // 2. Poisson Delay (HIGH-04 Fix)
        let delay = self.poisson_timer.next_delay();
        tokio::time::sleep(delay).await;

        // 3. Physical Dispatch
        stream.write_all(&data).await?;
        stream.finish().await?;
        Ok(())
    }
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
