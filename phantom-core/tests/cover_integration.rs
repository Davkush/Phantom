use phantom_core::cover::poisson::PoissonTimer;
use phantom_core::transport::obfuscation::TrafficShaper;
use std::time::Duration;

#[tokio::test]
async fn test_cover_traffic_integration() {
    let mean_interval_ms = 100.0;
    let shaper = TrafficShaper::new(mean_interval_ms);
    let iterations = 1000;
    let mut total_delay = 0.0;
    let mut large_packets = 0;
    let mut small_packets = 0;

    for _ in 0..iterations {
        // Test 1: Poisson Delay (Temporal Obfuscation)
        let delay = shaper.get_inter_packet_interval();
        total_delay += delay.as_secs_f64() * 1000.0;

        // Test 2: Multi-size packet randomization (Volumetric Obfuscation)
        let size = shaper.sample_packet_size();
        assert!(size >= 500 && size <= 1452, "Packet size bounds violated");
        
        if size < 1000 {
            small_packets += 1;
        } else {
            large_packets += 1;
        }
    }

    let empirical_mean = total_delay / (iterations as f64);
    
    // Ensure mean is close to 100ms
    assert!(empirical_mean > 90.0 && empirical_mean < 110.0, "Poisson mean shifted");
    
    // Ensure packet sizes are distributed, not constant
    assert!(small_packets > 0 && large_packets > 0, "Packet sizes are not distributed");
    
    // Make sure we have 9KB static serialization for Sphinx payloads
    let dummy_packet = phantom_core::packet::SphinxPacket {
        version: 1,
        epoch: 0,
        current_kem: [0u8; 1600],
        beta_routing: [0u8; 68],
        gamma_mac: [0u8; 32],
        kem_sidecar: [0u8; 6400],
        payload: vec![0u8; 128],
    };

    let static_payload = dummy_packet.serialize_to_9kb();
    assert_eq!(static_payload.len(), 9216, "Sphinx packet did not serialize to 9KB internal standard");
}
