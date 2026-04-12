#![no_main]
use libfuzzer_sys::fuzz_target;
use phantom_core::packet::SphinxPacket;
use phantom_core::processor::process_packet;
use phantom_core::hybrid_kem::HybridKeyPair;
use phantom_core::replay_cache::ReplayCache;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize data as a SphinxPacket
    if let Ok(mut packet) = bincode::deserialize::<SphinxPacket>(data) {
        let node_keypair = HybridKeyPair::generate();
        let mut cache = ReplayCache::new(1000, 0.01);
        
        // Fuzz the packet processor with arbitrary (potentially malformed) packets
        let _ = process_packet(&node_keypair, &mut packet, &mut cache);
    }
});
