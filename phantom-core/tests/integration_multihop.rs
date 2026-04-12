use phantom_core::builder::build_packet;
use phantom_core::processor::process_packet;
use phantom_core::packet::{RoutingAction, NodeId};
use phantom_core::hybrid_kem::HybridKeyPair;
use phantom_core::replay_cache::ReplayCache;
use std::sync::{Arc, Mutex};

#[test]
fn test_multihop_approach_b_circuit() {
    // Setup a 5-hop circuit (Approach B allows up to 5 hops with 8100B header)
    let mut nodes = Vec::new();
    let mut caches = Vec::new();
    for _ in 0..5 {
        nodes.push(HybridKeyPair::generate());
        caches.push(Arc::new(Mutex::new(ReplayCache::new(1000, 0.01))));
    }

    let path: Vec<_> = nodes.iter().map(|n| n.public_key()).collect();
    
    // Actions: 4 Forwards, 1 Deliver
    let mut actions = Vec::new();
    for i in 1..5 {
        actions.push(RoutingAction::Forward(NodeId([i as u8; 32])));
    }
    actions.push(RoutingAction::Deliver);

    let original_payload = vec![0xCC; 100]; // 100 bytes of data
    let c_batch = [0xAA; 16];
    let epoch = 123456;

    // 1. Build Packet
    let mut packet = build_packet(&path, &actions, &original_payload, c_batch, epoch)
        .expect("Failed to build packet");

    // 2. Process through 5 hops
    for i in 0..5 {
        println!("Processing hop {}...", i);
        let mut cache = caches[i].lock().unwrap();
        let block = process_packet(&nodes[i], &mut packet, &mut cache)
            .expect(&format!("Processing failed at hop {}", i));
        
        assert_eq!(block.epoch, epoch, "Epoch mismatch at hop {}", i);
        
        if i < 4 {
            assert!(matches!(block.action, RoutingAction::Forward(_)));
        } else {
            assert!(matches!(block.action, RoutingAction::Deliver));
        }
    }

    // 3. Final Payload Verification
    // The payload is padded to constant size, so we check the prefix
    assert_eq!(&packet.payload[..original_payload.len()], &original_payload[..]);
    println!("Multihop circuit test: SUCCESS");
}

#[test]
fn test_replay_protection() {
    let node = HybridKeyPair::generate();
    let mut cache = ReplayCache::new(1000, 0.01);
    
    let path = vec![node.public_key()];
    let actions = vec![RoutingAction::Deliver];
    let payload = b"Repeat after me";
    let c_batch = [0u8; 16];
    let epoch = 1;

    let mut packet = build_packet(&path, &actions, payload, c_batch, epoch).unwrap();
    let mut packet_duplicate = packet.clone();

    // First time: PASS
    process_packet(&node, &mut packet, &mut cache).expect("First attempt should pass");

    // Second time (Replay): FAIL
    let result = process_packet(&node, &mut packet_duplicate, &mut cache);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Replayed packet"));
    println!("Replay protection test: SUCCESS");
}
