pub mod packet;
pub mod constants;
pub mod builder;
pub mod processor;
pub mod dht;
pub mod identity;
pub mod hidden_service;
pub mod config;
pub mod genesis;
pub mod replay_cache;
pub mod batching;
pub mod transport;
pub mod cover_traffic;
pub mod dcnet;
pub mod intro_point;
pub mod rendezvous;
pub mod mix;
pub mod sentinel;
pub mod zk;
pub mod incentives;

#[cfg(test)]
mod tests {
    use crate::packet::{RoutingAction};
    use crate::builder::build_packet;
    use crate::processor::process_packet;
    use phantom_crypto::hybrid_kem::HybridKeyPair;

    #[test]
    fn test_sphinx_packet_lifecycle() {
        use crate::replay_cache::ReplayCache;
        let mut cache1 = ReplayCache::new(1000, 0.01);
        let mut cache2 = ReplayCache::new(1000, 0.01);
        let mut cache3 = ReplayCache::new(1000, 0.01);

        // Setup 3 nodes for the circuit: First, Middle, Last
        let node1 = HybridKeyPair::generate();
        let node2 = HybridKeyPair::generate();
        let node3 = HybridKeyPair::generate();

        let path = vec![node1.public_key(), node2.public_key(), node3.public_key()];
        
        let action1 = RoutingAction::Forward(crate::packet::NodeId([1u8; 32])); 
        let action2 = RoutingAction::Forward(crate::packet::NodeId([2u8; 32]));
        let action3 = RoutingAction::Deliver;

        let actions = vec![action1, action2, action3];
        let original_payload = b"Top secret post-quantum message!";

        // Client builds the packet
        let c_batch = [7u8; 16];
        let epoch = 42;
        let mut packet = build_packet(&path, &actions, original_payload, c_batch, epoch)
            .expect("Failed to build packet");
            
        // Initial state check
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.epoch, 42);

        // Hop 1 (Node 1)
        let block1 = process_packet(&node1, &mut packet, &mut cache1).expect("Node 1 processing failed");
        assert!(matches!(block1.action, RoutingAction::Forward(_)));
        assert_eq!(block1.c_batch, c_batch);
        assert_eq!(block1.epoch, epoch);

        // Hop 2 (Node 2)
        let block2 = process_packet(&node2, &mut packet, &mut cache2).expect("Node 2 processing failed");
        assert!(matches!(block2.action, RoutingAction::Forward(_)));

        // Hop 3 (Node 3 - Receiver)
        let block3 = process_packet(&node3, &mut packet, &mut cache3).expect("Node 3 processing failed");
        assert!(matches!(block3.action, RoutingAction::Deliver));

        // Check if the final payload starts with original
        assert_eq!(&packet.payload[..original_payload.len()], original_payload);
    }

