use super::{DhtNode, NodeDescriptor};

impl DhtNode {
    /// Active Sybil Defense: Secure Multi-path Lookup (HIGH-03)
    pub async fn secure_lookup(&self, target_id: [u8; 32]) -> Option<NodeDescriptor> {
        // 1. Parallel disjoint lookups (d=5)
        let mut results = Vec::new();
        let seeds = self.get_disjoint_paths(target_id, 5);

        for seed in seeds {
            if let Some(desc) = self.single_path_lookup(target_id, seed).await {
                // Immediate cryptographic validation (Signatures + PoW)
                if desc.verify_integrity().is_ok() {
                    results.push(desc);
                } else {
                    println!("DHT: Rejected invalid result from path {:x?}", &seed[0..2]);
                }
            }
        }

        // 2. Quorum selection (quorum=3)
        self.find_consensus(results, 3)
    }

    /// Fetches a descriptor from a specific keyspace region using Iterative Kademlia Routing.
    async fn single_path_lookup(&self, target: [u8; 32], seed: [u8; 32]) -> Option<NodeDescriptor> {
        println!("DHT: Iterative Kademlia lookup towards {:x?} starting from vector {:x?}...", &target[0..2], &seed[0..2]);

        let mut current_closest = self.get_closest_peers(seed, 20); // K=20
        let mut queried = std::collections::HashSet::new();

        let alpha = 3;
        let mut staleness = 0;
        
        loop {
            // Sort current active nodes by distance to the true target
            current_closest.sort_by_key(|n| super::xor_distance(n.node_id, target));
            current_closest.truncate(20);

            // Exit immediately if the target is found
            if let Some(desc) = current_closest.iter().find(|n| n.node_id == target) {
                return Some(desc.clone());
            }

            // Pick up to 'alpha' peers we haven't queried yet
            let to_query: Vec<_> = current_closest.iter()
                .filter(|n| !queried.contains(&n.node_id))
                .take(alpha)
                .cloned()
                .collect();

            // All closest nodes run out, network traversal exhausted
            if to_query.is_empty() {
                println!("DHT: Lookup exhausted paths without finding target");
                break; 
            }

            let mut newly_discovered = Vec::new();
            for node in to_query {
                queried.insert(node.node_id);
                // Execute logical RPC traversal jump
                let (found, peers) = self.rpc_find_node(node.node_id, target).await;
                if let Some(target_desc) = found { 
                    return Some(target_desc); 
                }
                newly_discovered.extend(peers);
            }

            if newly_discovered.is_empty() {
                staleness += 1;
                // Halt traversal if queries return no new nodes multiple times 
                if staleness > 3 {
                    println!("DHT: Path stalled. Halting lookup.");
                    break; 
                }
            } else {
                staleness = 0;
                current_closest.extend(newly_discovered);
            }
        }
        
        None
    }

    /// Sorts local routing table records to yield the K-closest peers to a given ID.
    fn get_closest_peers(&self, target: [u8; 32], k: usize) -> Vec<NodeDescriptor> {
        let mut sorted = self.known_peers.clone();
        sorted.sort_by_key(|n| super::xor_distance(n.node_id, target));
        sorted.into_iter().take(k).collect()
    }

    /// Simulated Phase 1 Quic RPC 'FIND_NODE' protocol.
    async fn rpc_find_node(&self, _peer: [u8; 32], _target: [u8; 32]) -> (Option<NodeDescriptor>, Vec<NodeDescriptor>) {
        // Simulate real QUIC RTT latencies
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        // The mock currently doesn't possess peer routing tables, only its own.
        // Returning empty array forces lookup to rely strictly on initial graph local seeds.
        (None, vec![]) 
    }
    
    /// Finds the most frequent descriptor that meets the quorum threshold.
    fn find_consensus(&self, results: Vec<NodeDescriptor>, quorum: usize) -> Option<NodeDescriptor> { 
        use std::collections::HashMap;
        
        let mut counts = HashMap::new();
        for res in results {
            // Hash the descriptor for the map key (Identity binding)
            let mut hasher = blake3::Hasher::new();
            hasher.update(&res.ed25519_pubkey);
            hasher.update(&res.dilithium_pubkey);
            let key = hasher.finalize();
            
            counts.entry(key).or_insert((0, res)).0 += 1;
        }

        counts.into_values()
            .find(|(count, _res)| *count >= quorum)
            .map(|(_count, res)| res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn mock_descriptor(node_id: [u8; 32]) -> NodeDescriptor {
        NodeDescriptor {
            node_id,
            ed25519_pubkey: [0u8; 32],
            dilithium_pubkey: [0u8; 1312],
            x25519_pubkey: [0u8; 32],
            kyber_pubkey: [0u8; 1568],
            quic_addr: "127.0.0.1:443".parse().unwrap(),
            pow_nonce: [0u8; 16],
            uptime_schedule: super::UptimeSchedule::default(),
            signature_ed25519: [0u8; 64],
            signature_dilithium: [0u8; 2420],
        }
    }

    #[test]
    fn test_sr_dht_quorum() {
        let node = DhtNode::new([0u8; 32]);
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        
        // 3 votes for A, 2 votes for B
        let results = vec![
            mock_descriptor(id_a),
            mock_descriptor(id_a),
            mock_descriptor(id_b),
            mock_descriptor(id_a),
            mock_descriptor(id_b),
        ];

        let consensus = node.find_consensus(results, 3);
        assert!(consensus.is_some());
        assert_eq!(consensus.unwrap().node_id, id_a);
    }
    
    #[test]
    fn test_sr_dht_no_quorum() {
        let node = DhtNode::new([0u8; 32]);
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        
        // 2 votes for A, 2 votes for B - no quorum of 3
        let results = vec![
            mock_descriptor(id_a),
            mock_descriptor(id_a),
            mock_descriptor(id_b),
            mock_descriptor(id_b),
        ];

        let consensus = node.find_consensus(results, 3);
        assert!(consensus.is_none());
    }

    #[tokio::test]
    async fn test_kademlia_local_resolution() {
        let mut node = DhtNode::new([0u8; 32]);
        
        // Target to find
        let target_id = [7u8; 32];
        let target_desc = mock_descriptor(target_id);

        // Noise
        for i in 1..25 {
            node.known_peers.push(mock_descriptor([i as u8; 32]));
        }
        // Insert target physically into the known subset
        node.known_peers.push(target_desc);

        // Random starting vector (seed)
        let seed = [255u8; 32];
        
        let found = node.single_path_lookup(target_id, seed).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().node_id, target_id);
    }
}
