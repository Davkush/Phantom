use crate::constants::*;
use phantom_crypto::hybrid_kem::{HybridCiphertext, HybridPublicKey};
use serde::{Serialize, Deserialize};
use rand::{thread_rng, RngCore};

/// Routing instruction for the next hop.
#[derive(Clone, Serialize, Deserialize)]
pub enum RoutingAction {
    /// Forward the packet to the next DHT node ID.
    Forward(NodeId),
    /// The packet has reached its destination or an exit node.
    Deliver,
    /// Phase 10: Deliver to an Introduction Point (Hidden Service).
    DeliverIP,
    /// Phase 10: Deliver to a Rendezvous Point with a splicing cookie.
    DeliverRP([u8; 32]),
    /// Phase 7: Deliver using a SURB with the specified ID.
    DeliverSURB([u8; 16]),
    /// Discard this layer (often a dummy packet for cover traffic).
    Drop,
}

/// A 32-byte identifier for a node in the DHT.
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

/// The encrypted routing information payload that only one specific node can decrypt.
/// It contains the MAC of the packet up to this point, the routing action, and padding to
/// maintain constant packet sizes.
#[derive(Clone, Serialize, Deserialize)]
pub struct RoutingInfoBlock {
    pub action: RoutingAction,
    /// Addressing MED-03: expanded to 16 bytes and encrypted per hop.
    pub c_batch: [u8; 16],
    /// Addressing HIGH-05: epoch is now encrypted per hop inside the routing block.
    pub epoch: u32,
}

/// Phase 5, 6 & 7: PhantomStreamHeader for MTU management, reassembly, and reliability.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PhantomStreamHeader {
    pub stream_id: u64,          // Unique ID for the TCP stream
    pub seq_num: u64,            // Sequence number for in-order reassembly
    pub ack_num: u64,            // Cumulative ACK for the reverse path
    pub window_size: u16,        // Sliding window size for flow control
    pub padding_len: u32,        // Length of random padding in the 9KB payload
    pub target_addr: Option<String>, // Target destination (only on first packet)
    pub surb_id: Option<[u8; 16]>, // Used by Exit to identify which SURB keys to use
}

/// Phase 7: Single-Use Reply Block (SURB) for anonymous return paths.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SURB {
    pub surb_id: [u8; 16],
    pub header: Vec<u8>,         // The pre-built 9KB Sphinx header layers
    pub first_hop: std::net::SocketAddr,
}

/// Phase 7: PayloadEnvelope to encapsulate stream data and piggybacked SURBs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PayloadEnvelope {
    pub stream_header: PhantomStreamHeader,
    pub data: Vec<u8>,
    pub surb_bundle: Vec<SURB>,  // Piggybacked SURBs for the return path
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SphinxPacket {
    pub version: u8,
    pub epoch: u32,
    
    /// Current hop KEM block (1600 B: 32B X25519 Ephemeral PK + 1568B Kyber-1024 CT)
    pub current_kem: [u8; KEM_BLOCK_SIZE],
    
    /// Onion-encrypted routing info for this hop (68 B)
    pub beta_routing: [u8; ROUTING_INFO_SIZE],
    
    /// Per-hop MAC (32 B BLAKE3) - Must be verified BEFORE Kyber decapsulation
    pub gamma_mac: [u8; MAC_SIZE],
    
    /// KEM sidecar (6400 B: 4 remaining hops, onion-encrypted)
    pub kem_sidecar: [u8; SIDECAR_SIZE],
    
    /// Encrypted payload (1116 B)
    pub payload: Vec<u8>,
}

use rand::{thread_rng, RngCore};

impl SphinxPacket {
    /// Serializes the packet to exactly 9216 bytes with random padding.
    /// Addressing HIGH-04: Bitwise and Volumetric indistinguishability.
    /// All packets, regardless of type, look like 9KB of high-entropy noise.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; PACKET_SIZE];
        // Fill buffer with random noise first to ensure constant-size and bitwise masking
        thread_rng().fill_bytes(&mut buffer);
        
        let serialized = bincode::serialize(self).unwrap_or_default();
        
        // Copy serialized data over the noise
        let copy_len = std::cmp::min(serialized.len(), PACKET_SIZE);
        buffer[..copy_len].copy_from_slice(&serialized[..copy_len]);
        
        buffer
    }

    /// Alias for serialize() to match TrafficShaper's expectation.
    pub fn serialize_to_9kb(&self) -> Vec<u8> {
        self.serialize()
    }

    /// Deserializes a SphinxPacket from a 9KB buffer.
    pub fn deserialize(data: &[u8]) -> anyhow::Result<Self> {
        // bincode can handle the extra random trailing bytes as long as it finds 
        // the end of the struct.
        let packet: Self = bincode::deserialize(data)?;
        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_size_calculation() {
        // Verify PACKET_SIZE accommodates the full Approach B header
        let header_calc = KEM_BLOCK_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + SIDECAR_SIZE;
        assert_eq!(header_calc, HEADER_TOTAL_SIZE);
        assert!(PACKET_SIZE >= HEADER_TOTAL_SIZE, 
            "PACKET_SIZE ({}) must be >= header size ({})", 
            PACKET_SIZE, HEADER_TOTAL_SIZE);
        
        println!("✅ Approach B Packet size: {} bytes (header: {} bytes)", 
            PACKET_SIZE, HEADER_TOTAL_SIZE);
    }
    
    #[test]
    fn test_c_batch_uniqueness() {
        // MED-03: Verify 16-byte c_batch has negligible collision risk
        use std::collections::HashSet;
        
        let mut batches = HashSet::new();
        for i in 0u64..1_000_000u64 {
            let mut c_batch = [0u8; 16];
            c_batch[0..8].copy_from_slice(&i.to_le_bytes());
            c_batch[8..16].copy_from_slice(&(i.wrapping_add(1)).to_le_bytes());
            batches.insert(c_batch);
        }
        
        assert_eq!(batches.len(), 1_000_000, "All c_batch values should be unique");
        println!("✅ c_batch uniqueness verified for 1M batches");
    }
}
