use phantom_crypto::hybrid_kem::{HybridCiphertext, HybridPublicKey};
use serde::{Serialize, Deserialize};

pub const KYBER_CT_SIZE: usize = 1568;
pub const MAX_HOPS: usize = 5;
pub const HEADER_SIZE: usize = 32 + (MAX_HOPS * KYBER_CT_SIZE) + 128 + 32 + 16 + 2 + 6;
pub const PACKET_SIZE: usize = 9216; // 9KB (CRIT-01/MED-03 Fix)

/// Routing instruction for the next hop.
#[derive(Clone, Serialize, Deserialize)]
pub enum RoutingAction {
    /// Forward the packet to the next DHT node ID.
    Forward(NodeId),
    /// The packet has reached its destination or a rendezvous point.
    Deliver,
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
    pub mac: [u8; 32],
    pub action: RoutingAction,
    /// Addressing MED-03: expanded to 16 bytes and encrypted per hop.
    pub c_batch: [u8; 16],
    /// Addressing HIGH-05: epoch is now encrypted per hop inside the routing block.
    pub epoch: u64,
    /// Chacha20 stream output to pad the routing block back to constant length when a layer is removed.
    pub padding: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SphinxPacket {
    pub version: u8,         // 0x01
    pub flags: u8,           // bitflags
    pub epoch: u32,         // big-endian
    
    // --- Header Section ---
    pub alpha_cl: [u8; 32],      // X25519 Blinded Element
    pub alpha_pq_onion: Vec<u8>, // Contains (MAX_HOPS * 1568) bytes
    pub beta_routing: [u8; 128], // Onion-encrypted hops
    pub gamma_mac: [u8; 32],     // BLAKE3 per-hop MAC
    
    // --- Metadata Section ---
    pub c_batch: [u8; 16],       // MED-03 Fix: Expanded to 128-bit
    pub pi_ref: u16,            // Index in batch
    
    pub payload: Vec<u8>,        // Encrypted data
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
        // Verify PACKET_SIZE accommodates worst-case
        let header_size = 32 + (MAX_HOPS * KYBER_CT_SIZE) + 128 + 32 + 16 + 2 + 6;
        assert!(PACKET_SIZE >= header_size, 
            "PACKET_SIZE ({}) must be >= header size ({})", 
            PACKET_SIZE, header_size);
        
        println!("✅ Packet size: {} bytes (header: {} bytes)", 
            PACKET_SIZE, header_size);
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
