use phantom_crypto::hybrid_kem::{HybridCiphertext, HybridPublicKey};
use serde::{Deserialize, Serialize};

/// Maximum depth of the mixnet path.
pub const MAX_HOPS: usize = 5;

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

/// The core Sphinx⁺ data structure.
/// Addressing CRIT-01: Contains a vector of full HybridCiphertexts, one for each hop.
#[derive(Clone, Serialize, Deserialize)]
pub struct SphinxPacket {
    /// The nested hybrid ciphertexts. The outermost one is decapsulated by the immediate next hop.
    pub crypto_headers: Vec<HybridCiphertext>,
    /// The encrypted routing block containing the actions and the MAC.
    pub routing_info: Vec<u8>,
    /// The symmetrically encrypted actual message.
    pub payload: Vec<u8>,
}
