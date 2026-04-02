use serde::{Serialize, Deserialize};

/// Simulating Dilithium-2 public key (1312 bytes) and signature (2420 bytes) sizes
/// Addressing MED-06: Downgraded from Dilithium-3 to Dilithium-2 for Descriptor size reduction.
type Dilithium2PublicKey = [u8; 1312];
type Dilithium2Signature = [u8; 2420];

/// Node Descriptor
/// Addressing MED-06: The Dilithium signature is sized for Dilithium-2 (Level 2).
#[derive(Clone, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub ed25519_pubkey: [u8; 32],
    pub dilithium_pubkey: Dilithium2PublicKey,
    pub x25519_pubkey: [u8; 32],
    pub kyber_pubkey: [u8; 1184], // Kyber-1024
    
    pub signature_ed25519: [u8; 64],
    pub signature_dilithium: Dilithium2Signature,
}
