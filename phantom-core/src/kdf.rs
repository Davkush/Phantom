use tiny_keccak::{Hasher, Shake};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Determines what the derived key will be used for, ensuring domain separation.
pub enum KdfPurpose {
    PayloadEncryption,
    HeaderMac,
    NextHopPrng,
}

impl KdfPurpose {
    fn as_bytes(&self) -> &[u8] {
        match self {
            KdfPurpose::PayloadEncryption => b"PHANTOM_PAYLOAD_ENC",
            KdfPurpose::HeaderMac => b"PHANTOM_HEADER_MAC",
            KdfPurpose::NextHopPrng => b"PHANTOM_NEXT_HOP_PRNG",
        }
    }
}

/// A derived 32-byte key, automatically zeroized when dropped to preserve forward secrecy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

/// Derives a 32-byte key using SHAKE-256 (SHA-3) for FO-compliant PQC security.
/// Addressing CRIT-05: Using a proper SHA-3 XOF for domain separation.
pub fn derive_key(hybrid_secret_bytes: &[u8], purpose: KdfPurpose, info: &[u8]) -> DerivedKey {
    let mut shake = Shake::v256();
    // 1. Domain Separation
    shake.update(purpose.as_bytes());
    // 2. Secret Material
    shake.update(hybrid_secret_bytes);
    // 3. Contextual Entropy (Hop index, etc)
    shake.update(info);
    
    let mut out = [0u8; 32];
    shake.finalize(&mut out);
    
    DerivedKey(out)
}

/// A cryptographic ratchet for per-hop session key evolution.
pub struct PqcRatchet {
    state: [u8; 32],
}

impl PqcRatchet {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { state: seed }
    }

    pub fn next(&mut self, purpose: KdfPurpose) -> DerivedKey {
        let mut shake = Shake::v256();
        shake.update(purpose.as_bytes());
        shake.update(&self.state);
        
        let mut out = [0u8; 32];
        shake.finalize(&mut out);
        
        // Evolve state: SHA3-256(state || "NEXT")
        let mut next_shake = Shake::v256();
        next_shake.update(&self.state);
        next_shake.update(b"PHANTOM_RATCHET_NEXT");
        next_shake.finalize(&mut self.state);
        
        DerivedKey(out)
    }
}
