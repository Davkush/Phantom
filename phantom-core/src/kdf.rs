use blake3::Hasher;
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

/// Derives a 32-byte key using BLAKE3 from a hybrid shared secret and a domain separator string.
pub fn derive_key(hybrid_secret_bytes: &[u8], purpose: KdfPurpose, info: &[u8]) -> DerivedKey {
    let mut hasher = Hasher::new();
    // Prepend the purpose to strictly enforce domain separation.
    hasher.update(purpose.as_bytes());
    // Mix in the actual shared secret from the KEM.
    hasher.update(hybrid_secret_bytes);
    // Mix in any additional context (like routing hop index or unique packet ID).
    hasher.update(info);
    
    let mut out = [0u8; 32];
    let mut output_reader = hasher.finalize_xof();
    output_reader.fill(&mut out);
    
    DerivedKey(out)
}
