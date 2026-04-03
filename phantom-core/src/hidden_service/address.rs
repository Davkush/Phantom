use blake3::Hasher;
use base32::{encode, Alphabet};

pub struct PhantomAddress {
    pub raw_bytes: [u8; 32],
    pub human_readable: String,
}

impl PhantomAddress {
    /// Derives the .phantom address from the Hybrid Identity Keys
    pub fn derive(ed_pk: &[u8; 32], kyber_pk: &[u8; 1568]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"phantom-hs-v1");
        hasher.update(ed_pk);
        hasher.update(kyber_pk);
        
        let hash = hasher.finalize();
        let raw_bytes: [u8; 32] = hash.into();
        
        // Base32 encoding (no padding, lowercase)
        let human_readable = format!("{}.phantom", 
            encode(Alphabet::Crockford, &raw_bytes).to_lowercase());
            
        Self { raw_bytes, human_readable }
    }
}
