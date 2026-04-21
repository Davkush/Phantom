use blake3::Hasher;
use base32::{encode, Alphabet};

pub struct PhantomAddress {
    pub raw_bytes: [u8; 32],
    pub human_readable: String,
}

impl PhantomAddress {
    /// Derives the .phantom address from the Permanent Identity Keys (Task 5.3)
    pub fn derive_v2(ed_pk: &[u8; 32], dil_pk: &[u8; 1312]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"phantom-hs-v2");
        hasher.update(ed_pk);
        hasher.update(dil_pk);
        
        let hash = hasher.finalize();
        let raw_bytes: [u8; 32] = hash.into();
        
        // Base32 encoding (Crockford alphabet, lowercase)
        let human_readable = format!("{}.phantom", 
            encode(Alphabet::Crockford, &raw_bytes).to_lowercase());
            
        Self { raw_bytes, human_readable }
    }
}
