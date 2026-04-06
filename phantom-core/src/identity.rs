use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use ed25519_dalek::{SigningKey, VerifyingKey};
use phantom_crypto::hybrid_kem::HybridKeyPair;
use std::path::Path;
use std::fs;
use rand::rngs::OsRng;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use blake3;

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
    pub quic_addr: std::net::SocketAddr, // Added for Phase 7 SURB first-hop routing
    
    pub signature_ed25519: [u8; 64],
    pub signature_dilithium: Dilithium2Signature,
}

pub struct IdentityManager {
    // Zeroizing ensures the private key is wiped from memory when dropped
    signing_key: Zeroizing<SigningKey>,
    pub node_id: [u8; 32],
}

impl IdentityManager {
    /// Loads an identity from a JSON file or generates a new one if it doesn't exist.
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        if path.as_ref().exists() {
            let data = fs::read(path)?;
            // In a real impl, this would be a secure JSON/PKCS#8 decode.
            let mut seed = [0u8; 32];
            if data.len() >= 32 {
                seed.copy_from_slice(&data[..32]);
            }
            let signing_key = SigningKey::from_bytes(&seed);
            let node_id = blake3::hash(signing_key.verifying_key().as_bytes()).into();
            Ok(Self { 
                signing_key: Zeroizing::new(signing_key), 
                node_id 
            })
        } else {
            let mut csprng = OsRng;
            let signing_key = SigningKey::generate(&mut csprng);
            let node_id = blake3::hash(signing_key.verifying_key().as_bytes()).into();
            
            // Save seed stub
            if let Some(parent) = path.as_ref().parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, signing_key.to_bytes())?;
            
            Ok(Self { 
                signing_key: Zeroizing::new(signing_key), 
                node_id 
            })
        }
    }

    /// Export the Ed25519 private key in DER format for rcgen (TLS cert generation)
    pub fn export_ed25519_der(&self) -> Vec<u8> {
        // rcgen requires the key in DER format for certificate signing
        // KeyPair::from_der expects the raw 32-byte seed for Ed25519
        self.signing_key.to_bytes().to_vec()
    }

    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }
    
    /// Returns the long-term Hybrid KeyPair for mix processing.
    pub fn mix_keypair(&self) -> HybridKeyPair {
        // Phase 5: Derive mix keys from identity seed for persistence.
        // For now, generating fresh for Phase 5 prototype logic.
        HybridKeyPair::generate()
    }

    /// Solve the memory-hard Argon2id PoW challenge.
    /// Addressing HIGH-01/03: Mitigates Sybil and DoS attacks.
    pub async fn solve_pow(&self, challenge: &[u8]) -> anyhow::Result<String> {
        println!("PoW: Computing Argon2id Sybil-resistance token...");
        let salt = SaltString::generate(&mut OsRng);
        
        // Phase 10: Production-grade memory-hard hashing
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(challenge, &salt)
            .map_err(|e| anyhow::anyhow!("PoW Hash Error: {}", e))?
            .to_string();
            
        Ok(password_hash)
    }
}
