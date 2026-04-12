use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use ed25519_dalek::{SigningKey, VerifyingKey};
use phantom_crypto::hybrid_kem::HybridKeyPair;
use std::path::Path;
use std::fs;
use rand::rngs::OsRng;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params,
};
use std::time::{Instant, Duration};
use std::collections::HashMap;

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

/// Argon2id parameters for Sybil resistance (CRIT-03/HIGH-01)
const ARGON2_T: u32 = 3;
const ARGON2_M: u32 = 65536; // 64MB (in KB)
const ARGON2_P: u32 = 1;

pub struct IdentityManager {
    // Zeroizing ensures the private key is wiped from memory when dropped
    signing_key: Zeroizing<SigningKey>,
    pub node_id: [u8; 32],
    
    // MED-03 fixation: Burst detection / Rate limiting state
    burst_cache: HashMap<[u8; 16], (Instant, u32)>, 
}

impl IdentityManager {
    /// Loads an identity from a JSON file or generates a new one if it doesn't exist.
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let signing_key = if path.as_ref().exists() {
            let data = fs::read(path)?;
            let mut seed = [0u8; 32];
            if data.len() >= 32 {
                seed.copy_from_slice(&data[..32]);
            }
            SigningKey::from_bytes(&seed)
        } else {
            let mut csprng = OsRng;
            let key = SigningKey::generate(&mut csprng);
            if let Some(parent) = path.as_ref().parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, key.to_bytes())?;
            key
        };

        let node_id = blake3::hash(signing_key.verifying_key().as_bytes()).into();
        Ok(Self { 
            signing_key: Zeroizing::new(signing_key), 
            node_id,
            burst_cache: HashMap::new(),
        })
    }

    /// Solve the memory-hard Argon2id PoW challenge (CRIT-03).
    pub async fn solve_pow(&self, challenge: &[u8]) -> anyhow::Result<String> {
        println!("PoW: Computing Argon2id Sybil-resistance token (64MB memory-hard)...");
        let salt = SaltString::generate(&mut OsRng);
        
        // Configure Argon2id with roadmap-mandated parameters
        let params = Params::new(ARGON2_M, ARGON2_T, ARGON2_P, None)
            .map_err(|e| anyhow::anyhow!("Argon2 Param Error: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        
        let password_hash = argon2.hash_password(challenge, &salt)
            .map_err(|e| anyhow::anyhow!("PoW Hash Error: {}", e))?
            .to_string();
            
        Ok(password_hash)
    }

    /// Checks for metadata-based bursts (leaky bucket) to mitigate linking attacks.
    pub fn check_burst(&mut self, c_batch: [u8; 16]) -> bool {
        let now = Instant::now();
        let entry = self.burst_cache.entry(c_batch).or_insert((now, 0));
        
        // Reset count every 5 seconds
        if now.duration_since(entry.0) > Duration::from_secs(5) {
            *entry = (now, 1);
            return true;
        }

        entry.1 += 1;
        // Threshold: Max 10 packets per batch per 5s window (adjustable)
        entry.1 <= 10
    }

    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }
    
    pub fn mix_keypair(&self) -> HybridKeyPair {
        HybridKeyPair::generate()
    }
}
