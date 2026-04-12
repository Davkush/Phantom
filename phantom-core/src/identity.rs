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

use crate::dht::NodeDescriptor;

/// Argon2id parameters for Sybil resistance (CRIT-03/HIGH-01)
const ARGON2_T: u32 = 3;
const ARGON2_M: u32 = 65536; // 64MB (in KB)
const ARGON2_P: u32 = 1;

pub struct IdentityManager {
    // Zeroizing ensures the private key is wiped from memory when dropped
    signing_key: Zeroizing<SigningKey>,
    pub node_id: [u8; 32],
    pub pow_nonce: [u8; 16],
    
    // MED-03 fixation: Burst detection / Rate limiting state
    burst_cache: HashMap<[u8; 16], (Instant, u32)>, 
}

impl IdentityManager {
    /// Loads an identity from a JSON file or generates a new one if it doesn't exist.
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let (signing_key, pow_nonce) = if path.as_ref().exists() {
            let data = fs::read(path)?;
            let mut seed = [0u8; 32];
            let mut nonce = [0u8; 16];
            if data.len() >= 48 {
                seed.copy_from_slice(&data[..32]);
                nonce.copy_from_slice(&data[32..48]);
            }
            (SigningKey::from_bytes(&seed), nonce)
        } else {
            let mut csprng = OsRng;
            let key = SigningKey::generate(&mut csprng);
            let node_id: [u8; 32] = blake3::hash(key.verifying_key().as_bytes()).into();
            
            // Solve initial PoW admission challenge
            let nonce = crate::pow::solve_static_pow(&node_id, 4).unwrap_or([0u8; 16]);

            if let Some(parent) = path.as_ref().parent() {
                fs::create_dir_all(parent)?;
            }
            let mut buffer = Vec::new();
            buffer.extend_from_slice(&key.to_bytes());
            buffer.extend_from_slice(&nonce);
            fs::write(path, buffer)?;
            (key, nonce)
        };

        let node_id = blake3::hash(signing_key.verifying_key().as_bytes()).into();
        Ok(Self { 
            signing_key: Zeroizing::new(signing_key), 
            node_id,
            pow_nonce,
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
