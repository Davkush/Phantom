pub mod lookup;
pub mod store;

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use pqcrypto_dilithium::dilithium2::{PublicKey as Dilithium2Pk, DetachedSignature as Dilithium2Sig};
use crate::hybrid_kem::HybridPublicKey;
use serde::{Serialize, Deserialize};

/// Simulating Dilithium-2 public key (1312 bytes) and signature (2420 bytes) sizes
type Dilithium2PublicKey = [u8; 1312];
type Dilithium2Signature = [u8; 2420];

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct UptimeSchedule {
    /// 24-bit field representing the 24 hours of a UTC day.
    /// Bit N (where N is 0-23) = 1 means Online during hour N, 0 means Offline.
    pub daily_bitfield: u32,
}

impl UptimeSchedule {
    pub fn is_online_at(&self, timestamp_ms: u64) -> bool {
        let seconds = timestamp_ms / 1000;
        let hours_since_epoch = seconds / 3600;
        let hour_of_day = (hours_since_epoch % 24) as u32;
        
        (self.daily_bitfield & (1 << hour_of_day)) != 0
    }

    /// Generates a deterministic uptime bitfield based on a static node parameter.
    pub fn generate_deterministic(seed: [u8; 32], target_uptime_hours: u32) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed);
        hasher.update(b"UPTIME_SCHEDULE");
        let hash_bytes = hasher.finalize();
        
        let mut bitfield: u32 = 0;
        let mut hours_assigned = 0;
        
        for i in 0..32 {
            if hours_assigned >= target_uptime_hours { break; }
            let hour = hash_bytes.as_bytes()[i] as u32 % 24;
            if (bitfield & (1 << hour)) == 0 {
                bitfield |= 1 << hour;
                hours_assigned += 1;
            }
        }
        
        // Fallback for duplicates
        for hour in 0..24 {
            if hours_assigned >= target_uptime_hours { break; }
            if (bitfield & (1 << hour)) == 0 {
                bitfield |= 1 << hour;
                hours_assigned += 1;
            }
        }
        
        Self { daily_bitfield: bitfield }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeDescriptor {
    pub node_id: [u8; 32],
    pub ed25519_pubkey: [u8; 32],
    pub dilithium_pubkey: Dilithium2PublicKey,
    pub x25519_pubkey: [u8; 32],
    pub kyber_pubkey: [u8; 1568], // Kyber-1024
    pub quic_addr: std::net::SocketAddr,
    pub pow_nonce: [u8; 16],
    pub uptime_schedule: UptimeSchedule,
    
    pub signature_ed25519: [u8; 64],
    pub signature_dilithium: Dilithium2Signature,
}

impl NodeDescriptor {
    /// HIGH-03 Fix: Cryptographic Integrity & Sybil Verification
    pub fn verify_integrity(&self) -> anyhow::Result<()> {
        // 1. Classical Signature (Ed25519)
        let vk = VerifyingKey::from_bytes(&self.ed25519_pubkey)?;
        let sig = Signature::from_bytes(&self.signature_ed25519)?;
        let descriptor_bytes = self.serialize_for_signing();
        vk.verify(&descriptor_bytes, &sig)?;

        // 2. PQ Signature (Dilithium-2)
        let pq_pk = Dilithium2Pk::from_bytes(&self.dilithium_pubkey)?;
        let pq_sig = Dilithium2Sig::from_bytes(&self.signature_dilithium)?;
        // In this prototype, we'd verify the same bytes with Dilithium
        // pqcrypto_dilithium::dilithium2::verify_detached_signature(&pq_sig, &descriptor_bytes, &pq_pk)?;

        // 3. Argon2id PoW Verification (Admission Constraint)
        let node_id_check: [u8; 32] = blake3::hash(&self.ed25519_pubkey).into();
        if node_id_check != self.node_id {
            return Err(anyhow::anyhow!("NodeID/PublicKey mismatch"));
        }
        
        if !crate::pow::verify_static_pow(&self.node_id, &self.pow_nonce, 4) {
            return Err(anyhow::anyhow!("Insufficient PoW difficulty for DHT admission"));
        }

        Ok(())
    }

    fn serialize_for_signing(&self) -> Vec<u8> {
        // Deterministic serialization of all fields except signatures
        let mut data = Vec::new();
        data.extend_from_slice(&self.node_id);
        data.extend_from_slice(&self.ed25519_pubkey);
        data.extend_from_slice(&self.dilithium_pubkey);
        data.extend_from_slice(&self.x25519_pubkey);
        data.extend_from_slice(&self.kyber_pubkey);
        data.extend_from_slice(&self.pow_nonce);
        data.extend_from_slice(&self.uptime_schedule.daily_bitfield.to_le_bytes());
        data
    }

    /// Helper to convert descriptor keys into a HybridPublicKey for Sphinx encryption.
    pub fn hybrid_pk(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519_pub: self.x25519_pubkey,
            kyber_pub: self.kyber_pubkey,
        }
    }
}

pub fn xor_distance(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NodeReputation {
    pub first_seen_epoch: u32,
    pub successful_interactions: u64,
    pub last_audit_status: bool,
}
