use crate::packet::{RoutingAction, RoutingInfoBlock, SphinxPacket};
use crate::constants::*;
use x25519_dalek::{PublicKey, StaticSecret};
use subtle::ConstantTimeEq;
use rand::{thread_rng, RngCore};
use crate::hybrid_kem::{HybridKeyPair, HybridCiphertext, HybridSharedSecret};
use crate::kdf::{derive_key, KdfPurpose};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{generic_array::GenericArray};
use bincode;
use tiny_keccak::{Hasher, Shake};

use crate::replay_cache::ReplayCache;

pub fn process_packet(
    node_keypair: &HybridKeyPair,
    packet: &mut SphinxPacket,
    replay_cache: &mut ReplayCache
) -> Result<RoutingInfoBlock, &'static str> {
    // 1. Step 1: Classical Decapsulation for MAC Verification
    let my_ct: HybridCiphertext = bincode::deserialize(&packet.current_kem)
        .map_err(|_| "Failed to deserialize HybridCiphertext")?;
    
    let x25519_ss = node_keypair.decapsulate_x25519(&my_ct);
    
    // 2. Early MAC Key Derivation
    let mac_key = derive_key(&x25519_ss, KdfPurpose::HeaderMac, b"mac_check");
    
    // 3. CRITICAL: Verify MAC before expensive/sensitive Kyber decapsulation
    verify_mac(packet, &mac_key.0).map_err(|_| "MAC verification failed - dropping packet")?;

    // 4. LOW-01 Fix: Replay Protection (AFTER MAC verification)
    // Caching the current hop's KEM block (replay tag).
    let tag: [u8; 32] = blake3::hash(&packet.current_kem).into();
    if !replay_cache.insert(tag) {
        return Err("Replayed packet detected - dropping");
    }

    // 5. Step 2: PQ Decapsulation (Safe now that MAC and Replay are checked)
    let kyber_ss = node_keypair.decapsulate_kyber(&my_ct)?;
    
    let hybrid_ss = HybridSharedSecret { x25519_ss, kyber_ss };
    let ss_bytes = hybrid_ss.as_bytes();

    // 5. Derive keys for decryption layers
    let header_key_bytes = derive_key(&ss_bytes, KdfPurpose::HeaderMac, b"routing_idx");
    let payload_key_bytes = derive_key(&ss_bytes, KdfPurpose::PayloadEncryption, b"payload_idx");
    
    let header_key = Key::from_slice(&header_key_bytes.0);
    let payload_key = Key::from_slice(&payload_key_bytes.0);
    
    let aead_header = ChaCha20Poly1305::new(header_key);
    let aead_payload = ChaCha20Poly1305::new(payload_key);
    let nonce = GenericArray::from([0u8; 12]);

    // 6. Decrypt Header (Routing Info) and Sidecar
    aead_header.decrypt_in_place(&nonce, b"", &mut packet.beta_routing)
        .map_err(|_| "Routing block decryption failed")?;
        
    aead_header.decrypt_in_place(&nonce, b"", &mut packet.kem_sidecar)
        .map_err(|_| "KEM sidecar decryption failed")?;
        
    aead_payload.decrypt_in_place(&nonce, b"", &mut packet.payload)
        .map_err(|_| "Payload decryption failed")?;

    // 7. Extract the routing action intended for this node
    let root_block: RoutingInfoBlock = bincode::deserialize(&packet.beta_routing)
        .map_err(|_| "Failed to deserialize routing block")?;
        
    // 8. UPDATE FOR NEXT HOP (Approach B Peeling)
    // Shift the sidecar into the current KEM slot
    packet.current_kem.copy_from_slice(&packet.kem_sidecar[0..KEM_BLOCK_SIZE]);
    
    let mut next_sidecar = [0u8; SIDECAR_SIZE];
    next_sidecar[0..(SIDECAR_SIZE - KEM_BLOCK_SIZE)].copy_from_slice(&packet.kem_sidecar[KEM_BLOCK_SIZE..]);
    thread_rng().fill_bytes(&mut next_sidecar[(SIDECAR_SIZE - KEM_BLOCK_SIZE)..]);
    packet.kem_sidecar.copy_from_slice(&next_sidecar);

    // Peeling the Beta Onion (Routing Info)
    // Shift by 68 bytes and append 68 bytes of random noise
    let mut next_beta = [0u8; ROUTING_INFO_SIZE];
    next_beta[0..(ROUTING_INFO_SIZE - 68)].copy_from_slice(&packet.beta_routing[68..]);
    thread_rng().fill_bytes(&mut next_beta[(ROUTING_INFO_SIZE - 68)..]);
    packet.beta_routing.copy_from_slice(&next_beta);

    Ok(root_block)
}

/// MED-01 Fix: Encrypts/Masks the c_batch metadata field for the next hop.
/// This prevents a GPA from linking batches across different nodes.
pub fn encrypt_metadata_hop(c_batch: &mut [u8; 16], hop_secret: &[u8; 32]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(hop_secret);
    hasher.update(b"metadata_mask");
    let mask = hasher.finalize();
    let mask_bytes = mask.as_bytes();

    for i in 0..16 {
        c_batch[i] ^= mask_bytes[i];
    }
}

/// CRIT-01 Fix: Restores bitwise unlinkability using Scalar Multiplication.
pub fn blind_x25519(alpha_bytes: &mut [u8; 32], blind_bytes: &[u8; 32]) {
    let alpha_pub = PublicKey::from(*alpha_bytes);
    let scalar = StaticSecret::from(*blind_bytes);
    
    // alpha_next = alpha_current ^ blind (Group Scalar Multiplication)
    let blinded = scalar.diffie_hellman(&alpha_pub);
    *alpha_bytes = blinded.to_bytes();
}

/// HIGH-04 Fix: Constant-time MAC Verification using SHAKE-256.
pub fn verify_mac(pkt: &SphinxPacket, key: &[u8]) -> Result<(), String> {
    let mut shake = Shake::v256();
    shake.update(key);
    shake.update(b"PHANTOM_HEADER_MAC");
    
    // Header binding: Hash all fields to ensure bit-level integrity before decapsulation.
    shake.update(&pkt.version.to_le_bytes());
    shake.update(&pkt.epoch.to_le_bytes());
    shake.update(&pkt.current_kem);
    shake.update(&pkt.beta_routing);
    shake.update(&pkt.kem_sidecar);
    // Note: In high-performance nodes, payload hashing can be deferred or probabilistic.
    // For Phase 1 hardening, we enforce full integrity.
    shake.update(&pkt.payload);
    
    let mut computed = [0u8; 32];
    shake.finalize(&mut computed);
    
    if pkt.gamma_mac.ct_eq(&computed).into() {
        Ok(())
    } else {
        Err("MAC verification failed".to_string())
    }
}
