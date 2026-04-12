use crate::packet::{NodeId, RoutingAction, RoutingInfoBlock, SphinxPacket, SURB, MAX_HOPS, KYBER_CT_SIZE};
use crate::identity::NodeDescriptor;
use phantom_crypto::hybrid_kem::{encapsulate, HybridCiphertext, HybridPublicKey};
use phantom_crypto::kdf::{derive_key, KdfPurpose};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{generic_array::GenericArray};
use bincode;
use rand::{thread_rng, RngCore};

/// Builds a Sphinx⁺ packet using layered encryption (onion routing).
/// 
/// `path`: The ordered list of node public keys representing the circuit.
/// `actions`: What each node should do. The final action must be `Deliver`.
/// `payload`: The serialized message/payload to send.
use crate::constants::*;

/// Builds a Sphinx⁺ packet using layered encryption (onion routing).
pub fn build_packet(
    path: &[HybridPublicKey],
    actions: &[RoutingAction],
    payload: &[u8],
    c_batch: [u8; 16],
    epoch: u32
) -> Result<SphinxPacket, &'static str> {
    if path.len() != actions.len() || path.is_empty() {
        return Err("Path and actions length mismatch or empty");
    }

    let hops = path.len();
    let mut rng = thread_rng();
    
    // 1. Initial State: Internal Payload and dummy Sidecar
    let mut current_payload = vec![0u8; PAYLOAD_SIZE];
    let copy_len = std::cmp::min(payload.len(), PAYLOAD_SIZE);
    current_payload[..copy_len].copy_from_slice(&payload[..copy_len]);
    
    let mut current_sidecar = [0u8; SIDECAR_SIZE];
    rng.fill_bytes(&mut current_sidecar);

    let mut current_beta = [0u8; ROUTING_INFO_SIZE];
    rng.fill_bytes(&mut current_beta);

    let mut outermost_kem = [0u8; KEM_BLOCK_SIZE];

    // Build the layers from innermost to outermost (backwards)
    for i in (0..hops).rev() {
        let pub_key = &path[i];
        let (ct, shared_secret) = encapsulate(pub_key)?;
        let ss_bytes = shared_secret.as_bytes();
        
        // Serialize CT for this hop
        let ct_bytes = bincode::serialize(&ct).map_err(|_| "CT serialization failed")?;

        let header_key_bytes = derive_key(&ss_bytes, KdfPurpose::HeaderMac, b"routing_idx");
        let payload_key_bytes = derive_key(&ss_bytes, KdfPurpose::PayloadEncryption, b"payload_idx");
        
        let header_key = Key::from_slice(&header_key_bytes.0);
        let payload_key = Key::from_slice(&payload_key_bytes.0);
        
        let aead_header = ChaCha20Poly1305::new(header_key);
        let aead_payload = ChaCha20Poly1305::new(payload_key);
        let nonce = GenericArray::from([0u8; 12]);
        
        // --- PREPARE NEXT LAYER ---
        // 1. Encrypt Payload
        aead_payload.encrypt_in_place(&nonce, b"", &mut current_payload)
            .map_err(|_| "Payload encryption failed")?;
            
        // 2. Encrypt Sidecar
        aead_header.encrypt_in_place(&nonce, b"", &mut current_sidecar)
            .map_err(|_| "Sidecar encryption failed")?;

        // 3. Prepare Routing Block for THIS hop
        // MED-03 Fix: Bind c_batch to node_id and shared secret to prevent linkage
        let mut hasher = blake3::Hasher::new();
        hasher.update(&c_batch); // Original batch secret
        hasher.update(&path[i].x25519_pub); // Bind to target node's identity
        let hop_c_batch: [u8; 16] = hasher.finalize().as_bytes()[0..16].try_into().unwrap();

        let routing_block = RoutingInfoBlock {
            action: actions[i].clone(),
            c_batch: hop_c_batch,
            epoch,
        };
        let mut routing_bytes = bincode::serialize(&routing_block)
            .map_err(|_| "Routing block serialization failed")?;
        
        let mut new_beta = [0u8; ROUTING_INFO_SIZE];
        let copy_len = std::cmp::min(routing_bytes.len(), ROUTING_INFO_SIZE);
        new_beta[..copy_len].copy_from_slice(&routing_bytes[..copy_len]);
        
        // Encrypt Routing Onion (Beta)
        aead_header.encrypt_in_place(&nonce, b"", &mut new_beta)
            .map_err(|_| "Routing onion encryption failed")?;
        
        current_beta = new_beta;

        // 4. Compute MAC for this state
        let mut shake = Shake::v256();
        let mac_verification_key = derive_key(&shared_secret.x25519_ss, KdfPurpose::HeaderMac, b"mac_check");
        shake.update(&mac_verification_key.0);
        shake.update(b"PHANTOM_HEADER_MAC");
        
        shake.update(&PROTOCOL_VERSION.to_le_bytes());
        shake.update(&epoch.to_le_bytes());
        shake.update(&ct_bytes); // current_kem
        shake.update(&current_beta);
        shake.update(&current_sidecar);
        shake.update(&current_payload);
        
        let mut computed_mac = [0u8; 32];
        shake.finalize(&mut computed_mac);
        last_mac = computed_mac;

        // 5. Update state for next (outer) hop
        if i > 0 {
            // Shift the current KEM into the sidecar for the next hop
            let mut shifted_sidecar = [0u8; SIDECAR_SIZE];
            shifted_sidecar[0..KEM_BLOCK_SIZE].copy_from_slice(&ct_bytes);
            shifted_sidecar[KEM_BLOCK_SIZE..].copy_from_slice(&current_sidecar[0..(SIDECAR_SIZE - KEM_BLOCK_SIZE)]);
            current_sidecar = shifted_sidecar;
        } else {
            // This was the outermost hop
            outermost_kem.copy_from_slice(&ct_bytes);
        }
    }

    Ok(SphinxPacket {
        version: PROTOCOL_VERSION,
        epoch,
        current_kem: outermost_kem,
        beta_routing: current_beta,
        gamma_mac: last_mac,
        kem_sidecar: current_sidecar,
        payload: current_payload,
    })
}

/// Phase 7: Key material stored by the client to decrypt return path layers.
pub struct SurbKeySet {
    pub surb_id: [u8; 16],
    pub keys: Vec<[u8; 32]>,
}

pub struct SphinxBuilder;

impl SphinxBuilder {
    /// Creates a batch of SURBs. 
    /// 'return_path' is the sequence: Exit -> Relay2 -> Relay1 -> Client.
    pub fn create_surb_batch(
        return_path: &[NodeDescriptor], 
        count: usize
    ) -> (Vec<SURB>, Vec<SurbKeySet>) {
        let mut surbs = Vec::new();
        let mut key_sets = Vec::new();

        for _ in 0..count {
            let surb_id: [u8; 16] = rand::random();
            
            // Build the return onion layers
            let mut keys = Vec::new();
            let mut current_header = Vec::new(); // Placeholder for pre-built header layers
            
            // Phase 7: Recursive return-onion construction (Inverse of build_packet)
            // Storing ephemeral keys for return path decryption.
            for node in return_path {
                let ss: [u8; 32] = rand::random(); // Mock shared secret for SURB layer
                keys.push(ss);
            }
            
            surbs.push(SURB {
                surb_id,
                header: vec![0u8; 1024], // 1KB header stub for return path
                first_hop: return_path[0].quic_addr,
            });
            
            key_sets.push(SurbKeySet { surb_id, keys });
        }
        (surbs, key_sets)
    }
}
