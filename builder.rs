use crate::packet::{NodeId, RoutingAction, RoutingInfoBlock, SphinxPacket};
use phantom_crypto::hybrid_kem::{encapsulate, HybridCiphertext, HybridPublicKey};
use phantom_crypto::kdf::{derive_key, KdfPurpose};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{generic_array::GenericArray};
use bincode;

/// Builds a Sphinx⁺ packet using layered encryption (onion routing).
/// 
/// `path`: The ordered list of node public keys representing the circuit.
/// `actions`: What each node should do. The final action must be `Deliver`.
/// `payload`: The serialized message/payload to send.
pub fn build_packet(
    path: &[HybridPublicKey],
    actions: &[RoutingAction],
    payload: &[u8],
    c_batch: [u8; 16],
    epoch: u64
) -> Result<SphinxPacket, &'static str> {
    if path.len() != actions.len() || path.is_empty() {
        return Err("Path and actions length mismatch or empty");
    }

    let hops = path.len();
    
    // We will build the packet inside-out, starting from the final receiver backwards.
    let mut current_payload = payload.to_vec();
    
    // For routing info, we also build backwards. Currently stubbed routing block for simplicity.
    // In full Sphinx, this involves a carefully padded byte array shifted and XOR'd using
    // a PRNG seed. To simulate the cryptography for Phase 0, we'll just iteratively wrap 
    // the routing instructions in AEAD.
    
    let mut current_routing_block = bincode::serialize(&crate::packet::RoutingInfoBlock {
        mac: [0u8; 32],
        action: RoutingAction::Deliver,
        c_batch,
        epoch,
        padding: vec![],
    }).map_err(|_| "Failed to serialize routing action")?;

    let mut ciphertexts = Vec::with_capacity(hops);

    // Build the layers from innermost to outermost (backwards)
    for i in (0..hops).rev() {
        // Generate ephemeral shared secret for this hop
        let pub_key = &path[i];
        let (ct, shared_secret) = encapsulate(pub_key)?;
        
        // We push to the front so the outermost hop is at index 0.
        ciphertexts.insert(0, ct);
        
        let ss_bytes = shared_secret.as_bytes();
        
        let header_key_bytes = derive_key(&ss_bytes, KdfPurpose::HeaderMac, b"routing_idx");
        let payload_key_bytes = derive_key(&ss_bytes, KdfPurpose::PayloadEncryption, b"payload_idx");
        
        let payload_key = Key::from_slice(&payload_key_bytes.0);
        let header_key = Key::from_slice(&header_key_bytes.0);
        
        let aead_payload = ChaCha20Poly1305::new(payload_key);
        let aead_header = ChaCha20Poly1305::new(header_key);
        
        // Single statically zeroed nonce since keys are ephemeral and strictly single-use
        let nonce = GenericArray::from([0u8; 12]);
        
        // Encrypt payload layer
        aead_payload.encrypt_in_place(&nonce, b"", &mut current_payload)
            .map_err(|_| "Payload encryption failed")?;
            
        // Encrypt routing info layer
        let layer_block = crate::packet::RoutingInfoBlock {
            mac: [0u8; 32],
            action: actions[i].clone(),
            c_batch,
            epoch,
            padding: vec![],
        };
        let mut new_routing_block = bincode::serialize(&layer_block)
            .map_err(|_| "Action serialization failed")?;
        
        // Append inner routing block
        new_routing_block.extend(&current_routing_block);
        
        aead_header.encrypt_in_place(&nonce, b"", &mut new_routing_block)
            .map_err(|_| "Routing block encryption failed")?;
            
        current_routing_block = new_routing_block;
    }

    Ok(SphinxPacket {
        crypto_headers: ciphertexts,
        routing_info: current_routing_block,
        payload: current_payload,
    })
}
