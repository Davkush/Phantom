use crate::packet::{RoutingAction, RoutingInfoBlock, SphinxPacket};
use phantom_crypto::hybrid_kem::{HybridKeyPair};
use phantom_crypto::kdf::{derive_key, KdfPurpose};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{generic_array::GenericArray};
use bincode;

/// Peels one layer off a Sphinx packet using the node's long-term mix keypair.
/// Returns the RoutingAction intended for this node, and the new modified SphinxPacket 
/// to be sent to the next hop.
pub fn process_packet(
    node_keypair: &HybridKeyPair,
    packet: &mut SphinxPacket
) -> Result<RoutingInfoBlock, &'static str> {
    if packet.crypto_headers.is_empty() {
        return Err("No layers left to peel");
    }

    // 1. Pop the outermost hybrid encapsulation meant for this hop
    let outermost_header = packet.crypto_headers.remove(0);
    
    // 2. Decapsulate to retrieve the shared secret
    let hybrid_ss = node_keypair.decapsulate(&outermost_header)?;
    let ss_bytes = hybrid_ss.as_bytes();

    // 3. Derive AEAD keys for MAC checking and decryption
    let header_key_bytes = derive_key(&ss_bytes, KdfPurpose::HeaderMac, b"routing_idx");
    let payload_key_bytes = derive_key(&ss_bytes, KdfPurpose::PayloadEncryption, b"payload_idx");
    
    let payload_key = Key::from_slice(&payload_key_bytes.0);
    let header_key = Key::from_slice(&header_key_bytes.0);
    
    let aead_payload = ChaCha20Poly1305::new(payload_key);
    let aead_header = ChaCha20Poly1305::new(header_key);
    let nonce = GenericArray::from([0u8; 12]);

    // 4. Decrypt route info
    aead_header.decrypt_in_place(&nonce, b"", &mut packet.routing_info)
        .map_err(|_| "Routing block decryption/MAC failed")?;
        
    // 5. Decrypt payload
    aead_payload.decrypt_in_place(&nonce, b"", &mut packet.payload)
        .map_err(|_| "Payload decryption/MAC failed")?;

    // 6. Extract the routing action and metadata intended for this node
    // Since we appended in build(), the current innermost action is now at the front.
    let root_block: RoutingInfoBlock = bincode::deserialize(&packet.routing_info)
        .map_err(|_| "Failed to deserialize routing block")?;
        
    // Strip the read block from the routing block so the next node reads the correct one.
    let block_size = bincode::serialized_size(&root_block)
        .map_err(|_| "Failed to get block size")? as usize;
    packet.routing_info.drain(0..block_size);

    Ok(root_block)
}
