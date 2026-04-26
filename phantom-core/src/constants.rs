pub const PACKET_SIZE: usize = 9216; // 9KB (CRIT-01/MED-03 Mandatory Standard)
pub const MAX_HOPS: usize = 5;

// KEM Constants (Kyber-1024 + X25519)
pub const X25519_PUB_SIZE: usize = 32;
pub const KYBER_CT_SIZE: usize = 1568; // Full ciphertext for IND-CCA2 security
pub const KEM_BLOCK_SIZE: usize = X25519_PUB_SIZE + KYBER_CT_SIZE; // 1600 B

// Routing Info Constants (Approach B: Separated KEM sidecar)
pub const ROUTING_INFO_SIZE: usize = 340; // 68 bytes * 5 hops (Full Routing Onion)
pub const MAC_SIZE: usize = 32;          // BLAKE3 MAC
pub const SIDECAR_SIZE: usize = (MAX_HOPS - 1) * KEM_BLOCK_SIZE; // 6400 B

// Header Total: 1600 + 340 + 32 + 6400 = 8372 B
pub const HEADER_TOTAL_SIZE: usize = KEM_BLOCK_SIZE + ROUTING_INFO_SIZE + MAC_SIZE + SIDECAR_SIZE;

// Usable Payload: 9216 - 8372 = 844 B
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_TOTAL_SIZE;

// Versioning and Protocol Identifiers
pub const PROTOCOL_VERSION: u8 = 0x02; // Hard break from truncated Kyber (v1)
