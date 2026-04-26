use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::circuit_data::FriConfig;

/// Base field for all Phantom STARKs.
/// Goldilocks: p = 2^64 - 2^32 + 1
pub type F = GoldilocksField;

/// The configuration used for STARK proofs in the mixnet.
/// Poseidon hash function over the Goldilocks field.
pub type C = PoseidonGoldilocksConfig;

/// Rate bits controls the blowup factor of the FRI polynomial commitment.
/// Blowup factor = 2^RATE_BITS. 
/// A rate bits of 3 means a blowup factor of 8.
pub const RATE_BITS: usize = 3;

/// Number of FRI queries.
/// Higher queries = higher security, but larger proofs and verification time.
/// 28 queries combined with rate bits = 3 provides ~100 bits of security.
pub const QUERIES: usize = 28;

/// Degree bits determines the size of the circuit (2^DEGREE_BITS gates).
/// For the batch shuffling circuit, this will be dynamically scaled,
/// but bounded to prevent memory exhaustion on validators.
pub const MAX_DEGREE_BITS: usize = 16;

/// Task 2.1: Minimum batch size for STARK shuffling proofs.
pub const MIN_BATCH_SIZE: usize = 4;

/// Returns the standard FRI configuration for Phantom mixnet.
pub fn default_fri_config() -> FriConfig {
    FriConfig {
        rate_bits: RATE_BITS,
        cap_height: 4,
        proof_of_work_bits: 16,
        reduction_arity_bits: vec![4, 4],
        num_query_steps: QUERIES,
    }
}
