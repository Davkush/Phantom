use plonky2::plonk::config::FriConfig;

/// Phase 16: Step 1: Transparent FRI Parameters
/// Designed for 100-bit security without a Trusted Setup.
/// FIX: Converted to a function to avoid 'vec![]' in const on stable Rust.
pub fn default_fri_config() -> FriConfig {
    FriConfig {
        rate_log: 3,              // Blowup Factor = 8
        num_query_steps: 28,       // Number of FRI queries
        proof_of_work_bits: 16,   // Grinding PoW to harden proof
        reduction_arity_bits: vec![4, 4, 4, 4], // Arity for FRI tree reduction
    }
}

/// High-level security parameters for the Shuffling circuit
pub const MIN_BATCH_SIZE: usize = 16;
pub const MAX_BATCH_SIZE: usize = 256;
pub const CIRCUIT_CAP_LOG: usize = 4; // Merkle tree cap size for proof consistency
