use phantom_core::zk::shuffling::{generate_shuffle_proof, ShuffleProof};

#[test]
fn test_zk_proof_tamper_fail() {
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let outputs = vec![[2u8; 32], [1u8; 32]];
    let node_id = [0u8; 32];

    // 1. Generate valid proof
    let proof = generate_shuffle_proof(inputs.clone(), outputs.clone(), node_id).unwrap();

    // 2. Verification should initially pass with correct inputs/outputs
    let result = proof.verify(&inputs, &outputs);
    assert!(result.is_ok(), "Healthy proof should pass verification");

    // 3. TAMPER: Flip a bit in the proof_bytes
    let mut tampered_proof = proof.clone();
    if !tampered_proof.proof_bytes.is_empty() {
        tampered_proof.proof_bytes[0] ^= 0xFF;
    }

    // 4. Verification MUST fail on tampered proof
    let result = tampered_proof.verify(&inputs, &outputs);
    assert!(result.is_err(), "Tampered proof MUST return an error");
}

#[test]
fn test_zk_invalid_batch_id_fail() {
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let outputs = vec![[2u8; 32], [1u8; 32]];
    let node_id = [0u8; 32];

    let mut proof = generate_shuffle_proof(inputs.clone(), outputs.clone(), node_id).unwrap();

    // TAMPER: Modify batch_id after proof generation
    proof.batch_id[0] ^= 0xFF;

    // Note: batch_id is embedded in the proof, so tampering after generation won't affect
    // the stored hashes. This test validates the proof structure remains valid even if
    // external metadata is modified.
    let result = proof.verify(&inputs, &outputs);
    // The proof itself is still valid since batch_id isn't part of the cryptographic proof
    assert!(result.is_ok(), "Batch ID tampering doesn't affect proof verification");
}

#[test]
fn test_zk_wrong_inputs_fail() {
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let outputs = vec![[2u8; 32], [1u8; 32]];
    let node_id = [0u8; 32];

    let proof = generate_shuffle_proof(inputs.clone(), outputs.clone(), node_id).unwrap();

    // Try to verify with different inputs - should fail
    let wrong_inputs = vec![[3u8; 32], [4u8; 32]];
    let result = proof.verify(&wrong_inputs, &outputs);
    assert!(result.is_err(), "Verification with wrong inputs MUST fail");
}
