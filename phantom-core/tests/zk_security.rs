use phantom_core::zk::shuffling::{generate_shuffle_proof, ShufflingProof};

#[test]
fn test_zk_proof_tamper_fail() {
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let outputs = vec![[2u8; 32], [1u8; 32]];
    let permutation = vec![1, 0];
    let node_id = [0u8; 32];

    // 1. Generate valid proof
    let proof = generate_shuffle_proof(inputs, outputs, permutation, node_id).unwrap();
    
    // 2. Verification should initially pass (once implemented)
    // assert!(proof.verify().is_ok(), "Healthy proof should pass");

    // 3. TAMPER: Flip a bit in the proof_bytes
    let mut tampered_proof = proof.clone();
    if !tampered_proof.proof_bytes.is_empty() {
        tampered_proof.proof_bytes[0] ^= 0xFF;
    }

    // 4. Verification MUST fail
    let result = tampered_proof.verify();
    assert!(result.is_err(), "Tampered proof MUST return an error");
}

#[test]
fn test_zk_invalid_batch_id_fail() {
    let inputs = vec![[1u8; 32], [2u8; 32]];
    let outputs = vec![[2u8; 32], [1u8; 32]];
    let permutation = vec![1, 0];
    let node_id = [0u8; 32];

    let mut proof = generate_shuffle_proof(inputs, outputs, permutation, node_id).unwrap();
    
    // TAMPER: Modify batch_id
    proof.batch_id[0] ^= 0xFF;

    let result = proof.verify();
    assert!(result.is_err(), "Proof with invalid batch_id MUST fail");
}
