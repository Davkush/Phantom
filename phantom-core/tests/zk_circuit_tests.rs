use phantom_core::zk::shuffling::generate_shuffle_proof;
use phantom_core::zk::constants::MIN_BATCH_SIZE;

#[tokio::test]
async fn test_zk_proof_negative_binding() {
    let inputs = vec![[1u8; 32]; MIN_BATCH_SIZE];
    let mut outputs = inputs.clone();
    outputs.reverse(); // Shuffled

    let node_id = [7u8; 32];
    
    // 1. Generate a valid proof
    let proof = generate_shuffle_proof(inputs.clone(), outputs.clone(), node_id)
        .expect("Failed to generate valid proof");

    // 2. ASSERT: Tampered Inputs fail verification
    let mut tampered_inputs = inputs.clone();
    tampered_inputs[0][0] ^= 1;
    assert!(proof.verify(&tampered_inputs, &outputs).is_err(), "Proof should FAIL with tampered inputs");

    // 3. ASSERT: Tampered Outputs fail verification
    let mut tampered_outputs = outputs.clone();
    tampered_outputs[0][0] ^= 1;
    assert!(proof.verify(&inputs, &tampered_outputs).is_err(), "Proof should FAIL with tampered outputs");

    // 4. ASSERT: Valid re-verification succeeds
    assert!(proof.verify(&inputs, &outputs).is_ok(), "Valid proof verification failed");
}

#[tokio::test]
async fn test_zk_proof_size_mismatch() {
    let inputs = vec![[1u8; 32]; MIN_BATCH_SIZE];
    let outputs = vec![[1u8; 32]; MIN_BATCH_SIZE + 1];

    let node_id = [7u8; 32];
    let proof = generate_shuffle_proof(inputs.clone(), inputs.clone(), node_id).unwrap();

    // Verify with mismatched sizes should return error
    assert!(proof.verify(&inputs, &outputs).is_err(), "Proof should fail with size mismatch");
}
