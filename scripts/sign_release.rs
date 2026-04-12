//! Phase 1: Dilithium-3 Release Signing Utility
//! Requirements: Needs pqcrypto-dilithium = "0.5.0"
//! Usage: Add to Cargo.toml as [[bin]] or run via `cargo run --bin sign_release`

use pqcrypto_dilithium::dilithium3::*;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use std::fs;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: sign_release <file_to_sign> <output_sig_file> [--gen-keys]");
        return Ok(());
    }

    let input_path = &args[1];
    let output_path = &args[2];

    if args.contains(&"--gen-keys".to_string()) {
        let (pk, sk) = keypair();
        fs::write("dilithium3_release_pk.bin", pk.as_bytes())?;
        fs::write("dilithium3_release_sk.bin", sk.as_bytes())?;
        println!("Successfully generated dilithium3_release_pk.bin and dilithium3_release_sk.bin");
    }

    // Load secret key
    let sk_bytes = fs::read("dilithium3_release_sk.bin")
        .map_err(|_| "Secret key file not found. Run with --gen-keys first.")?;
    let sk = SecretKey::from_bytes(&sk_bytes).map_err(|_| "Invalid Secret Key")?;

    // Load file to sign
    let data = fs::read(input_path)?;

    // Sign
    println!("Signing {} with Dilithium-3 (PQ-Safe)...", input_path);
    let signature = detached_sign(&data, &sk);

    // Write signature
    fs::write(output_path, signature.as_bytes())?;
    println!("Signature written to {}", output_path);

    // Self-verification check
    let pk_bytes = fs::read("dilithium3_release_pk.bin")?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| "Invalid Public Key")?;
    
    verify_detached_signature(&signature, &data, &pk)
        .map_err(|_| "Internal verification failed!")?;
    
    println!("Release signing verified successfully.");

    Ok(())
}
