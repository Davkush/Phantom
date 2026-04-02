use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::Sign;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;

/// A hybrid public key containing both X25519 and Kyber-1024 public keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub x25519_pub: [u8; 32],
    pub kyber_pub: [u8; kyber1024::public_key_bytes()],
}

/// A serialized hybrid ciphertext containing both X25519 ephemeral pubkey and Kyber ciphertext.
/// Addressing CRIT-01: We use the full Kyber ciphertext (1568 bytes) to preserve IND-CCA2 security,
/// rather than the unproven 96-byte truncation scheme.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_pub: [u8; 32],
    pub kyber_ct: [u8; kyber1024::ciphertext_bytes()],
}

/// Hybrid shared secret containing both X25519 and Kyber-1024 derived secrets.
/// This struct implements ZeroizeOnDrop to ensure secrets are cleared from memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    pub x25519_ss: [u8; 32],
    pub kyber_ss: [u8; kyber1024::shared_secret_bytes()],
}

impl HybridSharedSecret {
    /// Combines the classical and post-quantum secrets into a single 64-byte array.
    pub fn as_bytes(&self) -> [u8; 32 + kyber1024::shared_secret_bytes()] {
        let mut combined = [0u8; 32 + kyber1024::shared_secret_bytes()];
        combined[..32].copy_from_slice(&self.x25519_ss);
        combined[32..].copy_from_slice(&self.kyber_ss);
        combined
    }
}

/// A recipient's hybrid keypair.
pub struct HybridKeyPair {
    x25519_secret: EphemeralSecret,
    x25519_public: X25519PublicKey,
    kyber_public: kyber1024::PublicKey,
    kyber_secret: kyber1024::SecretKey,
}

impl HybridKeyPair {
    /// Generate a new ephemeral hybrid keypair.
    pub fn generate() -> Self {
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (kyber_public, kyber_secret) = kyber1024::keypair();

        Self {
            x25519_secret,
            x25519_public,
            kyber_public,
            kyber_secret,
        }
    }

    /// Extract the public key portion.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519_pub: *self.x25519_public.as_bytes(),
            kyber_pub: self.kyber_public.as_bytes().try_into().expect("Kyber pubkey length mismatch"),
        }
    }

    /// Decapsulate a received hybrid ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ct: &HybridCiphertext) -> Result<HybridSharedSecret, &'static str> {
        let sender_x25519_pub = X25519PublicKey::from(ct.x25519_ephemeral_pub);
        let x25519_ss = self.x25519_secret.diffie_hellman(&sender_x25519_pub);

        let kyber_ct_struct = kyber1024::Ciphertext::from_bytes(&ct.kyber_ct)
            .map_err(|_| "Invalid Kyber ciphertext")?;
            
        let kyber_ss = kyber1024::decapsulate(&kyber_ct_struct, &self.kyber_secret);

        Ok(HybridSharedSecret {
            x25519_ss: *x25519_ss.as_bytes(),
            kyber_ss: kyber_ss.as_bytes().try_into().expect("Kyber ss length mismatch"),
        })
    }
}

/// Encapsulate a hybrid shared secret against a recipient's public key.
pub fn encapsulate(recipient_pub: &HybridPublicKey) -> Result<(HybridCiphertext, HybridSharedSecret), &'static str> {
    let sender_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_x25519_public = X25519PublicKey::from(&sender_x25519_secret);

    let rec_x25519_pub = X25519PublicKey::from(recipient_pub.x25519_pub);
    let x25519_ss = sender_x25519_secret.diffie_hellman(&rec_x25519_pub);

    let rec_kyber_public = kyber1024::PublicKey::from_bytes(&recipient_pub.kyber_pub)
        .map_err(|_| "Invalid Kyber public key")?;

    let (kyber_ss, kyber_ct) = kyber1024::encapsulate(&rec_kyber_public);

    let hybrid_ct = HybridCiphertext {
        x25519_ephemeral_pub: *sender_x25519_public.as_bytes(),
        kyber_ct: kyber_ct.as_bytes().try_into().expect("Kyber ct length mismatch"),
    };

    let hybrid_ss = HybridSharedSecret {
        x25519_ss: *x25519_ss.as_bytes(),
        kyber_ss: kyber_ss.as_bytes().try_into().expect("Kyber ss length mismatch"),
    };

    Ok((hybrid_ct, hybrid_ss))
}
