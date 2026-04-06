use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpgradeMessage {
    pub new_cid: String,
    pub epoch: u32,
    /// Vector of (Public Key, Signature) pairs
    pub signatures: Vec<([u8; 32], [u8; 64])>,
}

/// Phase 11: Multisig Governance Committee
/// Ensures protocol upgrades (Genesis CID, PoW Difficulty) are decentralized.
/// Addressing CRIT-03: Moving from "Centralized" to "No Centre" principle.
pub struct MultisigCommittee {
    pub authorized_keys: Vec<[u8; 32]>,
}

impl MultisigCommittee {
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        Self { authorized_keys: keys }
    }

    /// Verifies if the upgrade message has at least 5-of-9 valid signatures 
    /// from authorized committee members.
    pub fn verify_5_of_9(&self, msg: &UpgradeMessage) -> bool {
        let mut valid_count = 0;
        // The message payload for the signature is the CID concatenated with the epoch
        let message_bytes = format!("{}:{}", msg.new_cid, msg.epoch);

        for (pubkey_bytes, sig_bytes) in &msg.signatures {
            // 1. Check if the signer is in the authorized committee
            if self.authorized_keys.contains(pubkey_bytes) {
                // 2. Verify the Ed25519 signature
                if let Ok(pubkey) = VerifyingKey::from_bytes(pubkey_bytes) {
                    if let Ok(sig) = Signature::from_bytes(sig_bytes) {
                        if pubkey.verify(message_bytes.as_bytes(), &sig).is_ok() {
                            valid_count += 1;
                        }
                    }
                }
            }
        }

        if valid_count >= 5 {
            println!("Governance: THRESHOLD MET ({}/9). Protocol upgrade authorized.", valid_count);
            true
        } else {
            println!("Governance: THRESHOLD FAILED ({}/9). Upgrade rejected.", valid_count);
            false
        }
    }
}
