use rand::Rng;
use std::env;

/// Phase 12: Adversarial Simulation Profile
/// Implements behaviors for the "Public Gauntlet" resilience test.
/// Nodes run with PHANTOM_ADVERSARIAL=true will attempt to disrupt the network.
pub struct AdversarialProfile {
    pub is_malicious: bool,
    pub drop_rate: f64,
    pub proof_suppression: bool,
}

impl AdversarialProfile {
    /// Loads the adversarial profile from environment variables.
    pub fn from_env() -> Self {
        let is_malicious = env::var("PHANTOM_ADVERSARIAL").map(|v| v == "true").unwrap_or(false);
        
        if is_malicious {
            println!("\x1B[1;31mADVERSARIAL WARNING: Node running in MALICIOUS mode (Gauntlet Test).\x1B[0m");
        }

        Self {
            is_malicious,
            drop_rate: 0.15,          // 15% selective packet dropping
            proof_suppression: true,   // Malicious nodes do not broadcast STARK proofs
        }
    }

    /// Determines if a packet should be dropped to simulate adversarial disruption.
    pub fn should_drop_packet(&self) -> bool {
        if !self.is_malicious {
            return false;
        }
        let mut rng = rand::thread_rng();
        rng.gen::<f64>() < self.drop_rate
    }

    /// Determines if the STARK shuffling proof for a batch should be suppressed.
    /// This triggers the GossipSub proof-failure ejection logic (HIGH-03).
    pub fn should_suppress_proof(&self) -> bool {
        self.is_malicious && self.proof_suppression
    }
}
