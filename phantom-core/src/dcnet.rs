use blake3::Hasher;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

/// Task 4.1: DC-Net Verdict Jamming Protection
///
/// Implements a Verdict-based jamming protection mechanism where each participant
/// generates a Verdict MAC in a DC-Net round. If Verdict MAC fails, the sender
/// is flagged/slashed.
///
/// Per roadmap Task 4.1 requirements:
/// - Verdict MAC derived from message + shared secret + round counter
/// - Slot validation before broadcast
/// - Jamming detection and flagging
pub struct DCNetRound {
    pub my_message: Vec<u8>,
    pub shared_pads: Vec<Vec<u8>>, // Pads shared with other group members
}

impl DCNetRound {
    /// Computes the XOR sum: (Message XOR Pad_1 XOR Pad_2 ... XOR Pad_N)
    /// Addressing HIGH-02: Information-theoretic anonymity.
    pub fn compute_broadcast_share(&self) -> Vec<u8> {
        let mut share = self.my_message.clone();
        // 9KB constraint applies to DC-Net broadcasts to maintain indistinguishability
        if share.len() < crate::packet::PACKET_SIZE {
            share.resize(crate::packet::PACKET_SIZE, 0);
        }

        for pad in &self.shared_pads {
            for (i, byte) in share.iter_mut().enumerate() {
                if i < pad.len() {
                    *byte ^= pad[i];
                }
            }
        }
        share
    }

    /// Global XOR of all shares reveals the original message
    pub fn reveal(shares: Vec<Vec<u8>>) -> Vec<u8> {
        let mut result = vec![0u8; crate::packet::PACKET_SIZE];
        for share in shares {
            for (i, byte) in result.iter_mut().enumerate() {
                if i < share.len() {
                    *byte ^= share[i];
                }
            }
        }
        result
    }
}

/// Task 4.1: Verdict MAC for DC-Net slot validation.
///
/// Each participant computes a Verdict MAC proving they legitimately
/// own the slot they're transmitting in. This prevents jamming attacks
/// where an adversary floods the network with garbage messages.
#[derive(Debug, Clone)]
pub struct VerdictMac {
    /// The MAC tag
    pub tag: [u8; 32],
    /// Round number this verdict is for
    pub round: u64,
    /// Slot index in the DC-Net round
    pub slot: u32,
}

impl VerdictMac {
    /// Compute a Verdict MAC for a message.
    ///
    /// Uses HMAC-like construction: H(shared_secret || round || slot || message)
    /// This allows any group member to verify the verdict without revealing
    /// the sender's identity.
    pub fn compute(
        shared_secret: &[u8],
        round: u64,
        slot: u32,
        message: &[u8],
    ) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(shared_secret);
        hasher.update(&round.to_le_bytes());
        hasher.update(&slot.to_le_bytes());
        hasher.update(message);

        let hash = hasher.finalize();
        let mut tag = [0u8; 32];
        tag.copy_from_slice(hash.as_bytes());

        Self { tag, round, slot }
    }

    /// Verify a Verdict MAC.
    pub fn verify(&self, shared_secret: &[u8], slot: u32, message: &[u8]) -> bool {
        let expected = Self::compute(shared_secret, self.round, slot, message);
        self.tag == expected.tag
    }
}

/// Task 4.1: Jamming detector state.
pub struct JammingDetector {
    /// Tracks failed verdict MACs per node
    failed_verdicts: RwLock<HashMap<Vec<u8>, FailedVerdictTracker>>,
    /// Configuration
    config: JammingConfig,
}

#[derive(Debug, Clone)]
struct FailedVerdictTracker {
    /// Count of failed verdicts
    failures: u32,
    /// First failure timestamp
    first_failure: std::time::Instant,
    /// Last suspicion timestamp
    last_suspicion: std::time::Instant,
}

/// Task 4.1: Jamming detection configuration.
#[derive(Debug, Clone)]
pub struct JammingConfig {
    /// Maximum failed verdicts before flagging
    pub max_failures_before_flag: u32,
    /// Window for counting failures (seconds)
    pub failure_window_secs: u64,
    /// Cooldown between flagging actions (seconds)
    pub flag_cooldown_secs: u64,
}

impl Default for JammingConfig {
    fn default() -> Self {
        Self {
            max_failures_before_flag: 3,
            failure_window_secs: 300,  // 5 minutes
            flag_cooldown_secs: 600,    // 10 minutes
        }
    }
}

impl JammingDetector {
    /// Create a new jamming detector.
    pub fn new() -> Self {
        Self {
            failed_verdicts: RwLock::new(HashMap::new()),
            config: JammingConfig::default(),
        }
    }

    /// Record a failed Verdict MAC.
    ///
    /// Returns true if the node should be flagged as a jammer.
    pub async fn record_failed_verdict(&self, node_key: &[u8]) -> bool {
        let mut tracker = self.failed_verdicts.write().await;
        let now = std::time::Instant::now();

        let entry = tracker.entry(node_key.to_vec()).or_insert(FailedVerdictTracker {
            failures: 0,
            first_failure: now,
            last_suspicion: now,
        });

        // Reset if outside window
        let window = std::time::Duration::from_secs(self.config.failure_window_secs);
        if now.duration_since(entry.first_failure) > window {
            entry.failures = 0;
            entry.first_failure = now;
        }

        entry.failures += 1;
        entry.last_suspicion = now;

        entry.failures >= self.config.max_failures_before_flag
    }

    /// Record a successful Verdict verification.
    /// Resets the failure counter for a node.
    pub async fn record_successful_verdict(&self, node_key: &[u8]) {
        let mut tracker = self.failed_verdicts.write().await;
        if let Some(entry) = tracker.get_mut(node_key) {
            entry.failures = 0;
        }
    }

    /// Check if a node is currently flagged.
    pub async fn is_flagged(&self, node_key: &[u8]) -> bool {
        let tracker = self.failed_verdicts.read().await;
        if let Some(entry) = tracker.get(node_key) {
            let cooldown = std::time::Duration::from_secs(self.config.flag_cooldown_secs);
            entry.failures >= self.config.max_failures_before_flag
                && entry.last_suspicion.elapsed() < cooldown
        } else {
            false
        }
    }

    /// Get the current failure count for a node.
    pub async fn get_failure_count(&self, node_key: &[u8]) -> u32 {
        let tracker = self.failed_verdicts.read().await;
        tracker.get(node_key).map(|e| e.failures).unwrap_or(0)
    }

    /// Reset detection state (typically at epoch boundary).
    pub async fn reset(&self) {
        let mut tracker = self.failed_verdicts.write().await;
        tracker.clear();
    }
}

impl Default for JammingDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Task 4.1: Verdict-based slot validator.
///
/// Validates that a sender legitimately owns their DC-Net slot by checking
/// the Verdict MAC before allowing the broadcast to proceed.
pub struct SlotValidator {
    detector: JammingDetector,
    /// Per-slot secrets for verification
    slot_secrets: RwLock<HashMap<u32, Vec<u8>>>,
}

impl SlotValidator {
    /// Create a new slot validator.
    pub fn new() -> Self {
        Self {
            detector: JammingDetector::new(),
            slot_secrets: RwLock::new(HashMap::new()),
        }
    }

    /// Register a slot with its shared secret.
    pub async fn register_slot(&self, slot: u32, shared_secret: Vec<u8>) {
        let mut secrets = self.slot_secrets.write().await;
        secrets.insert(slot, shared_secret);
    }

    /// Validate a Verdict MAC for a slot.
    ///
    /// Returns Ok(()) if valid, Err with reason if invalid.
    pub async fn validate_verdict(
        &self,
        slot: u32,
        message: &[u8],
        mac: &VerdictMac,
        node_key: &[u8],
    ) -> Result<(), VerdictError> {
        // Check if node is already flagged
        if self.detector.is_flagged(node_key).await {
            return Err(VerdictError::NodeFlagged);
        }

        // Get slot secret
        let secret = {
            let secrets = self.slot_secrets.read().await;
            secrets.get(&slot).cloned()
        };

        let secret = secret.ok_or(VerdictError::UnknownSlot)?;

        // Verify MAC
        if !mac.verify(&secret, slot, message) {
            let should_flag = self.detector.record_failed_verdict(node_key).await;
            if should_flag {
                return Err(VerdictError::JammingDetected);
            }
            return Err(VerdictError::InvalidMac);
        }

        // Record successful verification
        self.detector.record_successful_verdict(node_key).await;
        Ok(())
    }
}

impl Default for SlotValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Task 4.1: Verdict validation errors.
#[derive(Debug, Clone)]
pub enum VerdictError {
    /// Node has been flagged for jamming
    NodeFlagged,
    /// Slot is not registered
    UnknownSlot,
    /// Verdict MAC is invalid
    InvalidMac,
    /// Jamming attack detected (multiple failures)
    JammingDetected,
}

impl std::fmt::Display for VerdictError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeFlagged => write!(f, "Node is flagged for jamming"),
            Self::UnknownSlot => write!(f, "Unknown DC-Net slot"),
            Self::InvalidMac => write!(f, "Invalid Verdict MAC"),
            Self::JammingDetected => write!(f, "Jamming attack detected"),
        }
    }
}

impl std::error::Error for VerdictError {}

/// Generates a deterministic XOR pad from a shared secret using BLAKE3.
/// This pad should be distributed over Sphinx+ (Standard Mode) circuits.
pub fn generate_shared_pad(shared_secret: &[u8], length: usize, counter: u64) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(shared_secret);
    hasher.update(&counter.to_le_bytes());

    let mut output = vec![0u8; length];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);

    output
}
