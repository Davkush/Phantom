use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, Zeroizing};
use ed25519_dalek::{SigningKey, VerifyingKey};
use crate::hybrid_kem::HybridKeyPair;
use std::path::Path;
use std::fs;
use rand::rngs::OsRng;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params,
};
use std::time::{Instant, Duration};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use crate::dht::NodeDescriptor;

/// Argon2id parameters for Sybil resistance (CRIT-03/HIGH-01)
const ARGON2_T: u32 = 3;
const ARGON2_M: u32 = 65536; // 64MB (in KB)
const ARGON2_P: u32 = 1;

/// MED-02: Burst detection parameters from roadmap
/// If more than 1,000 new node admissions in a 10-minute window, increment C2 by 2
const BURST_WINDOW_SECS: u64 = 600;       // 10 minutes
const BURST_THRESHOLD: u32 = 1_000;
const BURST_C2_INCREMENT: u32 = 2;

/// Adaptive difficulty parameter (C2)
static ADAPTIVE_C2: AtomicU32 = AtomicU32::new(0);

/// Returns the current adaptive difficulty (C2) for PoW
pub fn get_current_difficulty() -> u32 {
    4 + ADAPTIVE_C2.load(Ordering::Relaxed)
}

/// Increments C2 by BURST_C2_INCREMENT (called when burst threshold exceeded)
pub fn increment_difficulty_for_burst() {
    let old = ADAPTIVE_C2.load(Ordering::Relaxed);
    let new = old.saturating_add(BURST_C2_INCREMENT);
    ADAPTIVE_C2.store(new, Ordering::Relaxed);
    println!("Burst detected: Incremented adaptive difficulty C2 to {}", new);
}

/// Identity storage format: 32 bytes seed + 16 bytes nonce + 16 bytes salt = 64 bytes
const IDENTITY_SIZE: usize = 32 + 16 + 16;

/// Thread-safe burst detector for tracking node admissions
pub struct BurstDetector {
    /// Maps timestamp -> count of new admissions in that window
    admission_counts: HashMap<u64, u32>,
    /// Last cleanup timestamp
    last_cleanup: Instant,
}

impl BurstDetector {
    pub fn new() -> Self {
        Self {
            admission_counts: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Record a new node admission and check if burst threshold is exceeded
    /// Returns true if burst was detected (threshold exceeded)
    pub fn record_admission(&mut self) -> bool {
        let now = Instant::now();

        // Cleanup old entries every minute
        if now.duration_since(self.last_cleanup) > Duration::from_secs(60) {
            self.cleanup_expired();
            self.last_cleanup = now;
        }

        // Get current window key (rounded to 10-minute windows)
        let window_key = (now.elapsed().as_secs() / BURST_WINDOW_SECS) * BURST_WINDOW_SECS;

        // Count in this window
        let count = self.admission_counts.entry(window_key).or_insert(0);
        *count += 1;

        // Check threshold
        if *count > BURST_THRESHOLD {
            increment_difficulty_for_burst();
            return true;
        }
        false
    }

    /// Remove expired window entries
    fn cleanup_expired(&mut self) {
        let now = (Instant::now().elapsed().as_secs() / BURST_WINDOW_SECS) * BURST_WINDOW_SECS;
        self.admission_counts.retain(|&key, _| key + BURST_WINDOW_SECS >= now);
    }

    /// Get current admission count in active window
    pub fn get_current_count(&self) -> u32 {
        let now = (Instant::now().elapsed().as_secs() / BURST_WINDOW_SECS) * BURST_WINDOW_SECS;
        self.admission_counts.get(&now).copied().unwrap_or(0)
    }
}

impl Default for BurstDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Global burst detector shared across all identity managers
static GLOBAL_BURST_DETECTOR: Mutex<Option<BurstDetector>> = Mutex::new(None);

/// Initialize or get the global burst detector
pub fn get_global_burst_detector() -> MutexGuard<'static, Option<BurstDetector>> {
    let mut guard = GLOBAL_BURST_DETECTOR.lock().unwrap();
    if guard.is_none() {
        *guard = Some(BurstDetector::new());
    }
    guard
}

pub struct IdentityManager {
    // Zeroizing ensures the private key is wiped from memory when dropped
    signing_key: Zeroizing<SigningKey>,
    pub node_id: [u8; 32],
    pub pow_nonce: [u8; 16],
    pub pow_salt: [u8; 16],

    // MED-03 fixation: Burst detection / Rate limiting state
    burst_cache: HashMap<[u8; 16], (Instant, u32)>,
}

impl IdentityManager {
    /// Loads an identity from a JSON file or generates a new one if it doesn't exist.
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let (signing_key, pow_nonce, pow_salt) = if path.as_ref().exists() {
            let data = fs::read(path)?;
            let mut seed = [0u8; 32];
            let mut nonce = [0u8; 16];
            let mut salt = [0u8; 16];
            if data.len() >= IDENTITY_SIZE {
                seed.copy_from_slice(&data[..32]);
                nonce.copy_from_slice(&data[32..48]);
                salt.copy_from_slice(&data[48..64]);
            }
            (SigningKey::from_bytes(&seed), nonce, salt)
        } else {
            let mut csprng = OsRng;
            let key = SigningKey::generate(&mut csprng);
            let node_id: [u8; 32] = blake3::hash(key.verifying_key().as_bytes()).into();

            // Solve initial PoW admission challenge (Task 1.3 Adaptive Difficulty)
            let difficulty = get_current_difficulty();
            let solution = crate::pow::solve_static_pow(&node_id, difficulty)
                .unwrap_or(crate::pow::PowSolution {
                    nonce: [0u8; 16],
                    salt: [0u8; 16],
                });

            // MED-02: Record admission for burst detection
            {
                let mut detector = get_global_burst_detector();
                if let Some(d) = detector.as_mut() {
                    d.record_admission();
                }
            }

            if let Some(parent) = path.as_ref().parent() {
                fs::create_dir_all(parent)?;
            }
            let mut buffer = Vec::with_capacity(IDENTITY_SIZE);
            buffer.extend_from_slice(&key.to_bytes());
            buffer.extend_from_slice(&solution.nonce);
            buffer.extend_from_slice(&solution.salt);
            fs::write(path, buffer)?;
            (key, solution.nonce, solution.salt)
        };

        let node_id = blake3::hash(signing_key.verifying_key().as_bytes()).into();
        Ok(Self {
            signing_key: Zeroizing::new(signing_key),
            node_id,
            pow_nonce,
            pow_salt,
            burst_cache: HashMap::new(),
        })
    }

    /// Solve the memory-hard Argon2id PoW challenge (CRIT-03).
    pub async fn solve_pow(&self, challenge: &[u8]) -> anyhow::Result<String> {
        println!("PoW: Computing Argon2id Sybil-resistance token (64MB memory-hard)...");
        let salt = SaltString::generate(&mut OsRng);

        // Configure Argon2id with roadmap-mandated parameters
        let params = Params::new(ARGON2_M, ARGON2_T, ARGON2_P, None)
            .map_err(|e| anyhow::anyhow!("Argon2 Param Error: {}", e))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let password_hash = argon2.hash_password(challenge, &salt)
            .map_err(|e| anyhow::anyhow!("PoW Hash Error: {}", e))?
            .to_string();

        Ok(password_hash)
    }

    /// Checks for metadata-based bursts (leaky bucket) to mitigate linking attacks.
    pub fn check_burst(&mut self, c_batch: [u8; 16]) -> bool {
        let now = Instant::now();
        let entry = self.burst_cache.entry(c_batch).or_insert((now, 0));

        // Reset count every 5 seconds
        if now.duration_since(entry.0) > Duration::from_secs(5) {
            *entry = (now, 1);
            return true;
        }

        entry.1 += 1;
        // Threshold: Max 10 packets per batch per 5s window (adjustable)
        entry.1 <= 10
    }

    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    pub fn mix_keypair(&self) -> HybridKeyPair {
        HybridKeyPair::generate()
    }
}
