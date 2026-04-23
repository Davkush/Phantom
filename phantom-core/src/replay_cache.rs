use bloomfilter::Bloom;
use std::sync::atomic::{AtomicU64, Ordering};

/// Task 1.5 (LOW-01): Time-bucketed Bloom filter for replay protection.
///
/// Two Bloom filters, each covering half an epoch.
/// At each half-epoch boundary: discard the older filter, start a new one.
/// Memory bound: O(packets_per_half_epoch) with configurable false-positive rate.
/// Maximum entries: 500,000 per filter before constant-time rejection.
pub struct ReplayCache {
    /// Current half-epoch bloom filter
    current_bucket: Bloom<[u8; 32]>,
    /// Previous half-epoch bloom filter (expiring)
    previous_bucket: Bloom<[u8; 32]>,
    /// Size of each bucket
    size: usize,
    /// False positive rate
    fp_rate: f64,
    /// Counter for entries in current bucket (for memory monitoring)
    current_count: AtomicU64,
    /// Counter for entries in previous bucket
    previous_count: AtomicU64,
    /// Maximum entries per bucket (memory limit)
    max_entries: usize,
}

impl ReplayCache {
    /// Create a new ReplayCache with specified parameters.
    ///
    /// # Arguments
    /// * `size` - Number of bits in the Bloom filter
    /// * `fp_rate` - False positive rate (lower = more memory)
    /// * `max_entries` - Maximum entries per bucket (default: 500,000)
    pub fn new(size: usize, fp_rate: f64, max_entries: usize) -> Self {
        Self {
            current_bucket: Bloom::new_for_fp_rate(size, fp_rate),
            previous_bucket: Bloom::new_for_fp_rate(size, fp_rate),
            size,
            fp_rate,
            current_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            max_entries,
        }
    }

    /// Rotate buckets at the half-epoch mark.
    /// The previous bucket is discarded and a new one is created.
    pub fn rotate(&mut self) {
        // Track what we're discarding
        let discarded_count = self.current_count.load(Ordering::Relaxed);
        println!("ReplayCache: Rotating buckets, discarding {} entries from previous epoch", discarded_count);

        // Swap buckets
        self.previous_bucket = std::mem::replace(&mut self.current_bucket, Bloom::new_for_fp_rate(self.size, self.fp_rate));

        // Update counters
        self.previous_count.store(self.current_count.load(Ordering::Relaxed), Ordering::Relaxed);
        self.current_count.store(0, Ordering::Relaxed);
    }

    /// Check and insert a replay tag (KEM block hash).
    /// Returns true if it was inserted successfully (not a replay).
    /// Returns false if:
    /// - Tag was already seen (replay attack detected)
    /// - Current bucket is full (memory limit reached)
    pub fn insert(&mut self, tag: [u8; 32]) -> bool {
        // Check memory limit first
        if self.current_count.load(Ordering::Relaxed) >= self.max_entries as u64 {
            println!("ReplayCache: Memory limit reached ({}), rejecting new entries", self.max_entries);
            return false;
        }

        // Check both buckets for replay
        if self.current_bucket.check(&tag) || self.previous_bucket.check(&tag) {
            return false;
        }

        // Insert into current bucket
        self.current_bucket.set(&tag);
        self.current_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Check if a tag exists without inserting.
    /// Used for verification without updating the cache.
    pub fn contains(&self, tag: &[u8; 32]) -> bool {
        self.current_bucket.check(tag) || self.previous_bucket.check(tag)
    }

    /// Get current entry count for monitoring
    pub fn current_entries(&self) -> u64 {
        self.current_count.load(Ordering::Relaxed)
    }

    /// Get previous bucket entry count
    pub fn previous_entries(&self) -> u64 {
        self.previous_count.load(Ordering::Relaxed)
    }

    /// Check if memory is within safe bounds
    pub fn is_memory_safe(&self) -> bool {
        self.current_count.load(Ordering::Relaxed) < (self.max_entries as u64)
    }

    /// Memory usage as percentage
    pub fn memory_usage_percent(&self) -> f64 {
        let current = self.current_count.load(Ordering::Relaxed) as f64;
        let max = self.max_entries as f64;
        (current / max) * 100.0
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        // Default: 500,000 entries per bucket, 1% false positive rate
        Self::new(500_000, 0.01, 500_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_replay_detection() {
        let mut cache = ReplayCache::default();
        let tag = [0u8; 32];

        // First insert should succeed
        assert!(cache.insert(tag), "First insert should succeed");

        // Second insert should fail (replay detected)
        assert!(!cache.insert(tag), "Replay should be detected");
    }

    #[test]
    fn test_bucket_rotation() {
        let mut cache = ReplayCache::default();
        let tag = [1u8; 32];

        cache.insert(tag);
        assert_eq!(cache.current_entries(), 1);

        cache.rotate();
        assert_eq!(cache.previous_entries(), 1);
        assert_eq!(cache.current_entries(), 0);
    }

    #[test]
    fn test_memory_limit() {
        let mut cache = ReplayCache::new(1000, 0.01, 10);

        for i in 0..15 {
            let tag = [i as u8; 32];
            let result = cache.insert(tag);
            if i < 10 {
                assert!(result, "Insert {} should succeed", i);
            } else {
                assert!(!result, "Insert {} should fail (memory limit)", i);
            }
        }
    }
}
