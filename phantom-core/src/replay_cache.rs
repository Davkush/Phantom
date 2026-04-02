use std::collections::HashSet;

/// Phase 2 LOW-01: Time-bucketed Bloom filter to efficiently reject replayed Packets 
/// without causing an unbounded map OOM vector under flood.
/// We use rotating HashSets simulating time-bucketing here as a Phase 0 implementation placeholder.
pub struct ReplayCache {
    current_bucket: HashSet<[u8; 32]>,
    previous_bucket: HashSet<[u8; 32]>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self {
            current_bucket: HashSet::new(),
            previous_bucket: HashSet::new(),
        }
    }

    /// Rotate buckets at the half-epoch mark.
    pub fn rotate(&mut self) {
        self.previous_bucket = std::mem::take(&mut self.current_bucket);
    }

    /// Check and insert an alpha_cl (replay tag). 
    /// Returns true if it was inserted successfully (not a replay).
    pub fn insert(&mut self, tag: [u8; 32]) -> bool {
        if self.current_bucket.contains(&tag) || self.previous_bucket.contains(&tag) {
            return false;
        }
        self.current_bucket.insert(tag);
        true
    }
}
