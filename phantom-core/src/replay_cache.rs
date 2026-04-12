use bloomfilter::Bloom;

/// Phase 2 LOW-01: Time-bucketed Bloom filter to efficiently reject replayed Packets 
/// without causing an unbounded map OOM vector under flood.
pub struct ReplayCache {
    current_bucket: Bloom<[u8; 32]>,
    previous_bucket: Bloom<[u8; 32]>,
    // Size and false positive rate
    size: usize,
    fp_rate: f64,
}

impl ReplayCache {
    pub fn new(size: usize, fp_rate: f64) -> Self {
        Self {
            current_bucket: Bloom::new(size, fp_rate),
            previous_bucket: Bloom::new(size, fp_rate),
            size,
            fp_rate,
        }
    }

    /// Rotate buckets at the half-epoch mark.
    pub fn rotate(&mut self) {
        self.previous_bucket = std::mem::replace(&mut self.current_bucket, Bloom::new(self.size, self.fp_rate));
    }

    /// Check and insert an alpha_cl (replay tag). 
    /// Returns true if it was inserted successfully (not a replay).
    pub fn insert(&mut self, tag: [u8; 32]) -> bool {
        if self.current_bucket.check(&tag) || self.previous_bucket.check(&tag) {
            return false;
        }
        self.current_bucket.set(&tag);
        true
    }
}
