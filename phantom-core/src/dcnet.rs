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

/// Generates a deterministic XOR pad from a shared secret using BLAKE3.
/// This pad should be distributed over Sphinx+ (Standard Mode) circuits.
pub fn generate_shared_pad(shared_secret: &[u8], length: usize, counter: u64) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(shared_secret);
    hasher.update(&counter.to_le_bytes());
    
    let mut output = vec![0u8; length];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);
    
    output
}
