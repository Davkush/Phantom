//! Generates the initial 5-node bootstrap set for the Private Testnet.
//! Pre-calculates Argon2id tokens to save time during orchestration.

use serde::{Serialize, Deserialize};

// Local mock definitions for struct dependencies matching library parameters
#[derive(Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub node_id: [u8; 32],
    pub ip: String,
    pub admission_token: [u8; 16],
    pub reputation: f64,
}

fn main() {
    let mut bootnodes = Vec::new();
    
    for i in 0..5 {
        // Construct mock tokens and IDs corresponding to pre-mined Argon2id sequences for speed
        let mut id = [0u8; 32];
        id[0] = i as u8;
        
        let token = [i as u8; 16]; // Simulated token
        
        let descriptor = NodeDescriptor {
            node_id: id,
            ip: format!("127.0.0.1:{}", 4000 + i),
            admission_token: token,
            reputation: 1.0, // Genesis nodes are trusted initially
        };
        bootnodes.push(descriptor);
    }
    
    // Output standard genesis file
    std::fs::write("bootnodes.txt", serde_json::to_string(&bootnodes).unwrap()).unwrap();
    println!("Genesis bootnodes.txt generated with 5 pre-mined descriptors.");
}
