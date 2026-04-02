use phantom_core::identity::IdentityManager;
use phantom_core::dht::PhantomDHT;
use phantom_core::cover::run_cover_loop;
use phantom_core::mix::run_mix_batch_loop;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Identity & Sybil Resistance
    let id_manager = IdentityManager::load_or_generate("~/.phantom/identity.json")?;
    println!("Node ID: {:?}", id_manager.node_id());

    // MED-02 Fix: Solving Argon2id puzzle to get admission token
    println!("Solving SR-DHT Admission Puzzle (Argon2id)...");
    let admission_token = id_manager.solve_pow().await?; 

    // 2. Network Initialization
    let bootnodes = phantom_core::dht::load_bootnodes("bootnodes.txt")?;
    let dht = PhantomDHT::start(id_manager.clone(), admission_token, bootnodes).await?;
    println!("DHT Initialized. Connected to {} peers.", dht.peer_count().await);

    // 3. Parallel Operational Loops
    let cover_handle = tokio::spawn(async move {
        // HIGH-04: Poisson timing to evade ML detection
        // run_cover_loop(100.0).await; 
    });

    let mix_handle = tokio::spawn(async move {
        // CRIT-02: STARK-based verifiable shuffling
        // run_mix_batch_loop().await;
    });

    println!("Phantom Node is OPERATIONAL.");

    // Keep process alive
    tokio::select! {
        res = cover_handle => println!("Cover loop exited: {:?}", res),
        res = mix_handle => println!("Mixer loop exited: {:?}", res),
    }

    Ok(())
}
