use phantom_core::identity::IdentityManager;
use phantom_core::transport::quic::PhantomTransport;
use phantom_core::mix::run_mix_batch_loop;
use tokio::sync::mpsc;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// Directory for configuration and identity files
    #[arg(short, long, default_value = "." )]
    config_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // 1. Identity & Crypto Bridge
    let id_path = args.config_dir.join("identity.json");
    let id_manager = IdentityManager::load_or_generate(id_path)?;
    println!("Node ID: {:x?}", id_manager.node_id());

    // 2. Start Physical Transport (Attempt Port with fallback)
    let transport = PhantomTransport::start(&id_manager, args.port).await?;
    println!("QUIC Transport ACTIVE. Identity-to-TLS bridge operational.");

    // 3. Communications Channel (Wire -> Mix Processor)
    let (mix_tx, mix_rx) = mpsc::channel(100);

    // 4. Parallel Async Operational Loops
    let wire_handle = tokio::spawn(async move {
        println!("Wire Listener: Monitoring UDP/QUIC streams...");
        transport.listen_loop(mix_tx).await;
    });

    let mix_handle = tokio::spawn(async move {
        // Now takes packets from the physical wire via the channel
        run_mix_batch_loop(mix_rx).await; 
    });

    println!("Phantom Node is OPERATIONAL.");

    // Keep process alive and monitor handles
    tokio::select! {
        _ = wire_handle => println!("Wire listener exited."),
        _ = mix_handle => println!("Mix processor exited."),
    }

    Ok(())
}
