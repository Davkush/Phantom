use phantom_core::identity::IdentityManager;
use phantom_core::transport::quic::PhantomTransport;
use phantom_core::mix::run_mix_batch_loop;
use tokio::sync::mpsc;
use clap::Parser;
use std::path::PathBuf;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

mod proxy;
mod reliability;

use crate::proxy::socks5::Socks5Entry;
use crate::reliability::{run_churn_loop, NodeHandle};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on for QUIC
    #[arg(short, long, default_value_t = 443)]
    port: u16,

    /// SOCKS5 Proxy listen port
    #[arg(long, default_value_t = 9050)]
    socks_port: u16,

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

    // 4. Start Usability Layer: SOCKS5 Proxy Entry
    let socks_addr = SocketAddr::from(([127, 0, 0, 1], args.socks_port));
    let socks_proxy = Socks5Entry {
        listen_addr: socks_addr,
        mix_tx: mix_tx.clone(),
    };
    let socks_handle = tokio::spawn(async move {
        let _ = socks_proxy.run_loop().await;
    });

    // 5. Start Churn Loop: HIGH-01 Mitigation
    let node_handle = NodeHandle {
        is_running: Arc::new(Mutex::new(true)),
    };
    let churn_handle = tokio::spawn(async move {
        run_churn_loop(node_handle).await;
    });

    // 6. Parallel Async Operational Loops
    let wire_handle = tokio::spawn(async move {
        println!("Wire Listener: Monitoring UDP/QUIC streams...");
        transport.listen_loop(mix_tx).await;
    });

    let mix_handle = tokio::spawn(async move {
        // Process packets from both SOCKS5 and the physical wire
        run_mix_batch_loop(mix_rx).await; 
    });

    println!("Phantom Node is OPERATIONAL.");

    // Keep process alive and monitor handles
    tokio::select! {
        _ = wire_handle => println!("Wire listener exited."),
        _ = mix_handle => println!("Mix processor exited."),
        _ = socks_handle => println!("SOCKS5 proxy exited."),
        _ = churn_handle => println!("Churn loop exited."),
    }

    Ok(())
}
