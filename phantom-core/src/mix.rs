use crate::packet::{SphinxPacket, RoutingAction};
use crate::processor::process_packet;
use crate::zk::shuffling::{ShuffleProof, generate_shuffle_proof};
use crate::hybrid_kem::HybridKeyPair;
use crate::replay_cache::ReplayCache;
use tokio::sync::mpsc::{Receiver, Sender};
use rand::seq::SliceRandom;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Mutex;

/// CRIT-02: STARK-based verifiable shuffling and batching.
/// MED-01: Jittered publication to prevent timing correlation.
pub async fn run_mix_batch_loop(
    mut rx: Receiver<SphinxPacket>, 
    out_tx: Sender<SphinxPacket>,
    exit_tx: Sender<SphinxPacket>,
    return_tx: Sender<SphinxPacket>,
    proof_tx: Sender<ShuffleProof>,
    batch_size_tx: Sender<usize>,
    zk_time_tx: Sender<Duration>,
    ip_handler: Option<Arc<IntroductionHandler>>,
    rp_splicer: Arc<Mutex<RendezvousSplicer>>,
    reciprocal_tracker: Arc<ReciprocalTracker>,
    node_keypair: HybridKeyPair,
    replay_cache: Arc<Mutex<ReplayCache>>, // HIGH-05: Replay protection
    token: tokio_util::sync::CancellationToken,
) {
    println!("Mix Processor: Batch loop active. Waiting for 9KB Sphinx packets...");
    
    let mut batch = Vec::new();
    let mut rng = rand::thread_rng();

    loop {
        // MED-01 Fix: Jittered 700ms +/- 50ms publication window
        let jitter = rng.gen_range(650..750);
        let timeout = Duration::from_millis(jitter);

        tokio::select! {
            _ = token.cancelled() => {
                println!("Mix Processor: Shutdown signal received. Exiting loop.");
                break;
            }
            result = tokio::time::timeout(timeout, rx.recv()) => {
                match result {
                    Ok(Some(pkt)) => {
                        println!("Mix Processor: Received packet (epoch {}). Queuing for batch.", pkt.epoch);
                        batch.push(pkt);
                    },
                    Ok(None) => break, // Channel closed
                    Err(_) => {
                        // Timeout reached, process the batch
                        if !batch.is_empty() {
                            println!("Mix Processor: Batch interval reached. Shuffling and processing {} packets...", batch.len());
                    
                    // 1. Shuffling (Real random permutation)
                    batch.shuffle(&mut rng);

                    // 2. PHASE 08: Capture Input/Output Hashes for ZK Verification
                    // Note: Simplified for Phase 1 - in prod, we'd hash the packet's total state or kem/beta.
                    let input_hashes: Vec<[u8; 32]> = batch.iter()
                        .map(|p| blake3::hash(&p.current_kem).into())
                        .collect();
                    
                    let mut outputs = Vec::new();

                    // 3. Peel/Process each packet and dispatch
                    {
                        let mut cache = replay_cache.lock().await;
                        for mut pkt in batch.drain(..) {
                            match process_packet(&node_keypair, &mut pkt, &mut cache) {
                                Ok(block) => {
                                    outputs.push(blake3::hash(&pkt.current_kem).into());
                                    
                                    // Peer reputation credit
                                    reciprocal_tracker.record_success([0u8; 32]).await;
                                    
                                    match block.action {
                                        RoutingAction::Forward(_) => {
                                            let _ = out_tx.send(pkt).await;
                                        },
                                        RoutingAction::Deliver => {
                                            println!("Mix Processor: DELIVER action reached.");
                                            let _ = exit_tx.send(pkt).await;
                                        },
                                        RoutingAction::DeliverSURB(surb_id) => {
                                            let _ = return_tx.send(pkt).await;
                                        },
                                        RoutingAction::DeliverIP => {
                                            if let Some(ref handler) = ip_handler {
                                                let _ = handler.handle_introduce(pkt).await;
                                            }
                                        },
                                        RoutingAction::DeliverRP(cookie) => {
                                            let mut splicer = rp_splicer.lock().await;
                                            if let Ok(Some(other_tx)) = splicer.splice(cookie, out_tx.clone()).await {
                                                println!("Mix Processor: Rendezvous spliced.");
                                            }
                                        },
                                        RoutingAction::Drop => {
                                            println!("Mix Processor: DROP action.");
                                        }
                                    }
                                },
                                Err(e) => println!("Mix Processor: Error processing packet: {}", e),
                            }
                        }
                    }

                    // 4. Background Proof Generation (Non-blocking)
                    let tx = proof_tx.clone();
                    let zk_tx = zk_time_tx.clone();
                    let _ = batch_size_tx.send(input_hashes.len()).await;
                    
                    let node_id = [0u8; 32];
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        if let Ok(proof) = generate_shuffle_proof(input_hashes, outputs, node_id) {
                            let duration = start.elapsed();
                            let _ = zk_tx.send(duration).await;
                            println!("Mix Processor: STARK Shuffle Proof generated in {:?}.", duration);
                            let _ = tx.send(proof).await;
                        }
                    });
                }
            }
        }
    }
}
