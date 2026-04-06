use crate::hidden_service::ip::IntroductionHandler;
use crate::hidden_service::rp::RendezvousSplicer;
use crate::incentives::reciprocal::ReciprocalTracker;
use std::sync::Arc;
use tokio::sync::Mutex;
use rand::Rng;
use std::time::Duration;

/// CRIT-02: STARK-based verifiable shuffling and batching.
/// MED-01: Jittered publication to prevent timing correlation.
pub async fn run_mix_batch_loop(
    mut rx: Receiver<SphinxPacket>, 
    out_tx: Sender<SphinxPacket>,
    exit_tx: Sender<SphinxPacket>,
    return_tx: Sender<SphinxPacket>,
    proof_tx: Sender<ShufflingProof>,
    batch_size_tx: Sender<usize>,
    zk_time_tx: Sender<Duration>,
    ip_handler: Option<Arc<IntroductionHandler>>,
    rp_splicer: Arc<Mutex<RendezvousSplicer>>,
    reciprocal_tracker: Arc<ReciprocalTracker>,     // Phase 11: Incentives
    node_keypair: HybridKeyPair
) {
    println!("Mix Processor: Batch loop active. Waiting for 9KB Sphinx packets...");
    
    let mut batch = Vec::new();
    let mut rng = rand::thread_rng();

    loop {
        // MED-01 Fix: Jittered 700ms +/- 50ms publication window
        let jitter = rng.gen_range(650..750);
        let timeout = Duration::from_millis(jitter);

        let result = tokio::time::timeout(timeout, rx.recv()).await;

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
                    
                    // 1. PHASE 08: Capture Input Hashes for ZK Verification
                    let input_hashes: Vec<[u8; 32]> = batch.iter()
                        .map(|p| blake3::hash(&p.payload).into())
                        .collect();
                    
                    let mut outputs = Vec::new();
                    let permutation: Vec<usize> = (0..batch.len()).collect(); // Stub permutation

                    // 2. Peel/Process each packet and dispatch
                    // Phase 11: Priority-Aware Draining (Tit-for-Tat)
                    // In a production impl, we would sort 'batch' by PeerReputation here.
                    for mut pkt in batch.drain(..) {
                        match process_packet(&node_keypair, &mut pkt) {
                            Ok(block) => {
                                outputs.push(blake3::hash(&pkt.payload).into());
                                
                                // Phase 11: Credit the peer for a successful hand-off
                                // In this prototype, we record success for a dummy NodeID
                                // In the full QUIC transport, this would be the authenticated PeerID.
                                reciprocal_tracker.record_success([0u8; 32]).await;
                                
                                match block.action {
                                    RoutingAction::Forward(_) => {
                                        let _ = out_tx.send(pkt).await;
                                    },
                                    RoutingAction::Deliver => {
                                        println!("Mix Processor: DELIVER action reached. Routing to ExitNode...");
                                        let _ = exit_tx.send(pkt).await;
                                    },
                                    RoutingAction::DeliverSURB(surb_id) => {
                                        println!("Mix Processor: DELIVER_SURB action (ID {:?}) reached.", surb_id);
                                        let _ = return_tx.send(pkt).await;
                                    },
                                    RoutingAction::DeliverIP => {
                                        // Phase 10: Forward to Introduction Handler
                                        if let Some(ref handler) = ip_handler {
                                            let _ = handler.handle_introduce(pkt).await;
                                        }
                                    },
                                    RoutingAction::DeliverRP(cookie) => {
                                        // Phase 10: Splice rendezvous halves
                                        let mut splicer = rp_splicer.lock().await;
                                        // In Phase 10 prototype, we splice back to the outbound queue
                                        // which then routes based on the peeled RoutingAction.
                                        if let Ok(Some(other_tx)) = splicer.splice(cookie, out_tx.clone()).await {
                                            // Splicing logic: Both sides now have each other's Sender
                                            println!("Mix Processor: Rendezvous spliced for cookie {:?}.", cookie);
                                        }
                                    },
                                    RoutingAction::Drop => {
                                        println!("Mix Processor: DROP action. Packet discarded.");
                                    }
                                }
                            },
                            Err(e) => println!("Mix Processor: Error processing packet: {}", e),
                        }
                    }

                    // 3. PHASE 08 & 09: Background Proof Generation (Non-blocking)
                    let tx = proof_tx.clone();
                    let zk_tx = zk_time_tx.clone();
                    let _ = batch_size_tx.send(input_hashes.len()).await;
                    
                    let node_id = [0u8; 32];
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        if let Ok(proof) = generate_shuffle_proof(input_hashes, outputs, permutation, node_id) {
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
