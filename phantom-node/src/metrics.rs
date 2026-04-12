use prometheus::{Encoder, TextEncoder, Registry, Gauge, Histogram, histogram_opts};
use lazy_static::lazy_static;
use warp::Filter;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    
    // Phase 9: Metric for ZK Proofing Performance
    pub static ref ZK_GEN_TIME: Histogram = Histogram::with_opts(
        histogram_opts!("phantom_zk_gen_ms", "Plonky2 proof generation time in ms")
    ).unwrap();

    // Phase 9: Metric for Mixnet Batching
    // Audit Metric A: Measures proof travel time across GossipSub.
    pub static ref PHANTOM_PROOF_DRIFT_MS: Histogram = register_histogram!(
        "phantom_proof_drift_ms", 
        "Time delta between proof creation and local validation",
        vec![100.0, 250.0, 500.0, 750.0, 1000.0, 1400.0, 2000.0]
    ).unwrap();

    // Audit Metric C: Counts total node blacklistings.
    pub static ref PHANTOM_EJECTION_COUNT: Counter = register_counter!(
        "phantom_ejection_count", 
        "Total number of peers blacklisted for proof failure"
    ).unwrap();

    pub static ref BATCH_SIZE: Gauge = Gauge::new(
        "phantom_mix_batch_size", "Number of packets in current mix batch"
    ).unwrap();

    // Phase 9: Metric for DHT Convergence
    pub static ref DHT_PEERS: Gauge = Gauge::new(
        "phantom_dht_peers", "Current number of discovered peers in the routing table"
    ).unwrap();
}

/// Spawns the Prometheus metrics exporter on the specified port.
/// Scraped by the Sentinel TUI or an external Prometheus server.
pub async fn spawn_metrics_server(port: u16) {
    // 1. Register metrics with the global registry
    let _ = REGISTRY.register(Box::new(ZK_GEN_TIME.clone()));
    let _ = REGISTRY.register(Box::new(PHANTOM_PROOF_DRIFT_MS.clone()));
    let _ = REGISTRY.register(Box::new(PHANTOM_EJECTION_COUNT.clone()));
    let _ = REGISTRY.register(Box::new(BATCH_SIZE.clone()));
    let _ = REGISTRY.register(Box::new(DHT_PEERS.clone()));

    // 2. Define the /metrics endpoint
    let metrics_route = warp::path!("metrics").map(|| {
        let mut buffer = Vec::new();
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    });

    println!("Orchestration: Prometheus exporter active on 0.0.0.0:{}", port);
    
    // 3. Start the warp server
    warp::serve(metrics_route).run(([0, 0, 0, 0], port)).await;
}
