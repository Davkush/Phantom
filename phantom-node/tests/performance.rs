use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Instant;
use phantom_core::packet::{SphinxPacket, PhantomStreamHeader};
use phantom_core::cover::poisson::PoissonTimer;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_throughput_mbps() -> anyhow::Result<()> {
    // 1. Setup Mock Circuit
    let (out_tx, mut out_rx) = mpsc::channel(1000);
    let (deliver_tx, mut deliver_rx) = mpsc::channel(1000);
    
    // 2. Start Mock Exit Node
    let mut exit_received_bytes = 0usize;
    let start_time = Instant::now();
    
    tokio::spawn(async move {
        while let Some(pkt) = deliver_rx.recv().await {
            let header: PhantomStreamHeader = bincode::deserialize(&pkt.payload).unwrap();
            let header_size = 12; // Approximation
            let data_len = pkt.payload.len() - header_size - header.padding_len as usize;
            exit_received_bytes += data_len;
            
            if exit_received_bytes >= 1024 * 1024 { // 1MB reached
                let duration = start_time.elapsed().as_secs_f64();
                let mbps = (exit_received_bytes as f64 * 8.0) / (duration * 1_000_000.0);
                println!("🚀 Benchmark: Received 1MB. Throughput: {:.2} Mbps over {:.2}s", mbps, duration);
                break;
            }
        }
    });

    // 3. Start Mock Mix Node (Forwarder)
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            // In a real test, this would have Poisson delay. 
            // For throughput ceiling, we forward immediately.
            let _ = deliver_tx.send(pkt).await;
        }
    });

    // 4. Start SOCKS5-to-Mixnet Feeding (Entry)
    let stream_id = 42u64;
    let mut seq_num = 0u64;
    let chunk_size = 1024;
    let total_data = 1024 * 1024; // 1MB
    let mut sent = 0usize;

    println!("🚀 Starting 1MB Throughput Test...");

    while sent < total_data {
        let n = std::cmp::min(chunk_size, total_data - sent);
        let header = PhantomStreamHeader {
            stream_id,
            seq_num,
            padding_len: (chunk_size - n) as u32,
            target_addr: None,
        };
        
        let mut payload = bincode::serialize(&header)?;
        payload.extend(vec![0u8; n]);
        payload.extend(vec![0u8; chunk_size - n]); // Padding

        let pkt = SphinxPacket {
            version: 1,
            flags: 0,
            epoch: 0,
            alpha_cl: [0u8; 32],
            alpha_pq_onion: vec![0u8; 1568 * 5],
            beta_routing: [0u8; 128],
            gamma_mac: [0u8; 32],
            c_batch: [0u8; 16],
            pi_ref: 0,
            payload,
        };

        let _ = out_tx.send(pkt).await;
        sent += n;
        seq_num += 1;
    }

    Ok(())
}

#[tokio::test]
async fn test_poisson_latency_impact() {
    let intervals = vec![10.0, 50.0, 100.0]; // ms
    
    for interval in intervals {
        let timer = PoissonTimer::new(interval);
        let mut total_delay = 0.0;
        let samples = 100;
        
        for _ in 0..samples {
            total_delay += timer.next_delay().as_millis() as f64;
        }
        
        let avg_latency = total_delay / samples as f64;
        println!("⏱️ Poisson Interval {}ms -> Avg Added Latency: {:.2}ms", interval, avg_latency);
    }
}
