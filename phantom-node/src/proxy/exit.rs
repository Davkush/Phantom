use tokio::sync::{Mutex, mpsc};
use tokio::io::AsyncReadExt;
use phantom_core::packet::{SphinxPacket, PhantomStreamHeader, PayloadEnvelope, SURB, RoutingAction};

pub struct ExitNode {
    /// Maps stream_id -> Sender for the stream's reassembly task
    active_streams: Arc<Mutex<HashMap<u64, mpsc::Sender<SphinxPacket>>>>,
    /// Channel to send return packets to the physical wire (Cover Loop)
    outbound_tx: mpsc::Sender<SphinxPacket>,
}

impl ExitNode {
    pub fn new(outbound_tx: mpsc::Sender<SphinxPacket>) -> Self {
        Self {
            active_streams: Arc::new(Mutex::new(HashMap::new())),
            outbound_tx,
        }
    }

    pub async fn handle_deliver(&self, packet: SphinxPacket) -> anyhow::Result<()> {
        let envelope: PayloadEnvelope = bincode::deserialize(&packet.payload)?;
        let stream_id = envelope.stream_header.stream_id;

        let mut streams = self.active_streams.lock().await;

        if let Some(tx) = streams.get(&stream_id) {
            let _ = tx.send(packet).await;
        } else {
            // New stream initiated!
            if let Some(target) = envelope.stream_header.target_addr.clone() {
                println!("ExitNode: Initiating new outbound stream {} to {}", stream_id, target);
                
                let (tx, rx) = mpsc::channel(100);
                streams.insert(stream_id, tx);
                
                let streams_clone = self.active_streams.clone();
                let outbound_clone = self.outbound_tx.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = run_bidirectional_stream(stream_id, target, rx, outbound_clone).await {
                        println!("ExitNode: Stream {} error: {}", stream_id, e);
                    }
                    streams_clone.lock().await.remove(&stream_id);
                });
                
                let _ = streams.get(&stream_id).unwrap().send(packet).await;
            }
        }

        Ok(())
    }
}

async fn run_bidirectional_stream(
    stream_id: u64,
    target: String,
    mut mix_rx: mpsc::Receiver<SphinxPacket>,
    outbound_tx: mpsc::Sender<SphinxPacket>
) -> anyhow::Result<()> {
    let mut tcp_stream = tokio::net::TcpStream::connect(&target).await?;
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    
    let surb_pool = Arc::new(Mutex::new(Vec::new()));
    let surb_pool_clone = surb_pool.clone();
    
    // 1. FORWARD PATH: Mixnet -> TCP Target
    let mut forward_handle = tokio::spawn(async move {
        let mut next_seq = 0u64;
        let mut buffer = BTreeMap::new();
        while let Some(pkt) = mix_rx.recv().await {
            if let Ok(envelope) = bincode::deserialize::<PayloadEnvelope>(&pkt.payload) {
                // Piggyback: Add new SURBs to the pool
                surb_pool_clone.lock().await.extend(envelope.surb_bundle);
                
                buffer.insert(envelope.stream_header.seq_num, envelope.data);
                while let Some(data) = buffer.remove(&next_seq) {
                    let _ = tcp_write.write_all(&data).await;
                    next_seq += 1;
                }
            }
        }
    });

    // 2. REVERSE PATH: TCP Target -> Mixnet (via SURBs)
    let mut reverse_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 7168]; // Matching chunk_size
        let mut seq_num = 0u64;
        
        while let Ok(n) = tcp_read.read(&mut buf).await {
            if n == 0 { break; }
            
            // Pop a SURB for the return journey
            let mut pool = surb_pool.lock().await;
            if let Some(surb) = pool.pop() {
                let header = PhantomStreamHeader {
                    stream_id,
                    seq_num,
                    ack_num: 0, // Placeholder
                    window_size: 64,
                    padding_len: (7168 - n) as u32,
                    target_addr: None,
                    surb_id: Some(surb.surb_id),
                };
                
                let envelope = PayloadEnvelope {
                    stream_header: header,
                    data: buf[..n].to_vec(),
                    surb_bundle: Vec::new(), // Response usually doesn't carry SURBs back to client
                };
                
                let payload = bincode::serialize(&envelope).unwrap();
                
                // Construct Sphinx Packet using the pre-built SURB header
                let mut return_pkt = SphinxPacket {
                    version: 1,
                    epoch: 0,
                    current_kem: [0u8; 1600],
                    beta_routing: [0u8; 68],
                    gamma_mac: [0u8; 32],
                    kem_sidecar: [0u8; 6400],
                    payload,
                };
                
                // If surb.header contains pre-built layers, we could parse them here.
                // For now, we mock the return path.

                
                let _ = outbound_tx.send(return_pkt).await;
                seq_num += 1;
            } else {
                println!("ExitNode: No SURBs available for stream {}. Dropping response chunk.", stream_id);
                // In production, we'd buffer or wait for a replenishment packet
            }
        }
    });

    tokio::select! {
        _ = forward_handle => println!("Forward stream {} closed.", stream_id),
        _ = reverse_handle => println!("Reverse stream {} closed.", stream_id),
    }

    Ok(())
}
