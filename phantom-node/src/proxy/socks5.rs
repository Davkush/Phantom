use std::collections::{HashMap, BTreeMap};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use phantom_core::packet::{SphinxPacket, PhantomStreamHeader, MAX_HOPS, KYBER_CT_SIZE, PayloadEnvelope, SURB, RoutingAction};
use phantom_core::builder::{SphinxBuilder, build_packet};
use phantom_core::routing::guards::GuardManager;
use phantom_core::routing::path::PathSelector;
use phantom_core::identity::NodeDescriptor;
use phantom_crypto::kdf::{derive_key, KdfPurpose};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, AeadInPlace};
use chacha20poly1305::aead::{generic_array::GenericArray};
use std::sync::Arc;

pub struct Socks5Entry {
    pub listen_addr: SocketAddr,
    pub mix_tx: tokio::sync::mpsc::Sender<SphinxPacket>,
    pub guards: Vec<NodeDescriptor>,
    pub middle_nodes: Vec<NodeDescriptor>,
    pub exit_nodes: Vec<NodeDescriptor>,
}

impl Socks5Entry {
    pub async fn run_loop(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        println!("SOCKS5 Proxy active on {}", self.listen_addr);

        loop {
            let (mut stream, _) = listener.accept().await?;
            let tx = self.mix_tx.clone();
            
            tokio::spawn(async move {
                // 1. Handle SOCKS5 Handshake (Version 5, No Auth)
                if let Ok(target) = handle_socks5_handshake(&mut stream).await {
                    println!("SOCKS5: CONNECT request to {:?}", target);
                    
                    // GAP-06: Persistent Guard Selection
                    let path = PathSelector::select_circuit(
                        &self.guards,
                        &self.middle_nodes,
                        &self.exit_nodes
                    );

                    if let Ok(circuit) = path {
                        let _ = pipe_stream_to_mixnet(stream, target, tx, circuit).await;
                    } else {
                        println!("SOCKS5: Failed to select circuit for stream.");
                    }
                }
            });
        }
    }
}

async fn handle_socks5_handshake(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).await?;

    if buf[0] != 0x05 { return Err(anyhow::anyhow!("Invalid SOCKS version")); }
    
    // Send NO AUTH response
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    if header[1] != 0x01 { return Err(anyhow::anyhow!("Only CONNECT supported")); }

    let target = match header[3] {
        0x01 => { // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", Ipv4Addr::from(addr), u16::from_be_bytes(port))
        }
        0x03 => { // Domain name
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", String::from_utf8_lossy(&domain), u16::from_be_bytes(port))
        }
        _ => return Err(anyhow::anyhow!("Address type not supported")),
    };

    // Send Success response
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    Ok(target)
}

async fn pipe_stream_to_mixnet(
    mut stream: TcpStream, 
    target: String, 
    tx: tokio::sync::mpsc::Sender<SphinxPacket>,
    circuit: Vec<NodeDescriptor>
) -> anyhow::Result<()> {
    let stream_id: u64 = rand::random();
    let mut seq_num = 0u64;
    let chunk_size = 7168; // (MED-03/PHASE-07) effective application data (9KB total)
    let mut buf = vec![0u8; chunk_size];
    
    // Simulate pre-existing SURB bundle (Phase 7 logic)
    let surb_bundle = Vec::new(); 
    
    // Prepare Circuit Data
    let path_keys: Vec<_> = circuit.iter().map(|n| n.hybrid_pk()).collect();
    let actions = vec![
        RoutingAction::Forward(phantom_core::packet::NodeId(circuit[1].node_id)),
        RoutingAction::Forward(phantom_core::packet::NodeId(circuit[2].node_id)),
        RoutingAction::Deliver,
    ];

    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 { break; }
        
        let header = PhantomStreamHeader {
            stream_id,
            seq_num,
            ack_num: 0,
            window_size: 64,
            padding_len: (chunk_size - n) as u32,
            target_addr: if seq_num == 0 { Some(target.clone()) } else { None },
            surb_id: None,
        };
        
        let envelope = PayloadEnvelope {
            stream_header: header,
            data: buf[..n].to_vec(),
            surb_bundle: surb_bundle.clone(),
        };
        
        let payload = bincode::serialize(&envelope)?;
        let c_batch: [u8; 16] = rand::random();
        let epoch = 0; // Current protocol epoch

        // PHASE 05 Hardening: Construct Real Sphinx Packet with persistent Entry Guard
        let packet = build_packet(&path_keys, &actions, &payload, c_batch, epoch)
            .map_err(|e| anyhow::anyhow!("Sphinx construction failed: {}", e))?;
        
        tx.send(packet).await?;
        seq_num += 1;
    }
    Ok(())
}

/// Phase 7: StreamManager handles the reassembly of out-of-order return packets.
pub struct StreamManager {
    pub reassembly_buffer: BTreeMap<u64, Vec<u8>>,
    pub next_expected_seq: u64,
    pub surb_keys: HashMap<[u8; 16], Vec<[u8; 32]>>,
    pub active_tcp_streams: HashMap<u64, tokio::sync::mpsc::Sender<Vec<u8>>>,
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            reassembly_buffer: BTreeMap::new(),
            next_expected_seq: 0,
            surb_keys: HashMap::new(),
            active_tcp_streams: HashMap::new(),
        }
    }

    pub fn has_active_streams(&self) -> bool {
        !self.active_tcp_streams.is_empty()
    }

    /// Process a packet arriving from the Exit node via a SURB.
    pub async fn handle_inbound(&mut self, surb_id: [u8; 16], encrypted_payload: Vec<u8>) -> anyhow::Result<()> {
        // 1. Retrieve the pre-stored keys for this specific SURB
        let keys = self.surb_keys.get(&surb_id).ok_or_else(|| anyhow::anyhow!("Unknown SURB"))?;
        
        // 2. Decrypt the layers (Client "unpeels" what they pre-wrapped)
        let decrypted_payload = self.peel_surb_layers(encrypted_payload, keys);
        
        // 3. Reassembly logic
        if let Ok(envelope) = bincode::deserialize::<PayloadEnvelope>(&decrypted_payload) {
            let stream_id = envelope.stream_header.stream_id;
            self.reassembly_buffer.insert(envelope.stream_header.seq_num, envelope.data);
            
            if let Some(data) = self.try_flush_buffer() {
                if let Some(tx) = self.active_tcp_streams.get(&stream_id) {
                    let _ = tx.send(data).await;
                }
            }
        }
        Ok(())
    }

    /// Phase 7 & MED-01: Client peels layers by iteratively applying symmetric decryption.
    pub fn peel_surb_layers(&self, mut payload: Vec<u8>, keys: &Vec<[u8; 32]>) -> Vec<u8> {
        let nonce = GenericArray::from([0u8; 12]);
        // Reverse of encryption: The Exit node "wrapped" the response layers using 
        // keys we provided. We now "unpeel" them in reverse order.
        for ss_bytes in keys.iter().rev() {
            let key_bytes = derive_key(ss_bytes, KdfPurpose::PayloadEncryption, b"payload_idx");
            let key = Key::from_slice(&key_bytes.0);
            let aead = ChaCha20Poly1305::new(key);
            
            // Decrypt in-place using the single-use key
            let _ = aead.decrypt_in_place(&nonce, b"", &mut payload);
        }
        payload
    }

    fn try_flush_buffer(&mut self) -> Option<Vec<u8>> {
        let mut combined_data = Vec::new();
        while let Some(data) = self.reassembly_buffer.remove(&self.next_expected_seq) {
            combined_data.extend(data);
            self.next_expected_seq += 1;
        }
        if combined_data.is_empty() { None } else { Some(combined_data) }
    }
}
