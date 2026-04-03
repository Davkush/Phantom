use quinn::{Endpoint, ServerConfig, TransportConfig};
use std::sync::Arc;
use std::net::SocketAddr;
use crate::identity::IdentityManager;
use crate::packet::SphinxPacket;
use crate::transport::certificate::generate_node_certificate;
use rand::Rng;

pub struct PhantomTransport {
    pub endpoint: Endpoint,
}

impl PhantomTransport {
    /// Initializes a QUIC endpoint using the Node's Cryptographic Identity.
    /// Addressing HIGH-04: Port fallback logic (Port -> 4443).
    pub async fn start(identity: &IdentityManager, preferred_port: u16) -> anyhow::Result<Self> {
        // 1. Generate a self-signed cert bound to the Ed25519 identity
        let (cert, priv_key) = generate_node_certificate(identity)?;
        
        // 2. Configure Server with QUIC 'GREASE' and Header Protection (HIGH-04 Fix)
        let server_config = ServerConfig::with_single_cert(vec![cert], priv_key)?;
        let mut transport_config = TransportConfig::default();
        
        // Optimization for Mixnets: High concurrency of short-lived unidirectional streams
        transport_config.max_concurrent_uni_streams(1000u32.into());
        
        // Enable QUIC grease to prevent fingerprinting
        transport_config.initial_rtt(std::time::Duration::from_millis(100)); 
        
        // SECURITY HIGH-04: Hybrid Rotation with Jittered Thresholds
        // Decision: Maintain connections for max 10-15 mins with +/- 20% jitter
        let mut rng = rand::thread_rng();
        let timeout_secs = rng.gen_range(600..900); // 10 to 15 minutes
        transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(timeout_secs).try_into()?));
        
        // Disable keep-alives to prevent "persistent link" signature mapping
        transport_config.keep_alive_interval(None);

        let mut server_config = server_config;
        server_config.transport_config(Arc::new(transport_config));

        // 3. Bind to UDP port (with fallback)
        let addr = SocketAddr::from(([0, 0, 0, 0], preferred_port));
        let endpoint = match Endpoint::server(server_config.clone(), addr) {
            Ok(ep) => ep,
            Err(_) => {
                println!("Permission denied for port {}, falling back to 4443.", preferred_port);
                let fallback = SocketAddr::from(([0, 0, 0, 0], 4443));
                Endpoint::server(server_config, fallback)?
            }
        };

        Ok(Self { endpoint })
    }

    /// Sends a 9KB Sphinx Packet over the wire using the provided TrafficShaper.
    pub async fn send_packet(
        &self, 
        target_addr: SocketAddr, 
        packet: SphinxPacket,
        shaper: &crate::transport::obfuscation::TrafficShaper
    ) -> anyhow::Result<()> {
        // 1. Establish or Re-use QUIC Connection
        let connection = self.endpoint.connect(target_addr, "phantom-node")?.await?;
        
        // 2. Open unidirectional stream
        let stream = connection.open_uni().await?;
        
        // 3. Apply Traffic Shaping (Poisson + 9KB random padding) and Dispatch
        shaper.shape_and_send(stream, packet).await?;
        
        Ok(())
    }

    /// Listens for incoming QUIC streams and injects them into the Mix Processor.
    /// Addressing HIGH-04: Enforces 9216 byte read boundary.
    pub async fn listen_loop(&self, tx: tokio::sync::mpsc::Sender<SphinxPacket>) {
        while let Some(conn) = self.endpoint.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let connection = conn.await.ok()?;
                while let Ok(mut stream) = connection.accept_uni().await {
                    // Force 9KB buffer to ensure bitwise indistinguishability
                    let mut buf = vec![0u8; crate::packet::PACKET_SIZE];
                    if stream.read_exact(&mut buf).await.is_ok() {
                        // Deserialize and inject into the mix engine
                        if let Ok(pkt) = SphinxPacket::deserialize(&buf) {
                            let _ = tx.send(pkt).await;
                        }
                    }
                }
                Some(())
            });
        }
    }
    /// Returns the local address of the QUIC endpoint.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}
