use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use std::collections::HashMap;
use quinn::{Endpoint, ServerConfig, ClientConfig, TransportConfig, Connection};
use async_trait::async_trait;
use phantom_core::dht::transport::{DhtTransport, DhtRpc, DhtResponse, TransportError};
use rustls::{Certificate, PrivateKey};

pub struct QuicDhtTransport {
    endpoint: Endpoint,
    /// Connection pool indexed by SocketAddr
    connections: Arc<Mutex<HashMap<SocketAddr, Connection>>>,
}

impl QuicDhtTransport {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn get_connection(&self, peer: SocketAddr) -> Result<Connection, TransportError> {
        let mut pool = self.connections.lock().await;
        
        if let Some(conn) = pool.get(&peer) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }

        // Establish new connection
        let conn = self.endpoint.connect(peer, "phantom-dht")
            .map_err(|e| TransportError::ProtocolError(format!("Connect error: {}", e)))?
            .await
            .map_err(|e| TransportError::ConnectionFailed)?;
            
        pool.insert(peer, conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl DhtTransport for QuicDhtTransport {
    async fn send_rpc(
        &self,
        peer: SocketAddr,
        rpc: DhtRpc,
    ) -> Result<DhtResponse, TransportError> {
        let conn = self.get_connection(peer).await?;
        
        // Open a unidirectional stream for the RPC request/response
        let mut send = conn.open_uni().await
            .map_err(|_| TransportError::ConnectionFailed)?;
            
        let request_data = bincode::serialize(&rpc)
            .map_err(|_| TransportError::SerializationError)?;
            
        send.write_all(&request_data).await
            .map_err(|_| TransportError::ProtocolError("Write failed".into()))?;
        send.finish().await
            .map_err(|_| TransportError::ProtocolError("Finish failed".into()))?;

        // In this minimal QUIC implementation, we wait for a response on a separate stream 
        // or we use a bidirectional stream. The user suggested "send a FindNode RPC as a QUIC stream".
        // Let's use bidirectional for simpler Request-Response mapping.
        
        // Re-implementing with Bi-directional stream for proper Request-Response
        let (mut send_bi, mut recv_bi) = conn.open_bi().await
            .map_err(|_| TransportError::ConnectionFailed)?;
            
        send_bi.write_all(&request_data).await
            .map_err(|_| TransportError::ProtocolError("Write-Bi failed".into()))?;
        send_bi.finish().await
            .map_err(|_| TransportError::ProtocolError("Finish-Bi failed".into()))?;

        // Timeout 500ms as per spec
        let response_data = tokio::time::timeout(Duration::from_millis(500), recv_bi.read_to_end(1024 * 1024))
            .await
            .map_err(|_| TransportError::Timeout)?
            .map_err(|_| TransportError::ProtocolError("Read failed".into()))?;
            
        let response: DhtResponse = bincode::deserialize(&response_data)
            .map_err(|_| TransportError::SerializationError)?;
            
        Ok(response)
    }
}

pub fn make_quic_configs(node_id: &[u8; 32]) -> anyhow::Result<(ServerConfig, ClientConfig)> {
    let cert = rcgen::generate_simple_self_signed(vec![hex::encode(node_id)])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();

    let server_cert = Certificate(cert_der.clone());
    let server_key = PrivateKey(priv_key);

    let mut server_config = ServerConfig::with_single_cert(vec![server_cert], server_key)?;
    
    // MTU 9000 as per spec to match docker-compose/jumbo frames
    let mut transport = TransportConfig::default();
    transport.initial_mtu(9000);
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    
    let transport_arc = Arc::new(transport);
    server_config.transport_config(transport_arc.clone());

    // Client config - skip certificate verification for DHT peer discovery
    // (Actual trust is in NodeDescriptor signatures)
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
        
    let mut client_config = ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(transport_arc);

    Ok((server_config, client_config))
}

struct SkipServerVerification;

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _sct_list: &[u8],
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
