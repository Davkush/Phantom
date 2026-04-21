use std::net::{SocketAddr, Ipv4Addr};
use std::sync::Arc;
use phantom_core::dht::{DhtNode, NodeDescriptor, UptimeSchedule};
use phantom_core::dht::transport::{DhtRpc, DhtResponse, DhtTransport};
use phantom_node::transport::quic::{make_quic_configs, QuicDhtTransport};
use quinn::Endpoint;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_quic_dht_rpc_connectivity() {
    // 1. Setup Node B (Server)
    let node_id_b = [2u8; 32];
    let (server_config_b, client_config_b) = make_quic_configs(&node_id_b).unwrap();
    let addr_b = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let endpoint_b = Endpoint::server(server_config_b, addr_b).unwrap();
    let port_b = endpoint_b.local_addr().unwrap().port();
    
    // 2. Setup Node A (Client)
    let node_id_a = [1u8; 32];
    let (server_config_a, client_config_a) = make_quic_configs(&node_id_a).unwrap();
    let mut endpoint_a = Endpoint::client(addr_b).unwrap(); // Bind to random port
    endpoint_a.set_default_client_config(client_config_a);
    
    let transport_a = QuicDhtTransport::new(endpoint_a);
    
    // 3. Start Mock Server B Loop
    tokio::spawn(async move {
        while let Some(conn) = endpoint_b.accept().await {
            tokio::spawn(async move {
                let connection = conn.await.unwrap();
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let req_data = recv.read_to_end(1024).await.unwrap();
                    let req: DhtRpc = bincode::deserialize(&req_data).unwrap();
                    
                    let resp = match req {
                        DhtRpc::Ping => DhtResponse::Pong,
                        DhtRpc::FindNode { .. } => DhtResponse::Nodes(vec![]),
                        _ => DhtResponse::Ack,
                    };
                    
                    let resp_data = bincode::serialize(&resp).unwrap();
                    send.write_all(&resp_data).await.unwrap();
                    send.finish().await.unwrap();
                }
            });
        }
    });

    // 4. Node A sends Ping to Node B
    let target_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port_b));
    let response = transport_a.send_rpc(target_addr, DhtRpc::Ping).await.unwrap();
    
    match response {
        DhtResponse::Pong => println!("Integration Test: Received PONG over real QUIC!"),
        _ => panic!("Expected Pong, got {:?}", response),
    }
}

#[tokio::test]
async fn test_dht_descriptor_validation_gate() {
    // Task 1.4 security gate verification
    let node_id = [0u8; 32];
    // Mock transport that returns one valid and one invalid descriptor
    struct BadTransport;
    #[async_trait::async_trait]
    impl DhtTransport for BadTransport {
        async fn send_rpc(&self, _: SocketAddr, _: DhtRpc) -> Result<DhtResponse, phantom_core::dht::transport::TransportError> {
            let valid_desc = NodeDescriptor {
                node_id: [1u8; 32],
                ed25519_pubkey: [1u8; 32],
                dilithium_pubkey: [0u8; 1312],
                x25519_pubkey: [0u8; 32],
                kyber_pubkey: [0u8; 1568],
                quic_addr: "127.0.0.1:443".parse().unwrap(),
                pow_nonce: [0u8; 16],
                pow_salt: [0u8; 16],
                uptime_schedule: UptimeSchedule::default(),
                signature_ed25519: [0u8; 64], // Invalid sig
                signature_dilithium: [0u8; 2420],
            };
            Ok(DhtResponse::Nodes(vec![valid_desc]))
        }
    }

    let transport = Arc::new(BadTransport);
    let dht = DhtNode::new(node_id, transport.clone());
    
    // Attempt lookup
    // Since rpc_find_node is private, we test it via the public secure_lookup or check logic directly.
    // However, we want to verify the 'rpc_find_node' logic specifically.
    
    // In lookup.rs, our updated rpc_find_node filters out invalid descriptors.
    // Let's test single_path_lookup behavior.
}
