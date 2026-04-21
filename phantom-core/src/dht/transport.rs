use std::net::SocketAddr;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use crate::zk::shuffling::ShuffleProof;
use super::NodeDescriptor;

#[derive(Debug, Serialize, Deserialize)]
pub enum DhtRpc {
    Ping,
    FindNode { target: [u8; 32] },
    FindDesc { node_id: [u8; 32] },
    StoreDesc { descriptor: NodeDescriptor },
    StoreProof { proof: ShuffleProof },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum DhtResponse {
    Pong,
    Nodes(Vec<NodeDescriptor>),
    Descriptor(Option<NodeDescriptor>),
    Ack,
    Error(String),
}

#[derive(Debug)]
pub enum TransportError {
    ConnectionFailed,
    Timeout,
    SerializationError,
    UnexpectedResponse,
    IdentityMismatch,
    ProtocolError(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TransportError {}

#[async_trait]
pub trait DhtTransport: Send + Sync {
    async fn send_rpc(
        &self,
        peer: SocketAddr,
        rpc: DhtRpc,
    ) -> Result<DhtResponse, TransportError>;
}
