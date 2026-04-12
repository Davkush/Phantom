pub mod obfuscation;
pub mod quic;
pub mod certificate;
pub mod nat;

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::packet::SphinxPacket;
use tokio::sync::mpsc::Sender;

/// Phase 13: Transport Trait Abstraction
/// Addressing the "Identity Plugin" requirement: Allows for pluggable obfuscation 
/// layers (QUIC, WebRTC, TLS-Mimic).
#[async_trait]
pub trait PhantomTransport: Send + Sync {
    /// Sends a 9KB Sphinx Packet over the wire using the provided TrafficShaper.
    async fn send_packet(&self, target_addr: SocketAddr, packet: SphinxPacket, shaper: &crate::transport::obfuscation::TrafficShaper) -> anyhow::Result<()>;
    
    /// Listens for incoming streams and injects them into the Mix Processor.
    async fn listen_loop(&self, tx: Sender<SphinxPacket>, token: tokio_util::sync::CancellationToken);
    
    /// Returns the local address of the transport endpoint.
    fn local_addr(&self) -> anyhow::Result<SocketAddr>;
}
