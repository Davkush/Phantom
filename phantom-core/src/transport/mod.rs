pub mod obfuscation;
pub mod quic;
pub mod certificate;
pub mod nat;

pub use quic::QuicTransport;

use async_trait::async_trait;
use std::net::SocketAddr;
use crate::packet::SphinxPacket;
use tokio::sync::mpsc::Sender;

/// Task 3.2: Transport Trait Abstraction for pluggable transport layers.
///
/// Addressing the "Identity Plugin" requirement: Allows for pluggable obfuscation
/// layers (QUIC, WebRTC, TLS-Mimic).
///
/// Per roadmap Task 3.2 requirements:
/// - Trait must be Send + Sync to support multi-threaded async
/// - MUST have graceful shutdown semantics via CancellationToken
/// - Supports set_options() for runtime configuration
#[async_trait]
pub trait PhantomTransport: Send + Sync {
    /// Sends a Sphinx Packet over the wire using the provided TrafficShaper.
    async fn send_packet(&self, target_addr: SocketAddr, packet: SphinxPacket, shaper: &crate::transport::obfuscation::TrafficShaper) -> anyhow::Result<()>;

    /// Listens for incoming streams and injects them into the Mix Processor.
    /// Uses CancellationToken for graceful shutdown semantics.
    async fn listen_loop(&self, tx: Sender<SphinxPacket>, token: tokio_util::sync::CancellationToken);

    /// Returns the local address of the transport endpoint.
    fn local_addr(&self) -> anyhow::Result<SocketAddr>;

    /// Task 3.2: Set runtime transport options.
    ///
    /// Allows configuration of transport-specific parameters:
    /// - Buffer sizes
    /// - Timeouts
    /// - Rate limiting
    /// - Obfuscation parameters
    fn set_options(&self, options: TransportOptions) -> anyhow::Result<()>;

    /// Task 3.2: Check if transport is currently connected/operational.
    fn is_connected(&self) -> bool;
}

/// Task 3.2: Transport configuration options.
///
/// Used with set_options() to configure transport behavior at runtime.
#[derive(Debug, Clone, Default)]
pub struct TransportOptions {
    /// Maximum packet size (affects padding behavior)
    pub max_packet_size: Option<usize>,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: Option<u64>,
    /// Enable/disable keep-alive
    pub keep_alive: Option<bool>,
    /// Maximum concurrent streams
    pub max_concurrent_streams: Option<u32>,
    /// Rate limit: bytes per second (0 = unlimited)
    pub rate_limit_bps: Option<u64>,
}

impl TransportOptions {
    /// Create new empty options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum packet size
    pub fn with_max_packet_size(mut self, size: usize) -> Self {
        self.max_packet_size = Some(size);
        self
    }

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, ms: u64) -> Self {
        self.connection_timeout_ms = Some(ms);
        self
    }

    /// Set keep-alive preference
    pub fn with_keep_alive(mut self, enabled: bool) -> Self {
        self.keep_alive = Some(enabled);
        self
    }

    /// Set maximum concurrent streams
    pub fn with_max_concurrent_streams(mut self, max: u32) -> Self {
        self.max_concurrent_streams = Some(max);
        self
    }

    /// Set rate limit in bytes per second
    pub fn with_rate_limit(mut self, bps: u64) -> Self {
        self.rate_limit_bps = Some(bps);
        self
    }
}
