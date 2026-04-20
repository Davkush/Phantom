use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use rand::Rng;
use crate::hybrid_kem::PublicKey;
use crate::identity::NodeId;

/// Task 3.3: Reciprocal Routing Incentives
///
/// Implements the "proof-of-routing" requirement: nodes MUST route traffic for
/// others before they can send their own traffic. Prevents free-riding attacks.
///
/// Per roadmap Task 3.3:
/// - Track inbound/outbound bytes per node
/// - Minimum routing ratio before sending
/// - Sliding window for fair reciprocity
#[derive(Debug, Clone)]
pub struct RoutingStats {
    /// Total bytes sent for others this epoch
    pub outbound_bytes: u64,
    /// Total bytes received for processing this epoch
    pub inbound_bytes: u64,
    /// Number of packets routed
    pub packets_routed: u64,
    /// Last update timestamp
    pub last_update: std::time::Instant,
}

impl Default for RoutingStats {
    fn default() -> Self {
        Self {
            outbound_bytes: 0,
            inbound_bytes: 0,
            packets_routed: 0,
            last_update: std::time::Instant::now(),
        }
    }
}

impl RoutingStats {
    /// Record outbound traffic
    pub fn record_outbound(&mut self, bytes: u64) {
        self.outbound_bytes += bytes;
        self.last_update = std::time::Instant::now();
    }

    /// Record inbound traffic
    pub fn record_inbound(&mut self, bytes: u64) {
        self.inbound_bytes += bytes;
        self.last_update = std::time::Instant::now();
    }
}

/// Routing incentive configuration
pub struct IncentiveConfig {
    /// Minimum inbound/outbound ratio required (default: 0.8 = 80%)
    pub min_routing_ratio: f64,
    /// Minimum bytes to route before sending (default: 1MB)
    pub min_bytes_before_send: u64,
    /// Sliding window duration in seconds (default: 3600 = 1 epoch)
    pub window_secs: u64,
    /// Enable strict reciprocity enforcement
    pub strict_mode: bool,
}

impl Default for IncentiveConfig {
    fn default() -> Self {
        Self {
            min_routing_ratio: 0.8,
            min_bytes_before_send: 1_048_576, // 1 MB
            window_secs: 3600,                  // 1 epoch
            strict_mode: false,                // Lenient by default
        }
    }
}

/// Reciprocal routing incentive tracker.
///
/// Tracks each node's contribution to the network and enforces minimum
/// routing requirements before allowing outbound traffic.
pub struct RoutingIncentives {
    /// Per-node routing statistics
    node_stats: RwLock<HashMap<PublicKey, RoutingStats>>,
    /// Configuration
    config: IncentiveConfig,
    /// Own node's public key (for self-referential checks)
    own_public_key: PublicKey,
}

impl RoutingIncentives {
    /// Create a new incentive tracker.
    pub fn new(own_public_key: PublicKey) -> Self {
        Self {
            node_stats: RwLock::new(HashMap::new()),
            config: IncentiveConfig::default(),
            own_public_key,
        }
    }

    /// Create with custom configuration.
    pub fn with_config(own_public_key: PublicKey, config: IncentiveConfig) -> Self {
        Self {
            node_stats: RwLock::new(HashMap::new()),
            config,
            own_public_key,
        }
    }

    /// Record outbound traffic for a specific node.
    pub async fn record_outbound(&self, node_key: &PublicKey, bytes: u64) {
        let mut stats = self.node_stats.write().await;
        let node_stats = stats.entry(node_key.clone()).or_default();
        node_stats.record_outbound(bytes);
    }

    /// Record inbound traffic for a specific node.
    pub async fn record_inbound(&self, node_key: &PublicKey, bytes: u64) {
        let mut stats = self.node_stats.write().await;
        let node_stats = stats.entry(node_key.clone()).or_default();
        node_stats.record_inbound(bytes);
    }

    /// Check if a node has met the routing requirements.
    ///
    /// Returns Ok(()) if the node can send traffic.
    /// Returns Err with reason if the node must route more first.
    pub async fn check_routing_permission(&self, node_key: &PublicKey) -> Result<(), RoutingDenied> {
        let stats = self.node_stats.read().await;
        let node_stats = stats.get(node_key).ok_or_else(|| RoutingDenied::NoHistory)?;

        // Check minimum bytes requirement
        if node_stats.outbound_bytes < self.config.min_bytes_before_send {
            return Err(RoutingDenied::InsufficientRouting {
                required: self.config.min_bytes_before_send,
                actual: node_stats.outbound_bytes,
            });
        }

        // Calculate and check routing ratio
        if node_stats.inbound_bytes > 0 {
            let ratio = node_stats.outbound_bytes as f64 / node_stats.inbound_bytes as f64;
            if ratio < self.config.min_routing_ratio {
                if self.config.strict_mode {
                    return Err(RoutingDenied::LowRoutingRatio {
                        required: self.config.min_routing_ratio,
                        actual: ratio,
                    });
                }
            }
        }

        Ok(())
    }

    /// Get the current routing ratio for a node.
    pub async fn get_routing_ratio(&self, node_key: &PublicKey) -> f64 {
        let stats = self.node_stats.read().await;
        match stats.get(node_key) {
            Some(s) if s.inbound_bytes > 0 => s.outbound_bytes as f64 / s.inbound_bytes as f64,
            _ => 0.0,
        }
    }

    /// Get routing statistics for a node.
    pub async fn get_stats(&self, node_key: &PublicKey) -> Option<RoutingStats> {
        let stats = self.node_stats.read().await;
        stats.get(node_key).cloned()
    }

    /// Reset statistics for all nodes (typically at epoch boundary).
    pub async fn reset_all_stats(&self) {
        let mut stats = self.node_stats.write().await;
        stats.clear();
    }

    /// Set new configuration.
    pub fn set_config(&mut self, config: IncentiveConfig) {
        self.config = config;
    }
}

/// Reason for routing permission denial.
#[derive(Debug, Clone)]
pub enum RoutingDenied {
    /// Node has no routing history
    NoHistory,
    /// Node hasn't routed enough bytes
    InsufficientRouting { required: u64, actual: u64 },
    /// Node's routing ratio is too low
    LowRoutingRatio { required: f64, actual: f64 },
}

impl std::fmt::Display for RoutingDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHistory => write!(f, "No routing history - must route traffic first"),
            Self::InsufficientRouting { required, actual } => {
                write!(f, "Insufficient routing: need {} bytes, have {} bytes", required, actual)
            }
            Self::LowRoutingRatio { required, actual } => {
                write!(f, "Low routing ratio: need {:.2}, have {:.2}", required, actual)
            }
        }
    }
}

impl std::error::Error for RoutingDenied {}

/// Route selector that integrates incentive checking.
///
/// Routes packets through nodes that have met their routing requirements.
pub struct IncentiveAwareRouter {
    incentives: Arc<RoutingIncentives>,
    /// Fallback nodes (Bootstrap nodes, pre-certified nodes)
    fallback_nodes: RwLock<Vec<PublicKey>>,
    /// Minimum number of viable routes to have before selecting
    min_viable_routes: usize,
}

impl IncentiveAwareRouter {
    /// Create a new incentive-aware router.
    pub fn new(own_key: PublicKey) -> Self {
        Self {
            incentives: Arc::new(RoutingIncentives::new(own_key)),
            fallback_nodes: RwLock::new(Vec::new()),
            min_viable_routes: 3,
        }
    }

    /// Add a fallback node (bootstrap node).
    pub async fn add_fallback_node(&self, node_key: PublicKey) {
        let mut fallback = self.fallback_nodes.write().await;
        if !fallback.contains(&node_key) {
            fallback.push(node_key);
        }
    }

    /// Select a route path that satisfies incentive requirements.
    ///
    /// Returns a vector of viable public keys for routing, or an error if
    /// there aren't enough viable nodes.
    pub async fn select_route(
        &self,
        available_nodes: &[PublicKey],
        path_length: usize,
    ) -> Result<Vec<PublicKey>, RouteSelectionError> {
        let mut rng = rand::thread_rng();

        // Filter nodes that have routing permission
        let mut viable: Vec<PublicKey> = Vec::new();
        for node in available_nodes {
            if self.incentives.check_routing_permission(node).await.is_ok() {
                viable.push(node.clone());
            }
        }

        // If not enough viable nodes, add fallbacks
        if viable.len() < self.min_viable_routes {
            let fallback = self.fallback_nodes.read().await;
            for node in fallback.iter().take(self.min_viable_routes - viable.len()) {
                if !viable.contains(node) {
                    viable.push(node.clone());
                }
            }
        }

        if viable.len() < path_length {
            return Err(RouteSelectionError::InsufficientViableNodes {
                required: path_length,
                available: viable.len(),
            });
        }

        // Shuffle and select path_length nodes
        use rand::seq::SliceRandom;
        let mut shuffled = viable;
        shuffled.shuffle(&mut rng);
        Ok(shuffled.into_iter().take(path_length).collect())
    }

    /// Get reference to the incentive tracker.
    pub fn incentives(&self) -> Arc<RoutingIncentives> {
        self.incentives.clone()
    }
}

/// Error during route selection.
#[derive(Debug, Clone)]
pub enum RouteSelectionError {
    /// Not enough viable nodes meeting routing requirements
    InsufficientViableNodes { required: usize, available: usize },
    /// No nodes available at all
    NoNodesAvailable,
}

impl std::fmt::Display for RouteSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientViableNodes { required, available } => {
                write!(f, "Need {} nodes, only {} are viable", required, available)
            }
            Self::NoNodesAvailable => write!(f, "No nodes available for routing"),
        }
    }
}

impl std::error::Error for RouteSelectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_routing_permission_new_node() {
        let key = PublicKey::random();
        let incentives = RoutingIncentives::new(key.clone());

        // New node should be denied
        let result = incentives.check_routing_permission(&key).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_routing_permission_after_routing() {
        let key = PublicKey::random();
        let mut incentives = RoutingIncentives::new(key.clone());

        // Lower the threshold for testing
        incentives.set_config(IncentiveConfig {
            min_bytes_before_send: 1000,
            ..Default::default()
        });

        // Record some outbound traffic
        incentives.record_outbound(&key, 2000).await;
        incentives.record_inbound(&key, 1000).await;

        // Now should be allowed
        let result = incentives.check_routing_permission(&key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_routing_ratio_enforcement() {
        let key = PublicKey::random();
        let mut incentives = RoutingIncentives::new(key.clone());

        // Set strict ratio requirement
        incentives.set_config(IncentiveConfig {
            min_routing_ratio: 0.8,
            min_bytes_before_send: 100,
            strict_mode: true,
            ..Default::default()
        });

        // Record high inbound, low outbound (ratio 0.1)
        incentives.record_inbound(&key, 10000).await;
        incentives.record_outbound(&key, 1000).await;

        // Should be denied due to low ratio
        let result = incentives.check_routing_permission(&key).await;
        assert!(result.is_err());
    }
}
