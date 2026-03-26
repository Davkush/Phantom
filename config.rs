use serde::{Serialize, Deserialize};

/// Configuration for network bootstrapping.
#[derive(Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Addressing LOW-02: Make mDNS bootstrap opt-in via config flag.
    /// This defaults to false to prevent local network presence leakage.
    pub enable_mdns: bool,
    
    /// Optional explicitly defined bootstrap node addresses.
    pub explicit_nodes: Vec<String>,
    
    /// Phase 2 HIGH-01: Variable node uptime patterns to thwart long-term intersection attacks.
    /// Define an interval in hours before the node intentionally cycles downtime.
    pub variable_uptime_hours: u32,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            enable_mdns: false, // LOW-02 enforcement
            explicit_nodes: Vec::new(),
            variable_uptime_hours: 12, // Default to a 12 hour cycle phase
        }
    }
}
