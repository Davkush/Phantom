use crate::packet::{SphinxPacket, RoutingInfoBlock};
use crate::hybrid_kem::HybridKeyPair;
use crate::replay_cache::ReplayCache;

pub struct MixNode {
    pub keypair: HybridKeyPair,
    pub node_id: [u8; 32],
    pub replay_cache: ReplayCache,
}

impl MixNode {
    pub fn new(keypair: HybridKeyPair, node_id: [u8; 32], cache_size: usize, fp_rate: f64) -> Self {
        Self {
            keypair,
            node_id,
            replay_cache: ReplayCache::new(cache_size, fp_rate),
        }
    }

    /// Processes an incoming SphinxPacket, verifying its MAC, updating its internal state for the next hop,
    /// and returning the routing instruction block (which contains the next hop action, c_batch, etc).
    pub fn process_packet(&mut self, mut pkt: SphinxPacket) -> Result<(SphinxPacket, RoutingInfoBlock), &'static str> {
        let routing_info = crate::processor::process_packet(&self.keypair, &mut pkt, &mut self.replay_cache)?;
        Ok((pkt, routing_info))
    }
}
