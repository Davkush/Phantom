use crate::dht::NodeDescriptor;
use rand::seq::SliceRandom;
use std::net::IpAddr;

pub struct PathSelector;

impl PathSelector {
    /// GAP-06: Builds a 3-hop circuit following Guard -> Middle -> Exit topology.
    pub fn select_circuit(
        guards: &[NodeDescriptor],
        middle_candidates: &[NodeDescriptor],
        exit_candidates: &[NodeDescriptor]
    ) -> anyhow::Result<Vec<NodeDescriptor>> {
        let mut rng = rand::thread_rng();
        
        // 1. Pick a random guard from the persistent set
        let guard = guards.choose(&mut rng)
            .ok_or_else(|| anyhow::anyhow!("No guards available"))?;
            
        // 2. Pick a random middle relay with IP diversity
        let middle = middle_candidates.iter()
            .filter(|n| !Self::is_same_subnet(n.quic_addr.ip(), guard.quic_addr.ip()))
            .collect::<Vec<_>>()
            .choose(&mut rng)
            .ok_or_else(|| anyhow::anyhow!("No suitable middle relay found (IP diversity failed)"))?;
            
        // 3. Pick a random exit node with IP diversity
        let exit = exit_candidates.iter()
            .filter(|n| !Self::is_same_subnet(n.quic_addr.ip(), guard.quic_addr.ip()) && 
                        !Self::is_same_subnet(n.quic_addr.ip(), (**middle).quic_addr.ip()))
            .collect::<Vec<_>>()
            .choose(&mut rng)
            .ok_or_else(|| anyhow::anyhow!("No suitable exit node found (IP diversity failed)"))?;
            
        Ok(vec![guard.clone(), (*middle).clone(), (*exit).clone()])
    }

    /// Helper to prevent selection of nodes in the same /16 subnet (Sybil mitigation)
    fn is_same_subnet(a: IpAddr, b: IpAddr) -> bool {
        match (a, b) {
            (IpAddr::V4(a_v4), IpAddr::V4(b_v4)) => {
                let octets_a = a_v4.octets();
                let octets_b = b_v4.octets();
                octets_a[0] == octets_b[0] && octets_a[1] == octets_b[1]
            }
            _ => false, // IPv6 diversity logic could be added here
        }
    }
}
