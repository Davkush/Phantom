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
        
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;
        let future_ms = now_ms + (10 * 60 * 1000); // Require at least 10 minutes of guaranteed uptime

        // 1. Pick a random guard from the persistent set
        let active_guards: Vec<_> = guards.iter()
            .filter(|n| n.uptime_schedule.is_online_at(now_ms) && n.uptime_schedule.is_online_at(future_ms))
            .collect();
            
        let guard = active_guards.choose(&mut rng)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No active guards available matching uptime schedule"))?;
            
        // 2. Pick a random middle relay with IP diversity and Uptime criteria
        let active_middles: Vec<_> = middle_candidates.iter()
            .filter(|n| n.uptime_schedule.is_online_at(now_ms) && n.uptime_schedule.is_online_at(future_ms))
            .filter(|n| !Self::is_same_subnet(n.quic_addr.ip(), guard.quic_addr.ip()))
            .collect();
            
        let middle = active_middles.choose(&mut rng)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No suitable middle relay found (IP diversity or uptime failed)"))?;
            
        // 3. Pick a random exit node with IP diversity and Uptime criteria
        let active_exits: Vec<_> = exit_candidates.iter()
            .filter(|n| n.uptime_schedule.is_online_at(now_ms) && n.uptime_schedule.is_online_at(future_ms))
            .filter(|n| !Self::is_same_subnet(n.quic_addr.ip(), guard.quic_addr.ip()) && 
                        !Self::is_same_subnet(n.quic_addr.ip(), middle.quic_addr.ip()))
            .collect();
            
        let exit = active_exits.choose(&mut rng)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("No suitable exit node found (IP diversity or uptime failed)"))?;
            
        Ok(vec![(*guard).clone(), (*middle).clone(), (*exit).clone()])
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
