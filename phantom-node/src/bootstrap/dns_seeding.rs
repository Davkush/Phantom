use trust_dns_resolver::TokioAsyncResolver;
use phantom_core::identity::NodeDescriptor;
use std::net::{SocketAddr};
use std::str::FromStr;

/// Phase 11: DNS Seeder Implementation
/// Bootstraps node discovery by querying TXT records from seed.phantom-protocol.net 
/// when no local peers or cached entries are available.
/// Addressing Technical Spec №3, Section 11.2 (DNS Seeding).
pub struct DnsBootstrap;

impl DnsBootstrap {
    /// Queries a list of DNS seeders to find initial network entry points.
    pub async fn query_seeders(domain: &str) -> Vec<NodeDescriptor> {
        println!("Bootstrap: Querying DNS seeder {} for TXT records...", domain);
        
        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => {
                println!("Bootstrap ERROR: DNS resolver init failed: {}", e);
                return Vec::new();
            }
        };

        let mut discovered = Vec::new();
        // TXT records contain <node_id>@<ip>:<port>
        if let Ok(lookup) = resolver.txt_lookup(domain).await {
            for record in lookup.iter() {
                for txt in record.txt_data() {
                    let s = String::from_utf8_lossy(txt);
                    if let Some(desc) = Self::parse_record(&s) {
                        discovered.push(desc);
                    }
                }
            }
        }
        
        if !discovered.is_empty() {
            println!("Bootstrap: Successfully discovered {} nodes via DNS seeding.", discovered.len());
        } else {
            println!("Bootstrap: DNS seeder {} returned no valid TXT records.", domain);
        }
        
        discovered
    }

    /// Parses a TXT record of format: <hex_pubkey>@<ip_addr>:<port>
    /// Example: 82a5...7bc@144.91.72.10:443
    fn parse_record(s: &str) -> Option<NodeDescriptor> {
        let parts: Vec<&str> = s.split('@').collect();
        if parts.len() != 2 { return None; }

        // 1. Decode Pubkey (Mocked for Phase 11, in production we base32 decode)
        let pubkey_bytes = [0u8; 32];
        
        // 2. Parse Address
        let addr = SocketAddr::from_str(parts[1]).ok()?;
        
        // 3. Construct Minimal Descriptor for initial contact
        // Full keys (Kyber/Dilithium) are pulled from the DHT once connected to the seed.
        Some(NodeDescriptor {
            node_id: [0u8; 32],
            pow_nonce: [0u8; 16],
            uptime_schedule: phantom_core::dht::UptimeSchedule::default(),
            ed25519_pubkey: pubkey_bytes,
            dilithium_pubkey: [0u8; 1312], 
            x25519_pubkey: [0u8; 32],
            kyber_pubkey: [0u8; 1568],
            quic_addr: addr,
            signature_ed25519: [0u8; 64],
            signature_dilithium: [0u8; 2420],
        })
    }
}
