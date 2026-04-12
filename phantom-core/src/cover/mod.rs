pub mod poisson;

use poisson::PoissonTimer;

// Stubbed environment types for Phase 0 Loop tests
pub struct MockQueue;
impl MockQueue { pub fn try_pop(&self) -> Option<MockPacket> { None } }
pub struct MockPacket;
impl MockPacket { pub fn serialize(&self) -> Vec<u8> { vec![] } }
fn generate_dummy_sphinx() -> Vec<u8> { vec![0; 8192] }
pub struct MockTransport;
impl MockTransport { pub async fn send_obfuscated(&self, _packet: Vec<u8>) {} }

use crate::constants::{PACKET_SIZE, PAYLOAD_SIZE, KEM_BLOCK_SIZE, ROUTING_INFO_SIZE, MAC_SIZE, SIDECAR_SIZE, PROTOCOL_VERSION};
use rand::{Rng, RngCore};

pub async fn run_cover_loop(
    avg_interval: f64, 
    mut packet_rx: tokio::sync::mpsc::Receiver<crate::packet::SphinxPacket>, 
    transport: &crate::transport::quic::PhantomTransport,
    target_addr: std::net::SocketAddr,
    shaper: &crate::transport::obfuscation::TrafficShaper
) {
    let timer = PoissonTimer::new(avg_interval);
    let mut rng = rand::thread_rng();
    
    // Task 3.1: Multi-size standard distribution (2KB, 4KB, 9KB)
    let standard_sizes = vec![2048, 4096, PACKET_SIZE];

    loop {
        let delay = timer.next_delay();
        tokio::time::sleep(delay).await;

        use rand::seq::SliceRandom;
        let target_size = *standard_sizes.choose(&mut rng).unwrap();

        // Pull from the priority inbound queue or send decoy
        let mut packet = match packet_rx.try_recv() {
            Ok(p) => p,
            Err(_) => generate_dummy_sphinx_packet(),
        };

        // Ensure packet matches the randomized cover size
        // If it's a decoy, we might truncate it to target_size for obfuscation
        if packet.payload.len() > target_size {
             packet.payload.truncate(target_size.saturating_sub(PACKET_SIZE - PAYLOAD_SIZE));
        } else {
             packet.payload.resize(target_size.saturating_sub(PACKET_SIZE - PAYLOAD_SIZE), 0u8);
        }

        // Dispatch via QUIC with Traffic Shaping
        let _ = transport.send_packet(target_addr, packet, shaper).await;
    }
}

fn generate_dummy_sphinx_packet() -> crate::packet::SphinxPacket {
    let mut rng = rand::thread_rng();
    
    let mut current_kem = [0u8; KEM_BLOCK_SIZE];
    let mut beta_routing = [0u8; ROUTING_INFO_SIZE];
    let mut gamma_mac = [0u8; MAC_SIZE];
    let mut kem_sidecar = [0u8; SIDECAR_SIZE];
    let mut payload = vec![0u8; PAYLOAD_SIZE];

    rng.fill_bytes(&mut current_kem);
    rng.fill_bytes(&mut beta_routing);
    rng.fill_bytes(&mut gamma_mac);
    rng.fill_bytes(&mut kem_sidecar);
    rng.fill_bytes(&mut payload);

    crate::packet::SphinxPacket {
        version: PROTOCOL_VERSION,
        epoch: 0,
        current_kem,
        beta_routing,
        gamma_mac,
        kem_sidecar,
        payload, 
    }
}
