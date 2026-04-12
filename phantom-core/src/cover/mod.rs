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
    let standard_sizes = vec![2048, 4096, 9216];

    loop {
        let delay = timer.next_delay();
        tokio::time::sleep(delay).await;

        use rand::seq::SliceRandom;
        let target_size = *standard_sizes.choose(&mut rng).unwrap();

        // Pull from the priority inbound queue or send decoy
        let mut packet = match packet_rx.try_recv() {
            Ok(p) => p,
            Err(_) => generate_dummy_sphinx_packet(target_size),
        };

        // Ensure packet matches the randomized cover size
        if packet.payload.len() < target_size {
            packet.payload.resize(target_size, 0u8);
        }

        // Dispatch via QUIC with Traffic Shaping
        let _ = transport.send_packet(target_addr, packet, shaper).await;
    }
}

fn generate_dummy_sphinx_packet(size: usize) -> crate::packet::SphinxPacket {
    crate::packet::SphinxPacket {
        version: 1,
        flags: 0x01, // Drop flag
        epoch: 0,
        alpha_cl: [0u8; 32],
        alpha_pq_onion: vec![0u8; crate::packet::MAX_HOPS * crate::packet::KYBER_CT_SIZE],
        beta_routing: [0u8; 128],
        gamma_mac: [0u8; 32],
        c_batch: [0u8; 16],
        pi_ref: 0,
        payload: vec![0u8; size], 
    }
}
