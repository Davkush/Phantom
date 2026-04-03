use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::{SocketAddr, Ipv4Addr};
use phantom_core::packet::SphinxPacket;

pub struct Socks5Entry {
    pub listen_addr: SocketAddr,
    pub mix_tx: tokio::sync::mpsc::Sender<SphinxPacket>,
}

impl Socks5Entry {
    pub async fn run_loop(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        println!("SOCKS5 Proxy active on {}", self.listen_addr);

        loop {
            let (mut stream, _) = listener.accept().await?;
            let tx = self.mix_tx.clone();
            
            tokio::spawn(async move {
                // 1. Handle SOCKS5 Handshake (Version 5, No Auth)
                if let Ok(target) = handle_socks5_handshake(&mut stream).await {
                    println!("SOCKS5: CONNECT request to {:?}", target);
                    // 2. Initiate Sphinx Circuit for this stream and pipe data
                    let _ = pipe_stream_to_mixnet(stream, target, tx).await;
                }
            });
        }
    }
}

async fn handle_socks5_handshake(stream: &mut TcpStream) -> anyhow::Result<String> {
    let mut buf = [0u8; 3];
    stream.read_exact(&mut buf).await?;

    if buf[0] != 0x05 { return Err(anyhow::anyhow!("Invalid SOCKS version")); }
    
    // Send NO AUTH response
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    if header[1] != 0x01 { return Err(anyhow::anyhow!("Only CONNECT supported")); }

    let target = match header[3] {
        0x01 => { // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", Ipv4Addr::from(addr), u16::from_be_bytes(port))
        }
        0x03 => { // Domain name
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await?;
            format!("{}:{}", String::from_utf8_lossy(&domain), u16::from_be_bytes(port))
        }
        _ => return Err(anyhow::anyhow!("Address type not supported")),
    };

    // Send Success response
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    Ok(target)
}

async fn pipe_stream_to_mixnet(
    mut stream: TcpStream, 
    _target: String, 
    tx: tokio::sync::mpsc::Sender<SphinxPacket>
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 8192]; // Leave room for Sphinx headers in 9KB
    
    while let Ok(n) = stream.read(&mut buf).await {
        if n == 0 { break; }
        
        // Phase 5 Placeholder: Wrap TCP chunk in a Sphinx Packet
        // In a real impl, this would resolve 'target' to a DHT NodeDescriptor 
        // and build a full path.
        println!("SOCKS5: Tunneling {} bytes to mixnet...", n);
        
        // This is a dummy packet reflecting the 9KB requirement
        let dummy_pkt = SphinxPacket {
            version: 1,
            flags: 0,
            epoch: 0,
            alpha_cl: [0u8; 32],
            alpha_pq_onion: vec![0u8; 1568 * 5],
            beta_routing: [0u8; 128],
            gamma_mac: [0u8; 32],
            c_batch: [0u8; 16],
            pi_ref: 0,
            payload: buf[..n].to_vec(),
        };
        
        tx.send(dummy_pkt).await?;
    }
    
    Ok(())
}
