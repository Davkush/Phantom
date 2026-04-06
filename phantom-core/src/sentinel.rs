use std::process::{Child, Command, Stdio};
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Sentinel {
    nodes: Arc<Mutex<Vec<Child>>>,
    base_dir: PathBuf,
}

impl Sentinel {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            nodes: Arc::new(Mutex::new(Vec::new())),
            base_dir,
        }
    }

    /// Spawns a new Phantom Node as a separate OS process.
    /// Addressing Phase 5: Process-based isolation and socket-level realism.
    pub fn spawn_node(&self, port: u16, node_name: &str) -> anyhow::Result<()> {
        let node_dir = self.base_dir.join(node_name);
        std::fs::create_dir_all(&node_dir)?;

        let log_path = node_dir.join(format!("node_{}.log", port));
        let log_file = File::create(log_path)?;

        // Assuming phantom-node binary is in the path or target/debug
        // In a real testnet_sim, we'd use the canonical path to the built binary.
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("phantom-node")
            .arg("--")
            .arg("--port")
            .arg(port.to_string())
            .arg("--config-dir")
            .arg(node_dir.to_str().unwrap())
            .stdout(Stdio::from(log_file.try_clone()?))
            .stderr(Stdio::from(log_file))
            .spawn()?;

        let nodes = self.nodes.clone();
        tokio::spawn(async move {
            let mut nodes = nodes.lock().await;
            nodes.push(child);
        });

        Ok(())
    }

    /// Bootstraps a local testnet with N nodes.
    pub async fn bootstrap_local_testnet(&self, node_count: usize) -> anyhow::Result<()> {
        println!("🚀 Sentinel: Bootstrapping local testnet ({} nodes)...", node_count);
        for i in 0..node_count {
            let port = 4443 + i as u16;
            let node_name = format!("node_{}", i);
            self.spawn_node(port, &node_name)?;
            println!("   - Spawned {} on port {}", node_name, port);
        }
        Ok(())
    }

    /// Gracefully terminates all managed nodes.
    pub async fn kill_all(&self) {
        let mut nodes = self.nodes.lock().await;
        for mut child in nodes.drain(..) {
            let _ = child.kill();
        }
    }
}
