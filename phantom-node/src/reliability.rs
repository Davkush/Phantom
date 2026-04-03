use tokio::time::Duration;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct NodeHandle {
    pub is_running: Arc<Mutex<bool>>,
}

impl NodeHandle {
    pub async fn graceful_shutdown(&self) {
        let mut running = self.is_running.lock().await;
        *running = false;
        println!("NodeHandle: Shutdown signal sent.");
    }

    pub async fn restart(&self) {
        let mut running = self.is_running.lock().await;
        *running = true;
        println!("NodeHandle: Restart signal sent.");
    }
}

/// HIGH-01 Mitigation: Randomized uptime scheduling.
/// Decision: 2–6 Hours "Online" / 30–90 Minutes "Offline" to disrupt intersection attacks.
pub async fn run_churn_loop(node_handle: NodeHandle) {
    let mut rng = thread_rng();
    
    loop {
        // Online Phase: 2 - 6 hours
        let online_secs = rng.gen_range(7200..21600);
        println!("Churn: Online phase started ({} seconds).", online_secs);
        tokio::time::sleep(Duration::from_secs(online_secs)).await;
        
        println!("Churn: Going offline to disrupt intersection attacks...");
        node_handle.graceful_shutdown().await;

        // Offline Phase: 30 - 90 minutes
        let offline_secs = rng.gen_range(1800..5400);
        println!("Churn: Offline phase started ({} seconds).", offline_secs);
        tokio::time::sleep(Duration::from_secs(offline_secs)).await;

        println!("Churn: Rejoining network with fresh session...");
        node_handle.restart().await;
    }
}
