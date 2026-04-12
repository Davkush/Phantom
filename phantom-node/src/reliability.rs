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
pub async fn run_churn_loop(
    node_handle: NodeHandle,
    stream_manager: Arc<Mutex<crate::proxy::socks5::StreamManager>>,
) {
    let mut rng = thread_rng();
    
    loop {
        // Online Phase: 2 - 6 hours
        let online_secs = rng.gen_range(7200..21600);
        println!("Churn: Online phase started ({} seconds).", online_secs);
        tokio::time::sleep(Duration::from_secs(online_secs)).await;
        
        // Task 2.3: Coordination with StreamManager (Draining)
        println!("Churn: Online phase ended. Checking for active streams before shutdown...");
        let mut retry_count = 0;
        while retry_count < 12 { // Wait up to 60 seconds (12 * 5s)
            let sm = stream_manager.lock().await;
            if !sm.has_active_streams() {
                println!("Churn: No active streams. Proceeding to shutdown.");
                break;
            }
            drop(sm);
            println!("Churn: Active streams detected. Waiting 5s for drain (Attempt {}/12)...", retry_count + 1);
            tokio::time::sleep(Duration::from_secs(5)).await;
            retry_count += 1;
        }

        if retry_count == 12 {
            println!("Churn: Drain timeout reached. Forcing shutdown to maintain intersection resistance.");
        }
        
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
