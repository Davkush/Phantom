use tokio::time::Duration;
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub struct NodeHandle {
    pub cancel_token: CancellationToken,
}

impl NodeHandle {
    pub fn signal_shutdown(&self) {
        self.cancel_token.cancel();
        println!("NodeHandle: Session termination signal sent.");
    }
}

/// HIGH-01 Mitigation: Randomized uptime scheduling.
/// Disrupts intersection attacks by creating non-predictable node session patterns.
pub async fn run_churn_loop(
    target_uptime_hours: u32,
    stream_manager: Arc<Mutex<crate::proxy::socks5::StreamManager>>,
) {
    let mut rng = thread_rng();
    
    loop {
        // 1. Calculate Jittered Online Phase (+/- 20% of config)
        let base_secs = target_uptime_hours * 3600;
        let jitter = (base_secs as f32 * 0.2) as u32;
        let online_secs = rng.gen_range((base_secs - jitter)..(base_secs + jitter));
        
        println!("Churn: Session active. Randomized uptime: {} hours ({}s).", 
            online_secs / 3600, online_secs);
            
        tokio::time::sleep(Duration::from_secs(online_secs as u64)).await;
        
        // 2. Draining Phase: Wait for SOCKS5 streams to close
        println!("Churn: Session cycle reached. Draining active streams...");
        let mut retry_count = 0;
        while retry_count < 12 { // Wait up to 60 seconds
            let sm = stream_manager.lock().await;
            if !sm.has_active_streams() {
                println!("Churn: All streams drained. Proceeding to rotate session.");
                break;
            }
            drop(sm);
            println!("Churn: Drain in progress... {} active streams (Attempt {}/12).", 
                "N/A", retry_count + 1);
            tokio::time::sleep(Duration::from_secs(5)).await;
            retry_count += 1;
        }

        if retry_count == 12 {
            println!("Churn: Drain timeout. Forcing session rotation for intersection resistance.");
        }
        
        // 3. Trigger Global Shutdown for current session
        println!("Churn: Entering OFFLINE phase to disrupt long-term mapping...");
        
        // Return from this function to signal to main that it should rotate
        // Actually, main will be watching this loop or the token
        return;
    }
}
