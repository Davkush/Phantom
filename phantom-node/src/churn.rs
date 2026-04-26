use std::sync::Arc;
use tokio::sync::Mutex;
use crate::proxy::socks5::StreamManager;
use tokio::time::{Duration, sleep};
use phantom_core::dht::UptimeSchedule;

/// Task 2.3: Formal Churn Manager.
/// This module handles the randomized session lifetimes and coordination of 
/// offline phases to protect against long-term statistical intersection attacks.
pub struct ChurnManager {
    schedule: UptimeSchedule,
    stream_manager: Arc<Mutex<StreamManager>>,
}

impl ChurnManager {
    pub fn new(seed: [u8; 32], base_uptime_hours: u32, stream_manager: Arc<Mutex<StreamManager>>) -> Self {
        let schedule = UptimeSchedule::generate_deterministic(seed, base_uptime_hours);
        Self {
            schedule,
            stream_manager,
        }
    }

    /// Primary loop governing the node session lifecycle.
    pub async fn run_session_loop(&self) {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;

            let is_online = self.schedule.is_online_at(now);

            if is_online {
                // Determine remaining uptime in current session
                let mut future = now;
                // Check in 1-hour increments for efficiency
                while self.schedule.is_online_at(future) {
                    future += 3600_000; 
                }
                let diff_ms = future.saturating_sub(now);
                println!("ChurnManager: Node is ONLINE. Session expires in {} minutes.", diff_ms / 60_000);
                sleep(Duration::from_millis(diff_ms)).await;
            } else {
                // Trigger graceful churn
                println!("ChurnManager: UptimeSchedule dictates OFFLINE phase. Initiating graceful churn...");
                self.drain_and_restart().await;
                break; 
            }
        }
    }

    /// Gracefully clears all active circuits and resets local state to prevent metadata leaking.
    async fn drain_and_restart(&self) {
        let mut manager = self.stream_manager.lock().await;
        println!("ChurnManager: Draining {} active streams to mask session transition.", manager.streams.len());
        manager.streams.clear();
        // Additional state cleanup could be added here
    }

    /// Returns the required sleep duration until the next valid online window.
    pub fn get_offline_duration(&self) -> Duration {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
            
        let mut future = now;
        while !self.schedule.is_online_at(future) {
            future += 3600_000;
        }
        Duration::from_millis(future.saturating_sub(now))
    }
}
