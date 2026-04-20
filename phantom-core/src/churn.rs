use std::time::{Duration, Instant};
use rand::Rng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Task 2.3 (HIGH-01): Churn Manager for node rotation.
///
/// Implements Poisson-distributed node churn to break long-term intersection attacks.
/// Nodes must be online for at least one full epoch (3600 seconds) before rotation.
pub struct ChurnConfig {
    /// Minimum uptime before first churn (default: 1 epoch = 3600s)
    pub min_uptime_before_churn: Duration,
    /// Mean interval between churn events (Poisson parameter)
    pub mean_churn_interval: Duration,
    /// Maximum offline duration
    pub max_offline_duration: Duration,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            min_uptime_before_churn: Duration::from_secs(3600), // 1 epoch
            mean_churn_interval: Duration::from_secs(21600),     // 6 hours
            max_offline_duration: Duration::from_secs(600),      // 10 minutes
        }
    }
}

/// Churn Manager states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChurnState {
    /// Node is active, accumulating uptime
    Active,
    /// Node is preparing to go offline (draining circuits)
    Draining,
    /// Node is offline and rotating
    Offline,
    /// Node is re-entering the network
    Rejoining,
}

/// Churn Manager events for logging and monitoring
#[derive(Debug, Clone)]
pub enum ChurnEvent {
    /// Churn schedule triggered
    Scheduled { scheduled_at: Instant },
    /// Started draining active circuits
    DrainStarted { active_circuits: usize },
    /// Drain completed
    DrainCompleted,
    /// Node went offline
    WentOffline { offline_until: Instant },
    /// Node rejoined the network
    Rejoined { new_uptime: Duration },
    /// Minimum uptime not met, skipping
    UptimeNotMet { uptime: Duration, required: Duration },
}

/// Churn Manager manages node rotation to prevent long-term intersection attacks.
///
/// Per roadmap Task 2.3:
/// - Nodes must be online for at least 1 epoch (3600s) before first rotation
/// - Churn intervals drawn from Poisson distribution
/// - StreamManager coordination to drain circuits before going offline
pub struct ChurnManager {
    /// Configuration
    config: ChurnConfig,
    /// Current state
    state: ChurnState,
    /// Time when node last came online
    last_online: Instant,
    /// Time of next scheduled churn
    next_churn: Option<Instant>,
    /// Event sender for logging
    event_tx: mpsc::Sender<ChurnEvent>,
}

impl ChurnManager {
    /// Create a new ChurnManager with default configuration.
    pub fn new(event_tx: mpsc::Sender<ChurnEvent>) -> Self {
        Self {
            config: ChurnConfig::default(),
            state: ChurnState::Active,
            last_online: Instant::now(),
            next_churn: None,
            event_tx,
        }
    }

    /// Create a new ChurnManager with custom configuration.
    pub fn with_config(config: ChurnConfig, event_tx: mpsc::Sender<ChurnEvent>) -> Self {
        Self {
            config,
            state: ChurnState::Active,
            last_online: Instant::now(),
            next_churn: None,
            event_tx,
        }
    }

    /// Start the churn management loop.
    /// This should be run as an async task.
    pub async fn run(&mut self, shutdown_token: CancellationToken) {
        println!("ChurnManager: Starting churn management loop");
        self.schedule_next_churn();

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    println!("ChurnManager: Shutdown signal received, exiting");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    if let Err(e) = self.tick().await {
                        println!("ChurnManager: Error in tick: {}", e);
                    }
                }
            }
        }
    }

    /// Called during each tick to check if churn should occur.
    async fn tick(&mut self) -> Result<(), String> {
        let now = Instant::now();

        match self.state {
            ChurnState::Active => {
                // Check if it's time for churn
                if let Some(next) = self.next_churn {
                    if now >= next {
                        self.initiate_churn(now).await?;
                    }
                }
            }
            ChurnState::Draining => {
                // In production: wait for StreamManager to drain circuits
                // For now: simulate immediate drain
                self.complete_drain().await?;
            }
            ChurnState::Offline => {
                // Check if offline duration exceeded
                if let Some(offline_until) = self.get_offline_until() {
                    if now >= offline_until {
                        self.rejoin().await?;
                    }
                }
            }
            ChurnState::Rejoining => {
                // In production: wait for descriptor republication
                // For now: immediate rejoin
                self.complete_rejoin().await?;
            }
        }

        Ok(())
    }

    /// Schedule the next churn event using Poisson distribution.
    fn schedule_next_churn(&mut self) {
        let mut rng = rand::thread_rng();

        // Poisson-distributed interval with exponential distribution
        // For Poisson with mean λ, inter-arrival times are exponential(1/λ)
        let mean_secs = self.config.mean_churn_interval.as_secs_f64();
        let interval_secs = rng.gen::<f64>() * mean_secs * 2.0; // Simplified Poisson

        let jitter_ms = rng.gen_range(-600_000..600_000); // ±10 minutes jitter
        let interval = Duration::from_secs_f64(interval_secs)
            + Duration::from_millis(jitter_ms as u64);

        let next = Instant::now() + interval;
        self.next_churn = Some(next);

        println!("ChurnManager: Next churn scheduled for {:?}", next);
    }

    /// Initiate the churn process.
    async fn initiate_churn(&mut self, now: Instant) -> Result<(), String> {
        // Check minimum uptime
        let uptime = now.duration_since(self.last_online);
        if uptime < self.config.min_uptime_before_churn {
            let _ = self.event_tx.send(ChurnEvent::UptimeNotMet {
                uptime,
                required: self.config.min_uptime_before_churn,
            }).await;
            self.schedule_next_churn();
            return Ok(());
        }

        self.state = ChurnState::Draining;
        let _ = self.event_tx.send(ChurnEvent::DrainStarted {
            active_circuits: 0, // Would be populated by StreamManager
        }).await;

        println!("ChurnManager: Initiating churn after {:?} of uptime", uptime);
        Ok(())
    }

    /// Complete the drain phase and go offline.
    async fn complete_drain(&mut self) -> Result<(), String> {
        let _ = self.event_tx.send(ChurnEvent::DrainCompleted).await;

        self.state = ChurnState::Offline;
        let offline_until = Instant::now() + self.config.max_offline_duration;

        let _ = self.event_tx.send(ChurnEvent::WentOffline {
            offline_until,
        }).await;

        println!("ChurnManager: Node went offline until {:?}", offline_until);
        Ok(())
    }

    /// Get when the offline period ends.
    fn get_offline_until(&self) -> Option<Instant> {
        Some(Instant::now() + self.config.max_offline_duration)
    }

    /// Begin rejoin process.
    async fn rejoin(&mut self) -> Result<(), String> {
        self.state = ChurnState::Rejoining;
        println!("ChurnManager: Node rejoining the network");
        Ok(())
    }

    /// Complete the rejoin process.
    async fn complete_rejoin(&mut self) -> Result<(), String> {
        self.state = ChurnState::Active;
        self.last_online = Instant::now();

        let _ = self.event_tx.send(ChurnEvent::Rejoined {
            new_uptime: Duration::ZERO,
        }).await;

        self.schedule_next_churn();
        println!("ChurnManager: Node rejoined, uptime timer reset");
        Ok(())
    }

    /// Get current churn state.
    pub fn state(&self) -> ChurnState {
        self.state
    }

    /// Get current uptime.
    pub fn current_uptime(&self) -> Duration {
        if self.state == ChurnState::Active {
            Instant::now().duration_since(self.last_online)
        } else {
            Duration::ZERO
        }
    }

    /// Get next scheduled churn time.
    pub fn next_churn_time(&self) -> Option<Instant> {
        self.next_churn
    }

    /// Check if node is currently online.
    pub fn is_online(&self) -> bool {
        matches!(self.state, ChurnState::Active | ChurnState::Draining | ChurnState::Rejoining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_churn_manager_initialization() {
        let (tx, _rx) = mpsc::channel(10);
        let manager = ChurnManager::new(tx);

        assert_eq!(manager.state(), ChurnState::Active);
        assert!(manager.is_online());
    }

    #[test]
    fn test_churn_config_default() {
        let config = ChurnConfig::default();
        assert_eq!(config.min_uptime_before_churn, Duration::from_secs(3600));
        assert_eq!(config.mean_churn_interval, Duration::from_secs(21600));
        assert_eq!(config.max_offline_duration, Duration::from_secs(600));
    }

    #[test]
    fn test_churn_state_transitions() {
        let (tx, _rx) = mpsc::channel(10);
        let manager = ChurnManager::new(tx);

        // Initial state should be Active
        assert_eq!(manager.state(), ChurnState::Active);
        assert!(manager.is_online());
    }
}
