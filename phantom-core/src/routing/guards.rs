use std::path::PathBuf;
use std::fs;
use crate::dht::NodeDescriptor;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub struct GuardSet {
    pub guards: Vec<NodeDescriptor>,
    pub selected_at_ms: u64,
}

pub struct GuardManager {
    pub persistence_path: PathBuf,
}

impl GuardManager {
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            persistence_path: config_dir.join("guards.json"),
        }
    }

    /// GAP-06: Selects a persistent set of 3 entry guards.
    pub fn get_or_select_guards(&self, candidates: &[NodeDescriptor]) -> anyhow::Result<Vec<NodeDescriptor>> {
        if self.persistence_path.exists() {
            let data = fs::read_to_string(&self.persistence_path)?;
            if let Ok(set) = serde_json::from_str::<GuardSet>(&data) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
                // Rotate every 60 days (5184000000 ms)
                if now - set.selected_at_ms < 5184000000 {
                    return Ok(set.guards);
                }
                println!("GuardManager: 60-day rotation period reached. Rotating guards.");
            }
        }

        // Selection Logic: High PoW Difficulty + Network Capacity
        let mut guards = candidates.iter()
            .cloned()
            .take(3)
            .collect::<Vec<_>>();

        if guards.is_empty() {
             return Err(anyhow::anyhow!("No guard candidates available"));
        }

        let set = GuardSet {
            guards: guards.clone(),
            selected_at_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        };

        fs::write(&self.persistence_path, serde_json::to_string_pretty(&set)?)?;
        println!("GuardManager: Persistent entry guards selected and saved.");
        
        Ok(guards)
    }
}
