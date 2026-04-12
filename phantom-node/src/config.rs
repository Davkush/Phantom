use serde::{Deserialize, Serialize};
use config::{Config, ConfigError, File, Environment};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct PhantomConfig {
    pub port: u16,
    pub socks_port: u16,
    pub config_dir: String,
    pub bootstrap_addr: Option<String>,
    pub adversarial_mode: bool,
    pub variable_uptime_hours: u32,
}

impl PhantomConfig {
    pub fn build(config_dir: &str) -> Result<Self, ConfigError> {
        let mut s = Config::builder();

        // 1. Hardcoded Defaults
        s = s.set_default("port", 443)?
             .set_default("socks_port", 9050)?
             .set_default("config_dir", config_dir)?
             .set_default("adversarial_mode", false)?
             .set_default("variable_uptime_hours", 12)?;

        // 2. Local Config File (phantom.toml) - High Precedence
        let config_file = format!("{}/phantom.toml", config_dir);
        s = s.add_source(File::with_name(&config_file).required(false));

        // 3. Environment Variables (PHANTOM_*) - Highest Precedence
        s = s.add_source(Environment::with_prefix("PHANTOM"));

        let cfg: PhantomConfig = s.build()?.try_deserialize()?;
        Ok(cfg)
    }
}
