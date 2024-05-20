pub mod error;

use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use strum::EnumIter;

use self::error::ConfigError;

const DEFAULT_TOR_ADDR: &str = "127.0.0.1:9050";

#[derive(Debug, Serialize, Deserialize, EnumIter)]
pub enum Mode {
    Standard,
    Safe,
    Clean,
}

impl Mode {
    pub fn ip_address(&self) -> &str {
        match self {
            Mode::Standard => "1.1.1.1",
            Mode::Safe => "1.1.1.2",
            Mode::Clean => "1.1.1.3",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub address: Option<String>,
}

impl TorConfig {
    pub fn get_address(&self) -> Result<SocketAddr, ConfigError> {
        let default_addr: SocketAddr = DEFAULT_TOR_ADDR.parse()?;

        let addr: SocketAddr = match &self.address {
            Some(addr_str) => addr_str.parse()?,
            None => default_addr,
        };

        Ok(addr)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub mode: Mode,
    pub address: SocketAddr,
    pub tor: TorConfig,
}

impl Default for SwiftConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
            address: "127.0.0.1:53".parse().unwrap(),
            tor: TorConfig {
                enabled: false,
                address: Some(DEFAULT_TOR_ADDR.to_string()),
            },
        }
    }
}

pub fn get_config() -> Result<SwiftConfig, ConfigError> {
    let config_path = config_location().join("config.toml");
    confy::load_path::<SwiftConfig>(config_path).map_err(ConfigError::from)
}

pub fn config_location() -> PathBuf {
    if cfg!(debug_assertions) {
        env::current_dir()
            .unwrap_or_else(|_| error!("Current directory inaccessible"))
            .join("assets/")
    } else {
        Path::new("/etc/swiftdns/").to_path_buf()
    }
}
