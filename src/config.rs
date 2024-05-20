use std::{
    env,
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

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

impl TryFrom<&str> for Mode {
    type Error = String;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        Mode::iter()
            .find(|mode| mode.ip_address() == input)
            .ok_or_else(|| format!("Invalid mode `{}`", input))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub address: Option<String>,
}

impl TorConfig {
    pub fn get_address(&self) -> String {
        self.address.clone().unwrap_or(DEFAULT_TOR_ADDR.to_string())
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

pub fn get_config() -> Result<SwiftConfig, Box<dyn Error>> {
    let config_path = config_location().join("config.toml");
    let config: SwiftConfig = confy::load_path(config_path)?;

    Ok(config)
}

pub fn config_location() -> PathBuf {
    if cfg!(debug_assertions) {
        return env::current_dir()
            .expect("Directory should exist")
            .join("assets/");
    }

    Path::new("/etc/swiftdns/").to_path_buf()
}
