pub mod error;

use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
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
pub struct SwiftConfigV1 {
    pub mode: Mode,
    pub address: SocketAddr,
    pub tor: bool,
}

impl Default for SwiftConfigV1 {
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
            address: "127.0.0.1:53".parse().unwrap(),
            tor: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub version: u8,
    pub mode: Mode,
    pub scope: Option<Scope>,
    pub address: SocketAddr,
    pub log_queries: Option<bool>,
    pub tor: TorConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Scope {
    Global,
    Local,
}

impl FromStr for Scope {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "global" => Ok(Scope::Global),
            "local" => Ok(Scope::Local),
            _ => Err(ConfigError::InvalidScope(s.to_string())),
        }
    }
}

impl Default for SwiftConfig {
    fn default() -> Self {
        Self {
            version: 2,
            mode: Mode::Standard,
            scope: Some(Scope::Local),
            address: "127.0.0.1:53".parse().unwrap(),
            log_queries: Some(false),
            tor: TorConfig {
                enabled: false,
                address: Some(DEFAULT_TOR_ADDR.to_string()),
            },
        }
    }
}

impl From<SwiftConfigV1> for SwiftConfig {
    fn from(old_config: SwiftConfigV1) -> Self {
        Self {
            version: 2,
            mode: old_config.mode,
            address: old_config.address,
            scope: Some(Scope::Local),
            log_queries: Some(false),
            tor: TorConfig {
                enabled: old_config.tor,
                address: None,
            },
        }
    }
}

pub fn get_config() -> Result<SwiftConfig, ConfigError> {
    let config_path = get_config_path().join("config.toml");

    if let Ok(old_config) = confy::load_path::<SwiftConfigV1>(&config_path) {
        let new_config: SwiftConfig = old_config.into();
        confy::store_path(&config_path, &new_config)?;

        return Ok(new_config);
    }

    confy::load_path::<SwiftConfig>(config_path).map_err(ConfigError::from)
}

pub fn get_config_path() -> PathBuf {
    if cfg!(debug_assertions) {
        env::current_dir()
            .unwrap_or_else(|_| error!("Current directory inaccessible"))
            .join("assets/")
    } else {
        Path::new("/etc/swiftdns/").to_path_buf()
    }
}
