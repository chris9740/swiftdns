use std::{
    env,
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

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

impl From<&str> for Mode {
    fn from(input: &str) -> Mode {
        for resolver in Mode::iter() {
            let resolver_value = resolver.ip_address();

            if input == resolver_value {
                return resolver;
            }
        }

        panic!("Invalid mode `{}`", input);
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub address: Option<String>,
}

impl TorConfig {
    pub fn default_address() -> String {
        "127.0.0.1:9050".to_string()
    }

    pub fn get_address(&self) -> String {
        self.address.clone().unwrap_or(Self::default_address())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub mode: Mode,
    pub address: SocketAddr,
    pub tor: TorConfig,
}

impl std::default::Default for SwiftConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Standard,
            address: "127.0.0.1:53".parse().unwrap(),
            tor: TorConfig {
                enabled: false,
                address: Some(TorConfig::default_address()),
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
