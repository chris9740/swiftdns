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

use crate::dns::provider;

use self::error::ConfigError;

const DEFAULT_TOR_ADDR: &str = "127.0.0.1:9050";

#[derive(Debug, Serialize, Deserialize, EnumIter)]
pub enum Mode {
    Standard,
    Safe,
    Clean,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode_str = match self {
            Mode::Standard => "Standard",
            Mode::Safe => "Safe",
            Mode::Clean => "Clean",
        };
        write!(f, "{}", mode_str)
    }
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
pub struct ResolverConfig {
    pub provider: String,
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub scope: Option<Scope>,
    pub address: SocketAddr,
    pub log_queries: Option<bool>,
    pub resolver: ResolverConfig,
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
            scope: Some(Scope::Local),
            address: "127.0.0.1:53".parse().unwrap(),
            log_queries: Some(false),
            resolver: ResolverConfig {
                provider: "Cloudflare".to_string(),
                mode: Mode::Standard.to_string(),
            },
            tor: TorConfig {
                enabled: false,
                address: Some(DEFAULT_TOR_ADDR.to_string()),
            },
        }
    }
}

impl SwiftConfig {
    pub fn get_active_provider(&self) -> (&str, &str, &String) {
        let provider = provider::get_provider(&self.resolver.provider)
            .expect("Provider validation already performed");
        let mode = provider::get_provider_mode(&self.resolver.provider, &self.resolver.mode)
            .expect("Mode validation already performed");

        (&provider.name, &mode.ip, &self.resolver.mode)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !provider::is_valid_provider(&self.resolver.provider) {
            let valid_providers = provider::get_valid_providers().join(", ");
            return Err(ConfigError::InvalidProvider(
                self.resolver.provider.clone(),
                valid_providers,
            ));
        }

        let provider = provider::get_provider(&self.resolver.provider)
            .expect("Provider existence already validated");

        if !provider.modes.iter().any(|m| m.name == self.resolver.mode) {
            let valid_modes: Vec<_> = provider.modes.iter().map(|m| m.name.as_str()).collect();
            return Err(ConfigError::InvalidProviderMode(
                self.resolver.provider.clone(),
                self.resolver.mode.clone(),
                valid_modes.join(", "),
            ));
        }

        Ok(())
    }
}

pub fn get_config() -> Result<SwiftConfig, ConfigError> {
    let config_path = get_config_path().join("config.toml");
    let config = confy::load_path::<SwiftConfig>(config_path).map_err(ConfigError::from)?;
    config.validate()?;
    Ok(config)
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
