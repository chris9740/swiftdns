pub mod error;

use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::Domain;

use self::error::ConfigError;

const DEFAULT_TOR_ADDR: &str = "127.0.0.1:9050";

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub url: String,
    pub bootstrap_ips: Option<Vec<SocketAddr>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub scope: Option<Scope>,
    pub address: SocketAddr,
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
            resolver: ResolverConfig {
                url: "https://1.1.1.1/dns-query?name={name}&type={type}".to_string(),
                bootstrap_ips: None,
            },
            tor: TorConfig {
                enabled: false,
                address: Some(DEFAULT_TOR_ADDR.to_string()),
            },
        }
    }
}

impl SwiftConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match url::Url::parse(&self.resolver.url) {
            Ok(url) => {
                if url.scheme() != "https" && url.host_str() != Some("127.0.0.1") {
                    return Err(ConfigError::InvalidResolverScheme(
                        self.resolver.url.clone(),
                    ));
                }

                if let Some(host) = url.host_str() {
                    if host.is_empty() {
                        return Err(ConfigError::InvalidResolverHost(self.resolver.url.clone()));
                    }

                    // Check if host is a valid IP address or domain
                    let is_valid =
                        host.parse::<std::net::IpAddr>().is_ok() || Domain::from_str(host).is_ok();

                    if !is_valid {
                        return Err(ConfigError::InvalidResolverHost(self.resolver.url.clone()));
                    }
                } else {
                    return Err(ConfigError::InvalidResolverHost(self.resolver.url.clone()));
                }
            }
            Err(_) => {
                return Err(ConfigError::InvalidResolverUrl(self.resolver.url.clone()));
            }
        }

        Ok(())
    }
}

pub fn get_config() -> Result<SwiftConfig, ConfigError> {
    let config_path = get_config_path().join("config.toml");

    if !config_path.exists() {
        create_default_config(&config_path)?;
    }

    let config_str = std::fs::read_to_string(&config_path)
        .map_err(|e| ConfigError::IoError(config_path.clone(), e))?;

    let config: SwiftConfig = toml::from_str(&config_str)
        .map_err(|e| ConfigError::DeserializeError(config_path.clone(), e))?;

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

pub fn create_default_config(path: &Path) -> Result<(), ConfigError> {
    let config = SwiftConfig::default();
    let toml_string = toml::to_string_pretty(&config)
        .map_err(|e| ConfigError::SerializeError(path.to_path_buf(), e))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| ConfigError::IoError(parent.to_path_buf(), e))?;
    }

    std::fs::write(path, toml_string).map_err(|e| ConfigError::IoError(path.to_path_buf(), e))?;

    Ok(())
}
