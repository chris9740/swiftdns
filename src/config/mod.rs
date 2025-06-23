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

pub const CONFIG_FILE_NAME: &str = "config.toml";

const DEFAULT_TOR_ADDR: &str = "127.0.0.1:9050";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub address: SocketAddr,
    pub resolver: ResolverConfig,
    pub tor: TorConfig,
    pub blocking: BlockConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub url: String,
    pub bootstrap_ips: Option<Vec<SocketAddr>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TorConfig {
    pub enabled: bool,
    pub address: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockConfig {
    pub strategy: BlockStrategy,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockStrategy {
    #[default]
    /// Respond with RCODE 0 and synthetic A/AAAA records pointing to a sinkhole IP.
    Sinkhole,
    /// Respond with RCODE 3 (NXDOMAIN).
    NxDomain,
    /// Respond with RCODE 5 (REFUSED).
    Refused,
    /// Drop the query without responding (causing a timeout on the client side).
    Drop,
}

impl Default for SwiftConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:53".parse().unwrap(),
            resolver: ResolverConfig {
                url: "https://1.1.1.1/dns-query".to_string(),
                bootstrap_ips: None,
            },
            tor: TorConfig {
                enabled: false,
                address: Some(DEFAULT_TOR_ADDR.to_string()),
            },
            blocking: BlockConfig {
                strategy: BlockStrategy::default(),
            },
        }
    }
}

impl SwiftConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match url::Url::parse(&self.resolver.url) {
            Ok(url) => {
                if url.as_str().contains("{name}") || url.as_str().contains("{type}") {
                    return Err(ConfigError::InvalidResolverUrl(
                        format!("JSON-style URLs with {{name}} and {{type}} placeholders are no longer supported: {}", 
                        self.resolver.url)
                    ));
                }

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

pub fn get_config() -> Result<SwiftConfig, ConfigError> {
    let config_path = get_config_path().join(CONFIG_FILE_NAME);

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

pub fn get_filters_path() -> PathBuf {
    get_config_path().join("filters")
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
