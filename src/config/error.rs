use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file {0}: {1}")]
    IoError(PathBuf, std::io::Error),

    #[error("Failed to deserialize config file {0}: {1}")]
    DeserializeError(PathBuf, toml::de::Error),

    #[error("Failed to serialize config file {0}: {1}")]
    SerializeError(PathBuf, toml::ser::Error),

    #[error("Invalid provider '{0}'. Valid providers are: {1}")]
    InvalidProvider(String, String),

    #[error("Invalid mode '{1}' for provider '{0}'. Valid modes are: {2}")]
    InvalidProviderMode(String, String, String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Invalid socket address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
}
