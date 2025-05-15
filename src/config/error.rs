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

    #[error("Invalid resolver scheme: {0}")]
    InvalidResolverScheme(String),

    #[error("Invalid resolver host: {0}")]
    InvalidResolverHost(String),

    #[error("Invalid resolver URL: {0}")]
    InvalidResolverUrl(String),

    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    #[error("Invalid socket address: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
}
