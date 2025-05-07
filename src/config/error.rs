#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(std::io::Error),
    #[error("Address parse error: {0}")]
    AddrParseError(std::net::AddrParseError),
    #[error("Configuration error: {0}")]
    ConfyError(confy::ConfyError),
    #[error("Invalid mode `{0}`")]
    InvalidMode(String),
    #[error("Invalid scope `{0}`")]
    InvalidScope(String),
    #[error("Invalid provider '{0}'. Valid providers are: {1}")]
    InvalidProvider(String, String),
    #[error("Invalid mode '{1}' for provider '{0}'. Valid modes are: {2}")]
    InvalidProviderMode(String, String, String),
}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        ConfigError::IoError(error)
    }
}

impl From<std::net::AddrParseError> for ConfigError {
    fn from(error: std::net::AddrParseError) -> Self {
        ConfigError::AddrParseError(error)
    }
}

impl From<confy::ConfyError> for ConfigError {
    fn from(error: confy::ConfyError) -> Self {
        ConfigError::ConfyError(error)
    }
}
