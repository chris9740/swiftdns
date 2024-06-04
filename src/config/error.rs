use std::fmt;

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    AddrParseError(std::net::AddrParseError),
    ConfyError(confy::ConfyError),
    InvalidMode(String),
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

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "IO error: {}", e),
            ConfigError::AddrParseError(e) => write!(f, "Address parse error: {}", e),
            ConfigError::ConfyError(e) => write!(f, "Configuration error: {}", e),
            ConfigError::InvalidMode(mode) => write!(f, "Invalid mode `{}`", mode),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::IoError(e) => Some(e),
            ConfigError::AddrParseError(e) => Some(e),
            ConfigError::ConfyError(e) => Some(e),
            ConfigError::InvalidMode(_) => None,
        }
    }
}
