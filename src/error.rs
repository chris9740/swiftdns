use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS decode error: {0}")]
    DecodeError(#[from] dns_message_parser::DecodeError),

    #[error("DNS encode error: {0}")]
    EncodeError(#[from] dns_message_parser::EncodeError),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Invalid query: {0}")]
    QueryError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),
}
