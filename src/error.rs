use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Invalid resolver URL: {0}")]
    InvalidResolverUrl(String),

    #[error("DNS proto error: {0}")]
    ProtoError(#[from] hickory_proto::ProtoError),

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

    #[error("Invalid query type: {0}")]
    InvalidQueryType(String),
}
