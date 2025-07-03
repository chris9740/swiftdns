use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("DNS proto error: {0}")]
    ProtoError(#[from] hickory_proto::ProtoError),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid query: {0}")]
    QueryError(String),
}
