use hickory_proto::op::ResponseCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Invalid resolver URL: {0}")]
    InvalidResolverUrl(String),

    #[error("DNS proto error: {0}")]
    ProtoError(#[from] hickory_proto::ProtoError),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid query: {0}")]
    QueryError(String),

    #[error("Record data format error: {0}")]
    RecordDataFormatError(String),

    #[error("Dropped")]
    Dropped,
}

impl DnsError {
    /// Get the appropriate DNS response code for this error
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::RecordDataFormatError(_) => ResponseCode::FormErr,
            Self::QueryError(_) => ResponseCode::ServFail,
            _ => ResponseCode::ServFail,
        }
    }
}
