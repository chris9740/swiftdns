use hickory_proto::op::ResponseCode;
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

    #[error("Unsupported record type: {0}")]
    UnsupportedRecordType(String),

    #[error("Unsupported record data: {0}")]
    UnsupportedRecordData(String),

    #[error("Record data format error: {0}")]
    RecordDataFormatError(String),

    #[error("Output error: {0}")]
    OutputError(#[from] anyhow::Error),
}

impl DnsError {
    /// Get the appropriate DNS response code for this error
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::UnsupportedRecordType(_) => ResponseCode::NotImp,
            Self::UnsupportedRecordData(_) => ResponseCode::NotImp,
            Self::RecordDataFormatError(_) => ResponseCode::FormErr,
            Self::QueryError(_) => ResponseCode::ServFail,
            Self::ProtoError(_) => ResponseCode::ServFail,
            _ => ResponseCode::ServFail,
        }
    }
}
