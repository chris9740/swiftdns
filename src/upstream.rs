use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{RData, Record, RecordType},
    serialize::binary::{BinDecodable as _, BinEncodable as _},
};

use crate::{config::SwiftConfig, error::DnsError, http};

pub async fn resolve(
    client: &http::Client,
    config: &SwiftConfig,
    message: &Message,
) -> Result<Message, DnsError> {
    if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        return simulate_dns_response(message);
    }

    let request = client
        .post(&config.resolver.url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .body(message.to_bytes()?);

    let response = request
        .send()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to send request: {}", e)))?;

    if response.status() == reqwest::StatusCode::BAD_REQUEST {
        return Err(DnsError::QueryError("Bad request".to_string()));
    }

    let response_bytes = response
        .bytes()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to read response: {}", e)))?;

    Ok(Message::from_bytes(&response_bytes)?)
}

/// Simulates a DNS response for testing purposes.
///
/// We use this in our cli tests to avoid making real network requests.
fn simulate_dns_response(message: &Message) -> Result<Message, DnsError> {
    let mut response = message.clone();

    response.set_message_type(MessageType::Response);

    if let Some(query) = message.queries().first() {
        let name = query.name().to_string();
        let record_type = query.query_type();

        match name.as_str() {
            "example.com" if record_type == RecordType::A => {
                let ip = "93.184.216.34".parse().expect("Failed to parse IP address");
                let rdata = RData::A(ip);
                let record = Record::from_rdata(query.name().clone(), 300, rdata);
                response.add_answer(record);
            }
            "nxdomain.example" => {
                response.set_response_code(ResponseCode::NXDomain);
            }
            _ => {
                response.set_response_code(ResponseCode::NotImp);
            }
        }
    }

    Ok(response)
}
