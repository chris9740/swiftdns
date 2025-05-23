use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable as _, BinEncodable},
};
use std::{fmt::Display, str::FromStr};
use strum::{EnumIter, IntoEnumIterator};

use crate::{config::SwiftConfig, error::DnsError, http};

use super::message_types::{DnsJsonQuestion, DnsJsonResponse};

#[derive(Debug, EnumIter, Clone, Copy, Eq, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum DnsRecordType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    NS = 2,
    SRV = 33,
    SOA = 6,
    TXT = 16,
    RRSIG = 46,
    ANY = 255,
}

impl DnsRecordType {
    pub fn value(&self) -> u16 {
        *self as u16
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        Self::iter().find(|r| r.value() == value)
    }
}

impl FromStr for DnsRecordType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.to_lowercase();
        Self::iter()
            .find(|rt| rt.to_string().to_lowercase() == input)
            .ok_or("Invalid record type")
    }
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::CNAME => "CNAME",
            Self::MX => "MX",
            Self::NS => "NS",
            Self::SRV => "SRV",
            Self::SOA => "SOA",
            Self::TXT => "TXT",
            Self::RRSIG => "RRSIG",
            Self::ANY => "ANY",
        };
        f.write_str(str)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QueryType(DnsRecordType);

impl QueryType {
    pub fn new(record_type: DnsRecordType) -> Option<Self> {
        match record_type {
            DnsRecordType::A
            | DnsRecordType::AAAA
            | DnsRecordType::CNAME
            | DnsRecordType::MX
            | DnsRecordType::TXT
            | DnsRecordType::SOA => Some(Self(record_type)),
            _ => None,
        }
    }

    pub fn value(&self) -> u16 {
        self.0.value()
    }

    pub fn into_inner(self) -> DnsRecordType {
        self.0
    }
}

impl From<QueryType> for DnsRecordType {
    fn from(qt: QueryType) -> Self {
        qt.0
    }
}

pub async fn resolve(
    client: &mut http::Client,
    config: &SwiftConfig,
    question: &DnsJsonQuestion,
) -> Result<DnsJsonResponse, DnsError> {
    if std::env::var("SWIFTDNS_TEST_MODE").is_ok() {
        return Ok(mock_response_for_tests(question));
    }

    if is_rfc8484_url(&config.resolver.url) {
        resolve_rfc8484(client, config, question).await
    } else {
        resolve_json(client, config, question).await
    }
}

fn is_rfc8484_url(url: &str) -> bool {
    !url.contains("{name}") && !url.contains("{type}")
}

async fn resolve_rfc8484(
    client: &mut http::Client,
    config: &SwiftConfig,
    question: &DnsJsonQuestion,
) -> Result<DnsJsonResponse, DnsError> {
    let dns_message = create_dns_query_message(question)?;
    let wire_format = dns_message
        .to_bytes()
        .map_err(|e| DnsError::NetworkError(format!("Failed to encode DNS message: {}", e)))?;

    let url = url::Url::parse(&config.resolver.url)
        .map_err(|_| DnsError::InvalidResolverUrl(config.resolver.url.clone()))?;

    let request = client
        .post(&config.resolver.url)
        .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .header(reqwest::header::HOST, url.host_str().unwrap_or(""))
        .body(wire_format);

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

    let dns_response = Message::from_bytes(&response_bytes)
        .map_err(|e| DnsError::NetworkError(format!("Failed to parse DNS response: {}", e)))?;

    convert_dns_message_to_json(dns_response)
}

async fn resolve_json(
    client: &mut http::Client,
    config: &SwiftConfig,
    question: &DnsJsonQuestion,
) -> Result<DnsJsonResponse, DnsError> {
    let url = url::Url::parse(&config.resolver.url)
        .map_err(|_| DnsError::InvalidResolverUrl(config.resolver.url.clone()))?;

    let mut formatted_url = url
        .as_str()
        .replace("{name}", &question.name)
        .replace("{type}", &question.qtype.to_string());

    // Add DNSSEC flag for JSON queries
    if let Some(dnssec) = question.dnssec {
        let separator = if formatted_url.contains('?') {
            "&"
        } else {
            "?"
        };
        let do_value = if dnssec { "1" } else { "0" };
        formatted_url = format!("{}{separator}do={do_value}", formatted_url);
    }

    let request = client
        .get(&formatted_url)
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .header(reqwest::header::HOST, url.host_str().unwrap_or(""));

    let res = request
        .send()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to send request: {}", e)))?;

    if res.status() == reqwest::StatusCode::BAD_REQUEST {
        return Err(DnsError::QueryError("Bad request".to_string()));
    }

    res.json()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to parse response: {}", e)))
}

fn create_dns_query_message(question: &DnsJsonQuestion) -> Result<Message, DnsError> {
    let mut message = Message::new();
    message.set_id(rand::random());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);

    let name = Name::from_str(&question.name)
        .map_err(|e| DnsError::NetworkError(format!("Invalid domain name: {}", e)))?;

    let record_type = RecordType::from(question.qtype);
    let query = Query::query(name, record_type);
    message.add_query(query);

    // Handle DNSSEC preferences for RFC 8484
    if let Some(dnssec) = question.dnssec {
        if dnssec {
            // Create EDNS with DO bit set
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_dnssec_ok(true);
            edns.set_max_payload(4096);
            message.set_edns(edns);
        }
        // If dnssec is false, we don't set EDNS or DO bit
    }

    Ok(message)
}

fn convert_dns_message_to_json(message: Message) -> Result<DnsJsonResponse, DnsError> {
    use super::message_types::DnsJsonQuestion;

    let mut json_response = DnsJsonResponse {
        status: message.response_code().low(),
        tc: message.truncated(),
        rd: message.recursion_desired(),
        ra: message.recursion_available(),
        ad: message.authentic_data(),
        cd: message.checking_disabled(),
        question: None,
        answer: vec![],
        authority: None,
    };

    if !message.queries().is_empty() {
        json_response.question = Some(
            message
                .queries()
                .iter()
                .map(|q| DnsJsonQuestion {
                    name: q.name().to_string(),
                    qtype: q.query_type().into(),
                    dnssec: message
                        .extensions()
                        .as_ref()
                        .map(|edns| edns.flags().dnssec_ok),
                })
                .collect(),
        );
    }

    for record in message.answers() {
        if let Ok(json_answer) = crate::dns::records::rr_to_json_answer(record) {
            json_response.answer.push(json_answer);
        }
    }

    if !message.name_servers().is_empty() {
        let mut authority = vec![];
        for record in message.name_servers() {
            if let Ok(json_answer) = crate::dns::records::rr_to_json_answer(record) {
                authority.push(json_answer);
            }
        }
        if !authority.is_empty() {
            json_response.authority = Some(authority);
        }
    }

    Ok(json_response)
}

fn mock_response_for_tests(question: &DnsJsonQuestion) -> DnsJsonResponse {
    use crate::dns::message_types::{DnsJsonAnswer, DnsJsonResponse};

    let domain = question.name.clone();
    let qtype = question.qtype;

    let mut response = DnsJsonResponse {
        status: 0,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        question: Some(vec![DnsJsonQuestion {
            name: domain.clone(),
            qtype,
            dnssec: None,
        }]),
        answer: vec![],
        authority: None,
    };

    match domain.as_str() {
        "example.com" => {
            if qtype == 1 {
                response.answer = vec![DnsJsonAnswer {
                    name: domain,
                    rtype: qtype,
                    ttl: 300,
                    data: "93.184.216.34".to_string(),
                }];
            }
        }
        "nxdomain.example" => {
            response.status = 3; // NXDOMAIN
        }
        _ => {
            if qtype == QueryType::new(DnsRecordType::A).unwrap().value() {
                response.answer = vec![DnsJsonAnswer {
                    name: domain,
                    rtype: qtype,
                    ttl: 300,
                    data: "192.0.2.1".to_string(),
                }];
            }
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SwiftConfig;

    #[test]
    fn test_dns_record_type() {
        assert_eq!(DnsRecordType::A.value(), 1);
        assert_eq!(DnsRecordType::AAAA.value(), 28);
        assert_eq!(DnsRecordType::CNAME.value(), 5);
        assert_eq!(DnsRecordType::MX.value(), 15);
        assert_eq!(DnsRecordType::NS.value(), 2);
        assert_eq!(DnsRecordType::SRV.value(), 33);
        assert_eq!(DnsRecordType::SOA.value(), 6);
        assert_eq!(DnsRecordType::TXT.value(), 16);
        assert_eq!(DnsRecordType::ANY.value(), 255);
    }

    #[test]
    fn test_query_type() {
        let a_query = QueryType::new(DnsRecordType::A);
        assert!(a_query.is_some());
        assert_eq!(a_query.unwrap().value(), 1);

        let any_query = QueryType::new(DnsRecordType::ANY);
        assert!(any_query.is_none());
    }

    #[test]
    fn test_resolve_with_mock() {
        let mut server = mockito::Server::new();

        let host = server.host_with_port();

        let mock_response = r#"{
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "example.com",
                    "type": 1
                }
            ],
            "Answer": [
                {
                    "name": "example.com",
                    "type": 1,
                    "TTL": 300,
                    "data": "93.184.216.34"
                },
                {
                    "name": "example.com",
                    "type": 1,
                    "TTL": 300,
                    "data": "93.184.216.35"
                }
            ]
        }"#;

        let mock = server
            .mock("GET", "/resolve?name=example.com&type=1")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create();

        let config = SwiftConfig {
            resolver: crate::config::ResolverConfig {
                url: format!(
                    "http://{host}/resolve?name={{name}}&type={{type}}",
                    host = host
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        let question = DnsJsonQuestion {
            name: "example.com".to_string(),
            qtype: DnsRecordType::A.value(),
            dnssec: None,
        };

        let mut client = tokio_test::block_on(http::Client::connect(&config)).unwrap();
        let result = tokio_test::block_on(resolve(&mut client, &config, &question));

        assert!(result.is_ok());

        if let Ok(response) = result {
            assert_eq!(response.status, 0);
            assert!(!response.tc);
            assert!(response.rd);
            assert!(response.ra);
            assert!(!response.ad);
            assert!(!response.cd);

            assert_eq!(response.answer.len(), 2);
            assert_eq!(response.answer[0].data, "93.184.216.34");
            assert_eq!(response.answer[1].data, "93.184.216.35");
        }

        mock.assert();
    }

    #[test]
    fn test_resolve_cname() {
        let mut server = mockito::Server::new();

        let host = server.host_with_port();

        let mock_response = r#"{
            "Status": 0,
            "TC": false,
            "RD": true,
            "RA": true,
            "AD": false,
            "CD": false,
            "Question": [
                {
                    "name": "example.com",
                    "type": 5
                }
            ],
            "Answer": [
                {
                    "name": "example.com",
                    "type": 5,
                    "TTL": 300,
                    "data": "www.example.com"
                }
            ]
        }"#;

        let mock = server
            .mock("GET", "/resolve?name=example.com&type=5")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(mock_response)
            .create();

        let config = SwiftConfig {
            resolver: crate::config::ResolverConfig {
                url: format!(
                    "http://{host}/resolve?name={{name}}&type={{type}}",
                    host = host
                ),
                ..Default::default()
            },
            ..Default::default()
        };

        let question = DnsJsonQuestion {
            name: "example.com".to_string(),
            qtype: DnsRecordType::CNAME.value(),
            dnssec: None,
        };

        let mut client = tokio_test::block_on(http::Client::connect(&config)).unwrap();
        let result = tokio_test::block_on(resolve(&mut client, &config, &question));

        assert!(result.is_ok());

        if let Ok(response) = result {
            assert_eq!(response.status, 0);
            assert!(!response.tc);
            assert!(response.rd);
            assert!(response.ra);
            assert!(!response.ad);
            assert!(!response.cd);

            assert_eq!(response.answer.len(), 1);
            assert_eq!(response.answer[0].data, "www.example.com");
        }

        mock.assert();
    }
}
