use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        RData, Record, RecordType,
    },
};

use crate::config::{BlockConfig, BlockStrategy};

/// IPv4 sinkhole address (0.0.0.0)
const SINKHOLE_IPV4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// IPv6 sinkhole address (::)
const SINKHOLE_IPV6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

/// TTL for sinkhole responses (in seconds)
const SINKHOLE_TTL: u32 = 1;

/// Creates a DNS response for a blocked domain based on the configured blocking strategy.
///
/// Returns `None` for the `Drop` strategy, indicating the query should be silently dropped.
pub fn create_blocked_response(
    message: &Message,
    query_type: RecordType,
    config: &BlockConfig,
) -> Option<Message> {
    let query = message.queries().first()?;
    let mut response = create_response_base(message);

    match config.strategy {
        BlockStrategy::Sinkhole => {
            response.set_response_code(ResponseCode::NoError);

            if let Some(rdata) = sinkhole_rdata(query_type) {
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    SINKHOLE_TTL,
                    rdata,
                ));
            } else {
                // Unsupported record types get REFUSED
                response.set_response_code(ResponseCode::Refused);
            }

            Some(response)
        }
        BlockStrategy::NxDomain => {
            response.set_response_code(ResponseCode::NXDomain);
            Some(response)
        }
        BlockStrategy::Refused => {
            response.set_response_code(ResponseCode::Refused);
            Some(response)
        }
        BlockStrategy::Drop => None,
    }
}

/// Returns the appropriate sinkhole RData for the given record type.
fn sinkhole_rdata(query_type: RecordType) -> Option<RData> {
    match query_type {
        RecordType::A => Some(RData::A(A(SINKHOLE_IPV4))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(SINKHOLE_IPV6))),
        _ => None,
    }
}

/// Creates a base DNS response message from a query.
pub fn create_response_base(message: &Message) -> Message {
    let mut response = message.clone();

    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_authoritative(false);
    response.set_truncated(false);
    response.set_recursion_available(true);
    response.set_authentic_data(false);

    response
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn create_test_message(domain: &str, record_type: RecordType) -> Message {
        let mut message = Message::new();
        let query = Query::query(Name::from_str(domain).unwrap(), record_type);
        message.add_query(query);
        message
    }

    #[test]
    fn test_sinkhole_responses() {
        let config = BlockConfig {
            strategy: BlockStrategy::Sinkhole,
        };
        let message = create_test_message("blocked.com", RecordType::A);

        // Test A record response
        let response = create_blocked_response(&message, RecordType::A, &config).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answer = response.answers().first().unwrap();
        assert!(matches!(answer.data(), RData::A(ip) if ip.to_string() == "0.0.0.0"));

        // Test AAAA record response
        let response = create_blocked_response(&message, RecordType::AAAA, &config).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);

        let answer = response.answers().first().unwrap();
        assert!(matches!(answer.data(), RData::AAAA(ip) if ip.to_string() == "::"));

        // Test other record types
        let response = create_blocked_response(&message, RecordType::CNAME, &config).unwrap();
        assert_eq!(response.response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_nx_domain_response() {
        let config = BlockConfig {
            strategy: BlockStrategy::NxDomain,
        };
        let message = create_test_message("blocked.com", RecordType::A);

        let response = create_blocked_response(&message, RecordType::A, &config);

        assert!(response.is_some());
        assert_eq!(response.unwrap().response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_refused_response() {
        let config = BlockConfig {
            strategy: BlockStrategy::Refused,
        };
        let message = create_test_message("blocked.com", RecordType::A);

        let response = create_blocked_response(&message, RecordType::A, &config);

        assert!(response.is_some());
        assert_eq!(response.unwrap().response_code(), ResponseCode::Refused);
    }

    #[test]
    fn test_drop_strategy_returns_none() {
        let config = BlockConfig {
            strategy: BlockStrategy::Drop,
        };
        let message = create_test_message("blocked.com", RecordType::A);

        let response = create_blocked_response(&message, RecordType::A, &config);
        assert!(response.is_none());
    }
}
