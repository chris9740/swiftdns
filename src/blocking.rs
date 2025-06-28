use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, RecordType},
};

use crate::config::{BlockConfig, BlockStrategy};

pub fn create_blocked_response(
    message: &Message,
    query_type: RecordType,
    config: &BlockConfig,
) -> Option<Message> {
    let query = message.queries().first()?;
    let mut response = create_response_base(message);

    match config.strategy {
        BlockStrategy::Sinkhole => {
            let ttl = 1;

            response.set_response_code(ResponseCode::NoError);

            match query_type {
                RecordType::A => {
                    let sinkhole = RData::A("0.0.0.0".parse().unwrap());
                    response.add_answer(Record::from_rdata(query.name().clone(), ttl, sinkhole));
                }
                RecordType::AAAA => {
                    let sinkhole = RData::AAAA("::".parse().unwrap());
                    response.add_answer(Record::from_rdata(query.name().clone(), ttl, sinkhole));
                }
                _ => {
                    response.set_response_code(ResponseCode::Refused);
                }
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
        BlockStrategy::Drop => None, // Signal to drop the packet
    }
}

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
