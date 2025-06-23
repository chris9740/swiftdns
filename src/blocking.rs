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
