use dns_message_parser::{rr::RR, DecodeError, Dns, EncodeError, Flags};
use message_types::DnsJsonAnswer;

use self::resolver::DnsRecordType;

pub mod message_types;
pub mod provider;
pub mod resolver;

#[derive(Debug)]
pub struct DnsEncoder;

impl DnsEncoder {
    pub fn encode_response(query: Dns) -> Result<bytes::BytesMut, EncodeError> {
        let response = Dns {
            id: query.id,
            flags: Self::construct_response_flags(&query.flags),
            additionals: query.additionals,
            authorities: query.authorities,
            questions: query.questions,
            answers: query.answers,
        };

        Dns::encode(&response)
    }

    fn construct_response_flags(query_flags: &Flags) -> Flags {
        Flags {
            qr: true,                   // Always true for responses
            opcode: query_flags.opcode, // Reflect query opcode
            aa: false,                  // Not authoritative
            tc: false,                  // No truncation by default
            rd: query_flags.rd,         // Reflect recursion desired
            ra: true,                   // Recursion available
            ad: false,                  // No DNSSEC validation
            cd: query_flags.cd,         // Reflect checking disabled
            rcode: query_flags.rcode,   // Reflect response code
        }
    }
}

pub fn decode(query_bytes: &[u8]) -> Result<Dns, DecodeError> {
    Dns::decode(Vec::from(query_bytes).into())
}

pub fn map_answers(answers: &[DnsJsonAnswer]) -> Vec<RR> {
    answers
        .iter()
        .filter_map(|answer| {
            DnsRecordType::from_u16(answer.rtype).and_then(|record_type| {
                record_type
                    .construct_rr(answer)
                    .map_err(|err| {
                        eprintln!("Failed to construct RR: {:?}", err);
                        err
                    })
                    .ok()
            })
        })
        .collect()
}
