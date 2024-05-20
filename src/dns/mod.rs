use dns_message_parser::{rr::RR, DecodeError, Dns, EncodeError, Flags};

use self::resolver::{DnsAnswer, RecordType};

pub mod resolver;

pub fn encode(query: Dns) -> Result<bytes::BytesMut, EncodeError> {
    Dns::encode(&Dns {
        id: query.id,
        flags: Flags {
            qr: true,
            opcode: query.flags.opcode,
            aa: false,
            tc: query.flags.tc,       // echo this from CF
            rd: query.flags.rd,       // reflect query
            ra: true,                 // reflect CF
            ad: true,                 // reflect CF
            cd: query.flags.cd,       // reflect query
            rcode: query.flags.rcode, // reflect CF
        },
        additionals: query.additionals,
        authorities: query.authorities,
        questions: query.questions,
        answers: query.answers,
    })
}

pub fn decode(query_bytes: &[u8]) -> Result<Dns, DecodeError> {
    let bytes = Vec::from(query_bytes);

    Dns::decode(bytes.into())
}

pub fn map_answers(answers: &Vec<DnsAnswer>) -> Vec<RR> {
    let mut group = Vec::new();

    for answer in answers {
        match RecordType::from_u16(answer.rtype) {
            Some(record_type) => {
                if let Ok(rr) = record_type.construct_rr(answer) {
                    group.push(rr);
                }
            }
            None => continue,
        }
    }

    group
}
