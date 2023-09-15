use std::net::{Ipv4Addr, Ipv6Addr};

use dns_message_parser::{
    rr::{self, RR},
    DecodeError, Dns, DomainName, Flags, EncodeError,
};

use self::resolver::{DnsAnswer, RecordType};

pub mod resolver;

pub fn encode(query: Dns) -> Result<bytes::BytesMut, EncodeError> {
    Dns::encode(&Dns {
        id: query.id,
        flags: Flags {
            qr: true,
            opcode: query.flags.opcode,
            aa: true,
            tc: query.flags.tc,
            rd: query.flags.rd,
            ra: true,
            ad: true,
            cd: query.flags.cd,
            rcode: query.flags.rcode,
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

pub fn group_answers(answers: &Vec<DnsAnswer>) -> Vec<RR> {
    let mut group = Vec::new();

    for answer in answers {
        if answer.r#type == RecordType::A.value() {
            group.push(RR::A(rr::A {
                domain_name: answer.domain_name.parse::<DomainName>().unwrap(),
                ttl: answer.ttl,
                ipv4_addr: answer.data.parse::<Ipv4Addr>().unwrap(),
            }));
        } else if answer.r#type == RecordType::AAAA.value() {
            group.push(RR::AAAA(rr::AAAA {
                domain_name: answer.domain_name.parse::<DomainName>().unwrap(),
                ttl: answer.ttl,
                ipv6_addr: answer.data.parse::<Ipv6Addr>().unwrap(),
            }));
        }
    }

    group
}
