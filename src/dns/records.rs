use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr as _,
};

use dns_message_parser::{
    rr::{self, Class, NonEmptyVec, RR},
    DomainName,
};

use super::{message_types::DnsJsonAnswer, resolver::DnsRecordType};

pub fn json_answer_to_rr(answer: &DnsJsonAnswer) -> Result<RR, Box<dyn Error>> {
    let domain_name: DomainName = answer.name.name().parse()?;
    let ttl = answer.ttl;
    let data = &answer.data;

    let record_type =
        DnsRecordType::from_u16(answer.rtype).ok_or("Unknown record type from JSON response")?;

    match record_type {
        DnsRecordType::A => {
            let ipv4_addr = data.parse::<Ipv4Addr>()?;
            Ok(RR::A(rr::A {
                domain_name,
                ttl,
                ipv4_addr,
            }))
        }
        DnsRecordType::AAAA => {
            let ipv6_addr = data.parse::<Ipv6Addr>()?;
            Ok(RR::AAAA(rr::AAAA {
                domain_name,
                ttl,
                ipv6_addr,
            }))
        }
        DnsRecordType::CNAME => {
            let c_name = data.parse::<DomainName>()?;
            Ok(RR::CNAME(rr::CNAME {
                domain_name,
                ttl,
                class: Class::IN,
                c_name,
            }))
        }
        DnsRecordType::MX => {
            let priority_and_domain = data.splitn(2, ' ').collect::<Vec<&str>>();
            if priority_and_domain.len() != 2 {
                return Err("Invalid data format for MX record".into());
            }
            let priority = priority_and_domain[0].parse::<u16>()?;
            let exchange_str = priority_and_domain[1];
            let exchange = if exchange_str == "." {
                DomainName::default()
            } else {
                DomainName::from_str(exchange_str)?
            };

            Ok(RR::MX(rr::MX {
                domain_name,
                ttl,
                class: Class::IN,
                preference: priority,
                exchange,
            }))
        }
        DnsRecordType::NS => {
            let ns_d_name = data.parse::<DomainName>()?;
            Ok(RR::NS(rr::NS {
                domain_name,
                ttl,
                class: Class::IN,
                ns_d_name,
            }))
        }
        DnsRecordType::SRV => {
            let parts = data.split_whitespace().collect::<Vec<&str>>();
            if parts.len() != 4 {
                return Err("Invalid data format for SRV record".into());
            }
            let priority = parts[0].parse::<u16>()?;
            let weight = parts[1].parse::<u16>()?;
            let port = parts[2].parse::<u16>()?;
            let target = parts[3].parse::<DomainName>()?;
            Ok(RR::SRV(rr::SRV {
                domain_name,
                ttl,
                class: Class::IN,
                priority,
                weight,
                port,
                target,
            }))
        }
        DnsRecordType::SOA => {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() < 7 {
                return Err("Insufficient data for SOA record".into());
            }

            let m_name = DomainName::from_str(parts[0])?;
            let r_name = DomainName::from_str(parts[1])?;
            let serial: u32 = parts[2].parse()?;
            let refresh: u32 = parts[3].parse()?;
            let retry: u32 = parts[4].parse()?;
            let expire: u32 = parts[5].parse()?;
            let min_ttl: u32 = parts[6].parse()?;

            Ok(RR::SOA(rr::SOA {
                domain_name,
                ttl,
                class: Class::IN,
                m_name,
                r_name,
                serial,
                refresh,
                retry,
                expire,
                min_ttl,
            }))
        }
        DnsRecordType::TXT => {
            let strings: Vec<String> = data
                .split('\"')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<String>>();

            let strings = NonEmptyVec::try_from(strings)
                .map_err(|_| "TXT record must have at least one string".to_string())?;

            Ok(RR::TXT(rr::TXT {
                domain_name,
                ttl,
                class: Class::IN,
                strings,
            }))
        }
        DnsRecordType::ANY => Err("ANY record type should not appear in answers".into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr as _};

    use dns_message_parser::{rr::RR, DomainName};

    use crate::{
        dns::{message_types::DnsJsonAnswer, resolver::DnsRecordType},
        Domain,
    };

    use super::json_answer_to_rr;

    #[test]
    fn test_json_answer_to_rr() {
        let answer = DnsJsonAnswer {
            name: Domain::from_str("example.com.").unwrap(),
            rtype: 1,
            ttl: 3600,
            data: "127.0.0.1".to_string(),
        };

        let rr = json_answer_to_rr(&answer).unwrap();

        if let RR::A(a) = rr {
            assert_eq!(a.ipv4_addr, Ipv4Addr::new(127, 0, 0, 1));
            assert_eq!(a.domain_name, DomainName::from_str("example.com.").unwrap());
            assert_eq!(a.ttl, 3600);
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_invalid_record_type() {
        let answer = DnsJsonAnswer {
            name: Domain::from_str("example.com.").unwrap(),
            rtype: 256, // Invalid record type
            ttl: 3600,
            data: "invalid_data".to_string(),
        };

        let result = json_answer_to_rr(&answer);

        assert!(result.is_err(), "Expected error for invalid record type");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Unknown record type from JSON response"
        );
    }

    #[test]
    fn test_invalid_data_format() {
        let answer = DnsJsonAnswer {
            name: Domain::from_str("example.com.").unwrap(),
            rtype: DnsRecordType::MX.value(),
            ttl: 3600,
            data: "invalid_data".to_string(),
        };
        let result = json_answer_to_rr(&answer);
        assert!(result.is_err(), "Expected error for invalid data format");
        assert_eq!(
            result.unwrap_err().to_string(),
            "Invalid data format for MX record"
        );
    }
}
