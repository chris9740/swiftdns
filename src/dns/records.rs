use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr as _,
};

use hickory_proto::rr::{resource::Record, Name, RData};

use super::{message_types::DnsJsonAnswer, resolver::DnsRecordType};

pub fn json_answer_to_rr(answer: &DnsJsonAnswer) -> Result<Record, Box<dyn Error>> {
    let name: Name = answer.name.parse()?;
    let ttl = answer.ttl;
    let data = &answer.data;

    let rdata = match DnsRecordType::from_u16(answer.rtype) {
        Some(DnsRecordType::A) => {
            let ipv4_addr = data.parse::<Ipv4Addr>()?;
            RData::A(hickory_proto::rr::rdata::A(ipv4_addr))
        }
        Some(DnsRecordType::AAAA) => {
            let ipv6_addr = data.parse::<Ipv6Addr>()?;
            RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6_addr))
        }
        Some(DnsRecordType::CNAME) => {
            let c_name = data.parse::<Name>()?;
            RData::CNAME(hickory_proto::rr::rdata::CNAME(c_name))
        }
        Some(DnsRecordType::MX) => {
            let priority_and_domain = data.splitn(2, ' ').collect::<Vec<&str>>();
            if priority_and_domain.len() != 2 {
                return Err("Invalid data format for MX record".into());
            }
            let priority = priority_and_domain[0].parse::<u16>()?;
            let exchange_str = priority_and_domain[1];
            let exchange = if exchange_str == "." {
                Name::root()
            } else {
                Name::from_str(exchange_str)?
            };

            RData::MX(hickory_proto::rr::rdata::MX::new(priority, exchange))
        }
        Some(DnsRecordType::NS) => {
            let ns_name = data.parse::<Name>()?;
            RData::NS(hickory_proto::rr::rdata::NS(ns_name))
        }
        Some(DnsRecordType::SOA) => {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() < 7 {
                return Err("Insufficient data for SOA record".into());
            }

            let mname = Name::from_str(parts[0])?;
            let rname = Name::from_str(parts[1])?;
            let serial: u32 = parts[2].parse()?;
            let refresh: i32 = parts[3].parse()?;
            let retry: i32 = parts[4].parse()?;
            let expire: i32 = parts[5].parse()?;
            let minimum: u32 = parts[6].parse()?;

            RData::SOA(hickory_proto::rr::rdata::SOA::new(
                mname, rname, serial, refresh, retry, expire, minimum,
            ))
        }
        Some(DnsRecordType::TXT) => {
            let clean_data = if data.starts_with('"') && data.ends_with('"') && data.len() > 1 {
                &data[1..data.len() - 1] // Remove surrounding quotes
            } else {
                data
            };
            let txt_data = hickory_proto::rr::rdata::TXT::new(vec![clean_data.to_string()]);
            RData::TXT(txt_data)
        }
        Some(DnsRecordType::SRV) => {
            let parts = data.split_whitespace().collect::<Vec<&str>>();
            if parts.len() != 4 {
                return Err("Invalid data format for SRV record".into());
            }
            let priority = parts[0].parse::<u16>()?;
            let weight = parts[1].parse::<u16>()?;
            let port = parts[2].parse::<u16>()?;
            let target = parts[3].parse::<Name>()?;

            RData::SRV(hickory_proto::rr::rdata::SRV::new(
                priority, weight, port, target,
            ))
        }
        _ => return Err("Unknown record type from JSON response".into()),
    };

    Ok(Record::from_rdata(name, ttl, rdata))
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr as _};

    use hickory_proto::rr::{Name, RData};

    use crate::dns::{message_types::DnsJsonAnswer, resolver::DnsRecordType};

    use super::json_answer_to_rr;

    #[test]
    fn test_json_answer_to_rr() {
        let answer = DnsJsonAnswer {
            name: "example.com.".to_string(),
            rtype: 1,
            ttl: 3600,
            data: "127.0.0.1".to_string(),
        };

        let rr = json_answer_to_rr(&answer).unwrap();

        if let RData::A(a) = rr.data() {
            assert_eq!(a.0, Ipv4Addr::new(127, 0, 0, 1));
            assert_eq!(*rr.name(), Name::from_str("example.com.").unwrap());
            assert_eq!(rr.ttl(), 3600);
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_invalid_record_type() {
        let answer = DnsJsonAnswer {
            name: "example.com.".to_string(),
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
            name: "example.com.".to_string(),
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
