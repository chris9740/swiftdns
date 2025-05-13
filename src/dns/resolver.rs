use anyhow::Result;
use dns_message_parser::{
    question::Question,
    rr::{self, Class, NonEmptyVec, RR},
    DomainName,
};
use std::{
    error::Error,
    fmt::Display,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use strum::{EnumIter, IntoEnumIterator};

use crate::{config::SwiftConfig, error::DnsError, http};

use super::{
    message_types::{DnsJsonAnswer, DnsJsonQuestion, DnsJsonResponse},
    provider,
};

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
}

impl DnsRecordType {
    pub fn value(&self) -> u16 {
        *self as u16
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        Self::iter().find(|r| r.value() == value)
    }

    pub fn construct_rr(&self, answer: &DnsJsonAnswer) -> Result<RR, Box<dyn Error>> {
        let domain_name: DomainName = answer.name.name().parse()?;
        let ttl = answer.ttl;
        let class = Class::IN;
        let data = &answer.data;

        match self {
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
                let priority = parts[0].parse::<u16>()?;
                let weight = parts[1].parse::<u16>()?;
                let port = parts[2].parse::<u16>()?;
                let target = parts[3].parse::<DomainName>()?;
                Ok(RR::SRV(rr::SRV {
                    domain_name,
                    ttl,
                    class,
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
                    class,
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
                    class,
                    strings,
                }))
            }
        }
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
    question: &Question,
) -> Result<DnsJsonResponse, DnsError> {
    let provider = config.get_active_provider();
    let provider = provider::get_provider(provider.0).expect("Provider not found");

    provider::query(
        client,
        provider,
        &DnsJsonQuestion {
            name: question.domain_name.to_string(),
            qtype: question
                .q_type
                .to_string()
                .parse::<DnsRecordType>()
                .map_err(|_| DnsError::InvalidRecordType(question.q_type.to_string()))?
                .value(),
        },
        config,
    )
    .await
}
