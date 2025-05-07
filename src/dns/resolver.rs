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

use crate::{config::SwiftConfig, http};

use super::{
    message_types::{DnsJsonAnswer, DnsJsonResponse},
    provider,
};

#[derive(Debug, EnumIter, Clone, Eq, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    SRV,
    SOA,
    TXT,
}

impl RecordType {
    pub fn value(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
            RecordType::NS => 2,
            RecordType::SRV => 33,
            RecordType::SOA => 6,
            RecordType::TXT => 16,
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        RecordType::iter().find(|r| r.value() == value)
    }

    pub fn construct_rr(&self, answer: &DnsJsonAnswer) -> Result<RR, Box<dyn Error>> {
        let domain_name: DomainName = answer.name.name().parse()?;
        let ttl = answer.ttl;
        let class = Class::IN;
        let data = &answer.data;

        match self {
            RecordType::A => {
                let ipv4_addr = data.parse::<Ipv4Addr>()?;
                Ok(RR::A(rr::A {
                    domain_name,
                    ttl,
                    ipv4_addr,
                }))
            }
            RecordType::AAAA => {
                let ipv6_addr = data.parse::<Ipv6Addr>()?;
                Ok(RR::AAAA(rr::AAAA {
                    domain_name,
                    ttl,
                    ipv6_addr,
                }))
            }
            RecordType::CNAME => {
                let c_name = data.parse::<DomainName>()?;
                Ok(RR::CNAME(rr::CNAME {
                    domain_name,
                    ttl,
                    class: Class::IN,
                    c_name,
                }))
            }
            RecordType::MX => {
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
            RecordType::NS => {
                let ns_d_name = data.parse::<DomainName>()?;

                Ok(RR::NS(rr::NS {
                    domain_name,
                    ttl,
                    class: Class::IN,
                    ns_d_name,
                }))
            }
            RecordType::SRV => {
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
            RecordType::SOA => {
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
            RecordType::TXT => {
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

#[derive(Debug, Clone, Copy, EnumIter)]
pub enum QueryType {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    TXT = 16,
    SOA = 6,
}

impl QueryType {
    pub fn value(&self) -> u16 {
        *self as u16
    }

    pub fn name(&self) -> String {
        format!("{self:#?}")
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        Self::iter().find(|r| r.value() == value)
    }
}

impl FromStr for QueryType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.to_lowercase();
        Self::iter()
            .find(|rt| rt.to_string().to_lowercase() == input)
            .ok_or("Invalid record type")
    }
}

impl TryFrom<&str> for QueryType {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}
impl Display for QueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            RecordType::SRV => "SRV",
            RecordType::SOA => "SOA",
            RecordType::TXT => "TXT",
        };

        f.write_str(str)
    }
}

pub async fn resolve(
    client: &mut http::Client,
    config: &SwiftConfig,
    question: &Question,
) -> Result<DnsJsonResponse> {
    let provider = config.get_active_provider();
    let provider = provider::get_provider(provider.0).expect("Provider not found");

    provider::query(client, provider, question, config).await
}
