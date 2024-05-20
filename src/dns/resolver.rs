use colored::Colorize;
use dns_message_parser::{
    rr::{self, Class, RR},
    DomainName,
};
use std::{
    error::Error,
    fmt::Display,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use strum::{EnumIter, IntoEnumIterator};
use tabwriter::TabWriter;

use crate::{config, http};

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
        }
    }

    pub fn from_u16(value: u16) -> Option<Self> {
        RecordType::iter().find(|r| r.value() == value)
    }

    pub fn construct_rr(&self, answer: &DnsAnswer) -> Result<RR, Box<dyn Error>> {
        let domain_name: DomainName = answer.domain_name.parse()?;
        let ttl = answer.ttl;
        let class = Class::IN;
        let data = answer.data.clone(); // TODO: remove need for .clone() somehow (im tired rn)

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
                let exchange = priority_and_domain[1].parse::<DomainName>()?;

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
        }
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
        };

        f.write_str(str)
    }
}

impl FromStr for RecordType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.to_lowercase();
        RecordType::iter()
            .find(|rt| rt.to_string().to_lowercase() == input)
            .ok_or("Invalid record type")
    }
}

impl TryFrom<&str> for RecordType {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        RecordType::from_str(value)
    }
}

#[derive(crate::Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DnsResponse {
    pub status: u8,
    #[serde(rename = "TC")]
    pub tc: bool,
    #[serde(rename = "RD")]
    pub rd: bool,
    #[serde(rename = "RA")]
    pub ra: bool,
    #[serde(rename = "AD")]
    pub ad: bool,
    #[serde(rename = "CD")]
    pub cd: bool,
    pub question: Option<Vec<DnsQuestion>>,
    #[serde(default)]
    pub answer: Vec<DnsAnswer>,
    pub authority: Option<Vec<DnsAnswer>>,
}

impl DnsResponse {
    pub fn display(&self) -> Result<String, Box<dyn Error>> {
        let mut tw = TabWriter::new(vec![]);
        let header = vec!["domain", "type", "ttl", "data"];

        let records: String = self
            .answer
            .clone()
            .into_iter()
            .map(|record| {
                let record_type = match RecordType::from_u16(record.r#type) {
                    Some(r_type) => {
                        format!("{} ({})", r_type.to_string(), r_type.value())
                    }
                    None => "".to_string(),
                };

                vec![
                    idna::domain_to_unicode(&record.domain_name).0,
                    record_type,
                    format!("{} secs", record.ttl),
                    record.data,
                ]
                .join("\t")
            })
            .collect::<Vec<String>>()
            .join("\n");

        write!(&mut tw, "{}\n{records}", header.join("\t"))?;

        tw.flush()?;

        let formatted = String::from_utf8(tw.into_inner()?)?;
        let mut output_splitter = formatted.splitn(2, '\n');
        let mut header_line: String = output_splitter.next().unwrap_or("").to_string();
        let remaining: String = output_splitter.next().unwrap_or("").to_string();

        #[allow(clippy::unnecessary_to_owned)]
        for item in header {
            header_line = header_line.replace(item, &item.on_bright_white().black().to_string());
        }

        Ok(format!("{header_line}\n{remaining}"))
    }
}

#[derive(crate::Deserialize, Debug, Clone)]
pub struct DnsAnswer {
    #[serde(rename = "name")]
    pub domain_name: String,
    pub r#type: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

#[derive(crate::Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct DnsQuestion {
    pub name: String,
    pub r#type: u16,
}

pub async fn resolve(
    client: &mut http::client::Client,
    name: &str,
    record_type: &RecordType,
) -> Result<DnsResponse, Box<dyn Error>> {
    let config = config::get_config()?;
    let resolver_ip = config.mode.ip_address();

    let url = format!(
        "https://{}/dns-query?name={}&type={}&do=1",
        resolver_ip,
        name,
        &record_type.to_string()
    );

    let res = client
        .get(&url)
        .await
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await?;

    let status = res.status();

    if status == reqwest::StatusCode::BAD_REQUEST {
        return Err("Bad request".into());
    }

    let dns_response = res.json::<DnsResponse>().await?;

    Ok(dns_response)
}
