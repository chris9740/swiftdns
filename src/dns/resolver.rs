use anyhow::{Context, Result};
use colored::Colorize;
use dns_message_parser::{
    question::Question,
    rr::{self, Class, RR},
    DomainName,
};
use serde::Deserialize;
use std::{
    error::Error,
    fmt::Display,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use strum::{EnumIter, IntoEnumIterator};
use tabwriter::TabWriter;

use crate::{config::SwiftConfig, domain::Domain, http};

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

    pub fn construct_rr(&self, answer: &ApiAnswer) -> Result<RR, Box<dyn Error>> {
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
        };

        f.write_str(str)
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ApiResponse {
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
    pub question: Option<Vec<ApiQuestion>>,
    #[serde(default)]
    pub answer: Vec<ApiAnswer>,
    pub authority: Option<Vec<ApiAnswer>>,
}

impl ApiResponse {
    pub fn format_output(&self) -> Result<String> {
        let mut tw = TabWriter::new(vec![]);
        let headers = vec!["domain", "type", "ttl", "data"];

        writeln!(tw, "{}", headers.join("\t"))?;

        for record in &self.answer {
            let record_type =
                RecordType::from_u16(record.rtype).context("Unknown record type")?;

            write!(tw, "{}\t", record.name.to_unicode())?;
            write!(tw, "{} ({})\t", record_type, record_type.value())?;
            write!(tw, "{}\t", record.ttl)?;
            write!(tw, "{}", record.data)?;
            writeln!(tw)?;
        }

        tw.flush()?;

        let formatted = String::from_utf8(tw.into_inner()?)?;
        let mut output_splitter = formatted.splitn(2, '\n');
        let mut header_line: String = output_splitter.next().unwrap_or("").to_string();
        let remaining: String = output_splitter.next().unwrap_or("").to_string();

        for item in headers {
            header_line = header_line.replace(item, &item.on_truecolor(190, 190, 190).black().to_string());
        }

        Ok(format!("{header_line}\n{remaining}"))
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ApiAnswer {
    pub name: Domain,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}

#[derive(Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
pub struct ApiQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: u16,
}

pub async fn resolve(
    client: &mut http::Client,
    config: &SwiftConfig,
    question: &Question,
) -> Result<ApiResponse> {
    let resolver_ip = config.mode.ip_address();

    let url = format!(
        "https://{}/dns-query?name={}&type={}",
        resolver_ip, question.domain_name, question.q_type
    );

    let res = client
        .get(&url)
        .await?
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await?;

    let status = res.status();

    if status == reqwest::StatusCode::BAD_REQUEST {
        anyhow::bail!("Bad request");
    }

    let dns_response = res.json::<ApiResponse>().await?;

    Ok(dns_response)
}
