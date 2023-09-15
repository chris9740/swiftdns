use std::{error::Error, fmt::Display, str::FromStr, io::Write};
use colored::Colorize;
use strum::{EnumIter, IntoEnumIterator};
use tabwriter::TabWriter;

use crate::{config, http};

#[derive(Debug, EnumIter, Clone, Eq, Hash, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    AAAA,
}

impl RecordType {
    pub fn value(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::AAAA => 28,
        }
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
        };

        f.write_str(str)
    }
}

impl FromStr for RecordType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for record_type in RecordType::iter() {
            let input = s.to_lowercase();
            let record_type_value = record_type.to_string().to_lowercase();

            if input == record_type_value {
                return Ok(record_type);
            }
        }

        Err("Invalid record type")
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
    pub fn display(&self, record_type: &RecordType) -> Result<String, Box<dyn Error>> {
        let mut tw = TabWriter::new(vec![]);
        let header = vec!["domain", "type", "ttl", "data"];

        let records: String = self.answer
            .clone()
            .into_iter()
            .map(|record| {
                vec![
                    idna::domain_to_unicode(&record.domain_name).0,
                    format!("{} ({})", record_type.to_string(), record_type.value()),
                    format!("{} secs", record.ttl),
                    record.data
                ].join("\t")
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
