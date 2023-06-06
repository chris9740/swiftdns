use std::{error::Error, fmt::Display, str::FromStr};
use strum::{EnumIter, IntoEnumIterator};

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
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for record_type in RecordType::iter() {
            let input = s.to_lowercase();
            let record_type_value = record_type.to_string().to_lowercase();

            if input == record_type_value {
                return Ok(record_type);
            }
        }

        Err(())
    }

    type Err = ();
}

impl From<&str> for RecordType {
    fn from(value: &str) -> RecordType {
        match RecordType::from_str(value) {
            Ok(record_type) => record_type,
            Err(_) => panic!("Invalid record type `{}`", value),
        }
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
    pub answer: Option<Vec<DnsAnswer>>,
    pub authority: Option<Vec<DnsAnswer>>,
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
    let config = config::get_config().unwrap();
    let resolver_ip = config.mode.ip_address();

    let url = format!(
        "https://{}/dns-query?name={}&type={}&do=1",
        resolver_ip,
        urlencoding::encode(name),
        &record_type.to_string()
    );

    let res = client
        .get(&url)
        .await
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await
        .expect("error: could not query Cloudflare DOH server");

    let status = res.status();

    if status == reqwest::StatusCode::BAD_REQUEST {
        panic!("Bad request");
    }

    let dns_response = res.json::<DnsResponse>().await?;

    Ok(dns_response)
}
