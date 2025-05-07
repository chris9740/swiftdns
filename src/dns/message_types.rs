use std::io::Write as _;

use anyhow::{Context as _, Result};
use colored::Colorize as _;
use serde::Deserialize;
use tabwriter::TabWriter;

use crate::Domain;

use super::resolver::RecordType;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct DnsJsonResponse {
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
    pub question: Option<Vec<DnsJsonQuestion>>,
    #[serde(default)]
    pub answer: Vec<DnsJsonAnswer>,
    pub authority: Option<Vec<DnsJsonAnswer>>,
}

impl DnsJsonResponse {
    pub fn format_output(&self) -> Result<String> {
        let mut tw = TabWriter::new(vec![]);
        let headers = vec!["domain", "type", "ttl", "data"];

        writeln!(tw, "{}", headers.join("\t"))?;

        for record in &self.answer {
            let record_type = RecordType::from_u16(record.rtype).context("Unknown record type")?;

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
            header_line =
                header_line.replace(item, &item.on_truecolor(190, 190, 190).black().to_string());
        }

        Ok(format!("{header_line}\n{remaining}"))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsJsonQuestion {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: u16,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DnsJsonAnswer {
    pub name: Domain,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: u32,
    pub data: String,
}
