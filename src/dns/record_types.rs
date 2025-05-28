use std::convert::{TryFrom, TryInto};
use std::{fmt::Display, str::FromStr};

use anyhow::{anyhow, Result};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use strum::{EnumIter, IntoEnumIterator};

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, EnumIter)]
#[allow(clippy::upper_case_acronyms)]
pub enum SupportedRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    SRV,
    SOA,
    TXT,
    PTR,
}

impl SupportedRecordType {
    pub fn value(&self) -> u16 {
        RecordType::from(*self).into()
    }

    /// Returns all supported record types
    pub fn all() -> &'static [SupportedRecordType] {
        &[
            Self::A,
            Self::AAAA,
            Self::CNAME,
            Self::MX,
            Self::NS,
            Self::SRV,
            Self::SOA,
            Self::TXT,
            Self::PTR,
        ]
    }

    /// Check if the record data is supported by our implementation.
    ///
    /// Even though we support the record type, the data might not be supported.
    /// For example, we might support RRSIG records, but not all RRSIG data.
    pub fn supports_record_data(&self, record: &Record) -> bool {
        match (self, record.data()) {
            (Self::A, RData::A(_)) => true,
            (Self::AAAA, RData::AAAA(_)) => true,
            (Self::CNAME, RData::CNAME(_)) => true,
            (Self::MX, RData::MX(_)) => true,
            (Self::NS, RData::NS(_)) => true,
            (Self::SRV, RData::SRV(_)) => true,
            (Self::SOA, RData::SOA(_)) => true,
            (Self::TXT, RData::TXT(_)) => true,
            (Self::PTR, RData::PTR(_)) => true,
            _ => false,
        }
    }

    /// Extract data from a DNS record according to its type
    pub fn format_data(&self, record: &Record) -> Result<String, &'static str> {
        let formatted = match (self, record.data()) {
            (Self::A, RData::A(ip)) => ip.to_string(),
            (Self::AAAA, RData::AAAA(ip)) => ip.to_string(),
            (Self::CNAME, RData::CNAME(name)) => name.to_string(),
            (Self::MX, RData::MX(mx)) => mx.to_string(),
            (Self::NS, RData::NS(ns)) => ns.to_string(),
            (Self::PTR, RData::PTR(ptr)) => ptr.to_string(),
            (Self::SOA, RData::SOA(soa)) => soa.to_string(),
            (Self::SRV, RData::SRV(srv)) => srv.to_string(),
            (Self::TXT, RData::TXT(txt)) => txt.to_string(),
            _ => return Err("Mismatched RData type for record"),
        };
        Ok(formatted)
    }

    /// Parse a string into DNS record data according to its type
    pub fn parse_data(&self, data: &str, name: Name, ttl: u32) -> Result<Record> {
        match self {
            Self::A => {
                let ip = data.parse()?;
                Ok(Record::from_rdata(name, ttl, RData::A(ip)))
            }
            Self::AAAA => {
                let ip = data.parse()?;
                Ok(Record::from_rdata(name, ttl, RData::AAAA(ip)))
            }
            Self::CNAME => {
                let cname = Name::from_ascii(data)?;
                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(cname)),
                ))
            }
            Self::MX => {
                // Parse MX record format: "preference exchange"
                let parts: Vec<&str> = data.splitn(2, ' ').collect();
                if parts.len() != 2 {
                    return Err(anyhow!("Invalid data format for MX record"));
                }
                let preference = u16::from_str(parts[0])?;
                let exchange = Name::from_ascii(parts[1])?;

                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::MX(hickory_proto::rr::rdata::MX::new(preference, exchange)),
                ))
            }
            Self::NS => {
                let ns_name = Name::from_ascii(data)?;
                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::NS(hickory_proto::rr::rdata::NS(ns_name)),
                ))
            }
            Self::PTR => {
                let ptr_name = Name::from_ascii(data)?;
                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::PTR(hickory_proto::rr::rdata::PTR(ptr_name)),
                ))
            }
            Self::SOA => {
                // Parse SOA record format: "mname rname serial refresh retry expire minimum"
                let soa_parts: Vec<&str> = data.split_whitespace().collect();
                if soa_parts.len() < 6 {
                    return Err(anyhow!("Invalid data format for SOA record"));
                }

                let mname = Name::from_ascii(soa_parts[0])?;
                let rname = Name::from_ascii(soa_parts[1])?;
                let serial = u32::from_str(soa_parts[2])?;
                let refresh = u32::from_str(soa_parts[3])?;
                let retry = u32::from_str(soa_parts[4])?;
                let expire = u32::from_str(soa_parts[5])?;
                let minimum = u32::from_str(soa_parts.get(6).unwrap_or(&"0"))?;

                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::SOA(hickory_proto::rr::rdata::SOA::new(
                        mname.try_into().unwrap(),
                        rname.try_into().unwrap(),
                        serial,
                        refresh.try_into().unwrap(),
                        retry.try_into().unwrap(),
                        expire.try_into().unwrap(),
                        minimum,
                    )),
                ))
            }
            Self::SRV => {
                // Parse SRV record format: "priority weight port target"
                let parts: Vec<&str> = data.split_whitespace().collect();
                if parts.len() != 4 {
                    return Err(anyhow!("Invalid data format for SRV record"));
                }

                let priority = u16::from_str(parts[0])?;
                let weight = u16::from_str(parts[1])?;
                let port = u16::from_str(parts[2])?;
                let target = Name::from_ascii(parts[3])?;

                Ok(Record::from_rdata(
                    name,
                    ttl,
                    RData::SRV(hickory_proto::rr::rdata::SRV::new(
                        priority, weight, port, target,
                    )),
                ))
            }
            Self::TXT => {
                let clean_data = if data.starts_with('"') && data.ends_with('"') && data.len() > 1 {
                    &data[1..data.len() - 1] // Remove surrounding quotes
                } else {
                    data
                };
                let txt_data = hickory_proto::rr::rdata::TXT::new(vec![clean_data.to_string()]);
                Ok(Record::from_rdata(name, ttl, RData::TXT(txt_data)))
            }
        }
    }
}

impl Display for SupportedRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", RecordType::from(*self))
    }
}

impl From<SupportedRecordType> for RecordType {
    fn from(rt: SupportedRecordType) -> Self {
        match rt {
            SupportedRecordType::A => Self::A,
            SupportedRecordType::AAAA => Self::AAAA,
            SupportedRecordType::CNAME => Self::CNAME,
            SupportedRecordType::MX => Self::MX,
            SupportedRecordType::NS => Self::NS,
            SupportedRecordType::SRV => Self::SRV,
            SupportedRecordType::SOA => Self::SOA,
            SupportedRecordType::TXT => Self::TXT,
            SupportedRecordType::PTR => Self::PTR,
        }
    }
}

impl TryFrom<RecordType> for SupportedRecordType {
    type Error = &'static str;

    fn try_from(rt: RecordType) -> Result<Self, Self::Error> {
        match rt {
            RecordType::A => Ok(Self::A),
            RecordType::AAAA => Ok(Self::AAAA),
            RecordType::CNAME => Ok(Self::CNAME),
            RecordType::MX => Ok(Self::MX),
            RecordType::NS => Ok(Self::NS),
            RecordType::SRV => Ok(Self::SRV),
            RecordType::SOA => Ok(Self::SOA),
            RecordType::TXT => Ok(Self::TXT),
            RecordType::PTR => Ok(Self::PTR),
            _ => Err("Cannot convert unsupported RecordType to SupportedRecordType"),
        }
    }
}

impl TryFrom<u16> for SupportedRecordType {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        let hickory_type = RecordType::from(value);
        hickory_type.try_into()
    }
}

impl FromStr for SupportedRecordType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.to_lowercase();
        Self::iter()
            .find(|rt| rt.to_string().to_lowercase() == input)
            .ok_or("Invalid record type")
    }
}
