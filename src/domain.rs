use std::{fmt::Display, str::FromStr};

use anyhow::Result;
use idna::Errors;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Domain(String);

impl FromStr for Domain {
    type Err = DomainError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Domain::new(s)
    }
}

#[derive(Debug, PartialEq)]
pub enum DomainError {
    InvalidCharacter(char),
    InvalidLabel {
        label: String,
        why: String,
    },
    InvalidLength {
        segment: DomainSegment,
        min: usize,
        max: usize,
    },
    FormatError,
}

impl Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainError::InvalidCharacter(c) => write!(f, "Invalid character found: '{}'", c),
            DomainError::InvalidLabel { label, why } => {
                write!(f, "Invalid label '{}': {}", label, why)
            }
            DomainError::InvalidLength { segment, min, max } => write!(
                f,
                "{:?} must be between {} and {} characters in length",
                segment, min, max
            ),
            DomainError::FormatError => write!(f, "Format error in domain name"),
        }
    }
}

impl std::error::Error for DomainError {}

#[derive(Debug, PartialEq)]
pub enum DomainSegment {
    Label,
    Domain,
    TLD,
}

impl From<Errors> for DomainError {
    fn from(_value: Errors) -> Self {
        Self::FormatError
    }
}

impl Domain {
    pub fn new(domain: &str) -> Result<Self, DomainError> {
        let domain = domain.to_lowercase().trim().to_string();

        // Fully qualified domain names (FQDN) end with an extra dot,
        // representing an empty label (e.g. "www.example.com.").
        //
        // We are stripping it, since it's
        // redundant in our application.
        let domain = match domain.strip_suffix('.') {
            Some(s) => s.to_string(),
            None => domain,
        };

        let punycode = idna::domain_to_ascii(&domain)?;

        for c in punycode.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
                return Err(DomainError::InvalidCharacter(c));
            }
        }

        let max_domain_length = 253;
        let max_label_length = 63;

        if punycode.is_empty() || punycode.len() > max_domain_length {
            return Err(DomainError::InvalidLength {
                segment: DomainSegment::Domain,
                min: 1,
                max: max_domain_length,
            });
        }

        let labels: Vec<&str> = punycode.split('.').collect();

        if labels
            .iter()
            .any(|label| label.is_empty() || label.len() > max_label_length)
        {
            return Err(DomainError::InvalidLength {
                segment: DomainSegment::Label,
                min: 1,
                max: max_label_length,
            });
        }

        if let Some(label) = labels
            .iter()
            .find(|label| label.starts_with('-') || label.ends_with('-'))
        {
            return Err(DomainError::InvalidLabel {
                label: label.to_string(),
                why: "A label cannot contain a hyphen at the beginning or end".to_string(),
            });
        }

        let tld = labels.last().unwrap_or(&"");

        if tld.len() < 2 || tld.len() > max_label_length {
            println!("label error!");
            return Err(DomainError::InvalidLength {
                segment: DomainSegment::TLD,
                min: 2,
                max: max_label_length,
            });
        }

        Ok(Domain(punycode))
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    pub fn to_unicode(&self) -> String {
        idna::domain_to_unicode(&self.name()).0
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{Domain, DomainError, DomainSegment};

    #[test]
    fn valid_domain_works() {
        assert_eq!(Domain::new("signal.org.").unwrap().name(), "signal.org");
        assert_eq!(Domain::new("signal.org").unwrap().name(), "signal.org");
    }

    #[test]
    fn invalid_domain_causes_error() {
        assert_eq!(
            Domain::new("tuta_nota.com").unwrap_err(),
            DomainError::InvalidCharacter('_')
        );

        assert_eq!(
            Domain::new("tuta_nota.com").unwrap_err().to_string(),
            "Invalid character found: '_'"
        );

        assert_eq!(
            Domain::new("torproject.o").unwrap_err(),
            DomainError::InvalidLength {
                segment: DomainSegment::TLD,
                min: 2,
                max: 63
            }
        );
    }
}
