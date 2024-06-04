use std::{fmt::Display, str::FromStr};

use anyhow::Result;
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
    FormatError(String),
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
            DomainError::FormatError(why) => write!(f, "Format error in domain name: {why}"),
        }
    }
}

impl std::error::Error for DomainError {}

#[derive(Debug, PartialEq)]
pub enum DomainSegment {
    Domain,
    Label,
    TLD,
}

impl From<idna::Errors> for DomainError {
    fn from(_: idna::Errors) -> Self {
        Self::FormatError("domain format error".to_string())
    }
}

impl Domain {
    pub fn new(domain: &str) -> Result<Self, DomainError> {
        let domain = domain.to_lowercase();
        let domain = domain.trim();

        // Fully qualified domain names (FQDN) end with an extra dot,
        // representing an empty label (e.g. "www.example.com.").
        //
        // We are stripping it, since it's
        // redundant in our application.
        let domain = domain.strip_suffix('.').unwrap_or(domain);

        let ascii_domain = idna::domain_to_ascii(domain)?;

        for c in ascii_domain.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' {
                return Err(DomainError::InvalidCharacter(c));
            }
        }

        let max_domain_length = 253;
        let max_label_length = 63;

        if ascii_domain.is_empty() || ascii_domain.len() > max_domain_length {
            return Err(DomainError::InvalidLength {
                segment: DomainSegment::Domain,
                min: 1,
                max: max_domain_length,
            });
        }

        let labels: Vec<&str> = ascii_domain.split('.').collect();

        if labels.len() < 2 {
            return Err(DomainError::FormatError("a fully-qualified domain name must have two or more labels".to_string()))
        }

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
                why: "A label cannot contain a leading or trailing hyphen".to_string(),
            });
        }

        let tld = labels.last().unwrap_or(&"");

        if tld.len() < 2 || tld.len() > max_label_length {
            return Err(DomainError::InvalidLength {
                segment: DomainSegment::TLD,
                min: 2,
                max: max_label_length,
            });
        }

        Ok(Domain(ascii_domain))
    }

    pub fn name(&self) -> &str {
        &self.0
    }

    pub fn to_unicode(&self) -> String {
        idna::domain_to_unicode(&self.0).0
    }
}

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_unicode())
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
    fn unicode_works() {
        let unicode_name = "münich.de";
        let domain = Domain::new(unicode_name).unwrap();

        assert_eq!(domain.name(), "xn--mnich-kva.de");
        assert_eq!(format!("{domain}"), unicode_name);
    }

    #[test]
    fn invalid_domain_causes_error() {
        let invalid_char_err = Domain::new("tuta_nota.com").unwrap_err();

        assert_eq!(invalid_char_err, DomainError::InvalidCharacter('_'));
        assert_eq!(invalid_char_err.to_string(), "Invalid character found: '_'");

        assert_eq!(
            Domain::new("torproject.o").unwrap_err(),
            DomainError::InvalidLength {
                segment: DomainSegment::TLD,
                min: 2,
                max: 63
            }
        );

        assert_eq!(
            Domain::new("www.duckduckgo-.com").unwrap_err(),
            DomainError::InvalidLabel {
                label: String::from("duckduckgo-"),
                why: String::from("A label cannot contain a leading or trailing hyphen")
            }
        )
    }
}
