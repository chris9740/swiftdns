use serde::Deserialize;
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone)]
pub enum DnsName {
    Domain(Domain),    // Regular domains with validation
    Authority(String), // Authority names (less strict)
    Root,              // The root domain "."
}

impl FromStr for DnsName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();

        if trimmed == "." {
            return Ok(DnsName::Root);
        }

        if let Ok(domain) = Domain::from_str(s) {
            return Ok(DnsName::Domain(domain));
        }

        let authority = trimmed.strip_suffix('.').unwrap_or(trimmed);
        Ok(DnsName::Authority(authority.to_string()))
    }
}

impl Display for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsName::Domain(d) => write!(f, "{}", d.name()),
            DnsName::Authority(a) => write!(f, "{}", a),
            DnsName::Root => write!(f, "."),
        }
    }
}

impl<'de> Deserialize<'de> for DnsName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DnsName::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl DnsName {
    /// Converts the DNS name to its unicode format for display
    pub fn to_unicode(&self) -> String {
        match self {
            DnsName::Domain(d) => d.to_unicode(),
            DnsName::Authority(a) => {
                if a.contains('.') {
                    idna::domain_to_unicode(a).0
                } else {
                    a.clone()
                }
            }
            DnsName::Root => ".".to_string(),
        }
    }

    /// Returns the raw name (punycode for domains, as-is for others)
    pub fn name(&self) -> String {
        match self {
            DnsName::Domain(d) => d.name().to_string(),
            DnsName::Authority(a) => a.clone(),
            DnsName::Root => ".".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Domain(String);

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

impl FromStr for Domain {
    type Err = DomainError;

    /// Tries to create a new `Domain` from a given string.
    /// Validates the domain string for adherence to DNS naming conventions, including checks for:
    /// - Character validity: Only alphanumeric characters, hyphens, and dots are allowed.
    /// - Length constraints: The entire domain must not exceed 253 characters, and individual labels must not exceed 63 characters.
    /// - Label rules: Labels must not start or end with a hyphen and must contain at least one character.
    /// - Fully-qualified domains: Domains are expected to have at least two labels to be considered fully-qualified.
    ///
    /// # Errors
    /// Returns `Err` with `DomainError` detailing the specific reason for validation error.
    ///
    /// # Examples
    /// Basic usage:
    /// ```no_run
    /// # use swiftdns::Domain;
    /// # use std::str::FromStr;
    /// let domain = Domain::from_str("example.com.").unwrap();
    /// assert_eq!(domain.name(), "example.com");
    /// ```
    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        let domain = s.to_lowercase();
        let domain = domain.trim();

        if s == "." {
            return Ok(Domain(".".to_string()));
        }

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
            return Err(DomainError::FormatError(
                "a fully-qualified domain name must have two or more labels".to_string(),
            ));
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
}

impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Domain::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Domain {
    /// Returns the punycode version of this domain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use swiftdns::Domain;
    /// # use std::str::FromStr;
    /// let domain = Domain::from_str("hälsa.se").unwrap();
    ///
    /// assert_eq!(domain.name(), "xn--hlsa-loa.se");
    /// ```
    pub fn name(&self) -> &str {
        &self.0
    }

    /// Converts and returns the domain name to its unicode format.
    ///
    /// This method is useful when the domain name needs to be displayed in a human-friendly format,
    /// especially if the domain name contains international characters.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use swiftdns::Domain;
    /// # use std::str::FromStr;
    /// let domain = Domain::from_str("xn--hlsa-loa.se").unwrap();
    ///
    /// assert_eq!(domain.to_unicode(), "hälsa.se".to_string());
    /// ```
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
    use std::str::FromStr;

    use crate::domain::{Domain, DomainError, DomainSegment};

    #[test]
    fn valid_domain_works() {
        assert_eq!(
            Domain::from_str("signal.org.").unwrap().name(),
            "signal.org"
        );
        assert_eq!(Domain::from_str("signal.org").unwrap().name(), "signal.org");
    }

    #[test]
    fn unicode_works() {
        let unicode_name = "münich.de";
        let punycode_name = "xn--mnich-kva.de";
        let domain = Domain::from_str(unicode_name).unwrap();

        assert_eq!(domain.name(), punycode_name);
        assert_eq!(format!("{domain}"), unicode_name);
        assert_eq!(
            Domain::from_str(punycode_name).unwrap().to_unicode(),
            unicode_name
        );
    }

    #[test]
    fn invalid_domain_causes_error() {
        let invalid_char_err = Domain::from_str("tuta_nota.com").unwrap_err();

        assert_eq!(invalid_char_err, DomainError::InvalidCharacter('_'));
        assert_eq!(invalid_char_err.to_string(), "Invalid character found: '_'");

        assert_eq!(
            Domain::from_str("torproject.o").unwrap_err(),
            DomainError::InvalidLength {
                segment: DomainSegment::TLD,
                min: 2,
                max: 63
            }
        );

        assert_eq!(
            Domain::from_str("www.duckduckgo-.com").unwrap_err(),
            DomainError::InvalidLabel {
                label: String::from("duckduckgo-"),
                why: String::from("A label cannot contain a leading or trailing hyphen")
            }
        )
    }
}
