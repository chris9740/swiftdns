use std::str::FromStr;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct Domain(String, String);

impl FromStr for Domain {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Domain::new(s)
    }
}

impl Domain {
    pub fn new(domain: &str) -> Result<Self> {
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
                return Err(anyhow!(format!("Invalid character found: '{c}'")));
            }
        }

        let max_domain_length = 253;
        let max_label_length = 63;

        if punycode.is_empty() || punycode.len() > max_domain_length {
            return Err(anyhow!(format!(
                "Domain must be between 1 and {max_domain_length} in length"
            )));
        }

        let labels: Vec<&str> = punycode.split('.').collect();

        if labels
            .iter()
            .any(|label| label.is_empty() || label.len() > max_label_length)
        {
            return Err(anyhow!(format!(
                "Each label must be between 1 and {max_label_length} in length"
            )));
        }

        if let Some(label) = labels
            .iter()
            .find(|label| label.starts_with('-') || label.ends_with('-'))
        {
            return Err(anyhow!(format!(
                "A label cannot contain a hyphen at the beginning or end ({label})"
            )));
        }

        let tld = labels.last().unwrap_or(&"");

        if tld.len() < 2 || tld.len() > max_label_length {
            return Err(anyhow!(format!(
                "Domain TLD must be between 2 and {max_label_length} in length"
            )));
        }

        Ok(Domain(punycode, domain))
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::Domain;

    #[test]
    fn valid_works() {
        assert_eq!(Domain::new("signal.org.").unwrap().name(), "signal.org");
        assert_eq!(Domain::new("signal.org").unwrap().name(), "signal.org");
    }

    #[test]
    fn invalid_errors() {
        assert_eq!(
            Domain::new("tuta_nota.com").unwrap_err().to_string(),
            String::from("Invalid character found: '_'")
        );
    }
}
