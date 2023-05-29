// Fully qualified domain names (FQDN) end with a seemingly redundant dot,
// representing an empty label (this is to make it unambiguous).
//
// Domains in our filter lists are _partially_ qualified, meaning they don't include
// the empty label at the end, so we will strip it out.
//
// https://en.wikipedia.org/wiki/Fully_qualified_domain_name
fn parse(name: &str) -> &str {
    if !name.ends_with('.') {
        return name;
    }

    let mut chars = name.chars();

    chars.next_back();

    chars.as_str()
}

#[derive(Clone)]
pub struct Domain {
    pub name: String,
}

impl From<&str> for Domain {
    fn from(value: &str) -> Self {
        let name = parse(value);

        Domain {
            name: name.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::Domain;

    #[test]
    fn parses_domain() {
        assert_eq!(Domain::from("signal.org.").name, "signal.org");
        assert_eq!(Domain::from("signal.org").name, "signal.org");
    }
}
