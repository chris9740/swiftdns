// DNS requests include domains that end with a dot, such as 'google.com.',
// and this function removes any unnecessary dots
fn parse(name: &str) -> String {
    let parsed: Vec<&str> = name.split(".").filter(|label| label.len() > 0).collect();

    parsed.join(".")
}

#[derive(Clone)]
pub struct Domain {
    pub name: String,
}

impl From<&str> for Domain {
    fn from(value: &str) -> Self {
        let name = parse(value);

        Domain { name }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::Domain;

    #[test]
    fn parses_domain() {
        assert_eq!(Domain::from("signal.org.").name, "signal.org");
    }
}
