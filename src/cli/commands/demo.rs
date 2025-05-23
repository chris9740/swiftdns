use anyhow::Result;
use colored::Colorize;

pub use super::resolve::ResolveArgs as DemoArgs;

/// Command to test if a domain would be blocked by the blacklist.
/// Does not perform any DNS resolution.
pub async fn execute(args: DemoArgs) -> Result<()> {
    let name = args.domain.name();

    if let Some(entry) = crate::filter::blacklist::find(&name) {
        println!(
            "{} would be blacklisted by {}:{} (pattern `{}`)",
            name.red(),
            entry.file,
            entry.line,
            entry.pattern
        );
    } else {
        println!("{} is not blacklisted", name.green());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::domain::DnsName;

    #[test]
    fn test_blacklist_detection() {
        let args = DemoArgs {
            domain: DnsName::from_str("example.com").unwrap(),
            tor: false,
            qtype: crate::dns::resolver::DnsRecordType::A,
        };

        let result = tokio_test::block_on(execute(args));
        assert!(result.is_ok());
    }
}
