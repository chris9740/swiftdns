use anyhow::Result;
use colored::Colorize;

use crate::filter::{DnsFilter, FilterResult};

pub use super::resolve::ResolveArgs as DemoArgs;

pub async fn execute(args: DemoArgs) -> Result<()> {
    let filter = if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        DnsFilter::from_mock_data()
    } else {
        DnsFilter::from_default_path().await?
    };

    if let FilterResult::Block(rule) = filter.check_domain(&args.domain.name()).await {
        println!(
            "{} is blacklisted {}",
            args.domain.name().red(),
            format!(
                "(matched with `{}`, found in `{}`)",
                rule.original_pattern().yellow(),
                rule.path().green()
            )
            .bright_black()
        );
    } else {
        println!("{} is not blacklisted", args.domain.name().green());
    }

    Ok(())
}
