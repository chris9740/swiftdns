use anyhow::Result;
use colored::Colorize;

use crate::{
    config::SwiftConfig,
    filter::{
        types::{FilterPattern, FilterResult},
        DomainFilter,
    },
};

pub use super::resolve::ResolveArgs as CheckArgs;

pub async fn execute(args: CheckArgs, config: &SwiftConfig) -> Result<()> {
    let filter = if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        DomainFilter::from_mock_data()
    } else {
        DomainFilter::from_config(config).await?
    };

    let format_rule_info = |rule: &FilterPattern| {
        format!(
            "(matched with `{}`, found in `{}`)",
            rule.original_pattern().yellow(),
            rule.path().green()
        )
        .bright_black()
    };

    match filter.check_domain(&args.domain.name()).await {
        FilterResult::Block(rule) => {
            println!(
                "{} is blacklisted {}",
                args.domain.name().red(),
                format_rule_info(&rule)
            );
        }
        FilterResult::Whitelisted(rule) => {
            println!(
                "{} is whitelisted {}",
                args.domain.name().blue(),
                format_rule_info(&rule)
            );
        }
        FilterResult::Allow => {
            println!("{} is not blacklisted", args.domain.name().green());
        }
    }

    Ok(())
}
