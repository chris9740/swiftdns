use anyhow::Result;
use colored::Colorize;

use crate::filter;

pub use super::resolve::ResolveArgs as DemoArgs;

pub async fn execute(args: DemoArgs) -> Result<()> {
    filter::initialize_filters()?;
    let name = args.domain.name();

    if let Some(entry) = crate::filter::blacklist::find(&name) {
        println!(
            "{} is blacklisted (pattern `{}`)",
            name.red(),
            entry.pattern.yellow(),
        );
    } else {
        println!("{} is not blacklisted", name.green());
    }

    Ok(())
}
