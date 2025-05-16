use anyhow::Result;
use colored::Colorize;

pub use super::resolve::ResolveArgs as DemoArgs;

/// Command to test if a domain would be blocked by the blacklist.
/// Does not perform any DNS resolution.
pub async fn execute(args: DemoArgs) -> Result<()> {
    let name = args.domain.name();

    // Check if the domain is blacklisted
    if let Some(entry) = crate::filter::blacklist::find(name) {
        println!(
            "{} would be blacklisted by {}:{} (pattern `{}`)",
            name, entry.file, entry.line, entry.pattern
        );
    } else {
        println!("{} is not blacklisted", name.green());
    }

    Ok(())
}
