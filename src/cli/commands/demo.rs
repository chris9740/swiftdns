use anyhow::Result;
use colored::Colorize;

pub use super::resolve::ResolveArgs as DemoArgs;

pub async fn execute(args: DemoArgs) -> Result<()> {
    let name = args.domain.name();

    if let Some(entry) = crate::filter::blacklist::find(name) {
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
