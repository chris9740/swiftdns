use anyhow::Result;
use colored::*;
use std::io::Write;
use tabwriter::TabWriter;

use crate::config::SwiftConfig;

pub async fn execute(config: &SwiftConfig) -> Result<()> {
    println!("{}", "SwiftDNS Status".bold().underline());
    println!();

    let mut tw = TabWriter::new(vec![]);

    writeln!(tw, "{}", "Configuration:".bold())?;
    writeln!(tw, "  {}:\t{}", "Listening address".cyan(), config.address)?;
    writeln!(tw, "  {}:\t{}", "Resolver URL".cyan(), config.resolver.url)?;

    let bootstrap_ips = config.resolver.bootstrap_ips.clone().unwrap_or_default();
    if !bootstrap_ips.is_empty() {
        let ips = bootstrap_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(tw, "  {}:\t{}", "Bootstrap IPs".cyan(), ips)?;
    }

    writeln!(
        tw,
        "  {}:\t{}",
        "Tor enabled".cyan(),
        if config.tor.enabled {
            format!("Yes ({})", config.tor.get_address()?)
        } else {
            "No".to_string()
        }
    )?;

    tw.flush()?;
    let formatted_output = String::from_utf8(tw.into_inner()?)?;
    println!("{}", formatted_output);

    Ok(())
}
