use anyhow::Result;
use clap::crate_version;
use colored::*;
use std::io::Write;
use tabwriter::TabWriter;

use crate::config::{get_config_path, SwiftConfig, CONFIG_FILE_NAME};

pub async fn execute(config: &SwiftConfig) -> Result<()> {
    println!("{}", "Swiftdns".bold());
    println!(
        " {}: {} ({})",
        "Version".cyan(),
        crate_version!(),
        env!("GIT_COMMIT_HASH")
    );
    println!();

    let mut tw = TabWriter::new(vec![]);

    writeln!(tw, "{}", "Configuration:".bold())?;

    let config_path = config
        .config_path
        .as_ref()
        .map(|p| {
            p.canonicalize()
                .unwrap_or_else(|_| p.to_path_buf())
                .display()
                .to_string()
        })
        .unwrap_or_else(|| {
            get_config_path()
                .join(CONFIG_FILE_NAME)
                .display()
                .to_string()
        });

    writeln!(tw, "  {}:\t{}", "Config path".cyan(), config_path)?;

    writeln!(tw, "  {}:\t{}", "Listening address".cyan(), config.address)?;

    writeln!(
        tw,
        "  {}:\t{}",
        "Tor enabled".cyan(),
        if config.tor.enabled {
            format!(
                "Yes ({})",
                format!("socks5h://{}", config.tor.get_address()?).bright_black()
            )
        } else {
            "No".to_string()
        }
    )?;

    writeln!(tw, "  {}:\t{}", "Upstream".cyan(), config.resolver.url)?;

    let bootstrap_ips = config.resolver.bootstrap_ips.clone().unwrap_or_default();
    if !bootstrap_ips.is_empty() {
        let ips = bootstrap_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(tw, "   - {}:\t{}", "Bootstrap IPs".cyan(), ips)?;
    }

    tw.flush()?;
    let formatted_output = String::from_utf8(tw.into_inner()?)?;
    print!("{}", formatted_output);

    Ok(())
}
