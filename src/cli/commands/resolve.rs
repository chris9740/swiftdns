use anyhow::Result;
use clap::Args;
use std::time::Instant;

use crate::{
    config::SwiftConfig,
    dns::{self, message_types::DnsJsonQuestion, resolver::DnsRecordType},
    domain::Domain,
    filter,
    http::Client,
};

#[derive(Args)]
pub struct ResolveArgs {
    #[arg(
        name = "name",
        help = "Domain to resolve",
        required = true,
        value_parser = clap::value_parser!(Domain)
    )]
    pub domain: Domain,

    #[arg(
        name = "type",
        help = "The type of record to query for",
        required = false,
        value_parser = clap::value_parser!(DnsRecordType),
        default_value_t = DnsRecordType::A
    )]
    pub qtype: DnsRecordType,

    #[arg(long = "tor", help = "Route through Tor", action = clap::ArgAction::SetTrue)]
    pub tor: bool,
}

pub async fn execute(args: ResolveArgs, config: &SwiftConfig) -> Result<()> {
    let mut config = config.clone();
    if args.tor {
        config.tor.enabled = true;
    }

    let name = args.domain.name();
    let mut client = Client::create(&config)?;

    if let Some(entry) = filter::blacklist::find(name) {
        println!("{}", entry.format_log_message(&args.domain));
        return Ok(());
    }

    let query_start_time = Instant::now();

    let question = DnsJsonQuestion {
        name: args.domain.name().to_string(),
        qtype: args.qtype.value(),
    };

    Ok(dns::resolver::resolve(&mut client, &config, &question)
        .await
        .map_or_else(
            |err| {
                println!("Error: {err}");
                Err(err)
            },
            |response| {
                if response.answer.is_empty() {
                    println!("{}: No DNS records found", args.domain);
                    return Ok(());
                }

                let elapsed = query_start_time.elapsed().as_millis();
                let output = response.format_output().unwrap_or_else(|err| {
                    println!("Error: {err}");
                    String::new()
                });
                let record_count = response.answer.len();

                let url = url::Url::parse(&config.resolver.url)
                    .expect("Resolver URL should have been validated earlier");

                println!("Upstream DNS: {}", url.host_str().unwrap_or("unknown"));
                println!();
                println!("{output}");
                println!(
                    "({record_count} {} found, query time: {elapsed}ms)",
                    if record_count == 1 {
                        "record"
                    } else {
                        "records"
                    }
                );
                Ok(())
            },
        )?)
}
