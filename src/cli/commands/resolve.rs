use anyhow::{anyhow, Result};
use clap::Args;
use dns_message_parser::question::{QClass, QType, Question};
use std::time::Instant;

use crate::{
    config::SwiftConfig,
    dns::{self, resolver::DnsRecordType},
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

pub async fn execute(args: ResolveArgs, config: &mut SwiftConfig) -> Result<()> {
    if args.tor {
        config.tor.enabled = true;
    }

    let name = args.domain.name();
    let mut client = Client::create(config)?;

    if let Some(entry) = filter::blacklist::find(name) {
        println!("{}", entry.format_log_message(&args.domain));
        return Ok(());
    }

    let query_start_time = Instant::now();

    let question = Question {
        domain_name: name.parse()?,
        q_class: QClass::IN,
        q_type: QType::try_from(args.qtype.value())
            .map_err(|value| anyhow!("Failed to parse question type from value: {value}"))?,
    };

    Ok(dns::resolver::resolve(&mut client, config, &question)
        .await
        .map(|response| {
            if response.answer.is_empty() {
                println!("{}: No DNS records found", args.domain);
                return;
            }

            let elapsed = query_start_time.elapsed().as_millis();
            let output = response.format_output().unwrap_or_else(|err| {
                println!("Error: {err}");
                String::new()
            });
            let records_len = response.answer.len();
            let provider = config.get_active_provider();

            println!("Upstream DNS: {} ({})", provider.0, provider.1);
            println!();
            println!("{output}");
            println!(
                "({records_len} {} found, query time: {elapsed}ms)",
                if records_len == 1 {
                    "record"
                } else {
                    "records"
                }
            );
        })?)
}
