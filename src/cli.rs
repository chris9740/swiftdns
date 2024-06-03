use crate::{
    config, db::create_conn, dns::{self, resolver::QueryType}, domain::Domain, filter, http, listener, metrics::{self, Format}
};
use anyhow::Result;
use clap::{crate_description, crate_version, ArgAction, Parser, Subcommand};
use dns_message_parser::question::{QClass, QType, Question};
use std::{net::SocketAddr, time::Instant};

#[derive(Parser)]
#[command(
    about = crate_description!(),
    version = crate_version!(),
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Start the DNS listener")]
    Start {
        #[arg(
            help = "Specify the address for the DNS client to listen on",
            long = "address",
            short = 'a',
            value_parser = clap::value_parser!(SocketAddr)
        )]
        address: Option<SocketAddr>,
    },
    #[command(about = "Resolve a domain name")]
    Resolve {
        #[arg(
            name = "name",
            help = "Domain to resolve",
            required = true,
            value_parser = clap::value_parser!(Domain)
        )]
        domain: Domain,
        #[arg(
            name = "type",
            help = "The type of record to query for",
            required = false,
            value_parser = clap::value_parser!(QueryType),
            default_value_t = QueryType::A
        )]
        qtype: QueryType,
        #[arg(long = "tor", help = "Route through Tor", action = ArgAction::SetTrue)]
        tor: bool,
    },
    #[command(about = "Output metrics to stdout as JSON")]
    Metrics {
        #[arg(long = "format", help = "The desired output format", default_value_t = Format::Json)]
        format: Format,
    }
}

pub async fn start() -> Result<()> {
    let args = Cli::parse();

    let mut config = config::get_config()?;

    filter::migrate_filters()?;

    match args.command {
        Commands::Start { address } => {
            let addr = address.unwrap_or(config.address);

            listener::start(&addr, &config).await
        }
        Commands::Resolve { domain, qtype, tor } => {
            if tor {
                config.tor.enabled = true;
            }

            let name = domain.name();
            let mut client = http::Client::create(&config)?;

            if let Some(entry) = filter::blacklist::find(name) {
                println!("{}", entry.format_log_message(&domain));
                return Ok(());
            }

            let query_start_time = Instant::now();

            let question = Question {
                domain_name: name.parse()?,
                q_class: QClass::IN,
                q_type: QType::try_from(qtype.value()).unwrap()
            };

            dns::resolver::resolve(&mut client, &config, &question)
                .await
                .map(|response| {
                    if response.answer.is_empty() {
                        println!("No records found for {}", domain);
                        return;
                    }

                    let elapsed = query_start_time.elapsed().as_millis();

                    let output = response
                        .format_output()
                        .unwrap_or("Error: Could not render response".to_string());

                    let records_len = response.answer.len();

                    println!("Upstream DNS: Cloudflare ({})", config.mode.ip_address());
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
                })
        }
        Commands::Metrics { format } => {
            let conn = create_conn()?;
            let analytics = metrics::compile_analytics(&conn)?;

            let output = match format {
                Format::Csv => analytics.to_csv()?,
                Format::Json => analytics.to_json()?,
            };

            println!("{output}");

            Ok(())
        }
    }
}
