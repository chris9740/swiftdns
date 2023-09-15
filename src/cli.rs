use chrono::Local;
use clap::{Parser, Subcommand, ArgAction, crate_description, crate_version};
use crate::{Domain, RecordType, listener, filter, http, dns, config};
use std::net::SocketAddr;

#[derive(Parser)]
#[command(
    about = crate_description!(),
    version = crate_version!(),
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands
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
        address: Option<SocketAddr>
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
        #[arg(long = "type", short = 't', default_value = "A", value_parser = clap::value_parser!(RecordType))]
        record_type: RecordType,
        #[arg(long = "tor", help = "Use tor", action = ArgAction::SetTrue)]
        tor: bool,
    }
}

pub async fn parse_args() {
    let args = Cli::parse();

    let mut config = config::get_config().unwrap_or_else(|err| {
        error!("Error while loading config: {}", err);
    });

    match args.command {
        Commands::Start { address } => {
            let addr = address.unwrap_or({
                config.address
            });

            if let Err(err) = listener::start(&addr, &config).await {
                eprintln!("Error: {}", err);
            }
        },
        Commands::Resolve { domain, record_type, tor } => {
            if tor {
                config.tor = true;
            }

            let domain_name = domain.name();
            let mut http_client = http::client::Client::new(&config).expect("Should be able to build client wrapper");

            if let Some(entry) = filter::blacklist::find(domain_name) {
                println!("{}", entry.format_message(&domain));
                return;
            }

            let start_time = Local::now().time();

            match dns::resolver::resolve(&mut http_client, domain_name, &record_type).await {
                Ok(response) => {
                    if response.answer.is_empty() {
                        println!("No records found for {}", domain_name);
                        return;
                    }

                    let end_time = Local::now().time();
                    let total_time = end_time - start_time;

                    let output = response.display(&record_type).unwrap_or("Error: Could not render response".to_string());

                    let records_len = response.answer.len();
                    let ms = total_time.num_milliseconds();

                    println!("{output}");
                    println!("\n({records_len} {} found, query time: {ms}ms)", if records_len == 1 { "record" } else { "records" });
                },
                Err(err) => {
                    error!("Error, could not resolve domain: {}", err);
                }
            }
        }
    };
}
