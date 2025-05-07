use crate::{
    config::{self, Scope},
    db::create_conn,
    dns::{self, resolver::QueryType},
    domain::Domain,
    filter, http, listener,
    metrics::{self, Format},
};
use anyhow::{anyhow, Result};
use clap::{crate_description, crate_version, ArgAction, Parser, Subcommand};
use colored::Colorize;
use dns_message_parser::question::{QClass, QType, Question};
use std::{
    ffi::OsStr,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Instant,
};

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
        #[arg(
            help = "Specify the scope of the DNS server",
            long = "scope",
            short = 's',
            value_parser = clap::value_parser!(Scope)
        )]
        scope: Option<Scope>,
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
        #[arg(long = "format", short = 'f', help = "The desired output format", default_value_t = Format::Json)]
        format: Format,
        #[arg(long = "reverse", short = 'r', help = "Reverse the order of the output", action = ArgAction::SetTrue)]
        reverse: bool,
        #[arg(
            long = "search",
            short = 's',
            help = "Filter the output by domain name"
        )]
        search: Option<String>,
    },
    #[command(about = "List all filters", name = "filters")]
    ListFilters,
}

pub async fn start() -> Result<()> {
    let args = Cli::parse();

    let mut config = config::get_config()?;

    filter::migrate_filters()?;

    match args.command {
        Commands::Start { address, scope } => {
            let addr = address.unwrap_or(config.address);

            if let Some(scope) = scope {
                config.scope = Some(scope);
            }

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
                q_type: QType::try_from(qtype.value()).map_err(|value| {
                    anyhow!("Failed to parse question type from value: {value}")
                })?,
            };

            dns::resolver::resolve(&mut client, &config, &question)
                .await
                .map(|response| {
                    if response.answer.is_empty() {
                        println!("{domain}: No DNS records found");
                        return;
                    }

                    let elapsed = query_start_time.elapsed().as_millis();

                    let output = response
                        .format_output()
                        .unwrap_or("Error: Could not render response".to_string());

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
                })
        }
        Commands::Metrics {
            format,
            reverse,
            search,
        } => {
            let conn = create_conn()?;
            let mut analytics = metrics::compile_analytics(&conn, search.as_deref())?;

            if reverse {
                analytics.reverse();
            }

            let output = match format {
                Format::Csv => analytics.to_csv()?,
                Format::Json => analytics.to_json()?,
            };

            let mut lock = std::io::stdout().lock();
            lock.write_all(output.as_bytes())?;
            lock.write(b"\n")?;
            lock.flush()?;

            Ok(())
        }
        Commands::ListFilters => {
            let mut filters = filter::load_filters()?;
            filters.sort_by_key(|filter| filter.pathname.clone());

            println!("{}", "Filters".bold());

            for (index, filter) in filters.iter().enumerate() {
                let path = Path::new(&filter.pathname);
                let relative_path = path
                    .iter()
                    .skip_while(|&component| component != OsStr::new("filters"))
                    .skip(1)
                    .collect::<PathBuf>();

                let filter_name = relative_path
                    .file_stem()
                    .map(|name| name.to_string_lossy())
                    .unwrap_or_else(|| relative_path.to_string_lossy());

                let mut v: Vec<char> = filter_name.chars().collect();
                v[0] = v[0].to_uppercase().next().unwrap();
                let filter_name = v.into_iter().collect::<String>();

                println!(
                    " {}) {} {}",
                    index + 1,
                    filter_name,
                    format!("({})", relative_path.display().to_string().italic())
                );
            }

            Ok(())
        }
    }
}
