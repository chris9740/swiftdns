#[macro_use]
extern crate log;

use std::{error::Error, net::SocketAddr};

use dns::RecordType;
use domain::Domain;
use env_logger::Builder;
use log::LevelFilter;
use reqwest;

use clap::{crate_description, crate_version, Arg, Command};
use serde::Deserialize;

mod cache;
mod client;
mod config;
mod dns;
mod domain;
mod filter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let log_level = if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };

    Builder::new().filter_level(log_level).init();

    config::get_config().expect("Config should be valid");

    let reqw_client = reqwest::Client::new();

    let matches = Command::new("swiftdns")
        .version(crate_version!())
        .arg_required_else_help(true)
        .about(crate_description!())
        .subcommand(
            Command::new("start").about("Start the DNS listener").arg(
                Arg::new("address")
                    .short('a')
                    .long("address")
                    .required(false)
                    .value_parser(clap::value_parser!(SocketAddr))
                    .help("Specify the address for the DNS client to listen on"),
            ),
        )
        .subcommand(
            Command::new("resolve")
                .about("Resolve a domain name")
                .arg(
                    Arg::new("name")
                        .help("Domain to resolve")
                        .value_parser(clap::value_parser!(Domain))
                        .required(true),
                )
                .arg(
                    Arg::new("type")
                        .short('t')
                        .help("The type of record to resolve (A, AAAA)")
                        .default_value("A")
                        .value_parser(clap::value_parser!(RecordType)),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("start", start_match)) => {
            let conf = config::get_config().unwrap();
            let debug_addr = "127.0.0.1:5053".parse::<SocketAddr>().unwrap();
            let release_addr = conf.address;

            let addr = {
                if let Some(specified_addr) = start_match.get_one::<SocketAddr>("address") {
                    specified_addr
                } else {
                    if cfg!(debug_assertions) {
                        &debug_addr
                    } else {
                        &release_addr
                    }
                }
            };

            client::start(addr, reqw_client).await;
        },
        Some(("resolve", resolve_match)) => {
            let domain = resolve_match.get_one::<Domain>("name").unwrap();
            let record_type = resolve_match.get_one::<RecordType>("type").unwrap();

            if let Some(blacklisted) = filter::blacklist::find(&domain.name) {
                info!(
                    "the domain `{}` has been blacklisted (pattern `{}`, {}:{}), refusing to resolve.",
                    domain.name,
                    blacklisted.pattern,
                    blacklisted.file,
                    blacklisted.line
                );

                return Ok(());
            }

            let response = dns::resolve(&reqw_client, &domain.name, &record_type).await.unwrap();

            if let Some(answer) = response.answer {
                let record = answer.last().expect("Answer should have at least 1 entry");

                info!(
                    "the `{}` record for `{}` was resolved to {}",
                    record_type.to_string(),
                    domain.name,
                    record.data
                );
            } else {
                info!(
                    "no `{}` record exists for {}",
                    record_type.to_string(),
                    domain.name
                );
            }
        }
        _ => panic!("Something went wrong. A subcommand was provided and accepted by clap but not caught by match"),
    };

    return Ok(());
}
