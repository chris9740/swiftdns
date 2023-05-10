use std::net::{SocketAddr, UdpSocket};

use cache::Cache;
use dns::RecordType;
use dns_message_parser::{Dns, RCode};
use domain::Domain;
use reqwest;

use clap::{crate_version, Arg, Command};
use serde::Deserialize;

mod cache;
mod dns;
mod domain;
mod filter;

#[tokio::main]
async fn main() {
    let client = reqwest::Client::new();

    let matches = Command::new("swiftdns")
        .version(crate_version!())
        .arg_required_else_help(true)
        .about("A DNS client with blacklisting that resolves from Cloudflare DOH")
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
            let mut cache = Cache::new();

            let debug_addr = "127.0.0.1:5053".parse::<SocketAddr>().unwrap();
            let release_addr = "127.0.0.53:53".parse::<SocketAddr>().unwrap();

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

            let socket = match UdpSocket::bind(addr) {
                Ok(socket) => socket,
                Err(_) => panic!("failed to bind listener on addr `{}`", addr.to_string()),
            };

            println!("Listening on {addr}");

            loop {
                let mut buf = [0; 512];
                let (amt, src) = socket.recv_from(&mut buf).unwrap();
                let mut query = dns::decode(&buf[..amt]).unwrap();

                let question = query.questions.get(0).unwrap();
                let domain = Domain::from(question.domain_name.to_string().as_str());

                let q_type = question.q_type.to_string();
                let record_type: RecordType = q_type.parse().unwrap();

                if let Some(_) = filter::blacklist::find(&domain.name) {
                    let mut flags = query.flags.clone();

                    println!("`{}` has been blacklisted, refusing", &domain.name);

                    flags.rcode = RCode::Refused;

                    let dns = Dns {
                        id: query.id,
                        flags: flags,
                        questions: query.questions,
                        additionals: Vec::new(),
                        answers: Vec::new(),
                        authorities: Vec::new(),
                    };

                    let response = dns::encode(dns).unwrap();

                    socket.send_to(&response, src).unwrap();

                    continue;
                }

                let question = dns::DnsQuestion {
                    name: domain.name.clone(),
                    r#type: record_type.value()
                };

                let cached_response = cache.get(&question);
                let was_cached = cached_response.is_some();

                let response = {
                    if was_cached {
                        let unwrapped = cached_response.unwrap();

                        unwrapped.response.clone()
                    } else {
                        dns::resolve(&client, &domain.name, &record_type).await.unwrap()
                    }
                };

                if !was_cached && response.answer.is_some() {
                    cache.set(question, &response);
                }

                if let Some(answers) = response.answer {
                    query.answers = dns::format_answers(&answers);

                    let encoding_result = dns::encode(query);

                    if let Ok(encoded) = encoding_result {
                        socket.send_to(&encoded, src).unwrap();

                        println!(
                            "successfully resolved `{}` record for `{}` ({})",
                            record_type.to_string(),
                            &domain.name,
                            {
                                if was_cached {
                                    "cached"
                                } else {
                                    "not cached"
                                }
                            }
                        );
                    } else {
                        println!(
                            "notice: silently ignoring resolution of `{}` record for `{}`",
                            record_type.to_string(),
                            &domain.name
                        );
                        println!("debug: {:?}", encoding_result);
                    }
                } else {
                    let mut flags = query.flags.clone();

                    flags.rcode = RCode::NXDomain;

                    let dns = Dns {
                        id: query.id,
                        flags: flags,
                        questions: query.questions,
                        additionals: Vec::new(),
                        answers: Vec::new(),
                        authorities: Vec::new(),
                    };

                    let encoded = dns::encode(dns).unwrap();

                    socket.send_to(&encoded, src).unwrap();

                    println!(
                        "error: no `{}` record exists for {}",
                        record_type.to_string(),
                        domain.name
                    );
                }
            }
        },
        Some(("resolve", resolve_match)) => {
            let domain = resolve_match.get_one::<Domain>("name").unwrap();
            let record_type = resolve_match.get_one::<RecordType>("type").unwrap();

            if let Some(blacklisted) = filter::blacklist::find(&domain.name) {
                println!(
                    "error: the domain `{}` has been blacklisted (pattern `{}`, {}:{}), refusing to resolve.",
                    domain.name,
                    blacklisted.pattern,
                    blacklisted.file,
                    blacklisted.line
                );

                return;
            }

            let response = dns::resolve(&client, &domain.name, &record_type).await.unwrap();

            if let Some(answer) = response.answer {
                let record = answer.last().expect("Answer should have at least 1 entry");

                println!(
                    "success: the `{}` record for `{}` was resolved to {}",
                    record_type.to_string(),
                    domain.name,
                    record.data
                );
            } else {
                println!(
                    "error: no `{}` record exists for {}",
                    record_type.to_string(),
                    domain.name
                );
            }
        }
        _ => panic!("Something went wrong. A subcommand was provided and accepted by clap but not caught by match"),
    }
}
