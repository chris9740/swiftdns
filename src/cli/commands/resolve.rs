use anyhow::Result;
use clap::Args;
use colored::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{rdata, Name, RData, Record, RecordType},
};
use std::{
    io::Write,
    net::IpAddr,
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tabwriter::TabWriter;
use url::Url;

use crate::{
    config::SwiftConfig,
    domain::DnsName,
    filter::{DnsFilter, FilterResult},
    hosts,
    http::Client,
    upstream,
};

#[derive(Args)]
pub struct ResolveArgs {
    #[arg(
        name = "name",
        help = "Domain to resolve",
        required = true,
        value_parser = clap::value_parser!(DnsName)
    )]
    pub domain: DnsName,

    #[arg(
        name = "type",
        help = "The type of record to query for",
        required = false,
        value_parser = clap::value_parser!(RecordType),
        default_value = "A",
        default_value_t = RecordType::A,
    )]
    pub qtype: RecordType,

    #[arg(long = "tor", help = "Route through Tor", action = clap::ArgAction::SetTrue)]
    pub tor: bool,
}

pub async fn execute(args: ResolveArgs, config: &SwiftConfig) -> Result<()> {
    let mut config = config.clone();
    let hosts_map = hosts::parse_hosts_file()?;

    if config.hosts.enabled {
        if let Some(ips) = hosts_map.get(&args.domain) {
            let name = Name::from_str(&args.domain.name()).unwrap();
            let mut rows = Vec::new();

            match args.qtype {
                RecordType::A => {
                    for ip in ips {
                        if let IpAddr::V4(v4) = ip {
                            rows.push(Record::from_rdata(name.clone(), 0, RData::A(rdata::A(*v4))));
                        }
                    }
                }
                RecordType::AAAA => {
                    for ip in ips {
                        if let IpAddr::V6(v6) = ip {
                            rows.push(Record::from_rdata(
                                name.clone(),
                                0,
                                RData::AAAA(rdata::AAAA(*v6)),
                            ));
                        }
                    }
                }
                _ => {}
            }

            if rows.is_empty() {
                println!("{}: No {} records found", args.domain, args.qtype);
            } else {
                print_record_table(&rows)?;
            }
            return Ok(());
        }
    }

    if args.tor {
        config.tor.enabled = true;
    }

    let filter = if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        DnsFilter::from_mock_data()
    } else {
        DnsFilter::from_default_path().await?
    };

    if let FilterResult::Block(entry) = filter.check_domain(&args.domain.name()).await {
        eprintln!(
            "Query for {} refused (pattern `{}`, path `{}`)",
            args.domain.name(),
            entry.original_pattern().yellow(),
            entry.path().green()
        );
        return Ok(());
    }

    let client = Client::connect(&config).await?;
    let start = Instant::now();

    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u16;

    let mut message = Message::new();
    message.set_id(id);
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);
    message.add_query(Query::query(
        Name::from_str(&args.domain.name())?,
        args.qtype,
    ));

    let upstream_url = if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        "https://dns.swiftdns.mock/dns-query"
    } else {
        &config.resolver.url
    };

    let response = upstream::resolve(&client, &config, &message).await?;
    let duration_ms = start.elapsed().as_millis();

    match response.response_code() {
        ResponseCode::NXDomain => {
            println!("{}: Domain does not exist", args.domain);
            return Ok(());
        }
        ResponseCode::ServFail => {
            println!("{}: Server failure", args.domain);
            return Ok(());
        }
        ResponseCode::Refused => {
            println!("{}: Query refused", args.domain);
            return Ok(());
        }
        ResponseCode::NoError => { /* continue */ }
        other => {
            println!("{}: DNS error: {:?}", args.domain, other);
            return Ok(());
        }
    }

    if response.answers().is_empty() {
        println!("{}: No {} records found", args.domain, args.qtype);
        return Ok(());
    }

    let url = Url::parse(upstream_url)?;
    println!("Upstream DNS: {}\n", url.host_str().unwrap_or("unknown"));
    print_record_table(response.answers())?;

    let count = response.answers().len();
    println!(
        "\n({count} {} found, query time: {}ms)",
        if count == 1 { "record" } else { "records" },
        duration_ms
    );

    Ok(())
}

fn print_record_table(records: &[Record]) -> anyhow::Result<()> {
    let headers = ["domain", "type", "ttl", "data"];

    let mut tw = TabWriter::new(Vec::new());
    writeln!(
        tw,
        "{}\t{}\t{}\t{}",
        headers[0], headers[1], headers[2], headers[3]
    )?;
    for rec in records {
        writeln!(
            tw,
            "{}\t{} ({})\t{}\t{}",
            rec.name(),
            rec.record_type(),
            u16::from(rec.record_type()),
            rec.ttl(),
            rec.data()
        )?;
    }

    tw.flush()?;

    let output = String::from_utf8(tw.into_inner()?)?;
    let mut lines = output.lines();
    if let Some(header_line) = lines.next() {
        let mut colored_header = header_line.to_string();
        for header in &headers {
            colored_header = colored_header.replace(
                header,
                &header.on_truecolor(190, 190, 190).black().to_string(),
            );
        }
        println!("{}", colored_header);
    }
    for line in lines {
        println!("{}", line);
    }

    Ok(())
}
