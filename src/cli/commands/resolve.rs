use anyhow::Result;
use clap::Args;
use colored::*;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use std::io::Write;
use std::{str::FromStr, time::Instant};
use tabwriter::TabWriter;

use crate::{config::SwiftConfig, domain::DnsName, filter, http::Client, upstream};

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
    if args.tor {
        config.tor.enabled = true;
    }

    let client = Client::connect(&config).await?;

    if let Some(entry) = filter::blacklist::find(&args.domain.name()) {
        println!("{}", entry.format_log_message(&args.domain));
        return Ok(());
    }

    let query_start_time = Instant::now();

    let mut message = Message::new();
    message.set_id(rand::random());
    message.set_message_type(MessageType::Query);
    message.set_op_code(OpCode::Query);
    message.set_recursion_desired(true);

    let query = Query::query(Name::from_str(&args.domain.name())?, args.qtype);

    message.add_query(query);

    let upstream_dns = if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        "https://dns.swiftdns.mock/dns-query"
    } else {
        config.resolver.url.as_str()
    };

    let response = upstream::resolve(&client, &config, &message).await?;
    let elapsed = query_start_time.elapsed().as_millis();

    match response.response_code() {
        hickory_proto::op::ResponseCode::NXDomain => {
            println!("{}: Domain does not exist", args.domain);
            return Ok(());
        }
        hickory_proto::op::ResponseCode::ServFail => {
            println!("{}: Server failure", args.domain);
            return Ok(());
        }
        hickory_proto::op::ResponseCode::Refused => {
            println!("{}: Query refused", args.domain);
            return Ok(());
        }
        hickory_proto::op::ResponseCode::NoError => {
            // Continue to check answers
        }
        other => {
            println!("{}: DNS error: {:?}", args.domain, other);
            return Ok(());
        }
    }

    if response.answers().is_empty() {
        println!("{}: No {} records found", args.domain, args.qtype);
        return Ok(());
    }

    let record_count = response.answers().len();
    let url = url::Url::parse(upstream_dns)?;

    println!("Upstream DNS: {}", url.host_str().unwrap_or("unknown"));
    println!();

    let mut tw = TabWriter::new(vec![]);
    let headers = vec!["domain", "type", "ttl", "data"];

    writeln!(tw, "{}", headers.join("\t"))?;

    for record in response.answers() {
        let record_type = record.record_type();
        let name = record.name();
        let ttl = record.ttl();
        let data = record.data();

        writeln!(
            tw,
            "{}\t{} ({})\t{}\t{}",
            name,
            record_type,
            u16::from(record_type),
            ttl,
            data
        )?;
    }

    tw.flush()?;
    let formatted = String::from_utf8(tw.into_inner()?)?;
    let mut lines = formatted.lines();
    if let Some(header_line) = lines.next() {
        let mut colored_header = header_line.to_string();
        for header in &headers {
            colored_header = colored_header.replace(
                header,
                &header.on_truecolor(190, 190, 190).black().to_string(),
            );
        }
        println!("{}", colored_header);

        for line in lines {
            println!("{}", line);
        }
    }

    println!();
    println!(
        "({record_count} {} found, query time: {elapsed}ms)",
        if record_count == 1 {
            "record"
        } else {
            "records"
        }
    );

    Ok(())
}
