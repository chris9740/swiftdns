use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
};

use anyhow::Result;
use dns_message_parser::{question::QType, Dns, Flags, RCode};

use crate::{
    cache::Cache,
    config::{Scope, SwiftConfig},
    dns::{self, message_types::DnsJsonQuestion},
    domain::Domain,
    error::DnsError,
    filter,
    http::Client,
};

async fn handle_query(
    query: &Dns,
    client: &mut Client,
    config: &SwiftConfig,
    cache: &mut Cache,
) -> Result<Dns, DnsError> {
    let mut response = query.clone();

    // RFC 1035 allows multiple questions per query for forward compatibility.
    // This feature is not implemented or used in practice
    // and poses security risks (DNS amplification).
    // This implementation supports only single-question queries.
    if query.questions.len() != 1 {
        response.flags.rcode = RCode::FormErr;

        return Ok(response);
    }

    let question = query.questions.first().unwrap();

    let domain: Domain = ok_or_rcode!(
        question.domain_name.to_string().parse(),
        mut response,
        RCode::NXDomain
    );

    if let Some(entry) = filter::blacklist::find(domain.name()) {
        println!("{}", entry.format_log_message(&domain));
        response.flags.rcode = RCode::Refused;

        return Ok(response);
    }

    let cached = cache.get(question)?;

    let api_response = if let Some(cached) = cached.clone() {
        cached.response
    } else {
        dns::resolver::resolve(
            client,
            config,
            &DnsJsonQuestion {
                name: question.domain_name.to_string(),
                qtype: match question.q_type {
                    QType::A => dns::resolver::DnsRecordType::A,
                    QType::AAAA => dns::resolver::DnsRecordType::AAAA,
                    QType::CNAME => dns::resolver::DnsRecordType::CNAME,
                    QType::MX => dns::resolver::DnsRecordType::MX,
                    QType::TXT => dns::resolver::DnsRecordType::TXT,
                    QType::SOA => dns::resolver::DnsRecordType::SOA,
                    _ => dns::resolver::DnsRecordType::ANY,
                }
                .value(),
            },
        )
        .await
        .map_err(|e| DnsError::ProviderError(e.to_string()))?
    };

    let rcode = ok_or_rcode!(
        RCode::try_from(api_response.status),
        mut response,
        RCode::ServFail
    );

    if cached.is_none() && !api_response.answer.is_empty() {
        cache.set(question.clone(), api_response.clone())?;
    }

    response.answers = api_response
        .answer
        .iter()
        .map(|a| dns::records::json_answer_to_rr(a))
        .filter_map(|rr| rr.ok())
        .collect();

    if let Some(authority) = &api_response.authority {
        response.authorities = authority
            .iter()
            .filter_map(|rr| dns::records::json_answer_to_rr(rr).ok())
            .collect();
    }

    response.flags = Flags {
        qr: true,
        aa: false,
        tc: api_response.tc,
        ra: api_response.ra,
        ad: api_response.ad,
        rcode,

        ..query.flags
    };

    Ok(response)
}

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    if std::env::var("SWIFTDNS_TEST_MODE").is_ok() {
        println!("Starting DNS server on {}", addr);

        if config.scope == Some(Scope::Local) {
            println!("Server scope: Local only");
        } else {
            println!("Server scope: All interfaces");
        }

        if config.tor.enabled {
            println!("Tor routing: Enabled");
        }

        return Ok(());
    }

    let mut client = Client::connect(config).await?;
    let mut cache = Cache::new();

    let socket = match UdpSocket::bind(addr) {
        Ok(socket) => socket,
        Err(err) => {
            let suffix = match err.kind() {
                ErrorKind::PermissionDenied => "Permission denied".to_string(),
                ErrorKind::AddrInUse => "Address already in use".to_string(),
                err => format!("binding error ({})", err),
            };

            error!("Failed to bind listener on addr `{addr}` ({suffix})");
        }
    };

    println!("Listening on {addr}");

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf)?;

        if config.scope == Some(Scope::Local) && !src.ip().is_loopback() {
            eprintln!("Received non-local request from {src}");
            continue;
        }

        match Dns::decode(Vec::from(&buf[..amt]).into()).map_err(DnsError::DecodeError) {
            Ok(query) => match handle_query(&query, &mut client, config, &mut cache).await {
                Ok(response) => {
                    let response = Dns {
                        id: response.id,
                        flags: Flags {
                            qr: true,                      // Always true for responses
                            opcode: response.flags.opcode, // Reflect query opcode
                            aa: false,                     // Not authoritative
                            tc: false,                     // No truncation by default
                            rd: response.flags.rd,         // Reflect recursion desired
                            ra: true,                      // Recursion available
                            ad: false,                     // No DNSSEC validation
                            cd: response.flags.cd,         // Reflect checking disabled
                            rcode: response.flags.rcode,   // Reflect response code
                        },
                        additionals: response.additionals,
                        authorities: response.authorities,
                        questions: response.questions,
                        answers: response.answers,
                    };

                    let response_bytes = Dns::encode(&response).map_err(DnsError::EncodeError)?;
                    socket.send_to(&response_bytes, src)?;
                }
                Err(why) => {
                    eprintln!("There was an error while resolving: {}", why);
                    continue;
                }
            },
            Err(err) => {
                eprintln!("Error, received invalid query: {}", err);
            }
        }
    }
}
