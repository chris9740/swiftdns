use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::{Name, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};

use crate::{
    cache::Cache,
    config::{Scope, SwiftConfig},
    dns::{self, message_types::DnsJsonQuestion},
    domain::DnsName,
    error::DnsError,
    filter,
    http::Client,
};

async fn handle_query(
    query: &Message,
    client: &mut Client,
    config: &SwiftConfig,
    cache: &mut Cache,
) -> Result<Message, DnsError> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(query.op_code());
    response.set_authoritative(false);
    response.set_truncated(false);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authentic_data(false);
    response.set_checking_disabled(query.checking_disabled());

    let dnssec_requested = if let Some(edns) = query.extensions() {
        edns.flags().dnssec_ok
    } else {
        false
    };

    let requested_buffer_size = if let Some(edns) = query.extensions() {
        edns.max_payload()
    } else {
        512
    };

    if query.extensions().is_some() {
        let opt_rdata = hickory_proto::rr::rdata::OPT::new(vec![]);

        let mut opt_record = hickory_proto::rr::Record::from_rdata(
            Name::root(),
            0,
            hickory_proto::rr::RData::OPT(opt_rdata),
        );

        let response_buffer_size = std::cmp::min(requested_buffer_size, 4096);
        opt_record.set_dns_class(hickory_proto::rr::DNSClass::OPT(response_buffer_size));
        response.add_additional(opt_record);
    }

    for question in query.queries() {
        response.add_query(question.clone());
    }

    // RFC 1035 allows multiple questions per query for forward compatibility.
    // This feature is not implemented or used in practice
    // and poses security risks (DNS amplification).
    // This implementation supports only single-question queries.
    if query.queries().len() != 1 {
        response.set_response_code(ResponseCode::FormErr);
        return Ok(response);
    }

    let question = query.queries().first().unwrap();

    let domain: DnsName = match question.name().to_string().parse() {
        Ok(d) => d,
        Err(err) => {
            eprintln!("Error parsing domain name: {}", err);
            response.set_response_code(ResponseCode::NXDomain);
            return Ok(response);
        }
    };

    if let Some(entry) = filter::blacklist::find(&domain.name()) {
        println!("{}", entry.format_log_message(&domain));
        response.set_response_code(ResponseCode::Refused);
        return Ok(response);
    }

    let qtype = match question.query_type() {
        RecordType::A => dns::resolver::DnsRecordType::A,
        RecordType::AAAA => dns::resolver::DnsRecordType::AAAA,
        RecordType::CNAME => dns::resolver::DnsRecordType::CNAME,
        RecordType::MX => dns::resolver::DnsRecordType::MX,
        RecordType::TXT => dns::resolver::DnsRecordType::TXT,
        RecordType::SOA => dns::resolver::DnsRecordType::SOA,
        RecordType::NS => dns::resolver::DnsRecordType::NS,
        RecordType::SRV => dns::resolver::DnsRecordType::SRV,
        RecordType::PTR => dns::resolver::DnsRecordType::PTR,
        RecordType::RRSIG => dns::resolver::DnsRecordType::RRSIG,
        _ => {
            response.set_response_code(ResponseCode::ServFail);
            return Ok(response);
        }
    };

    let question = DnsJsonQuestion {
        name: question.name().to_string(),
        qtype: qtype.value(),
        dnssec: Some(dnssec_requested),
    };

    let cached = cache.get(&question)?;

    let api_response = if let Some(cached) = cached.clone() {
        cached.response
    } else {
        let response = dns::resolver::resolve(client, config, &question)
            .await
            .map_err(|e| DnsError::ProviderError(e.to_string()))?;

        if !response.answer.is_empty() || response.authority.is_some() {
            cache.set(question.clone(), response.clone())?;
        }

        response
    };

    let response_bytes = response.to_bytes().map_err(DnsError::ProtoError)?;
    if response_bytes.len() > requested_buffer_size as usize {
        response.set_truncated(true);
    }

    let rcode = ResponseCode::from_low(api_response.status);

    if cached.is_none() && !api_response.answer.is_empty() {
        cache.set(question.clone(), api_response.clone())?;
    }

    for answer in &api_response.answer {
        match dns::records::json_answer_to_rr(answer) {
            Ok(record) => {
                response.add_answer(record);
            }
            Err(err) => {
                eprintln!("Error converting JSON answer to RR: {}", err);
                response.set_response_code(ResponseCode::ServFail);
                return Ok(response);
            }
        }
    }

    if let Some(authority) = &api_response.authority {
        for auth in authority {
            if let Ok(record) = dns::records::json_answer_to_rr(auth) {
                response.add_name_server(record);
            }
        }
    }

    response.set_response_code(rcode);
    response.set_truncated(api_response.tc);
    response.set_recursion_available(api_response.ra);
    response.set_authentic_data(api_response.ad);
    response.set_checking_disabled(api_response.cd);

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

        match Message::from_bytes(&buf[..amt]) {
            Ok(query) => match handle_query(&query, &mut client, config, &mut cache).await {
                Ok(response) => {
                    let response_bytes = response.to_bytes().map_err(DnsError::ProtoError)?;
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
