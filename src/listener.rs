use std::{
    io::ErrorKind,
    net::{IpAddr, SocketAddr, UdpSocket},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable},
};

use crate::{
    cache::Cache,
    config::SwiftConfig,
    domain::DnsName,
    error::DnsError,
    filter::{DnsFilter, FilterResult},
    http::Client,
    upstream,
};

fn create_response_base(message: &Message) -> Message {
    let mut response = message.clone();

    response.set_message_type(MessageType::Response);
    response.set_authoritative(false);
    response.set_truncated(false);
    response.set_recursion_available(true);
    response.set_authentic_data(false);

    response
}

async fn handle_message(
    message: &Message,
    client: &Client,
    config: &SwiftConfig,
    filter: &DnsFilter,
    cache: &mut Cache,
) -> Result<Message, DnsError> {
    // RFC 1035 allows multiple queries per message for forward compatibility.
    // This feature is not implemented or used in practice
    // and poses security risks (DNS amplification).
    // This implementation supports only single-query messages.
    if message.queries().len() != 1 {
        let mut response = create_response_base(message);
        response.set_response_code(ResponseCode::FormErr);
        return Ok(response);
    }

    let query = message.queries().first().unwrap();
    let domain: DnsName = match query.name().to_string().parse() {
        Ok(domain) => domain,
        Err(_) => {
            let mut response = create_response_base(message);
            response.set_response_code(ResponseCode::FormErr);
            return Ok(response);
        }
    };

    if let FilterResult::Block(rule) = filter.check_domain(&domain.name()) {
        eprintln!(
            "Query for {} refused (pattern `{}`, path `{}`)",
            domain.name(),
            rule.original_pattern(),
            rule.path()
        );
        let mut response = create_response_base(message);
        response.set_response_code(ResponseCode::Refused);
        return Ok(response);
    }

    let mut cached = false;

    let upstream_response = match cache.get(query.name(), query.query_type()) {
        Some(cached_response) => {
            cached = true;
            cached_response
        }
        None => upstream::resolve(client, config, message).await?,
    };

    if !cached {
        cache.insert(query.name(), query.query_type(), &upstream_response);
    }

    let mut response = create_response_base(message);
    response.set_response_code(upstream_response.response_code());
    response.add_answers(upstream_response.answers().to_vec());
    response.add_name_servers(upstream_response.name_servers().to_vec());
    response.add_additionals(upstream_response.additionals().to_vec());

    Ok(response)
}

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    let filter = DnsFilter::from_default_path()?;
    let client = Client::connect(config).await?;
    let mut cache = Cache::new(1000);

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

        if !is_local_ip(&src.ip()) {
            eprintln!("Received non-local request from {src}");
            continue;
        }

        if let Ok(message) = Message::from_bytes(&buf[..amt]) {
            match handle_message(&message, &client, config, &filter, &mut cache).await {
                Ok(response) => {
                    socket.send_to(&response.to_bytes()?, src)?;
                }
                Err(why) => {
                    eprintln!("Error resolving query: {}", why);
                    let mut error_response = create_response_base(&message);
                    error_response.set_response_code(why.response_code());
                    socket.send_to(&error_response.to_bytes()?, src)?;
                }
            }
        } else {
            eprintln!("Received invalid DNS message from {src}");
        }
    }
}

fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
