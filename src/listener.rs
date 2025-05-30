use std::{
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable},
};

use crate::{
    cache::Cache, config::SwiftConfig, domain::DnsName, error::DnsError, filter, http::Client,
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
    cache: &mut Cache,
) -> Result<Message, DnsError> {
    let mut response = create_response_base(message);

    // RFC 1035 allows multiple queries per message for forward compatibility.
    // This feature is not implemented or used in practice
    // and poses security risks (DNS amplification).
    // This implementation supports only single-query messages.
    if message.queries().len() != 1 {
        response.set_response_code(ResponseCode::FormErr);
        return Ok(response);
    }

    let query = message.queries().first().unwrap();

    let domain: DnsName = ok_or_rcode!(
        query.name().to_string().parse(),
        mut response,
        ResponseCode::FormErr
    );

    if let Some(filter) = filter::blacklist::find(&domain.name()) {
        eprintln!("{}", filter.format_log_message(&domain));
        response.set_response_code(ResponseCode::Refused);
        return Ok(response);
    }

    if let Some(cached_response) = cache.get(query.name(), query.query_type()) {
        response.set_response_code(cached_response.response_code());

        response.insert_answers(cached_response.answers().to_vec());
        response.insert_name_servers(cached_response.name_servers().to_vec());
        response.insert_additionals(cached_response.additionals().to_vec());
        return Ok(response);
    }

    let resolved_response = upstream::resolve(client, config, message).await?;

    cache.insert(query.name(), query.query_type(), &resolved_response);

    Ok(resolved_response)
}

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    let client = Client::connect(config).await?;
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

        if !src.ip().is_loopback() {
            eprintln!("Received non-local request from {src}");
            continue;
        }

        if let Ok(message) = Message::from_bytes(&buf[..amt]) {
            match handle_message(&message, &client, config, &mut cache).await {
                Ok(response) => {
                    socket.send_to(&response.to_bytes()?, src)?;
                }
                Err(why) => {
                    eprintln!("Error resolving query: {}", why);

                    let mut error_response = create_response_base(&message);

                    error_response.set_response_code(why.response_code());

                    error_response.insert_answers(vec![]);
                    error_response.insert_name_servers(vec![]);
                    error_response.insert_additionals(vec![]);

                    socket.send_to(&error_response.to_bytes()?, src)?;
                }
            }
        } else {
            eprintln!("Failed to parse DNS message from {src}");
        }
    }
}
