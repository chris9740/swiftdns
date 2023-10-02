use std::{
    error::Error,
    io::ErrorKind,
    net::{SocketAddr, UdpSocket},
};

use anyhow::Result;
use dns_message_parser::{Dns, RCode};

use crate::{
    cache::Cache,
    config::SwiftConfig,
    dns::{
        self,
        resolver::{DnsQuestion, RecordType},
    },
    domain::Domain,
    filter,
    http::client::Client,
};

macro_rules! ok_or_rcode {
    ($result:expr, mut $query:expr, $rcode:expr) => {
        match $result {
            Ok(val) => val,
            Err(_) => {
                $query.flags.rcode = $rcode;

                return Ok(());
            }
        }
    };
}

async fn handle_query(
    query: &mut Dns,
    client: &mut Client,
    cache: &mut Cache,
) -> Result<(), Box<dyn Error>> {
    // Multiple questions are *technically* allowed in the protocol, but rarely supported.
    if query.questions.len() != 1 {
        query.flags.rcode = RCode::FormErr;

        return Ok(());
    }

    let question = query.questions.get(0).unwrap();

    let domain: Domain = ok_or_rcode!(
        question.domain_name.to_string().parse(),
        mut query,
        RCode::NXDomain
    );

    let record_type: RecordType = ok_or_rcode!(
        question.q_type.to_string().parse(),
        mut query,
        RCode::NotImp
    );

    if let Some(entry) = filter::blacklist::find(domain.name()) {
        println!("{}", entry.format_message(&domain));

        query.flags.rcode = RCode::Refused;

        return Ok(());
    }

    let question = DnsQuestion {
        name: domain.name().to_string(),
        r#type: record_type.value(),
    };

    let cached = cache.get(&question);

    let response = if let Some(cached) = cached.clone() {
        cached.response
    } else {
        dns::resolver::resolve(client, domain.name(), &record_type).await?
    };

    if !response.answer.is_empty() {
        if cached.is_none() {
            cache.set(question.clone(), &response);
        }

        query.answers = dns::group_answers(&response.answer);
    } else {
        query.flags.rcode = RCode::NXDomain;
    }

    Ok(())
}

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    let mut client = Client::new(config).expect("Should be able to build client wrapper");
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

        match dns::decode(&buf[..amt]) {
            Ok(mut query) => {
                if let Err(why) = handle_query(&mut query, &mut client, &mut cache).await {
                    eprintln!("There was an error while resolving: {}", why);
                    continue;
                }

                let encoded = dns::encode(query)?;
                socket.send_to(&encoded, src)?;
            }
            Err(err) => {
                eprintln!("Error, received invalid query: {}", err);
            }
        }
    }
}
