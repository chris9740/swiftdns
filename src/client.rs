use std::net::{SocketAddr, UdpSocket};

use chrono::Utc;
use dns_message_parser::{Dns, RCode};

use crate::{
    cache::Cache,
    dns::{self, RecordType},
    domain::Domain,
    filter,
};

pub async fn start(addr: &SocketAddr, client: reqwest::Client) {
    let mut cache = Cache::new();

    let socket = match UdpSocket::bind(addr) {
        Ok(socket) => socket,
        Err(err) => panic!(
            "failed to bind listener on addr `{}` ({})",
            addr.to_string(),
            err
        ),
    };

    info!("listening on {addr}");

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf).unwrap();
        let mut query = dns::decode(&buf[..amt]).unwrap();

        let question = query.questions.get(0).unwrap();
        let domain = Domain::from(question.domain_name.to_string().as_str());

        let q_type = question.q_type.to_string();
        let record_type: RecordType = q_type.parse().unwrap_or(RecordType::A);

        if let Some(entry) = filter::blacklist::find(&domain.name) {
            let mut flags = query.flags.clone();

            info!("{}", entry.format_message(&domain));

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
            r#type: record_type.value(),
        };

        let cached_response = cache.get(&question);
        let was_cached = cached_response.is_some();

        let start_time = Utc::now().time();

        let response = {
            if was_cached {
                let unwrapped = cached_response.unwrap();

                unwrapped.response.clone()
            } else {
                dns::resolve(&client, &domain.name, &record_type)
                    .await
                    .unwrap()
            }
        };

        let end_time = Utc::now().time();
        let total_time = end_time - start_time;

        if !was_cached && response.answer.is_some() {
            cache.set(question, &response);
        }

        if let Some(answers) = response.answer {
            query.answers = dns::format_answers(&answers);

            let encoding_result = dns::encode(query);

            if let Ok(encoded) = encoding_result {
                socket.send_to(&encoded, src).unwrap();

                info!(
                    "successfully resolved `{}` record for `{}` ({}, {}ms)",
                    record_type.to_string(),
                    &domain.name,
                    {
                        if was_cached {
                            "cached"
                        } else {
                            "not cached"
                        }
                    },
                    total_time.num_milliseconds()
                );
            } else {
                warn!(
                    "notice: silently ignoring resolution of `{}` record for `{}`",
                    record_type.to_string(),
                    &domain.name
                );
                debug!("something went wrong when encoding: {:?}", encoding_result);
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

            info!(
                "no `{}` record exists for {}",
                record_type.to_string(),
                domain.name
            );
        }
    }
}
