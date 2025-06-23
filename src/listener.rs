use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{IpAddr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, ResponseCode},
    serialize::binary::{BinDecodable, BinEncodable},
};

use crate::{
    blocking::{self, create_response_base},
    cache::Cache,
    config::SwiftConfig,
    domain::DnsName,
    error::DnsError,
    filter::{DnsFilter, FilterResult},
    http::Client,
    upstream,
};

struct BurstTracker {
    registry: HashMap<String, Instant>,
    burst_duration_secs: Duration,
}

impl BurstTracker {
    fn new() -> Self {
        Self {
            registry: HashMap::new(),
            burst_duration_secs: Duration::from_secs(15),
        }
    }

    fn is_bursting(&mut self, key: &str) -> bool {
        let now = Instant::now();

        self.registry
            .retain(|_, &mut t| now.duration_since(t) < self.burst_duration_secs);

        let is_bursting = match self.registry.get_mut(key) {
            Some(ts) if now.duration_since(*ts) < self.burst_duration_secs => true,
            _ => {
                self.registry.insert(key.to_string(), now);
                false
            }
        };

        is_bursting
    }
}

async fn handle_message(
    message: &Message,
    client: &Client,
    config: &SwiftConfig,
    filter: &DnsFilter,
    cache: &mut Cache,
    burst_tracker: &mut BurstTracker,
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

    if let FilterResult::Block(rule) = filter.check_domain(&domain.name()).await {
        if !burst_tracker.is_bursting(&domain.name()) {
            eprintln!(
                "Query for {} refused (pattern `{}`, path `{}`)",
                domain.name(),
                rule.original_pattern(),
                rule.path()
            );
        }

        match blocking::create_blocked_response(message, query.query_type(), &config.blocking) {
            Some(response) => return Ok(response),
            None => {
                return Err(DnsError::Dropped);
            }
        }
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
    let filter = DnsFilter::from_default_path().await?;

    #[cfg(feature = "notify")]
    if let Err(e) = filter.start_watching().await {
        eprintln!("Warning: Failed to start filter file watching: {}", e);
        eprintln!("Filter hot-reloading will not be available");
    }

    let client = Client::connect(config).await?;
    let mut cache = Cache::new(1000);
    let mut burst_tracker = BurstTracker::new();

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
            match handle_message(
                &message,
                &client,
                config,
                &filter,
                &mut cache,
                &mut burst_tracker,
            )
            .await
            {
                Ok(response) => {
                    socket.send_to(&response.to_bytes()?, src)?;
                }
                Err(DnsError::Dropped) => {
                    // Drop strategy - no response sent (this is intentional)
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
