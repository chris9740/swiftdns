use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{rdata, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Mutex,
};

use crate::{
    blocking::{self, create_response_base},
    cache::Cache,
    config::SwiftConfig,
    domain::DnsName,
    error::DnsError,
    filter::{DnsFilter, FilterResult},
    hosts,
    http::Client,
    upstream,
};

enum MessageResult {
    Response(Message),
    Drop,
}

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

struct DnsContext {
    filter: DnsFilter,
    cache: Arc<Mutex<Cache>>,
    hosts: HashMap<DnsName, Vec<IpAddr>>,
    burst: Arc<Mutex<BurstTracker>>,
    client: Client,
    config: SwiftConfig,
}

impl DnsContext {
    /// Build the filter, cache, hosts table, HTTP client, etc
    async fn new(config: &SwiftConfig) -> Result<Self> {
        let filter = DnsFilter::from_default_path().await?;
        #[cfg(feature = "notify")]
        if let Err(e) = filter.start_watching().await {
            eprintln!("Warning: failed to hot-reload filters: {}", e);
        }

        let client = Client::connect(config).await?;
        let cache = Arc::new(Mutex::new(Cache::new(1000)));
        let burst = Arc::new(Mutex::new(BurstTracker::new()));
        let hosts = hosts::parse_hosts_file()?;

        Ok(DnsContext {
            filter,
            cache,
            hosts,
            burst,
            client,
            config: config.clone(),
        })
    }

    async fn handle_message(&self, message: &Message) -> Result<MessageResult, DnsError> {
        // RFC 1035 allows multiple queries per message for forward compatibility.
        // This feature is not implemented or used in practice
        // and poses security risks (DNS amplification).
        // This implementation supports only single-query messages.
        if message.queries().len() != 1 {
            let mut response = create_response_base(message);
            response.set_response_code(ResponseCode::FormErr);
            return Ok(MessageResult::Response(response));
        }

        let query = message.queries().first().expect("Query should exist");
        let domain: DnsName = match query.name().to_string().parse() {
            Ok(domain) => domain,
            Err(_) => {
                let mut response = create_response_base(message);
                response.set_response_code(ResponseCode::FormErr);
                return Ok(MessageResult::Response(response));
            }
        };

        if query.query_type() == RecordType::ANY {
            let mut response = create_response_base(message);
            response.set_response_code(ResponseCode::NotImp);
            return Ok(MessageResult::Response(response));
        }

        if self.config.hosts.enabled && self.hosts.contains_key(&domain) {
            let ips = self
                .hosts
                .get(&domain)
                .expect("Hosts should contain the domain");
            let mut response = create_response_base(message);
            response.set_response_code(ResponseCode::NoError);

            match query.query_type() {
                RecordType::A => {
                    for ip in ips {
                        if let IpAddr::V4(v4) = ip {
                            let record = Record::from_rdata(
                                query.name().clone(),
                                300,
                                RData::A(rdata::A(*v4)),
                            );
                            response.add_answer(record);
                        }
                    }
                }
                RecordType::AAAA => {
                    for ip in ips {
                        if let IpAddr::V6(v6) = ip {
                            let record = Record::from_rdata(
                                query.name().clone(),
                                300,
                                RData::AAAA(rdata::AAAA(*v6)),
                            );
                            response.add_answer(record);
                        }
                    }
                }
                _ => {
                    // Domain exists in hosts but query type is unsupported
                    // Since /etc/hosts is authoritative, we return NODATA
                }
            }

            return Ok(MessageResult::Response(response));
        }

        if let FilterResult::Block(rule) = self.filter.check_domain(&domain.name()).await {
            let mut burst = self.burst.lock().await;
            if !burst.is_bursting(&domain.name()) {
                eprintln!(
                    "Query for {} refused (pattern `{}`, path `{}`)",
                    domain.name(),
                    rule.original_pattern(),
                    rule.path()
                );
            }

            match blocking::create_blocked_response(
                message,
                query.query_type(),
                &self.config.blocking,
            ) {
                Some(response) => return Ok(MessageResult::Response(response)),
                None => {
                    return Ok(MessageResult::Drop);
                }
            }
        }

        let mut cache = self.cache.lock().await;
        let mut cached = false;

        let upstream_response = match cache.get(query.name(), query.query_type()) {
            Some(cached_response) => {
                cached = true;
                cached_response
            }
            None => upstream::resolve(&self.client, &self.config, message).await?,
        };

        if !cached {
            cache.insert(query.name(), query.query_type(), &upstream_response);
        }

        let mut response = create_response_base(message);
        response.set_response_code(upstream_response.response_code());
        response.add_answers(upstream_response.answers().to_vec());
        response.add_name_servers(upstream_response.name_servers().to_vec());
        response.add_additionals(upstream_response.additionals().to_vec());

        Ok(MessageResult::Response(response))
    }
}

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    let ctx = Arc::new(DnsContext::new(config).await?);
    let udp = start_udp(addr, ctx.clone());
    let tcp = start_tcp(addr, ctx.clone());

    tokio::try_join!(udp, tcp)?;

    Ok(())
}

async fn start_udp(addr: &SocketAddr, ctx: Arc<DnsContext>) -> Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    println!("Listening on {addr} (UDP)");

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf).await?;

        if !is_local_ip(&src.ip()) {
            eprintln!("non-local UDP from {src}");
            continue;
        }

        if let Ok(message) = Message::from_bytes(&buf[..amt]) {
            match ctx.handle_message(&message).await {
                Ok(MessageResult::Response(response)) => {
                    socket.send_to(&response.to_bytes()?, src).await?;
                }
                Ok(MessageResult::Drop) => {
                    // Drop strategy - no response sent (this is intentional)
                }
                Err(why) => {
                    eprintln!("Error resolving query: {}", why);
                    let mut error_response = create_response_base(&message);
                    error_response.set_response_code(ResponseCode::ServFail);
                    socket.send_to(&error_response.to_bytes()?, src).await?;
                }
            }
        } else {
            eprintln!("Received invalid DNS message from {src}");
        }
    }
}

async fn start_tcp(addr: &SocketAddr, ctx: Arc<DnsContext>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("Listening on {addr} (TCP)");

    loop {
        let (mut stream, peer) = listener.accept().await?;
        if !is_local_ip(&peer.ip()) {
            eprintln!("non-local TCP from {peer}");
            continue;
        }
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(&mut stream, ctx).await {
                eprintln!("TCP handler error: {}", e);
            }
        });
    }
}

async fn handle_tcp(stream: &mut tokio::net::TcpStream, ctx: Arc<DnsContext>) -> Result<()> {
    let mut lenb = [0u8; 2];

    stream.read_exact(&mut lenb).await?;

    let len = u16::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];

    stream.read_exact(&mut buf).await?;

    if let Ok(message) = Message::from_bytes(&buf) {
        let response = match ctx.handle_message(&message).await {
            Ok(MessageResult::Response(r)) => r,
            Ok(MessageResult::Drop) => return Ok(()),
            Err(_) => {
                let mut response = create_response_base(&message);
                response.set_response_code(ResponseCode::ServFail);
                response
            }
        };

        let resp_bytes = response.to_bytes()?;
        let resp_bytes_len = resp_bytes.len() as u16;

        stream.write_all(&resp_bytes_len.to_be_bytes()).await?;
        stream.write_all(&resp_bytes).await?;
    }
    Ok(())
}

fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
