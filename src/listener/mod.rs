mod tcp;
mod udp;
mod utils;

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
};
use tokio::sync::Mutex;

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

pub async fn start(addr: &SocketAddr, config: &SwiftConfig) -> Result<()> {
    let ctx = Arc::new(DnsContext::new(config).await?);
    let udp = udp::start_udp(addr, ctx.clone());
    let tcp = tcp::start_tcp(addr, ctx.clone());

    tracing::info!("Listening on {addr} via UDP and TCP");

    tokio::try_join!(udp, tcp)?;

    Ok(())
}

enum MessageResult {
    Response(Message),
    Drop,
}

struct DnsContext {
    filter: DnsFilter,
    cache: Arc<Mutex<Cache>>,
    hosts: HashMap<DnsName, Vec<IpAddr>>,
    burst: Arc<Mutex<BurstTracker>>,
    error_rl: Arc<Mutex<RateLimiter>>,
    client: Client,
    config: SwiftConfig,
}

impl DnsContext {
    async fn new(config: &SwiftConfig) -> Result<Self> {
        let filter = DnsFilter::from_default_path().await?;
        #[cfg(feature = "notify")]
        if let Err(e) = filter.start_watching().await {
            tracing::error!("Failed to start filter watcher: {}", e);
        }

        let client = Client::connect(config).await?;
        let cache = Arc::new(Mutex::new(Cache::new(1000)));
        let burst = Arc::new(Mutex::new(BurstTracker::new()));
        let error_rl = Arc::new(Mutex::new(RateLimiter::new(Duration::from_secs(15))));
        let hosts = hosts::parse_hosts_file()?;

        Ok(DnsContext {
            filter,
            cache,
            hosts,
            burst,
            error_rl,
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
                tracing::warn!(
                  domain    = %domain.name(),
                  pattern   = %rule.original_pattern(),
                  path      = %rule.path(),
                  strategy  = ?self.config.blocking.strategy,
                  "Refusing query for blocked domain"
                );
            }

            match blocking::create_blocked_response(
                message,
                query.query_type(),
                &self.config.blocking,
            ) {
                Some(response) => return Ok(MessageResult::Response(response)),
                None => return Ok(MessageResult::Drop),
            }
        }

        let mut cache = self.cache.lock().await;
        let mut cached = false;

        let upstream_response = if let Some(cached_response) =
            cache.get(query.name(), query.query_type())
        {
            cached = true;
            cached_response
        } else {
            match upstream::resolve(&self.client, &self.config, message).await {
                Ok(response) => response,
                Err(err @ DnsError::NetworkError(_)) => {
                    let mut error_rl = self.error_rl.lock().await;
                    if error_rl.allow() {
                        tracing::error!(error = %err, "Network error during upstream resolution");
                    }
                    return Err(err);
                }
                Err(err) => {
                    tracing::error!(error = %err, "Error resolving query");
                    return Err(err);
                }
            }
        };

        tracing::debug!(
            domain = %query.name(),
            query_type = ?query.query_type(),
            cached,
            "Cache lookup",
        );

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

struct RateLimiter {
    last: Instant,
    interval: Duration,
}

impl RateLimiter {
    fn new(interval: Duration) -> Self {
        Self {
            last: Instant::now() - interval,
            interval,
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last) >= self.interval {
            self.last = now;
            true
        } else {
            false
        }
    }
}
