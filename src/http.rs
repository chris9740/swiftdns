use anyhow::{Context, Result};
use reqwest::{IntoUrl, Proxy, RequestBuilder};
use rustls_native_certs::load_native_certs;
use std::net::SocketAddr;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::config::SwiftConfig;

#[derive(Clone, Debug)]
pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub async fn connect(config: &SwiftConfig) -> Result<Self> {
        if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
            return Ok(Self {
                client: reqwest::Client::new(),
            });
        }

        let mut root_store = RootCertStore::empty();

        for cert in load_native_certs()? {
            root_store
                .add(&tokio_rustls::rustls::Certificate(cert.0))
                .context("Failed to add native certificate")?;
        }

        let tls_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let mut client_builder = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5));

        if let Some(bootstrap_ips) = &config.resolver.bootstrap_ips {
            for ip in bootstrap_ips {
                let url = url::Url::parse(&config.resolver.url)
                    .context("Failed to parse resolver URL")?;

                client_builder = client_builder.resolve_to_addrs(
                    url.host_str()
                        .context("Failed to get host from resolver URL")?,
                    &[*ip],
                );
            }
        }

        if config.tor.enabled {
            let tor_address: SocketAddr = config
                .tor
                .get_address()
                .context("Failed to get Tor proxy address")?;
            let proxy = Proxy::all(format!("socks5h://{tor_address}"))
                .context("Failed to configure proxy")?;
            client_builder = client_builder.proxy(proxy);
        }

        let client = client_builder
            .build()
            .context("Failed to build HTTP client")?;

        let result = Self { client };

        if config.tor.enabled {
            tor::proxy::validate(&result.client).await?;
        }

        Ok(result)
    }

    pub fn get<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.client.get(url)
    }

    pub fn post<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.client.post(url)
    }
}

mod tor {
    pub mod proxy {
        use anyhow::Result;

        pub async fn validate(client: &reqwest::Client) -> Result<()> {
            let connectivity_check_url = "https://check.torproject.org";
            let response = client
                .get(connectivity_check_url)
                .send()
                .await?
                .text()
                .await?;

            if !response.contains("Congratulations. This browser is configured to use Tor.") {
                anyhow::bail!(
                    "The proxy settings are correct, but it looks like we're not actually routing through the Tor network.\n\
                    Confirm that your configured proxy is specifically a Tor proxy, and ensure the Tor service is running."
                );
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ResolverConfig, SwiftConfig, TorConfig};

    #[test]
    fn test_client_creation() {
        let config = SwiftConfig {
            resolver: ResolverConfig {
                url: "https://dns.swiftdns.mock/dns-query".to_string(),
                bootstrap_ips: None,
            },
            tor: TorConfig {
                enabled: false,
                address: None,
            },
            ..Default::default()
        };

        assert!(tokio_test::block_on(Client::connect(&config)).is_ok());
    }
}
