use anyhow::{Context, Result};
use reqwest::{IntoUrl, Proxy, RequestBuilder};
use rustls_native_certs::load_native_certs;
use std::net::SocketAddr;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::config::SwiftConfig;

enum ClientState {
    NeedsValidation,
    Ready,
}

pub struct Client {
    client: reqwest::Client,
    state: ClientState,
}

impl Client {
    pub fn create(config: &SwiftConfig) -> Result<Self> {
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

        Ok(Self {
            client,
            state: if config.tor.enabled {
                ClientState::NeedsValidation
            } else {
                ClientState::Ready
            },
        })
    }

    pub async fn get<U>(&mut self, url: U) -> Result<RequestBuilder>
    where
        U: IntoUrl,
    {
        if let ClientState::NeedsValidation = self.state {
            self.validate().await?;
        }
        Ok(self.client.get(url))
    }

    async fn validate(&mut self) -> Result<()> {
        if let ClientState::NeedsValidation = self.state {
            tor::proxy::validate(&self.client).await?;
            self.state = ClientState::Ready;
        }
        Ok(())
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
