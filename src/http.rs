use std::net::SocketAddr;

use anyhow::{Context, Result};
use reqwest::{IntoUrl, Proxy, RequestBuilder};

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
        let client = if config.tor.enabled {
            let tor_address: SocketAddr = config
                .tor
                .get_address()
                .context("Failed to get Tor proxy address")?;

            let proxy = Proxy::all(format!("socks5h://{tor_address}"))
                .context("Failed to configure proxy")?;

            reqwest::Client::builder()
                .proxy(proxy)
                .build()
                .context("Client should have valid configuration")?
        } else {
            reqwest::Client::new()
        };

        Ok(Client {
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

            println!("Connection to Tor has been established, and the proxy has passed the integrity verification.");
            Ok(())
        }
    }
}
