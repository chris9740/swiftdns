use std::net::SocketAddr;

use reqwest::{IntoUrl, RequestBuilder};

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
    pub fn create(config: &SwiftConfig) -> Self {
        let client = if config.tor.enabled {
            let tor_address: SocketAddr = config.tor.get_address().expect("Failed to parse Tor proxy address");

            let proxy = tor::proxy::create(tor_address);

            reqwest::Client::builder()
                .proxy(proxy)
                .build()
                .expect("Client should have valid configuration")
        } else {
            reqwest::Client::new()
        };

        Client {
            client,
            state: if config.tor.enabled {
                ClientState::NeedsValidation
            } else {
                ClientState::Ready
            },
        }
    }

    pub async fn get<U>(&mut self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        if let ClientState::NeedsValidation = self.state {
            self.validate().await;
        }

        self.client.get(url)
    }

    async fn validate(&mut self) {
        tor::proxy::validate(&self.client).await;

        self.state = ClientState::Ready;
    }
}

mod tor {
    pub mod proxy {
        use std::net::SocketAddr;

        enum ValidationError {
            Timeout,
            ConnectionError,
            Unknown,
        }
        
        impl From<reqwest::Error> for ValidationError {
            fn from(err: reqwest::Error) -> Self {
                if err.is_timeout() {
                    ValidationError::Timeout
                } else if err.is_connect() {
                    ValidationError::ConnectionError
                } else {
                    ValidationError::Unknown
                }
            }
        }

        pub fn create(address: SocketAddr) -> reqwest::Proxy {
            reqwest::Proxy::all(format!("socks5h://{address}")).unwrap_or_else(|_| {
                error!("Invalid socket address was provided ({address})");
            })
        }

        pub async fn validate(client: &reqwest::Client) {
            let connectivity_check_url = "https://check.torproject.org";

            let response = client
                .get(connectivity_check_url)
                .send()
                .await
                .unwrap_or_else(|err| {
                    let error_cause = if err.is_timeout() {
                        "Timeout"
                    } else if err.is_connect() {
                        "Connection error"
                    } else {
                        "Unknown cause"
                    };

                    error!("Failed to connect to Tor Connectivity URL {connectivity_check_url}: {error_cause}");
                });

            let response_body = response.text().await.unwrap_or_else(|_| {
                error!("Failed to read the response from {connectivity_check_url}")
            });

            let did_route_successfully =
                response_body.contains("Congratulations. This browser is configured to use Tor.");

            if !did_route_successfully {
                error!("Failed to verify Tor connectivity via {connectivity_check_url}");
            }
        }
    }
}
