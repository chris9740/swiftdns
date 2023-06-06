use std::error::Error;

use reqwest::{IntoUrl, RequestBuilder};

use crate::config::SwiftConfig;

use super::tor;

pub struct Client {
    client: reqwest::Client,
    validated: bool,
}

impl Client {
    pub fn new(config: &SwiftConfig) -> Result<Self, Box<dyn Error>> {
        let client = if config.tor {
            let proxy = tor::proxy();

            reqwest::Client::builder()
                .proxy(proxy)
                .build()
                .expect("Should be able to build client")
        } else {
            reqwest::Client::new()
        };

        // We only need to validate the client if tor is enabled
        let validated = !config.tor;

        Ok(Client { client, validated })
    }

    pub async fn get<U>(&mut self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        if !self.validated {
            self.validate().await;
        }

        self.client.get(url)
    }

    async fn validate(&mut self) {
        tor::validate_client_proxy(&self.client).await;

        self.validated = true;
    }
}
