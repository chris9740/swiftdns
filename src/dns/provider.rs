use anyhow::Result;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::HashMap;

use crate::{config::SwiftConfig, error::DnsError, http};

use super::message_types::{DnsJsonQuestion, DnsJsonResponse};

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderMode {
    pub name: String,
    pub ip: String,
}

#[derive(Debug, Deserialize)]
pub struct Provider {
    pub name: String,
    pub url: String,
    pub modes: Vec<ProviderMode>,
}

#[derive(Debug, Deserialize)]
struct ProvidersConfig {
    providers: Vec<Provider>,
}

static PROVIDERS: Lazy<HashMap<String, Provider>> = Lazy::new(|| {
    let providers_toml = include_str!("../../assets/providers.toml");
    let config: ProvidersConfig =
        toml::from_str(providers_toml).expect("Failed to parse providers.toml");

    config
        .providers
        .into_iter()
        .map(|p| (p.name.clone(), p))
        .collect()
});

pub async fn query(
    client: &mut http::Client,
    provider: &Provider,
    question: &DnsJsonQuestion,
    config: &SwiftConfig,
) -> Result<DnsJsonResponse, DnsError> {
    let mode = provider
        .modes
        .iter()
        .find(|m| m.name == config.resolver.mode)
        .ok_or_else(|| {
            DnsError::ProviderError(format!(
                "Provider {} does not support mode {}",
                provider.name, config.resolver.mode
            ))
        })?;

    let url = provider
        .url
        .replace("{ip}", &mode.ip)
        .replace("{name}", &question.name)
        .replace("{type}", &question.qtype.to_string());

    let res = client
        .get(&url)
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to send request: {}", e)))?
        .header(reqwest::header::ACCEPT, "application/dns-json")
        .send()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to send request: {}", e)))?;

    if res.status() == reqwest::StatusCode::BAD_REQUEST {
        return Err(DnsError::QueryError("Bad request".to_string()));
    }

    res.json()
        .await
        .map_err(|e| DnsError::NetworkError(format!("Failed to parse response: {}", e)))
}

pub fn is_valid_provider(name: &str) -> bool {
    PROVIDERS.contains_key(name)
}

pub fn get_provider(name: &str) -> Option<&'static Provider> {
    PROVIDERS.get(name)
}

pub fn get_valid_providers() -> Vec<&'static str> {
    PROVIDERS.keys().map(|s| s.as_str()).collect()
}

pub fn get_provider_mode(provider: &str, mode: &str) -> Option<&'static ProviderMode> {
    PROVIDERS
        .get(provider)?
        .modes
        .iter()
        .find(|m| m.name == mode)
}
