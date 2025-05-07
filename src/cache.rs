use std::collections::HashMap;

use chrono::{DateTime, Duration, Local};
use dns_message_parser::question::Question;

use crate::{dns::message_types::DnsJsonResponse, error::DnsError};

#[derive(Clone)]
pub struct CacheEntry {
    pub expires_at: DateTime<Local>,
    pub response: DnsJsonResponse,
}

pub struct Cache {
    hash_map: HashMap<Question, CacheEntry>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Cache {
        let hash_map = HashMap::new();

        Cache { hash_map }
    }

    pub fn get(&mut self, question: &Question) -> Result<Option<CacheEntry>, DnsError> {
        let entry = self
            .hash_map
            .get(question)
            .filter(|entry| entry.expires_at > Local::now())
            .cloned();

        if entry.is_none() {
            self.hash_map.remove(question);
        }

        Ok(entry)
    }

    pub fn set(&mut self, question: Question, response: DnsJsonResponse) -> Result<(), DnsError> {
        let ttl = response
            .answer
            .iter()
            .map(|a| a.ttl)
            .filter(|&t| t > 0)
            .min()
            .ok_or_else(|| DnsError::CacheError("No valid TTL found".to_string()))?;

        let expires_at = Local::now() + Duration::seconds(ttl as i64);

        let entry = CacheEntry {
            response,
            expires_at,
        };

        self.hash_map.insert(question, entry);

        Ok(())
    }
}
