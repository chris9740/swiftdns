use std::collections::HashMap;

use chrono::{DateTime, Duration, Local};

use crate::{
    dns::message_types::{DnsJsonQuestion, DnsJsonResponse},
    error::DnsError,
};

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub expires_at: DateTime<Local>,
    pub response: DnsJsonResponse,
}

pub struct Cache {
    hash_map: HashMap<DnsJsonQuestion, CacheEntry>,
    last_cleanup: DateTime<Local>,
    cleanup_interval: Duration,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Cache {
        let hash_map = HashMap::new();

        Cache {
            hash_map,
            last_cleanup: Local::now(),
            cleanup_interval: Duration::seconds(60),
        }
    }

    pub fn get(&mut self, question: &DnsJsonQuestion) -> Result<Option<CacheEntry>, DnsError> {
        self.cleanup()?;

        Ok(self
            .hash_map
            .get(question)
            .filter(|entry| entry.expires_at > Local::now())
            .cloned())
    }

    pub fn set(
        &mut self,
        question: DnsJsonQuestion,
        response: DnsJsonResponse,
    ) -> Result<(), DnsError> {
        let ttl = response
            .answer
            .iter()
            .map(|a| a.ttl)
            .filter(|&t| t > 0)
            .min()
            .or_else(|| {
                response
                    .authority
                    .as_ref()?
                    .iter()
                    .map(|a| a.ttl)
                    .filter(|&t| t > 0)
                    .min()
            })
            .unwrap_or(300);

        let expires_at = Local::now() + Duration::seconds(ttl as i64);

        let entry = CacheEntry {
            response,
            expires_at,
        };

        self.hash_map.insert(question, entry);

        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<(), DnsError> {
        let now = Local::now();
        if now - self.last_cleanup > self.cleanup_interval {
            self.hash_map.retain(|_, entry| entry.expires_at > now);
            self.last_cleanup = now;
        }
        Ok(())
    }
}
