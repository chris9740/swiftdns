use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::dns;

#[derive(Clone)]
pub struct CacheEntry {
    pub valid_until: DateTime<Utc>,
    pub response: dns::DnsResponse,
}

pub struct Cache {
    hash_map: HashMap<dns::DnsQuestion, CacheEntry>,
}

impl Cache {
    pub fn new() -> Cache {
        let hash_map = HashMap::new();

        Cache { hash_map }
    }

    pub fn set(&mut self, question: dns::DnsQuestion, response: &dns::DnsResponse) {
        let response = response.clone();

        // We will assume that the TTL for the first record will be the same for all records in this response.
        // There are rare edge-cases where this is not necessarily the case, but we can pretend those cases don't exist,
        // and it's unlikely to cause any issues.
        let first_answer = response.answer.as_ref().unwrap().get(0);
        let ttl_seconds = first_answer.unwrap().ttl;

        debug!("ttl for `{}` is {} seconds", question.name, ttl_seconds);

        let valid_until = Utc::now() + Duration::seconds(ttl_seconds.into());

        let entry = CacheEntry {
            response: response,
            valid_until: valid_until,
        };

        self.hash_map.insert(question, entry);
    }

    pub fn get(&mut self, question: &dns::DnsQuestion) -> Option<CacheEntry> {
        if let Some(entry) = self.hash_map.get(question) {
            if entry.valid_until < Utc::now() {
                self.hash_map.remove(question);

                return None;
            }

            return Some(entry.clone());
        }

        None
    }
}
