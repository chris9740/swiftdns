use std::collections::HashMap;

use chrono::{DateTime, Duration, Local};
use dns_message_parser::question::Question;

use crate::dns::resolver::ApiResponse;

#[derive(Clone)]
pub struct CacheEntry {
    pub expires_at: DateTime<Local>,
    pub response: ApiResponse,
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

    pub fn set(&mut self, question: Question, response: ApiResponse) {
        let ttl = response
            .answer
            .iter()
            .map(|a| a.ttl)
            .filter(|&t| t > 0)
            .min();

        if let Some(ttl) = ttl {
            let expires_at = Local::now() + Duration::seconds(ttl as i64);

            let entry = CacheEntry {
                response,
                expires_at,
            };

            self.hash_map.insert(question, entry);
        }
    }

    pub fn get(&mut self, question: &Question) -> Option<CacheEntry> {
        self.hash_map
            .get(question)
            .filter(|entry| entry.expires_at > Local::now())
            .cloned()
            .or_else(|| {
                self.hash_map.remove(question);
                None
            })
    }
}
