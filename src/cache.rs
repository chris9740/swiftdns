use std::collections::HashMap;

use chrono::{DateTime, Duration, Local};

use crate::dns::resolver::{DnsQuestion, DnsResponse};

#[derive(Clone)]
pub struct CacheEntry {
    pub valid_until: DateTime<Local>,
    pub response: DnsResponse,
}

pub struct Cache {
    hash_map: HashMap<DnsQuestion, CacheEntry>,
}

impl Cache {
    pub fn new() -> Cache {
        let hash_map = HashMap::new();

        Cache { hash_map }
    }

    pub fn set(&mut self, question: DnsQuestion, response: &DnsResponse) {
        let response = response.clone();

        // We will assume that the TTL for the first record will be the same for all records in this response.
        // This might not always be the case, but it's uncommon for them to differ.
        //
        // At worst, this will cause a second query to have to be made, which is not
        // a problem worth spending time on.
        if let Some(first_answer) = response.answer.get(0) {
            let ttl_seconds = first_answer.ttl;
            let valid_until = Local::now() + Duration::seconds(ttl_seconds.into());

            let entry = CacheEntry {
                response,
                valid_until,
            };

            self.hash_map.insert(question, entry);
        }
    }

    pub fn get(&mut self, question: &DnsQuestion) -> Option<CacheEntry> {
        if let Some(entry) = self.hash_map.get(question) {
            if entry.valid_until < Local::now() {
                self.hash_map.remove(question);

                return None;
            }

            return Some(entry.clone());
        }

        None
    }
}
