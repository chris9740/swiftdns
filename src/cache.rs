use chrono::{DateTime, Duration, Local};
use hickory_proto::{
    op::Message,
    rr::{Name, RecordType},
};
use std::collections::HashMap;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub name: Name,
    pub record_type: RecordType,
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub response: Message,
    pub expires_at: DateTime<Local>,
}

pub struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
    last_cleanup: DateTime<Local>,
    cleanup_interval: Duration,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

const FIVE_MINUTES: u32 = 300;

impl Cache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            last_cleanup: Local::now(),
            cleanup_interval: Duration::seconds(60),
        }
    }

    pub fn get(&mut self, name: &Name, record_type: RecordType) -> Option<Message> {
        self.cleanup();

        let key = CacheKey {
            name: name.clone(),
            record_type,
        };

        self.entries
            .get(&key)
            .filter(|entry| entry.expires_at > Local::now())
            .map(|entry| entry.response.clone())
    }

    pub fn insert(&mut self, name: &Name, record_type: RecordType, response: &Message) {
        let ttl = response
            .answers()
            .iter()
            .map(|record| record.ttl())
            .filter(|&ttl| ttl > 0)
            .min()
            .unwrap_or(FIVE_MINUTES);

        let expires_at = Local::now() + Duration::seconds(ttl as i64);

        let key = CacheKey {
            name: name.clone(),
            record_type,
        };

        let entry = CacheEntry {
            response: response.clone(),
            expires_at,
        };

        self.entries.insert(key, entry);
    }

    fn cleanup(&mut self) {
        let now = Local::now();
        if now - self.last_cleanup > self.cleanup_interval {
            self.entries.retain(|_, entry| entry.expires_at > now);
            self.last_cleanup = now;
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
