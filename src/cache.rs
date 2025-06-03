use chrono::{DateTime, Duration, Local};
use hickory_proto::{
    op::Message,
    rr::{Name, RecordType},
};
use std::collections::{HashMap, VecDeque};

pub struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
    insertion_order: VecDeque<CacheKey>,
    last_cleanup: DateTime<Local>,
    cleanup_interval: Duration,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct CacheKey {
    pub name: Name,
    pub record_type: RecordType,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    pub response: Message,
    pub expires_at: DateTime<Local>,
}

const FIVE_MINUTES: u32 = 300;
const CACHE_CAPACITY: usize = 1000;

impl Cache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: VecDeque::with_capacity(CACHE_CAPACITY),
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

        if self.entries.contains_key(&key) {
            self.insertion_order.retain(|k| k != &key);
        }

        let entry = CacheEntry {
            response: response.clone(),
            expires_at,
        };

        self.entries.insert(key.clone(), entry);
        self.insertion_order.push_back(key);

        while self.entries.len() > CACHE_CAPACITY {
            if let Some(oldest_key) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest_key);
            }
        }
    }

    fn cleanup(&mut self) {
        let now = Local::now();
        if now - self.last_cleanup > self.cleanup_interval {
            self.entries.retain(|_, entry| entry.expires_at > now);
            self.last_cleanup = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    #[test]
    fn ensure_cache_eviction_policy() {
        use super::*;
        let mut cache = Cache::new();
        let response = Message::new();

        for i in 0..CACHE_CAPACITY + 100 {
            let name = Name::from_str(&format!("example{i}.com")).unwrap();
            cache.insert(&name, RecordType::A, &response);
        }

        assert_eq!(cache.entries.len(), CACHE_CAPACITY);
        assert!(
            cache
                .entries
                .get(&CacheKey {
                    name: Name::from_str("example0.com").unwrap(),
                    record_type: RecordType::A,
                })
                .is_none(),
            "Oldest entry should be removed when capacity is exceeded"
        );
        assert!(
            cache
                .entries
                .get(&CacheKey {
                    name: Name::from_str("example100.com").unwrap(),
                    record_type: RecordType::A,
                })
                .is_some(),
            "New entries should still be added"
        );
    }
}
