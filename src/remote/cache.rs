use hickory_proto::{
    op::Message,
    rr::{Name, RecordType},
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// A simple LRU cache for DNS responses.
///
/// Entries are automatically evicted when:
/// - The cache exceeds its capacity (oldest entries removed first)
/// - An entry's TTL has expired
pub struct Cache {
    capacity: usize,
    entries: HashMap<CacheKey, CacheEntry>,
    lru_keys: VecDeque<CacheKey>,
}

/// Cache key combining domain name and record type.
type CacheKey = (Name, RecordType);

#[derive(Clone, Debug)]
struct CacheEntry {
    response: Message,
    expires_at: Instant,
}

/// Default TTL when response has no answers (in seconds).
const DEFAULT_TTL_SECONDS: u32 = 300;

impl Cache {
    /// Creates a new cache with the specified maximum capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            lru_keys: VecDeque::with_capacity(capacity),
        }
    }

    /// Retrieves a cached response, updating TTLs to reflect remaining time.
    ///
    /// Returns `None` if the entry doesn't exist or has expired.
    pub fn get(&mut self, name: &Name, record_type: RecordType) -> Option<Message> {
        let now = Instant::now();
        let key = (name.clone(), record_type);
        let entry = self.entries.get(&key)?;

        if entry.expires_at < now {
            self.entries.remove(&key);
            self.remove_from_lru(&key);
            return None;
        }

        let remaining_ttl = entry.expires_at.saturating_duration_since(now).as_secs() as u32;

        let mut message = entry.response.clone();
        for answer in message.answers_mut() {
            answer.set_ttl(remaining_ttl);
        }

        self.remove_from_lru(&key);
        self.lru_keys.push_back(key);

        Some(message)
    }

    /// Inserts a response into the cache.
    ///
    /// TTL is derived from the minimum TTL of all answer records.
    /// Responses with TTL of 0 are not cached.
    pub fn insert(&mut self, name: &Name, record_type: RecordType, response: &Message) {
        let ttl = response
            .answers()
            .iter()
            .map(|record| record.ttl())
            .min()
            .unwrap_or(DEFAULT_TTL_SECONDS);

        // Don't cache responses with zero TTL
        if ttl == 0 {
            return;
        }

        let now = Instant::now();
        let expires_at = now
            .checked_add(Duration::from_secs(u64::from(ttl)))
            .unwrap_or_else(|| now + Duration::from_secs(u64::from(DEFAULT_TTL_SECONDS)));

        let key = (name.clone(), record_type);
        let entry = CacheEntry {
            response: response.clone(),
            expires_at,
        };

        // Remove old entry from LRU if updating
        if self.entries.contains_key(&key) {
            self.remove_from_lru(&key);
        }

        self.entries.insert(key.clone(), entry);
        self.lru_keys.push_back(key);

        if self.entries.len() > self.capacity {
            if let Some(oldest_key) = self.lru_keys.pop_front() {
                self.entries.remove(&oldest_key);
            }
        }
    }

    fn remove_from_lru(&mut self, key: &CacheKey) {
        if let Some(pos) = self.lru_keys.iter().position(|k| k == key) {
            self.lru_keys.remove(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{RData, Record};
    use std::str::FromStr;

    fn make_message(name_str: &str, ttl: u32) -> Message {
        let mut msg = Message::new();
        let name = Name::from_str(name_str).unwrap();
        let record = Record::from_rdata(name.clone(), ttl, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);
        msg
    }

    #[test]
    fn ttl_decreases_on_get() {
        let mut cache = Cache::new(10);
        let name = Name::from_str("example.com").unwrap();
        let msg = make_message("example.com", 5);

        cache.insert(&name, RecordType::A, &msg);

        let fetched = cache.get(&name, RecordType::A).expect("Should be in cache");

        let returned_ttl = fetched.answers()[0].ttl();
        assert!(returned_ttl < 5, "TTL should have ticked down");
        assert!(returned_ttl > 0, "TTL should still be positive");
    }

    #[test]
    fn zero_ttl_should_not_be_cached() {
        let mut cache = Cache::new(10);
        let name = Name::from_str("example.com").unwrap();
        let msg = make_message("example.com", 0);

        cache.insert(&name, RecordType::A, &msg);

        assert!(cache.entries.is_empty(), "Zero TTL should not be cached");
    }

    #[test]
    fn capacity_eviction_oldest_removed() {
        let mut cache = Cache::new(2);
        let a = Name::from_str("one.com").unwrap();
        let b = Name::from_str("two.com").unwrap();
        let c = Name::from_str("three.com").unwrap();
        let msg = make_message("x.com", 300);

        cache.insert(&a, RecordType::A, &msg);
        cache.insert(&b, RecordType::A, &msg);

        // Sanity: both are in the map
        assert!(cache.entries.contains_key(&(a.clone(), RecordType::A)));
        assert!(cache.entries.contains_key(&(b.clone(), RecordType::A)));

        // Now overflow
        cache.insert(&c, RecordType::A, &msg);

        // A must be gone, B and C remain
        assert!(!cache.entries.contains_key(&(a.clone(), RecordType::A)));
        assert!(cache.entries.contains_key(&(b.clone(), RecordType::A)));
        assert!(cache.entries.contains_key(&(c.clone(), RecordType::A)));
    }

    #[test]
    fn lru_eviction_keeps_recently_used() {
        let mut cache = Cache::new(2);
        let n1 = Name::from_str("one.com").unwrap();
        let n2 = Name::from_str("two.com").unwrap();
        let n3 = Name::from_str("three.com").unwrap();

        let msg1 = make_message("one.com", 300);
        let msg2 = make_message("two.com", 300);
        let msg3 = make_message("three.com", 300);

        // Insert A and B
        cache.insert(&n1, RecordType::A, &msg1);
        cache.insert(&n2, RecordType::A, &msg2);

        // The front is the least recently used
        assert_eq!(cache.lru_keys.front(), Some(&(n1.clone(), RecordType::A)));

        // Access A to make it the most recently used
        assert!(cache.get(&n1, RecordType::A).is_some());

        // Insert C, which should evict B (the least recently used)
        cache.insert(&n3, RecordType::A, &msg3);
        assert!(
            cache.get(&n2, RecordType::A).is_none(),
            "Least recently used entry (two.com) should be evicted"
        );
        assert!(cache.get(&n1, RecordType::A).is_some());
        assert!(cache.get(&n3, RecordType::A).is_some());
    }
}
