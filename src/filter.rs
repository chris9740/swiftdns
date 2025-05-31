use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result};
use wildmatch::WildMatch;

#[derive(Debug)]
pub struct Filter {
    pub contents: String,
    pub filename: String,
}

pub struct FilterEntry {
    pub pattern: String,
}

pub enum FilterType {
    Whitelist,
    Blacklist,
}

#[derive(Debug, Clone)]
struct FilterPattern {
    pattern: String,
}

#[derive(Debug, Default)]
struct FilterData {
    /// Exact matches (^domain.com patterns)
    exact_matches: HashSet<String>,
    /// Domain and subdomain matches (domain.com patterns)
    domain_matches: HashSet<String>,
    /// Complex wildcard patterns that need WildMatch
    wildcard_patterns: Vec<FilterPattern>,
}

impl FilterData {
    /// Finds a matching filter pattern for the given domain name.
    ///
    /// This method checks:
    /// 1. Exact matches (fastest)
    /// 2. Domain and subdomain matches (e.g., "google.com" matches "maps.google.com")
    /// 3. Wildcard patterns (slowest, but should be minimal)
    fn find_match(&self, name: &str) -> Option<String> {
        if self.exact_matches.contains(name) {
            return Some(format!("^{}", name));
        }

        let parts: Vec<&str> = name.split('.').collect();
        for i in 0..parts.len() {
            let domain_suffix = parts[i..].join(".");
            if self.domain_matches.contains(&domain_suffix) {
                return Some(domain_suffix);
            }
        }

        for pattern in &self.wildcard_patterns {
            if WildMatch::new(&pattern.pattern).matches(name) {
                return Some(pattern.pattern.clone());
            }
        }

        None
    }
}

static WHITELIST_CACHE: OnceLock<FilterData> = OnceLock::new();
static BLACKLIST_CACHE: OnceLock<FilterData> = OnceLock::new();

/// Initialize the filter caches. Should be called once at startup.
pub fn initialize_filters() -> Result<()> {
    if WHITELIST_CACHE.get().is_some() && BLACKLIST_CACHE.get().is_some() {
        return Ok(());
    }

    if std::env::var("SWIFTDNS_CLI_TEST_MODE").is_ok() {
        let (blacklist_data, whitelist_data) = generate_test_filters();
        let _ = BLACKLIST_CACHE.set(blacklist_data);
        let _ = WHITELIST_CACHE.set(whitelist_data);

        return Ok(());
    }

    let filters = load_filters()?;

    let mut whitelist_data = FilterData::default();
    let mut blacklist_data = FilterData::default();

    for filter in filters {
        let is_whitelist = filter.filename == "whitelist.list";
        let target_data = if is_whitelist {
            &mut whitelist_data
        } else {
            &mut blacklist_data
        };

        parse_filter_into_data(&filter, target_data)?;
    }

    WHITELIST_CACHE
        .set(whitelist_data)
        .map_err(|_| anyhow::anyhow!("Failed to initialize whitelist cache"))?;

    BLACKLIST_CACHE
        .set(blacklist_data)
        .map_err(|_| anyhow::anyhow!("Failed to initialize blacklist cache"))?;

    Ok(())
}

fn parse_filter_into_data(filter: &Filter, data: &mut FilterData) -> Result<()> {
    for line in filter.contents.lines() {
        let pattern = line.trim();

        if pattern.starts_with('#') || pattern.is_empty() {
            continue;
        }

        if let Some(exact_domain) = pattern.strip_prefix('^') {
            data.exact_matches.insert(exact_domain.to_string());
        } else if pattern.contains('*') {
            data.wildcard_patterns.push(FilterPattern {
                pattern: pattern.to_string(),
            });
        } else {
            data.domain_matches.insert(pattern.to_string());
        }
    }

    Ok(())
}

pub fn load_filters() -> Result<Vec<Filter>> {
    use crate::config;

    let base_directory_path = config::get_config_path().join("filters");
    let mut filters = Vec::new();

    let mut file_paths = Vec::new();
    visit_dirs(&base_directory_path, &mut file_paths)?;

    for path in file_paths {
        let contents = fs::read_to_string(&path).context("Failed to read filter contents")?;
        let filename = path
            .file_name()
            .context("Failed to get filename")?
            .to_string_lossy()
            .to_string();

        filters.push(Filter { filename, contents });
    }

    Ok(filters)
}

fn visit_dirs(dir: &Path, file_paths: &mut Vec<PathBuf>) -> Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                visit_dirs(&path, file_paths)?;
            } else {
                let pathname = path.to_string_lossy();

                if pathname.ends_with(".list") {
                    file_paths.push(path);
                }
            }
        }
    }
    Ok(())
}

pub mod whitelist {
    use super::{FilterEntry, WHITELIST_CACHE};

    pub fn find(name: &str) -> Option<FilterEntry> {
        let cache = WHITELIST_CACHE.get()?;
        let pattern = cache.find_match(name)?;

        Some(FilterEntry { pattern })
    }
}

pub mod blacklist {
    use super::{FilterEntry, BLACKLIST_CACHE};

    pub fn find(name: &str) -> Option<FilterEntry> {
        if super::whitelist::find(name).is_some() {
            return None;
        }

        let cache = BLACKLIST_CACHE.get()?;
        let pattern = cache.find_match(name)?;

        Some(FilterEntry { pattern })
    }
}

fn generate_test_filters() -> (FilterData, FilterData) {
    let mut blacklist_data = FilterData::default();

    // Exact matches (^domain.com patterns)
    blacklist_data.exact_matches.extend([
        "google.com".to_string(),
        "www.google.com".to_string(),
        "facebook.com".to_string(),
        "www.facebook.com".to_string(),
        "tiktok.com".to_string(),
    ]);

    // Domain matches (blocks domain and all subdomains)
    blacklist_data.domain_matches.extend([
        "doubleclick.net".to_string(),
        "googleadservices.com".to_string(),
        "meta.com".to_string(),
        "instagram.com".to_string(),
        "bytedance.com".to_string(),
    ]);

    // Wildcard patterns
    blacklist_data.wildcard_patterns.extend([
        FilterPattern {
            pattern: "*analytics*".to_string(),
        },
        FilterPattern {
            pattern: "*.zip".to_string(),
        },
        FilterPattern {
            pattern: "*.mov".to_string(),
        },
        FilterPattern {
            pattern: "tiktok*.com*".to_string(),
        },
        FilterPattern {
            pattern: "*s.google.com".to_string(),
        },
        FilterPattern {
            pattern: "*ads*".to_string(),
        },
    ]);

    let mut whitelist_data = FilterData::default();

    // Whitelist some Google services that should be accessible
    whitelist_data.exact_matches.extend([
        "maps.google.com".to_string(),
        "translate.google.com".to_string(),
    ]);

    // Allow specific Discord CDN that might be caught by broader blocks
    whitelist_data
        .domain_matches
        .extend(["discord-attachments-uploads-prd.storage.googleapis.com".to_string()]);

    (blacklist_data, whitelist_data)
}

#[cfg(test)]
mod tests {
    use super::{blacklist, whitelist};

    fn setup_test_mode() {
        std::env::set_var("SWIFTDNS_CLI_TEST_MODE", "1");
        super::initialize_filters().expect("Failed to initialize filters");
    }

    #[test]
    fn test_exact_blacklist_matches() {
        setup_test_mode();

        // Test exact matches (^domain.com patterns)
        assert!(blacklist::find("google.com").is_some());
        assert!(blacklist::find("www.google.com").is_some());
        assert!(blacklist::find("facebook.com").is_some());
        assert!(blacklist::find("www.facebook.com").is_some());
        assert!(blacklist::find("tiktok.com").is_some());

        // These should NOT match exact patterns
        assert!(blacklist::find("maps.google.com").is_none()); // Whitelisted
        assert!(blacklist::find("subdomain.google.com").is_none()); // Only exact google.com is blocked
    }

    #[test]
    fn test_domain_and_subdomain_blacklist_matches() {
        setup_test_mode();

        // Test domain matches (blocks domain and all subdomains)
        assert!(blacklist::find("doubleclick.net").is_some());
        assert!(blacklist::find("ads.doubleclick.net").is_some());
        assert!(blacklist::find("stats.doubleclick.net").is_some());

        assert!(blacklist::find("googleadservices.com").is_some());
        assert!(blacklist::find("pagead.googleadservices.com").is_some());

        assert!(blacklist::find("meta.com").is_some());
        assert!(blacklist::find("about.meta.com").is_some());

        assert!(blacklist::find("instagram.com").is_some());
        assert!(blacklist::find("www.instagram.com").is_some());

        assert!(blacklist::find("bytedance.com").is_some());
        assert!(blacklist::find("www.bytedance.com").is_some());
    }

    #[test]
    fn test_wildcard_blacklist_patterns() {
        setup_test_mode();

        // Test *analytics* pattern
        assert!(blacklist::find("google-analytics.com").is_some());
        assert!(blacklist::find("analytics.google.com").is_some());
        assert!(blacklist::find("someanalytics.example.com").is_some());
        assert!(blacklist::find("example-analytics-service.net").is_some());

        // Test *.zip and *.mov patterns
        assert!(blacklist::find("example.zip").is_some());
        assert!(blacklist::find("malware.zip").is_some());
        assert!(blacklist::find("video.mov").is_some());
        assert!(blacklist::find("suspicious.mov").is_some());

        // Test tiktok*.com* pattern
        assert!(blacklist::find("tiktokv.com").is_some());
        assert!(blacklist::find("tiktokcdn.com").is_some());
        assert!(blacklist::find("tiktok-analytics.com.evil").is_some());

        // Test *s.google.com pattern
        assert!(blacklist::find("books.google.com").is_some());
        assert!(blacklist::find("services.google.com").is_some());

        // Test *ads* pattern
        assert!(blacklist::find("googleads.com").is_some());
        assert!(blacklist::find("ads.yahoo.com").is_some());
        assert!(blacklist::find("adservice.google.com").is_some());
    }

    #[test]
    fn test_whitelist_functionality() {
        setup_test_mode();

        // Test whitelisted domains that would otherwise be blocked
        assert!(whitelist::find("maps.google.com").is_some());
        assert!(whitelist::find("translate.google.com").is_some());
        assert!(
            whitelist::find("discord-attachments-uploads-prd.storage.googleapis.com").is_some()
        );

        // Test that whitelisted domains are NOT blocked
        assert!(blacklist::find("maps.google.com").is_none());
        assert!(blacklist::find("translate.google.com").is_none());
        assert!(
            blacklist::find("discord-attachments-uploads-prd.storage.googleapis.com").is_none()
        );

        // Test that subdomains of whitelisted domains also work
        assert!(
            blacklist::find("cdn.discord-attachments-uploads-prd.storage.googleapis.com").is_none()
        );
    }

    #[test]
    fn test_allowed_domains() {
        setup_test_mode();

        // Test domains that should never be blocked
        assert!(blacklist::find("duckduckgo.com").is_none());
        assert!(blacklist::find("signal.org").is_none());
        assert!(blacklist::find("tutanota.com").is_none());
        assert!(blacklist::find("protonmail.com").is_none());
        assert!(blacklist::find("github.com").is_none());
        assert!(blacklist::find("stackoverflow.com").is_none());
    }

    #[test]
    fn test_complex_subdomain_scenarios() {
        setup_test_mode();

        // Test that deep subdomains work correctly
        assert!(blacklist::find("level1.level2.doubleclick.net").is_some());
        assert!(blacklist::find("very.deep.subdomain.meta.com").is_some());

        // Test that patterns don't over-match
        assert!(blacklist::find("notgoogle.com").is_none());
        assert!(blacklist::find("google-com.example.org").is_none());
    }

    #[test]
    fn test_edge_cases() {
        setup_test_mode();

        // Test empty and invalid domains
        assert!(blacklist::find("").is_none());
        assert!(blacklist::find(".").is_none());
        assert!(blacklist::find("..").is_none());

        // Test domains that partially match patterns but shouldn't be blocked
        assert!(blacklist::find("analyticsnot.com").is_some()); // Should match *analytics*
        assert!(blacklist::find("zipfile.com").is_none()); // Should NOT match *.zip
        assert!(blacklist::find("tiktok-fake.net").is_none()); // Should NOT match tiktok*.com*
    }

    #[test]
    fn test_case_sensitivity() {
        setup_test_mode();

        // DNS domains should be case-insensitive, but our current implementation
        // is case-sensitive. These tests document the current behavior.
        assert!(blacklist::find("GOOGLE.COM").is_none()); // Currently case-sensitive
        assert!(blacklist::find("Google.com").is_none()); // Currently case-sensitive
        assert!(blacklist::find("google.com").is_some()); // Exact match
    }

    #[test]
    fn test_whitelist_priority() {
        setup_test_mode();

        // Ensure whitelist takes priority over blacklist
        // maps.google.com would match *s.google.com wildcard but is whitelisted
        assert!(whitelist::find("maps.google.com").is_some());
        assert!(blacklist::find("maps.google.com").is_none());

        // translate.google.com would also match *s.google.com but is whitelisted
        assert!(whitelist::find("translate.google.com").is_some());
        assert!(blacklist::find("translate.google.com").is_none());
    }
}
