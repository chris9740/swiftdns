use std::{fs, path::Path, sync::Arc};
use tokio::sync::RwLock;
use wildmatch::WildMatch;

use crate::config;

#[derive(Debug, thiserror::Error)]
#[error("Filter error: {0}")]
pub enum FilterError {
    IoError(String),
    #[cfg(feature = "notify")]
    WatchError(String),
}

impl From<std::io::Error> for FilterError {
    fn from(err: std::io::Error) -> Self {
        FilterError::IoError(err.to_string())
    }
}

#[cfg(feature = "notify")]
impl From<notify::Error> for FilterError {
    fn from(err: notify::Error) -> Self {
        FilterError::WatchError(err.to_string())
    }
}

#[derive(Debug, Default, Clone)]
struct DnsFilterInner {
    filters: Vec<FilterData>,
    whitelist: Vec<FilterPattern>,
}

#[derive(Debug, Clone)]
pub struct DnsFilter {
    inner: Arc<RwLock<DnsFilterInner>>,
}

impl Default for DnsFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsFilter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsFilterInner::default())),
        }
    }

    pub async fn from_default_path() -> Result<Self, FilterError> {
        let filter = Self::new();
        filter.load_from_default_path().await?;
        Ok(filter)
    }

    pub async fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, FilterError> {
        let filter = Self::new();
        filter.load_from_path(path).await?;
        Ok(filter)
    }

    pub async fn check_domain(&self, domain: &str) -> FilterResult {
        let filter = self.inner.read().await;
        Self::check_domain_impl(&filter, domain)
    }

    async fn load_from_default_path(&self) -> Result<(), FilterError> {
        self.load_from_path(config::get_filters_path()).await
    }

    async fn load_from_path<P: AsRef<Path>>(&self, path: P) -> Result<(), FilterError> {
        let file_data = Self::read_filter_files(path)?;
        let mut filter = self.inner.write().await;
        Self::load_filter_data(&mut filter, file_data)?;
        Ok(())
    }

    pub async fn reload(&self) -> Result<(), FilterError> {
        self.load_from_default_path().await?;
        tracing::debug!("Filters reloaded successfully");
        Ok(())
    }

    #[cfg(feature = "notify")]
    pub async fn start_watching(&self) -> Result<(), FilterError> {
        use notify::{Event, EventKind, RecursiveMode, Watcher};
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel(100);
        let filter_path = config::get_filters_path();
        let filter_clone = self.clone();

        tokio::spawn(async move {
            let mut watcher = match notify::recommended_watcher(
                move |res: Result<Event, notify::Error>| {
                    if let Ok(event) = res {
                        if matches!(
                            event.kind,
                            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                        ) {
                            for path in &event.paths {
                                if path.extension().and_then(|s| s.to_str()) == Some("list") {
                                    if let Err(e) = tx.try_send(()) {
                                        tracing::error!(error=?e, "Failed to send filter change event");
                                    }
                                    break;
                                }
                            }
                        }
                    }
                },
            ) {
                Ok(watcher) => watcher,
                Err(e) => {
                    tracing::error!(error=?e, "Failed to create file watcher");
                    return;
                }
            };

            if let Err(e) = watcher.watch(&filter_path, RecursiveMode::NonRecursive) {
                tracing::error!(error=?e, path=%filter_path.display(), "Failed to watch filter path");
                return;
            }

            tracing::debug!(path=%filter_path.display(), "Started watching for filter changes");

            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });

        tokio::spawn(async move {
            const DEBOUNCE_DURATION: tokio::time::Duration =
                tokio::time::Duration::from_millis(500);

            while rx.recv().await.is_some() {
                loop {
                    match tokio::time::timeout(DEBOUNCE_DURATION, rx.recv()).await {
                        Ok(Some(())) => {
                            // Got another event, continue draining
                        }
                        Ok(None) => {
                            // Channel closed
                            return;
                        }
                        Err(_) => {
                            // Timeout reached, no more events - time to reload
                            break;
                        }
                    }
                }

                if let Err(e) = filter_clone.reload().await {
                    tracing::error!(error=?e, "Failed to reload filters");
                } else {
                    tracing::info!("Filter files changed, reloaded automatically");
                }
            }
        });

        Ok(())
    }

    fn read_filter_files<P>(path: P) -> Result<Vec<(String, String)>, FilterError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if !path.exists() {
            return Err(FilterError::IoError(format!(
                "Filter path does not exist: {}",
                path.display()
            )));
        }

        let mut file_data = Vec::new();

        let entries: Vec<std::fs::DirEntry> = path
            .read_dir()?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|ft| ft.is_file())
                    .map(|_| entry)
            })
            .filter(|file| {
                file.file_name()
                    .to_ascii_lowercase()
                    .to_string_lossy()
                    .ends_with(".list")
            })
            .collect();

        for entry in entries {
            let filename = entry.file_name().to_string_lossy().to_string();
            let contents = fs::read_to_string(entry.path())?;
            file_data.push((filename, contents));
        }

        Ok(file_data)
    }

    fn load_filter_data(
        filter: &mut DnsFilterInner,
        files: Vec<(String, String)>,
    ) -> Result<(), FilterError> {
        filter.filters.clear();
        filter.whitelist.clear();

        for (filename, contents) in files {
            let is_whitelist = filename == "whitelist.list";
            let mut line_number = 0;
            let mut blacklist_data = if is_whitelist {
                None
            } else {
                Some(FilterData::default())
            };

            for pattern in contents.lines().map(|line| line.trim()) {
                line_number += 1;

                if pattern.is_empty() || pattern.starts_with('#') {
                    continue;
                }

                let filter_pattern = Self::parse_pattern(pattern, &filename, line_number);

                if is_whitelist {
                    filter.whitelist.push(filter_pattern);
                } else {
                    blacklist_data.as_mut().unwrap().add_pattern(filter_pattern);
                }
            }

            if let Some(data) = blacklist_data {
                filter.filters.push(data);
            }
        }
        Ok(())
    }

    fn check_domain_impl(filter: &DnsFilterInner, domain: &str) -> FilterResult {
        if let Some(pattern) = filter.whitelist.iter().find(|rule| rule.matches(domain)) {
            return FilterResult::Whitelisted(pattern.clone());
        }

        for filter_data in &filter.filters {
            let mut patterns = Vec::new();

            patterns.extend(&filter_data.exact_matches);
            patterns.extend(&filter_data.domain_matches);
            patterns.extend(&filter_data.wildcard_patterns);

            for pattern in patterns {
                if pattern.matches(domain) {
                    return FilterResult::Block(pattern.clone());
                }
            }
        }

        FilterResult::Allow
    }

    fn parse_pattern(pattern: &str, filename: &str, line_number: usize) -> FilterPattern {
        if let Some(exact_domain) = pattern.strip_prefix('^') {
            FilterPattern::Exact {
                pattern: pattern.to_string(),
                filename: filename.to_string(),
                line_number,
                exact_domain: exact_domain.to_string(),
            }
        } else if pattern.contains('*') {
            FilterPattern::Wildcard {
                pattern: pattern.to_string(),
                filename: filename.to_string(),
                line_number,
            }
        } else {
            FilterPattern::Domain {
                pattern: pattern.to_string(),
                filename: filename.to_string(),
                line_number,
            }
        }
    }

    pub fn from_mock_data() -> Self {
        let mut filter = Self::new();

        let mock_files = vec![
            (
                "social-media.list".to_string(),
                concat!(
                    "^facebook.com\n",
                    "^www.facebook.com\n",
                    "instagram.com\n",
                    "tiktok.com\n",
                    "snapchat.com\n",
                    "*tiktok*"
                )
                .to_string(),
            ),
            (
                "advertising.list".to_string(),
                concat!(
                    "doubleclick.net\n",
                    "googleadservices.com\n",
                    "*analytics*\n",
                    "*ads*\n",
                    "^googleads.com"
                )
                .to_string(),
            ),
            (
                "whitelist.list".to_string(),
                concat!(
                    "# Exact domain exceptions\n",
                    "^packages.microsoft.com\n",
                    "^vscode.microsoft.com\n",
                    "^analytics.example.com\n",
                    "^business.facebook.com\n",
                    "\n",
                    "# Domain and subdomain exceptions\n",
                    "github.com\n",
                    "stackoverflow.com\n",
                    "developer.mozilla.org\n",
                    "\n",
                    "# Wildcard exceptions\n",
                    "*essential*\n",
                    "api.*.com\n",
                    "cdn-*.amazonaws.com\n",
                    "*-docs.github.io"
                )
                .to_string(),
            ),
        ];

        let mut inner = DnsFilterInner::default();
        Self::load_filter_data(&mut inner, mock_files).unwrap();

        filter.inner = Arc::new(RwLock::new(inner));
        filter
    }
}

#[derive(Debug, Default, Clone)]
pub struct FilterData {
    exact_matches: Vec<FilterPattern>,
    domain_matches: Vec<FilterPattern>,
    wildcard_patterns: Vec<FilterPattern>,
}

impl FilterData {
    pub fn add_pattern(&mut self, pattern: FilterPattern) {
        match &pattern {
            FilterPattern::Exact { .. } => self.exact_matches.push(pattern),
            FilterPattern::Domain { .. } => self.domain_matches.push(pattern),
            FilterPattern::Wildcard { .. } => self.wildcard_patterns.push(pattern),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FilterPattern {
    Exact {
        pattern: String,
        filename: String,
        line_number: usize,
        exact_domain: String,
    },
    Domain {
        pattern: String,
        filename: String,
        line_number: usize,
    },
    Wildcard {
        pattern: String,
        filename: String,
        line_number: usize,
    },
}

impl FilterPattern {
    fn matches(&self, domain: &str) -> bool {
        match self {
            FilterPattern::Exact { exact_domain, .. } => exact_domain == domain,
            FilterPattern::Domain { pattern, .. } => {
                let parts: Vec<&str> = domain.split('.').collect();
                for i in 0..parts.len() {
                    let domain_suffix = parts[i..].join(".");
                    if pattern == &domain_suffix {
                        return true;
                    }
                }
                false
            }
            FilterPattern::Wildcard { pattern, .. } => WildMatch::new(pattern).matches(domain),
        }
    }

    pub fn original_pattern(&self) -> &str {
        match self {
            FilterPattern::Exact { pattern, .. } => pattern,
            FilterPattern::Domain { pattern, .. } => pattern,
            FilterPattern::Wildcard { pattern, .. } => pattern,
        }
    }

    pub fn path(&self) -> String {
        match self {
            FilterPattern::Exact {
                filename,
                line_number,
                ..
            } => format!("{}:{}", filename, line_number),
            FilterPattern::Domain {
                filename,
                line_number,
                ..
            } => format!("{}:{}", filename, line_number),
            FilterPattern::Wildcard {
                filename,
                line_number,
                ..
            } => format!("{}:{}", filename, line_number),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterResult {
    Allow,
    Whitelisted(FilterPattern),
    Block(FilterPattern),
}

#[cfg(test)]
mod tests {
    use crate::filter::{DnsFilter, FilterPattern, FilterResult};

    #[tokio::test]
    async fn test_filter_loading() {
        let filter = DnsFilter::from_mock_data();
        let inner = filter.inner.read().await;
        assert_eq!(inner.filters.len(), 2);
    }

    #[tokio::test]
    async fn test_blacklisted_gets_blocked() {
        let filter = DnsFilter::from_mock_data();

        assert_eq!(
            filter.check_domain("facebook.com").await,
            FilterResult::Block(FilterPattern::Exact {
                pattern: "^facebook.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 1,
                exact_domain: "facebook.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("www.facebook.com").await,
            FilterResult::Block(FilterPattern::Exact {
                pattern: "^www.facebook.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 2,
                exact_domain: "www.facebook.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("instagram.com").await,
            FilterResult::Block(FilterPattern::Domain {
                pattern: "instagram.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 3
            })
        );
        assert_eq!(
            filter.check_domain("tiktokvideo.com").await,
            FilterResult::Block(FilterPattern::Wildcard {
                pattern: "*tiktok*".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 6
            })
        );
    }

    #[tokio::test]
    async fn test_whitelisted_is_allowed() {
        let filter = DnsFilter::from_mock_data();

        assert_eq!(
            filter.check_domain("packages.microsoft.com").await,
            FilterResult::Whitelisted(FilterPattern::Exact {
                pattern: "^packages.microsoft.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 2,
                exact_domain: "packages.microsoft.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("vscode.microsoft.com").await,
            FilterResult::Whitelisted(FilterPattern::Exact {
                pattern: "^vscode.microsoft.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 3,
                exact_domain: "vscode.microsoft.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("github.com").await,
            FilterResult::Whitelisted(FilterPattern::Domain {
                pattern: "github.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 8
            })
        );
        assert_eq!(
            filter.check_domain("api.example.com").await,
            FilterResult::Whitelisted(FilterPattern::Wildcard {
                pattern: "api.*.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 14
            })
        );
    }

    #[tokio::test]
    async fn test_non_blacklisted_is_allowed() {
        let filter = DnsFilter::from_default_path()
            .await
            .expect("Failed to read filters");

        assert_eq!(
            (filter.check_domain("example.com")).await,
            FilterResult::Allow
        );
        assert_eq!(
            (filter.check_domain("signal.org")).await,
            FilterResult::Allow
        );
    }
}
