use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

use crate::{
    config,
    filter::{
        loader::{populate_filter_context, scan_dir},
        types::{FilterData, FilterError, FilterPattern, FilterResult},
    },
};

mod loader;
pub mod types;

#[cfg(feature = "notify")]
pub mod observer;

#[derive(Debug, Default, Clone)]
struct FilterContext {
    filters: Vec<FilterData>,
    whitelist: Vec<FilterPattern>,
}

#[derive(Debug, Clone)]
pub struct DomainFilter {
    path: PathBuf,
    context: Arc<RwLock<FilterContext>>,
}

impl DomainFilter {
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self, FilterError> {
        let path = path.as_ref().to_path_buf();
        let context = Arc::new(RwLock::new(FilterContext::default()));
        let filter = DomainFilter {
            path: path.clone(),
            context,
        };
        filter.reload().await?;
        Ok(filter)
    }

    pub async fn from_default_path() -> Result<Self, FilterError> {
        DomainFilter::new(config::get_filters_path()).await
    }

    pub async fn reload(&self) -> Result<(), FilterError> {
        let file_data = scan_dir(&self.path)?;
        let mut filter = self.context.write().await;
        populate_filter_context(&mut filter, file_data)?;
        Ok(())
    }

    pub async fn check_domain(&self, domain: &str) -> FilterResult {
        let filter = self.context.read().await;

        if let Some(pattern) = filter.whitelist.iter().find(|rule| rule.matches(domain)) {
            return FilterResult::Whitelisted(pattern.clone());
        }

        for filter_data in &filter.filters {
            let patterns = filter_data
                .exact_matches
                .iter()
                .chain(filter_data.domain_matches.iter())
                .chain(filter_data.wildcard_patterns.iter());

            for pattern in patterns {
                if pattern.matches(domain) {
                    return FilterResult::Block(pattern.clone());
                }
            }
        }

        FilterResult::Allow
    }

    pub fn from_mock_data() -> Self {
        let mock_files = vec![
            (
                "social-media.list".into(),
                "^facebook.com\ninstagram.com\n*tiktok*".into(),
            ),
            (
                "advertising.list".into(),
                "doubleclick.net\n*ads*\n^googleads.com".into(),
            ),
            (
                "whitelist.list".into(),
                "^packages.microsoft.com\ngithub.com\napi.*.com".into(),
            ),
        ];

        let mut inner = FilterContext::default();
        populate_filter_context(&mut inner, mock_files).unwrap();

        DomainFilter {
            path: PathBuf::new(),
            context: Arc::new(RwLock::new(inner)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::filter::{types::FilterResult, DomainFilter, FilterPattern};

    #[tokio::test]
    async fn test_filter_loading() {
        let filter = DomainFilter::from_mock_data();
        let inner = filter.context.read().await;
        assert_eq!(inner.filters.len(), 2);
    }

    #[tokio::test]
    async fn test_blacklisted_gets_blocked() {
        let filter = DomainFilter::from_mock_data();

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
            filter.check_domain("instagram.com").await,
            FilterResult::Block(FilterPattern::Domain {
                pattern: "instagram.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 2
            })
        );
        assert_eq!(
            filter.check_domain("tiktokvideo.com").await,
            FilterResult::Block(FilterPattern::Wildcard {
                pattern: "*tiktok*".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 3
            })
        );
    }

    #[tokio::test]
    async fn test_whitelisted_is_allowed() {
        let filter = DomainFilter::from_mock_data();

        assert_eq!(
            filter.check_domain("packages.microsoft.com").await,
            FilterResult::Whitelisted(FilterPattern::Exact {
                pattern: "^packages.microsoft.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 1,
                exact_domain: "packages.microsoft.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("github.com").await,
            FilterResult::Whitelisted(FilterPattern::Domain {
                pattern: "github.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 2
            })
        );
        assert_eq!(
            filter.check_domain("api.example.com").await,
            FilterResult::Whitelisted(FilterPattern::Wildcard {
                pattern: "api.*.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 3
            })
        );
    }

    #[tokio::test]
    async fn test_non_blacklisted_is_allowed() {
        let filter = DomainFilter::from_mock_data();

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
