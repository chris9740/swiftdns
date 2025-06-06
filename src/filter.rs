use std::{fs, path::Path};

use wildmatch::WildMatch;

use crate::config;

#[derive(Debug, thiserror::Error)]
#[error("Filter error: {0}")]
pub enum FilterError {
    IoError(String),
}

impl From<std::io::Error> for FilterError {
    fn from(err: std::io::Error) -> Self {
        FilterError::IoError(err.to_string())
    }
}

#[derive(Debug, Default)]
pub struct DnsFilter {
    filters: Vec<FilterData>,
    whitelist: Vec<FilterPattern>,
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

impl DnsFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_default_path() -> Result<Self, FilterError> {
        Self::from_path(config::get_filters_path())
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, FilterError> {
        let mut filter = Self::new();
        filter.load_filters(path)?;
        Ok(filter)
    }

    fn load_filters<P>(&mut self, path: P) -> Result<(), FilterError>
    where
        P: AsRef<Path>,
    {
        let file_data = self.read_filter_files(path)?;
        self.load_filter_data(file_data)
    }

    fn read_filter_files<P>(&self, path: P) -> Result<Vec<(String, String)>, FilterError>
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

    fn load_filter_data(&mut self, files: Vec<(String, String)>) -> Result<(), FilterError> {
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
                    self.whitelist.push(filter_pattern);
                } else {
                    blacklist_data.as_mut().unwrap().add_pattern(filter_pattern);
                }
            }

            if let Some(data) = blacklist_data {
                self.filters.push(data);
            }
        }
        Ok(())
    }

    pub fn check_domain(&self, domain: &str) -> FilterResult {
        if let Some(pattern) = self.whitelist.iter().find(|rule| rule.matches(domain)) {
            return FilterResult::Whitelisted(pattern.clone());
        }

        for filter in &self.filters {
            let mut patterns = Vec::new();

            patterns.extend(&filter.exact_matches);
            patterns.extend(&filter.domain_matches);
            patterns.extend(&filter.wildcard_patterns);

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
        let mut filter = Self::default();

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

        filter.load_filter_data(mock_files).unwrap();
        filter
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

    #[test]
    fn test_filter_loading() {
        let filter = DnsFilter::from_mock_data();
        assert_eq!(filter.filters.len(), 2);
    }

    #[test]
    fn test_blacklisted_gets_blocked() {
        let filter = DnsFilter::from_mock_data();

        assert_eq!(
            filter.check_domain("facebook.com"),
            FilterResult::Block(FilterPattern::Exact {
                pattern: "^facebook.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 1,
                exact_domain: "facebook.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("www.facebook.com"),
            FilterResult::Block(FilterPattern::Exact {
                pattern: "^www.facebook.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 2,
                exact_domain: "www.facebook.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("instagram.com"),
            FilterResult::Block(FilterPattern::Domain {
                pattern: "instagram.com".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 3
            })
        );
        assert_eq!(
            filter.check_domain("tiktokvideo.com"),
            FilterResult::Block(FilterPattern::Wildcard {
                pattern: "*tiktok*".to_string(),
                filename: "social-media.list".to_string(),
                line_number: 6
            })
        );
    }

    #[test]
    fn test_whitelisted_is_allowed() {
        let filter = DnsFilter::from_mock_data();

        assert_eq!(
            filter.check_domain("packages.microsoft.com"),
            FilterResult::Whitelisted(FilterPattern::Exact {
                pattern: "^packages.microsoft.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 2,
                exact_domain: "packages.microsoft.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("vscode.microsoft.com"),
            FilterResult::Whitelisted(FilterPattern::Exact {
                pattern: "^vscode.microsoft.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 3,
                exact_domain: "vscode.microsoft.com".to_string()
            })
        );
        assert_eq!(
            filter.check_domain("github.com"),
            FilterResult::Whitelisted(FilterPattern::Domain {
                pattern: "github.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 8
            })
        );
        assert_eq!(
            filter.check_domain("api.example.com"),
            FilterResult::Whitelisted(FilterPattern::Wildcard {
                pattern: "api.*.com".to_string(),
                filename: "whitelist.list".to_string(),
                line_number: 14
            })
        );
    }

    #[test]
    fn test_non_blacklisted_is_allowed() {
        let filter = DnsFilter::from_default_path().expect("Failed to read filters");

        assert_eq!(filter.check_domain("example.com"), FilterResult::Allow);
        assert_eq!(filter.check_domain("signal.org"), FilterResult::Allow);
    }
}
