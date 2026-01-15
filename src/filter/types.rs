use crate::config;
use wildmatch::WildMatch;

#[derive(Debug, Default, Clone)]
pub struct FilterData {
    pub exact_matches: Vec<FilterPattern>,
    pub domain_matches: Vec<FilterPattern>,
    pub wildcard_patterns: Vec<FilterPattern>,
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
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            FilterPattern::Exact { exact_domain, .. } => exact_domain == domain,
            FilterPattern::Domain { pattern, .. } => {
                let parts: Vec<&str> = domain.split('.').collect();
                for i in 0..parts.len() {
                    let suffix = parts[i..].join(".");
                    if pattern == &suffix {
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
        let (filename, line_number) = match self {
            FilterPattern::Exact {
                filename,
                line_number,
                ..
            } => (filename, line_number),
            FilterPattern::Domain {
                filename,
                line_number,
                ..
            } => (filename, line_number),
            FilterPattern::Wildcard {
                filename,
                line_number,
                ..
            } => (filename, line_number),
        };
        format!("{}:{}", filename, line_number)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum FilterResult {
    Allow,
    Whitelisted(FilterPattern),
    Block(FilterPattern),
}

#[derive(Debug, thiserror::Error)]
#[error("Filter error: {0}")]
pub enum FilterError {
    IoError(String),
    ConfigError(config::error::ConfigError),
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
