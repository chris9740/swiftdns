use crate::config;
use wildmatch::WildMatch;

/// Common metadata shared by all filter pattern types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatternSource {
    pub pattern: String,
    pub filename: String,
    pub line_number: usize,
}

impl PatternSource {
    pub fn new(
        pattern: impl Into<String>,
        filename: impl Into<String>,
        line_number: usize,
    ) -> Self {
        Self {
            pattern: pattern.into(),
            filename: filename.into(),
            line_number,
        }
    }

    /// Returns the location string in "filename:line" format.
    pub fn location(&self) -> String {
        format!("{}:{}", self.filename, self.line_number)
    }
}

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
    /// Exact match: only matches the specified domain exactly (prefix: ^)
    Exact {
        source: PatternSource,
        exact_domain: String,
    },
    /// Domain match: matches the domain and all its subdomains
    Domain { source: PatternSource },
    /// Wildcard match: uses glob-style patterns with * wildcards
    Wildcard { source: PatternSource },
}

impl FilterPattern {
    /// Creates a new exact-match pattern.
    pub fn exact(pattern: &str, filename: &str, line_number: usize, exact_domain: &str) -> Self {
        Self::Exact {
            source: PatternSource::new(pattern, filename, line_number),
            exact_domain: exact_domain.to_string(),
        }
    }

    /// Creates a new domain-match pattern.
    pub fn domain(pattern: &str, filename: &str, line_number: usize) -> Self {
        Self::Domain {
            source: PatternSource::new(pattern, filename, line_number),
        }
    }

    /// Creates a new wildcard-match pattern.
    pub fn wildcard(pattern: &str, filename: &str, line_number: usize) -> Self {
        Self::Wildcard {
            source: PatternSource::new(pattern, filename, line_number),
        }
    }

    /// Returns the source metadata for this pattern.
    fn source(&self) -> &PatternSource {
        match self {
            Self::Exact { source, .. } | Self::Domain { source } | Self::Wildcard { source } => {
                source
            }
        }
    }

    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact { exact_domain, .. } => exact_domain == domain,
            Self::Domain { source } => {
                let parts: Vec<&str> = domain.split('.').collect();
                for i in 0..parts.len() {
                    let suffix = parts[i..].join(".");
                    if source.pattern == suffix {
                        return true;
                    }
                }
                false
            }
            Self::Wildcard { source } => WildMatch::new(&source.pattern).matches(domain),
        }
    }

    pub fn original_pattern(&self) -> &str {
        &self.source().pattern
    }

    pub fn path(&self) -> String {
        self.source().location()
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
