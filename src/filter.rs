use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::PathBuf,
};

use anyhow::Result;
use wildmatch::WildMatch;

use crate::domain::Domain;

#[derive(serde::Serialize, Debug)]
pub struct Filter {
    #[serde(skip_serializing)]
    pub path: PathBuf,
    #[serde(skip_serializing)]
    pub pathname: String,
    #[serde(skip_serializing)]
    pub contents: String,
    pub filename: String,
}

pub struct FilterEntry {
    pub file: String,
    pub pattern: String,
    pub line: usize,
}

impl FilterEntry {
    pub fn format_message(&self, domain: &Domain) -> String {
        format!(
            "the domain `{}` has been blacklisted (pattern `{}`, {}:{}), refusing to resolve.",
            domain.name(),
            self.pattern,
            self.file,
            self.line
        )
    }
}

pub fn get_filters() -> Result<Vec<Filter>> {
    use crate::config;

    let directory_path = config::config_location().join("filters");
    let directory = fs::read_dir(directory_path)?;

    let filters: Vec<Filter> = directory
        .filter_map(|object| {
            let dir_entry = object.expect("Should always be Ok");

            let path = dir_entry.path();
            let pathname = path.to_string_lossy().to_string();

            if !path.is_file() || !pathname.ends_with(".list") {
                return None;
            }

            let contents = fs::read_to_string(&path).unwrap_or_default();
            let filename = path.file_name()?.to_string_lossy().to_string();

            Some(Filter {
                path,
                pathname,
                filename,
                contents
            })
        })
        .collect();

    Ok(filters)
}

pub mod whitelist {

    use crate::config;

    use super::FilterEntry;

    pub fn find(name: &str) -> Option<FilterEntry> {
        let whitelist_path = config::config_location().join("filters/whitelist.list");
        let exists = whitelist_path.try_exists().unwrap_or(false);

        if !exists {
            return None;
        }

        super::enumerate(&whitelist_path, name)
    }
}

pub mod blacklist {
    use super::FilterEntry;

    pub fn find(name: &str) -> Option<FilterEntry> {
        if super::whitelist::find(name).is_some() {
            return None;
        }

        let filters = super::get_filters().unwrap();

        let blacklists = filters
            .iter()
            .filter(|filter| filter.filename != "whitelist.list");

        for filter in blacklists {
            let result = super::enumerate(&filter.path, name);

            if result.is_some() {
                return result;
            }
        }

        None
    }
}

/// Enumerates the file and matches patterns against the domain name
fn enumerate(path: &PathBuf, name: &str) -> Option<FilterEntry> {
    let file = File::open(path).unwrap();
    let reader = BufReader::new(file);

    for (index, entry) in reader.lines().enumerate() {
        let line = entry.unwrap();
        let pattern = line.trim();

        if pattern.starts_with('#') || pattern.is_empty() {
            continue;
        }

        let filename = path.to_string_lossy().to_string();

        let line_number = index + 1;

        // This is a globstar pattern, a shorthand for blacklisting a domain and all it's subdomains.
        //
        // The pattern `**.example.com` will be "unwrapped" to two distinct patterns:
        // `example.com` and `*.example.com`
        if pattern.starts_with("**.") {
            let domain_pattern = pattern.strip_prefix("**.").unwrap();
            let subdomain_pattern = format!("*.{}", domain_pattern);

            if WildMatch::new(domain_pattern).matches(name)
                || WildMatch::new(&subdomain_pattern).matches(name)
            {
                return Some(FilterEntry {
                    file: filename,
                    pattern: pattern.to_string(),
                    line: line_number,
                });
            }
        }

        if WildMatch::new(pattern).matches(name) {
            return Some(FilterEntry {
                file: filename,
                pattern: pattern.to_string(),
                line: line_number,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::blacklist;

    #[test]
    fn filters_bad_domains() {
        assert!(blacklist::find("google.com").is_some());
        assert!(blacklist::find("maps.google.com").is_some());
        assert!(blacklist::find("google-analytics.com").is_some());
        assert!(blacklist::find("tiktokv.com").is_some());
        assert!(blacklist::find("facebook.com").is_some());
        assert!(blacklist::find("doubleclick.net").is_some());
    }

    #[test]
    fn allows_good_domains() {
        assert!(blacklist::find("duckduckgo.com").is_none());
        assert!(blacklist::find("signal.org").is_none());
        assert!(blacklist::find("tutanota.com").is_none());
    }
}
