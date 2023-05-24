use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use wildmatch::WildMatch;

use crate::domain::Domain;

pub mod whitelist {

    use crate::config;

    use super::FilterEntry;

    pub fn find(name: &str) -> Option<FilterEntry> {
        let whitelist_path = config::get_path().join("rules/whitelist.txt");
        let exists = whitelist_path.try_exists().unwrap();

        if !exists {
            return None;
        }

        super::enumerate(&whitelist_path, name)
    }
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
            domain.name, self.pattern, self.file, self.line
        )
    }
}

pub mod blacklist {
    use std::fs;

    use crate::config;

    use super::FilterEntry;

    pub fn find(name: &str) -> Option<FilterEntry> {
        if super::whitelist::find(name).is_some() {
            return None;
        }

        let blacklists_dir = config::get_path().join("rules");

        match fs::read_dir(&blacklists_dir) {
            Ok(dir) => {
                for dir_entry in dir {
                    let dir_entry = dir_entry.expect("Should always be Ok");
                    let path = dir_entry.path();

                    if !path.is_file() {
                        continue;
                    }

                    let full_path = path.to_string_lossy().to_string();

                    if !full_path.ends_with(".txt") {
                        continue;
                    }

                    let result = super::enumerate(&path, name);

                    if result.is_some() {
                        return result;
                    }
                }

                None
            }
            Err(_) => None,
        }
    }
}

/// Enumerates the file and matches patterns against the domain name
fn enumerate(path: &PathBuf, name: &str) -> Option<FilterEntry> {
    let file = File::open(&path).unwrap();
    let reader = BufReader::new(file);

    for (index, entry) in reader.lines().enumerate() {
        let line = entry.unwrap();
        let pattern = line.trim();

        if pattern.starts_with("#") || pattern.len() == 0 {
            continue;
        }

        let filename = path.to_string_lossy().to_string();

        let line_number = index + 1;

        // This is a globstar pattern, a shorthand for blacklisting a domain and all it's subdomains.
        //
        // The pattern `**.example.com` will be "unwrapped" to two distinct patterns:
        // `example.com` and `*.example.com`
        if pattern.starts_with("**.") {
            let domain_pattern = &pattern[3..];
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

        if WildMatch::new(&pattern).matches(name) {
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
