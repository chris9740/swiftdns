use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use wildmatch::WildMatch;

use crate::{config::get_config_path, domain::Domain};

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

pub struct FilterEntry<T> {
    pub file: String,
    pub pattern: String,
    pub line: usize,
    _marker: PhantomData<T>,
}

pub enum FilterType {
    Whitelist,
    Blacklist,
}

pub struct Whitelist;
pub struct Blacklist;

impl FilterEntry<Blacklist> {
    pub fn format_log_message(&self, domain: &Domain) -> String {
        format!(
            "{} has been blacklisted (pattern `{}`, {}:{}), refusing.",
            domain.name(),
            self.pattern,
            self.file,
            self.line
        )
    }
}

/// Retreives all filter entries from the configuration directory.
///
/// This reads from the `filters/` directory with infinite depth and returns a list of all filter files.
pub fn load_filters() -> Result<Vec<Filter>> {
    use crate::config;

    let base_directory_path = config::get_config_path().join("filters");
    let mut filters = Vec::new();

    // Define a recursive function to traverse directories
    fn visit_dirs(dir: &Path, filters: &mut Vec<Filter>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    // Recursively call visit_dirs for subdirectories
                    visit_dirs(&path, filters)?;
                } else {
                    let pathname = path.to_string_lossy().to_string();

                    // Check if the entry is a file and ends with ".list"
                    if pathname.ends_with(".list") {
                        let contents =
                            fs::read_to_string(&path).context("Failed to read filter contents")?;
                        let filename = path
                            .file_name()
                            .context("Failed to get filename")?
                            .to_string_lossy()
                            .to_string();

                        filters.push(Filter {
                            path: path.clone(),
                            pathname,
                            filename,
                            contents,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    // Start the recursive traversal from the base directory
    visit_dirs(&base_directory_path, &mut filters)?;

    Ok(filters)
}

pub mod whitelist {
    use crate::config;

    use super::{FilterEntry, Whitelist};

    /// Searches for a domain in the whitelist filters and returns the relevant filter entry if found.
    pub fn find(name: &str) -> Option<FilterEntry<Whitelist>> {
        let whitelist_path = config::get_config_path().join("filters/whitelist.list");
        let exists = whitelist_path.try_exists().unwrap_or(false);

        if !exists {
            return None;
        }

        super::enumerate(&whitelist_path, name)
    }
}

pub mod blacklist {
    use super::{Blacklist, FilterEntry};

    /// Searches for a domain in the blacklist filters and returns the relevant filter entry if found,
    /// unless the domain is also found in the whitelist.
    pub fn find(name: &str) -> Option<FilterEntry<Blacklist>> {
        if super::whitelist::find(name).is_some() {
            return None;
        }

        let filters = super::load_filters().unwrap();

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
fn enumerate<T>(path: &PathBuf, name: &str) -> Option<FilterEntry<T>> {
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

        if let Some(domain_pattern) = pattern.strip_prefix('^') {
            if WildMatch::new(domain_pattern).matches(name) {
                return Some(FilterEntry {
                    file: filename,
                    pattern: pattern.to_string(),
                    line: line_number,
                    _marker: PhantomData,
                });
            }
        }

        let subdomain_pattern = format!("*.{}", pattern);

        if WildMatch::new(pattern).matches(name) || WildMatch::new(&subdomain_pattern).matches(name)
        {
            return Some(FilterEntry {
                file: filename,
                pattern: pattern.to_string(),
                line: line_number,
                _marker: PhantomData,
            });
        }
    }

    None
}

/// Initiates a migration process for filter files to update their formatting or content.
///
/// Checks if a migration is needed by looking for a '.migrated' marker file. If not found,
/// it reads each filter file, updates lines according to specified rules, and writes the changes back.
/// It finally creates a '.migrated' file to mark completion.
pub fn migrate_filters() -> Result<()> {
    let migration_marker_path = get_config_path().join("filters/.migrated");

    if migration_marker_path.exists() {
        return Ok(());
    }

    let filters = load_filters()?;

    for filter in filters {
        let mut updated_lines: Vec<String> = Vec::new();

        for line in filter.contents.lines() {
            let line = line.trim().to_string();

            if let Some(stripped_line) = line.strip_prefix("**.") {
                updated_lines.push(stripped_line.to_string());
                continue;
            }

            if line.starts_with('#')
                || line.is_empty()
                || line.starts_with('*')
                || line.starts_with('^')
            {
                updated_lines.push(line);
                continue;
            }

            updated_lines.push(format!("^{line}"));
        }

        let mut file = File::create(filter.path)?;

        for line in updated_lines {
            writeln!(file, "{}", line)?;
        }
    }

    let mut migration_marker = File::create(migration_marker_path)?;

    writeln!(
        migration_marker,
        "This file is used to indicate that the filter migration has been completed"
    )?;

    Ok(())
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
