pub mod blacklist {
    use std::fs;
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use wildmatch::WildMatch;

    use crate::config;
    use crate::domain::Domain;

    pub struct BlacklistEntry {
        pub pattern: String,
        pub path: String,
        pub line: usize,
    }

    impl BlacklistEntry {
        pub fn format_message(&self, domain: &Domain) -> String {
            format!(
                "the domain `{}` has been blacklisted (pattern `{}`, {}:{}), refusing to resolve.",
                domain.name, self.pattern, self.path, self.line
            )
        }
    }

    pub fn find(name: &str) -> Option<BlacklistEntry> {
        let rules_path = config::get_path().join("rules");

        if let Ok(dir) = fs::read_dir(rules_path) {
            for dir_entry in dir {
                let path = dir_entry.unwrap().path();

                if !path.is_file() {
                    continue;
                }

                let full_path = path.to_string_lossy().to_string();

                if !full_path.ends_with(".txt") {
                    continue;
                }

                let file = File::open(&full_path).unwrap();
                let reader = BufReader::new(file);

                for (index, entry) in reader.lines().enumerate() {
                    let pattern = entry.unwrap();

                    if self::matches(&pattern, name) {
                        let line = index + 1;

                        return Some(BlacklistEntry {
                            pattern: pattern,
                            path: full_path.clone(),
                            line: line,
                        });
                    }
                }
            }
        }

        None
    }

    fn matches(pattern: &str, name: &str) -> bool {
        /*
         * This is a globstar pattern, a shorthand for blacklisting a domain and all it's subdomains.
         *
         * Example:
         *
         * The rule "**.example.com" will be unpacked to two distinct rules:
         * "example.com" and "*.example.com"
         */
        if pattern.starts_with("**.") {
            let domain_pattern = &pattern[3..];
            let subdomain_pattern = format!("*.{}", domain_pattern);

            if WildMatch::new(domain_pattern).matches(name)
                || WildMatch::new(&subdomain_pattern).matches(name)
            {
                return true;
            }
        }

        if WildMatch::new(&pattern).matches(name) {
            return true;
        }

        false
    }
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
