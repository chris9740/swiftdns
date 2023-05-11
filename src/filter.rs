pub mod blacklist {
    use std::fs;
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use wildmatch::WildMatch;

    use crate::config;

    pub struct BlacklistEntry {
        pub file: String,
        pub pattern: String,
        pub line: usize,
    }

    pub fn find(name: &str) -> Option<BlacklistEntry> {
        let rules_path = config::get_path().join("rules");

        match fs::read_dir(&rules_path) {
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

                    let f = File::open(&full_path).unwrap();
                    let reader = BufReader::new(f);

                    for (index, entry) in reader.lines().enumerate() {
                        let line = entry.unwrap();

                        if line.starts_with("#") || line.trim().len() == 0 {
                            continue;
                        }

                        if WildMatch::new(&line).matches(name) {
                            return Some(BlacklistEntry {
                                file: full_path,
                                pattern: line.to_string(),
                                line: index + 1,
                            });
                        }
                    }
                }

                None
            }
            Err(_) => None,
        }
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
