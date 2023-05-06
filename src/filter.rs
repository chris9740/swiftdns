pub mod blacklist {
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use std::{fs, path::Path};
    use wildmatch::WildMatch;

    pub struct BlacklistEntry {
        pub file: String,
        pub pattern: String,
        pub line: usize,
    }

    pub fn find(name: &str) -> Option<BlacklistEntry> {
        let rules_path = if cfg!(debug_assertions) {
            Path::new("./rules").to_path_buf()
        } else {
            Path::new("/etc/swiftdns/rules").to_path_buf()
        };

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
