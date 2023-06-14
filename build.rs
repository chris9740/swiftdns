use std::{process::Command, path::Path};

fn main() {
    let profile = std::env::var("PROFILE").unwrap();
    let is_git_repo = Path::new(".git/").exists();

    if profile == "debug" && is_git_repo {
        let log_output = Command::new("git")
            .arg("log")
            .arg("-1")
            .arg("--pretty=format:\"%h\"")
            .output()
            .expect("Failed to run git command");

        let commit_hash = String::from_utf8_lossy(&log_output.stdout);
        let pkg_version = env!("CARGO_PKG_VERSION");
        let github_url = "https://github.com/chris9740/swiftdns";

        let file_header = concat!(
            "# This file is managed by build.rs, don't edit this file as it will be overwritten.\n",
            "# It contains information about the project and will be read by scripts/install.sh\n",
        );

        let metadata = format!(
            "{}\nCOMMIT_HASH={}\nPKG_VERSION={}\nGITHUB_URL={}\n",
            file_header, commit_hash, pkg_version, github_url
        );

        std::fs::write("assets/.metadata.sh", metadata).expect("Failed to write to metadata file");
    }
}
