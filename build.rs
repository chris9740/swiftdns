fn main() {
    let git_commit = std::process::Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .expect("Failed to get git commit hash");
    let git_commit = String::from_utf8(git_commit.stdout)
        .expect("Failed to convert git commit hash to string")
        .trim()
        .to_string();

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", git_commit);
}
