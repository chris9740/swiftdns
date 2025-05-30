use assert_cmd::Command;
use predicates::prelude::*;

fn test_command() -> Command {
    std::env::set_var("SWIFTDNS_CLI_TEST_MODE", "1");
    Command::cargo_bin("swiftdns").unwrap()
}

#[test]
fn test_demo_command() {
    let mut cmd = Command::cargo_bin("swiftdns").unwrap();
    let assert = cmd.arg("demo").arg("example.com").assert();

    assert
        .success()
        .stdout(predicate::str::contains("example.com is not blacklisted"));

    let mut cmd = Command::cargo_bin("swiftdns").unwrap();
    let assert = cmd.arg("demo").arg("google.com").assert();

    assert.success().stdout(predicate::str::contains(
        "google.com is blacklisted (pattern `^google.com`)",
    ));
}

#[test]
fn test_resolve_command() {
    let mut cmd = test_command();
    let assert = cmd.arg("resolve").arg("example.com").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Upstream DNS: dns.swiftdns.mock"))
        .stdout(predicate::str::contains("93.184.216.34"))
        .stdout(predicate::str::contains("Upstream DNS:"))
        .stdout(predicate::str::contains("(1 record found"));

    let mut cmd = test_command();
    let assert = cmd.arg("resolve").arg("nxdomain.example").assert();

    assert
        .success()
        .stdout(predicate::str::contains("Domain does not exist"));

    let mut cmd = test_command();
    let assert = cmd.arg("resolve").arg("example.com").arg("AAAA").assert();

    assert
        .success()
        .stdout(predicate::str::contains("DNS error: NotImp"));

    std::env::remove_var("SWIFTDNS_CLI_TEST_MODE");
}
