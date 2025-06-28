*** Settings ***
Documentation       Tor proxy integration tests

Resource            common.resource

Test Teardown       Stop Swiftdns

Test Tags           tor


*** Test Cases ***
# This test doesn't actually verify that the DNS resolution is proxied through Tor,
# but it ensures that we can still resolve domains when Tor is enabled.
# We will need to implement a more robust test that checks the actual Tor routing.
Test DNS Resolution Through Tor
    [Documentation]    Test DNS resolution through Tor
    [Timeout]    45s

    Verify Tor Connection
    Start Swiftdns    tor_enabled=true    timeout=20

    Expect Answer    example.com    A    timeout=10


*** Keywords ***
Verify Tor Connection
    [Documentation]    Fail fast if Tor SOCKS port is not open
    ${result}=    Run Process    /usr/bin/nc    -z    127.0.0.1    9050
    Should Be Equal As Integers    ${result.rc}    0    msg=Tor SOCKS port is not open
