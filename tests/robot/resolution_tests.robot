*** Settings ***
Documentation       Basic DNS resolution tests

Resource            common.resource

Test Teardown       Stop Swiftdns


*** Test Cases ***
Should Resolve A Record
    [Documentation]    Test basic A record resolution

    Start Swiftdns
    Expect Answer    example.com    A

Should Resolve AAAA Record
    [Documentation]    Test AAAA record resolution

    Start Swiftdns
    Expect Answer    example.com    AAAA

Should Handle Non-Existent Domain
    [Documentation]    Test non-existent domain handling

    Start Swiftdns
    Query Domain    nonexistent.invalid    A    NXDOMAIN
