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

Should Resolve With TCP
    [Documentation]    Test Swiftdns TCP listener functionality

    Start Swiftdns
    ${result}=    Query Domain    example.com    A    tcp=True

    Should Be Equal As Integers    ${result.rc}    0
    Should Contain    ${result.stdout}    status: NOERROR
    Should Contain    ${result.stdout}    SERVER: 127.0.0.1#55353(127.0.0.1) (TCP)

Should Handle Non-Existent Domain
    [Documentation]    Test non-existent domain handling

    Start Swiftdns
    Query Domain    nonexistent.invalid    A    NXDOMAIN
