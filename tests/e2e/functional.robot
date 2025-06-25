*** Settings ***
Documentation       Functional tests for Swiftdns

Library             Collections
Library             DateTime
Library             OperatingSystem
Library             Process
Library             String

Test Teardown       Stop Swiftdns


*** Variables ***
${BINARY_PATH}      ${CURDIR}/../../target/debug/swiftdns
${CONFIG_PATH}      ${CURDIR}/test-config.toml
${FILTER_DIR}       ${CURDIR}/../../assets/filters
${PORT}             55353
${TOR_AVAILABLE}    ${TRUE}


*** Test Cases ***
Basic DNS Resolution
    [Documentation]    Test basic DNS resolution functionality
    Start Swiftdns
    Expect DNS Answer    example.com    A
    Expect DNS Answer    example.com    AAAA

Different Record Types
    [Documentation]    Test resolution of different DNS record types
    Start Swiftdns
    Expect DNS Answer    example.com    A
    Expect DNS Answer    example.com    AAAA
    Expect DNS Answer    example.com    MX
    Expect DNS Answer    example.com    TXT

Domain Blocking Test
    [Documentation]    Test that blacklisted domains are blocked
    Start Swiftdns
    Expect Blocked Response    facebook.com    A
    Expect Blocked Response    instagram.com    A
    Expect Blocked Response    tiktokvideo.com    A

IPv6 Blocking Test
    [Documentation]    Test IPv6 sinkhole blocking
    Start Swiftdns
    Expect Blocked Response    facebook.com    AAAA
    Expect Blocked Response    instagram.com    AAAA

Whitelist Override Test
    [Documentation]    Test that whitelisted domains bypass blacklists
    Start Swiftdns
    Expect DNS Answer    business.facebook.com    A
    Expect DNS Answer    github.com    A

NXDOMAIN Handling
    [Documentation]    Test handling of non-existent domains
    Start Swiftdns
    Expect DNS Error    thisdoesnotexist.invalid    A    NXDOMAIN

Blocking Strategies
    [Documentation]    Test different blocking strategies
    Test Blocking Strategy    refused    facebook.com    REFUSED
    Test Blocking Strategy    nxdomain    facebook.com    NXDOMAIN
    Test Blocking Strategy    sinkhole    facebook.com    NOERROR

Dynamic Filter Reload Test
    [Documentation]    Test that filter changes are detected and applied
    Create Directory    ${FILTER_DIR}
    Start Swiftdns

    # Test with real domain first (should work)
    Expect DNS Answer    github.com    A

    # Add github.com to blocklist
    Create Filter File    ${FILTER_DIR}/dynamic-e2e-test.list    github.com
    Sleep    1s    # Wait for file watcher
    Expect Blocked Response    github.com    A

    # Remove from blocklist
    Remove File    ${FILTER_DIR}/dynamic-e2e-test.list
    Sleep    1s
    Expect DNS Answer    github.com    A

Tor Integration Test
    [Documentation]    Test Tor proxy integration (requires Tor to be running)
    [Timeout]    3s
    Check Tor Is Running
    Skip If    not ${TOR_AVAILABLE}    Tor not available for testing
    Start Swiftdns    tor_enabled=true    wait_timeout=5
    ${result}=    Run Dig Query    example.com    A
    Should Contain    ${result.stdout}    ANSWER SECTION
    Log    Tor integration test completed - response: ${result.stdout}

Network Error Handling
    [Documentation]    Test behavior when upstream resolver is unreachable
    Start Swiftdns
    ...    resolver_url=https://nonexistent.resolver.invalid/dns-query
    ...    bootstrap_ips=["192.0.2.1:443"]

    ${result}=    Run Dig Query    example.com    A    timeout=3    expected_status=SERVFAIL
    Log    Network error test completed - response: ${result.stdout}

Multiple Blocking Strategies Test
    [Documentation]    Test all blocking strategies with template
    [Template]    Test Blocking Strategy
    refused    facebook.com    REFUSED
    nxdomain    facebook.com    NXDOMAIN
    sinkhole    facebook.com    NOERROR
    sinkhole    instagram.com    NOERROR

Performance Baseline Test
    [Documentation]    Establish performance baselines for DNS queries
    Start Swiftdns
    ${avg_duration}=    Measure Average Query Time
    ...    example.com
    ...    github.com
    ...    mozilla.org
    ...    debian.org
    ...    kernel.org

    Log    Average query time: ${avg_duration}s
    Should Be True
    ...    ${avg_duration} < 0.080
    ...    msg=Queries should complete within 80 milliseconds, but average was ${avg_duration}s

Log Analysis Test
    [Documentation]    Test that appropriate logs are generated
    Start Swiftdns
    Expect Blocked Response    facebook.com    A

    # Stop and capture logs
    Send Signal To Process    SIGTERM    swiftdns
    ${result}=    Wait For Process    swiftdns    timeout=5s

    Log    ${result.stdout}

    # Check logs for blocked domain
    Should Contain
    ...    ${result.stdout}
    ...    Query for facebook.com refused (pattern `facebook.com`, path `meta.list:9`)
    ...    msg=Should log blocked domain


*** Keywords ***
Create Test Config
    [Documentation]    Create a test configuration file for Swiftdns
    [Arguments]    ${strategy}=sinkhole
    ...    ${tor_enabled}=false
    ...    ${resolver_url}=https://cloudflare-dns.com/dns-query
    ...    ${bootstrap_ips}=["1.1.1.1:443"]

    ${config_content}=    Catenate    SEPARATOR=\n
    ...    address = "127.0.0.1:${PORT}"
    ...    [resolver]
    ...    url = "${resolver_url}"
    ...    bootstrap_ips = ${bootstrap_ips}
    ...    [blocking]
    ...    strategy = "${strategy}"
    ...    [tor]
    ...    enabled = ${tor_enabled}
    Create File    ${CONFIG_PATH}    ${config_content}

Create Filter File
    [Documentation]    Create a filter file with given content
    [Arguments]    ${file_path}    ${content}
    Create File    ${file_path}    ${content}

Create Invalid Config
    [Documentation]    Create an intentionally invalid configuration
    ${config_content}=    Catenate    SEPARATOR=\n
    ...    address = "invalid-address"
    ...    [resolver]
    ...    url = "not-a-url"
    ...    [blocking]
    ...    strategy = "invalid-strategy"
    Create File    ${CONFIG_PATH}    ${config_content}

Wait For Swiftdns UDP
    [Documentation]    Wait for Swiftdns to respond to a UDP query
    [Arguments]    ${domain}=example.com    ${port}=${PORT}    ${timeout}=1
    ${start}=    Get Time    epoch
    FOR    ${_}    IN RANGE    0    ${timeout * 5}
        ${result}=    Run Process    dig    @127.0.0.1    -p    ${port}    ${domain}    A    stderr=STDOUT
        IF    not ${result.rc}    BREAK
        Sleep    0.1s
    END
    ${end}=    Get Time    epoch
    ${elapsed}=    Evaluate    ${end} - ${start}
    Should Be Equal As Integers
    ...    ${result.rc}    0
    ...    msg=Swiftdns did not respond to UDP query in ${timeout} seconds (waited ${elapsed}s)

Start Swiftdns
    [Documentation]    Start the Swiftdns proxy with configurable options
    [Arguments]    ${strategy}=sinkhole
    ...    ${tor_enabled}=false
    ...    ${resolver_url}=https://cloudflare-dns.com/dns-query
    ...    ${bootstrap_ips}=["1.1.1.1:443"]
    ...    ${wait_timeout}=1

    Create Test Config
    ...    strategy=${strategy}
    ...    tor_enabled=${tor_enabled}
    ...    resolver_url=${resolver_url}
    ...    bootstrap_ips=${bootstrap_ips}

    File Should Exist    ${BINARY_PATH}
    File Should Exist    ${CONFIG_PATH}

    Start Process
    ...    ${BINARY_PATH}
    ...    start
    ...    --config
    ...    ${CONFIG_PATH}
    ...    --address
    ...    127.0.0.1:${PORT}
    ...    stderr=STDOUT
    ...    alias=swiftdns

    Wait For Swiftdns UDP    timeout=${wait_timeout}

Check Tor Is Running
    [Documentation]    Fail fast if Tor SOCKS port is not open
    ${result}=    Run Process    /usr/bin/nc    -z    127.0.0.1    9050
    Should Be Equal As Integers    ${result.rc}    0    msg=Tor SOCKS port is not open

Test Blocking Strategy
    [Documentation]    Helper to test a blocking strategy and expected DNS status
    [Arguments]    ${strategy}    ${domain}    ${expected_status}
    Start Swiftdns    strategy=${strategy}
    Run Dig Query    ${domain}    A    ${expected_status}
    Stop Swiftdns

Stop Swiftdns
    [Documentation]    Stop the Swiftdns proxy and clean up
    [Arguments]    ${proxy}=swiftdns
    ${proxy_exists}=    Run Keyword And Return Status    Variable Should Exist    ${proxy}
    IF    ${proxy_exists}
        Send Signal To Process    SIGTERM    ${proxy}
        ${result}=    Wait For Process    ${proxy}    timeout=10s
        Log    ${result.rc}
        Log    ${result.stdout}
        Log    ${result.stderr}
    END
    Wait Until Keyword Succeeds    5x    0.5s    Port Should Not Be Listening    ${PORT}
    ${config_exists}=    Run Keyword And Return Status    File Should Exist    ${CONFIG_PATH}
    IF    ${config_exists}    Remove File    ${CONFIG_PATH}

Port Should Not Be Listening
    [Documentation]    Check that a port is not listening
    [Arguments]    ${port}
    ${result}=    Run Process    bash    -c    "ss -lun | grep -q :${port}"    shell=True
    Should Not Be Equal As Integers    ${result.rc}    0    msg=Port ${port} is still in use

Run Dig Query
    [Documentation]    Run a dig query against the Swiftdns proxy
    [Arguments]    ${domain}=example.com
    ...    ${record_type}=A
    ...    ${expected_status}=NOERROR
    ...    ${timeout}=5
    ...    ${retry}=1

    VAR    ${timeout_arg}=    +timeout=${timeout}
    VAR    ${retry_arg}=    +retry=${retry}
    VAR    ${server_arg}=    @127.0.0.1

    ${result}=    Run Process
    ...    dig
    ...    ${timeout_arg}
    ...    ${retry_arg}
    ...    ${server_arg}
    ...    -p
    ...    ${PORT}
    ...    ${domain}
    ...    ${record_type}
    ...    stderr=STDOUT

    Log    ${result.stdout}
    Should Be Equal As Integers    ${result.rc}    0    msg=dig command failed
    Should Contain    ${result.stdout}    status: ${expected_status}    msg=Expected DNS status ${expected_status}
    RETURN    ${result}

Expect DNS Answer
    [Documentation]    Expect a DNS answer for a given domain and record type
    [Arguments]    ${domain}=example.com    ${record_type}=A
    ${result}=    Run Dig Query    ${domain}    ${record_type}
    Should Contain    ${result.stdout}    ANSWER SECTION    msg=Expected answer section in DNS response
    Should Contain    ${result.stdout}    status: NOERROR    msg=Expected NOERROR status in DNS response
    RETURN    ${result}

Expect DNS Error
    [Documentation]    Expect a DNS error response for a given domain and record type
    [Arguments]    ${domain}=example.com    ${record_type}=A    ${expected_status}=NXDOMAIN
    ${result}=    Run Dig Query    ${domain}    ${record_type}    ${expected_status}
    Should Not Contain    ${result.stdout}    ANSWER SECTION    msg=Should not have answer section for error response
    RETURN    ${result}

Expect Blocked Response
    [Documentation]    Expect a blocked response for a domain and record type
    [Arguments]    ${domain}=facebook.com    ${record_type}=A

    ${result}=    Run Dig Query    ${domain}    ${record_type}    NOERROR

    IF    "${record_type}" == "A"
        Should Contain    ${result.stdout}    0.0.0.0    msg=Expected sinkhole IP for blocked A record
    ELSE IF    "${record_type}" == "AAAA"
        Should Contain    ${result.stdout}    ::    msg=Expected sinkhole IPv6 for blocked AAAA record
    ELSE
        Run Dig Query    ${domain}    ${record_type}    REFUSED
    END
    RETURN    ${result}

Measure Average Query Time
    [Documentation]    Measure average time taken for DNS queries to multiple domains
    [Arguments]    @{domains}
    VAR    @{durations}=    @{EMPTY}
    FOR    ${domain}    IN    @{domains}
        ${start}=    Get Current Date
        Expect DNS Answer    ${domain}    A
        ${end}=    Get Current Date
        ${duration_secs}=    Subtract Date From Date    ${end}    ${start}
        Append To List    ${durations}    ${duration_secs}
    END
    ${avg_duration}=    Evaluate    sum(@{durations}) / len(@{durations})
    RETURN    ${avg_duration}
