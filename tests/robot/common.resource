*** Settings ***
Documentation       Common keywords and variables for Swiftdns E2E tests

Library             Collections
Library             DateTime
Library             OperatingSystem
Library             Process
Library             String


*** Variables ***
${BINARY_PATH}      ${CURDIR}/../../target/debug/swiftdns
${CONFIG_PATH}      ${CURDIR}/test-config.toml
${FILTER_DIR}       ${CURDIR}/../../assets/filters
${PORT}             55353


*** Keywords ***
Create Basic Config
    [Documentation]    Create a basic Swiftdns configuration file
    [Arguments]    ${strategy}=sinkhole    ${tor_enabled}=false

    VAR    ${config_content}=    SEPARATOR=\n
    ...    address = "127.0.0.1:${PORT}"
    ...    [resolver]
    ...    url = "https://cloudflare-dns.com/dns-query"
    ...    bootstrap_ips = ["1.1.1.1:443"]
    ...    [blocking]
    ...    strategy = "${strategy}"
    ...    [tor]
    ...    enabled = ${tor_enabled}

    Create File    ${CONFIG_PATH}    ${config_content}

Wait For Swiftdns UDP
    [Documentation]    Wait for Swiftdns to respond to a UDP query
    [Arguments]    ${timeout}=1

    ${start}=    Get Time    epoch
    FOR    ${i}    IN RANGE    0    ${timeout * 2}
        ${result}=    Run Process    dig    @127.0.0.1    -p    ${PORT}    ${i}.example.com    A    stderr=STDOUT
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
    ...    ${timeout}=5

    Create Basic Config
    ...    strategy=${strategy}
    ...    tor_enabled=${tor_enabled}

    File Should Exist    ${BINARY_PATH}
    File Should Exist    ${CONFIG_PATH}

    Start Process
    ...    ${BINARY_PATH}
    ...    start
    ...    --config-file
    ...    ${CONFIG_PATH}
    ...    --address
    ...    127.0.0.1:${PORT}
    ...    stderr=STDOUT
    ...    alias=swiftdns

    Wait For Swiftdns UDP    timeout=${timeout}

Stop Swiftdns
    [Documentation]    Stop the Swiftdns proxy and clean up
    [Arguments]    ${proxy}=swiftdns

    ${proxy_exists}=    Run Keyword And Return Status    Variable Should Exist    ${proxy}

    IF    ${proxy_exists}
        Send Signal To Process    SIGTERM    ${proxy}
        ${result}=    Wait For Process    ${proxy}    timeout=10s
        Log    ${result}
    END

    Wait Until Keyword Succeeds    5x    0.5s    Port Should Not Be Listening    ${PORT}
    ${config_exists}=    Run Keyword And Return Status    File Should Exist    ${CONFIG_PATH}
    IF    ${config_exists}    Remove File    ${CONFIG_PATH}

Port Should Not Be Listening
    [Documentation]    Check that a port is not listening
    [Arguments]    ${port}

    ${result}=    Run Process    bash    -c    "ss -lun | grep -q :${port}"    shell=True
    Should Not Be Equal As Integers    ${result.rc}    0    msg=Port ${port} is still in use

Run Dig Command
    [Documentation]    Run a DNS query using the `dig` command
    [Arguments]    ${domain}    ${record_type}=A    ${timeout}=5    ${retry}=1

    VAR    ${timeout_arg}=    +timeout=${timeout}
    VAR    ${retry_arg}=    +retry=${retry}
    VAR    ${server_arg}=    @127.0.0.1

    ${result}=    Run Process
    ...    dig    ${timeout_arg}    ${retry_arg}    ${server_arg}
    ...    -p    ${PORT}    ${domain}    ${record_type}    stderr=STDOUT

    Log    ${result.stdout}
    RETURN    ${result}

Query Domain
    [Documentation]    Execute DNS query expecting success
    [Arguments]    ${domain}    ${record_type}=A    ${expected_status}=NOERROR    ${timeout}=5

    ${result}=    Run Dig Command    ${domain}    ${record_type}    ${timeout}
    Should Be Equal As Integers    ${result.rc}    0    msg=DNS query failed
    Should Contain    ${result.stdout}    status: ${expected_status}
    RETURN    ${result}

Expect Timeout
    [Documentation]    Execute DNS query expecting timeout
    [Arguments]    ${domain}    ${record_type}=A    ${timeout}=1

    ${result}=    Run Dig Command    ${domain}    ${record_type}    ${timeout}    retry=0
    Should Not Be Equal As Integers    ${result.rc}    0    msg=Expected DNS query to timeout
    RETURN    ${result}

Expect Answer
    [Documentation]    Expect a valid DNS answer for the given domain
    [Arguments]    ${domain}    ${record_type}=A    ${timeout}=5

    ${result}=    Query Domain    ${domain}    ${record_type}    timeout=${timeout}
    Log    ${result}
    Should Contain    ${result.stdout}    ANSWER SECTION
    RETURN    ${result}

Expect Sinkhole
    [Documentation]    Expect a sinkhole response for the given domain
    [Arguments]    ${domain}    ${record_type}=A    ${timeout}=5

    ${result}=    Query Domain    ${domain}    ${record_type}    timeout=${timeout}
    IF    "${record_type}" == "A"
        Should Contain    ${result.stdout}    0.0.0.0
    ELSE IF    "${record_type}" == "AAAA"
        Should Contain    ${result.stdout}    ::
    END
    RETURN    ${result}
