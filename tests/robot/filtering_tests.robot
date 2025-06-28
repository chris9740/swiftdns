*** Settings ***
Documentation       Domain filtering tests

Resource            common.resource

Test Teardown       Stop Swiftdns


*** Test Cases ***
Block Facebook
    [Documentation]    Test that facebook.com is blocked by default filters

    Start Swiftdns
    Expect Sinkhole    facebook.com    A

Dynamic Filter Reload
    [Documentation]    Test hot-reloading of filter files

    Start Swiftdns

    # Should work initially
    Expect Answer    reddit.com    A

    # Add to blacklist
    Create File    ${FILTER_DIR}/test-temp.list    reddit.com
    Sleep    1s    # Wait for file watcher
    Expect Sinkhole    reddit.com    A

    # Clean up
    Remove File    ${FILTER_DIR}/test-temp.list
    Sleep    1s
    Expect Answer    reddit.com    A
