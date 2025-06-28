*** Settings ***
Documentation       DNS blocking strategy tests

Resource            common.resource

Test Teardown       Stop Swiftdns


*** Test Cases ***
Sinkhole Strategy
    [Documentation]    Test sinkhole blocking returns 0.0.0.0/::

    Start Swiftdns    strategy=sinkhole

    Expect Sinkhole    facebook.com    A
    Expect Sinkhole    facebook.com    AAAA

NXDOMAIN Strategy
    [Documentation]    Test NXDOMAIN blocking strategy

    Start Swiftdns    strategy=nxdomain
    Query Domain    facebook.com    A    NXDOMAIN

Refused Strategy
    [Documentation]    Test REFUSED blocking strategy

    Start Swiftdns    strategy=refused
    Query Domain    facebook.com    A    REFUSED

Drop Strategy
    [Documentation]    Test DROP strategy causes timeout

    Start Swiftdns    strategy=drop
    Expect Timeout    facebook.com    A    timeout=1
