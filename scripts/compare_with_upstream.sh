#!/bin/bash

# DNS Resolver Comparison Script
# Compares your SwiftDNS resolver against Cloudflare (1.1.1.1)

# Configuration
YOUR_RESOLVER="127.0.0.1"
YOUR_PORT="5053"
CLOUDFLARE_RESOLVER="1.1.1.1"

# Test domains and query types
declare -a TESTS=(
    "example.com A"
    "example.com AAAA"
    "example.com MX"
    "example.com TXT"
    "example.com NS"
    "example.com SOA"
    "duckduckgo.com A"
    "duckduckgo.com AAAA"
    "duckduckgo.com MX"
    "duckduckgo.com NS"
    "signal.org A"
    "signal.org AAAA"
    "signal.org MX"
    "signal.org NS"
    "_sip._tcp.example.com SRV"
    "nonexistent.example.com A"
    "com NS"
)

echo "DNS Resolver Comparison Test"
echo "============================"
echo "Your Resolver: ${YOUR_RESOLVER}:${YOUR_PORT}"
echo "Upstream: ${CLOUDFLARE_RESOLVER}"
echo ""

# Test each domain/type combination
for test in "${TESTS[@]}"; do
    read -r domain type <<<"$test"

    echo "Testing: $domain $type"
    echo "=================================================="

    echo "--- SwiftDNS ---"
    echo "Query: $domain $type"
    dig @$YOUR_RESOLVER -p $YOUR_PORT $domain $type +short +time=5 +tries=1 2>/dev/null
    echo ""

    echo "--- Cloudflare ---"
    echo "Query: $domain $type"
    dig @$CLOUDFLARE_RESOLVER -p 53 $domain $type +short +time=5 +tries=1 2>/dev/null
    echo ""

    echo "Detailed comparison:"
    echo "--------------------------------------------------"

    echo "--- SwiftDNS Detailed ---"
    echo "Query: $domain $type"
    dig @$YOUR_RESOLVER -p $YOUR_PORT $domain $type +time=5 +tries=1 2>/dev/null
    echo ""

    echo "--- Cloudflare Detailed ---"
    echo "Query: $domain $type"
    dig @$CLOUDFLARE_RESOLVER -p 53 $domain $type +time=5 +tries=1 2>/dev/null
    echo ""

    echo "=================================================="
    echo ""

    sleep 1
done

echo "Test completed!"
echo ""
echo "Key things to check:"
echo "1. Response codes (NOERROR, NXDOMAIN, etc.)"
echo "2. Answer sections match"
echo "3. TTL values are reasonable"
echo "4. Authority sections for negative responses"
echo ""
