---
layout: default
title: Configuration
---

## Configuration

Swiftdns uses a TOML configuration file located at `/etc/swiftdns/config.toml`. Below is an example configuration with explanations for each section.

```toml
# The address to listen on for DNS queries
address = "127.0.0.1:53"

# DNS-over-HTTPS (DoH) endpoint (works with every compliant DoH server)
[resolver]
url = "https://cloudflare-dns.com/dns-query"
bootstrap_ips = ["1.1.1.1:443", "1.0.0.1:443"]
# └─ Skip normal DNS for that hostname and dial these IPs directly
#    (avoids circular lookups where Swiftdns would unsuccessfully try to query itself)

[blocking]
strategy = "sinkhole"

[tor]
enabled = false
address = "127.0.0.1:9050"
```

### Strategy Options

**`sinkhole`** (default - recommended)

-   Returns `0.0.0.0` for A records and `::` for AAAA records
-   Returns REFUSED for other types (MX, TXT, etc.)
-   1s TTL for immediate whitelist changes
-   Prevents fallback resolvers
-   Mimics Cloudflare's blocking behavior

**`nxdomain`**

-   Returns RCODE 3 (NXDOMAIN)
-   No SOA record (per RFC 2308), so most clients don't cache
-   Prevents fallback resolvers

**`refused`**

-   Returns RCODE 5 (REFUSED)
-   Most transparent; explicit "access denied"
-   **Warning:** may trigger fallback DNS servers - make sure you have no other resolvers configured

**`drop`** (not recommended)

-   Silently drops queries (timeout)
-   Hardest for applications trying to determine if a domain is blocked
-   Can appear as packet loss; poor UX due to long waits

## Next Steps

-   [Set up domain filtering](filtering.md)
