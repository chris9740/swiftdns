# Project todo list

-   [x] **Config option for Tor SOCKS address**

Let user configurate the SOCKS address for Tor if it's non-standard (`127.0.0.1:9050`)

-   [ ] **Built-in proxy**

A proxy that only lets through requests to IP address that it knows about (that it gathers from DNS responses), as well as `1.1.1.x` (Cloudflare DNS servers).
This will prevent websites bypassing the DNS block by using the IP instead of domain.

(This feature should be disabled by default.)

-   [x] **Personal usage data**

Save usage data in a local database, such as how often a domain has been queried and how many of those queries were cached/blacklisted.
The metrics should be aggregated into analytics on request, and exported as either JSON and CSV.

```json
{
    "wikipedia.com": {
        "total_queries": 378,
        "cache_hits": 359,
        "blacklist_hits": 2
    },
    "google-analytics.com": {
        "total_queries": 47,
        "cache_hits": 0,
        "blacklist_hits": 47
    }
}
```
