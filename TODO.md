# Project todo list

- [x] **Config option for Tor SOCKS address**

Let user configurate the SOCKS address for Tor if it's non-standard (`127.0.0.1:9050`)

- [ ] **Built-in proxy**

A proxy that only lets through requests to IP address that it knows about (that it gathers from DNS responses), as well as `1.1.1.x` (Cloudflare DNS servers).
This will prevent websites bypassing the DNS block by using the IP instead of domain.

(This feature should be disabled by default.)

- [ ] **Personal usage data**

Save usage data in a local file, such as how often a domain has been queried and how many of those queries were cached.
This should be saved as YAML.

(This feature should be disabled by default.)

```yaml
---
wikipedia.org:
  total: 378
  cached: 312
stackoverflow.com:
  total: 87
  cached: 55
```
