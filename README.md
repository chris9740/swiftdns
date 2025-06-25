<p align="center">
  <img src="assets/logo.png" alt="Swiftdns logo" width="120"/>
</p>

# Swiftdns

Swiftdns tunnels your normal DNS-over-UDP queries over HTTPS for end-to-end privacy.

It is specifically designed for power users, hobbyists, and privacy-conscious individuals. It's tailored for Debian-based systems, but can be built for other Linux distributions as well.

## Project Overview

Swiftdns listens on localhost via UDP like a standard resolver, then encrypts and forwards every query over HTTPS to your DoH server, ensuring end-to-end privacy and preventing eavesdropping. You can also define filter rules to block unwanted domains at the DNS level.

For an extra layer of privacy, you can route all queries through a Tor proxy. This way, your DNS queries are anonymized even from your DoH provider.

## Installation

1. **Install dependencies:**

    ```bash
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env

    # Install cargo-deb and sccache
    cargo install cargo-deb sccache

    # Install mold and clang
    sudo apt install mold clang
    ```

2. **Clone the repository:**

    ```bash
    git clone https://github.com/chris9740/swiftdns.git
    cd swiftdns
    ```

3. **Build the .deb package**

    To build with the default features, run:

    ```bash
    make package
    ```

    Alternatively, you can run `cargo deb` directly with the desired features:

    ```bash
    cargo deb --no-default-features --features "tracing"
    ```

4. **Install the package:**

    ```bash
    sudo dpkg -i target/debian/swiftdns_*.deb
    ```

5. **Configure your system to use Swiftdns:**  
   Set your system's DNS resolver to `127.0.0.1` to route queries through Swiftdns. Make sure you don't have any fallback DNS resolvers configured to prevent DNS leaks.

## Features

[Blacklisting](#blacklisting) & [Whitelisting](#whitelisting) - Block or allow specific domains using custom rules. Queries for blacklisted domains won't leave your system.  
[Tor Proxy](#tor) - Route all DNS queries through Tor.  
[Customization](#configuration) - Customize Swiftdns behavior with a simple configuration file.

## Blacklisting

Swiftdns will look for our blacklist rules inside `.list` files located in `/etc/swiftdns/filters/`.

**Note:** Swiftdns will watch `/etc/swiftdns/filters/` for changes, and automatically reload them. If you compiled without the `notify` feature, you need to restart the service after modifying any filter files.

### Getting Started with Preset Filters

```bash
# Copy all preset filters
sudo cp assets/filters/*.list /etc/swiftdns/filters/

# Or copy specific filters
sudo cp assets/filters/meta.list /etc/swiftdns/filters/
sudo cp assets/filters/nsfw.list /etc/swiftdns/filters/
```

Review filters before use.

### Creating Custom Filters

Create `/etc/swiftdns/filters/google.list` and add:

```
^google.com
^www.google.com
```

This blocks only `google.com` and its `www` subdomain. To block all subdomains, use:

```
google.com
```

Wildcards also work:

```
*s.google.com
```

Comments can help document rules:

```sh
# Block analytics-related domains
*analytics*

# Block new TLDs exploited for phishing
*.zip
*.mov

# Block TikTok domains and subdomains
tiktok*.com*
```

**Tip** - Test your rules without sending queries:

```bash
swiftdns check example.com
```

## Whitelisting

Whitelisting uses the same syntax as blacklisting. Place rules in `/etc/swiftdns/filters/whitelist.list`. Whitelist rules take precedence over any blacklist.

## Tor

Routing queries through Tor increases privacy at the cost of latency. Initial queries may take several seconds; subsequent queries typically finish in less than 400 ms. For comparison, normal DoH queries take ~ 5-80 ms. You can enable Tor routing in the [configuration](#configuration) section.

<details>
<summary>Show installation steps for Tor</summary>

1.  **Install Tor:**

    ```bash
    sudo apt update
    sudo apt install tor
    ```

2.  **Start the Tor service:**

    ```bash
    sudo systemctl start tor
    ```

3.  **Enable Tor on boot:**

    ```bash
    sudo systemctl enable tor
    ```

4.  **Verify the Tor service is running:**
    ```bash
    sudo systemctl status tor
    ```
    </details>

## Configuration

Below is an example of a fully annotated `/etc/swiftdns/config.toml`.

```toml
# The address to listen on for DNS queries
address = "127.0.0.1:53"

# DNS-over-HTTPS (DoH) endpoint.
# Swiftdns is standards-compliant and will work with any compliant DoH server.
[resolver]
url = "https://cloudflare-dns.com/dns-query"
bootstrap_ips = ["1.1.1.1:443"]
# └─ Skip normal DNS for that hostname and dial these IPs directly
#    (avoids circular lookups where Swiftdns would unsuccessfully try to query itself)

# Blocking strategy: sinkhole, nxdomain, refused, or drop
[blocking]
strategy = "sinkhole"

# Tor proxy settings
[tor]
enabled = false
address = "127.0.0.1:9050"
```

-   **bootstrap_ips**  
    Optional list of IPs to use when your `resolver.url` is a hostname. Swiftdns skips your system resolver and connects directly. Note that they need to include the port, e.g., `"1.1.1.1:443"`.

-   **strategy**  
    one of `sinkhole`, `nxdomain`, `refused`, or `drop` (see "Show strategies" under [Blocking Strategies](#blocking-strategies) for details).

-   **tor.enabled** / **tor.address**  
    Whether to route queries through Tor, and the SOCKS proxy to use.

## Commands

### Start

Normally you would want to start it with `systemctl start swiftdns`,  
but you can run in the foreground with:

```bash
swiftdns start [--address <socketaddr>]
```

### Resolve

Resolve a domain in the terminal (not cached):

```bash
swiftdns resolve <domain> [type: A] [--tor]
```

### Check

Test if a domain would be blocked, without sending external queries:

```bash
swiftdns check <domain>
```

Of course, you can always run `swiftdns --help` to get more detailed documentation.

## Blocking Strategies

<details>
<summary>Show strategies</summary>

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

</details>

## Troubleshooting

<details>
<summary>Show troubleshooting steps</summary>

1. **Check the service status:**

    ```bash
    sudo systemctl status swiftdns
    ```

2. Make sure your system's DNS resolver is set to `127.0.0.1:53`.

    ```bash
    cat /etc/resolv.conf
    ```

3. **Make sure Swiftdns is actually being used:**

    Use `dig` or `nslookup` to test DNS resolution:

    ```bash
    dig example.com
    ```

    The output should show `;; SERVER: 127.0.0.1#53` (or your configured address) indicating that the query is being handled by Swiftdns.

4. **Check the logs:**

    ```bash
    journalctl -u swiftdns -f
    ```

5. **If you have issues with blacklisting or whitelisting:**

    Use the `check` command to verify if a domain is blocked or allowed:

    ```bash
    swiftdns check example.com
    ```

</details>

## Further Reading

If you're interested in the technical details of Swiftdns (DNS, DoH, and related protocols), here are some resources to get you started:

-   [RFC 1035: _Domain names - implementation and specification_](https://datatracker.ietf.org/doc/html/rfc1035)
-   [RFC 8484: _DNS Queries over HTTPS (DoH)_](https://datatracker.ietf.org/doc/html/rfc8484)
-   [RFC 2308: _Negative Caching of DNS Queries (DNS NCACHE)_](https://datatracker.ietf.org/doc/html/rfc2308)
