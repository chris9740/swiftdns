<p align="center">
  <img src="docs/logo.png" alt="Swiftdns logo" width="120"/>
</p>

# Swiftdns

Swiftdns tunnels your DNS-over-UDP queries over HTTPS for end-to-end privacy. Designed for power users, hobbyists, and privacy-conscious individuals on Debian-based systems.

## Quick Start

1. **Install dependencies:**

    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    cargo install cargo-deb sccache
    sudo apt install mold clang
    ```

2. **Build and install:**

    ```bash
    git clone https://github.com/chris9740/swiftdns.git
    cd swiftdns
    make package
    sudo dpkg -i target/debian/swiftdns_*.deb
    ```

3. **Configure DNS:**
   Set your system's DNS resolver to `127.0.0.1` to route queries through Swiftdns.

## Features

-   **DNS-over-HTTPS**: Encrypt all DNS queries for privacy
-   **Domain Filtering**: Block ads, trackers, and unwanted domains
-   **Tor Support**: Route queries through Tor for anonymity
-   **Hot Reload**: Filter changes apply instantly
-   **Caching**: Fast responses with intelligent TTL handling

## Basic Usage

### Domain Filtering

Create filter files in `/etc/swiftdns/filters/`:

```bash
# Block exact domains
echo "^facebook.com" | sudo tee /etc/swiftdns/filters/social.list

# Block domains and subdomains
echo "google.com" | sudo tee -a /etc/swiftdns/filters/social.list

# Use wildcards
echo "*ads*" | sudo tee -a /etc/swiftdns/filters/social.list
```

Test your filters:

```bash
swiftdns check facebook.com
```

### Configuration

Edit `/etc/swiftdns/config.toml`:

```toml
address = "127.0.0.1:53"

[resolver]
url = "https://cloudflare-dns.com/dns-query"
bootstrap_ips = ["1.1.1.1:443", "1.0.0.1:443"]

[blocking]
strategy = "sinkhole"  # sinkhole | nxdomain | refused | drop

[tor]
enabled = false
address = "127.0.0.1:9050"
```

### Commands

```bash
swiftdns check facebook.com   # Test filter rules (does not make a DNS query)
swiftdns resolve example.com  # Test DNS resolution (makes a DNS query)
swiftdns config               # Show configuration
swiftdns --help               # Show help
```

## Documentation

For detailed configuration, advanced features, and troubleshooting, visit the [full documentation](https://chris9740.github.io/swiftdns/).
