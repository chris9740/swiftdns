# Swiftdns

Swiftdns is a local forwarding DNS resolver tailored for Debian distributions, with a focus on user privacy.

## Project

Swiftdns enhances your browsing security by seamlessly integrating DNS over HTTPS (DoH) with your local system's existing UDP-based DNS queries. Unlike traditional DNS queries that are visible to ISPs, DoH encrypts your requests, ensuring that the domains you access remain confidential between you and your chosen DNS provider. This setup allows you to take full advantage of secure DNS resolution without any complex configuration. Swiftdns operates quietly in the background, ensuring your DNS queries are both secure and private, with minimal configuration effort on your part.

For those seeking an extra layer of privacy, Swiftdns also offers the option to route queries through a Tor proxy.

## Installing

### Prerequisites

-   systemd
-   Rust toolchain (for compilation)
-   `cargo-deb` (for creating .deb packages)

### Installation Steps

1. **Install Rust and cargo-deb:**

    ```bash
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env

    # Install cargo-deb
    cargo install cargo-deb
    ```

2. **Clone the repository:**

    ```bash
    git clone https://github.com/chris9740/swiftdns.git
    cd swiftdns
    ```

3. **Build and create the package:**

    ```bash
    make package
    ```

4. **Install the package:**

    ```bash
    sudo dpkg -i target/debian/swiftdns_*.deb
    ```

5. **Configure your system to use Swiftdns:**
   Set your system's DNS resolver to `127.0.0.1` to route queries through Swiftdns.

## Features

[Blacklisting](#blacklisting) - Queries for domains that you have blacklisted will never get to leave your machine. Useful for blocking websites with poor privacy practices (e.g., Facebook, Tiktok) or adult websites.

[Whitelisting](#whitelisting) - Exempt certain domains from being flagged by the blacklist. This can be used if you want to block e.g., `googleapis.com` and all its subdomains except for `discord-attachments-uploads-prd.storage.googleapis.com`.

[Tor Proxy](#tor) - Route all DNS queries through Tor.

[Custom Resolvers](#configuration) - Configure any DoH provider of your choice, with support for bootstrapping IP addresses to avoid circular DNS dependencies.

## Blacklisting

Swiftdns will look for our blacklist rules inside `.list` files located in `/etc/swiftdns/filters/` and any of its immediate subdirectories, in case you want to organize your rules.

**Important:** You need to restart the service after creating or modifying any of these files for the changes to take effect.

### Getting Started with Preset Filters

If you want to get started quickly with some common blocking rules, you can copy the preset filters from the repository:

```bash
# Copy all preset filters (optional)
sudo cp assets/filters/*.list /etc/swiftdns/filters/

# Or copy specific preset filters
sudo cp assets/filters/meta.list /etc/swiftdns/filters/
sudo cp assets/filters/nsfw.list /etc/swiftdns/filters/
```

**Note:** These are example filters - review them first to make sure they match your needs.

### Creating Custom Filters

Knowing this, let's create a `google.list` file to make sure we never accidentally use `google.com` for searching, while still being able to visit subdomains such as `maps.google.com` and `translate.google.com`.

Inside our newly created `/etc/swiftdns/filters/google.list` file, we will enter the following:

```
^google.com
^www.google.com
```

Once we save the file, the rules will go into effect immediately.

If we want to block _all_ subdomains of `google.com`, we can simply add:

```
google.com
```

This will block `google.com` and every single subdomain of `google.com`.

In addition to blocking subdomains by default, we can also use simple wildcard matching:

```
*s.google.com
```

This will match any domain that ends in `s.google.com`, such as `books.google.com` and `services.google.com`.

Let's make use of comments to describe our rules:

```sh
# Block any domain that has the word "analytics" anywhere in it
*analytics*

# Block the new TLD's created by Genius Google that are being widely exploited for phishing and malware
*.zip
*.mov

# Let's also make sure we block "tiktok.com", "tiktokv.com", "tiktokcdn.com" and all their subdomains
tiktok*.com*
```

**Tip** - Test your rules with `swiftdns demo example.com`. This will show you whether this domain would be blocked or not. No queries will be sent to the DNS provider.

## Whitelisting

The syntax for whitelisting is identical to that of blacklisting.
The only difference is that the rules _have_ to be located in the already-created file `/etc/swiftdns/filters/whitelist.list`.
The whitelist takes precedence over any blacklist file.

## Tor

To achieve the highest level of privacy, you can route your traffic through Tor. See [configuration](#configuration). This will noticeably increase query times. The initial query may take several seconds, while subsequent queries will be significantly faster, usually taking no more than 400ms if you have a fast network. For comparison, normal queries typically take anywhere from 10ms to 80ms.

<details>
<summary>Show installation steps for Tor</summary>

If you want to route your DNS queries through the Tor network, you will need to install the Tor proxy. Here are the steps to install and set up Tor on a Debian-based system:

1. **Install Tor:**

    ```bash
    sudo apt update
    sudo apt install tor
    ```

2. **Start the Tor service:**

    ```bash
    sudo systemctl start tor
    ```

3. **Enable Tor to start on boot:**

    ```bash
    sudo systemctl enable tor
    ```

4. **Verify the Tor service:**
    ```bash
    sudo systemctl status tor
    ```
    </details>

## Configuration

You can configure Swiftdns to behave to your liking.
To change a setting, simply open `/etc/swiftdns/config.toml` in a text editor (note that this requires root permissions).
After saving your configuration file, run `systemctl restart swiftdns` to have the changes applied.

### General Configuration

| Key     | Default        | Value(s)                   | Description                         |
| ------- | -------------- | -------------------------- | ----------------------------------- |
| address | `127.0.0.1:53` | A socket address with port | The address to bind the listener to |

### Resolver Configuration

The `[resolver]` section defines which DNS-over-HTTPS provider Swiftdns will use:

```toml
[resolver]
# The DoH URL for DNS-over-HTTPS queries
url = "https://1.1.1.1/dns-query"

# Optional: IP addresses to directly connect to (bypassing system DNS)
# Used when the URL contains a domain name that needs to be resolved
bootstrap_ips = []  # Example: ["45.90.28.0", "45.90.30.0"] for NextDNS
```

#### Example Configurations

**Cloudflare (Default)**

```toml
[resolver]
url = "https://1.1.1.1/dns-query"
```

**Cloudflare Family (Blocks malware and adult content)**

```toml
[resolver]
url = "https://1.1.1.3/dns-query"
```

**NextDNS with Custom Profile ID**

```toml
[resolver]
url = "https://dns.nextdns.io/abc123/dns-query"
bootstrap_ips = ["45.90.28.0", "45.90.30.0"]
```

**Google DNS**

```toml
[resolver]
url = "https://8.8.8.8/dns-query"
```

### Tor Configuration

| Key         | Default          | Value(s)                | Description                              |
| ----------- | ---------------- | ----------------------- | ---------------------------------------- |
| tor.enabled | `false`          | bool                    | Whether to route DNS queries through tor |
| tor.address | `127.0.0.1:9050` | A socket address w/port | The address your Tor proxy is using      |

## Commands

### Start

Normally you would want to start it with `systemctl start swiftdns`,
but you can start the listener in the foreground with the `start` subcommand (override the configured address with `--address <socketaddr>`).

```bash
$ swiftdns start
```

---

### Resolve

Resolve a domain in the terminal. These queries are not cached

```bash
$ swiftdns resolve <domain> [type: A] [--tor]
```

**Flags**:

`--tor`: Boolean flag to route the query through the Tor network.

---

### Demo

Test if a domain would be blocked by the current filters without actually sending a DNS query.

```bash
$ swiftdns demo <domain>
```

This command will output whether the domain is blocked or not, without sending any queries to the DNS provider.

---

Of course, you can always run `swiftdns --help` to get more detailed documentation.
