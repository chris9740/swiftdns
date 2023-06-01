# SwiftDNS

SwiftDNS is a simple, privacy-focused DNS client, written for Debian distributions in Rust.

## Project

The SwiftDNS client can currently resolve A and AAAA records (more will be supported later).

In the background, it uses Cloudflare's DOH (DNS over HTTPS) API to resolve the domains.

## Notice

SwiftDNS works well with Firefox, but it throws a fit for a lot of domains in Chromium (`ERR_NAME_NOT_RESOLVED`, it often doesn't even try to query the DNS). Not sure why, feel free to file an issue or a pull request if you can figure it out.

## Installing

To install SwiftDNS, download the [latest release](https://github.com/chris9740/swiftdns/releases/latest).

## Features

[Blacklisting](#blacklisting) - Queries for domains that you have blacklisted will be refused by the client on your machine, and the query itself will never see the light of day. This can be useful for blocking unwanted sites, such as websites with poor privacy practices (e.g. Facebook, Tiktok) or adult websites.

[Whitelisting](#whitelisting) - Exempt certain domains from being caught by the blacklist. Useful if you want to block `googleapis.com` and all it's subdomains, except for `discord-attachments-uploads-prd.storage.googleapis.com`.

[Tor Proxy](#tor) - Route all DNS queries through Tor for the utmost privacy.

## Blacklisting

There are a few ways to blacklist a domain. All rules have to be specified in `.txt` files inside `/etc/swiftdns/rules/`. You can have as many files as you want, and each file can contain an unlimited amount of rules.

### Basic Syntax

A DNS blacklist rule is a simple text string that specifies the domain or subdomain to block. For example, to block the domains `example.com` and `ads.invasive.web`, you can create rules with the following syntax:

```
example.com
ads.invasive.web
```

### Wildcard Patterns

You can also use wildcard patterns to create more general rules that apply to multiple subdomains. For example, to block all subdomains of `example.com`, you can use the `*` wildcard pattern:

```
*.example.com
```

This rule will block requests for any subdomain of `example.com`, such as `mail.example.com`, `blog.example.com` and `james.blog.example.com`, but not `example.com` itself.

If you want to block all subdomains, including the root domain, you can use the `**` wildcard pattern:

```
**.example.com
```

This rule will block any request for `example.com` as well as all subdomains of `example.com`. Note that, unlike `*.`, the `**.` pattern can only exist at the beginning of the line.

**Tip** - Test your rules with `swiftdns resolve example.com`. If done correctly, trying to resolve a blacklisted domain should give you an error.

## Whitelisting

The syntax for whitelisting is identical to that of blacklisting. The only difference is that they _have_ to be located in the already-created file `/etc/swiftdns/rules/whitelist.txt`. The whitelist takes precedence over any blacklist file.

## Tor

To achieve the most privacy possible, you can route your traffic through Tor. See [configuration](#configuration) (note that this will drastically increase the time it takes to query).

## Configuration

You can configure SwiftDNS to behave to your liking. To change a setting, simply open `/etc/swiftdns/conf.d/default-config.toml` in a text editor (note that this requires root privileges). After saving your configuration file, run `systemctl restart swiftdns` to clear the cache.

The different configuration options have more elaborate documentation within the config file.

| Key     | Default         | Value(s)                           | Description                              |
| ------- | --------------- | ---------------------------------- | ---------------------------------------- |
| mode    | `Standard`      | One of `Standard`, `Safe`, `Clean` | Configure which mode to run SwiftDNS in  |
| address | `127.0.0.53:53` | A socket address (with port)       | The address to bind the listener to      |
| tor     | `false`         | bool                               | Whether to route DNS queries through tor |

## Commands

-   ### Start

    Normally you would want to start it with `systemctl start swiftdns`, but you can start the listener in the foreground at 127.0.0.53:53 (or specify address with `--address <socketaddr>`).

    ```bash
    $ swiftdns start
    ```

-   ### Resolve

    Resolve a domain in the terminal (specify type with `-t <type>`, default is `A`)

    ```bash
    $ swiftdns resolve <domain>
    ```
