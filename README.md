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

### Blacklisting

You can blacklist certain domains that you don't want to be resolved. Blacklisted domains will resolve with `REFUSED` (Return Code 5).

There are a few ways to blacklist a domain. All rules have to be specified in `.txt` files inside `/etc/swiftdns/rules/`. You can have as many files as you want, and you can add as many rules inside each file as you please.

Here are a few examples:

[wordpress.txt]

```sh
# This is a comment inside our wordpress.txt file.
# We want to block access to `wordpress.com` and `stats.wordpress.com`,
# but still allow access to other subdomains, i.e. `public-api.wordpress.com` and the like.
# Note that this does not block `www.wordpress.com`.

wordpress.com
stats.wordpress.com
```

[facebook.txt]

```sh
# Inside this file, we want to blacklist `facebook.com` and every single one of it's subdomains.
# This is referred to as wildcard matching.

facebook.com
*.facebook.com
```

[tiktok.txt]

```sh
# We can use wildcard matching within the domain name as well.
# Tiktok, for example, also has domains like `tiktokv.com`.
# The following rule will block `tiktok.com`, `tiktokv.com`, and also other domains like `tiktokcdn.com`.

tiktok*.com
```

**Tip** - Test your rules with `swiftdns resolve example.com`. If done correctly, trying to resolve a blacklisted domain should give you an error.

## Configuration

You can configure SwiftDNS to behave to your liking. To change a setting, simply open `/etc/swiftdns/config/default-config.toml` in a text editor (note that this requires root privileges). After saving your configuration file, run `systemctl restart swiftdns` to clear the cache.

The different configuration options have more elaborate documentation within the config file.

| Key  | Default    | Value(s)                           | Description                             |
| ---- | ---------- | ---------------------------------- | --------------------------------------- |
| mode | `Standard` | One of `Standard`, `Safe`, `Clean` | Configure which mode to run SwiftDNS in |

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
