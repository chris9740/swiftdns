# Swiftdns

Swiftdns is a privacy-focused DNS client tailored for debian distributions.

## Project

The Swiftdns client can currently resolve A and AAAA records (more will be supported later).

In the background, it uses Cloudflare's DOH (DNS over HTTPS) API to resolve the domains, and optionally routes through a tor proxy.

## Notice

At this moment, Swiftdns should not be considered stable.

Swiftdns works well with most software, but Chromium doesn't always query the client, it occasionally errors with `ERR_NAME_NOT_RESOLVED` for some reason.
This can cause Chromium to erroneously fail to resolve a domain. However, it will never accidentally resolve a blacklisted domain, assuming your computer is properly configured to use Swiftdns.

## Installing

### Prerequisites

-   systemd

To install Swiftdns, first download the .deb file from the [release page](https://github.com/chris9740/swiftdns/releases/latest).
Then, install it using your preferred method (e.g. `dpkg -i swiftdns.deb`).

Don't forget to configure your computer to use Swiftdns as a resolver.

## Features

[Blacklisting](#blacklisting) - Queries for domains that you have blacklisted will never get to leave your machine. Useful for blocking websites with poor privacy practices (e.g. Facebook, Tiktok) or adult websites.

[Whitelisting](#whitelisting) - Exempt certain domains from being flagged by the blacklist. This can be used if you want to block e.g. `googleapis.com` and all it's subdomains except for `discord-attachments-uploads-prd.storage.googleapis.com`.

[Tor Proxy](#tor) - Route all DNS queries through Tor.

## Blacklisting

Swiftdns will look for our blacklist rules inside `.list` files located in the root of `/etc/swiftdns/filters/`.

Knowing this, let's create a `google.list` file to make sure we never accidentally use `google.com` for searching, while still being able to visit subdomains such as `maps.google.com` and `translate.google.com`.

Inside our newly created `/etc/swiftdns/filters/google.list` file, we will enter the following:

```
google.com
www.google.com
```

Once we save the file, the rules will go into effect immediately.

If we want to block _all_ subdomains of `google.com`, we can do that using the _globstar pattern_ (`**.`), like this:

```
**.google.com
```

This will block `google.com` and every single subdomain of `google.com`. Note that `**.` can only be specified at the very beginning of the line.

In addition to globstar, we can also use simple wildcard matching:

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
**.tiktok*.com*
```

**Tip** - Test your rules with `swiftdns resolve example.com`. If done correctly, trying to resolve a blacklisted domain should give you an error.

## Whitelisting

The syntax for whitelisting is identical to that of blacklisting.
The only difference is that the rules _have_ to be located in the already-created file `/etc/swiftdns/filters/whitelist.list`.
The whitelist takes precedence over any blacklist file.

## Tor

To achieve the most privacy possible, you can route your traffic through Tor. See [configuration](#configuration) (note that this can drastically increase the time it takes to query).

## Configuration

You can configure Swiftdns to behave to your liking.
To change a setting, simply open `/etc/swiftdns/config.toml` in a text editor (note that this requires root permissions).
After saving your configuration file, run `systemctl restart swiftdns` to have the changes applied.

The value for `mode` will dictate which of Cloudflare's resolvers to use. `Standard = 1.1.1.1`, `Safe = 1.1.1.2` (blocks malware), `Clean = 1.1.1.3` (blocks malware and adult websites).
In contrast to Swiftdns, Cloudflare blocks domains by "resolving" them with `0.0.0.0`, while Swiftdns returns the `REFUSED` status.

| Key     | Default         | Value(s)                           | Description                              |
| ------- | --------------- | ---------------------------------- | ---------------------------------------- |
| mode    | `Standard`      | One of `Standard`, `Safe`, `Clean` | Configure which mode to run Swiftdns in  |
| address | `127.0.0.1:53`  | A socket address (with port)       | The address to bind the listener to      |
| tor     | `false`         | bool                               | Whether to route DNS queries through tor |

## Commands

-   ### Start

Normally you would want to start it with `systemctl start swiftdns`,
but you can start the listener in the foreground with the `start` subcommand (override the configured address with `--address <socketaddr>`).

```bash
$ swiftdns start
```

-   ### Resolve

Resolve a domain in the terminal (specify type with `-t <type>`, default is `A`)

```bash
$ swiftdns resolve <domain>
```

Of course, you can always run `swiftdns --help` to get more detailed documentation.
