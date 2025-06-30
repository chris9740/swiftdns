---
layout: default
title: Filtering
---

# Domain Filtering

Swiftdns supports domain filtering through blacklists and whitelists using simple text files. Queries for blacklisted domains are blocked locally without leaving your system.

## Filter File Location

Filter files are stored in `/etc/swiftdns/filters/` and must have a `.list` extension. Swiftdns automatically watches this directory for changes and reloads filters without requiring a restart (if built with the `notify` feature).

## Filter Syntax

### Exact Domain Matching

Use `^` prefix to match only the exact domain:

```
^facebook.com
^www.facebook.com
```

### Domain and Subdomain Matching

Without a prefix, the rule matches the domain and all its subdomains:

```
facebook.com
```

### Wildcard Matching

Use `*` for pattern matching:

```
*facebook*
*ads*
*.tk
```

### Comments and Organization

Use `#` for comments and empty lines for organization:

```
# Social Media Blocking
^facebook.com
^www.facebook.com
instagram.com

# Advertising Networks
doubleclick.net
*analytics*
```

## Blacklisting

Create separate `.list` files for different categories. For example:

**`/etc/swiftdns/filters/social-media.list`:**

```
# Meta/Facebook
^facebook.com
^www.facebook.com
instagram.com

# TikTok
tiktok.com
*tiktok*

# Snapchat
snapchat.com
```

**`/etc/swiftdns/filters/advertising.list`:**

```
# Google Ads
doubleclick.net
googleadservices.com
^googleads.com

# Analytics
*analytics*
*tracking*
```

## Whitelisting

Whitelist rules take precedence over all blacklist rules and are defined in `/etc/swiftdns/filters/whitelist.list`:

```
# Essential Microsoft services
^packages.microsoft.com
^vscode.microsoft.com

# Development tools
github.com
stackoverflow.com

# Wildcard exceptions
*essential*
api.*.com
cdn-*.amazonaws.com
```

## Using Preset Filters

Swiftdns includes preset filters for common blocking scenarios:

```bash
# Copy all preset filters
sudo cp assets/filters/*.list /etc/swiftdns/filters/

# Copy specific filters
sudo cp assets/filters/meta.list /etc/swiftdns/filters/
sudo cp assets/filters/nsfw.list /etc/swiftdns/filters/
```

**Always review preset filters before use** to ensure they meet your needs.

## Testing Filters

Test your filter rules without sending external queries:

```bash
# Check if a domain would be blocked
swiftdns check facebook.com

# Test whitelist precedence
swiftdns check business.facebook.com
```

## Hot Reloading

If Swiftdns was built with the `notify` feature (default), filter changes are automatically detected and reloaded. You'll see a message in the logs when this happens:

```
Filter files changed, reloaded automatically
```

If built without `notify`, restart the service after making changes:

```bash
sudo systemctl restart swiftdns
```
