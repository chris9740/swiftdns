---
layout: default
title: Troubleshooting
---

# Troubleshooting

This guide assumes that Swiftdns is configured to listen on `127.0.0.1:53` and that you have basic knowledge of Linux command line tools.

## Common Issues

### Address Already in Use

**Problem**: "Address already in use" error when starting.

**Diagnosis**:

```bash
# Check what's using port 53
sudo netstat -tulpn | grep :53
```

**Solutions**:

1. Stop the conflicting service:

    ```bash
    sudo systemctl stop systemd-resolved
    sudo systemctl disable systemd-resolved
    ```

2. Or edit the `/etc/swiftdns/config.toml` to change the listening address:

    ```toml
    address = "127.0.0.53:53" # Use .53 instead of .1
    ```

### DNS Queries Not Being Intercepted

**Problem**: DNS queries bypass Swiftdns.

**Diagnosis**:

```bash
# Check system DNS configuration
resolvectl status

# Test if Swiftdns is receiving queries
# Look for ";; SERVER: 127.0.0.1#53" in output
dig example.com
```

**Solutions**:

1. Ensure your system's DNS resolver is set to `127.0.0.1`:

    ```bash
    # First find your interface name
    ip link show
    # Then set DNS (replace wlan0 with your interface)
    sudo resolvectl dns wlan0 127.0.0.1
    ```

2. Check `/etc/resolv.conf`:

    ```bash
    cat /etc/resolv.conf
    ```

### Filters Not Working

**Problem**: Domains that should be blocked are still accessible.

**Diagnosis**:

```bash
# Test filter rules. You will see either "not blocked," "blocked," or "whitelisted"
swiftdns check facebook.com

# Verify file permissions
ls -la /etc/swiftdns/filters/
```

**Solutions**:

```bash
# Fix file permissions
sudo chmod 644 /etc/swiftdns/filters/*.list
sudo chown swiftdns /etc/swiftdns/filters/*.list

# Force reload (if notify feature disabled)
sudo systemctl restart swiftdns
```

## Diagnostic Commands

### Service Status

```bash
systemctl status swiftdns
journalctl -u swiftdns -n 50
swiftdns config
```

### Network Diagnostics

1. Test DNS resolution:

    ```bash
    dig example.com @127.0.0.1
    ```

2. Check listening ports:

    ```bash
    sudo netstat -tulpn | grep swiftdns
    ```

3. Verify your configuration:

    ```bash
    swiftdns config
    ```

4. Make sure your DoH provider is reachable and that any bootstrap IPs can be pinged:

    ```bash
    curl -I https://cloudflare-dns.com/dns-query
    ping 1.1.1.1
    ```

## Getting Help

If you're still experiencing issues, please open an issue on the [Swiftdns GitHub repository](https://github.com/chris9740/swiftdns/issues).

Include the output of `swiftdns config` and relevant log entries when reporting issues.
