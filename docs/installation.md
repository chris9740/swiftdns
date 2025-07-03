---
layout: default
title: Installation
---

## Installation Guide

Follow these steps to build and install Swiftdns on your system.

### Building from source

1. Install Rust and Dependencies

    ```bash
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    # Install system dependencies
    sudo apt install mold clang libssl-dev
    # Install cargo tools
    cargo install cargo-deb sccache
    ```

2. Clone Repository

    ```bash
    git clone https://github.com/chris9740/swiftdns.git
    cd swiftdns
    ```

3. Build the Project

    ```bash
    make package
    ```

4. Install the Package

    ```bash
    sudo dpkg -i target/debian/swiftdns_*.deb
    ```

5. Start the Service

    ```bash
    sudo systemctl enable swiftdns
    sudo systemctl start swiftdns
    ```

    If you encounter issues, refer to the [Troubleshooting section](troubleshooting.md).

### Configuring DNS

To use Swiftdns, set your system's DNS resolver to `127.0.0.1:53`.

### Verification

To verify that Swiftdns is running correctly, you can use the `dig` command:

```bash
dig example.com
```

This should return a valid DNS response routed through Swiftdns (as indicated by the `SERVER` line in the output).

## Next Steps

-   [Configure Swiftdns](configuration.md)
-   [Set up domain filtering](filtering.md)
