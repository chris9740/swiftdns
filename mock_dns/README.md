# Mock DNS Server

A configurable DNS server for testing DNS resolver implementations and record type support.

## Overview

This mock DNS server provides a controlled environment for testing DNS resolvers by serving predefined responses from a JSON database. It eliminates the need to rely on external DNS infrastructure or hunt for real domains with specific record types during development and testing.

## Features

-   **Configurable Records**: Define any DNS record type via JSON configuration
-   **Error Simulation**: Test NXDOMAIN, NODATA, and SERVFAIL scenarios
-   **DoH Support**: HTTP API compatible with DNS-over-HTTPS (RFC 8484)
-   **Hot Reload**: Update records without restarting the server
-   **Development-Friendly**: No external dependencies, fully self-contained

## Setup

### Create Virtual Environment

```bash
python3 -m venv venv
```

### Install Dependencies

```bash
pip install -r assets/requirements.txt
```

## Usage

Start the server:

```bash
python dns_server.py
```

The server provides an HTTP endpoint at `http://localhost:8080/resolve` that accepts DNS-over-HTTPS style queries.

## Configuration

### DNS Records (`assets/dns_records.json`)

Define test records in standard DNS-JSON format:

```json
{
    "example.com": {
        "A": [
            {
                "name": "example.com.",
                "type": 1,
                "TTL": 300,
                "data": "93.184.216.34"
            }
        ],
        "CAA": [
            {
                "name": "example.com.",
                "type": 257,
                "TTL": 3600,
                "data": "0 issue \"letsencrypt.org\""
            }
        ]
    }
}
```

### Error Conditions

Use special flags to simulate DNS error responses:

```json
{
    "nonexistent.example.com": {
        "_nxdomain": true
    },
    "empty.example.com": {
        "_nodata": true
    }
}
```

## Testing

Query the server using standard tools:

```bash
curl -H "Accept: application/dns-json" \
  "http://localhost:8080/resolve?name=example.com&type=A" | jq

curl -H "Accept: application/dns-json" \
  "http://localhost:8080/resolve?name=example.com&type=CAA" | jq

curl -H "Accept: application/dns-json" \
  "http://localhost:8080/resolve?name=nonexistent.example.com&type=A" | jq
```

## API Endpoints

-   `GET /resolve?name={domain}&type={type}` - DNS lookup
-   `POST /reload` - Reload records from JSON file
-   `GET /health` - Health check and record count

## Record Generation

Use the included `generate_dns_records.py` script to populate the database with real DNS records:

```bash
python generate_dns_records.py assets/dns_records.json
```

This fetches actual DNS records from public resolvers to create a realistic test dataset.

## Use Cases

-   **Record Type Testing**: Add records for new DNS types you're implementing
-   **Error Handling**: Verify your resolver handles NXDOMAIN/SERVFAIL correctly
-   **Performance Testing**: Control response timing and record sizes
-   **Integration Testing**: Predictable responses for automated tests

## Configuration with SwiftDNS

Point your SwiftDNS configuration to use this mock server:

```toml
[resolver]
url = "http://127.0.0.1:8080/resolve?name={name}&type={type}"
```

## Deactivating Virtual Environment

When finished testing:

```bash
deactivate
```
