#!/usr/bin/env python3

import requests
import json
import sys
import time
from typing import Dict, List, Any, Optional
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class CloudflareDNSFetcher:
    def __init__(self):
        self.base_url = "https://cloudflare-dns.com/dns-query"
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/dns-json",
                "User-Agent": "DNS Record Fetcher/1.0",
            }
        )

        self.record_types = {
            "A": 1,
            "NS": 2,
            "CNAME": 5,
            "SOA": 6,
            "PTR": 12,
            "MX": 15,
            "TXT": 16,
            "AAAA": 28,
            "SRV": 33,
            "RRSIG": 46,
        }

        self.query_targets = [
            ("example.com", ["A", "AAAA", "NS", "SOA", "TXT", "RRSIG"]),
            ("google.com", ["A", "AAAA", "NS", "TXT", "RRSIG"]),
            ("cloudflare.com", ["A", "AAAA", "NS", "TXT", "RRSIG"]),
            ("www.github.com", ["CNAME", "RRSIG"]),
            ("www.stackoverflow.com", ["CNAME"]),
            ("www.reddit.com", ["CNAME"]),
            ("gmail.com", ["MX", "TXT", "RRSIG"]),
            ("yahoo.com", ["MX", "TXT"]),
            ("outlook.com", ["MX", "TXT"]),
            ("_sip._tcp.sip.voice.google.com", ["SRV"]),
            ("_xmpp-server._tcp.jabber.org", ["SRV"]),
            ("_minecraft._tcp.hypixel.net", ["SRV"]),
            ("_imaps._tcp.gmail.com", ["SRV"]),
            ("8.8.8.8.in-addr.arpa", ["PTR"]),
            ("1.1.1.1.in-addr.arpa", ["PTR"]),
            ("4.4.8.8.in-addr.arpa", ["PTR"]),
            ("mozilla.org", ["A", "AAAA", "MX", "TXT", "RRSIG"]),
            ("github.com", ["A", "AAAA", "MX", "TXT", "NS", "RRSIG"]),
            ("stackoverflow.com", ["A", "AAAA", "MX", "TXT"]),
        ]

    def query_dns(
        self, name: str, record_type: str, max_retries: int = 3
    ) -> Optional[Dict[str, Any]]:
        """Query Cloudflare DoH for a specific record type."""
        params = {"name": name, "type": record_type}

        for attempt in range(max_retries):
            try:
                logger.info(
                    f"Querying {name} for {record_type} records (attempt {attempt + 1})"
                )
                response = self.session.get(
                    self.base_url, params=params, timeout=10
                )
                response.raise_for_status()

                data = response.json()

                time.sleep(0.1)

                return data

            except requests.exceptions.RequestException as e:
                logger.warning(
                    f"Request failed for {name} {record_type} (attempt {attempt + 1}): {e}"
                )
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    logger.error(
                        f"Failed to query {name} {record_type} after {max_retries} attempts"
                    )
                    return None
            except json.JSONDecodeError as e:
                logger.error(
                    f"Invalid JSON response for {name} {record_type}: {e}"
                )
                return None

    def normalize_name(self, name: str) -> str:
        """Normalize domain name to ensure it ends with a dot."""
        if not name.endswith("."):
            name += "."
        return name

    def process_response(
        self, response: Dict[str, Any]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Process a DNS response and extract records by type."""
        records_by_type = {}

        if "Answer" in response:
            for record in response["Answer"]:
                record_type_num = record.get("type")
                record_type_name = None

                for name, num in self.record_types.items():
                    if num == record_type_num:
                        record_type_name = name
                        break

                if record_type_name:
                    if record_type_name not in records_by_type:
                        records_by_type[record_type_name] = []

                    normalized_record = {
                        "name": self.normalize_name(record.get("name", "")),
                        "type": record_type_num,
                        "TTL": record.get("TTL", 3600),
                        "data": record.get("data", ""),
                    }
                    records_by_type[record_type_name].append(normalized_record)

        return records_by_type

    def fetch_all_records(self) -> Dict[str, Any]:
        """Fetch all DNS records and organize them by domain."""
        all_records = {}

        for domain, record_types in self.query_targets:
            logger.info(f"Processing domain: {domain}")
            domain_key = domain.rstrip(".")

            domain_records = {}

            for record_type in record_types:
                response = self.query_dns(domain, record_type)

                if response and response.get("Status") == 0:  # NOERROR
                    type_records = self.process_response(response)
                    domain_records.update(type_records)
                elif response and response.get("Status") == 3:  # NXDOMAIN
                    logger.info(f"NXDOMAIN for {domain} {record_type}")
                elif response and response.get("Status") == 2:  # SERVFAIL
                    logger.warning(f"SERVFAIL for {domain} {record_type}")
                else:
                    logger.info(f"No records found for {domain} {record_type}")

            if domain_records:
                all_records[domain_key] = domain_records

        return all_records

    def add_special_test_cases(self, records: Dict[str, Any]) -> Dict[str, Any]:
        """Add some special test cases for edge case testing."""

        records["nxdomain.example.com"] = {"_nxdomain": True}
        records["empty.example.com"] = {"_nodata": True}

        soa_record = None
        if "example.com" in records and "SOA" in records["example.com"]:
            soa_record = records["example.com"]["SOA"][0]
        else:
            soa_record = {
                "name": "example.com.",
                "type": 6,
                "TTL": 1800,
                "data": "a.iana-servers.net. nstld.verisign-grs.com. 2025011650 7200 3600 1209600 3600",
            }

        records["_soa"] = soa_record

        return records

    def save_to_file(
        self, records: Dict[str, Any], filename: str = "assets/dns_records.json"
    ):
        """Save records to JSON file."""
        try:
            with open(filename, "w") as f:
                json.dump(records, f, indent=2, sort_keys=True)
            logger.info(
                f"Successfully saved {len(records)} domains to {filename}"
            )
        except IOError as e:
            logger.error(f"Failed to save records to {filename}: {e}")
            sys.exit(1)

    def print_summary(self, records: Dict[str, Any]):
        """Print a summary of fetched records."""
        logger.info("=== FETCH SUMMARY ===")

        type_counts = {}
        total_records = 0

        for domain, domain_records in records.items():
            if domain.startswith("_"):  # Skip special entries like _soa
                continue

            for record_type, type_records in domain_records.items():
                if record_type.startswith("_"):  # Skip special flags
                    continue

                if record_type not in type_counts:
                    type_counts[record_type] = 0

                type_counts[record_type] += (
                    len(type_records) if isinstance(type_records, list) else 1
                )
                total_records += (
                    len(type_records) if isinstance(type_records, list) else 1
                )

        logger.info(
            f"Total domains: {len([d for d in records.keys() if not d.startswith('_')])}"
        )
        logger.info(f"Total records: {total_records}")
        logger.info("Record types found:")
        for record_type, count in sorted(type_counts.items()):
            logger.info(f"  {record_type}: {count}")


def main():
    """Main function to fetch DNS records and generate JSON file."""
    logger.info("Starting DNS record fetch from Cloudflare...")

    fetcher = CloudflareDNSFetcher()

    try:
        records = fetcher.fetch_all_records()
        records = fetcher.add_special_test_cases(records)

        fetcher.print_summary(records)

        output_file = (
            sys.argv[1] if len(sys.argv) > 1 else "assets/dns_records.json"
        )
        fetcher.save_to_file(records, output_file)

        logger.info(f"DNS records successfully generated in {output_file}")
        logger.info("You can now use this file with your DoH server!")

    except KeyboardInterrupt:
        logger.info("Fetch interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
