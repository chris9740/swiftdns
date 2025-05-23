#!/usr/bin/env python3

import json
from typing import Dict, List, Any
from flask import Flask, request, jsonify, abort
import dns.rdatatype
import dns.rcode
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)


class DoHResolver:
    def __init__(self, db_file: str = "assets/dns_records.json"):
        self.db_file = db_file
        self.records = self.load_records()

    def load_records(self) -> Dict[str, Any]:
        """Load DNS records from the JSON database file."""
        try:
            with open(self.db_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Database file {self.db_file} not found")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.db_file}: {e}")
            return {}

    def reload_records(self):
        """Reload records from the database file."""
        self.records = self.load_records()
        logger.info("Records reloaded from database")

    def normalize_name(self, name: str) -> str:
        """Normalize domain name (ensure it ends with a dot)."""
        name = name.lower()
        if not name.endswith("."):
            name += "."
        return name

    def get_type_name(self, type_num: int) -> str:
        """Convert numeric DNS type to string."""
        try:
            rdata_type = dns.rdatatype.RdataType(type_num)
            return dns.rdatatype.to_text(rdata_type)
        except ValueError:
            return str(type_num)

    def get_type_number(self, type_name: str) -> int:
        """Convert DNS type string to number."""
        try:
            return dns.rdatatype.from_text(type_name.upper())
        except dns.rdatatype.UnknownRdatatype:
            try:
                return int(type_name)
            except ValueError:
                return 0

    def lookup_records(
        self, qname: str, qtype_num: int
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
        """
        Look up DNS records for a given name and type.
        Returns (answer_records, authority_records, rcode).
        """
        qname_normalized = self.normalize_name(qname)
        qtype_name = self.get_type_name(qtype_num)

        qname_key = qname_normalized.rstrip(".")

        if qname_key not in self.records:
            authority = []
            if "_soa" in self.records:
                authority = [self.records["_soa"]]
            return [], authority, dns.rcode.NXDOMAIN

        domain_records = self.records[qname_key]

        if domain_records.get("_nxdomain"):
            authority = []
            if "_soa" in self.records:
                authority = [self.records["_soa"]]
            return [], authority, dns.rcode.NXDOMAIN

        if domain_records.get("_nodata"):
            authority = []
            if "_soa" in self.records:
                authority = [self.records["_soa"]]
            return [], authority, dns.rcode.NOERROR

        if qtype_name in domain_records:
            return domain_records[qtype_name], [], dns.rcode.NOERROR

        authority = []
        if "_soa" in self.records:
            authority = [self.records["_soa"]]
        return [], authority, dns.rcode.NOERROR

    def handle_query(self, name: str, type_param: str) -> Dict[str, Any]:
        """Process a DNS query and return JSON response."""
        try:
            if type_param.isdigit():
                qtype_num = int(type_param)
            else:
                qtype_num = self.get_type_number(type_param)

            qname_normalized = self.normalize_name(name)

            answer_records, authority_records, rcode = self.lookup_records(
                name, qtype_num
            )

            result = {
                "Status": rcode,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": False,
                "CD": False,
                "Question": [{"name": qname_normalized, "type": qtype_num}],
            }

            if answer_records:
                result["Answer"] = answer_records

            if authority_records:
                result["Authority"] = authority_records

            return result

        except Exception as e:
            logger.error(f"Error processing query for {name} {type_param}: {e}")
            return {
                "Status": dns.rcode.SERVFAIL,
                "TC": False,
                "RD": True,
                "RA": True,
                "AD": False,
                "CD": False,
                "Question": [
                    {
                        "name": self.normalize_name(name),
                        "type": self.get_type_number(type_param),
                    }
                ],
            }


resolver = DoHResolver()


@app.route("/resolve", methods=["GET"])
def resolve():
    """Handle DoH queries using Google DNS API format."""
    name = request.args.get("name")
    type_param = request.args.get("type", "A")

    if not name:
        abort(400, "Missing 'name' parameter")

    result = resolver.handle_query(name, type_param)

    response = jsonify(result)
    response.headers["Content-Type"] = "application/dns-json"
    return response


@app.route("/reload", methods=["POST"])
def reload_database():
    """Reload the DNS records database."""
    resolver.reload_records()
    return jsonify({"status": "success", "message": "Database reloaded"})


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "ok", "records_loaded": len(resolver.records)})


if __name__ == "__main__":
    print("Starting DoH Resolver on http://localhost:8080")
    print("DoH endpoint: http://localhost:8080/resolve")
    print(
        "Example: http://localhost:8080/resolve?name=alias.example.com&type=DNAME"
    )
    print("Reload endpoint: http://localhost:8080/reload")
    print("Health check: http://localhost:8080/health")
    app.run(host="0.0.0.0", port=8080, debug=True)
