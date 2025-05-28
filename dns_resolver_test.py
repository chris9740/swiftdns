#!/usr/bin/env python3
"""
Comprehensive DNS Resolver Testing Suite
Tests a custom DNS resolver against Cloudflare's enterprise resolver
"""

import dns.resolver
import dns.message
import dns.query
import dns.rcode
import time
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class DNSTestCase:
    name: str
    domain: str
    record_type: str
    expected_rcode: int = dns.rcode.NOERROR
    description: str = ""


@dataclass
class TestResponse:
    success: bool
    rcode: int
    answers: List[str]
    authority: List[str]
    additional: List[str]
    response_time: float
    error: Optional[str] = None


class DNSResolverTester:
    def __init__(
        self, custom_resolver_host="127.0.0.1", custom_resolver_port=5053
    ):
        self.custom_resolver = (custom_resolver_host, custom_resolver_port)
        self.cloudflare_resolver = "1.1.1.1"
        self.test_domains = ["tutanota.com", "signal.org", "duckduckgo.com"]

    def define_test_cases(self) -> List[DNSTestCase]:
        """Define comprehensive test cases for DNS resolver functionality"""
        test_cases = []

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"A_record_{domain}",
                    domain=domain,
                    record_type="A",
                    description=f"IPv4 address lookup for {domain}",
                )
            )

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"AAAA_record_{domain}",
                    domain=domain,
                    record_type="AAAA",
                    description=f"IPv6 address lookup for {domain}",
                )
            )

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"MX_record_{domain}",
                    domain=domain,
                    record_type="MX",
                    description=f"Mail exchange records for {domain}",
                )
            )

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"TXT_record_{domain}",
                    domain=domain,
                    record_type="TXT",
                    description=f"Text records for {domain}",
                )
            )

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"NS_record_{domain}",
                    domain=domain,
                    record_type="NS",
                    description=f"Name server records for {domain}",
                )
            )

        for domain in self.test_domains:
            test_cases.append(
                DNSTestCase(
                    name=f"SOA_record_{domain}",
                    domain=domain,
                    record_type="SOA",
                    description=f"Start of Authority record for {domain}",
                )
            )

        test_cases.append(
            DNSTestCase(
                name="CNAME_record_www_tutanota",
                domain="www.tutanota.com",
                record_type="CNAME",
                description="CNAME record for www.tutanota.com",
            )
        )

        test_cases.append(
            DNSTestCase(
                name="NXDOMAIN_test",
                domain="this-domain-does-not-exist-12345.com",
                record_type="A",
                expected_rcode=dns.rcode.NXDOMAIN,
                description="Non-existent domain should return NXDOMAIN",
            )
        )

        test_cases.append(
            DNSTestCase(
                name="case_insensitive_test",
                domain="TUTANOTA.COM",
                record_type="A",
                description="Case insensitive domain lookup",
            )
        )

        return test_cases

    def query_custom_resolver(
        self, domain: str, record_type: str
    ) -> TestResponse:
        """Query the custom DNS resolver"""
        try:
            start_time = time.time()

            query = dns.message.make_query(domain, record_type)

            response = dns.query.udp(
                query,
                self.custom_resolver[0],
                port=self.custom_resolver[1],
                timeout=5.0,
            )

            response_time = time.time() - start_time

            answers = []
            authority = []
            additional = []

            for rrset in response.answer:
                for rdata in rrset:
                    answers.append(str(rdata))

            for rrset in response.authority:
                for rdata in rrset:
                    authority.append(str(rdata))

            for rrset in response.additional:
                for rdata in rrset:
                    additional.append(str(rdata))

            return TestResponse(
                success=True,
                rcode=response.rcode(),
                answers=answers,
                authority=authority,
                additional=additional,
                response_time=response_time,
            )

        except Exception as e:
            return TestResponse(
                success=False,
                rcode=-1,
                answers=[],
                authority=[],
                additional=[],
                response_time=0.0,
                error=str(e),
            )

    def query_cloudflare_resolver(
        self, domain: str, record_type: str
    ) -> TestResponse:
        """Query Cloudflare's DNS resolver"""
        try:
            start_time = time.time()

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.cloudflare_resolver]
            resolver.timeout = 5.0

            try:
                answer = resolver.resolve(domain, record_type)
                response_time = time.time() - start_time

                answers = (
                    [str(rdata) for rdata in answer.rrset]
                    if answer.rrset
                    else []
                )

                return TestResponse(
                    success=True,
                    rcode=dns.rcode.NOERROR,
                    answers=answers,
                    authority=[],
                    additional=[],
                    response_time=response_time,
                )

            except dns.resolver.NXDOMAIN:
                response_time = time.time() - start_time
                return TestResponse(
                    success=True,
                    rcode=dns.rcode.NXDOMAIN,
                    answers=[],
                    authority=[],
                    additional=[],
                    response_time=response_time,
                )

            except dns.resolver.NoAnswer:
                response_time = time.time() - start_time
                return TestResponse(
                    success=True,
                    rcode=dns.rcode.NOERROR,
                    answers=[],
                    authority=[],
                    additional=[],
                    response_time=response_time,
                )

        except Exception as e:
            return TestResponse(
                success=False,
                rcode=-1,
                answers=[],
                authority=[],
                additional=[],
                response_time=0.0,
                error=str(e),
            )

    def compare_responses(
        self,
        custom_resp: TestResponse,
        cloudflare_resp: TestResponse,
        test_case: DNSTestCase,
    ) -> Tuple[TestResult, str]:
        """Compare responses from both resolvers"""

        if not custom_resp.success:
            return (
                TestResult.FAIL,
                f"Custom resolver failed: {custom_resp.error}",
            )

        if not cloudflare_resp.success:
            return (
                TestResult.SKIP,
                f"Cloudflare resolver failed: {cloudflare_resp.error}",
            )

        if custom_resp.rcode != test_case.expected_rcode:
            return TestResult.FAIL, (
                f"Expected rcode {dns.rcode.to_text(dns.rcode.Rcode(test_case.expected_rcode))}, "
                f"got {dns.rcode.to_text(dns.rcode.Rcode(custom_resp.rcode))}"
            )

        if test_case.expected_rcode == dns.rcode.NXDOMAIN:
            if custom_resp.rcode == dns.rcode.NXDOMAIN:
                return TestResult.PASS, "Correctly returned NXDOMAIN"
            else:
                return (
                    TestResult.FAIL,
                    f"Expected NXDOMAIN, got {dns.rcode.to_text(dns.rcode.Rcode(custom_resp.rcode))}",
                )

        if test_case.expected_rcode == dns.rcode.NOERROR:
            custom_has_answers = len(custom_resp.answers) > 0
            cloudflare_has_answers = len(cloudflare_resp.answers) > 0

            if custom_has_answers != cloudflare_has_answers:
                return TestResult.FAIL, (
                    f"Answer presence mismatch: custom={custom_has_answers}, "
                    f"cloudflare={cloudflare_has_answers}"
                )

            if custom_has_answers:
                custom_set = set(custom_resp.answers)
                cloudflare_set = set(cloudflare_resp.answers)

                if (
                    len(custom_set.intersection(cloudflare_set)) == 0
                    and len(custom_set) > 0
                ):
                    return TestResult.FAIL, (
                        f"No matching answers found. "
                        f"Custom: {custom_resp.answers}, "
                        f"Cloudflare: {cloudflare_resp.answers}"
                    )

        return TestResult.PASS, f"Responses match appropriately"

    def run_test_case(self, test_case: DNSTestCase) -> Dict[str, Any]:
        """Run a single test case"""
        logger.info(f"Running test: {test_case.name}")

        custom_resp = self.query_custom_resolver(
            test_case.domain, test_case.record_type
        )
        cloudflare_resp = self.query_cloudflare_resolver(
            test_case.domain, test_case.record_type
        )

        result, message = self.compare_responses(
            custom_resp, cloudflare_resp, test_case
        )

        return {
            "test_case": test_case,
            "result": result,
            "message": message,
            "custom_response": custom_resp,
            "cloudflare_response": cloudflare_resp,
        }

    def run_all_tests(self) -> Dict[str, Any]:
        """Run all test cases and return results"""
        test_cases = self.define_test_cases()
        results = []

        logger.info(f"Running {len(test_cases)} DNS resolver tests...")
        logger.info(
            f"Custom resolver: {self.custom_resolver[0]}:{self.custom_resolver[1]}"
        )
        logger.info(f"Reference resolver: {self.cloudflare_resolver}")
        print("=" * 80)

        pass_count = 0
        fail_count = 0
        skip_count = 0

        for test_case in test_cases:
            try:
                result = self.run_test_case(test_case)
                results.append(result)

                status_symbol = {
                    TestResult.PASS: "✓",
                    TestResult.FAIL: "✗",
                    TestResult.SKIP: "⚠",
                }[result["result"]]

                print(
                    f"{status_symbol} {test_case.name:<30} | {result['message']}"
                )

                if result["result"] == TestResult.PASS:
                    pass_count += 1
                elif result["result"] == TestResult.FAIL:
                    fail_count += 1
                    print(f"  Custom:     {result['custom_response'].answers}")
                    print(
                        f"  Cloudflare: {result['cloudflare_response'].answers}"
                    )
                else:
                    skip_count += 1

            except Exception as e:
                logger.error(f"Test {test_case.name} crashed: {e}")
                fail_count += 1

        print("=" * 80)
        print(
            f"Test Results: {pass_count} passed, {fail_count} failed, {skip_count} skipped"
        )

        return {
            "total_tests": len(test_cases),
            "passed": pass_count,
            "failed": fail_count,
            "skipped": skip_count,
            "results": results,
        }


def main():
    """Main entry point"""
    tester = DNSResolverTester()

    try:
        test_resp = tester.query_custom_resolver("tutanota.com", "A")
        if not test_resp.success:
            logger.error(
                f"Cannot connect to custom resolver: {test_resp.error}"
            )
            return 1
        logger.info("Successfully connected to custom resolver")
    except Exception as e:
        logger.error(f"Failed to connect to custom resolver: {e}")
        return 1

    summary = tester.run_all_tests()

    success_rate = (summary["passed"] / summary["total_tests"]) * 100
    print(f"\nOverall Success Rate: {success_rate:.1f}%")

    if summary["failed"] > 0:
        print(
            f"\n⚠️  {summary['failed']} tests failed. Review the output above for details."
        )
        return 1
    else:
        print("\n🎉 All tests passed! Your DNS resolver is working correctly.")
        return 0


if __name__ == "__main__":
    exit(main())
