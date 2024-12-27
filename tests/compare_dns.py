import dns.resolver
import dns.message
import dns.query
import dns.exception


def query_dns(server, domain, qtype, use_tcp=False):
    ip, port = server.split(":")
    port = int(port)
    query = dns.message.make_query(domain, qtype)
    response = (
        dns.query.tcp(query, ip, port=port)
        if use_tcp
        else dns.query.udp(query, ip, port=port)
    )
    return response


def print_mismatch(field, value1, value2):
    print(f"{field} mismatch:\n\t1: {value1}\n\t2: {value2}")


def compare_rrsets(rrset1, rrset2):
    if len(rrset1) != len(rrset2):
        return False

    for rr1, rr2 in zip(rrset1, rrset2):
        for line1, line2 in zip(str(rr1).split("\n"), str(rr2).split("\n")):
            segments1 = line1.split(" ", 4)
            segments2 = line2.split(" ", 4)

            name_matches = segments1[0] == segments2[0]
            class_matches = segments1[2] == segments2[2]
            type_matches = segments1[3] == segments2[3]
            data_matches = segments1[4] == segments2[4]

            if not name_matches:
                print_mismatch("Name", segments1[0], segments2[0])
                return False

            if not class_matches:
                print_mismatch("Class", segments1[2], segments2[2])
                return False

            if not type_matches:
                print_mismatch("Type", segments1[3], segments2[3])
                return False

            if not data_matches:
                print_mismatch("Data", segments1[4], segments2[4])
                return False
    return True


def compare_responses(response1, response2):
    if response1.rcode() != response2.rcode():
        return False

    if response1.question != response2.question:
        return False

    if not compare_rrsets(response1.answer, response2.answer):
        return False

    if not compare_rrsets(response1.authority, response2.authority):
        return False

    if not compare_rrsets(response1.additional, response2.additional):
        return False

    return True


def main():
    servers = {"swiftdns": "127.0.0.1:5053", "cloudflare": "1.1.1.1:53"}
    domains = ["duckduckgo.com", "example.com"]
    query_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]

    print("Starting DNS comparison test")
    print(f"Domains:", ", ".join(domains))
    print(f"Query types:", ", ".join(query_types))

    for domain in domains:
        for qtype in query_types:
            swiftdns_response = None
            cloudflare_response = None

            try:
                swiftdns_response = query_dns(servers["swiftdns"], domain, qtype)
            except (dns.exception.DNSException, ValueError) as e:
                print(
                    f"SwiftDNS query failed for {domain} with query type {qtype}: {e}"
                )
                exit(1)

            try:
                cloudflare_response = query_dns(servers["cloudflare"], domain, qtype)
                if cloudflare_response.flags & dns.flags.TC:
                    cloudflare_response = query_dns(
                        servers["cloudflare"], domain, qtype, use_tcp=True
                    )
            except (dns.exception.DNSException, ValueError) as e:
                print(
                    f"Cloudflare query failed for {domain} with query type {qtype}: {e}"
                )
                exit(1)

            if swiftdns_response and cloudflare_response:
                if not compare_responses(swiftdns_response, cloudflare_response):
                    print(f"Results do not match for {domain} with query type {qtype}")
                    exit(1)
            else:
                print(f"One of the queries failed for {domain} with query type {qtype}")
                exit(1)

    print("All queries passed successfully")


if __name__ == "__main__":
    main()
