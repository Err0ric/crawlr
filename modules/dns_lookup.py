import asyncio
import ipaddress

import dns.resolver

from core.dnspool import dns_thread

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Cloudflare IPv4 ranges (from https://www.cloudflare.com/ips-v4/)
CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_NETS = [ipaddress.ip_network(r) for r in CLOUDFLARE_RANGES]


def _is_cloudflare_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _CF_NETS)
    except ValueError:
        return False


async def run_dns(domain: str) -> dict:
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 5
    resolver.lifetime = 5

    def query(rtype: str) -> list[str]:
        try:
            return [str(rdata) for rdata in resolver.resolve(domain, rtype)]
        except Exception:
            return []

    # dnspython is blocking: run the seven lookups side by side in threads.
    answers = await asyncio.gather(*(dns_thread(query, t) for t in RECORD_TYPES))
    for rtype, records in zip(RECORD_TYPES, answers):
        if records:
            results[rtype] = records

    # Cloudflare proxy detection
    a_records = results.get("A", [])
    cf_proxied = any(_is_cloudflare_ip(ip) for ip in a_records)

    return {
        "domain": domain,
        "total": sum(len(v) for v in results.values()),
        "records": results,
        "cloudflare_proxied": cf_proxied,
    }
