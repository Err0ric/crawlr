"""
Shodan InternetDB: free, no API key, no rate-limit headaches for light use.

Returns, per IP: open ports, CVEs, hostnames, tags, CPEs. It is a subset of the
full Shodan host API (no banners, no org/ISP/geo), which is why full Shodan
stays available as the bring-your-own-key upgrade. Accepts a domain and
resolves it first.

InternetDB describes an address, not a site. When the address is a shared edge of a hosting
platform (see core/shared_hosting.py) the result says so in `shared_host`, lists the other
sites seen there as `neighbors`, and `ports_note` explains whose ports these are.
"""

import dns.resolver
import httpx

from core import shared_hosting
from core.dnspool import dns_thread
from core.errors import error_fields
from core.validate import is_ip
from modules.resolver import resolve_domain

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


def _canonical_name(domain: str) -> str:
    """Where the name's CNAME chain ends, or "" when it has none or the lookup fails.
    Only used as a hint for shared-host detection, so a failure is not an error."""
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 2
    r.lifetime = 3
    try:
        name = str(r.resolve(domain, "A").canonical_name).rstrip(".").lower()
    except Exception:
        return ""
    return "" if name == domain.rstrip(".").lower() else name


async def run_internetdb(target: str, timeout: int = 15) -> dict:
    try:
        ip = await resolve_domain(target)
    except Exception as e:
        return {"target": target, "found": False, **error_fields(e)}
    cname = "" if is_ip(target) else await dns_thread(_canonical_name, target)
    cnames = [cname] if cname else []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(INTERNETDB_URL.format(ip=ip))
    except httpx.HTTPError as e:
        return {"target": target, "ip": ip, "found": False, **error_fields(e)}

    if resp.status_code == 404:
        empty = {"target": target, "ip": ip, "found": False, "ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
        return shared_hosting.annotate(empty, target, cnames=cnames)
    if resp.status_code != 200:
        return {"target": target, "ip": ip, "found": False, **error_fields(code="upstream", detail=f"InternetDB returned HTTP {resp.status_code}")}

    data = resp.json()
    vulns = sorted(data.get("vulns", []) or [], reverse=True)
    return shared_hosting.annotate({
        "target": target,
        "ip": data.get("ip", ip),
        "found": True,
        "source": "internetdb",
        "ports": sorted(data.get("ports", []) or []),
        "vulns": vulns[:50],
        "vuln_count": len(vulns),
        "hostnames": data.get("hostnames", []) or [],
        "tags": data.get("tags", []) or [],
        "cpes": data.get("cpes", []) or [],
    }, target, cnames=cnames)
