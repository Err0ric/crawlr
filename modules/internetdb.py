"""
Shodan InternetDB: free, no API key, no rate-limit headaches for light use.

Returns, per IP: open ports, CVEs, hostnames, tags, CPEs. It is a subset of the
full Shodan host API (no banners, no org/ISP/geo), which is why full Shodan
stays available as the bring-your-own-key upgrade. Accepts a domain and
resolves it first.
"""

import ipaddress

import httpx

from modules.resolver import resolve_domain

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"


async def run_internetdb(target: str, timeout: int = 15) -> dict:
    try:
        ip = str(ipaddress.ip_address(target))
    except ValueError:
        ip = resolve_domain(target)
    if not ip:
        return {"target": target, "found": False, "error": "Could not resolve target"}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(INTERNETDB_URL.format(ip=ip))
    except httpx.HTTPError as e:
        return {"target": target, "ip": ip, "found": False, "error": f"InternetDB unreachable: {type(e).__name__}"}

    if resp.status_code == 404:
        return {"target": target, "ip": ip, "found": False, "ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": []}
    if resp.status_code != 200:
        return {"target": target, "ip": ip, "found": False, "error": f"InternetDB returned {resp.status_code}"}

    data = resp.json()
    vulns = sorted(data.get("vulns", []) or [], reverse=True)
    return {
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
    }
