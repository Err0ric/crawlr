import dns.resolver
import httpx
import re

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    "api", "app", "dev", "staging", "test", "beta", "demo",
    "admin", "panel", "dashboard", "portal", "manage",
    "vpn", "remote", "gateway", "proxy",
    "cdn", "static", "assets", "media", "img", "images",
    "blog", "shop", "store", "docs", "wiki", "help", "support",
    "git", "gitlab", "jenkins", "ci", "build",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "auth", "login", "sso", "oauth",
    "m", "mobile", "wap",
    "cpanel", "whm", "plesk", "webmin",
    "cloud", "s3", "backup", "vault",
    "status", "monitor", "metrics", "grafana",
]


async def _query_crtsh(domain: str) -> list[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code != 200:
                return []
            entries = resp.json()
    except Exception:
        return []

    subs = set()
    for entry in entries:
        for field in ("common_name", "name_value"):
            val = entry.get(field, "")
            for name in val.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    if re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$', name):
                        subs.add(name)
    subs.discard(domain)
    return sorted(subs)


async def run_subdomains(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    found = []
    seen_fqdns = set()
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            found.append({"subdomain": fqdn, "ips": ips, "source": "DNS"})
            seen_fqdns.add(fqdn)
        except Exception:
            pass

    # Certificate transparency
    ct_subs = await _query_crtsh(domain)
    ct_count = 0
    for fqdn in ct_subs:
        if fqdn in seen_fqdns:
            continue
        ips = []
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
        except Exception:
            pass
        found.append({"subdomain": fqdn, "ips": ips, "source": "CT"})
        seen_fqdns.add(fqdn)
        ct_count += 1

    return {
        "domain": domain,
        "total": len(found),
        "checked": len(COMMON_SUBDOMAINS),
        "ct_found": ct_count,
        "subdomains": found,
    }
