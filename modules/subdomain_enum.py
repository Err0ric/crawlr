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


async def _query_crtsh(domain: str) -> tuple[list[str], list[dict]]:
    """Query crt.sh certificate transparency logs.
    Returns (unique_subdomains, raw_ct_entries)."""
    raw_entries = []
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code != 200:
                return [], []
            entries = resp.json()
    except Exception as e:
        print(f"[crt.sh] Error querying CT logs for {domain}: {type(e).__name__}: {e}")
        return [], []

    subs = set()
    seen_certs = set()
    domain_lower = domain.lower()

    for entry in entries:
        # Extract subdomains from both fields
        for field in ("common_name", "name_value"):
            val = entry.get(field, "")
            for name in val.split("\n"):
                name = name.strip().lower()
                while name.startswith("*."):
                    name = name[2:]
                if not name:
                    continue
                if (name.endswith(f".{domain_lower}") or name == domain_lower):
                    if re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$', name):
                        subs.add(name)

        # Build raw CT entry for the card (dedupe by cert serial)
        serial = entry.get("serial_number", "")
        name_value = entry.get("name_value", "").strip()
        # Clean name_value: take first line, strip wildcards
        first_name = name_value.split("\n")[0].strip().lower()
        while first_name.startswith("*."):
            first_name = first_name[2:]

        dedup_key = f"{serial}_{first_name}"
        if dedup_key not in seen_certs and first_name:
            seen_certs.add(dedup_key)
            issuer = entry.get("issuer_name", "")
            # Extract CN from issuer
            cn_match = re.search(r'CN=([^,]+)', issuer)
            issuer_short = cn_match.group(1).strip() if cn_match else issuer[:40]
            not_before = entry.get("not_before", "")[:10]
            raw_entries.append({
                "subdomain": first_name,
                "issuer": issuer_short,
                "date": not_before,
            })

    subs.discard(domain_lower)
    # Sort raw entries by date descending
    raw_entries.sort(key=lambda x: x["date"], reverse=True)
    return sorted(subs), raw_entries


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
    ct_subs, ct_entries = await _query_crtsh(domain)
    ct_count = 0
    for fqdn in ct_subs:
        if fqdn in seen_fqdns:
            # Tag existing DNS entry as also found in CT
            for item in found:
                if item["subdomain"] == fqdn and item["source"] == "DNS":
                    item["source"] = "DNS+CT"
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
        "ct_entries": ct_entries,
        "subdomains": found,
    }
