import asyncio
import dns.resolver
import re
from datetime import datetime, timezone

from core.dnspool import dns_thread
from modules.crtsh import fetch_crtsh
from core.logging import get_logger

log = get_logger(__name__)

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
    """Certificate transparency names and certificates for a domain.
    Returns (unique_subdomains, certificates). The crt.sh request is shared with the
    passive harvester through modules.crtsh, so a recon run asks crt.sh once."""
    raw_entries = []
    try:
        entries = await fetch_crtsh(domain)
    except Exception:
        return [], []

    subs = set()
    seen_certs = set()
    domain_lower = domain.lower()

    for entry in entries:
        # Extract subdomains from both fields
        for field in ("common_name", "name_value"):
            val = entry.get(field) or ""
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
        serial = entry.get("serial_number") or ""
        name_value = (entry.get("name_value") or "").strip()
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
            not_before = (entry.get("not_before") or "")[:10]
            raw_entries.append({
                "subdomain": first_name,
                "issuer": issuer_short,
                "date": not_before,
                "not_after": (entry.get("not_after") or "")[:10],
                "wildcard": "*." in name_value,
                "names": len([n for n in name_value.split("\n") if n.strip()]),
                "id": entry.get("id"),
            })

    subs.discard(domain_lower)
    # Sort raw entries by date descending
    raw_entries.sort(key=lambda x: x["date"], reverse=True)
    return sorted(subs), raw_entries


async def run_subdomains(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    def _lookup(fqdn: str) -> list[str]:
        try:
            return [str(r) for r in resolver.resolve(fqdn, "A")]
        except Exception:
            return []

    async def lookup(fqdn: str) -> list[str]:
        # dnspython is blocking: the shared DNS pool keeps the event loop free and the volume polite.
        return await dns_thread(_lookup, fqdn)

    found = []
    seen_fqdns = set()
    names = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]
    # The wordlist and the CT query run at the same time.
    wordlist_ips, (ct_subs, ct_entries) = await asyncio.gather(
        asyncio.gather(*(lookup(n) for n in names)),
        _query_crtsh(domain),
    )
    for fqdn, ips in zip(names, wordlist_ips):
        if ips:
            found.append({"subdomain": fqdn, "ips": ips, "source": "DNS"})
            seen_fqdns.add(fqdn)

    new_ct = [f for f in ct_subs if f not in seen_fqdns][:300]
    ct_ips = dict(zip(new_ct, await asyncio.gather(*(lookup(f) for f in new_ct))))
    ct_count = 0
    for fqdn in ct_subs:
        if fqdn in seen_fqdns:
            # Tag existing DNS entry as also found in CT
            for item in found:
                if item["subdomain"] == fqdn and item["source"] == "DNS":
                    item["source"] = "DNS+CT"
            continue
        found.append({"subdomain": fqdn, "ips": ct_ips.get(fqdn, []), "source": "CT"})
        seen_fqdns.add(fqdn)
        ct_count += 1

    return {
        "domain": domain,
        "total": len(found),
        "checked": len(COMMON_SUBDOMAINS),
        "ct_found": ct_count,
        "ct_entries": ct_entries[:400],
        "ct_summary": summarize_certificates(ct_entries, {f["subdomain"] for f in found if f["ips"]}),
        "subdomains": found,
    }


def summarize_certificates(entries: list[dict], resolving: set[str], today: str | None = None) -> dict | None:
    """Timeline facts from certificate transparency: when certificates were first and last
    issued, who issued them, how many are still valid, and which certified names no
    longer resolve (often retired or internal hosts)."""
    if not entries:
        return None
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    dated = sorted(e["date"] for e in entries if e.get("date"))
    issuers: dict[str, int] = {}
    by_year: dict[str, int] = {}
    for e in entries:
        issuers[e["issuer"]] = issuers.get(e["issuer"], 0) + 1
        if e.get("date"):
            by_year[e["date"][:4]] = by_year.get(e["date"][:4], 0) + 1
    active = [e for e in entries if e.get("not_after") and e["not_after"] >= today]
    names = {e["subdomain"] for e in entries}
    # The day each name was first certified: when a host appeared. Computed over every
    # entry, because the list sent to the browser is capped to the most recent ones.
    first_seen: dict[str, str] = {}
    for e in entries:
        d, n = e.get("date") or "", e.get("subdomain") or ""
        if d and n and (n not in first_seen or d < first_seen[n]):
            first_seen[n] = d
    return {
        "total": len(entries),
        "first_issued": dated[0] if dated else "",
        "last_issued": dated[-1] if dated else "",
        "active": len(active),
        "expired": len(entries) - len(active),
        "wildcards": sum(1 for e in entries if e.get("wildcard")),
        "issuers": sorted(({"name": k, "count": v} for k, v in issuers.items()), key=lambda x: -x["count"])[:8],
        "by_year": [{"year": y, "count": c} for y, c in sorted(by_year.items())],
        "not_resolving": sorted(n for n in names if n not in resolving)[:60],
        "first_seen": [{"name": n, "date": d[:10]} for n, d in sorted(first_seen.items(), key=lambda x: (x[1], x[0]))][:250],
    }
