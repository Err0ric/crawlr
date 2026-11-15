"""
DNS checks beyond the basic record list: who may issue certificates (CAA), whether the
zone is signed (DNSSEC), whether it answers for any name (wildcard), and what the
addresses call themselves (reverse DNS). DNS queries only.
"""

import asyncio
import secrets

import dns.resolver
import dns.reversename

from core.dnspool import dns_thread
from core.validate import registrable_domain


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 3
    r.lifetime = 4
    return r


def _query(name: str, rtype: str) -> list[str]:
    try:
        return [str(r) for r in _resolver().resolve(name, rtype)]
    except Exception:
        return []


def _ptr(ip: str) -> str:
    try:
        return str(_resolver().resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".")
    except Exception:
        return ""


def parse_caa(records: list[str]) -> dict:
    issue, wild, iodef = [], [], []
    for rec in records:
        parts = rec.split(None, 2)
        if len(parts) < 3:
            continue
        tag, value = parts[1].lower(), parts[2].strip('"')
        (issue if tag == "issue" else wild if tag == "issuewild" else iodef if tag == "iodef" else []).append(value)
    return {"issue": issue, "issuewild": wild, "iodef": iodef}


async def run_dns_depth(domain: str) -> dict:
    th = dns_thread
    apex = registrable_domain(domain)
    probe = f"crawlr-{secrets.token_hex(6)}.{domain}"
    caa, caa_apex, dnskey, ds, wildcard, a, aaaa, ns = await asyncio.gather(
        th(_query, domain, "CAA"), th(_query, apex, "CAA") if apex != domain else th(lambda: []),
        th(_query, apex, "DNSKEY"), th(_query, apex, "DS"),
        th(_query, probe, "A"), th(_query, domain, "A"), th(_query, domain, "AAAA"), th(_query, apex, "NS"),
    )
    ips = (a + aaaa)[:8]
    ptrs = await asyncio.gather(*(th(_ptr, ip) for ip in ips))
    caa_records = caa or caa_apex
    signed = bool(dnskey)
    findings = []
    add = lambda level, title, detail: findings.append({"level": level, "title": title, "detail": detail})
    if not caa_records:
        add("info", "No CAA record", "Any certificate authority may issue a certificate for this domain.")
    else:
        parsed = parse_caa(caa_records)
        add("ok", f"CAA limits issuance to {', '.join(parsed['issue']) or 'no CA'}", "Other certificate authorities must refuse to issue.")
    if signed and ds:
        add("ok", "DNSSEC is enabled", "Answers for this zone are signed and the parent zone vouches for the key.")
    elif signed and not ds:
        add("flag", "DNSSEC keys with no DS record", "The zone is signed but the parent does not point to it, so validation does not happen.")
    else:
        add("info", "DNSSEC is not enabled", "DNS answers for this domain are not signed, so they can be forged on a hostile network.")
    if wildcard:
        add("info", f"Wildcard DNS: any subdomain resolves ({', '.join(wildcard[:2])})", "A name that resolves is not proof a host exists. The subdomain check leaves out guessed names that only match the wildcard.")
    return {
        "domain": domain,
        "found": True,
        "caa": parse_caa(caa_records) if caa_records else None,
        "dnssec": {"signed": signed, "ds": bool(ds)},
        "wildcard": {"present": bool(wildcard), "ips": wildcard[:4]},
        "nameservers": sorted(n.rstrip(".").lower() for n in ns)[:8],
        "reverse_dns": [{"ip": ip, "ptr": ptr} for ip, ptr in zip(ips, ptrs)],
        "findings": findings,
    }
