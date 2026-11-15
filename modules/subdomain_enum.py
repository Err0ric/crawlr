import asyncio
import dns.resolver
import re
import secrets
import string
from datetime import datetime, timezone

from core.dnspool import dns_thread
from core.shared_hosting import wildcard_target
from modules import takeover
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


async def _query_crtsh(domain: str) -> tuple[list[str], list[dict], bool]:
    """Certificate transparency names and certificates for a domain.
    Returns (unique_subdomains, certificates, failed). `failed` is True when crt.sh could
    not be read: that is unknown, not "no certificate names anything". The crt.sh request
    is shared with the passive harvester through modules.crtsh, so a recon run asks crt.sh once."""
    raw_entries = []
    try:
        entries = await fetch_crtsh(domain)
    except Exception:
        return [], [], True

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
    return sorted(subs), raw_entries, False


# ---- wildcard DNS -------------------------------------------------------------------
# A zone with a wildcard record answers for every name, so "it resolves" stops being
# evidence that a host exists. Before the wordlist runs, three names that cannot exist are
# looked up. When they resolve, their answer is the wildcard's signature, and a guessed
# name with the same answer is left out unless another source attests it.

PROBE_LENGTHS = (16, 20, 24)      # three random labels of different lengths
MAX_PARENT_TESTS = 5              # extra parents (dev.example.com) tested for a wildcard of their own
PARENT_MIN_CHILDREN = 3           # a parent is only tested when this many children resolve alike
# Service names whose target is a host of the zone when the service is in use.
SRV_NAMES = ("_sip._tls", "_sipfederationtls._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp", "_autodiscover._tcp", "_imaps._tcp")
_ALNUM = string.ascii_lowercase + string.digits


def _make_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    return resolver


def _text(name) -> str:
    return str(name).rstrip(".").lower()


def random_label(length: int) -> str:
    """A label nobody would publish: lowercase letters and digits, new on every run."""
    return "".join(secrets.choice(_ALNUM) for _ in range(length))


def _own_cname(answer) -> str:
    """The CNAME a name itself carries, read from the answer to an address query. "" when
    the name has address records of its own (or the resolver did not show the chain)."""
    try:
        chain = answer.chaining_result.cnames
        return _text(chain[0][0].target) if chain else ""
    except Exception:
        return ""


def _lookup(resolver, fqdn: str) -> dict:
    """A records of a name and the CNAME it carries. Every failure reads as "no address"."""
    try:
        answer = resolver.resolve(fqdn, "A")
        return {"ips": [str(r) for r in answer], "cname": _own_cname(answer)}
    except Exception:
        return {"ips": [], "cname": ""}


def _probe(resolver, fqdn: str) -> dict:
    """What a name that cannot exist answers: {"state", "cnames", "ips"}.

    "resolves" when any of CNAME, A or AAAA returned a record. "absent" needs a definite
    answer: NXDOMAIN, or an empty answer for all three. A timeout, SERVFAIL or refused
    query is "unknown", never "absent"."""
    cnames, ips, failed = set(), set(), False
    for rtype in ("CNAME", "A", "AAAA"):
        try:
            answer = resolver.resolve(fqdn, rtype)
        except dns.resolver.NXDOMAIN:
            if rtype == "CNAME":          # asked for the name's own record: it does not exist
                return {"state": "absent", "cnames": [], "ips": []}
            continue                      # the CNAME exists and its target does not
        except dns.resolver.NoAnswer:
            continue
        except Exception:
            failed = True
            continue
        if rtype == "CNAME":
            cnames.update(_text(r.target) for r in answer)
        else:
            ips.update(str(r) for r in answer)
            own = _own_cname(answer)
            if own:
                cnames.add(own)
    state = "resolves" if (cnames or ips) else "unknown" if failed else "absent"
    return {"state": state, "cnames": sorted(cnames), "ips": sorted(ips)}


async def detect_wildcard(resolver, parent: str) -> dict:
    """Does every name under `parent` resolve? {"state": "yes" | "no" | "unknown", ...}.

    Two of the three probes resolving is a wildcard, two definitely absent is none, and
    anything else is unknown: a probe that failed is not a "no". The signature is the union
    over the probes, because the addresses behind a wildcard may rotate."""
    names = [f"{random_label(n)}.{parent}" for n in PROBE_LENGTHS]
    answers = await asyncio.gather(*(dns_thread(_probe, resolver, n) for n in names))
    resolved = [a for a in answers if a["state"] == "resolves"]
    absent = sum(1 for a in answers if a["state"] == "absent")
    state = "yes" if len(resolved) >= 2 else "no" if absent >= 2 else "unknown"
    return {
        "state": state,
        "cnames": sorted({c for a in resolved for c in a["cnames"]}) if state == "yes" else [],
        "ips": sorted({i for a in resolved for i in a["ips"]}) if state == "yes" else [],
        "probes": len(names),
        "matched": len(resolved),
        "failed": sum(1 for a in answers if a["state"] == "unknown"),
    }


def matches_wildcard(answer: dict, wildcard: dict) -> bool:
    """True when a name's answer is the wildcard's answer, so it proves nothing by itself.

    A name with a CNAME of its own is compared by that target alone: the same target is a
    match whatever the addresses are, a different one is not. A name with address records
    matches when it shares an address with the wildcard (the set may rotate)."""
    if wildcard.get("state") != "yes":
        return False
    if answer.get("cname"):
        return answer["cname"] in wildcard["cnames"]
    return bool(set(answer.get("ips") or []) & set(wildcard["ips"]))


def _record_targets(resolver, name: str, rtype: str) -> list[str] | None:
    """Hostnames an MX, NS or SRV record points at. None when the lookup failed."""
    try:
        answer = resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except Exception:
        return None
    return [_text(r.exchange if rtype == "MX" else r.target) for r in answer]


async def zone_attested(resolver, domain: str) -> tuple[dict[str, list[str]], list[str]]:
    """Names under the domain that its own MX, NS or SRV records point at: the zone's owner
    published them, so they exist whatever the wildcard says. Returns (name -> record
    types, record types whose lookup failed)."""
    asks = [(domain, "MX"), (domain, "NS")] + [(f"{s}.{domain}", "SRV") for s in SRV_NAMES]
    answers = await asyncio.gather(*(dns_thread(_record_targets, resolver, n, t) for n, t in asks))
    named: dict[str, list[str]] = {}
    failed: list[str] = []
    for (_, rtype), targets in zip(asks, answers):
        if targets is None:
            if rtype not in failed:
                failed.append(rtype)
            continue
        for t in targets:
            if t.endswith("." + domain) and rtype not in named.setdefault(t, []):
                named[t].append(rtype)
    return named, failed


def _alike(answers: list[dict]) -> bool:
    """Do these names all carry the same CNAME, or share an address?"""
    if not answers:
        return False
    cnames = {a["cname"] for a in answers}
    if len(cnames) == 1 and "" not in cnames:
        return True
    return bool(set.intersection(*(set(a["ips"]) for a in answers)))


async def _target_state(wildcard: dict) -> str:
    """Does the wildcard's CNAME target exist? "" for a wildcard with no CNAME. Uses the
    strict two-resolver test of the takeover check, and only when the probes saw no
    address behind the target."""
    if not wildcard["cnames"]:
        return ""
    if wildcard["ips"]:
        return "resolves"
    states = await asyncio.gather(*(dns_thread(takeover.resolution_state, c) for c in wildcard["cnames"][:2]))
    return "absent" if all(s == "absent" for s in states) else "resolves" if "resolves" in states else "unknown"


def wildcard_findings(domain: str, wildcard: dict) -> list[dict]:
    """The wildcard as findings. It is a configuration fact, so it is `info`. The one
    `flag` is a wildcard CNAME to a claimable service whose target is gone."""
    out = []
    add = lambda level, title, detail: out.append({"level": level, "title": title, "detail": detail})
    state = wildcard.get("state")
    if state == "unknown":
        add("info", f"Wildcard DNS could not be checked for {domain}",
            "The test lookups failed, so it is unknown whether every name under this domain resolves. "
            "No guessed name was left out, and a guessed name that resolves may not be a real host.")
    if state == "yes":
        target = ", ".join(wildcard["cnames"][:2]) or ", ".join(wildcard["ips"][:4])
        n = wildcard.get("suppressed", 0)
        left = ("No guessed name was left out." if not n
                else "1 guessed name was left out because it only matched the wildcard." if n == 1
                else f"{n} guessed names were left out because they only matched the wildcard.")
        detail = f"So a name that resolves is not proof a host exists. {left}"
        provider = wildcard.get("provider")
        if provider:
            detail += (f" The wildcard points at {provider['name']}, a third-party {provider['kind']}: "
                       f"what answers there is {provider['name']}'s, not a server of this domain's own.")
        service, t_state = wildcard.get("service"), wildcard.get("target_state")
        if service and t_state == "resolves" and not (provider and provider["name"] in service):
            detail += f" The target is hosted on {service}."
        elif t_state == "absent" and not service:
            detail += " The record's target does not resolve at the moment."
        elif service and t_state == "unknown":
            detail += f" Whether the {service} target still exists could not be checked: unknown, not safe."
        if wildcard.get("attest_failed"):
            detail += f" The {' and '.join(wildcard['attest_failed'])} lookup failed, so a mail or name server may be among the names left out."
        if wildcard.get("ct_failed"):
            detail += " Certificate logs could not be read, so names a certificate attests may be among those left out."
        add("info", f"Wildcard DNS: any name under {domain} resolves to {target}", detail)
        if service and t_state == "absent":
            add("flag", f"Wildcard DNS points at {wildcard['cnames'][0]} ({service}), which no longer resolves",
                f"Every name under {domain} follows this record, so whoever claims the {service} resource could answer for all of them. "
                "From DNS only: verify by hand before reporting a takeover.")
    for p in wildcard.get("parents") or []:
        target = ", ".join(p["cnames"][:2]) or ", ".join(p["ips"][:4])
        add("info", f"Wildcard DNS: any name under {p['parent']} resolves to {target}",
            "So a name under it that resolves is not proof a host exists. The names listed there come from certificate logs.")
    return out


async def run_subdomains(domain: str) -> dict:
    resolver = _make_resolver()

    async def lookup(fqdn: str) -> dict:
        # dnspython is blocking: the shared DNS pool keeps the event loop free and the volume polite.
        return await dns_thread(_lookup, resolver, fqdn)

    names = [f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS]

    async def dns_pass():
        wildcard = await detect_wildcard(resolver, domain)      # before the wordlist, so its answers can be read
        return wildcard, await asyncio.gather(*(lookup(n) for n in names))

    # The DNS pass and the CT query run at the same time.
    (wildcard, wordlist), (ct_subs, ct_entries, ct_failed) = await asyncio.gather(dns_pass(), _query_crtsh(domain))
    in_ct = set(ct_subs)
    attested, attest_failed = await zone_attested(resolver, domain) if wildcard["state"] == "yes" else ({}, [])

    found = []
    seen_fqdns = set()
    suppressed = []
    answers = {}
    for fqdn, ans in zip(names, wordlist):
        if not ans["ips"]:
            continue
        row = {"subdomain": fqdn, "ips": ans["ips"], "source": "DNS"}
        if matches_wildcard(ans, wildcard):
            # A guess that only repeats the wildcard is not a host. A name that a certificate
            # or the zone's own records attest is kept, and marked.
            if fqdn not in in_ct and fqdn not in attested:
                suppressed.append(fqdn)
                continue
            row["via_wildcard"] = True
            if fqdn in attested:
                row["attested"] = attested[fqdn]
        found.append(row)
        seen_fqdns.add(fqdn)
        answers[fqdn] = ans

    new_ct = [f for f in ct_subs if f not in seen_fqdns][:300]
    ct_answers = dict(zip(new_ct, await asyncio.gather(*(lookup(f) for f in new_ct))))
    answers.update(ct_answers)
    ct_count = 0
    for fqdn in ct_subs:
        if fqdn in seen_fqdns:
            # Tag existing DNS entry as also found in CT
            for item in found:
                if item["subdomain"] == fqdn and item["source"] == "DNS":
                    item["source"] = "DNS+CT"
            continue
        ans = ct_answers.get(fqdn) or {"ips": [], "cname": ""}
        row = {"subdomain": fqdn, "ips": ans["ips"], "source": "CT"}
        if matches_wildcard(ans, wildcard):
            row["via_wildcard"] = True          # certified, so it stays, but DNS alone proves nothing
        found.append(row)
        seen_fqdns.add(fqdn)
        ct_count += 1

    # One level down: a parent whose children all resolve alike may have a wildcard of its own.
    groups: dict[str, list[dict]] = {}
    for row in found:
        parent = row["subdomain"].split(".", 1)[1]
        if row["ips"] and not row.get("via_wildcard") and parent != domain and parent.endswith("." + domain):
            groups.setdefault(parent, []).append(row)
    suspects = sorted((p for p, rows in groups.items() if len(rows) >= PARENT_MIN_CHILDREN and _alike([answers[r["subdomain"]] for r in rows])),
                      key=lambda p: (-len(groups[p]), p))[:MAX_PARENT_TESTS]
    parents = []
    for parent, sub in zip(suspects, await asyncio.gather(*(detect_wildcard(resolver, p) for p in suspects))):
        if sub["state"] != "yes":
            continue
        parents.append({"parent": parent, "name": f"*.{parent}", "cnames": sub["cnames"], "ips": sub["ips"]})
        for row in groups[parent]:
            if matches_wildcard(answers[row["subdomain"]], sub):
                row["via_wildcard"] = True

    wildcard["suppressed"] = len(suppressed)
    wildcard["suppressed_names"] = suppressed
    wildcard["parents"] = parents
    if wildcard["state"] == "yes":
        wildcard["name"] = f"*.{domain}"
        wildcard["provider"] = wildcard_target(wildcard["cnames"], wildcard["ips"])
        wildcard["service"] = next((s for s in map(takeover.match_service, wildcard["cnames"]) if s), "")
        wildcard["target_state"] = await _target_state(wildcard)
        wildcard["attest_failed"] = attest_failed
        if ct_failed:
            # Without the logs, a certified name could not be told from a guess.
            wildcard["ct_failed"] = True
    findings = wildcard_findings(domain, wildcard)
    wildcard["note"] = next((f"{f['title']}. {f['detail']}" for f in findings if f["level"] == "info"), "")

    return {
        "domain": domain,
        "total": len(found),
        "checked": len(COMMON_SUBDOMAINS),
        "ct_found": ct_count,
        "ct_entries": ct_entries[:400],
        "ct_summary": summarize_certificates(ct_entries, {f["subdomain"] for f in found if f["ips"]}),
        "subdomains": found,
        "wildcard": wildcard,
        "findings": findings,
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
