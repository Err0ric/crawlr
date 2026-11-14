"""
Email security posture for a domain, from DNS alone.

Answers the question "can someone send mail that looks like it comes from this domain,
and would the domain owner find out?" by reading SPF, DMARC, DKIM selectors, MTA-STS,
TLS-RPT and BIMI records. Nothing here contacts the target's mail servers.
"""

import asyncio
import re

import dns.resolver

from core.dnspool import dns_thread

MAX_SPF_LOOKUPS = 10
# Selectors used by the large mail providers and common defaults. DKIM selectors cannot be
# listed from DNS, so a miss here does not prove the domain has no DKIM.
DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2", "dkim", "mail", "smtp",
    "mandrill", "mxvault", "zoho", "protonmail", "protonmail2", "protonmail3", "fm1", "fm2", "fm3",
    "amazonses", "sendgrid", "smtpapi", "mailjet", "pm", "postmark", "mg", "krs", "cm", "sig1", "everlytickey1",
]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 3
    r.lifetime = 4
    return r


def _txt(name: str) -> list[str]:
    try:
        return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in _resolver().resolve(name, "TXT")]
    except Exception:
        return []


def _mx(name: str) -> list[str]:
    try:
        return sorted(str(r.exchange).rstrip(".").lower() for r in _resolver().resolve(name, "MX"))
    except Exception:
        return []


def parse_spf(record: str) -> dict:
    terms = record.split()[1:]
    all_term = next((t for t in terms if t.lstrip("+-~?").lower() == "all"), "")
    qualifier = all_term[0] if all_term and all_term[0] in "+-~?" else ("+" if all_term else "")
    lookups = sum(1 for t in terms if re.match(r"^[+\-~?]?(include:|a\b|mx\b|exists:|ptr\b|redirect=)", t, re.I))
    return {
        "record": record[:500],
        "all": {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass"}.get(qualifier, "none"),
        "includes": [t.split(":", 1)[1] for t in terms if t.lower().lstrip("+-~?").startswith("include:")][:20],
        "redirect": next((t.split("=", 1)[1] for t in terms if t.lower().startswith("redirect=")), ""),
        "lookups": lookups,
    }


def parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            tags[k.strip().lower()] = v.strip()
    pct = tags.get("pct", "100")
    return {
        "record": record[:500],
        "policy": tags.get("p", "").lower(),
        "subdomain_policy": tags.get("sp", "").lower(),
        "pct": int(pct) if pct.isdigit() else 100,
        "rua": [u.strip() for u in tags.get("rua", "").split(",") if u.strip()][:5],
        "ruf": [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()][:5],
        "alignment": {"spf": tags.get("aspf", "r"), "dkim": tags.get("adkim", "r")},
    }


def assess(spf_records: list[str], dmarc_records: list[str], dkim: list[dict], mx: list[str], mta_sts: str, tls_rpt: str, bimi: str) -> dict:
    """Pure function: turn the raw records into findings, a spoofability verdict and a grade."""
    findings = []
    add = lambda level, title, detail: findings.append({"level": level, "title": title, "detail": detail})

    spf = parse_spf(spf_records[0]) if spf_records else None
    if not spf_records:
        add("flag", "No SPF record", "Any server can claim to send mail for this domain, and receivers have no list to check against.")
    else:
        if len(spf_records) > 1:
            add("flag", "More than one SPF record", "Receivers treat multiple SPF records as an error, so SPF fails for all mail.")
        if spf["all"] == "pass":
            add("flag", "SPF ends in +all", "This authorizes every server on the internet to send as this domain.")
        elif spf["all"] in ("neutral", "none") and not spf["redirect"]:
            add("flag", "SPF does not reject anything", "The record has no -all or ~all, so unauthorized senders are not marked.")
        elif spf["all"] == "softfail":
            add("info", "SPF soft-fails (~all)", "Unauthorized mail is marked but usually still delivered. DMARC decides what happens to it.")
        else:
            add("ok", "SPF is strict (-all)", "Mail from servers not listed is rejected by SPF.")
        if spf["lookups"] > MAX_SPF_LOOKUPS:
            add("flag", f"SPF needs {spf['lookups']} DNS lookups", "The limit is 10. Past it, receivers return a permanent error and SPF fails.")

    dmarc = parse_dmarc(dmarc_records[0]) if dmarc_records else None
    if not dmarc:
        add("flag", "No DMARC record", "Receivers are not told to reject mail that fails SPF and DKIM, and the owner gets no reports.")
    else:
        if dmarc["policy"] == "none":
            add("flag", "DMARC is monitor-only (p=none)", "Failing mail is still delivered. The domain can be spoofed in the From line.")
        elif dmarc["policy"] == "quarantine":
            add("info", "DMARC quarantines failing mail", "Spoofed mail goes to spam, not the inbox. p=reject is stricter.")
        elif dmarc["policy"] == "reject":
            add("ok", "DMARC rejects failing mail", "Spoofed mail using this domain in the From line is refused.")
        else:
            add("flag", "DMARC policy is missing or invalid", "The record has no usable p= tag, so receivers ignore it.")
        if dmarc["policy"] in ("quarantine", "reject") and dmarc["pct"] < 100:
            add("info", f"DMARC applies to {dmarc['pct']}% of mail", "The rest is treated as if the policy were one step weaker.")
        if not dmarc["rua"]:
            add("info", "No DMARC report address", "Without rua= the owner does not receive aggregate reports about who is sending as this domain.")
        if dmarc["subdomain_policy"] == "none" and dmarc["policy"] != "none":
            add("flag", "Subdomains are not protected (sp=none)", "The main domain has a policy but any subdomain can still be spoofed.")

    found_dkim = [d for d in dkim if d.get("found")]
    if found_dkim:
        weak = [d["selector"] for d in found_dkim if d.get("key_bits") and d["key_bits"] < 2048]
        add("ok", f"DKIM key published ({', '.join(d['selector'] for d in found_dkim[:6])})", "At least one signing key is in DNS.")
        if weak:
            add("info", f"DKIM key under 2048 bits ({', '.join(weak)})", "1024-bit keys are still accepted but are considered weak.")
    else:
        add("info", "No DKIM key at common selectors", "Selectors cannot be listed from DNS, so this is not proof that DKIM is missing. Check a real message's DKIM-Signature header.")

    if not mx:
        add("info", "No MX records", "The domain does not receive mail. It can still be spoofed as a sender unless SPF and DMARC say otherwise.")
    if mx and not mta_sts:
        add("info", "No MTA-STS", "Mail to this domain can be downgraded to unencrypted delivery by an attacker on the network path.")
    if mx and mta_sts:
        add("ok", "MTA-STS published", "Sending servers are told to require TLS when delivering to this domain.")
    if tls_rpt:
        add("ok", "TLS reporting enabled", "The owner receives reports about failed TLS deliveries.")
    if bimi:
        add("ok", "BIMI record published", "A brand logo is advertised for supporting inboxes.")

    spf_ok = bool(spf) and len(spf_records) == 1 and spf["all"] in ("fail", "softfail") and spf["lookups"] <= MAX_SPF_LOOKUPS
    enforced = bool(dmarc) and dmarc["policy"] in ("quarantine", "reject")
    if enforced and dmarc["policy"] == "reject" and dmarc["pct"] == 100 and spf_ok:
        spoofable, grade = "no", "A"
    elif enforced and spf_ok:
        spoofable, grade = "unlikely", "B"
    elif enforced:
        spoofable, grade = "unlikely", "C"
    elif spf_ok:
        spoofable, grade = "yes", "D"
    else:
        spoofable, grade = "yes", "F"
    summary = {
        "no": "Spoofed mail using this domain should be rejected.",
        "unlikely": "Spoofed mail should be caught, with some gaps listed below.",
        "yes": "The domain can be spoofed in the From line: there is no enforced DMARC policy.",
    }[spoofable]
    return {"grade": grade, "spoofable": spoofable, "summary": summary, "findings": findings, "spf": spf, "dmarc": dmarc}


def _dkim_lookup(domain: str, selector: str) -> dict:
    records = [t for t in _txt(f"{selector}._domainkey.{domain}") if "p=" in t or "v=DKIM1" in t]
    if not records:
        return {"selector": selector, "found": False}
    m = re.search(r"p=([A-Za-z0-9+/=]*)", records[0].replace(" ", ""))
    key = m.group(1) if m else ""
    # A base64 RSA public key of n bits is about n/8 * 4/3 characters plus a short header.
    bits = 4096 if len(key) > 600 else 2048 if len(key) > 300 else 1024 if len(key) > 150 else 0
    return {"selector": selector, "found": True, "revoked": key == "", "key_bits": bits or None}


async def run_email_posture(domain: str) -> dict:
    th = dns_thread
    spf_all, dmarc_all, mx, sts, rpt, bimi, *dkim = await asyncio.gather(
        th(_txt, domain), th(_txt, f"_dmarc.{domain}"), th(_mx, domain), th(_txt, f"_mta-sts.{domain}"),
        th(_txt, f"_smtp._tls.{domain}"), th(_txt, f"default._bimi.{domain}"),
        *(th(_dkim_lookup, domain, s) for s in DKIM_SELECTORS),
    )
    spf_records = [t for t in spf_all if t.lower().startswith("v=spf1")]
    dmarc_records = [t for t in dmarc_all if t.lower().startswith("v=dmarc1")]
    mta_sts = next((t for t in sts if t.lower().startswith("v=stsv1")), "")
    tls_rpt = next((t for t in rpt if t.lower().startswith("v=tlsrptv1")), "")
    bimi_rec = next((t for t in bimi if t.lower().startswith("v=bimi1")), "")
    result = assess(spf_records, dmarc_records, list(dkim), mx, mta_sts, tls_rpt, bimi_rec)
    return {
        "domain": domain,
        "found": True,
        **result,
        "mx": mx[:10],
        "dkim": [d for d in dkim if d.get("found")],
        "dkim_selectors_checked": len(DKIM_SELECTORS),
        "mta_sts": mta_sts[:200],
        "tls_rpt": tls_rpt[:200],
        "bimi": bimi_rec[:300],
    }
