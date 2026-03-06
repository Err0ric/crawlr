import whois

PRIVACY_KEYWORDS = [
    "privacy", "redacted", "whoisguard", "withheld", "protected",
    "domains by proxy", "contact privacy", "identity protect",
    "whois privacy", "private registration", "data protected",
    "not disclosed", "gdpr", "statutory masking",
]


def _detect_privacy(w) -> bool:
    """Check if WHOIS data indicates privacy protection."""
    for field in ["name", "org", "registrant_name", "emails"]:
        val = w.get(field, "")
        if isinstance(val, list):
            val = " ".join(str(v) for v in val)
        val = str(val).lower()
        if any(kw in val for kw in PRIVACY_KEYWORDS):
            return True
    return False


async def run_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        def first(val):
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val) if val else ""

        privacy = _detect_privacy(w)

        return {
            "domain": domain,
            "found": True,
            "registrar": first(w.registrar),
            "creation_date": first(w.creation_date),
            "expiration_date": first(w.expiration_date),
            "updated_date": first(w.updated_date),
            "name_servers": [str(ns) for ns in (w.name_servers or [])],
            "registrant": first(w.get("name", "")),
            "org": first(w.get("org", "")),
            "country": first(w.get("country", "")),
            "status": [str(s) for s in (w.status or [])] if isinstance(w.status, list) else [str(w.status)] if w.status else [],
            "privacy_protected": privacy,
        }
    except Exception as e:
        return {"domain": domain, "found": False, "error": str(e)}
