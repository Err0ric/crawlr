import whois


async def run_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        def first(val):
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val) if val else ""

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
        }
    except Exception as e:
        return {"domain": domain, "found": False, "error": str(e)}
