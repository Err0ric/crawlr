import httpx
from modules.resolver import resolve_domain

SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Content-Type-Options": "X-CTO",
    "X-Frame-Options": "XFO",
    "X-XSS-Protection": "X-XSS",
    "Referrer-Policy": "Referrer",
    "Permissions-Policy": "Permissions",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
    "Cross-Origin-Embedder-Policy": "COEP",
}


def _grade(present: int, total: int) -> str:
    ratio = present / total if total else 0
    if ratio >= 0.8:
        return "A"
    if ratio >= 0.6:
        return "B"
    if ratio >= 0.4:
        return "C"
    return "F"


async def run_headers(domain: str, timeout: int = 10) -> dict:
    try:
        ip = resolve_domain(domain)
    except Exception as e:
        return {"domain": domain, "found": False, "error": f"Could not resolve: {e}"}

    # Try https://{domain} first, fall back to https://www.{domain}
    last_error = None
    for url in [f"https://{domain}", f"https://www.{domain}"]:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                })

            headers = dict(resp.headers)
            server = headers.get("server", "")

            security = {}
            for header, label in SECURITY_HEADERS.items():
                val = headers.get(header.lower(), "")
                security[label] = {"header": header, "present": bool(val), "value": val[:200]}

            present = sum(1 for s in security.values() if s["present"])
            grade = _grade(present, len(SECURITY_HEADERS))

            return {
                "domain": domain,
                "found": True,
                "ip": ip,
                "url": str(resp.url),
                "status_code": resp.status_code,
                "server": server,
                "security_headers": security,
                "present": present,
                "total": len(SECURITY_HEADERS),
                "grade": grade,
                "all_headers": {k: v[:200] for k, v in headers.items()},
            }
        except Exception as e:
            last_error = e
            continue

    return {"domain": domain, "found": False, "error": str(last_error)}
