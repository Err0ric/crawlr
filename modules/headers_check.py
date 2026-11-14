import httpx

from core.errors import error_fields
from core.netguard import safe_fetch
from core.validate import is_ip

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


UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
      "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")


async def run_headers(domain: str, timeout: int = 10) -> dict:
    # https://{domain} first, then https://www.{domain}. Every hop is vetted by safe_fetch.
    urls = [f"https://{domain}"] if is_ip(domain) else [f"https://{domain}", f"https://www.{domain}"]
    last_error: Exception | None = None
    for url in urls:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                got = await safe_fetch(client, url, headers={"User-Agent": UA})
        except Exception as e:
            last_error = e
            continue

        resp = got.response
        headers = dict(resp.headers)
        security = {}
        for header, label in SECURITY_HEADERS.items():
            val = headers.get(header.lower(), "")
            security[label] = {"header": header, "present": bool(val), "value": val[:200]}
        present = sum(1 for s in security.values() if s["present"])

        return {
            "domain": domain,
            "found": True,
            "ip": got.hops[0]["ip"],
            "url": got.url,
            "status_code": resp.status_code,
            "server": headers.get("server", ""),
            "security_headers": security,
            "present": present,
            "total": len(SECURITY_HEADERS),
            "grade": _grade(present, len(SECURITY_HEADERS)),
            "all_headers": {k: v[:200] for k, v in headers.items()},
        }

    return {"domain": domain, "found": False, **error_fields(last_error)}
