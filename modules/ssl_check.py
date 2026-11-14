import asyncio
import socket
import ssl
from datetime import datetime, timezone

from core.errors import error_fields
from core.validate import is_ip
from modules.resolver import resolve_public_ip


def _fetch_cert(ip: str, port: int, hostname: str, timeout: float) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()


async def run_ssl(domain: str, port: int = 443, timeout: int = 5) -> dict:
    try:
        ip = await resolve_public_ip(domain)
    except Exception as e:
        return {"domain": domain, "found": False, **error_fields(e)}

    # SNI is the domain, then www.{domain}. An IP target has no alternate name to try.
    names = [domain] if is_ip(domain) else [domain, f"www.{domain}"]
    last_error: Exception | None = None
    for hostname in names:
        try:
            cert = await asyncio.to_thread(_fetch_cert, ip, port, hostname, timeout)
        except Exception as e:
            last_error = e
            continue

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

        days_left = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days

        return {
            "domain": domain,
            "found": True,
            "ip": ip,
            "common_name": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "not_before": not_before,
            "not_after": not_after,
            "days_left": days_left,
            "sans": sans[:50],
            "serial": cert.get("serialNumber", ""),
            "version": cert.get("version", ""),
        }

    return {"domain": domain, "found": False, **error_fields(last_error)}
