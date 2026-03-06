import ssl
import socket
from datetime import datetime, timezone


async def run_ssl(domain: str, port: int = 443, timeout: int = 5) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        sans = []
        for entry in cert.get("subjectAltName", []):
            if entry[0] == "DNS":
                sans.append(entry[1])

        days_left = None
        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days

        return {
            "domain": domain,
            "found": True,
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
    except Exception as e:
        return {"domain": domain, "found": False, "error": str(e)}
