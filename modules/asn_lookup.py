import httpx
import socket
import re


async def run_asn(domain: str, timeout: int = 10) -> dict:
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"domain": domain, "found": False, "error": f"Could not resolve: {e}"}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(
                f"https://bgp.he.net/ip/{ip}",
                headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
                },
            )

        text = resp.text
        asn_match = re.search(r'(AS\d+)', text)
        asn = asn_match.group(1) if asn_match else ""

        org_match = re.search(r'<title>([^<]+)</title>', text)
        org = org_match.group(1).strip() if org_match else ""

        prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
        unique_prefixes = list(dict.fromkeys(prefixes))[:20]

        return {
            "domain": domain,
            "found": True,
            "ip": ip,
            "asn": asn,
            "org": org,
            "prefixes": unique_prefixes,
        }
    except Exception as e:
        return {"domain": domain, "found": bool(ip), "ip": ip, "asn": "", "org": "", "prefixes": [], "error": str(e)}
