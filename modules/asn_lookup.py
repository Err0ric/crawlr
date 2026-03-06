import httpx
import re
from modules.resolver import resolve_domain

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


async def run_asn(domain: str) -> dict:
    try:
        ip = resolve_domain(domain)
    except Exception as e:
        return {"domain": domain, "found": False, "error": f"Could not resolve: {e}"}

    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        # Step 1: Get ASN for this IP via RIPE stat
        asn = ""
        org = ""
        try:
            resp = await client.get(
                f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                asns = data.get("asns", [])
                if asns:
                    asn = f"AS{asns[0]}"
                prefix = data.get("prefix", "")
        except Exception:
            pass

        # Step 2: Get org info from RDAP if we have an ASN
        if asn:
            asn_num = asn.replace("AS", "")
            try:
                resp = await client.get(
                    f"https://rdap.arin.net/registry/autnum/{asn_num}",
                    headers={"Accept": "application/rdap+json"},
                )
                if resp.status_code == 200:
                    rdap = resp.json()
                    org = rdap.get("name", "")
                    if not org:
                        for entity in rdap.get("entities", []):
                            vcard = entity.get("vcardArray", [None, []])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        org = item[3] or ""
                                        break
                            if org:
                                break
            except Exception:
                pass

        # Step 3: Get prefixes from RIPE stat
        prefixes = []
        if asn:
            try:
                resp = await client.get(
                    f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
                )
                if resp.status_code == 200:
                    prefix_data = resp.json().get("data", {}).get("prefixes", [])
                    prefixes = [p["prefix"] for p in prefix_data if "." in p.get("prefix", "")][:20]
            except Exception:
                pass

        # Fallback: bgp.he.net scrape if we still have no ASN
        if not asn:
            try:
                resp = await client.get(f"https://bgp.he.net/ip/{ip}", headers=HEADERS)
                text = resp.text
                asn_match = re.search(r'(AS\d+)', text)
                asn = asn_match.group(1) if asn_match else ""
                org_match = re.search(r'<title>([^<]+)</title>', text)
                org = org_match.group(1).strip() if org_match else ""
                if not prefixes:
                    found_prefixes = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', text)
                    prefixes = list(dict.fromkeys(found_prefixes))[:20]
            except Exception:
                pass

    return {
        "domain": domain,
        "found": bool(asn),
        "ip": ip,
        "asn": asn,
        "org": org,
        "prefixes": prefixes,
    }
