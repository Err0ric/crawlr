import httpx
import re
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 15


async def _scrape_bgp_he(asn: int, client: httpx.AsyncClient) -> dict:
    """Scrape bgp.he.net for ASN info, prefixes, and peers."""
    result = {"org": "", "prefixes_v4": [], "prefixes_v6": [], "peers": []}
    try:
        resp = await client.get(
            f"https://bgp.he.net/AS{asn}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return result
        text = resp.text

        # Org name from title
        title_m = re.search(r"<title>([^<]+)</title>", text)
        if title_m:
            raw = title_m.group(1).strip()
            # Title is usually "AS12345 Org Name - bgp.he.net"
            raw = re.sub(r"\s*-\s*bgp\.he\.net$", "", raw)
            raw = re.sub(r"^AS\d+\s*", "", raw)
            result["org"] = raw.strip()

        # IPv4 prefixes
        v4 = re.findall(r"(\d+\.\d+\.\d+\.\d+/\d+)", text)
        result["prefixes_v4"] = list(dict.fromkeys(v4))[:50]

        # IPv6 prefixes
        v6 = re.findall(r"([0-9a-fA-F:]+/\d+)", text)
        v6 = [p for p in v6 if ":" in p]
        result["prefixes_v6"] = list(dict.fromkeys(v6))[:30]

        # Peers - look for links to other ASNs
        peer_matches = re.findall(r'href="/AS(\d+)"[^>]*>AS\d+\s+([^<]{1,80})', text)
        seen = set()
        for asn_num, name in peer_matches:
            if asn_num not in seen and int(asn_num) != asn:
                seen.add(asn_num)
                result["peers"].append({"asn": f"AS{asn_num}", "name": name.strip()})
            if len(result["peers"]) >= 30:
                break
    except Exception:
        pass
    return result


async def _query_rdap(asn: int, client: httpx.AsyncClient) -> dict:
    """Query RDAP for structured ASN data."""
    result = {"org": "", "handle": "", "country": "", "rir": "", "date": "", "ip_ranges": []}
    try:
        resp = await client.get(
            f"https://rdap.arin.net/registry/autnum/{asn}",
            headers={"Accept": "application/rdap+json"},
            follow_redirects=True,
        )
        if resp.status_code != 200:
            # Try RIPE
            resp = await client.get(
                f"https://rdap.db.ripe.net/autnum/{asn}",
                headers={"Accept": "application/rdap+json"},
                follow_redirects=True,
            )
        if resp.status_code != 200:
            return result

        data = resp.json()
        result["handle"] = data.get("handle", "")
        result["name"] = data.get("name", "")

        # Determine RIR from port43 or links
        port43 = data.get("port43", "")
        if "arin" in port43:
            result["rir"] = "ARIN"
        elif "ripe" in port43:
            result["rir"] = "RIPE NCC"
        elif "apnic" in port43:
            result["rir"] = "APNIC"
        elif "lacnic" in port43:
            result["rir"] = "LACNIC"
        elif "afrinic" in port43:
            result["rir"] = "AFRINIC"

        # Org/entity info
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        result["org"] = item[3] or ""
                    if item[0] == "adr" and isinstance(item[3], list):
                        # Country is usually last element
                        for part in item[3]:
                            if isinstance(part, str) and len(part) == 2 and part.isupper():
                                result["country"] = part

        # Events (registration date)
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                result["date"] = event.get("eventDate", "")[:10]
            elif event.get("eventAction") == "last changed" and not result["date"]:
                result["date"] = event.get("eventDate", "")[:10]

    except Exception:
        pass
    return result


async def run_asn_detail(asn_number: int) -> dict:
    """Run full ASN lookup combining bgp.he.net and RDAP."""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        bgp = await _scrape_bgp_he(asn_number, client)
        rdap = await _query_rdap(asn_number, client)

    org = rdap.get("org") or bgp.get("org", "")
    prefixes = bgp["prefixes_v4"] + bgp["prefixes_v6"]

    return {
        "asn": f"AS{asn_number}",
        "asn_number": asn_number,
        "found": True,
        "org": org,
        "name": rdap.get("name", ""),
        "handle": rdap.get("handle", ""),
        "country": rdap.get("country", ""),
        "rir": rdap.get("rir", ""),
        "date_registered": rdap.get("date", ""),
        "total_prefixes": len(prefixes),
        "prefixes_v4": bgp["prefixes_v4"],
        "prefixes_v6": bgp["prefixes_v6"],
        "total_peers": len(bgp["peers"]),
        "peers": bgp["peers"],
    }
