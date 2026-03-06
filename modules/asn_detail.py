import httpx
import re

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


async def _query_rdap(asn: int, client: httpx.AsyncClient) -> dict:
    """Query RDAP for structured ASN data."""
    result = {"org": "", "handle": "", "country": "", "rir": "", "date": "", "name": ""}
    for url in [
        f"https://rdap.arin.net/registry/autnum/{asn}",
        f"https://rdap.db.ripe.net/autnum/{asn}",
    ]:
        try:
            resp = await client.get(url, headers={"Accept": "application/rdap+json"})
            if resp.status_code != 200:
                continue
            data = resp.json()
            result["handle"] = data.get("handle", "")
            result["name"] = data.get("name", "")

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

            for entity in data.get("entities", []):
                vcard = entity.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            result["org"] = item[3] or ""
                        if item[0] == "adr" and isinstance(item[3], list):
                            for part in item[3]:
                                if isinstance(part, str) and len(part) == 2 and part.isupper():
                                    result["country"] = part

            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    result["date"] = event.get("eventDate", "")[:10]
                elif event.get("eventAction") == "last changed" and not result["date"]:
                    result["date"] = event.get("eventDate", "")[:10]

            break  # Got data, stop trying other RDAP servers
        except Exception:
            continue
    return result


async def _query_ripe_prefixes(asn: int, client: httpx.AsyncClient) -> dict:
    """Query RIPE stat for announced prefixes."""
    prefixes_v4 = []
    prefixes_v6 = []
    try:
        resp = await client.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("prefixes", [])
            for p in data:
                prefix = p.get("prefix", "")
                if ":" in prefix:
                    prefixes_v6.append(prefix)
                elif "." in prefix:
                    prefixes_v4.append(prefix)
    except Exception:
        pass
    return {"prefixes_v4": prefixes_v4[:50], "prefixes_v6": prefixes_v6[:30]}


async def _query_ripe_neighbours(asn: int, client: httpx.AsyncClient) -> list:
    """Query RIPE stat for ASN neighbours/peers."""
    peers = []
    try:
        resp = await client.get(
            f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}"
        )
        if resp.status_code == 200:
            neighbours = resp.json().get("data", {}).get("neighbours", [])
            for n in neighbours[:30]:
                peer_asn = n.get("asn", "")
                power = n.get("power", 0)
                ntype = n.get("type", "")
                type_label = {"left": "upstream", "right": "downstream", "uncertain": "peer"}.get(ntype, ntype)
                peers.append({
                    "asn": f"AS{peer_asn}",
                    "name": type_label,
                })
    except Exception:
        pass
    return peers


async def _scrape_bgp_he_fallback(asn: int, client: httpx.AsyncClient) -> dict:
    """Fallback: scrape bgp.he.net for ASN info."""
    result = {"org": "", "prefixes_v4": [], "prefixes_v6": [], "peers": []}
    try:
        resp = await client.get(f"https://bgp.he.net/AS{asn}", headers=HEADERS)
        if resp.status_code != 200:
            return result
        text = resp.text

        title_m = re.search(r"<title>([^<]+)</title>", text)
        if title_m:
            raw = title_m.group(1).strip()
            raw = re.sub(r"\s*-\s*bgp\.he\.net$", "", raw)
            raw = re.sub(r"^AS\d+\s*", "", raw)
            result["org"] = raw.strip()

        v4 = re.findall(r"(\d+\.\d+\.\d+\.\d+/\d+)", text)
        result["prefixes_v4"] = list(dict.fromkeys(v4))[:50]

        v6 = re.findall(r"([0-9a-fA-F:]+/\d+)", text)
        v6 = [p for p in v6 if ":" in p]
        result["prefixes_v6"] = list(dict.fromkeys(v6))[:30]

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


async def run_asn_detail(asn_number: int) -> dict:
    """Run full ASN lookup combining RDAP, RIPE stat, and bgp.he.net fallback."""
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        rdap = await _query_rdap(asn_number, client)
        prefix_data = await _query_ripe_prefixes(asn_number, client)
        peers = await _query_ripe_neighbours(asn_number, client)

        # If RIPE returned no prefixes, fall back to bgp.he.net
        if not prefix_data["prefixes_v4"] and not prefix_data["prefixes_v6"]:
            bgp = await _scrape_bgp_he_fallback(asn_number, client)
            prefix_data["prefixes_v4"] = bgp["prefixes_v4"]
            prefix_data["prefixes_v6"] = bgp["prefixes_v6"]
            if not peers:
                peers = bgp["peers"]
            if not rdap.get("org"):
                rdap["org"] = bgp["org"]

    org = rdap.get("org", "")
    prefixes = prefix_data["prefixes_v4"] + prefix_data["prefixes_v6"]

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
        "prefixes_v4": prefix_data["prefixes_v4"],
        "prefixes_v6": prefix_data["prefixes_v6"],
        "total_peers": len(peers),
        "peers": peers,
    }
