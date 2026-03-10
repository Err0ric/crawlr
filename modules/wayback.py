import httpx


async def run_wayback(domain: str) -> dict:
    """Query Wayback Machine for snapshot history of a domain."""
    result = {
        "domain": domain,
        "found": False,
        "most_recent_snapshot": None,
        "total_snapshots": 0,
        "snapshot_history": [],
    }

    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # 1. Most recent snapshot
        try:
            resp = await client.get(
                "https://archive.org/wayback/available",
                params={"url": domain},
            )
            if resp.status_code == 200:
                data = resp.json()
                snap = (
                    data.get("archived_snapshots", {})
                    .get("closest", {})
                )
                if snap and snap.get("available"):
                    result["most_recent_snapshot"] = {
                        "url": snap.get("url", ""),
                        "timestamp": snap.get("timestamp", ""),
                    }
                    result["found"] = True
        except Exception:
            pass

        # 2. CDX API for snapshot history
        try:
            resp = await client.get(
                "http://web.archive.org/cdx/search/cdx",
                params={
                    "url": domain,
                    "output": "json",
                    "limit": 10,
                    "fl": "timestamp,statuscode",
                    "filter": "statuscode:200",
                    "collapse": "timestamp:6",
                },
            )
            if resp.status_code == 200:
                rows = resp.json()
                # First row is the header ["timestamp", "statuscode"]
                if len(rows) > 1:
                    result["found"] = True
                    for row in rows[1:]:
                        ts = row[0]
                        result["snapshot_history"].append({
                            "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts,
                            "url": f"https://web.archive.org/web/{ts}/{domain}",
                        })
                    result["total_snapshots"] = len(rows) - 1
        except Exception:
            pass

    return result
