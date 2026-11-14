import re
from urllib.parse import urlsplit

import httpx

# Archived URLs worth a second look: admin and login pages, backups, config and data files,
# API descriptions, debug pages. Matched against the path of URLs the Wayback Machine has seen.
PATH_GROUPS = {
    "Admin and login": re.compile(r"/(wp-admin|admin|administrator|login|signin|dashboard|console|manage|cpanel|phpmyadmin)(/|\.|$)", re.I),
    "Backups and dumps": re.compile(r"\.(bak|old|backup|sql|dump|tar|tar\.gz|tgz|zip|7z|rar)($|\?)|/backup", re.I),
    "Config and secrets": re.compile(r"\.(env|ini|conf|config|yml|yaml|pem|key|htpasswd)($|\?)|/\.git/|/\.svn/|/config\.", re.I),
    "APIs": re.compile(r"/(api|graphql|swagger|openapi|v[0-9]+)(/|\.|$)|swagger\.json|api-docs", re.I),
    "Debug and internal": re.compile(r"/(debug|phpinfo|server-status|internal|staging|test|dev|trace)(/|\.|$)|phpinfo\.php", re.I),
    "Data files": re.compile(r"\.(csv|xls|xlsx|json|xml|log|txt)($|\?)", re.I),
}
STATIC = re.compile(r"\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|eot|mp4|webp|map)($|\?)", re.I)


def interesting_paths(urls: list[str], limit_per_group: int = 12) -> dict[str, list[str]]:
    """Group archived URLs by why they might matter. Pure function."""
    out: dict[str, list[str]] = {}
    seen: set[str] = set()
    for u in urls:
        parts = urlsplit(u if "://" in u else "http://" + u)
        path = parts.path or "/"
        if path in seen or STATIC.search(path) or path in ("/", "/robots.txt", "/sitemap.xml", "/favicon.ico"):
            continue
        for group, rx in PATH_GROUPS.items():
            if rx.search(path):
                bucket = out.setdefault(group, [])
                if len(bucket) < limit_per_group:
                    bucket.append(f"{parts.netloc.split(':')[0]}{path}"[:160])
                    seen.add(path)
                break
    return out


async def run_wayback(domain: str) -> dict:
    """Query Wayback Machine for snapshot history of a domain."""
    result = {
        "domain": domain,
        "found": False,
        "most_recent_snapshot": None,
        "total_snapshots": 0,
        "snapshot_history": [],
        "interesting_paths": {},
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

        # 3. Archived URLs under the domain, mined for paths worth a look
        try:
            resp = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": f"{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": 4000},
                timeout=20,
            )
            if resp.status_code == 200:
                rows = resp.json()
                result["interesting_paths"] = interesting_paths([r[0] for r in rows[1:] if r])
                if result["interesting_paths"]:
                    result["found"] = True
        except Exception:
            pass

    return result
