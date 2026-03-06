import httpx

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10

PLATFORMS = [
    {"name": "Facebook", "url": "https://www.facebook.com/{username}", "sherlock": "Facebook"},
    {"name": "Instagram", "url": "https://www.instagram.com/{username}/", "sherlock": "Instagram"},
    {"name": "Twitter", "url": "https://twitter.com/{username}", "sherlock": "Twitter"},
    {"name": "X", "url": "https://x.com/{username}", "sherlock": "X"},
    {"name": "LinkedIn", "url": "https://www.linkedin.com/in/{username}", "sherlock": "LinkedIn"},
    {"name": "Threads", "url": "https://www.threads.net/@{username}", "sherlock": "Threads"},
]

# Platforms that can't be reliably checked programmatically — manual link only
MANUAL_PLATFORMS = [
    {"name": "OnlyFans", "url": "https://onlyfans.com/{username}"},
]


async def run_platform_check(
    username: str,
    sherlock_sites: list[str] | None = None,
    timeout: int = TIMEOUT,
) -> dict:
    # Build set of Sherlock-covered sites (lowercase) to skip
    covered = set()
    if sherlock_sites:
        covered = {s.lower() for s in sherlock_sites}

    results = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for plat in PLATFORMS:
            # Skip if Sherlock already found/checked this platform
            if plat["sherlock"].lower() in covered:
                continue

            url = plat["url"].format(username=username)
            try:
                resp = await client.head(url, headers=HEADERS)
                found = resp.status_code == 200
            except Exception:
                found = False

            results.append({
                "platform": plat["name"],
                "url": url,
                "found": found,
            })

    # Append manual-check-only platforms
    for plat in MANUAL_PLATFORMS:
        url = plat["url"].format(username=username)
        results.append({
            "platform": plat["name"],
            "url": url,
            "found": None,  # None = manual check required
            "manual": True,
        })

    found_count = sum(1 for r in results if r["found"] is True)
    return {
        "username": username,
        "total": found_count,
        "checked": len([r for r in results if not r.get("manual")]),
        "results": results,
    }
