import json
import re

import httpx
from bs4 import BeautifulSoup

from core.boilerplate import clean_bio

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


def _json_text(raw: str) -> str:
    """Decode the inside of a JSON string literal (\\n, \\uXXXX); fall back to the raw text."""
    try:
        return str(json.loads(f'"{raw}"'))
    except ValueError:
        return raw


def _filter_bio(profile: dict, username: str) -> dict:
    """Blank a bio that is platform boilerplate and say so, so the UI can tell "no bio" from
    "the platform's own text". The display name is left alone."""
    raw = profile.get("bio") or ""
    cleaned = clean_bio(raw, profile.get("platform", ""), username, profile.get("display_name", ""))
    profile["bio"] = cleaned[:300]
    if raw.strip() and not cleaned:
        profile["bio_boilerplate"] = True
    return profile


async def _scrape_reddit(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers={"User-Agent": "Crawlr/0.1"},
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {})
        sub = d.get("subreddit", {})
        title = sub.get("title", "")
        bio = sub.get("public_description", "")
        if not title and not bio:
            return None
        return {
            "platform": "Reddit",
            "display_name": title,
            "bio": bio,
            "url": f"https://reddit.com/u/{username}",
        }
    except Exception:
        return None


async def _scrape_tiktok(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://www.tiktok.com/@{username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        nickname_m = re.search(r'"nickname":"([^"]+)"', r.text)
        # "signature" is the bio the person wrote. "desc" is TikTok's share text (follower
        # counts plus a slogan), kept only as a fallback; the boilerplate filter cleans it.
        sig_m = re.search(r'"signature":"((?:[^"\\]|\\.){1,500})"', r.text)
        desc_m = re.search(r'"desc":"((?:[^"\\]|\\.){1,300})"', r.text)
        nickname = nickname_m.group(1) if nickname_m else ""
        desc = _json_text(sig_m.group(1)) if sig_m else ""
        if not desc.strip():
            desc = _json_text(desc_m.group(1)) if desc_m else ""
        if not nickname and not desc:
            return None
        return {
            "platform": "TikTok",
            "display_name": nickname,
            "bio": desc,
            "url": f"https://tiktok.com/@{username}",
        }
    except Exception:
        return None


async def _scrape_youtube(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://www.youtube.com/@{username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        name = og_title["content"] if og_title and og_title.get("content") else ""
        desc = og_desc["content"] if og_desc and og_desc.get("content") else ""
        if not name and not desc:
            return None
        return {
            "platform": "YouTube",
            "display_name": name,
            "bio": desc[:300],
            "url": f"https://youtube.com/@{username}",
        }
    except Exception:
        return None


async def _scrape_twitch(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://www.twitch.tv/{username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        raw_title = og_title["content"] if og_title and og_title.get("content") else ""
        desc = og_desc["content"] if og_desc and og_desc.get("content") else ""
        # og:title is usually "Name - Twitch"
        name = raw_title.replace(" - Twitch", "") if raw_title else ""
        # Detect generic Twitch page (user doesn't exist)
        if not name or name.lower() == "twitch" or "world's leading" in desc.lower():
            return None
        return {
            "platform": "Twitch",
            "display_name": name,
            "bio": desc[:300],
            "url": f"https://twitch.tv/{username}",
        }
    except Exception:
        return None


async def _scrape_onlyfans(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://onlyfans.com/{username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        name = og_title["content"] if og_title and og_title.get("content") else ""
        desc = og_desc["content"] if og_desc and og_desc.get("content") else ""
        # Filter generic / not-found pages
        if not name or name.lower() == "onlyfans" or "onlyfans" == name.strip().lower():
            return None
        return {
            "platform": "OnlyFans",
            "display_name": name,
            "bio": desc[:300],
            "url": f"https://onlyfans.com/{username}",
        }
    except Exception:
        return None


async def _scrape_patreon(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://www.patreon.com/{username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        raw_title = og_title["content"] if og_title and og_title.get("content") else ""
        desc = og_desc["content"] if og_desc and og_desc.get("content") else ""
        # Title is usually "Name | creating ... | Patreon" or "Name is creating ... | Patreon"
        name = re.split(r"\s*[\|]", raw_title)[0].strip() if raw_title else ""
        if not name or name.lower() == "patreon" or "best platform for creators" in desc.lower():
            return None
        return {
            "platform": "Patreon",
            "display_name": name,
            "bio": desc[:300],
            "url": f"https://patreon.com/{username}",
        }
    except Exception:
        return None


async def _scrape_cashapp(username: str, client: httpx.AsyncClient) -> dict | None:
    try:
        r = await client.get(
            f"https://cash.app/${username}",
            headers=HEADERS,
            follow_redirects=True,
        )
        if r.status_code != 200:
            return None
        soup = BeautifulSoup(r.text, "html.parser")
        og_title = soup.find("meta", property="og:title")
        og_desc = soup.find("meta", property="og:description")
        name = og_title["content"] if og_title and og_title.get("content") else ""
        desc = og_desc["content"] if og_desc and og_desc.get("content") else ""
        if not name or "cash app" in name.lower() or "send and receive money" in desc.lower():
            return None
        return {
            "platform": "CashApp",
            "display_name": name,
            "bio": desc[:300],
            "url": f"https://cash.app/${username}",
        }
    except Exception:
        return None


SCRAPERS = {
    "Reddit": _scrape_reddit,
    "TikTok": _scrape_tiktok,
    "YouTube": _scrape_youtube,
    "Twitch": _scrape_twitch,
    "OnlyFans": _scrape_onlyfans,
    "Patreon": _scrape_patreon,
    "CashApp": _scrape_cashapp,
}

# Sherlock site names that map to our scrapers
SITE_MAP = {
    "Reddit": "Reddit",
    "TikTok": "TikTok",
    "YouTube": "YouTube",
    "Twitch": "Twitch",
    "OnlyFans": "OnlyFans",
    "Patreon": "Patreon",
    "Cash App": "CashApp",
}


async def run_enricher(username: str, sherlock_sites: list[str] | None = None) -> dict:
    """Scrape profile data from platforms found by Sherlock."""
    # Determine which platforms to scrape
    targets = set()
    if sherlock_sites:
        for site in sherlock_sites:
            for key, scraper_name in SITE_MAP.items():
                if key.lower() in site.lower():
                    targets.add(scraper_name)
    else:
        targets = set(SCRAPERS.keys())

    profiles = []
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for platform in targets:
            scraper = SCRAPERS.get(platform)
            if scraper:
                result = await scraper(username, client)
                if result:
                    profiles.append(_filter_bio(result, username))

    return {
        "username": username,
        "total": len(profiles),
        "profiles": profiles,
    }
