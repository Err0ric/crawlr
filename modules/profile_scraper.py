import httpx
import re
from typing import Optional

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 12

# Patterns for extraction
EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
URL_RE = re.compile(r'https?://[^\s"\'<>]{5,120}')
LOCATION_KEYWORDS = re.compile(
    r'\b(?:based in|located in|living in|from|📍|🌍|🏠)\s*([A-Z][a-zA-Z\s,]{3,40})',
    re.IGNORECASE
)


def _extract_meta(html: str, attr: str) -> str:
    """Extract content from meta tags."""
    m = re.search(
        rf'<meta\s+(?:property|name)="{re.escape(attr)}"\s+content="([^"]*)"',
        html, re.IGNORECASE
    )
    if not m:
        m = re.search(
            rf'<meta\s+content="([^"]*)"\s+(?:property|name)="{re.escape(attr)}"',
            html, re.IGNORECASE
        )
    return m.group(1).strip() if m else ""


def _extract_text_block(html: str, max_len: int = 500) -> str:
    """Extract visible text from bio/about sections."""
    # Try common bio containers
    for pattern in [
        r'class="[^"]*bio[^"]*"[^>]*>([^<]{5,500})',
        r'class="[^"]*about[^"]*"[^>]*>([^<]{5,500})',
        r'class="[^"]*description[^"]*"[^>]*>([^<]{5,500})',
        r'class="[^"]*profile-header-bio[^"]*"[^>]*>([^<]{5,500})',
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:max_len]
    return ""


def _scrape_profile(html: str, url: str) -> dict:
    """Extract structured data from a profile page's HTML."""
    result = {
        "display_name": "",
        "bio": "",
        "emails": [],
        "links": [],
        "location": "",
    }

    # Display name from og:title or title tag
    og_title = _extract_meta(html, "og:title")
    if og_title:
        # Clean common suffixes like "(@user) / X" or "| GitHub"
        name = re.sub(r'\s*[\|/·–—-]\s*\S+$', '', og_title).strip()
        name = re.sub(r'\s*\(@?\w+\)\s*', ' ', name).strip()
        result["display_name"] = name[:100]
    elif not og_title:
        title_m = re.search(r'<title>([^<]{1,200})</title>', html)
        if title_m:
            name = re.sub(r'\s*[\|/·–—-]\s*\S+$', '', title_m.group(1)).strip()
            result["display_name"] = name[:100]

    # Bio from og:description or bio elements
    og_desc = _extract_meta(html, "og:description")
    bio_block = _extract_text_block(html)
    result["bio"] = (bio_block or og_desc)[:500]

    # Emails
    emails = set(EMAIL_RE.findall(html))
    # Filter out common false positives
    emails = {e for e in emails if not any(
        fp in e.lower() for fp in ['@example.', '@sentry.', '@w3.org', 'noreply', 'webpack']
    )}
    result["emails"] = sorted(emails)[:5]

    # Linked URLs (from href attributes, filtering noise)
    href_urls = re.findall(r'href="(https?://[^"]{5,120})"', html)
    seen = set()
    external_links = []
    for u in href_urls:
        u_lower = u.lower()
        # Skip same-site links, assets, trackers
        if any(skip in u_lower for skip in [
            'cdn.', 'static.', 'assets.', 'analytics.', 'google-analytics.',
            'favicon', '.css', '.js', '.png', '.jpg', '.svg', 'javascript:',
            'policies', 'terms', 'privacy', 'help.', 'support.',
        ]):
            continue
        domain = re.search(r'https?://([^/]+)', u)
        if domain and domain.group(1) not in seen:
            seen.add(domain.group(1))
            external_links.append(u)
        if len(external_links) >= 8:
            break
    result["links"] = external_links

    # Location
    loc_m = LOCATION_KEYWORDS.search(html)
    if loc_m:
        result["location"] = loc_m.group(1).strip()[:60]
    else:
        # Try og:locale or location meta
        loc_meta = _extract_meta(html, "og:locale")
        if loc_meta:
            result["location"] = loc_meta

    return result


async def scrape_profiles(urls: list[dict], timeout: int = TIMEOUT) -> list[dict]:
    """Scrape a list of profile URLs.

    Each item in urls should be: {"site": "GitHub", "url": "https://..."}
    Returns list of: {"site": ..., "url": ..., "display_name": ..., "bio": ..., ...}
    """
    results = []
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, headers=HEADERS
    ) as client:
        for item in urls[:20]:  # Cap at 20 profiles
            site = item.get("site", "")
            url = item.get("url", "")
            if not url:
                continue
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    results.append({
                        "site": site, "url": url,
                        "error": f"HTTP {resp.status_code}",
                    })
                    continue
                data = _scrape_profile(resp.text, url)
                data["site"] = site
                data["url"] = url
                results.append(data)
            except Exception as e:
                results.append({
                    "site": site, "url": url,
                    "error": str(e)[:100],
                })
    return results
