"""
Files a site publishes about itself: security.txt, robots.txt, and the favicon.

Three small requests to the target's web server, each through the outbound guard.
robots.txt often names the paths an owner would rather not have indexed; the favicon
hash lets an investigator find other hosts serving the same icon in Shodan.
"""

import base64
import hashlib
import re

import httpx

from core.errors import error_fields
from core.netguard import BlockedTarget, safe_fetch

UA = "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"
MAX_BYTES = 300_000
INTERESTING = re.compile(r"admin|login|signin|backup|\.bak|\.sql|\.zip|\.env|\.git|config|internal|private|staging|dev\b|test\b|api|graphql|swagger|debug|phpinfo|wp-admin|cgi-bin|dashboard|console|upload|secret|token|\.json|\.xml|\.log", re.I)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, returned as a signed int (the form Shodan indexes)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed
    rounded = len(data) & ~3
    for i in range(0, rounded, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h


def favicon_hash(data: bytes) -> int:
    # Shodan hashes the base64 text with a newline every 76 characters, as encodebytes writes it.
    return murmur3_32(base64.encodebytes(data))


def parse_security_txt(text: str) -> dict:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k in ("contact", "expires", "policy", "encryption", "acknowledgments", "hiring", "canonical", "preferred-languages"):
            fields.setdefault(k, []).append(v.strip()[:300])
    return fields


def parse_robots(text: str) -> dict:
    disallow, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        k, sep, v = line.partition(":")
        v = v.strip()
        if not sep or not v:
            continue
        if k.strip().lower() == "disallow" and v != "/" and v not in disallow:
            disallow.append(v[:200])
        elif k.strip().lower() == "sitemap" and v not in sitemaps:
            sitemaps.append(v[:300])
    return {
        "disallow_count": len(disallow),
        "interesting": [p for p in disallow if INTERESTING.search(p)][:40],
        "disallow": disallow[:80],
        "sitemaps": sitemaps[:10],
    }


async def _get(client: httpx.AsyncClient, url: str):
    got = await safe_fetch(client, url, headers={"User-Agent": UA}, max_redirects=4)
    return got.response


async def run_wellknown(domain: str) -> dict:
    out: dict = {"domain": domain, "found": False, "security_txt": None, "robots": None, "favicon": None}
    base = f"https://{domain}"
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            for path in ("/.well-known/security.txt", "/security.txt"):
                r = await _get(client, base + path)
                body = r.text[:MAX_BYTES] if r.status_code == 200 else ""
                if body and "contact:" in body.lower() and "<html" not in body[:300].lower():
                    out["security_txt"] = {"url": base + path, **parse_security_txt(body)}
                    break
            r = await _get(client, base + "/robots.txt")
            if r.status_code == 200 and "<html" not in r.text[:300].lower():
                out["robots"] = parse_robots(r.text[:MAX_BYTES])
            r = await _get(client, base + "/favicon.ico")
            data = r.content[:MAX_BYTES] if r.status_code == 200 else b""
            if data and not data[:200].lstrip().lower().startswith((b"<!doctype", b"<html")):
                h = favicon_hash(data)
                out["favicon"] = {
                    "hash": h, "md5": hashlib.md5(data).hexdigest(), "bytes": len(data),
                    "shodan_query": f"http.favicon.hash:{h}",
                }
        except (BlockedTarget, httpx.HTTPError, LookupError, OSError) as e:
            if not (out["security_txt"] or out["robots"] or out["favicon"]):
                return {**out, **error_fields(e)}
    out["found"] = bool(out["security_txt"] or out["robots"] or out["favicon"])
    return out
