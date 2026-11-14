"""
Platform check: is there a profile for this handle on the big social sites?

An HTTP status cannot answer that. These sites send 200 for any name, or a login page, or
the same error page for "no such account" and "we are not going to tell you". So each
platform has a rule in RULES that reads the response body, and every result lands in one of
five states:

  found       a marker in the page names this handle (title, og:url, embedded JSON)
  not_found   the site's own "no such account" page, and a known account was readable from
              this server at the same moment (see the canary note below)
  blocked     a login wall, a refusal (401, 403, 429, LinkedIn's 999) or a degraded page
  unknown     anything else: no marker either way, a timeout, an upstream error
  manual      never checked by the server, shown as a link to open by hand

`found` in a row is true only for state "found" and false only for "not_found". A bare 200
is never "found", and a wall is never "not_found".

Canary: some sites serve their "not available" page for real profiles too when they do not
like the request. Before a not-found page is believed, the platform's own official account
is fetched the same way. If that cannot be read either, the answer is "blocked".

What each site returned to an anonymous server-side GET on 2026-11-14 is recorded in
tests/fixtures/platform/ and the rules are written against those bodies. When a site changes
its page, record a new fixture and adjust that platform's entry; nothing else needs to move.
"""

import asyncio
import html
import json
import os
import re
import time
from collections import OrderedDict

import httpx

from core.errors import MESSAGES, classify

# A browser navigation, as a browser sends it. Without the Sec-Fetch headers Facebook answers
# 400 and Instagram serves its error page for every profile.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}
TIMEOUT = 12
MAX_BODY = 2_000_000          # profile pages run to 850 KB; the markers are all inside that

CACHE_TTL = int(os.getenv("PLATFORM_CHECK_CACHE_TTL", str(24 * 3600)))
CACHE_MAX = 2000
CANARY_TTL_OK = 600           # a readable canary is trusted for ten minutes
CANARY_TTL_FAIL = 120         # a failed one is retried sooner

REFUSED = (401, 403, 429, 999)
LOGIN_PATH = re.compile(r"/(?:accounts/)?login(?:[/?.]|$)|/checkpoint/|/challenge/|/authwall|/i/flow/login", re.I)

# --------------------------------------------------------------------------------------
# Rules. In every pattern `{u}` is the handle (regex-escaped, matched without regard to case).
#
#   found       [(field, pattern, evidence)]  any match means the profile exists
#   not_found   [(field, pattern, evidence)]  the site's own "no such account" page
#   wall        [(field, pattern, evidence)]  login or consent wall -> blocked
#   ambiguous   [(field, pattern, evidence)]  a page that proves nothing -> unknown
#   name        (field, pattern)              group 1 is the display name, read only when found
#   canary      an account that certainly exists, used to confirm a not-found page
#
# Fields: title, og:title, og:url, canonical, al:ios:url (all html-unescaped), body (raw),
# final_url, and status (the number as text).
# --------------------------------------------------------------------------------------
RULES = [
    {
        "name": "Facebook",
        "url": "https://www.facebook.com/{username}",
        "sherlock": ("facebook",),
        "found": [
            ("title", r"\(@{u}\)\s*[•|]\s*Facebook", "profile page names @{username}"),
            ("og:url", r"^https?://(?:www\.)?facebook\.com/{u}/?$", "profile page links to itself"),
            ("body", r'"userVanity":"{u}"', "profile data names @{username}"),
        ],
        "name_from": ("og:title", r"^(.{1,100})$"),
        "wall": [
            ("title", r"^(?:log in|log into) (?:to )?facebook|^facebook\s*[-\u2013]\s*log in", "login wall"),
            ("body", r"<h1>Sorry, something went wrong\.</h1>", "Facebook refused the request"),
        ],
        # Facebook sends this page for a handle nobody has and for a profile that is only
        # visible when logged in, so it cannot be read as "not found".
        "ambiguous": [
            ("body", r"This content isn(?:'|\\u2019|’|&#039;)t available right now",
             "Facebook shows the same page for a missing profile and a login-only one"),
        ],
    },
    {
        "name": "Instagram",
        "url": "https://www.instagram.com/{username}/",
        "sherlock": ("instagram",),
        "found": [
            ("og:title", r"\(@{u}\)\s*•\s*Instagram", "profile page names @{username}"),
            ("title", r"\(@{u}\)\s*•\s*Instagram", "profile page names @{username}"),
        ],
        "name_from": ("og:title", r"^(.{1,100}?)\s*\(@"),
        "wall": [
            ("title", r"^login\s*•\s*instagram", "login wall"),
        ],
        "not_found": [
            ("body", r'"page_logging":\{"name":"httpErrorPage"', "Instagram's page-not-available page"),
            ("body", r"Sorry, this page isn(?:'|\\u2019|’|&#039;|&#x27;)t available", "Instagram's page-not-available page"),
        ],
        "canary": "instagram",
    },
    {
        "name": "X",
        "url": "https://x.com/{username}",
        "sherlock": ("x", "twitter"),
        "found": [
            ("og:url", r"^https?://(?:x|twitter)\.com/{u}/?$", "profile page links to itself"),
            ("title", r"\(@{u}\)\s*/\s*X\s*$", "profile page names @{username}"),
            ("og:title", r"\(@{u}\) on X\s*$", "profile page names @{username}"),
        ],
        "name_from": ("og:title", r"^(.{1,100}?)\s*\(@"),
        "wall": [
            ("title", r"^log in to (?:x|twitter)", "login wall"),
        ],
        "not_found": [
            ("title", r"^User Profile Not Found\b", "X says this account doesn't exist"),
            ("body", r"<h\d[^>]*>This account doesn(?:'|’|&#x27;|&#39;)t exist</h\d>", "X says this account doesn't exist"),
        ],
        "canary": "x",
    },
    {
        "name": "Threads",
        "url": "https://www.threads.com/@{username}",
        "sherlock": ("threads",),
        "found": [
            ("og:title", r"\(@{u}\)\s*•\s*Threads", "profile page names @{username}"),
            ("title", r"\(@{u}\)\s*•\s*Threads", "profile page names @{username}"),
            ("al:ios:url", r"^barcelona://user\?username={u}$", "profile page names @{username}"),
        ],
        "name_from": ("og:title", r"^(.{1,100}?)\s*\(@"),
        # Threads sends a handle nobody has to its login page, and may send a real one there
        # too, so the login page stays "blocked" and is never read as "not found".
        "wall": [
            ("title", r"^Threads\s*•\s*Log in", "login wall"),
        ],
    },
    {
        "name": "TikTok",
        "url": "https://www.tiktok.com/@{username}",
        "sherlock": ("tiktok",),
        # The phrase "Couldn't find this account" is in the translation table of every TikTok
        # page, found or not, so it is not a marker. The status code in the page data is.
        "found": [
            ("body", r'"webapp\.user-detail":\{"userInfo":\{"user":\{[^{}]{0,400}?"uniqueId":"{u}"', "profile data names @{username}"),
        ],
        "name_from": ("body", r'"webapp\.user-detail":\{"userInfo":\{"user":\{[^{}]{0,400}?"nickname":"((?:[^"\\]|\\.){1,100})"'),
        "not_found": [
            ("body", r'"webapp\.user-detail":\{"statusCode":10221\b', "TikTok reports no such account"),
        ],
        "canary": "tiktok",
    },
    {
        "name": "LinkedIn",
        "url": "https://www.linkedin.com/in/{username}",
        "sherlock": ("linkedin",),
        # LinkedIn answers anonymous servers with HTTP 999 or its sign-in wall. There is no
        # found or not-found rule on purpose: nothing it sends here proves either.
        "wall": [
            ("title", r"^(?:sign (?:in|up)|linkedin login|join linkedin)\b", "login wall"),
            ("final_url", r"/authwall|/uas/login|/checkpoint/", "login wall"),
        ],
    },
]

# Platforms that can't be reliably checked programmatically: manual link only.
MANUAL_PLATFORMS = [
    {"name": "OnlyFans", "url": "https://onlyfans.com/{username}"},
]

PLATFORMS = RULES   # the old name, kept for anything that imports it

# --------------------------------------------------------------------------------------
# Caches
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[tuple[str, str], tuple[float, dict]]" = OrderedDict()
_canary: dict[str, tuple[float, bool]] = {}


def clear_cache_for_tests() -> None:
    _cache.clear()
    _canary.clear()


def _cache_get(key: tuple[str, str]) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    if time.time() - hit[0] > CACHE_TTL:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return dict(hit[1])


def _cache_put(key: tuple[str, str], row: dict) -> None:
    _cache[key] = (time.time(), dict(row))
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


# --------------------------------------------------------------------------------------
# Reading a page
# --------------------------------------------------------------------------------------
_TITLE = re.compile(r"<title[^>]*>([^<]{0,300})</title>", re.I)
_META = re.compile(r"<meta\s[^>]*>", re.I)
_LINK = re.compile(r"<link\s[^>]*>", re.I)
_ATTR = re.compile(r'([a-zA-Z:_-]+)\s*=\s*"([^"]*)"')
_HEAD_FIELDS = ("og:title", "og:url", "al:ios:url")


def page_fields(status: int, final_url: str, body: str) -> dict:
    """Pull the few fields the rules read out of a response."""
    fields = {"status": str(status), "final_url": final_url or "", "body": body or "", "title": "", "canonical": ""}
    fields.update({k: "" for k in _HEAD_FIELDS})
    m = _TITLE.search(body or "")
    if m:
        fields["title"] = html.unescape(m.group(1)).strip()
    for tag in _META.findall(body or ""):
        attrs = {k.lower(): v for k, v in _ATTR.findall(tag)}
        key = attrs.get("property") or attrs.get("name") or ""
        if key in _HEAD_FIELDS and not fields[key]:
            fields[key] = html.unescape(attrs.get("content", "")).strip()
    for tag in _LINK.findall(body or ""):
        attrs = {k.lower(): v for k, v in _ATTR.findall(tag)}
        if attrs.get("rel", "").lower() == "canonical" and not fields["canonical"]:
            fields["canonical"] = html.unescape(attrs.get("href", "")).strip()
    return fields


def _first(rules: list, fields: dict, username: str):
    """The first (evidence, match) among `rules` that matches, or None."""
    u = re.escape(username)
    for field, pattern, evidence in rules or []:
        m = re.search(pattern.replace("{u}", u), fields.get(field, ""), re.I)
        if m:
            return evidence.replace("{username}", username), m
    return None


def classify_page(rule: dict, username: str, status: int, final_url: str, body: str) -> dict:
    """Decide a state from one response. Pure: no network, so it is tested from fixtures.

    Returns {state, evidence, display_name}. "not_found" here is provisional for platforms
    with a canary; `_check` confirms it.
    """
    fields = page_fields(status, final_url, body)

    hit = _first(rule.get("found"), fields, username)
    if hit and status < 400:
        name = ""
        if rule.get("name_from"):
            field, pattern = rule["name_from"]
            m = re.search(pattern, fields.get(field, ""), re.I)
            name = _clean_name(m.group(1)) if m else ""
        return {"state": "found", "evidence": hit[0], "display_name": name}

    # A redirect that ended on a login page, whatever the body says.
    start_path = re.sub(r"^https?://[^/]+", "", rule["url"].format(username=username))
    end_path = re.sub(r"^https?://[^/]+", "", final_url or "")
    if LOGIN_PATH.search(end_path) and not LOGIN_PATH.search(start_path):
        return {"state": "blocked", "evidence": "login wall", "display_name": ""}
    hit = _first(rule.get("wall"), fields, username)
    if hit:
        return {"state": "blocked", "evidence": hit[0], "display_name": ""}
    if status in REFUSED:
        return {"state": "blocked", "evidence": f"the site refused the request (HTTP {status})", "display_name": ""}

    hit = _first(rule.get("not_found"), fields, username)
    if hit:
        return {"state": "not_found", "evidence": hit[0], "display_name": ""}
    hit = _first(rule.get("ambiguous"), fields, username)
    if hit:
        return {"state": "unknown", "evidence": hit[0], "display_name": ""}

    if status >= 500:
        return {"state": "unknown", "evidence": f"the site returned an error (HTTP {status})", "display_name": "", "error_code": "upstream"}
    if not (body or "").strip():
        return {"state": "unknown", "evidence": f"empty response (HTTP {status})", "display_name": ""}
    return {"state": "unknown", "evidence": f"no profile marker in the page (HTTP {status})", "display_name": ""}


def _clean_name(raw: str) -> str:
    name = raw
    if "\\" in name:                      # a JSON string literal from embedded page data
        try:
            name = str(json.loads(f'"{raw}"'))
        except ValueError:
            pass
    return re.sub(r"\s+", " ", html.unescape(name)).strip()[:100]


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[int, str, str]:
    """GET `url` and return (status, final url, body up to MAX_BODY). The hosts are fixed
    platform hosts and the handle has been through core.validate, so this is not a fetch of
    a user-supplied URL."""
    async with client.stream("GET", url, headers=HEADERS) as resp:
        chunks, size = [], 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BODY:
                break
        body = b"".join(chunks)[:MAX_BODY].decode(resp.encoding or "utf-8", errors="replace")
        return resp.status_code, str(resp.url), body


async def _fetch_state(client: httpx.AsyncClient, rule: dict, username: str, timeout: float) -> dict:
    url = rule["url"].format(username=username)
    try:
        status, final_url, body = await asyncio.wait_for(_fetch(client, url), timeout=timeout)
    except Exception as e:  # noqa: BLE001 - every failure becomes an "unknown" row with a code
        code = classify(e)
        return {"state": "unknown", "evidence": MESSAGES.get(code, MESSAGES["unknown"]), "display_name": "", "error_code": code}
    return classify_page(rule, username, status, final_url, body)


async def _canary_ok(client: httpx.AsyncClient, rule: dict, timeout: float) -> bool:
    """Can this server read a profile that certainly exists on this platform right now?"""
    name = rule["name"]
    hit = _canary.get(name)
    if hit and time.time() - hit[0] < (CANARY_TTL_OK if hit[1] else CANARY_TTL_FAIL):
        return hit[1]
    ok = (await _fetch_state(client, rule, rule["canary"], timeout))["state"] == "found"
    _canary[name] = (time.time(), ok)
    return ok


def _row(rule: dict, username: str, verdict: dict) -> dict:
    state = verdict["state"]
    row = {
        "platform": rule["name"],
        "url": rule["url"].format(username=username),
        "state": state,
        "found": True if state == "found" else False if state == "not_found" else None,
        "evidence": verdict.get("evidence", ""),
        "display_name": verdict.get("display_name", "") if state == "found" else "",
        "public_url": True,
    }
    if verdict.get("error_code"):
        row["error_code"] = verdict["error_code"]
    return row


async def _check(client: httpx.AsyncClient, rule: dict, username: str, timeout: float) -> dict:
    key = (rule["name"], username.lower())
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "url": rule["url"].format(username=username)}

    verdict = await _fetch_state(client, rule, username, timeout)
    if verdict["state"] == "not_found" and rule.get("canary"):
        if username.lower() == rule["canary"].lower() or not await _canary_ok(client, rule, timeout):
            verdict = {"state": "blocked", "display_name": "",
                       "evidence": f"{rule['name']} is showing its not-found page for every profile from this server"}

    row = _row(rule, username, verdict)
    if row["state"] in ("found", "not_found"):
        _cache_put(key, row)
    return row


async def run_platform_check(
    username: str,
    sherlock_sites: list[str] | None = None,
    timeout: int = TIMEOUT,
) -> dict:
    # Sites another tool already covered (lowercase) are skipped.
    covered = {s.strip().lower() for s in sherlock_sites or []}
    rules = [r for r in RULES if not covered.intersection(r["sherlock"])]

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
        results = list(await asyncio.gather(*(_check(client, r, username, timeout) for r in rules)))

    # Append manual-check-only platforms
    for plat in MANUAL_PLATFORMS:
        results.append({
            "platform": plat["name"],
            "url": plat["url"].format(username=username),
            "state": "manual",
            "found": None,  # None = manual check required
            "evidence": "not checked automatically, open the link to look",
            "display_name": "",
            "public_url": True,
            "manual": True,
        })

    return {
        "username": username,
        "total": sum(1 for r in results if r["state"] == "found"),
        "checked": len([r for r in results if not r.get("manual")]),
        "results": results,
    }
