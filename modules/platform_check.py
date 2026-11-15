"""
Platform check: is there a profile for this handle on the big social sites?

An HTTP status cannot answer that. These sites send 200 for any name, or a login page, or
the same error page for "no such account" and "we are not going to tell you". So each
platform has a rule in RULES that reads the response body, and every result lands in one of
six states:

  found       a marker in the page names this handle (title, og:url, embedded JSON), or the
              site's API returned the account. A profile was read.
  taken       the site's sign-up check says the handle is in use, and nothing was read: there
              is no profile to open and nothing says who holds it (Discord only)
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

Reddit and Discord are not page rules. Each has its own function below (`_reddit`, `_discord`)
and is always part of a run: the username tools list both, but Reddit refuses servers and
Discord has no profile page, so without these rows the investigator could not tell that
Reddit was not checkable or what the Discord answer means.
"""

import asyncio
import html
import json
import os
import re
import time
from collections import OrderedDict

import httpx

from core.boilerplate import clean_bio
from core.errors import MESSAGES, classify
from core.logging import get_logger

log = get_logger(__name__)

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

# Platforms that can't be reliably checked programmatically: manual link only. None today.
# Adult and dating sites are never listed here: they live in modules/adult_check.py, behind
# the opt-in, so an ordinary run never shows one.
MANUAL_PLATFORMS: list[dict] = []

PLATFORMS = RULES   # the old name, kept for anything that imports it

# --------------------------------------------------------------------------------------
# Caches
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[tuple[str, str], tuple[float, dict]]" = OrderedDict()
_canary: dict[str, tuple[float, bool]] = {}


def clear_cache_for_tests() -> None:
    _cache.clear()
    _canary.clear()
    _reddit_token.update(value="", expires=0.0)


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
async def _fetch(client: httpx.AsyncClient, url: str, with_type: bool = False) -> tuple:
    """GET `url` and return (status, final url, body up to MAX_BODY), plus the content type
    when `with_type` is set. The hosts are fixed platform hosts and the handle has been
    through core.validate, so this is not a fetch of a user-supplied URL."""
    async with client.stream("GET", url, headers=HEADERS) as resp:
        chunks, size = [], 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BODY:
                break
        body = b"".join(chunks)[:MAX_BODY].decode(resp.encoding or "utf-8", errors="replace")
        if with_type:
            return resp.status_code, str(resp.url), body, resp.headers.get("content-type", "")
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


# --------------------------------------------------------------------------------------
# Reddit
#
# Keyless (the default): one GET of the public about.json with browser navigation headers.
# Recorded on 2026-11-14 from a home connection and from the production host: HTTP 403 with
# an HTML "blocked by network security" page for an existing account and for a random handle
# alike (tests/fixtures/platform/reddit_blocked.html). So from a server this path usually
# ends in "blocked", and the row says so instead of staying silent.
#
# With REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET set (a free app registered at
# reddit.com/prefs/apps), the documented application-only OAuth flow is used first: a token
# from POST /api/v1/access_token with grant_type=client_credentials and HTTP basic auth, then
# GET oauth.reddit.com/user/{name}/about with the bearer token.
# UNRECORDED: this path could not be exercised without credentials. It is written against
# Reddit's public API documentation and the hand-written fixtures reddit_about_found.json,
# reddit_about_suspended.json, reddit_not_found.json and reddit_token.json, which mirror the
# documented shapes. Every failure on it falls back to the keyless request.
# --------------------------------------------------------------------------------------
REDDIT_URL = "https://www.reddit.com/user/{username}"
REDDIT_ABOUT = "https://www.reddit.com/user/{username}/about.json"
REDDIT_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
REDDIT_OAUTH_ABOUT = "https://oauth.reddit.com/user/{username}/about"
REDDIT_HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
REDDIT_BLOCKED = "Reddit refuses requests from servers, so this could not be checked automatically."
REDDIT_LIMITED = "Reddit's API is rate limiting CrawlR, and Reddit refuses other requests from servers, so this could not be checked."
REDDIT_HINT = "Open the link in a browser. A missing account shows 'nobody on Reddit goes by that name'."
REDDIT_MAX_BODY = 200_000
_reddit_token: dict = {"value": "", "expires": 0.0}


def _reddit_ua() -> str:
    # Reddit asks API clients for a descriptive User-Agent that names the app and its owner.
    return os.getenv("REDDIT_USER_AGENT") or "web:lol.crawlr:v1 (CrawlR, https://crawlr.lol)"


def _reddit_credentials() -> tuple[str, str] | None:
    cid, secret = os.getenv("REDDIT_CLIENT_ID", "").strip(), os.getenv("REDDIT_CLIENT_SECRET", "").strip()
    return (cid, secret) if cid and secret else None


def _reddit_text(value, cap: int) -> str:
    return re.sub(r"\s+", " ", html.unescape(str(value or ""))).strip()[:cap] if isinstance(value, str) else ""


def classify_reddit(username: str, status: int, content_type: str, body: str) -> dict:
    """One Reddit answer (keyless or OAuth) as a verdict. Pure, so it is tested from fixtures.

    found      a JSON body whose data.name is this handle
    not_found  Reddit's JSON 404 body
    blocked    403, 429, a challenge or any HTML where JSON was expected
    unknown    anything else
    """
    data = None
    if (body or "").lstrip()[:1] == "{":
        try:
            data = json.loads(body)
        except ValueError:
            data = None
    if isinstance(data, dict):
        d = data.get("data")
        if status == 200 and isinstance(d, dict) and str(d.get("name") or "").lower() == username.lower():
            sub = d.get("subreddit") if isinstance(d.get("subreddit"), dict) else {}
            name = _reddit_text(sub.get("title"), 100)
            out = {"state": "found", "evidence": "Reddit's own record for this handle", "display_name": name,
                   "bio": clean_bio(_reddit_text(sub.get("public_description"), 300), "reddit", username, name)}
            created = d.get("created_utc")
            if isinstance(created, (int, float)) and not isinstance(created, bool) and 0 < created < time.time() + 86400:
                out["created"] = time.strftime("%Y-%m-%d", time.gmtime(created))
            karma = d.get("total_karma")
            if isinstance(karma, int) and not isinstance(karma, bool) and karma >= 0:
                out["karma"] = karma
            icon = html.unescape(str(d.get("icon_img") or "")).strip()
            if icon.startswith("https://") and len(icon) <= 600:
                out["avatar_url"] = icon
            if d.get("is_suspended") is True:
                out["note"] = "suspended"
                out["evidence"] = "Reddit's own record for this handle, which Reddit marks as suspended"
            return out
        if data.get("error") == 404 or (status == 404 and str(data.get("message") or "").lower() == "not found"):
            return {"state": "not_found", "evidence": "Reddit says nobody goes by that name", "display_name": ""}
    if status in (401, 403, 429) or "html" in (content_type or "").lower() or re.match(r"\s*<", body or ""):
        return {"state": "blocked", "evidence": REDDIT_BLOCKED, "display_name": "", "hint": REDDIT_HINT,
                **({"error_code": "rate_limited"} if status == 429 else {})}
    if status >= 500:
        return {"state": "unknown", "evidence": f"Reddit returned an error (HTTP {status})", "display_name": "", "hint": REDDIT_HINT, "error_code": "upstream"}
    return {"state": "unknown", "evidence": f"Reddit sent an answer CrawlR could not read (HTTP {status})", "display_name": "", "hint": REDDIT_HINT}


async def _reddit_bearer(client: httpx.AsyncClient, creds: tuple[str, str]) -> str:
    """The application-only token, kept until shortly before it expires. "" when it cannot be had."""
    if _reddit_token["value"] and time.time() < _reddit_token["expires"]:
        return _reddit_token["value"]
    resp = await client.post(REDDIT_TOKEN_URL, data={"grant_type": "client_credentials"}, auth=creds,
                             headers={"User-Agent": _reddit_ua(), "Accept": "application/json"})
    if resp.status_code != 200:
        log.warning("reddit token refused", extra={"status": resp.status_code})
        return ""
    data = resp.json()
    token = data.get("access_token") if isinstance(data, dict) else ""
    if not isinstance(token, str) or not token:
        return ""
    try:
        ttl = float(data.get("expires_in") or 0)
    except (TypeError, ValueError):
        ttl = 0.0
    _reddit_token.update(value=token, expires=time.time() + max(0.0, min(ttl, 86400.0) - 60))
    return token


async def _reddit_oauth(client: httpx.AsyncClient, username: str, creds: tuple[str, str]) -> dict | None:
    """The API's verdict when it is found or not_found. Otherwise None (no token), or a dict
    with an empty state and `limited` (the API answered 429): the keyless request is tried."""
    token = await _reddit_bearer(client, creds)
    if not token:
        return None
    resp = await client.get(REDDIT_OAUTH_ABOUT.format(username=username),
                            headers={"User-Agent": _reddit_ua(), "Authorization": f"Bearer {token}", "Accept": "application/json"})
    if resp.status_code == 401:
        _reddit_token.update(value="", expires=0.0)      # a revoked or expired token is not reused
    if resp.status_code in (401, 403, 429) or resp.status_code >= 500:
        log.warning("reddit api did not answer", extra={"status": resp.status_code})
        return {"state": "", "limited": resp.status_code == 429}
    verdict = classify_reddit(username, resp.status_code, resp.headers.get("content-type", ""), resp.text[:REDDIT_MAX_BODY])
    return verdict if verdict["state"] in ("found", "not_found") else {"state": "", "limited": False}


def _reddit_row(username: str, verdict: dict) -> dict:
    row = _row({"name": "Reddit", "url": REDDIT_URL}, username, verdict)
    for k in ("bio", "created", "karma", "avatar_url", "note"):
        if verdict.get(k) not in (None, "") and row["state"] == "found":
            row[k] = verdict[k]
    if verdict.get("hint") and row["state"] in ("blocked", "unknown"):
        row["hint"] = verdict["hint"]
    return row


async def _reddit(client: httpx.AsyncClient, username: str, timeout: float) -> dict:
    if not REDDIT_HANDLE_RE.fullmatch(username):
        return _reddit_row(username, {"state": "not_found", "display_name": "",
                                      "evidence": "Not a valid Reddit name: Reddit names are 3 to 20 letters, digits, underscores or hyphens"})
    key = ("Reddit", username.lower())
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "url": REDDIT_URL.format(username=username)}

    limited = False
    creds = _reddit_credentials()
    verdict = None
    if creds:
        try:
            api = await asyncio.wait_for(_reddit_oauth(client, username, creds), timeout=timeout)
        except Exception as e:  # noqa: BLE001 - any failure here means "try the keyless request"
            log.warning("reddit api failed", extra={"error_code": classify(e)})
            api = None
        if api and api["state"]:
            verdict = api
        elif api:
            limited = bool(api.get("limited"))
    if verdict is None:
        try:
            status, _final, body, ctype = await asyncio.wait_for(
                _fetch(client, REDDIT_ABOUT.format(username=username), with_type=True), timeout=timeout)
            verdict = classify_reddit(username, status, ctype, body)
        except Exception as e:  # noqa: BLE001
            code = classify(e)
            verdict = {"state": "unknown", "evidence": MESSAGES.get(code, MESSAGES["unknown"]), "display_name": "", "hint": REDDIT_HINT, "error_code": code}
        if limited and verdict["state"] == "blocked":
            verdict = {**verdict, "evidence": REDDIT_LIMITED, "error_code": "rate_limited"}

    row = _reddit_row(username, verdict)
    if row["state"] in ("found", "not_found"):
        _cache_put(key, row)
    return row


# --------------------------------------------------------------------------------------
# Discord
#
# Discord has no public profile page. What can be asked is its sign-up form's own question,
# "is this handle available?": one POST with {"username": handle}. Recorded on 2026-11-14
# (tests/fixtures/platform/discord_*.json): {"taken": true}, {"taken": false}, and HTTP 400
# with code 50035 for a handle Discord's rules reject ("Username cannot contain ..."). The
# rate limit body is hand-written from Discord's documented shape; it was not provoked.
# "taken" is its own state: nothing was read and nothing says who holds the handle.
# --------------------------------------------------------------------------------------
DISCORD_ATTEMPT = "https://discord.com/api/v9/unique-username/username-attempt-unauthed"
DISCORD_HANDLE_RE = re.compile(r"^[a-z0-9_.]{2,32}$")
DISCORD_TAKEN = "Discord's sign-up check says this handle is taken. Discord has no public profile page, so who holds it is unknown."
DISCORD_FREE = "Discord's sign-up check says this handle is free"
DISCORD_REFUSED = "Discord does not allow this handle, so nobody can hold it"
DISCORD_INVALID = "Not a valid Discord handle: Discord handles are 2 to 32 lowercase letters, digits, underscores or periods"
DISCORD_LIMITED = "Discord rate limited the check. Try again in a few minutes."
DISCORD_HINT = "Discord has no public profile page. Search the handle inside the app or ask for the numeric user ID."


def classify_discord(status: int, body: str) -> dict:
    """One answer from Discord's sign-up check as a verdict. Pure, tested from fixtures."""
    try:
        data = json.loads(body) if (body or "").lstrip()[:1] == "{" else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        data = {}
    if status == 200 and data.get("taken") is True:
        return {"state": "taken", "evidence": DISCORD_TAKEN}
    if status == 200 and data.get("taken") is False:
        return {"state": "not_found", "evidence": DISCORD_FREE}
    if status == 429 or "rate limited" in str(data.get("message") or "").lower():
        return {"state": "blocked", "evidence": DISCORD_LIMITED, "error_code": "rate_limited"}
    if status == 400 and data.get("code") == 50035:
        return {"state": "not_found", "evidence": DISCORD_REFUSED}
    if status in REFUSED:
        return {"state": "blocked", "evidence": f"Discord refused the request (HTTP {status})"}
    return {"state": "unknown", "evidence": f"Discord sent an answer CrawlR could not read (HTTP {status})",
            **({"error_code": "upstream"} if status >= 500 else {})}


def _discord_row(verdict: dict) -> dict:
    state = verdict["state"]
    row = {
        "platform": "Discord", "url": "", "state": state,
        # Only a profile that was read is found: a taken handle is neither true nor false here.
        "found": False if state == "not_found" else None,
        "evidence": verdict.get("evidence", ""), "display_name": "", "public_url": False, "hint": DISCORD_HINT,
    }
    if verdict.get("error_code"):
        row["error_code"] = verdict["error_code"]
    return row


async def _discord(client: httpx.AsyncClient, username: str, timeout: float) -> dict:
    handle = username.lower()
    if not DISCORD_HANDLE_RE.fullmatch(handle):
        return _discord_row({"state": "not_found", "evidence": DISCORD_INVALID})
    key = ("Discord", handle)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    try:
        resp = await asyncio.wait_for(
            client.post(DISCORD_ATTEMPT, json={"username": handle},
                        headers={"User-Agent": HEADERS["User-Agent"], "Accept": "application/json", "Accept-Language": HEADERS["Accept-Language"]}),
            timeout=timeout)
        verdict = classify_discord(resp.status_code, resp.text[:20_000])
    except Exception as e:  # noqa: BLE001
        code = classify(e)
        verdict = {"state": "unknown", "evidence": MESSAGES.get(code, MESSAGES["unknown"]), "error_code": code}
    row = _discord_row(verdict)
    if row["state"] in ("taken", "not_found"):
        _cache_put(key, row)
    return row


# The rows that are always part of a run, after the page rules.
API_ROWS = (("Reddit", _reddit), ("Discord", _discord))


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
    only: tuple[str, ...] | None = None,
) -> dict:
    """`only`: platform names to ask, for a caller that wants a fixed subset (the handle probe)."""
    # Sites another tool already covered (lowercase) are skipped. Reddit and Discord are never
    # skipped: the username tools cannot say anything reliable about either (see above).
    covered = {s.strip().lower() for s in sherlock_sites or []}
    rules = [r for r in RULES if not covered.intersection(r["sherlock"]) and (only is None or r["name"] in only)]
    api = [fn for name, fn in API_ROWS if only is None or name in only]

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
        results = list(await asyncio.gather(*(_check(client, r, username, timeout) for r in rules),
                                            *(fn(client, username, timeout) for fn in api)))

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
