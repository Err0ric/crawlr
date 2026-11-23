"""
Adult and dating site check: is there a public profile for this handle on the sites that
matter in sextortion, romance-scam and catfish cases, and for people checking their own
exposure?

This only runs when the investigator opts in, after the ordinary sources, and never when the
handle states an age under 18 or a profile found for it suggests a minor (core.adult_guard.gate
runs first, here and in the router). It reports that a profile exists and a
little text the page states about it. It never fetches, stores or returns an image, a
thumbnail, a media address or post content.

The design is modules/platform_check.py's: a RULES table, a pure classify function, a browser
navigation request, and five states.

  found          a marker the site wrote names this handle (page title, profile data)
  not_found      the site's own no-such-user answer, recorded in tests/fixtures/adult
  blocked        a sign-in wall, an age gate, a bot check or a refusal
  unknown        anything else: a page that proves nothing, a timeout, a site with no
                 confirmed rule
  no_public_url  the site has no public page per username, so no request is made

`found` in a row is true only for "found" and false only for "not_found". A bare HTTP 200 is
never "found" and a wall is never "not_found". Only a rule whose markers were recorded from the
site itself (src "recorded") may conclude either way; tests/test_adult_check.py enforces that.

What each site sent to an anonymous server-side GET on 2026-11-14, for its own official
account and for a random 30-character handle:

  Fansly         public account lookup (JSON): the account, or an empty list
  Pornhub        200 and "<handle>'s ... - Pornhub.com", or 404 and "Page Not Found"
  xHamster       200 and "<handle>'s ... on xHamster", or 404 and "User not found"
  Chaturbate     200 and the room data or the page title naming the handle, or 404 and its own 404 page
  JustFor.Fans   200 and "<handle> @ JustFor.Fans", or a redirect to explore.php?error=usernotfound
  Tinder         200 and profile:username, or 200 and the homepage with an empty web profile
                 (confirmed against a canary before it is believed)
  FetLife        a redirect to /login for every handle: blocked, no rule either way
  OnlyFans       the same empty app page for every handle: unknown, no request is made
  LoyalFans      the same empty app page for every handle (its API answers 403): unknown,
                 no request is made
  Stripchat      could not be reached from the recording network, so there is no confirmed
                 rule: unknown, no request is made
  ManyVids, Clips4Sale            profile addresses carry a numeric ID: no public URL
  Bumble, Hinge, OkCupid, Plenty of Fish, Grindr   no public profile per username

Requests go only to the fixed hosts below. A redirect is followed only while it stays on the
same site. The handle has been through core.validate.
"""

import asyncio
import html
import json
import os
import re
import time
from collections import OrderedDict
from urllib.parse import urljoin, urlsplit

import httpx

from core import adult_guard
from core.boilerplate import clean_bio
from core.errors import classify, error_fields
from core.validate import registrable_domain
from modules.platform_check import HEADERS, LOGIN_PATH

TIMEOUT = 10                  # seconds, per request
MAX_BODY = 300_000            # bytes read from the wire per response
MAX_REDIRECTS = 5
CONCURRENCY = 4

CACHE_TTL = int(os.getenv("ADULT_CHECK_CACHE_TTL", str(24 * 3600)))   # found and not_found only
CACHE_MAX = 2000
CANARY_TTL_OK = 600           # a readable canary is trusted for ten minutes
CANARY_TTL_FAIL = 120         # a failed one is retried sooner

REFUSED = (401, 403, 429)

# --------------------------------------------------------------------------------------
# Evidence and hints. The only sentences a row's `evidence` and `hint` can hold. Nothing read
# from a fetched page is ever placed in either.
# --------------------------------------------------------------------------------------
EVIDENCE = {
    # found
    "page_names_handle": "The profile page loaded and its title names this handle.",
    "site_data": "The site's own profile data names this handle.",
    # not_found
    "no_such_user": "The site shows its own no-such-user page for this handle.",
    "lookup_empty": "The site's account lookup has no account with this handle.",
    # blocked
    "login_wall": "The site sends anonymous visitors to its sign-in page, so the profile cannot be read from here.",
    "challenge": "The site answered with a bot check or an age gate instead of the page.",
    "refused": "The site refused the request.",
    "canary_failed": "The site is showing its no-profile page for a profile that is known to exist, so its answer cannot be trusted right now.",
    # unknown
    "same_page": "The site sends the same page for every handle, so it cannot be checked automatically.",
    "unrecorded": "CrawlR has no confirmed rule for this site yet, so it was not checked automatically.",
    "no_marker": "The page loaded but nothing on it names this handle.",
    "off_site": "The site redirected to a different site, which does not say whether the profile exists.",
    "http_error": "The site answered with an error.",
    "unreadable": "The site sent a response CrawlR could not read.",
    "timeout": "The site took too long to answer.",
    "unreachable": "Could not connect to the site.",
    "dns": "The site's name could not be looked up.",
    "tls": "The secure connection to the site failed.",
    "failed": "The check could not be completed.",
    # no_public_url
    "no_public_url": "This site has no public profile page per username, so nothing was requested.",
}
_ERROR_EVIDENCE = {"timeout": "timeout", "unreachable": "unreachable", "dns": "dns", "tls": "tls", "bad_response": "unreadable"}

HINTS = {
    "open_link": "Open the link in a browser to look. The site only shows the profile to a real browser.",
    "sign_in": "Profiles are visible to signed-in members only. Search the handle on the site while signed in.",
    "site_search": "Profile addresses on this site carry a numeric ID. Use the site's own search for the handle or the display name.",
    "app_only": "Profiles exist only inside the app. There is no handle search: a profile can be reached only from a match or a link the person shared.",
    "okcupid": "OkCupid removed public usernames. A profile can be opened only by a signed-in member it is shown to.",
    "pof": "Plenty of Fish has a username search for signed-in members only. Search the handle there while signed in.",
}

# --------------------------------------------------------------------------------------
# Rules. In every pattern `{u}` is the handle (regex-escaped, matched without regard to case).
#
#   category     "adult" or "dating"
#   url          the public profile address shown to the investigator
#   check_url    the address that is requested, when it is not `url`
#   reader       "page" (default) or "fansly" (the JSON account lookup)
#   src          "recorded": the markers below were recorded from the site
#                (tests/fixtures/adult). Anything else may not have found or not_found.
#   found        [(field, pattern, evidence key)]  a marker the site wrote that names the handle
#   not_found    [(field, pattern, evidence key)]  the site's own no-such-user answer
#   not_found_status   when set, a not_found marker counts only with one of these statuses
#   wall         [(field, pattern, evidence key)]  sign-in wall or gate -> blocked
#   name_from    (field, pattern)  group 1 is the display name, read only when found
#   canary       an account that certainly exists, fetched to confirm a not-found page that
#                the site also serves with HTTP 200
#   static       (state, evidence key): no request is made and every handle gets this answer
#   hint         key in HINTS
#
# Fields: title, og:title, profile:username, profile:first_name (html-unescaped), body (raw),
# final_url, redirected_to (the final URL, empty unless a redirect happened), status.
# og:url and the canonical link are not fields: the site builds them from the request.
# --------------------------------------------------------------------------------------
RULES = [
    {
        "name": "OnlyFans", "category": "adult", "url": "https://onlyfans.com/{username}",
        "src": "recorded", "static": ("unknown", "same_page"), "hint": "open_link",
    },
    {
        "name": "Fansly", "category": "adult", "url": "https://fansly.com/{username}",
        "check_url": "https://apiv3.fansly.com/api/v1/account?usernames={username}",
        "reader": "fansly", "src": "recorded",
        # Stand-ins for the enumeration test: the reader below decides, not these patterns.
        "found": [("body", r'"username"\s*:\s*"{u}"', "site_data")],
        "not_found": [("body", r'^\s*\{\s*"success"\s*:\s*true\s*,\s*"response"\s*:\s*\[\s*\]\s*\}\s*$', "lookup_empty")],
    },
    {
        "name": "Pornhub", "category": "adult", "url": "https://www.pornhub.com/users/{username}",
        "src": "recorded",
        "found": [("title", r"^{u}'s [^<>|]{1,40} - Pornhub\.com$", "page_names_handle")],
        "not_found": [("title", r"^Page Not Found$", "no_such_user")],
        "not_found_status": (404,),
    },
    {
        "name": "xHamster", "category": "adult", "url": "https://xhamster.com/users/{username}",
        "src": "recorded",
        "found": [("title", r"^{u}'s [^<>|]{1,80} on xHamster$", "page_names_handle")],
        "not_found": [("title", r"^User not found$", "no_such_user")],
        "not_found_status": (404,),
    },
    {
        "name": "Chaturbate", "category": "adult", "url": "https://chaturbate.com/{username}/",
        "src": "recorded",
        "found": [
            ("body", r'\\u0022broadcaster_username\\u0022: \\u0022{u}\\u0022', "site_data"),
            # An account that has no room data still gets its own title. The 404 page does not.
            ("og:title", r"^{u} cam[^|]{0,60}\| Chaturbate$", "page_names_handle"),
        ],
        "not_found": [("body", r"<h1>HTTP 404 - Page Not Found</h1>", "no_such_user")],
        "not_found_status": (404,),
    },
    {
        "name": "Stripchat", "category": "adult", "url": "https://stripchat.com/{username}",
        "src": "unrecorded", "static": ("unknown", "unrecorded"), "hint": "open_link",
    },
    {
        "name": "ManyVids", "category": "adult", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "site_search",
    },
    {
        "name": "Clips4Sale", "category": "adult", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "site_search",
    },
    {
        "name": "FetLife", "category": "adult", "url": "https://fetlife.com/{username}",
        "src": "recorded",
        # FetLife sends every handle, real or not, to its sign-in page. No rule either way.
        "wall": [
            ("redirected_to", r"^https?://(?:www\.)?fetlife\.com/login", "login_wall"),
            ("title", r"^Login \| FetLife$", "login_wall"),
        ],
        "hint": "sign_in",
    },
    {
        "name": "JustFor.Fans", "category": "adult", "url": "https://justfor.fans/{username}",
        "src": "recorded",
        "found": [("title", r"^{u} @ JustFor\.Fans$", "page_names_handle")],
        "not_found": [("redirected_to", r"^https?://(?:www\.)?justfor\.fans/explore\.php\?error=usernotfound", "no_such_user")],
    },
    {
        "name": "LoyalFans", "category": "adult", "url": "https://www.loyalfans.com/{username}",
        "src": "recorded", "static": ("unknown", "same_page"), "hint": "open_link",
    },
    {
        "name": "Tinder", "category": "dating", "url": "https://tinder.com/@{username}",
        "src": "recorded",
        "found": [
            ("profile:username", r"^{u}$", "site_data"),
            ("title", r"\(@{u}\) \| Tinder$", "page_names_handle"),
        ],
        "name_from": ("profile:first_name", r"^(.{1,60})$"),
        # A handle with no web profile gets the homepage with HTTP 200, so the answer is
        # confirmed against the canary before it is believed.
        "not_found": [("body", r'"webProfile":\{\}', "no_such_user")],
        "canary": "tinder",
    },
    {
        "name": "Bumble", "category": "dating", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "app_only",
    },
    {
        "name": "Hinge", "category": "dating", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "app_only",
    },
    {
        "name": "OkCupid", "category": "dating", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "okcupid",
    },
    {
        "name": "Plenty of Fish", "category": "dating", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "pof",
    },
    {
        "name": "Grindr", "category": "dating", "url": "",
        "src": "recorded", "static": ("no_public_url", "no_public_url"), "hint": "app_only",
    },
]


def _site(url: str) -> str:
    try:
        return registrable_domain(urlsplit(url.replace("{username}", "x")).hostname or "")
    except ValueError:
        return ""


# Registrable domains of every platform here, with or without a public profile address.
# Other modules use it to recognise an adult or dating row.
HOSTS = frozenset(
    {_site(r[k]) for r in RULES for k in ("url", "check_url") if r.get(k)}
    | {"manyvids.com", "clips4sale.com", "bumble.com", "hinge.co", "okcupid.com", "pof.com", "grindr.com", "stripchat.com"}
) - {""}
CATEGORY_BY_HOST = {_site(r["url"]): r["category"] for r in RULES if r.get("url")}
CATEGORY_BY_HOST.update({"manyvids.com": "adult", "clips4sale.com": "adult", "bumble.com": "dating", "hinge.co": "dating",
                         "okcupid.com": "dating", "pof.com": "dating", "grindr.com": "dating"})

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
# Reading a response
# --------------------------------------------------------------------------------------
_TITLE = re.compile(r"<title[^>]*>([^<]{0,300})</title>", re.I)
_META = re.compile(r"<meta\s[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_HEAD_FIELDS = ("og:title", "profile:username", "profile:first_name")
_CHALLENGE_TITLE = re.compile(r"^\s*(?:just a moment|attention required|access denied|verify (?:you are|your age)|age verification|are you (?:18|over 18))", re.I)
_CHALLENGE_BODY = ("_cf_chl_opt", "cf-browser-verification", "challenges.cloudflare.com/turnstile", "captcha-delivery.com", "px-captcha")


def page_fields(status: int, final_url: str, body: str, redirected: bool = False) -> dict:
    """The few fields the rules read. Image and media tags are never read."""
    fields = {"status": str(status), "final_url": final_url or "", "redirected_to": (final_url or "") if redirected else "",
              "body": body or "", "title": ""}
    fields.update({k: "" for k in _HEAD_FIELDS})
    m = _TITLE.search(body or "")
    if m:
        fields["title"] = html.unescape(m.group(1)).strip()
    for tag in _META.findall(body or ""):
        attrs = {k.lower(): (a or b) for k, a, b in _ATTR.findall(tag)}
        key = attrs.get("property") or attrs.get("name") or ""
        if key in _HEAD_FIELDS and not fields[key]:
            fields[key] = html.unescape(attrs.get("content", "")).strip()
    return fields


def _first(rules, fields: dict, username: str):
    """The (evidence key, match) of the first of `rules` that matches, or None."""
    u = re.escape(username)
    for field, pattern, key in rules or []:
        m = re.search(pattern.replace("{u}", u), fields.get(field, ""), re.I)
        if m:
            return key, m
    return None


def _verdict(state: str, key: str, **extra) -> dict:
    return {"state": state, "evidence_key": key, "display_name": "", "joined": "", "followers": None, "bio": "", **extra}


def _count(value) -> int | None:
    """A follower count the site stated, as a number. Anything else is None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value < 10**10 else None
    if isinstance(value, str):
        digits = re.sub(r"[,\s.]", "", value.strip())
        return int(digits) if digits.isdigit() and len(digits) <= 10 else None
    return None


def _bio(text, platform: str, username: str, name: str) -> str:
    """The bio only when it is plain text a person wrote: platform boilerplate is removed and
    anything that carries a link or markup is dropped whole."""
    return adult_guard.plain_text(clean_bio(text, platform, username, name))


def _classify_fansly(username: str, status: int, body: str) -> dict:
    """Fansly's public account lookup: {"success": true, "response": [account, ...]}."""
    if status in REFUSED:
        return _verdict("blocked", "refused")
    if status >= 400:
        return _verdict("unknown", "http_error", error_code="upstream")
    try:
        data = json.loads(body)
    except ValueError:
        return _verdict("unknown", "unreadable")
    accounts = data.get("response") if isinstance(data, dict) else None
    if not isinstance(data, dict) or data.get("success") is not True or not isinstance(accounts, list):
        return _verdict("unknown", "unreadable")
    if not accounts:
        return _verdict("not_found", "lookup_empty")
    for account in accounts:
        if isinstance(account, dict) and str(account.get("username", "")).lower() == username.lower():
            name = adult_guard.plain_text(account.get("displayName"), 100)
            return _verdict("found", "site_data", display_name=name,
                            followers=_count(account.get("followCount")),
                            bio=_bio(account.get("about"), "Fansly", username, name))
    return _verdict("unknown", "no_marker")


def classify_response(rule: dict, username: str, status: int, final_url: str, body: str, redirected: bool = False) -> dict:
    """Decide a state from one response. Pure: no network, so it is tested from fixtures.

    Returns {state, evidence_key, display_name, joined, followers, bio}. "not_found" is
    provisional for a rule with a canary; `_check` confirms it.
    """
    if rule.get("src") != "recorded":
        return _verdict("unknown", "unrecorded")
    if rule.get("reader") == "fansly":
        return _classify_fansly(username, status, body)

    fields = page_fields(status, final_url, body, redirected)

    hit = _first(rule.get("found"), fields, username)
    if hit and status < 400:
        name = ""
        if rule.get("name_from"):
            field, pattern = rule["name_from"]
            m = re.search(pattern, fields.get(field, ""), re.I)
            name = adult_guard.plain_text(m.group(1), 100) if m else ""
        return _verdict("found", hit[0], display_name=name)

    hit = _first(rule.get("wall"), fields, username)
    if hit:
        return _verdict("blocked", hit[0])
    # A redirect that ended on a sign-in page, whatever the body says.
    start_path = re.sub(r"^https?://[^/]+", "", _check_url(rule, username))
    end_path = re.sub(r"^https?://[^/]+", "", final_url or "")
    if LOGIN_PATH.search(end_path) and not LOGIN_PATH.search(start_path):
        return _verdict("blocked", "login_wall")
    if _CHALLENGE_TITLE.search(fields["title"]) or any(marker in fields["body"] for marker in _CHALLENGE_BODY):
        return _verdict("blocked", "challenge")
    if status in REFUSED:
        return _verdict("blocked", "refused")

    wanted = rule.get("not_found_status")
    if not wanted or status in wanted:
        hit = _first(rule.get("not_found"), fields, username)
        if hit:
            return _verdict("not_found", hit[0])

    if status >= 500:
        return _verdict("unknown", "http_error", error_code="upstream")
    if status >= 400 and not rule.get("not_found"):
        return _verdict("unknown", "http_error")
    return _verdict("unknown", "no_marker")


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
def _check_url(rule: dict, username: str) -> str:
    return (rule.get("check_url") or rule["url"]).format(username=username)


def _client(timeout: float) -> httpx.AsyncClient:
    """One client per call. Redirects are walked by hand in `_fetch`."""
    return httpx.AsyncClient(timeout=timeout, follow_redirects=False)


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[int, str, str, bool, bool]:
    """GET `url` and return (status, final url, text up to MAX_BODY, redirected, left the site).

    The host is one of the fixed platform hosts. A redirect is followed only while it stays on
    that site, so a request never leaves for a host this module did not choose."""
    home = registrable_domain(urlsplit(url).hostname or "")
    current, redirected = url, False
    for _ in range(MAX_REDIRECTS + 1):
        async with client.stream("GET", current, headers=HEADERS) as resp:
            location = resp.headers.get("location", "")
            if resp.is_redirect and location:
                target = urljoin(current, location)
                parts = urlsplit(target)
                if parts.scheme not in ("http", "https") or registrable_domain(parts.hostname or "") != home:
                    return resp.status_code, current, "", redirected, True
                current, redirected = target, True
                continue
            chunks, size = [], 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY:
                    break
            try:
                text = b"".join(chunks)[:MAX_BODY].decode(resp.charset_encoding or "utf-8", errors="replace")
            except LookupError:
                text = b"".join(chunks)[:MAX_BODY].decode("utf-8", errors="replace")
            return resp.status_code, current, text, redirected, False
    raise httpx.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects")


async def _fetch_state(client: httpx.AsyncClient, rule: dict, username: str, timeout: float) -> dict:
    try:
        status, final_url, body, redirected, left = await asyncio.wait_for(_fetch(client, _check_url(rule, username)), timeout=timeout)
    except httpx.TooManyRedirects:
        return _verdict("unknown", "failed")
    except Exception as e:  # noqa: BLE001 - every failure becomes an "unknown" row with a code
        # Only the code is kept: the exception text can hold the URL, and the URL holds the handle.
        code = classify(e)
        return _verdict("unknown", _ERROR_EVIDENCE.get(code, "failed"), error_code=code)
    if left:
        return _verdict("unknown", "off_site")
    return classify_response(rule, username, status, final_url, body, redirected)


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
    found = state == "found"
    row = {
        "platform": rule["name"],
        "category": rule["category"],
        "url": rule["url"].format(username=username) if rule.get("url") else "",
        "state": state,
        "found": True if found else False if state == "not_found" else None,
        "evidence": EVIDENCE[verdict["evidence_key"]],
        "display_name": verdict.get("display_name", "") if found else "",
        "joined": verdict.get("joined", "") if found else "",
        "followers": verdict.get("followers") if found else None,
        "bio": verdict.get("bio", "") if found else "",
        "hint": HINTS.get(rule.get("hint", ""), "") if not found else "",
    }
    if verdict.get("error_code"):
        row["error_code"] = verdict["error_code"]
    # Text only. Nothing that names or addresses an image may leave in an adult row. A field
    # the filter removed comes back empty, so the row keeps its shape.
    clean = adult_guard.strip_media(row)
    return {**{k: (None if k == "followers" else "") for k in row if k not in clean}, **clean}


def is_fetched(rule: dict) -> bool:
    """Does checking this platform make a request at all?"""
    return not rule.get("static")


async def _check(client: httpx.AsyncClient, sem: asyncio.Semaphore, rule: dict, username: str, timeout: float) -> dict:
    if rule.get("static"):
        state, key = rule["static"]
        return _row(rule, username, _verdict(state, key))

    cache_key = (rule["name"], username.lower())
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "url": rule["url"].format(username=username)}

    async with sem:
        verdict = await _fetch_state(client, rule, username, timeout)
        if verdict["state"] == "not_found" and rule.get("canary"):
            if username.lower() == rule["canary"].lower() or not await _canary_ok(client, rule, timeout):
                verdict = _verdict("blocked", "canary_failed")

    row = _row(rule, username, verdict)
    if row["state"] in ("found", "not_found"):
        _cache_put(cache_key, row)
    return row


async def run_adult_check(username: str, timeout: float = TIMEOUT) -> dict:
    """Check every platform in RULES for `username`. The minor guard runs before anything else:
    the handle check, then the check of the profiles the ordinary sources found."""
    refused = adult_guard.gate(username)
    if refused:
        # The router answers before this point. This is the second lock on the door.
        return {"username": username, "checked": 0, "total": 0, "results": [], **adult_guard.gate_fields(refused)}

    sem = asyncio.Semaphore(CONCURRENCY)
    async with _client(timeout) as client:
        results = list(await asyncio.gather(*(_check(client, sem, rule, username, timeout) for rule in RULES)))

    return {
        "username": username,
        "checked": sum(1 for rule in RULES if is_fetched(rule)),
        "total": sum(1 for r in results if r["state"] == "found"),
        "results": results,
    }
