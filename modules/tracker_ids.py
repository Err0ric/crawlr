"""
Tracker and ad account IDs on a domain's home page.

Analytics, tag and ad snippets carry the ID of the account that receives the data. Two sites
that carry the same ID are usually run by the same owner (or the same agency, or were built
from the same copied template: a shared ID is a lead, not proof). This module reads one page
and lists the IDs it can match precisely. It looks nothing up anywhere else: the page compares
IDs across the investigator's own saved cases and offers a quoted string to copy.

What this module touches:

  * one GET to https://<domain>/ through core.netguard.safe_fetch, redirects followed (each hop
    vetted), body capped at MAX_BYTES (core.capfetch), the whole call capped at DEADLINE;
  * the bytes become text through core.charset (a short list of real charsets, UTF-8 for any
    other label), and decoding and matching run on the parse pool (core.parsepool): one parse
    at a time for the whole server, within a CPU budget, so other requests do not wait. A page
    not read to its end within the budget is `truncated` when IDs were found and `failed` when
    none were (part of it was never looked at). A full pool is `failed` with the code `busy`,
    and that answer is not kept. A body that is not text in the charset it was read in (UTF-16
    without a byte order mark, a binary file) is `failed`, never `none`;
  * nothing else. Scripts the page loads are not fetched, so an ID that only exists inside an
    external script or a tag manager container is not seen.

This is a second request pattern next to modules/tech_fingerprint.py, on purpose: that fetch
has no size cap and matches on a lowercased body, and the IDs here are case sensitive.

Matching is strict. Every pattern is tied to the place the vendor's own snippet puts the ID
(the script URL, the init call, the named meta tag), and a bare look-alike elsewhere in the
page is ignored. A missed ID is better than an invented one.

States:

  ok       the page was read and at least one ID matched
  none     the page was read and nothing matched (see `note`: this is not "no tracking")
  blocked  the site refused the request (401, 403, 429, 451 or a challenge page)
  failed   the page could not be fetched or was not HTML

A failure or a block is never "none". The domain is not logged.
"""

import asyncio
import copy
import json
import os
import re
import time
from collections import OrderedDict
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import httpx

from core import charset, inflight, parsepool
from core.capfetch import BadEncoding, CappedTransport, TooLarge, release, was_capped
from core.errors import classify_status, error_fields
from core.logging import get_logger
from core.netguard import safe_fetch
from core.validate import same_site

log = get_logger(__name__)

UA = "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"
MAX_BYTES = 1_500_000
DEADLINE = 15                 # seconds for the whole call
TIMEOUT = 8                   # seconds per connect or read
MAX_REDIRECTS = 5
MAX_IDS = 60
BLOCKED_STATUS = (401, 403, 429, 451)

CACHE_TTL = int(os.getenv("TRACKER_IDS_CACHE_TTL", "3600"))     # ok, none
CACHE_TTL_SOFT = 300                                              # blocked, failed
CACHE_MAX = 1000

NONE_NOTE = ("No tracker or ad account ID was found in the home page's own markup. IDs loaded by an external "
             "script or through a tag manager are not visible here, so this is not proof the site has none.")
OFF_SITE_NOTE = "The home page redirects to another site. These IDs were read from that site's page."
CAPPED_NOTE = "Only the first 1.5 MB of the page was read."
CUT_NOTE = "Only the first part of the page was read."
SLOW_PAGE = "The home page could not be read to its end, so no answer is given for it."
FEED = 32_768                 # characters handed to the parser between two looks at the CPU budget
MAX_PIECES = 2000             # scripts, meta tags, or image and frame addresses kept from one page

# kind -> (label, scope, what a match means). scope "account": one ID covers every site in the
# account. scope "site": the ID is issued per site, container or counter, so a match means the
# very same tag sits on both sites.
KINDS = {
    "google_analytics_ua": ("Google Analytics (Universal)", "account",
                            "The number before the last dash is the account. Properties of one account share it."),
    "google_analytics_4": ("Google Analytics 4", "site",
                           "A measurement ID belongs to one data stream. The same ID on two sites means both report into one property."),
    "google_tag_manager": ("Google Tag Manager", "site",
                           "A container ID. The same container on two sites means one person manages the tags of both."),
    "google_ads": ("Google Ads", "account", "A conversion ID of one Google Ads account."),
    "adsense": ("Google AdSense", "account", "A publisher ID: one per AdSense account, which is the account that gets paid."),
    "google_site_verification": ("Google site verification", "account",
                                 "A Search Console token. It is usually the same for every site one Google account verifies, but that is not guaranteed."),
    "bing_site_verification": ("Bing site verification", "account",
                               "A Bing Webmaster token. It is usually the same for every site one account verifies."),
    "meta_pixel": ("Meta pixel", "site", "A pixel ID. One pixel can be placed on several sites of the same business."),
    "hotjar": ("Hotjar", "site", "A Hotjar site ID."),
    "yandex_metrica": ("Yandex Metrica", "site", "A counter number. One counter can be placed on several sites."),
    "matomo": ("Matomo", "site",
               "The address of the Matomo server the page reports to. Sites that report to the same private server are usually run together."),
    "cloudflare_insights": ("Cloudflare Web Analytics", "site", "A beacon token issued per site, so it is rarely shared."),
    "microsoft_clarity": ("Microsoft Clarity", "site", "A Clarity project ID."),
    "linkedin_insight": ("LinkedIn Insight", "account", "A partner ID of one LinkedIn ads account."),
}
WHERE = {
    "script_src": "a script address",
    "inline_script": "an inline script",
    "meta_tag": "a meta tag",
    "noscript_tag": "an image or frame address",
    "attribute": "a tag attribute",
}

_Q = r"""["']"""
_UA = re.compile(r"^UA-(\d{4,10})-(\d{1,4})$")
_G4 = re.compile(r"^G-[A-Z0-9]{8,12}$")
_AW = re.compile(r"^AW-(\d{8,12})$")
_GTM = re.compile(r"^GTM-[A-Z0-9]{4,9}$")
_PUB = re.compile(r"(?<![\w-])ca-pub-(\d{16})(?!\d)")
_QUOTED_UA = re.compile(_Q + r"(UA-\d{4,10}-\d{1,4})" + _Q)
_QUOTED_G4 = re.compile(_Q + r"(G-[A-Z0-9]{8,12})" + _Q)
_QUOTED_AW = re.compile(_Q + r"(AW-\d{8,12})(?:/[\w-]{1,40})?" + _Q)
_QUOTED_GTM = re.compile(_Q + r"(GTM-[A-Z0-9]{4,9})" + _Q)
_FBQ = re.compile(r"fbq\(\s*" + _Q + "init" + _Q + r"\s*,\s*" + _Q + r"(\d{10,18})" + _Q)
_HJID = re.compile(r"\bhjid\s*:\s*(\d{4,10})\b")
_YM = re.compile(r"\bym\(\s*(\d{5,10})\s*,\s*" + _Q + "init" + _Q)
_YA = re.compile(r"\bYa\.Metrika2?\(\s*\{\s*id\s*:\s*(\d{5,10})\b")
_MATOMO_U = re.compile(r"\bvar\s+u\s*=\s*" + _Q + r"((?:https?:)?//[^\"'\s<>]{4,200})" + _Q)
_MATOMO_SITE = re.compile(r"setSiteId" + _Q + r"\s*,\s*" + _Q + r"?(\d{1,7})\b")
_CLARITY = re.compile(_Q + "clarity" + _Q + r"\s*,\s*" + _Q + "script" + _Q + r"\s*,\s*" + _Q + r"([a-z0-9]{8,12})" + _Q)
_LINKEDIN = re.compile(r"_linkedin_partner_id\s*=\s*" + _Q + r"(\d{4,10})" + _Q)
_GOOGLE_VERIFY = re.compile(r"^[A-Za-z0-9_-]{40,48}=?$")
_BING_VERIFY = re.compile(r"^[0-9A-Fa-f]{32}$")
_CF_TOKEN = re.compile(r"^[0-9a-f]{32}$")
_HOTJAR_SRC = re.compile(r"^/c/hotjar-(\d{4,10})\.js$")
_YANDEX_SRC = re.compile(r"^/watch/(\d{5,10})$")
_CLARITY_SRC = re.compile(r"^/tag/([a-z0-9]{8,12})$")
_DIGITS = re.compile(r"^\d{10,18}$")
_HOSTPATH = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}(?::\d{1,5})?(?:/[A-Za-z0-9._~/-]*)?$")


# --------------------------------------------------------------------------------------
# Reading the page
# --------------------------------------------------------------------------------------
class _Page(HTMLParser):
    """Collects the few places an ID can sit: script addresses and bodies, meta tags, image
    and frame addresses (the noscript fallbacks), and two named attributes."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.script_srcs: list[str] = []
        self.inline: list[str] = []
        self.metas: list[tuple[str, str]] = []
        self.embeds: list[str] = []
        self.ad_clients: list[str] = []
        self.cf_beacons: list[str] = []
        self.full = False                  # a list reached MAX_PIECES: the rest of that kind was not kept
        self._in_script = False
        self._buf: list[str] = []

    def _keep(self, where: list, value) -> None:
        if len(where) < MAX_PIECES:
            where.append(value)
        else:
            self.full = True

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script":
            self._in_script = True
            self._buf = []
            if a.get("src"):
                self._keep(self.script_srcs, a["src"])
            if a.get("data-cf-beacon"):
                self._keep(self.cf_beacons, a["data-cf-beacon"])
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").strip().lower()
            if name:
                self._keep(self.metas, (name, a.get("content", "").strip()))
        elif tag in ("img", "iframe") and a.get("src"):
            self._keep(self.embeds, a["src"])
        if a.get("data-ad-client"):
            self._keep(self.ad_clients, a["data-ad-client"])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == "script":
            self._in_script = False

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._buf)
            if text.strip():
                self._keep(self.inline, text)

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


def _url_parts(src: str):
    """(host, path, query dict) of a script, image or frame address, or None."""
    s = src.strip()
    if s.startswith("//"):
        s = "https:" + s
    try:
        parts = urlsplit(s)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    return host, parts.path, parse_qs(parts.query)


def _is(host: str, site: str) -> bool:
    return host == site or host.endswith("." + site)


class _Found:
    def __init__(self):
        self.rows: "OrderedDict[tuple[str, str], dict]" = OrderedDict()

    def add(self, kind: str, value: str, normalized: str, where: str, search: str = "", **extra) -> None:
        key = (kind, value)
        row = self.rows.get(key)
        if row is None:
            if len(self.rows) >= MAX_IDS:
                return
            label, scope, meaning = KINDS[kind]
            row = self.rows[key] = {
                "kind": kind, "label": label, "value": value, "normalized": normalized,
                "key": f"{kind}:{normalized}", "scope": scope, "seen_in": [],
                "search": f'"{search or normalized}"', "meaning": meaning, **extra,
            }
        if where not in row["seen_in"]:
            row["seen_in"].append(where)


def _google_tag(found: _Found, value: str, where: str) -> None:
    """An ID as gtag.js takes it: Universal Analytics, GA4 or Google Ads."""
    m = _UA.fullmatch(value)
    if m:
        found.add("google_analytics_ua", value, f"UA-{m.group(1)}", where, search=f"UA-{m.group(1)}-")
    elif _G4.fullmatch(value):
        found.add("google_analytics_4", value, value, where)
    elif _AW.fullmatch(value):
        found.add("google_ads", value, value, where)
    elif _GTM.fullmatch(value):
        found.add("google_tag_manager", value, value, where)


def _adsense(found: _Found, text: str, where: str) -> None:
    for m in _PUB.finditer(text):
        found.add("adsense", f"ca-pub-{m.group(1)}", f"pub-{m.group(1)}", where)


def _from_address(found: _Found, src: str, where: str) -> None:
    got = _url_parts(src)
    if not got:
        return
    host, path, query = got
    first = lambda name: (query.get(name) or [""])[0].strip()
    if _is(host, "googletagmanager.com"):
        if path == "/gtag/js":
            _google_tag(found, first("id"), where)
        elif path in ("/gtm.js", "/ns.html") and _GTM.fullmatch(first("id")):
            found.add("google_tag_manager", first("id"), first("id"), where)
    elif _is(host, "googlesyndication.com"):
        _adsense(found, first("client"), where)
    elif _is(host, "facebook.com") and path in ("/tr", "/tr/") and _DIGITS.fullmatch(first("id")):
        found.add("meta_pixel", first("id"), first("id"), where)
    elif host == "static.hotjar.com":
        m = _HOTJAR_SRC.fullmatch(path)
        if m:
            found.add("hotjar", m.group(1), m.group(1), where)
    elif host in ("mc.yandex.ru", "mc.yandex.com"):
        m = _YANDEX_SRC.fullmatch(path)
        if m:
            found.add("yandex_metrica", m.group(1), m.group(1), where)
    elif host == "www.clarity.ms":
        m = _CLARITY_SRC.fullmatch(path)
        if m:
            found.add("microsoft_clarity", m.group(1), m.group(1), where)
    elif host == "px.ads.linkedin.com" and re.fullmatch(r"\d{4,10}", first("pid")):
        found.add("linkedin_insight", first("pid"), first("pid"), where)


def _matomo_base(raw: str) -> str:
    """'//stats.example.org/matomo/' -> 'stats.example.org/matomo'. "" when it is not a plain address."""
    s = re.sub(r"^(?:https?:)?//", "", raw.strip()).rstrip("/")
    host, _, path = s.partition("/")
    s = host.lower() + ("/" + path if path else "")
    return s if _HOSTPATH.fullmatch(s) else ""


def _from_script(found: _Found, text: str) -> None:
    where = "inline_script"
    low = text.lower()
    for m in _QUOTED_UA.finditer(text):
        _google_tag(found, m.group(1), where)
    google_tag = "gtag(" in low or "googletagmanager.com" in low or "datalayer" in low
    if google_tag:
        for rx in (_QUOTED_G4, _QUOTED_AW):
            for m in rx.finditer(text):
                _google_tag(found, m.group(1), where)
    if "googletagmanager.com" in low or "gtm.start" in low:
        for m in _QUOTED_GTM.finditer(text):
            _google_tag(found, m.group(1), where)
    if "adsbygoogle" in low or "googlesyndication" in low:
        _adsense(found, text, where)
    for m in _FBQ.finditer(text):
        found.add("meta_pixel", m.group(1), m.group(1), where)
    if "hotjar" in low:
        for m in _HJID.finditer(text):
            found.add("hotjar", m.group(1), m.group(1), where)
    for rx in (_YM, _YA):
        for m in rx.finditer(text):
            found.add("yandex_metrica", m.group(1), m.group(1), where)
    if "_paq" in low and ("matomo" in low or "piwik" in low):
        m = _MATOMO_U.search(text)
        base = _matomo_base(m.group(1)) if m else ""
        if base:
            site = _MATOMO_SITE.search(text)
            extra = {"site_id": site.group(1)} if site else {}
            found.add("matomo", base, base, where, **extra)
    if "clarity" in low:
        for m in _CLARITY.finditer(text):
            found.add("microsoft_clarity", m.group(1), m.group(1), where)
    for m in _LINKEDIN.finditer(text):
        found.add("linkedin_insight", m.group(1), m.group(1), where)


def extract_ids(html: str, budget: parsepool.Budget | None = None) -> list[dict]:
    """Every ID the page's markup carries, in the order first seen. Pure. The work stops when
    `budget` (CPU time of this thread) is spent, with the IDs found up to there; `budget.cut`
    then says so."""
    budget = budget or parsepool.Budget()
    page = _Page()
    try:
        # In pieces, so the budget is looked at however the markup is written.
        for at in range(0, len(html), FEED):
            if budget.over(parsepool.READ_SHARE):
                break
            page.feed(html[at:at + FEED])
        if not budget.cut:
            page.close()
    except Exception:  # noqa: BLE001 - broken markup: keep what was collected before it
        pass
    if page._in_script and page._buf:          # the page was cut inside a script
        page.inline.append("".join(page._buf))
    if page.full:
        budget.cut = True                       # more of one kind than is kept: part of the page was not looked at
    found = _Found()
    for n, src in enumerate(page.script_srcs):
        if n % 256 == 0 and budget.over():
            break
        _from_address(found, src, "script_src")
    for n, text in enumerate(page.inline):
        if (n % 64 == 0 or len(text) > FEED) and budget.over():
            break
        _from_script(found, text)
    for name, content in page.metas:
        if name == "google-site-verification" and _GOOGLE_VERIFY.fullmatch(content):
            found.add("google_site_verification", content, content, "meta_tag")
        elif name == "msvalidate.01" and _BING_VERIFY.fullmatch(content):
            found.add("bing_site_verification", content, content.upper(), "meta_tag", search=content)
        elif name == "google-adsense-account":
            _adsense(found, content, "meta_tag")
    for n, src in enumerate(page.embeds):
        if n % 256 == 0 and budget.over():
            break
        _from_address(found, src, "noscript_tag")
    for value in page.ad_clients:
        _adsense(found, value, "attribute")
    for raw in page.cf_beacons:
        try:
            token = json.loads(raw).get("token", "")
        except (ValueError, AttributeError):
            token = ""
        if isinstance(token, str) and _CF_TOKEN.fullmatch(token):
            found.add("cloudflare_insights", token, token, "attribute")
    return list(found.rows.values())


def findings_for(ids: list[dict]) -> list[dict]:
    """One `info` row per ID. A shared ID is a lead about ownership, never a risk flag."""
    out = []
    for row in ids:
        places = " and ".join(WHERE[w] for w in row["seen_in"])
        out.append({"level": "info", "title": f"{row['label']}: {row['value']}", "detail": f"Seen in {places}. {row['meaning']}"})
    return out


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
def _inner_transport() -> httpx.AsyncBaseTransport:
    """The real network transport. Tests replace this with a mock."""
    return httpx.AsyncHTTPTransport(retries=0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=CappedTransport(_inner_transport(), MAX_BYTES, truncate=True), timeout=TIMEOUT)


def _base(domain: str, state: str) -> dict:
    return {"domain": domain, "state": state, "requests_target": True, "url": "", "final_host": "", "off_site": False,
            "ids": [], "count": 0, "truncated": False, "findings": [], "note": ""}


def _problem(domain: str, state: str, exc: BaseException | None = None, *, code: str | None = None, message: str | None = None) -> dict:
    # Only the exception's type is kept as detail: its text can hold the host.
    fields = error_fields(exc, code=code, message=message, detail=type(exc).__name__ if exc is not None else "")
    return {**_base(domain, state), **fields}


def _challenge(resp: httpx.Response) -> bool:
    if resp.headers.get("cf-mitigated"):
        return True
    return resp.status_code == 503 and "cloudflare" in resp.headers.get("server", "").lower()


def _parse(body: bytes, content_type: str) -> tuple[bool, list[dict], bool]:
    """(the start of the body looks like markup, the IDs, whether reading stopped at the CPU
    budget) from the fetched bytes. Runs on the parse pool. The page's own charset label never
    picks the codec: core.charset does. Raises ValueError for a body that is not text."""
    budget = parsepool.Budget()
    text = charset.decode(body, content_type)
    if charset.not_text(text):
        raise ValueError("not text")
    return "<" in text[:2000], extract_ids(text, budget), budget.cut


async def _read(domain: str) -> dict:
    try:
        async with _client() as client:
            got = await asyncio.wait_for(
                safe_fetch(client, f"https://{domain}/", max_redirects=MAX_REDIRECTS,
                           headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml", "Accept-Encoding": "gzip"}),
                timeout=DEADLINE,
            )
    except (TooLarge, BadEncoding) as e:
        return _problem(domain, "failed", e, code="bad_response")
    except Exception as e:  # noqa: BLE001 - every failure becomes a state with a code
        return _problem(domain, "failed", e)
    resp = release(got.response)             # the page is freed as soon as it has been read
    if resp.status_code in BLOCKED_STATUS or _challenge(resp):
        return _problem(domain, "blocked", code="rate_limited" if resp.status_code == 429 else "blocked",
                        message="The site refused the request, so its page could not be read.")
    if not 200 <= resp.status_code < 300:
        return _problem(domain, "failed", code=classify_status(resp.status_code))
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    if ctype not in ("text/html", "application/xhtml+xml", ""):
        return _problem(domain, "failed", code="bad_response", message="The home page is not an HTML page.")
    try:
        # On the parse pool, off the event loop: 1.5 MB of markup takes a moment to decode and match.
        markup, ids, cut = await parsepool.run(_parse, resp.content, resp.headers.get("content-type") or "")
    except parsepool.Busy as e:
        return _problem(domain, "failed", e, code="busy")       # nothing was read: not "none", and not kept
    except Exception as e:  # noqa: BLE001 - a page that cannot be read is a failure with a code, never "none"
        return _problem(domain, "failed", e, code="bad_response")
    if not ctype and not markup:
        return _problem(domain, "failed", code="bad_response", message="The home page is not an HTML page.")
    if cut and not ids:
        # Part of the page was never looked at, so "no ID" would be a guess.
        return _problem(domain, "failed", code="bad_response", message=SLOW_PAGE)
    final_host = (urlsplit(got.url).hostname or "").lower()
    off_site = not same_site(final_host, domain)
    out = _base(domain, "ok" if ids else "none")
    notes = []
    if not ids:
        notes.append(NONE_NOTE)
    if off_site:
        notes.append(OFF_SITE_NOTE)
    if was_capped(resp) and len(resp.content) >= MAX_BYTES:
        notes.append(CAPPED_NOTE)
    elif was_capped(resp) or cut:
        notes.append(CUT_NOTE)          # the site sent more than was kept, or the reading stopped at its budget
    out.update({
        "url": got.url, "final_host": final_host, "off_site": off_site, "ids": ids, "count": len(ids),
        "truncated": was_capped(resp) or cut, "findings": findings_for(ids), "note": " ".join(notes),
    })
    return out


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_pending: dict = {}           # domains being read right now (core.inflight)


def clear_cache_for_tests() -> None:
    _cache.clear()
    _pending.clear()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ttl = CACHE_TTL if hit[1]["state"] in ("ok", "none") else min(CACHE_TTL, CACHE_TTL_SOFT)
    if time.time() - hit[0] > ttl:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return copy.deepcopy(hit[1])


def _cache_put(key: str, answer: dict) -> None:
    _cache[key] = (time.time(), copy.deepcopy(answer))
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------
async def run_tracker_ids(domain: str) -> dict:
    """{domain, state, requests_target, url, final_host, off_site, ids, count, truncated,
    findings, note, cached}. `blocked` and `failed` add the three core.errors fields.
    `domain` has been through core.validate.host."""
    cached = _cache_get(domain)
    if cached is not None:
        return {**cached, "cached": True}
    async def fresh() -> dict:
        answer = await _read(domain)
        if answer.get("error_code") != "busy":          # a full pool says nothing about the page: not kept
            _cache_put(domain, answer)
        # State and a count only: no domain, URL or ID is logged.
        log.info("tracker ids", extra={"state": answer["state"], "ids": answer["count"]})
        return answer

    # The same domain asked for twice at once is read once; each caller gets its own copy.
    answer = copy.deepcopy(await inflight.shared(_pending, domain, fresh))
    return {**answer, "cached": False}
