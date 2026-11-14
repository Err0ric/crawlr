"""
Link verifier: does this account link really lead to a profile for this handle?

Sherlock and Maigret report a hit as a templated URL (https://site/{username}). Nobody has
opened it. Many of those links answer 404, show a "no such user" page with HTTP 200, bounce to
a login page, or land on the site's homepage. This module opens each link once and puts it in
one of five states:

  verified        the page answered, a marker on it names this handle, and the address after
                  redirects is still a profile address for the handle
  not_found       a definite absence: HTTP 404 or 410, or a no-such-user page that was
                  recorded from the site itself (tests/fixtures/links)
  blocked         401, 403, 429, 999, a login or consent wall, or a bot check
  unknown         anything else, including a timeout, a redirect away from the profile, a
                  page that only looks like a no-such-user page, and a 200 that proves nothing
  no_public_url   the site has no public page per handle, so no request is made

Two rules keep the answers honest:

  * Only a recorded rule may conclude. A phrase taken from Sherlock's or Maigret's site data,
    or a page shape nobody recorded, can at most say "this looks like a no-such-user page",
    which is reported as unknown.
  * A marker counts as proof only when the site wrote it about the account. og:url and the
    canonical link are built from the request, so they are never read. A positive marker is
    checked before any no-such-user phrase, and phrases are read from the top of the page
    only, so text a user wrote on a profile cannot make the profile "not found".

Where the rules come from, in order:

  1. modules.platform_check.RULES for the six big social sites (recorded there).
  2. RULES below: hand-written entries keyed by host.
  3. Sherlock's own site data, loaded once at import, for every other host it knows. Only
     entries whose check reads the public profile page itself are used (no API probes), and
     only as the unconfirmed hint described above.
  4. A generic reading of the status, the redirect and the page title.

The caller supplies the URLs, so this is not a general fetcher:

  * only sites Sherlock, Maigret or platform_check know are fetched (KNOWN_SITES);
  * the URL must name the handle, use http or https and carry no port;
  * every fetch goes through core.netguard.safe_fetch with a byte cap, a time limit and a
    redirect limit, and each site gets a bounded number of requests per minute process-wide;
  * nothing read from a fetched page is returned: `evidence` is always one of the fixed
    phrases in EVIDENCE, and `final_url` is returned only for a verified link on the same
    site as the one that was asked for.

What nine of these sites sent to an anonymous server-side GET on 2026-11-14 is recorded in
tests/fixtures/links/. Entries marked "recorded" were written against those bodies.
"""

import asyncio
import html
import importlib.util
import json
import os
import re
import time
import zlib
from collections import OrderedDict, deque
from urllib.parse import unquote, urlsplit, urlunsplit

import httpx

from core.errors import error_fields
from core.logging import get_logger
from core.netguard import safe_fetch
from core.validate import registrable_domain
from modules import platform_check as pc

log = get_logger(__name__)

MAX_LINKS = 25
CONCURRENCY = 6
PER_SITE = 2                  # requests in flight to one site within a call
SITE_RATE = 20                # requests to one site per SITE_WINDOW, across all calls
SITE_WINDOW = 60
TIMEOUT = 8                   # seconds, per request
TOTAL_TIMEOUT = 12            # seconds, for a link including its redirects
CALL_DEADLINE = 30            # seconds, for a whole call
MAX_BODY = 300_000            # bytes read from the wire, and bytes kept after decompression
HEAD_BYTES = 8_000            # no-such-user phrases are read from this much of the page only
MAX_REDIRECTS = 5
MAX_URL = 600

CACHE_TTL = int(os.getenv("LINK_VERIFY_CACHE_TTL", str(24 * 3600)))   # verified, not_found
CACHE_TTL_SOFT = 600                                                   # blocked, unknown
CACHE_MAX = 4000

# A browser navigation, as platform_check sends it. Only gzip is offered: it is decompressed
# here under a size limit, and anything else is reported as unreadable.
HEADERS = {**pc.HEADERS, "Accept-Encoding": "gzip"}

REFUSED = (401, 403, 429, 999)

# --------------------------------------------------------------------------------------
# Evidence. The only strings a result's `evidence` can hold.
# --------------------------------------------------------------------------------------
EVIDENCE = {
    # verified
    "page_names_handle": "The page loaded and its title names this handle.",
    "site_marker": "The page loaded and the site's own profile data names this handle.",
    # not_found
    "http_404": "The site answered 404: there is no page at this address.",
    "http_410": "The site answered 410: the page has been removed.",
    "soft_404": "The site shows its own no-such-user page for this handle.",
    # blocked
    "to_login": "The link redirects to a sign-in page.",
    "login_wall": "The site asks visitors to sign in or accept a prompt before it shows this page.",
    "refused": "The site refused the request.",
    "challenge": "The site answered with a bot check instead of the page.",
    # unknown
    "unconfirmed_soft_404": "The site shows what looks like a no-such-user page, but CrawlR has not confirmed that rule.",
    "to_homepage": "The link redirects to the site's homepage, which can mean no such user or a members-only page.",
    "to_not_found": "The link redirects to an error page, which does not say whether the profile exists.",
    "to_search": "The link redirects to a search page, not to a profile.",
    "ambiguous_page": "The site answers the same way for a missing profile and a refused request.",
    "walled_site": "This site rarely shows profiles to anonymous visitors, and nothing on the page names this handle.",
    "no_marker": "The page loaded but nothing on it names this handle.",
    "moved": "The link redirects to a page that is not a profile for this handle.",
    "off_site": "The link redirects to a different site.",
    "http_error": "The site answered with an error.",
    "unreadable": "The site sent a response CrawlR could not read.",
    "redirect_loop": "The link redirects too many times.",
    "timeout": "The site took too long to answer.",
    "unreachable": "Could not connect to the site.",
    "dns": "The site's name could not be looked up.",
    "tls": "The secure connection to the site failed.",
    "blocked_target": "CrawlR only connects to public internet hosts.",
    "failed": "The check could not be completed.",
    "unknown_site": "CrawlR only checks links on sites its tools know.",
    "handle_not_in_url": "This link does not name this handle, so it was not checked.",
    "bad_link": "This link is not a plain http or https address, so it was not checked.",
    "throttled": "CrawlR has checked this site many times in the last minute, so this link was not checked this time.",
    # no_public_url
    "no_profile_page": "This site has no public profile page to check.",
    "homepage_link": "This link points at the site's homepage, not at a profile.",
}
# core.errors code -> evidence key, for a fetch that raised.
_ERROR_EVIDENCE = {
    "timeout": "timeout", "unreachable": "unreachable", "dns": "dns", "tls": "tls",
    "blocked_target": "blocked_target", "bad_response": "unreadable",
}

# --------------------------------------------------------------------------------------
# Sites with no public page per handle
# --------------------------------------------------------------------------------------
HINTS = {
    "discord": "Discord has no public profile page. Search the handle inside the app or ask for the numeric user ID.",
    "whatsapp": "WhatsApp accounts are phone numbers, not handles. There is no public page to open.",
    "signal": "Signal has no public profiles. A handle can only be looked up inside the app by someone who knows it exactly.",
    "skype": "Skype has no public profile page. Search the name in the Skype or Teams directory while signed in.",
    "cashapp": "Cash App shows a page only at cash.app/$cashtag. Look the cashtag up inside the app to see the name on it.",
}
DEFAULT_HINT = "This link is the site's homepage. Search the handle on the site itself."

_NO_PROFILE_HOSTS = {
    "discord.com": "discord", "discordapp.com": "discord", "discord.gg": "discord",
    "whatsapp.com": "whatsapp", "wa.me": "whatsapp",
    "signal.org": "signal", "signal.me": "signal",
    "skype.com": "skype",
}


def _site_key(site: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (site or "").lower())


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _bare(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def _subdomain_labels(host: str) -> list[str]:
    """The labels in front of the registrable domain, without "www". For torvalds.substack.com
    that is ["torvalds"]; for www.reddit.com and reddit.com it is []."""
    host = (host or "").lower().rstrip(".")
    reg = registrable_domain(host)
    if not reg or not host.endswith(reg):
        return []
    return [label for label in host[: -len(reg)].rstrip(".").split(".") if label and label != "www"]


def _handle_is_subdomain(host: str, username: str) -> bool:
    return bool(username) and username.lower() in _subdomain_labels(host)


def _no_profile_kind(site: str, url: str) -> str:
    """'' when the link can be checked, else the key of the hint that explains why not."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return "homepage"
    host = (parts.hostname or "").lower().rstrip(".")
    reg = registrable_domain(host)
    key = _site_key(site)
    if reg == "cash.app" or key in ("cashapp", "cashme"):
        # The one public Cash App page is cash.app/$cashtag.
        return "" if reg == "cash.app" and re.match(r"^/\$[^/]+", unquote(parts.path)) else "cashapp"
    if reg in _NO_PROFILE_HOSTS:
        return _NO_PROFILE_HOSTS[reg]
    if key in ("discord", "whatsapp", "skype"):
        return key
    if key == "signal" and reg != "signalusers.org":      # Sherlock's "Signal" is the community forum
        return "signal"
    return ""


def has_public_profile_url(site: str, url: str, username: str = "") -> bool:
    """False when there is nothing to open: the site has no page per handle, or the link is a
    bare homepage. A bare path still counts when the handle is a subdomain in front of the
    site's own name (torvalds.substack.com), never when it is part of that name or "www"."""
    if _no_profile_kind(site, url):
        return False
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return False
    if parts.path in ("", "/") and not parts.query:
        return _handle_is_subdomain(parts.hostname or "", username)
    return True


def how_to_check(site: str, url: str = "") -> str:
    """A short hint for checking by hand a site that has no public page per handle."""
    kind = _no_profile_kind(site, url) or _site_key(site)
    if kind == "cashme":
        kind = "cashapp"
    return HINTS.get(kind, DEFAULT_HINT)


# --------------------------------------------------------------------------------------
# Rules. Keyed by host: the caller supplies the site name, so it is never trusted to pick one.
# In every pattern `{u}` is the handle, regex-escaped and matched without regard to case.
#
#   hosts        hostnames the rule covers (subdomains included); the longest match wins
#   found        [(field, pattern)]  a marker the site wrote that names this handle -> verified
#   not_found    [(field, pattern)]  the site's own "no such user" page, RECORDED in
#                tests/fixtures/links -> not_found. Only rules with src "recorded" may have it.
#   looks_absent [(field, pattern)]  a no-such-user page taken from Sherlock's or Maigret's
#                data or from memory, never recorded here -> unknown, with a note
#   wall         [(field, pattern)]  login, consent or bot wall -> blocked
#   generic      False when the site's titles name the handle whether or not it exists, so
#                the generic title reading must not be used
#   trust_404    False when the site sends 404 for pages that do exist (to servers, or for
#                a user with no page), so a 404 proves nothing
#   walled       True when the site usually refuses anonymous server requests
#   src          recorded (tests/fixtures/links), sherlock or maigret (phrases from their
#                site data for the public page), known (a page shape from memory)
#
# Fields: title, og:title, profile:username, twitter:title (html-unescaped), body (raw, whole
# page, for `found` only), head (raw, the first HEAD_BYTES), final_url, and redirected_to (the
# final URL, empty unless a redirect happened). og:url and canonical are not fields: the site
# builds them from the request, so they prove nothing.
# --------------------------------------------------------------------------------------
RULES = [
    {"name": "GitHub", "hosts": ("github.com",), "src": "recorded",
     "found": [("profile:username", r"^{u}$"), ("title", r"^{u}(?: \([^)]{0,120}\))? · GitHub$")]},
    {"name": "GitHub Gist", "hosts": ("gist.github.com",), "src": "known",
     "found": [("title", r"^{u}(?:’|')s gists · GitHub$")]},
    {"name": "GitLab", "hosts": ("gitlab.com",), "src": "recorded", "walled": True,
     # GitLab sends a handle nobody has to its sign-in page, behind a bot check. The generic
     # reading reports that as blocked, which is all it proves.
     "found": [("title", r"^{u} · GitLab$")]},
    {"name": "BitBucket", "hosts": ("bitbucket.org",), "src": "recorded",
     # The title is "Bitbucket" for every workspace; the page data carries the slug.
     "found": [("body", r'"workspace":\s*\{"type":\s*"workspace".{0,300}?"slug":\s*"{u}"')],
     "not_found": [("title", r"^404 \W Bitbucket$")]},
    {"name": "Reddit", "hosts": ("reddit.com",), "src": "recorded", "walled": True,
     # Reddit answered both a real and a missing user with its JavaScript challenge page
     # (HTTP 200), which the bot-check reading below catches. Its real pages were not seen.
     "found": [("title", r"\(u/{u}\)")],
     "looks_absent": [("head", r"Sorry, nobody on Reddit goes by that name\.")]},
    {"name": "Keybase", "hosts": ("keybase.io",), "src": "recorded",
     "found": [("title", r"^{u}(?: \([^)]{0,120}\))? \| Keybase$")]},
    {"name": "DeviantArt", "hosts": ("deviantart.com",), "src": "recorded", "walled": True,
     # Recorded: 403 from the CDN for every request. The pages themselves were not seen.
     "found": [("title", r"^{u}\b.{0,120}\| DeviantArt$")],
     "looks_absent": [("title", r"Llama Not Found")]},
    {"name": "Telegram", "hosts": ("t.me", "telegram.me"), "src": "recorded", "generic": False,
     # Telegram names the handle in the title whether or not anyone has it. An unclaimed
     # handle keeps the placeholder og:title; a real one carries the account's name there.
     "not_found": [("og:title", r"^Telegram: Contact @{u}$")],
     "found": [("title", r"^Telegram: (?:Contact|View) @{u}$")],
     "looks_absent": [("title", r"^Telegram Messenger$")]},
    {"name": "Snapchat", "hosts": ("snapchat.com",), "src": "recorded",
     "found": [("title", r"\(@{u}\) \| Snapchat")]},
    {"name": "CashApp", "hosts": ("cash.app",), "src": "recorded", "trust_404": False, "walled": True,
     # cash.app answered 404 "Page Not Found" for its own cashtag and for a random one.
     "found": [("title", r"\${u}\b.{0,60}Cash App")]},
    {"name": "Giphy", "hosts": ("giphy.com",), "src": "sherlock",
     "looks_absent": [("title", r"^GIFs - Find & Share on GIPHY$")]},
    {"name": "Steam", "hosts": ("steamcommunity.com",), "src": "sherlock",
     # The title carries the display name, not the vanity handle.
     "found": [("body", r"g_rgProfileData[^;]{0,200}?steamcommunity\.com\\?/id\\?/{u}\\?/")],
     "looks_absent": [("title", r"^Steam Community :: Error$")]},
    {"name": "SoundCloud", "hosts": ("soundcloud.com",), "src": "maigret",
     "looks_absent": [("title", r"^SoundCloud - Hear the world(?:’|')s sounds$")]},
    {"name": "Twitch", "hosts": ("twitch.tv",), "src": "sherlock",
     "found": [("title", r"^{u} - Twitch$")],
     "looks_absent": [("head", r"content='Twitch is the world&#39;s leading video platform and community for gamers\.'")]},
    {"name": "YouTube", "hosts": ("youtube.com",), "src": "known",
     # The title carries the channel name, not the handle.
     "found": [("body", r'"vanityChannelUrl":"https?://www\.youtube\.com/@{u}"'),
               ("body", r'"canonicalBaseUrl":"/@{u}"')],
     "wall": [("final_url", r"^https://consent\.(?:youtube|google)\.com/")]},
    {"name": "Bluesky", "hosts": ("bsky.app",), "src": "known",
     "found": [("title", r"@{u}\.bsky\.social\b"), ("og:title", r"@{u}\.bsky\.social\b"), ("title", r"\(@{u}\)")]},
    # These four answer servers with a bot check, and nothing they put in the page head
    # beyond og:url names the handle, so there is no marker to read.
    {"name": "Medium", "hosts": ("medium.com",), "src": "known", "walled": True},
    {"name": "Patreon", "hosts": ("patreon.com",), "src": "known", "walled": True},
    {"name": "Kick", "hosts": ("kick.com",), "src": "known", "walled": True},
    {"name": "VK", "hosts": ("vk.com", "vk.ru"), "src": "known", "walled": True},
    {"name": "Pinterest", "hosts": ("pinterest.com",), "src": "maigret",
     "found": [("title", r"\({u}\)\s*[-\N{EN DASH}|]\s*(?:Profile\s*\|\s*)?Pinterest")],
     "looks_absent": [("head", r"<h\d[^>]*>User not found\.</h\d>")]},
    {"name": "WordPress", "hosts": ("wordpress.com",), "src": "sherlock",
     "looks_absent": [("redirected_to", r"^https?://(?:www\.)?wordpress\.com/typo/?(?:\?|$)")]},
    {"name": "Itch.io", "hosts": ("itch.io",), "src": "known",
     "found": [("title", r"^{u} - itch\.io$")]},
    {"name": "Wikipedia", "hosts": ("wikipedia.org",), "src": "sherlock", "generic": False, "trust_404": False,
     # Special:CentralAuth echoes the name it was asked for, and a missing User: page is a
     # 404 even when the account exists.
     "looks_absent": [("head", r"centralauth-admin-nonexistent:")]},
    {"name": "Codecademy", "hosts": ("codecademy.com",), "src": "sherlock",
     "looks_absent": [("head", r"This profile could not be found")]},
    {"name": "Dribbble", "hosts": ("dribbble.com",), "src": "sherlock",
     "looks_absent": [("head", r"Whoops, that page is gone\.")]},
    {"name": "Pastebin", "hosts": ("pastebin.com",), "src": "sherlock",
     "found": [("title", r"^{u}(?:'|’)s Pastebin - Pastebin\.com$")],
     "looks_absent": [("head", r"Not Found \(#404\)")]},
    {"name": "Slashdot", "hosts": ("slashdot.org",), "src": "sherlock",
     "looks_absent": [("head", r"user you requested does not exist")]},
    {"name": "LibraryThing", "hosts": ("librarything.com",), "src": "sherlock",
     "looks_absent": [("head", r"<p>Error: This user doesn't exist</p>")]},
    {"name": "Houzz", "hosts": ("houzz.com",), "src": "maigret",
     "looks_absent": [("head", r"The page you requested was not found\.")]},
    {"name": "Ko-fi", "hosts": ("ko-fi.com",), "src": "sherlock", "walled": True,
     # Sherlock's data: a handle nobody has is redirected to https://ko-fi.com/art?=redirect.
     "looks_absent": [("redirected_to", r"^https://ko-fi\.com/art/?\?=redirect$")]},
    {"name": "Hugging Face", "hosts": ("huggingface.co",), "src": "known",
     "found": [("title", r"^{u} \([^)]{0,120}\)$")]},
    {"name": "OpenStreetMap", "hosts": ("openstreetmap.org",), "src": "known",
     "found": [("title", r"^{u} \| OpenStreetMap$")]},
    {"name": "Scratch", "hosts": ("scratch.mit.edu",), "src": "known",
     "found": [("title", r"^{u} on Scratch$")]},
    {"name": "Last.fm", "hosts": ("last.fm",), "src": "known",
     "found": [("title", r"^{u}(?:’|')s Music Profile \| Last\.fm$")]},
    {"name": "Chess", "hosts": ("chess.com",), "src": "known", "walled": True,
     "found": [("title", r"^{u} - Chess Profile\b")]},
    {"name": "Codewars", "hosts": ("codewars.com",), "src": "known",
     "found": [("title", r"^{u} \| Codewars$")]},
    {"name": "Mastodon", "hosts": ("mastodon.social", "pixelfed.social"), "src": "known",
     "found": [("og:title", r"\(@{u}@[a-z0-9.-]+\)"), ("title", r"\(@{u}@[a-z0-9.-]+\)")]},
    {"name": "Trello", "hosts": ("trello.com",), "src": "known",
     "found": [("title", r"\({u}\) \| Trello$")]},
    {"name": "Disqus", "hosts": ("disqus.com",), "src": "known",
     "found": [("title", r"^Disqus Profile - {u}$")]},
    {"name": "Freesound", "hosts": ("freesound.org",), "src": "known",
     "found": [("title", r"^Freesound - {u}$")]},
    {"name": "RubyGems", "hosts": ("rubygems.org",), "src": "known",
     "found": [("title", r"^Profile of {u} \| RubyGems\.org\b")]},
    {"name": "Docker Hub", "hosts": ("hub.docker.com",), "src": "known",
     "found": [("title", r"^{u}(?:'|’)s Profile \| Docker Hub$")]},
    {"name": "PayPal", "hosts": ("paypal.com",), "src": "maigret", "walled": True,
     "looks_absent": [("head", r'<div class="row error404"')]},
]
_RULE_FIELDS = ("title", "og:title", "profile:username", "twitter:title", "body", "head", "final_url", "redirected_to")

# The six big social sites are read with platform_check's recorded rules. Its "not found" is
# provisional there (confirmed by a canary request), and this module makes one request per
# link, so that page is reported as ambiguous here.
_PC_HOSTS = {
    "facebook.com": "Facebook", "instagram.com": "Instagram", "x.com": "X", "twitter.com": "X",
    "threads.com": "Threads", "threads.net": "Threads", "tiktok.com": "TikTok", "linkedin.com": "LinkedIn",
}
_PC_RULES = {r["name"]: r for r in pc.RULES}

# Registrable domains that are the same site under two names.
ALIASES = [
    {"twitter.com", "x.com"},
    {"threads.net", "threads.com"},
    {"vk.com", "vk.ru"},
    {"facebook.com", "fb.com"},
    {"t.me", "telegram.me"},
    {"youtube.com", "youtu.be"},
]


def same_site(a_url: str, b_url: str) -> bool:
    a, b = registrable_domain(_host(a_url)), registrable_domain(_host(b_url))
    if not a or not b:
        return False
    return a == b or any(a in group and b in group for group in ALIASES)


# --------------------------------------------------------------------------------------
# Sherlock's and Maigret's site data: the allowlist, and Sherlock's no-such-user phrases
# --------------------------------------------------------------------------------------
MIN_PHRASE = 12       # shorter phrases ("404", "Error!", "Sorry.") say nothing


def _package_data(package: str) -> str:
    try:
        spec = importlib.util.find_spec(package)
    except (ImportError, ValueError):
        return ""
    if not spec or not spec.origin:
        return ""
    return os.path.join(os.path.dirname(spec.origin), "resources", "data.json")


def _load_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _template_regex(template: str) -> re.Pattern | None:
    """Sherlock's URL template as a pattern over a normalized URL (see _norm_url)."""
    norm = _norm_url(template.replace("{}", "\x00"))
    if "\x00" not in norm:
        return None
    return re.compile("^" + re.escape(norm).replace("\x00", r"[^/?#&=]+") + "$")


def _norm_url(url: str) -> str:
    """host/path?query, lowercase, without scheme, "www." or a trailing slash. For comparing
    two addresses of the same page, never as a cache key."""
    u = re.sub(r"^https?://", "", (url or "").strip(), flags=re.I)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return u.split("#")[0].rstrip("/").lower()


def load_sherlock_rules(path: str | None = None) -> dict[str, list[dict]]:
    """{registrable domain: [rule]} from Sherlock's data.json: the phrases its "message" sites
    show for a handle nobody has. Only entries that describe the public page are kept: a check
    made against an API probe or with POST says nothing about what the profile URL returns.
    These phrases were never recorded here, so they can only produce the unconfirmed hint."""
    out: dict[str, list[dict]] = {}
    for name, entry in _load_json(path or _package_data("sherlock_project")).items():
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        if entry.get("urlProbe") or str(entry.get("request_method") or "GET").upper() != "GET":
            continue
        if entry.get("errorType") != "message":
            continue          # status_code sites are covered by the 404 reading; redirects prove nothing
        template = _template_regex(entry["url"])
        reg = registrable_domain(_host(entry["url"].replace("{}", "x")))
        msgs = entry.get("errorMsg")
        msgs = [msgs] if isinstance(msgs, str) else list(msgs or [])
        phrases = [m for m in msgs if isinstance(m, str) and len(m.strip()) >= MIN_PHRASE]
        if template and reg and phrases:
            out.setdefault(reg, []).append({"name": name, "match": template, "phrases": phrases})
    return out


def load_known_sites(sherlock_path: str | None = None, maigret_path: str | None = None) -> set[str]:
    """Registrable domains of every site Sherlock, Maigret or this app has a profile URL for.
    A link anywhere else is not fetched."""
    sites: set[str] = set(_PC_HOSTS)
    for group in ALIASES:
        sites.update(group)
    for rule in RULES:
        sites.update(registrable_domain(h) for h in rule["hosts"])

    def add(value) -> None:
        if isinstance(value, str) and value.lower().startswith(("http://", "https://")):
            reg = registrable_domain(_host(value.replace("{username}", "x").replace("{}", "x")))
            if reg and "." in reg and "{" not in reg:
                sites.add(reg)

    for entry in _load_json(sherlock_path or _package_data("sherlock_project")).values():
        if isinstance(entry, dict):
            add(entry.get("url"))
            add(entry.get("urlMain"))
    maigret = _load_json(maigret_path or _package_data("maigret")).get("sites")
    for entry in (maigret.values() if isinstance(maigret, dict) else ()):
        if isinstance(entry, dict):
            add(entry.get("url"))
            add(entry.get("urlMain"))
    return sites


SHERLOCK_RULES = load_sherlock_rules()
KNOWN_SITES = load_known_sites()


def _hand_rule(host: str) -> dict | None:
    best, best_len = None, -1
    for rule in RULES:
        for h in rule["hosts"]:
            if (host == h or host.endswith("." + h)) and len(h) > best_len:
                best, best_len = rule, len(h)
    return best


def _sherlock_rule(url: str) -> dict | None:
    norm = _norm_url(url)
    for rule in SHERLOCK_RULES.get(registrable_domain(_host(url)), ()):
        if rule["match"].match(norm):
            return rule
    return None


def rule_counts() -> dict:
    """How many sites each rule source covers. Used by the tests and the docs."""
    sherlock = [r for reg, rules in SHERLOCK_RULES.items() for r in rules if not _hand_rule(reg) and reg not in _PC_HOSTS]
    return {
        "hand_written": len(RULES), "platform_check": len(_PC_RULES), "sherlock": len(sherlock),
        "known_sites": len(KNOWN_SITES),
        "can_conclude_not_found": sorted(r["name"] for r in RULES if r.get("not_found")),
    }


# --------------------------------------------------------------------------------------
# Reading a page
# --------------------------------------------------------------------------------------
_TITLE = re.compile(r"<title[^>]*>([^<]{0,300})</title>", re.I)
_META = re.compile(r"<meta\s[^>]*>", re.I)
_ATTR = re.compile(r"""([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_HEAD_FIELDS = ("og:title", "profile:username", "twitter:title")

_CHALLENGE_TITLE = re.compile(
    r"^\s*(?:just a moment|attention required|access denied|access to this page has been denied|security check"
    r"|are you a robot|robot check|human verification|verif(?:y|ying) (?:that )?you are (?:a )?human"
    r"|pardon our interruption|one more step|checking your browser|captcha"
    r"|error: the request could not be satisfied)", re.I)
_CHALLENGE_BODY = ("_cf_chl_opt", "cf-browser-verification", "captcha-delivery.com", "px-captcha", 'name="js_challenge"')
_LOGIN_TITLE = re.compile(r"^\s*(?:log ?in|sign ?in|login|sign up|create (?:an |your )?account|join)\b", re.I)
_NEGATIVE_TITLE = re.compile(
    r"not found|\b404\b|\berrors?\b|\bsearch\b|sign ?in|log ?in|sign up|doesn(?:'|’)t exist|does not exist|no such"
    r"|unavailable|suspended|deleted|banned|removed|no longer", re.I)
_SOFT_404_TITLE = re.compile(
    r"^\s*(?:404\b|(?:error )?404 |not found\b|(?:page|user|profile|account|member|channel) (?:was |is )?not found\b)"
    r"|\b(?:page|user|profile|account|member) not found\b", re.I)

_LOGIN_PATH = re.compile(
    r"/(?:log[-_]?in|sign[-_]?in|sign[-_]?up|signup|register|registration|authwall|auth|sso|checkpoint|challenge|consent)"
    r"(?:[/?.]|$)", re.I)
_LOGIN_LABELS = {"login", "accounts", "account", "auth", "sso", "signin", "id", "consent", "passport"}
_NOT_FOUND_PATH = re.compile(r"/(?:404|not[-_]?found|notfound|error|errors|error404|fourohfour|missing)(?:[/?.]|$)", re.I)
_SEARCH_PATH = re.compile(r"/search(?:[/?.]|$)", re.I)

# Handles that are also words a site puts in its own titles. The generic reading cannot tell
# "user" the account from "User profile", so it never verifies these.
STOPLIST = frozenset("""
    user users username profile profiles account accounts member members admin administrator root
    home index main page pages login logout signin signup register join search about help support
    contact info news blog blogs forum forums post posts error errors null none nil undefined
    test tests testing demo example guest anonymous anon unknown deleted default new official
    settings staff team mod moderator api app apps web www site the and you your name title
""".split())


def page_fields(final_url: str, body: str, redirected: bool = False) -> dict:
    """The few fields the rules read, html-unescaped. `body` and `head` stay raw."""
    body = body or ""
    fields = {"final_url": final_url or "", "redirected_to": (final_url or "") if redirected else "",
              "body": body, "head": body[:HEAD_BYTES], "title": ""}
    fields.update({k: "" for k in _HEAD_FIELDS})
    m = _TITLE.search(body)
    if m:
        fields["title"] = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
    for tag in _META.findall(body):
        attrs = {k.lower(): (a or b) for k, a, b in _ATTR.findall(tag)}
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        if key in _HEAD_FIELDS and not fields[key]:
            fields[key] = html.unescape(attrs.get("content", "")).strip()
    return fields


def _token(username: str) -> re.Pattern:
    """The handle as a whole token: not part of a longer name or a dotted one."""
    return re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(username) + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])", re.I)


def _handle_position(username: str) -> re.Pattern:
    """The handle where a site writes a handle: "@u", "(u)", "(@u)", or the very start of the
    title followed by a separator or the end. "John Smith (@johnsmith99)" does not name john."""
    u = re.escape(username)
    return re.compile(
        r"(?<![A-Za-z0-9_.-])@" + u + r"(?![A-Za-z0-9_-]|\.[A-Za-z0-9])"
        r"|\(@?" + u + r"\)"
        r"|^" + u + r"(?:\s*$|\s*[|·•:(]|\s+[-\N{EN DASH}\N{EM DASH}/]\s)", re.I)


def _url_text(url: str) -> tuple[str, str, str]:
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return "", "", ""
    return (parts.hostname or "").lower(), unquote(parts.path or ""), unquote(parts.query or "")


def _is_homepage(url: str, username: str) -> bool:
    host, path, query = _url_text(url)
    return path in ("", "/") and not _handle_is_subdomain(host, username) and not _token(username).search(query)


def _names_handle(url: str, username: str) -> bool:
    host, path, query = _url_text(url)
    tok = _token(username)
    return _handle_is_subdomain(host, username) or bool(tok.search(path) or tok.search(query))


def url_names_handle(url: str, username: str) -> bool:
    """Does the link itself name the handle: as a subdomain, in the path or in the query?
    Looser than _names_handle (a dotted suffix such as torvalds.bsky.social still counts),
    because this only decides whether the link is worth opening for this handle."""
    host, path, query = _url_text(url)
    if _handle_is_subdomain(host, username):
        return True
    loose = re.compile(r"(?<![A-Za-z0-9])" + re.escape(username) + r"(?![A-Za-z0-9])", re.I)
    return bool(username) and bool(loose.search(path) or loose.search(query))


def _still_profile(requested: str, final: str, username: str) -> bool:
    """Is the address after redirects still a profile address for this handle?"""
    if not same_site(requested, final):
        return False
    if _names_handle(final, username):
        return True
    # The same page or one below it (for handles written as part of a longer name in the path).
    _, rpath, _ = _url_text(requested)
    _, fpath, _ = _url_text(final)
    rpath, fpath = rpath.rstrip("/").lower(), fpath.rstrip("/").lower()
    return bool(rpath) and username.lower() in rpath and (fpath == rpath or fpath.startswith(rpath + "/"))


def _match(rules, fields: dict, username: str) -> bool:
    u = re.escape(username)
    for field, pattern in rules or ():
        if re.search(pattern.replace("{u}", u), fields.get(field, ""), re.I):
            return True
    return False


def _verdict(state: str, key: str) -> dict:
    return {"state": state, "evidence_key": key}


def _generic_handle_ok(username: str, requested_url: str, site: str) -> bool:
    """Can a title naming this handle mean anything? Not when the handle is short, a common
    site word, or the site's own name."""
    u = username.lower()
    if len(u) < 3 or u in STOPLIST:
        return False
    reg = registrable_domain(_host(requested_url))
    if u in reg.split(".") or _site_key(u) == _site_key(reg.split(".")[0]):
        return False
    if site and _site_key(site) == _site_key(u):
        return False
    return True


def _generic_marker(fields: dict, username: str) -> bool:
    """The handle in a handle position in the title or og:title. A title that reads like an
    error, search or sign-in page rules it out."""
    title, og = fields["title"], fields["og:title"]
    if _NEGATIVE_TITLE.search(title) or _NEGATIVE_TITLE.search(og):
        return False
    pos = _handle_position(username)
    return bool(pos.search(title) or pos.search(og))


def classify(username: str, requested_url: str, status: int, final_url: str, body: str,
             headers: dict | None = None, site: str = "") -> dict:
    """Decide a state from one response. Pure: no network, so it is tested from fixtures.

    Returns {state, evidence_key}. `evidence_key` is a key of EVIDENCE. "not_found" comes
    only from HTTP 404 or 410 or from a recorded rule's `not_found` marker.
    """
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    final_url = final_url or requested_url
    host = _bare(_host(requested_url))
    reg = registrable_domain(host)
    moved = _norm_url(final_url) != _norm_url(requested_url)
    fields = page_fields(final_url, body, redirected=moved)
    hand = _hand_rule(host)
    title = fields["title"]

    # 1. A bot check, whatever the status.
    if (headers.get("cf-mitigated", "").lower() == "challenge" or _CHALLENGE_TITLE.search(title)
            or any(marker in fields["head"] for marker in _CHALLENGE_BODY)):
        return _verdict("blocked", "challenge")

    # 2. The six sites platform_check already has recorded rules for.
    if reg in _PC_HOSTS:
        return _classify_platform(_PC_RULES[_PC_HOSTS[reg]], username, requested_url, status, final_url, body)

    # 3. What the status alone proves.
    if status in (404, 410):
        if hand and hand.get("trust_404") is False:
            return _verdict("unknown", "ambiguous_page")
        return _verdict("not_found", "http_404" if status == 404 else "http_410")
    if status in REFUSED:
        return _verdict("blocked", "refused")
    if not 200 <= status < 300:
        return _verdict("unknown", "http_error")

    # 4. A redirect to a sign-in page, or the site's own wall.
    fhost, fpath, _fquery = _url_text(final_url)
    _rhost, rpath, _rquery = _url_text(requested_url)
    if moved and not _LOGIN_PATH.search(rpath) and (
            _LOGIN_PATH.search(fpath) or (not same_site(requested_url, final_url) and _LOGIN_LABELS.intersection(fhost.split(".")))):
        return _verdict("blocked", "to_login")
    if hand and _match(hand.get("wall"), fields, username):
        return _verdict("blocked", "login_wall")

    # 5. A recorded no-such-user page. These read the title and head tags, never user text.
    if hand and hand.get("src") == "recorded" and _match(hand.get("not_found"), fields, username):
        return _verdict("not_found", "soft_404")

    # 6. A redirect away from the profile. None of these says the account is missing: a
    #    members-only site sends visitors home, and /error can be a rate limit.
    if moved:
        if not same_site(requested_url, final_url):
            return _verdict("unknown", "off_site")
        if hand and _match([r for r in hand.get("looks_absent", ()) if r[0] == "redirected_to"], fields, username):
            return _verdict("unknown", "unconfirmed_soft_404")
        if _is_homepage(final_url, username):
            return _verdict("unknown", "to_homepage")
        if _NOT_FOUND_PATH.search(fpath) and not _NOT_FOUND_PATH.search(rpath):
            return _verdict("unknown", "to_not_found")
        if _SEARCH_PATH.search(fpath) and not _SEARCH_PATH.search(rpath):
            return _verdict("unknown", "to_search")

    # 7. A marker that names the handle, on an address that is still the handle's. This comes
    #    before any unrecorded no-such-user phrase.
    still = _still_profile(requested_url, final_url, username)
    if hand and _match(hand.get("found"), fields, username):
        return _verdict("verified", "site_marker") if still else _verdict("unknown", "moved")
    generic = not (hand and hand.get("generic") is False)
    if generic and still and _generic_handle_ok(username, requested_url, site) and _generic_marker(fields, username):
        return _verdict("verified", "page_names_handle")

    # 8. Something that looks like a no-such-user page, by a rule nobody recorded.
    if hand:
        looks_absent = _match(hand.get("looks_absent"), fields, username)
    else:
        sherlock = _sherlock_rule(requested_url)
        looks_absent = bool(sherlock) and any(phrase in fields["head"] for phrase in sherlock["phrases"])
    if looks_absent or (generic and _SOFT_404_TITLE.search(title)):
        return _verdict("unknown", "unconfirmed_soft_404")
    if _LOGIN_TITLE.search(title):
        return _verdict("blocked", "login_wall")

    if not (body or "").strip():
        return _verdict("unknown", "unreadable")
    if not still:
        return _verdict("unknown", "moved")
    if hand and hand.get("walled"):
        return _verdict("unknown", "walled_site")
    return _verdict("unknown", "no_marker")


def _classify_platform(rule: dict, username: str, requested_url: str, status: int, final_url: str, body: str) -> dict:
    got = pc.classify_page(rule, username, status, final_url, body)
    state = got["state"]
    if state == "found":
        return _verdict("verified", "site_marker") if _still_profile(requested_url, final_url, username) else _verdict("unknown", "moved")
    if state == "blocked":
        return _verdict("blocked", "refused" if status in REFUSED else "login_wall")
    if state == "not_found" or status in (404, 410):
        return _verdict("unknown", "ambiguous_page")
    if status >= 500:
        return _verdict("unknown", "http_error")
    return _verdict("unknown", "walled_site")


# --------------------------------------------------------------------------------------
# Which links are opened at all
# --------------------------------------------------------------------------------------
def refusal(username: str, url: str) -> str:
    """'' when the link may be fetched, else the evidence key that says why not."""
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return "bad_link"
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username or parts.password or port is not None:
        return "bad_link"
    if registrable_domain(parts.hostname.lower().rstrip(".")) not in KNOWN_SITES:
        return "unknown_site"
    if not url_names_handle(url, username):
        return "handle_not_in_url"
    return ""


# Requests per site across all calls, so the endpoint cannot be used to hammer one site.
_site_hits: "OrderedDict[str, deque]" = OrderedDict()
_SITE_HITS_MAX = 5000


def _throttle_take(site: str) -> bool:
    """Record one request to `site`. False when it has had SITE_RATE in the last SITE_WINDOW."""
    now = time.monotonic()
    hits = _site_hits.get(site)
    if hits is None:
        hits = _site_hits[site] = deque()
    _site_hits.move_to_end(site)
    while hits and hits[0] <= now - SITE_WINDOW:
        hits.popleft()
    if len(hits) >= SITE_RATE:
        return False
    hits.append(now)
    while len(_site_hits) > _SITE_HITS_MAX:
        _site_hits.popitem(last=False)
    return True


# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------
class _CappedTransport(httpx.AsyncBaseTransport):
    """Reads at most MAX_BODY bytes of a response and stops. A gzip body is decompressed here
    with the same limit on its output, so a small download cannot expand without bound."""

    def __init__(self, inner: httpx.AsyncBaseTransport):
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        resp = await self._inner.handle_async_request(request)
        chunks, seen = [], 0
        try:
            async for chunk in resp.stream:
                chunks.append(chunk)
                seen += len(chunk)
                if seen >= MAX_BODY:
                    break
        finally:
            await resp.aclose()
        raw = b"".join(chunks)[:MAX_BODY]
        encoding = (resp.headers.get("content-encoding") or "identity").strip().lower()
        unreadable = False
        if encoding in ("gzip", "x-gzip", "deflate"):
            try:
                raw = zlib.decompressobj(47).decompress(raw, MAX_BODY)      # 47: gzip or zlib header
            except zlib.error:
                try:
                    raw = zlib.decompressobj(-15).decompress(raw, MAX_BODY)   # raw deflate
                except zlib.error:
                    raw, unreadable = b"", True
        elif encoding not in ("", "identity"):
            raw, unreadable = b"", True          # an encoding that was not asked for
        headers = [(k, v) for k, v in resp.headers.items()
                   if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
        return httpx.Response(
            resp.status_code, headers=headers, content=raw, request=request,
            extensions={**resp.extensions, "crawlr_unreadable": unreadable},
        )

    async def aclose(self):
        await self._inner.aclose()


def _inner_transport() -> httpx.AsyncBaseTransport:
    """The real network transport. Tests replace this with a mock."""
    return httpx.AsyncHTTPTransport(retries=0)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=_CappedTransport(_inner_transport()), timeout=TIMEOUT)


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[int, str, str, dict, bool]:
    """One guarded GET. Returns (status, final url, text, headers, unreadable)."""
    got = await safe_fetch(client, url, headers=HEADERS, max_redirects=MAX_REDIRECTS)
    resp = got.response
    charset = resp.charset_encoding or "utf-8"
    try:
        text = resp.content.decode(charset, errors="replace")
    except LookupError:
        text = resp.content.decode("utf-8", errors="replace")
    return resp.status_code, got.url, text, dict(resp.headers), bool(resp.extensions.get("crawlr_unreadable"))


async def _verify(client: httpx.AsyncClient, username: str, url: str, site: str) -> dict:
    try:
        status, final_url, body, headers, unreadable = await asyncio.wait_for(_fetch(client, url), TOTAL_TIMEOUT)
    except httpx.TooManyRedirects:
        return {**_verdict("unknown", "redirect_loop"), "final_url": ""}
    except Exception as e:  # noqa: BLE001 - every failure becomes an "unknown" row with a code
        # Only the code is kept: the exception text can hold the URL.
        code = error_fields(e, detail=type(e).__name__)["error_code"]
        return {**_verdict("unknown", _ERROR_EVIDENCE.get(code, "failed")), "error_code": code, "final_url": ""}
    if unreadable and 200 <= status < 300:
        return {**_verdict("unknown", "unreadable"), "final_url": ""}
    return {**classify(username, url, status, final_url, body, headers, site), "final_url": final_url}


def _public_final_url(requested: str, final: str) -> str:
    """The address to show for a verified link: same site only, no credentials, no fragment."""
    try:
        parts = urlsplit(final or "")
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return ""
    if not same_site(requested, final):
        return ""
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    if len(clean) > MAX_URL or re.search(r"[\s<>\"'`\\]|[\x00-\x1f]", clean):
        return ""
    return clean


def _row(verdict: dict, requested: str) -> dict:
    state = verdict["state"]
    row = {
        "state": state,
        "final_url": _public_final_url(requested, verdict.get("final_url", "")) if state == "verified" else "",
        "evidence": EVIDENCE[verdict["evidence_key"]],
    }
    if verdict.get("error_code"):
        row["error_code"] = verdict["error_code"]
    return row


def _plain(key: str, state: str = "unknown") -> dict:
    """A row that was decided without a request. Never cached."""
    return {"state": state, "final_url": "", "evidence": EVIDENCE[key], "cached": False}


# --------------------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------------------
_cache: "OrderedDict[tuple[str, str], tuple[float, dict]]" = OrderedDict()


def clear_cache_for_tests() -> None:
    _cache.clear()
    _site_hits.clear()


def _cache_key(username: str, url: str) -> tuple[str, str]:
    """The URL exactly as it will be requested, and the handle exactly as given. Only the
    scheme and host are lowercased (they are case-insensitive on the wire) and the fragment
    is dropped (it is never sent). Path and query keep their case: /U/VICTIM and /u/victim
    can be different pages, and one must not answer for the other."""
    try:
        parts = urlsplit(url)
        key = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))
    except ValueError:
        key = url
    return (key, username)


def _cache_get(key: tuple[str, str]) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ttl = CACHE_TTL if hit[1]["state"] in ("verified", "not_found") else min(CACHE_TTL, CACHE_TTL_SOFT)
    if time.time() - hit[0] > ttl:
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
# Entry point
# --------------------------------------------------------------------------------------
async def _one(client: httpx.AsyncClient, sem: asyncio.Semaphore, site_sems: dict, username: str, url: str, site: str) -> dict:
    key = _cache_key(username, url)
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}
    reg = registrable_domain(_host(url))
    site_sem = site_sems.setdefault(reg, asyncio.Semaphore(PER_SITE))
    async with site_sem, sem:
        cached = _cache_get(key)          # another link in this call may have just answered it
        if cached is not None:
            return {**cached, "cached": True}
        if not _throttle_take(reg):
            return _plain("throttled")
        row = _row(await _verify(client, username, url, site), url)
        _cache_put(key, row)
    return {**row, "cached": False}


async def run_link_verify(username: str, links: list[dict]) -> dict:
    """links: [{id, site, url}] -> {"results": [{id, state, final_url, evidence, cached}]}.

    `username` has been through core.validate.username. A link with nothing to open gets
    `no_public_url` and a `hint`. A link on a site the tools do not know, one that does not
    name the handle, or one that is not a plain http(s) address is `unknown` with no request.
    """
    items = [(str(i.get("id") or ""), str(i.get("site") or ""), str(i.get("url") or "").strip())
             for i in (links or [])[:MAX_LINKS]]
    fixed: dict[int, dict] = {}
    todo: dict[str, str] = {}             # url -> site name, first seen
    for n, (_id, site, url) in enumerate(items):
        why = refusal(username, url)
        if why == "bad_link":
            fixed[n] = _plain("bad_link")
        elif not has_public_profile_url(site, url, username):
            kind = _no_profile_kind(site, url)
            fixed[n] = {**_plain("no_profile_page" if kind else "homepage_link", "no_public_url"), "hint": how_to_check(site, url)}
        elif why:
            fixed[n] = _plain(why)
        else:
            todo.setdefault(url, site)

    by_url: dict[str, dict] = {}
    if todo:
        sem = asyncio.Semaphore(CONCURRENCY)
        site_sems: dict[str, asyncio.Semaphore] = {}
        async with _client() as client:
            tasks = {url: asyncio.ensure_future(_one(client, sem, site_sems, username, url, site)) for url, site in todo.items()}
            _done, pending = await asyncio.wait(tasks.values(), timeout=CALL_DEADLINE)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        for url, task in tasks.items():
            if task.cancelled() or task.exception() is not None:
                by_url[url] = _plain("timeout" if task.cancelled() else "failed")
            else:
                by_url[url] = task.result()

    results = [{"id": id_, **(fixed[n] if n in fixed else by_url[url])} for n, (id_, _site, url) in enumerate(items)]
    # Counts only: no handle, site or URL is logged.
    log.info("link verify", extra={"links": len(items), "fetched": sum(1 for r in by_url.values() if not r["cached"])})
    return {"results": results}
