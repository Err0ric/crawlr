"""
Shared pieces for the profile sources in this package.

Every source asks one fixed host for one handle and hands back a `Result`:

  found         a record was read; `profile` holds the normalised row
  not_found     the API's own answer that there is no such account
  blocked       401, 403, or a web page where JSON was expected
  rate_limited  429, or the API's own rate message
  unknown       anything else that is not clear either way
  failed        timeout, 5xx or a body that could not be read (with the error fields)

A 403 or a 429 is never `not_found`.

Everything a source returns is outside data. Text is plain text with control characters removed
and a length cap. Links are http or https only, to a named host, without credentials, and never
to an adult or dating site or to an image file. A profile's own address is built here from a
handle that was checked against the site's handle rule, never copied from the response. The
picture address stays inside the package (`_avatar`): modules/profiles/__init__.py hashes it
through modules/avatar_hash.py and only the hash and the thumbnail leave the server.
"""

import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import httpx

from core import adult_sites
from core.errors import error_fields
from core.validate import EMAIL_RE, HOSTNAME_RE

USER_AGENT = "CrawlR/1.0 (+https://crawlr.lol)"
MAX_BODY = 512 * 1024         # bytes read from one response; a larger body is a failure

NAME_MAX = 100
BIO_MAX = 500                 # what a row shows
GUARD_BIO_MAX = 2000          # what the minor guard reads (core.profile_record.BIO_MAX)
FIELD_MAX = 100
LINK_MAX = 300
NOTE_MAX = 40
MAX_LINKS = 8
MAX_EMAILS = 5
MAX_ACCOUNTS = 25
MAX_ITEMS = 10
MAX_STATS = 8

_BIDI = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\ufeff")
_NOT_IN_A_LINK = frozenset({"Cc", "Cf", "Cs", "Co"})     # control, format, surrogate, private use
_IMAGE_PATH_RE = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|avif|bmp|ico)$", re.I)
_URL_IN_TEXT_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.I)
_EMAIL_IN_TEXT_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
_NOREPLY_RE = re.compile(r"no-?reply", re.I)


class SourceError(Exception):
    """A source could not be read. `code` is a core.errors code; `detail` never holds the handle."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


@dataclass
class Reply:
    status: int
    data: object = None       # the parsed JSON body (which may itself be null)
    parsed: bool = False      # the body was JSON
    walled: bool = False      # the body was a web page
    location: str = ""        # the Location header of a redirect, never followed here
    retry_after: int | None = None   # Retry-After in seconds, when the header is a whole number


@dataclass
class Result:
    state: str
    profile: dict | None = None
    error: dict | None = None
    note: str = ""
    settled: bool | None = None    # None: decided by the state (see modules/profiles/__init__.py)
    # Seconds the site asked this server to wait (Retry-After on a 429), when it said. With it,
    # or with the state rate_limited, the source is not asked again for anyone for a while.
    retry_after: int | None = None
    limited: bool = False          # a request of this read was answered 429, whatever the state


NOT_FOUND = Result("not_found")
UNKNOWN = Result("unknown")
BLOCKED = Result("blocked")


def failed(code: str, detail: str = "") -> Result:
    return Result("rate_limited" if code == "rate_limited" else "failed", error=error_fields(code=code, detail=detail))


async def get_json(client: httpx.AsyncClient, url: str, params: dict | None = None) -> Reply:
    """One GET to a fixed host. Redirects are never followed and the body is capped."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    size, chunks = 0, []
    async with client.stream("GET", url, params=params, headers=headers, follow_redirects=False) as resp:
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > MAX_BODY:
                raise SourceError("bad_response", "response too large")
            chunks.append(chunk)
        status, location = resp.status_code, resp.headers.get("location", "")
        wait = resp.headers.get("retry-after", "").strip()
    retry = int(wait) if wait.isascii() and wait.isdigit() and len(wait) <= 6 else None
    body = b"".join(chunks)
    try:
        return Reply(status, json.loads(body.decode("utf-8")), parsed=True, location=location, retry_after=retry)
    except ValueError:
        return Reply(status, walled=body.lstrip()[:1] == b"<", location=location, retry_after=retry)


def settle(reply: Reply, not_found: tuple[int, ...] = (404,)) -> Result | None:
    """What a reply means when it is not a readable 200. None: go on and read `reply.data`.

    `not_found` is the statuses that are this API's own "no such account". A source whose
    documented absence is a 200 with an empty value (Keybase, Hacker News, GitLab) or a 400
    passes `()`: a 404 from such a host is an edge or a moved API, which is "unknown"."""
    s = reply.status
    if s in not_found:
        return NOT_FOUND
    if s in (401, 403):
        return BLOCKED
    if s == 429:
        return Result("rate_limited", error=error_fields(code="rate_limited", detail="HTTP 429"), retry_after=reply.retry_after, limited=True)
    if s >= 500:
        return failed("upstream", f"HTTP {s}")
    if s != 200:
        return UNKNOWN
    if not reply.parsed:
        return BLOCKED if reply.walled else failed("bad_response", "unreadable body")
    return None


# ---- text ------------------------------------------------------------------------------

def clean(value, cap: int, lines: bool = False) -> str:
    """Plain text: no control characters, no direction overrides, runs of spaces collapsed.
    With `lines`, line breaks are kept (one per line of text); otherwise it is one line."""
    if not isinstance(value, str):
        return ""
    kept = "".join(ch for ch in value if ch in "\n\t " or (unicodedata.category(ch) not in ("Cc", "Cs") and ch not in _BIDI))
    rows = [" ".join(row.split()) for row in kept.split("\n")]
    return ("\n" if lines else " ").join(r for r in rows if r)[:cap].strip()


class _Text(HTMLParser):
    _BREAKS = frozenset({"p", "br", "li", "div", "tr", "blockquote", "h1", "h2", "h3", "pre"})
    _HIDDEN = frozenset({"script", "style"})

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._HIDDEN:
            self._hidden += 1
        elif tag in self._BREAKS:
            self.parts.append("\n")
        elif tag == "a":
            href = dict(attrs).get("href")
            if isinstance(href, str):
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag in self._HIDDEN:
            self._hidden = max(0, self._hidden - 1)
        elif tag in self._BREAKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._hidden:
            self.parts.append(data)


def html_text(value) -> tuple[str, list[str]]:
    """(plain text with one line per block, the addresses its links point at). Tags are dropped,
    entities are decoded, and the content of script and style elements is left out."""
    if not isinstance(value, str) or not value:
        return "", []
    parser = _Text()
    try:
        parser.feed(value)
        parser.close()
    except Exception:  # noqa: BLE001  (a broken fragment is read as far as it goes)
        pass
    return clean("".join(parser.parts), GUARD_BIO_MAX, lines=True), parser.links


def safe_link(value) -> str:
    """An http or https address of a named host, or "". A bare "host/path" gets https. An
    address that holds a control or format character (a direction override, a zero-width
    character) is refused whole: it would not show as the address it is."""
    if not isinstance(value, str):
        return ""
    v = value.strip()
    if not v or len(v) > LINK_MAX or any(ch.isspace() or unicodedata.category(ch) in _NOT_IN_A_LINK for ch in v):
        return ""
    if not re.match(r"^https?://", v, re.I):
        if "://" in v or v.startswith(("/", "@", "#", "mailto:")):
            return ""
        v = "https://" + v
    try:
        parts = urlsplit(v)
        port = parts.port
    except ValueError:
        return ""
    host = parts.hostname or ""
    if parts.username or parts.password or port is not None or not HOSTNAME_RE.fullmatch(host):
        return ""
    if _IMAGE_PATH_RE.search(parts.path) or adult_sites.is_adult_site(url=v):
        return ""
    return v if len(v) <= LINK_MAX else ""


def text_links(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:!?") for m in _URL_IN_TEXT_RE.finditer(text or "")]


def safe_email(value) -> str:
    if not isinstance(value, str):
        return ""
    v = value.strip().strip(".")
    if len(v) > 254 or ".." in v or not EMAIL_RE.fullmatch(v) or _NOREPLY_RE.search(v):
        return ""
    return v


def iso(value) -> str:
    """A date as the API gave it, as ISO 8601: "2015-12-27" or "2015-12-27T10:00:00Z" (UTC).
    Epoch seconds, epoch milliseconds, ISO strings and "Dec 27, 2015" are read. Else ""."""
    when, date_only = None, False
    try:
        if isinstance(value, bool):
            return ""
        if isinstance(value, (int, float)):
            when = datetime.fromtimestamp(value / 1000 if value > 100_000_000_000 else value, timezone.utc)
        elif isinstance(value, str) and value.strip():
            v = value.strip()[:40]
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
                when, date_only = datetime.strptime(v, "%Y-%m-%d").replace(tzinfo=timezone.utc), True
            elif re.fullmatch(r"[A-Z][a-z]{2} \d{1,2}, \d{4}", v):
                when, date_only = datetime.strptime(v, "%b %d, %Y").replace(tzinfo=timezone.utc), True
            else:
                when = datetime.fromisoformat(v.replace("Z", "+00:00"))
                when = (when if when.tzinfo else when.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return ""
    if when is None or not 1990 <= when.year <= datetime.now(timezone.utc).year + 1:
        return ""
    return when.strftime("%Y-%m-%d" if date_only else "%Y-%m-%dT%H:%M:%SZ")


def count(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


# ---- linked accounts -------------------------------------------------------------------

# key -> (site name, handle rule, address built from the handle)
ACCOUNT_SITES = {
    "github": ("GitHub", r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", "https://github.com/{}"),
    "twitter": ("X", r"[A-Za-z0-9_]{1,15}", "https://x.com/{}"),
    "reddit": ("Reddit", r"[A-Za-z0-9_-]{3,20}", "https://www.reddit.com/user/{}"),
    "hackernews": ("Hacker News", r"[A-Za-z0-9_-]{2,15}", "https://news.ycombinator.com/user?id={}"),
    "gitlab": ("GitLab", r"[A-Za-z0-9_][A-Za-z0-9_.-]{1,63}", "https://gitlab.com/{}"),
    "keybase": ("Keybase", r"[A-Za-z0-9_]{2,16}", "https://keybase.io/{}"),
    "linkedin": ("LinkedIn", r"[A-Za-z0-9_-]{3,100}", "https://www.linkedin.com/in/{}"),
    "twitch": ("Twitch", r"[A-Za-z0-9_]{3,25}", "https://www.twitch.tv/{}"),
    "instagram": ("Instagram", r"[A-Za-z0-9_.]{1,30}", "https://www.instagram.com/{}/"),
    "facebook": ("Facebook", r"[A-Za-z0-9.]{5,50}", "https://www.facebook.com/{}"),
    "youtube": ("YouTube", r"[A-Za-z0-9_.-]{3,30}", "https://www.youtube.com/@{}"),
    "bluesky": ("Bluesky", r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}", "https://bsky.app/profile/{}"),
    "devto": ("dev.to", r"[A-Za-z0-9_]{2,30}", "https://dev.to/{}"),
    "codeberg": ("Codeberg", r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?", "https://codeberg.org/{}"),
    "lichess": ("Lichess", r"[A-Za-z0-9][A-Za-z0-9_-]{1,29}", "https://lichess.org/@/{}"),
    "chesscom": ("Chess.com", r"[A-Za-z0-9_-]{3,25}", "https://www.chess.com/member/{}"),
    "flickr": ("Flickr", r"[A-Za-z0-9@_-]{3,40}", "https://www.flickr.com/photos/{}"),
    "wordpress": ("WordPress", r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?", "https://{}.wordpress.com"),
}
# host -> (key, the path segment that must come before the handle, or "")
_ACCOUNT_HOSTS = {
    "github.com": ("github", ""), "twitter.com": ("twitter", ""), "x.com": ("twitter", ""), "reddit.com": ("reddit", "user"),
    "gitlab.com": ("gitlab", ""), "keybase.io": ("keybase", ""), "linkedin.com": ("linkedin", "in"), "twitch.tv": ("twitch", ""),
    "instagram.com": ("instagram", ""), "facebook.com": ("facebook", ""), "youtube.com": ("youtube", ""), "bsky.app": ("bluesky", "profile"),
    "dev.to": ("devto", ""), "codeberg.org": ("codeberg", ""), "lichess.org": ("lichess", "@"), "chess.com": ("chesscom", "member"),
    "flickr.com": ("flickr", "photos"),
}
_FEDI_RE = re.compile(r"^@([A-Za-z0-9_]{1,30})$")
_SUBDOMAINS = ("www.", "old.", "m.", "mobile.")

# First path segments that are a page of the site and never an account, per site key. A name
# here passes the site's handle rule, so without this list "github.com/sponsors" would read
# as the account "sponsors". Compared in lower case.
_COMMON_PAGES = frozenset({
    "about", "account", "accounts", "admin", "api", "blog", "contact", "dashboard", "explore", "help", "home", "login", "logout",
    "new", "notifications", "privacy", "search", "settings", "signin", "signup", "support", "terms", "tos",
})
RESERVED = {
    "github": frozenset({
        "apps", "codespaces", "collections", "copilot", "customer-stories", "discussions", "enterprise", "events", "features", "gist",
        "issues", "join", "marketplace", "mobile", "orgs", "organizations", "pricing", "pulls", "readme", "security", "session",
        "sessions", "site", "sponsors", "stars", "team", "topics", "trending", "users", "watching"}),
    "twitter": frozenset({"compose", "download", "hashtag", "i", "intent", "jobs", "messages", "oauth", "share"}),
    "gitlab": frozenset({
        "-", "assets", "files", "groups", "health_check", "import", "jwt", "oauth", "profile", "projects", "public", "s", "sitemap",
        "snippets", "unsubscribes", "uploads", "users", "v2"}),
    "keybase": frozenset({"docs", "download", "encrypt", "decrypt", "inv", "jobs", "kbfs", "popular", "sign", "team", "verify", "warp"}),
    "twitch": frozenset({
        "bits", "broadcast", "directory", "downloads", "drops", "embed", "friends", "inventory", "jobs", "moderator", "p", "payments",
        "popout", "prime", "store", "subscriptions", "team", "turbo", "u", "videos", "wallet"}),
    "instagram": frozenset({"challenge", "developer", "direct", "directory", "legal", "p", "reel", "reels", "stories", "tv", "web"}),
    "facebook": frozenset({
        "ads", "business", "events", "games", "gaming", "groups", "hashtag", "marketplace", "messages", "pages", "people", "photo",
        "photos", "policies", "public", "reel", "share", "sharer", "stories", "watch"}),
    "youtube": frozenset({"c", "channel", "feed", "gaming", "hashtag", "music", "playlist", "results", "shorts", "user", "watch"}),
    "devto": frozenset({
        "badges", "challenges", "comments", "connect", "enter", "events", "faq", "feed", "followers", "followings", "latest",
        "listings", "mod", "organizations", "pod", "podcasts", "reactions", "readinglist", "rss", "series", "shop", "sponsors", "t",
        "tags", "top", "videos", "welcome"}),
    "codeberg": frozenset({
        "assets", "attachments", "avatar", "avatars", "captcha", "commits", "debug", "devtest", "error", "ghost", "issues", "metrics",
        "milestones", "org", "pulls", "raw", "repo", "repo-avatars", "ssh_info", "user", "v2"}),
    "reddit": frozenset({"me"}),
    "flickr": frozenset({"tags"}),
}
# A file name is a page, never a handle: "profile.php", "robots.txt", "index.html".
_PAGE_FILE_RE = re.compile(r"\.(?:php\d?|html?|aspx?|jsp|xml|txt|json|ico)$", re.I)


def reserved(key: str, handle: str) -> bool:
    """True when `handle` is a page of the site `key` (a key of ACCOUNT_SITES), not an account."""
    h = handle.lower()
    return h in _COMMON_PAGES or h in RESERVED.get(key, ()) or bool(_PAGE_FILE_RE.search(h))


def account(site: str, handle: str, url: str, proof: str, proof_url: str = "") -> dict | None:
    """One linked account, or None when the address is not a usable link or the site is an
    adult or dating site."""
    address = safe_link(url)
    name = clean(site, 60)
    if not address or not name or adult_sites.is_adult_site(name, address):
        return None
    out = {"site": name, "handle": clean(handle, FIELD_MAX), "url": address, "proof": proof}
    if proof_url and safe_link(proof_url):
        out["proof_url"] = safe_link(proof_url)
    return out


def known_account(key: str, handle, proof: str, proof_url: str = "") -> dict | None:
    """An account on a site in ACCOUNT_SITES, with its address built from the checked handle."""
    spec = ACCOUNT_SITES.get(key)
    h = handle.strip().lstrip("@") if isinstance(handle, str) else ""
    if not spec or not re.fullmatch(spec[1], h) or reserved(key, h):
        return None
    return account(spec[0], h, spec[2].format(h), proof, proof_url)


def account_from_url(url, proof: str, proof_url: str = "") -> dict | None:
    """The account a profile address names, when the host is a known site (or the address has
    the "/@name" shape of a fediverse profile). None for any other address, which then stays an
    ordinary link: an address with a query ("watch?v=", "profile.php?id=", "search?q="), with
    more path than the site's profile path, or whose first segment is a page of the site
    (RESERVED). The one query read is Hacker News's own "user?id=name"."""
    address = safe_link(url)
    if not address:
        return None
    parts = urlsplit(address)
    host = (parts.hostname or "").lower()
    for sub in _SUBDOMAINS:
        host = host.removeprefix(sub)
    segs = [s for s in parts.path.split("/") if s]
    if host == "news.ycombinator.com":
        query = parse_qs(parts.query, keep_blank_values=True)
        if segs != ["user"] or set(query) != {"id"} or len(query["id"]) != 1:
            return None
        return known_account("hackernews", query["id"][0], proof, proof_url)
    if parts.query:
        return None
    if host.endswith(".wordpress.com") and not segs:
        return known_account("wordpress", host[: -len(".wordpress.com")], proof, proof_url)
    spec = _ACCOUNT_HOSTS.get(host)
    if spec:
        key, lead = spec
        if lead and len(segs) == 2 and segs[0] in (lead, "u" if lead == "user" else lead):
            return known_account(key, segs[1], proof, proof_url)
        if not lead and len(segs) == 1:
            if key == "youtube" and not segs[0].startswith("@"):
                # "youtube.com/name" is an old custom address or a page, not the handle "@name".
                return None
            return known_account(key, segs[0], proof, proof_url)
        return None
    if len(segs) == 1 and _FEDI_RE.match(segs[0]):
        return account(host, _FEDI_RE.match(segs[0]).group(1), address, proof, proof_url)
    return None


# ---- the row ---------------------------------------------------------------------------

def _unique(values, key=lambda v: v):
    seen, out = set(), []
    for v in values:
        k = key(v)
        if v and k not in seen:
            seen.add(k)
            out.append(v)
    return out


def profile(source: str, site: str, handle: str, url: str, *, display_name="", bio="", location="", company="", website="", links=(), emails=(),
            created=None, last_active=None, accounts=(), stats: dict | None = None, items=(), note="", avatar="",
            avatar_default: bool = False) -> dict:
    """The normalised row for one profile that was read. `source` and `site` are the module's ID and SITE.
    `bio` is plain text already (use html_text first when the site returns HTML)."""
    full = clean(bio, GUARD_BIO_MAX, lines=True)
    shown = clean(full, BIO_MAX)
    site_link = safe_link(website)
    numbers = {}
    for key, value in (stats or {}).items():
        if count(value) is not None and len(numbers) < MAX_STATS:
            numbers[str(key)[:30]] = value
    found_emails = [*emails, *(m.group(0) for m in _EMAIL_IN_TEXT_RE.finditer(full))]
    picture = avatar.strip() if isinstance(avatar, str) else ""
    row = {
        "site": site, "source": source, "handle": clean(handle, FIELD_MAX), "url": url, "state": "found",
        "display_name": clean(display_name, NAME_MAX), "bio": shown,
        "location": clean(location, FIELD_MAX), "company": clean(company, FIELD_MAX), "website": site_link,
        "links": _unique(safe_link(u) for u in (site_link, *links, *text_links(full)))[:MAX_LINKS],
        "emails": _unique((safe_email(e) for e in found_emails), key=str.lower)[:MAX_EMAILS],
        "created": iso(created), "last_active": iso(last_active),
        "accounts": _unique((a for a in accounts if a), key=lambda a: a["url"].lower())[:MAX_ACCOUNTS],
        "stats": numbers, "items": [i for i in items if i][:MAX_ITEMS], "note": clean(note, NOTE_MAX),
        "_avatar": picture if picture.startswith("https://") and len(picture) <= 600 and not avatar_default else "",
        "_avatar_default": bool(avatar_default),
    }
    # The same names a handle-probe row uses, so the page can treat both kinds of row alike.
    row["name"] = row["display_name"]
    row["followers"] = numbers.get("followers")
    if full != shown:
        # Guard-only, as on a Maigret row: the whole bio for the minor guard's content check.
        row["guard"] = {"bio": full}
    return row


def item(name, url: str, kind: str) -> dict | None:
    label, address = clean(name, FIELD_MAX), safe_link(url)
    return {"name": label, "url": address, "kind": kind} if label and address else None
