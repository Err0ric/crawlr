"""
GitHub profile lookup.

A 403 or 429 from GitHub means "rate limited", not "no such user": the anonymous API allows
60 requests an hour per IP, which a shared host burns through quickly. Those responses are
reported as an error with a retry hint and never as a negative result.

GITHUB_TOKEN (optional, server-side) raises the limit to 5,000 an hour. A fine-grained token
with no scopes is enough; it only reads public profiles. Results are cached in memory so a
re-run does not spend another request.

`run_github_deep` reads the rest of what a public profile exposes: linked social accounts,
organizations, top repositories and languages, SSH and GPG key fingerprints, links in the
profile README and the author emails on the user's own commits. It makes at most
DEEP_MAX_REQUESTS calls per uncached user, and every section reports its own state so a rate
limit on one of them is never shown as an empty list.
"""

import asyncio
import base64
import binascii
import hashlib
import os
import re
import time
from collections import Counter, OrderedDict
from urllib.parse import quote, urlsplit

import httpx

from core.errors import error_fields
from core.logging import get_logger

log = get_logger(__name__)

CACHE_TTL = int(os.getenv("GITHUB_CACHE_TTL", "3600"))
CACHE_MAX = 1000
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()

# Deep pull: a complete result is kept for a day, a partial one only long enough to stop a
# retry loop from spending the hourly allowance.
DEEP_TTL_OK = int(os.getenv("GITHUB_DEEP_CACHE_TTL", "86400"))
DEEP_TTL_PARTIAL = 600
DEEP_CACHE_MAX = 500
DEEP_MAX_REQUESTS = 8
_deep_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()   # key -> (expires_at, result)


def clear_cache_for_tests() -> None:
    _cache.clear()
    _deep_cache.clear()


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    ts, val = hit
    if time.time() - ts > CACHE_TTL:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return val


def _cache_put(key: str, val: dict) -> None:
    _cache[key] = (time.time(), val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _retry_after(resp: httpx.Response) -> int:
    """Seconds until GitHub will answer again, from Retry-After or X-RateLimit-Reset."""
    try:
        if resp.headers.get("retry-after"):
            return max(1, int(resp.headers["retry-after"]))
        if resp.headers.get("x-ratelimit-reset"):
            return max(1, int(resp.headers["x-ratelimit-reset"]) - int(time.time()))
    except ValueError:
        pass
    return 600


def _headers() -> dict:
    h = {
        "User-Agent": "CrawlR/1.0 (+https://crawlr.lol)",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


# ---- shared with the other GitHub modules (github_email.py, github_activity.py) ------------

LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


def api_headers() -> dict:
    """Headers for api.github.com only. The token never goes to another host."""
    return _headers()


def retry_after(resp: httpx.Response) -> int:
    return _retry_after(resp)


def is_rate_limit(resp: httpx.Response) -> bool:
    """
    True when a response is GitHub's rate limit and not another refusal. A 429 always is. A 403
    is one when the allowance is spent, when GitHub says how long to wait, or when the message
    says so (the secondary limit sends a 403 with allowance left).
    """
    if resp.status_code == 429:
        return True
    if resp.status_code != 403:
        return False
    if resp.headers.get("x-ratelimit-remaining") == "0" or resp.headers.get("retry-after"):
        return True
    try:
        message = str((resp.json() or {}).get("message") or "").lower()
    except (ValueError, AttributeError):
        return False
    return "rate limit" in message or "abuse" in message


# A spent allowance, as GitHub's own headers reported it: resource ("core", "search") -> the time
# it resets. The allowance is one per server address (or per token), shared by every visitor,
# so once it is known to be spent no request is made until it resets.
QUOTA_WAIT_MAX = 3600
_quota_reset: dict[str, float] = {}


def clear_quota_for_tests() -> None:
    _quota_reset.clear()


def note_quota(resp: httpx.Response, resource: str) -> None:
    """Remember a spent allowance from a response: `x-ratelimit-remaining: 0` with its reset
    time (on a refusal or on the last request that was still served), or a rate limit answer
    with a Retry-After. Only what GitHub said in numbers is remembered: a refusal that names
    no time is reported and the next call asks again. `resource` is used when the response
    does not name its own."""
    name = resp.headers.get("x-ratelimit-resource") or resource
    name = name if name in ("core", "search") else resource
    now = time.time()
    until = 0.0
    reset, wait = resp.headers.get("x-ratelimit-reset", ""), resp.headers.get("retry-after", "")
    if resp.headers.get("x-ratelimit-remaining") == "0" and reset.isascii() and reset.isdigit() and len(reset) <= 12:
        until = float(reset)
    elif wait.isascii() and wait.isdigit() and len(wait) <= 6 and is_rate_limit(resp):
        until = now + int(wait)
    if until > now:
        _quota_reset[name] = max(_quota_reset.get(name, 0.0), min(until, now + QUOTA_WAIT_MAX))


def quota_wait(resource: str) -> int:
    """Seconds until a spent allowance resets, or 0 when a request may be made."""
    until = _quota_reset.get(resource)
    if until is None:
        return 0
    left = until - time.time()
    if left <= 0:
        _quota_reset.pop(resource, None)
        return 0
    return max(1, int(left + 0.999))


def rate_limited_fields(wait: int, detail: str) -> dict:
    """The error fields of a rate limited answer, the same words whether GitHub just refused
    or the allowance is already known to be spent."""
    mins = max(1, round(wait / 60))
    return error_fields(code="rate_limited", detail=detail,
                        message=f"GitHub is rate limiting CrawlR. Try again in about {mins} minute{'s' if mins != 1 else ''}.")


async def run_github(username: str, timeout: int = 10) -> dict:
    if not LOGIN_RE.fullmatch(username):
        # GitHub cannot hold this name (a dot, an underscore, over 39 characters), so that is
        # the answer and no request is made.
        return {"username": username, "found": False, "note": "GitHub cannot hold a name spelled like this."}
    key = username.lower()
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}

    url = f"https://api.github.com/users/{quote(username, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=_headers())
    except Exception as e:
        return {"username": username, "found": None, **error_fields(e)}

    if resp.status_code == 404:
        result = {"username": username, "found": False}
        _cache_put(key, result)
        return result

    if resp.status_code in (403, 429):
        wait = _retry_after(resp)
        mins = max(1, round(wait / 60))
        log.warning("github rate limited", extra={"retry_after_s": wait, "authenticated": bool(os.getenv("GITHUB_TOKEN"))})
        return {
            "username": username,
            "found": None,   # unknown: this is not a "no such user" answer
            "retry_after": wait,
            **error_fields(
                code="rate_limited",
                message=f"GitHub is rate limiting CrawlR. Try again in about {mins} minute{'s' if mins != 1 else ''}.",
                detail=f"HTTP {resp.status_code} from api.github.com",
            ),
        }

    if resp.status_code != 200:
        return {"username": username, "found": None, **error_fields(code="upstream", detail=f"HTTP {resp.status_code} from api.github.com")}

    try:
        data = resp.json()
    except ValueError as e:
        return {"username": username, "found": None, **error_fields(e)}

    result = {
        "username": username,
        "found": True,
        "name": data.get("name") or "",
        "bio": data.get("bio") or "",
        "location": data.get("location") or "",
        "company": data.get("company") or "",
        "email": data.get("email") or "",
        "blog": data.get("blog") or "",
        "public_repos": data.get("public_repos", 0),
        "followers": data.get("followers", 0),
        "profile_url": data.get("html_url", ""),
        "avatar_url": data.get("avatar_url", ""),
        "created_at": data.get("created_at", ""),
    }
    if data.get("twitter_username"):
        result["twitter_username"] = data["twitter_username"]
    if data.get("hireable") is not None:
        result["hireable"] = bool(data["hireable"])
    _cache_put(key, result)
    return result


# ---- deep pull ---------------------------------------------------------------------

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
README_MAX_BYTES = 200_000
MAX_README_LINKS = 20
MAX_COMMIT_EMAILS = 10
TOP_REPOS = 5
MAX_LANGUAGES = 10
DEEP_SECTIONS = ("social_accounts", "readme_links", "orgs", "top_repos", "ssh_keys", "gpg_keys", "commit_emails")

_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]`]+", re.I)
_IMAGE_EXT = (".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".avif")
# Hosts that only serve badges, counters or images. They say nothing about the person.
_BADGE_HOSTS = {
    "img.shields.io", "shields.io", "badgen.net", "badge.fury.io", "forthebadge.com", "komarev.com",
    "raw.githubusercontent.com", "user-images.githubusercontent.com", "camo.githubusercontent.com",
    "avatars.githubusercontent.com", "private-user-images.githubusercontent.com", "github.githubassets.com",
    "github-readme-stats.vercel.app", "github-readme-streak-stats.herokuapp.com", "github-profile-trophy.vercel.app",
    "github-readme-activity-graph.vercel.app", "readme-typing-svg.herokuapp.com", "readme-typing-svg.demolab.com",
    "skillicons.dev", "cdn.jsdelivr.net", "cdn.simpleicons.org", "simpleicons.org", "visitor-badge.laobi.icu",
    "visitcount.itsvg.in", "profile-counter.glitch.me", "capsule-render.vercel.app", "i.imgur.com", "imgur.com",
    "media.giphy.com", "giphy.com", "www.w3.org",
}
_BADGE_WORDS = ("badge", "shields", "visitor", "counter")


def ssh_fingerprint(key: str) -> dict | None:
    """`ssh-ed25519 AAAA...` -> {type, fingerprint}, the same SHA256 form `ssh-keygen -l` prints."""
    parts = (key or "").split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    if not blob:
        return None
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return {"type": parts[0][:40], "fingerprint": f"SHA256:{digest}"}


def is_noreply(email: str) -> bool:
    e = (email or "").strip().lower()
    return not e or e.endswith("noreply.github.com") or "noreply" in e or "no-reply" in e


def readme_links(text: str) -> list[str]:
    """http(s) links in a README, one per host and path, without badges and images."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in _URL_RE.findall(text or ""):
        url = raw.rstrip(".,;:!?*_~")
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host or "." not in host:
            continue
        path = parts.path.rstrip("/")
        if host in _BADGE_HOSTS or any(w in host for w in _BADGE_WORDS) or path.lower().endswith(_IMAGE_EXT):
            continue
        key = host.removeprefix("www.") + path.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(url[:300])
        if len(out) >= MAX_README_LINKS:
            break
    return out


def _deep_cache_get(key: str) -> dict | None:
    hit = _deep_cache.get(key)
    if not hit:
        return None
    expires, val = hit
    if time.time() > expires:
        _deep_cache.pop(key, None)
        return None
    _deep_cache.move_to_end(key)
    return val


def _deep_cache_put(key: str, val: dict, ttl: int) -> None:
    _deep_cache[key] = (time.time() + ttl, val)
    _deep_cache.move_to_end(key)
    while len(_deep_cache) > DEEP_CACHE_MAX:
        _deep_cache.popitem(last=False)


async def _readme(client: httpx.AsyncClient, url: str) -> tuple[str, object]:
    """The profile README is written by the target, so it is read as a stream and cut off at the cap."""
    try:
        # The token is for api.github.com only; the raw file host gets a plain request.
        async with client.stream("GET", url, headers={"User-Agent": _headers()["User-Agent"], "Accept-Encoding": "identity"}) as resp:
            if resp.status_code == 404:
                return "not_found", None
            if resp.status_code in (403, 429):
                return "rate_limited", None
            if resp.status_code != 200 or resp.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
                return "failed", None
            buf = bytearray()
            async for chunk in resp.aiter_bytes():     # identity encoding only, checked above
                buf += chunk
                if len(buf) >= README_MAX_BYTES:
                    break
            return "ok", bytes(buf[:README_MAX_BYTES]).decode("utf-8", errors="replace")
    except Exception:
        return "failed", None


async def _section(client: httpx.AsyncClient, url: str) -> tuple[str, object]:
    """One API GET. Returns (state, payload) with state ok, not_found, rate_limited or failed."""
    try:
        resp = await client.get(url, headers=_headers())
    except Exception:
        return "failed", None
    if resp.status_code == 404:
        return "not_found", None
    if resp.status_code in (403, 429):
        return "rate_limited", None
    if resp.status_code != 200:
        return "failed", None
    try:
        return "ok", resp.json()
    except ValueError:
        return "failed", None


def _rows(payload) -> list[dict]:
    return [x for x in payload if isinstance(x, dict)] if isinstance(payload, list) else []


def _is_own_commit(author: dict, login: str, profile_name: str) -> bool:
    """A pushed commit counts as the account's own only when its author line names the account."""
    name = str(author.get("name") or "").strip().casefold()
    local = str(author.get("email") or "").split("@")[0].strip().casefold()
    own_names = {n for n in (login.casefold(), profile_name.strip().casefold()) if n}
    return name in own_names or local == login.casefold()


def _event_commits(events: list[dict], login: str, profile_name: str = "") -> tuple[bool, list[dict]]:
    """
    (payload carried commits, rows). GitHub dropped commits from public push events in 2025.

    A push carries everyone's commits (merges, rebases, cherry-picks), so an author is kept only
    when the account made the push and the author line matches the account. Anything else is
    dropped: another person's address must never be reported as the target's.
    """
    carried = False
    rows: list[dict] = []
    for ev in events:
        payload = ev.get("payload")
        if ev.get("type") != "PushEvent" or not isinstance(payload, dict) or not isinstance(payload.get("commits"), list):
            continue
        carried = True
        if str((ev.get("actor") or {}).get("login") or "").casefold() != login.casefold():
            continue
        repo = (ev.get("repo") or {}).get("name") or ""
        for c in _rows(payload["commits"]):
            author = c.get("author") if isinstance(c.get("author"), dict) else {}
            if _is_own_commit(author, login, profile_name):
                rows.append({"email": author.get("email") or "", "name": author.get("name") or "", "repo": repo})
    return carried, rows


def _commit_emails(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        email = str(r.get("email") or "").strip()
        if is_noreply(email) or "@" not in email or email.lower() in seen:
            continue
        seen.add(email.lower())
        out.append({"email": email[:254], "name": str(r.get("name") or "")[:120], "repo": str(r.get("repo") or "")[:200]})
        if len(out) >= MAX_COMMIT_EMAILS:
            break
    return out


async def run_github_deep(username: str, timeout: int = 10) -> dict:
    if not LOGIN_RE.fullmatch(username):
        # GitHub cannot hold this name (a dot, an underscore, over 39 characters), so that is
        # the answer and no request is made.
        return {"username": username, "found": False, "note": "GitHub cannot hold a name spelled like this."}
    key = username.lower()
    cached = _deep_cache_get(key)
    if cached is not None:
        return {**cached, "cached": True}

    u = quote(username, safe="")
    base = f"{API}/users/{u}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            social, orgs, repos, ssh, gpg, readme, events = await asyncio.gather(
                _section(client, f"{base}/social_accounts"),
                _section(client, f"{base}/orgs"),
                _section(client, f"{base}/repos?type=owner&per_page=100"),
                _section(client, f"{base}/keys"),
                _section(client, f"{base}/gpg_keys"),
                _readme(client, f"{RAW}/{u}/{u}/HEAD/README.md"),
                _section(client, f"{base}/events/public?per_page=100"),
            )
            api_calls = (social, orgs, repos, ssh, gpg, events)
            # Every /users/{u}/... endpoint answers 404 for an account that does not exist.
            if any(state == "not_found" for state, _ in api_calls):
                result = {"username": username, "found": False}
                _deep_cache_put(key, result, DEEP_TTL_OK)
                return result

            owned = sorted(_rows(repos[1]), key=lambda r: int(r.get("stargazers_count") or 0), reverse=True)
            originals = [r for r in owned if not r.get("fork")]

            # The profile name is used only when the profile lookup already cached it: no extra request.
            profile_name = str((_cache_get(key) or {}).get("name") or "")
            carried, commit_rows = _event_commits(_rows(events[1]), username, profile_name)
            commit_state = events[0]
            pick = (originals or owned)[:1]
            if not carried and pick and pick[0].get("name"):
                # Fallback: commits GitHub itself attributes to this account in their top repository.
                repo_name = str(pick[0]["name"])
                commit_state, payload = await _section(
                    client, f"{API}/repos/{u}/{quote(repo_name, safe='')}/commits?author={u}&per_page=20")
                if commit_state == "not_found":      # an empty repository
                    commit_state, payload = "ok", []
                commit_rows = [
                    {"email": ((c.get("commit") or {}).get("author") or {}).get("email"),
                     "name": ((c.get("commit") or {}).get("author") or {}).get("name"),
                     "repo": f"{username}/{repo_name}"}
                    for c in _rows(payload)
                    # Only commits GitHub links to this account. The author filter also matches
                    # by name and email, so the linked login is checked here as well.
                    if str((c.get("author") or {}).get("login") or "").casefold() == username.casefold()
                ]
    except Exception as e:
        return {"username": username, "found": None, **error_fields(e)}

    sections = {
        "social_accounts": social[0],
        # No profile README is an answer, not a failure.
        "readme_links": "ok" if readme[0] == "not_found" else readme[0],
        "orgs": orgs[0],
        "top_repos": repos[0],
        "ssh_keys": ssh[0],
        "gpg_keys": gpg[0],
        "commit_emails": commit_state,
    }

    if all(state != "ok" for state, _ in api_calls):
        # Nothing answered, so whether the account exists is unknown.
        limited = any(state == "rate_limited" for state, _ in api_calls)
        if limited:
            log.warning("github deep rate limited", extra={"authenticated": bool(os.getenv("GITHUB_TOKEN"))})
        return {
            "username": username, "found": None, "sections": sections,
            **(error_fields(code="rate_limited", message="GitHub is rate limiting CrawlR. Try again later.",
                            detail="HTTP 403 or 429 from api.github.com")
               if limited else error_fields(code="upstream", detail="No GitHub endpoint answered")),
        }

    languages = [lang for lang, _n in Counter(
        str(r["language"]) for r in originals if r.get("language")).most_common(MAX_LANGUAGES)]

    result = {
        "username": username,
        "found": True,
        "state": "ok" if all(v == "ok" for v in sections.values()) else "partial",
        "cached": False,
        "social_accounts": [
            {"provider": str(a.get("provider") or "")[:40], "url": str(a["url"])[:300]}
            for a in _rows(social[1]) if str(a.get("url") or "").lower().startswith(("http://", "https://"))
        ],
        "readme_links": readme_links(readme[1]) if isinstance(readme[1], str) else [],
        "orgs": [
            {"login": str(o["login"])[:80], "url": f"https://github.com/{quote(str(o['login']), safe='')}"}
            for o in _rows(orgs[1]) if o.get("login")
        ],
        "top_repos": [
            {"name": str(r.get("name") or "")[:120],
             "url": str(r.get("html_url") or f"https://github.com/{u}/{quote(str(r.get('name') or ''), safe='')}"),
             "stars": int(r.get("stargazers_count") or 0),
             "language": r.get("language") or "",
             "description": str(r.get("description") or "")[:300],
             "fork": False}
            for r in originals[:TOP_REPOS]
        ],
        "languages": languages,
        "keys": {
            # Type and fingerprint only. The key body is never returned.
            "ssh": [fp for fp in (ssh_fingerprint(str(k.get("key") or "")) for k in _rows(ssh[1])) if fp],
            "gpg": [
                {"key_id": str(k.get("key_id") or "")[:40],
                 "emails": [str(e["email"])[:254] for e in _rows(k.get("emails"))
                            if e.get("email") and not is_noreply(str(e["email"]))]}
                for k in _rows(gpg[1]) if k.get("key_id")
            ],
        },
        "commit_emails": _commit_emails(commit_rows),
        "sections": sections,
    }
    if result["state"] != "ok" and "rate_limited" in sections.values():
        log.warning("github deep partly rate limited", extra={"authenticated": bool(os.getenv("GITHUB_TOKEN"))})
    _deep_cache_put(key, result, DEEP_TTL_OK if result["state"] == "ok" else DEEP_TTL_PARTIAL)
    return result
