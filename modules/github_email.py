"""
GitHub accounts tied to an email address. Two search requests, no key needed.

1. GET /search/commits?q=author-email:{address}&per_page=100
   Every hit is a commit whose author line carries the address. GitHub links a commit to an
   account when that account has the address added and confirmed, and returns it as
   `author.login`. That link is GitHub's and is a strong tie. Everything written inside the
   commit is not: anyone can put any name, address and date in a commit they make, so the
   names are self-declared, dates in the future are ignored, and a commit in a repository the
   account owns counts for more than one in a stranger's repository (`own_repo`).
   A hit with `author: null` is a commit GitHub ties to no account. Those are reported apart.

2. GET /search/users?q={address} in:email
   Accounts GitHub's user search matched to the address. The search row carries no email, so
   this module cannot see the address on the profile itself: such a row says `confirmed:
   false` and `how_note` words it as a search match. (A user can only show an address they
   confirmed; an organization can type anything, so `account_type` is passed on.) A row built
   from commits says `confirmed: true`: each counted commit was checked to carry the address.

Anonymous search allows 10 requests a minute per IP (30 with GITHUB_TOKEN). A 403 or 429 that
is GitHub's rate limit is `rate_limited`, never `none`. Commit search often answers with
`incomplete_results: true` and a huge `total_count` for a common address: only the first 100
hits are read, and `seen` says how many that was.

No URL returned here carries the address: evidence links are commit pages, checked against
the commit URL shape, and profile links are built from a checked login.
"""

import re
import unicodedata
from collections import Counter
from datetime import datetime, timedelta, timezone

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger
from modules.github import LOGIN_RE, api_headers, is_rate_limit, note_quota, quota_wait, rate_limited_fields, retry_after

log = get_logger(__name__)

API = "https://api.github.com"
HOST = "api.github.com"
PER_PAGE = 100
MAX_EVIDENCE = 3
MAX_NAMES = 5
MAX_OFFSETS = 3
MAX_ACCOUNTS = 10
MAX_PROFILE_ROWS = 5
EARLIEST = datetime(1990, 1, 1, tzinfo=timezone.utc)      # a commit dated before this is a clock fault or a forgery

_COMMIT_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}/commit/[0-9a-f]{7,64}$")
_ACCOUNT_TYPES = {"User", "Organization", "Bot"}
SEARCH_MATCH = "GitHub's search matched this address on the profile. The profile itself was not read to confirm it."
ONLY_SKIPPED = ("GitHub returned {n} commit{s} for this address and none could be counted: each was made by an app account, "
                "or its row was malformed or did not carry the address.")


def _text(value, cap: int) -> str:
    if not isinstance(value, str):
        return ""
    s = "".join(" " if unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co") else ch for ch in value)
    return " ".join(s.split())[:cap].strip()


def _rows(value) -> list[dict]:
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _when(value) -> datetime | None:
    """A commit date with its own UTC offset, or None when it cannot be read."""
    if not isinstance(value, str):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo is not None else None


def _iso(d: datetime | None) -> str:
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""


def _offset(d: datetime) -> str:
    minutes = int(d.utcoffset().total_seconds() // 60)
    sign = "-" if minutes < 0 else "+"
    return f"{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


def profile_url(login: str) -> str:
    return f"https://github.com/{login}"


class _Group:
    """Commits that share one attribution: an account, or none."""

    def __init__(self):
        self.commits = 0
        self.own = 0
        self.names: Counter = Counter()
        self.own_names: set[str] = set()
        self.offsets: Counter = Counter()
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.dates_ignored = 0
        self.evidence: list[tuple[bool, str]] = []
        self.account_type = ""

    def add(self, item: dict, own: bool, now: datetime) -> None:
        self.commits += 1
        self.own += own
        author = _dict(_dict(item.get("commit")).get("author"))
        name = _text(author.get("name"), 120)
        if name:
            self.names[name] += 1
            if own:
                self.own_names.add(name)
        d = _when(author.get("date"))
        if d is None or d < EARLIEST or d > now + timedelta(days=1):
            self.dates_ignored += 1
        else:
            self.first = d if self.first is None or d < self.first else self.first
            self.last = d if self.last is None or d > self.last else self.last
            self.offsets[_offset(d)] += 1
        url = item.get("html_url")
        if isinstance(url, str) and _COMMIT_URL_RE.fullmatch(url):
            self.evidence.append((own, url))

    def fields(self) -> dict:
        # Names written in the account's own repositories first, then by how often they appear.
        names = sorted(self.names.items(), key=lambda kv: (kv[0] not in self.own_names, -kv[1], kv[0]))
        # Evidence: the account's own repositories first, and one commit per repository before a second.
        ranked = sorted(self.evidence, key=lambda e: not e[0])
        repos_used: set[str] = set()
        spread, rest = [], []
        for _own, u in ranked:
            repo = u.split("/commit/")[0]
            (rest if repo in repos_used else spread).append(u)
            repos_used.add(repo)
        evidence = spread + rest
        return {
            "commits_seen": self.commits,
            "own_repo_commits": self.own,
            "names": [{"name": n, "commits": c, "own_repo": n in self.own_names} for n, c in names[:MAX_NAMES]],
            "first_commit": _iso(self.first),
            "last_commit": _iso(self.last),
            "dates_ignored": self.dates_ignored,
            # The offset is the one the committing machine wrote. Self-declared, like the name.
            "commit_utc_offsets": [{"offset": o, "commits": c} for o, c in sorted(self.offsets.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_OFFSETS]],
            "evidence": list(dict.fromkeys(evidence))[:MAX_EVIDENCE],
        }


def read_commits(payload: dict, email: str, now: datetime | None = None) -> dict:
    """A commit search answer into {accounts, unattributed, total, seen, incomplete, skipped}."""
    now = now or datetime.now(timezone.utc)
    want = email.casefold()
    groups: dict[str, _Group] = {}
    logins: dict[str, str] = {}
    loose = _Group()
    seen = skipped = 0
    for item in _rows(payload.get("items")):
        commit_author = _dict(_dict(item.get("commit")).get("author"))
        # The search is trusted for nothing: a hit that does not carry the address is dropped.
        if str(commit_author.get("email") or "").strip().casefold() != want:
            skipped += 1
            continue
        author = item.get("author")
        if author is None:
            seen += 1
            loose.add(item, False, now)
            continue
        login = _dict(author).get("login")
        if not isinstance(login, str) or not LOGIN_RE.fullmatch(login):
            # An app account ("name[bot]") or a malformed row: not a person's account.
            skipped += 1
            continue
        seen += 1
        key = login.casefold()
        logins.setdefault(key, login)
        group = groups.setdefault(key, _Group())
        kind = _dict(author).get("type")
        group.account_type = kind if kind in _ACCOUNT_TYPES else group.account_type
        owner = _dict(_dict(item.get("repository")).get("owner")).get("login")
        group.add(item, isinstance(owner, str) and owner.casefold() == key, now)

    accounts = [
        {"login": logins[k], "url": profile_url(logins[k]), "how": "commit_author", "hows": ["commit_author"],
         "confirmed": True, "account_type": g.account_type, **g.fields()}
        for k, g in sorted(groups.items(), key=lambda kv: (-kv[1].commits, kv[0]))
    ][:MAX_ACCOUNTS]
    total = payload.get("total_count")
    total = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None
    return {
        "accounts": accounts,
        "unattributed": {k: v for k, v in loose.fields().items() if k != "own_repo_commits"},
        "total": total,
        "seen": seen,
        "incomplete": bool(payload.get("incomplete_results")) or (total is not None and total > seen + skipped),
        "skipped": skipped,
    }


def read_users(payload: dict) -> dict:
    """A user search answer into {accounts, total}. Rows carry no commit facts."""
    out, seen = [], set()
    for item in _rows(payload.get("items")):
        login = item.get("login")
        if not isinstance(login, str) or not LOGIN_RE.fullmatch(login) or login.casefold() in seen:
            continue
        seen.add(login.casefold())
        kind = item.get("type")
        # The field name is kept for the page. What it means is in SEARCH_MATCH: the search
        # matched, and the profile was not read here to see the address on it.
        out.append({"login": login, "url": profile_url(login), "how": "public_profile_email",
                    "hows": ["public_profile_email"], "confirmed": False, "how_note": SEARCH_MATCH,
                    "account_type": kind if kind in _ACCOUNT_TYPES else ""})
        if len(out) >= MAX_PROFILE_ROWS:
            break
    total = payload.get("total_count")
    return {"accounts": out, "total": total if isinstance(total, int) and not isinstance(total, bool) else None}


async def _search(client: httpx.AsyncClient, label: str, path: str, params: dict) -> tuple[dict, dict | None]:
    """One search request. Returns (source state, payload or None). Never raises. When GitHub's
    headers have said the search allowance is spent, no request is made until it resets."""
    wait = quota_wait("search")
    if wait:
        return {"state": "rate_limited", "retry_after": wait, **rate_limited_fields(wait, f"The {HOST} search allowance is spent")}, None
    try:
        resp = await client.get(f"{API}{path}", params=params, headers=api_headers(), follow_redirects=False)
    except Exception as e:
        # The class name only: an exception text can carry the request URL, and the URL carries the address.
        fields = error_fields(code=classify(e), detail=type(e).__name__)
        log.warning("github email search did not answer", extra={"source": label, "error_code": fields["error_code"]})
        return {"state": "failed", **fields}, None
    note_quota(resp, "search")
    if is_rate_limit(resp):
        wait = retry_after(resp)
        log.warning("github email search rate limited", extra={"source": label, "retry_after_s": wait})
        return {"state": "rate_limited", "retry_after": wait, **rate_limited_fields(wait, f"HTTP {resp.status_code} from {HOST}")}, None
    if resp.status_code != 200:
        log.warning("github email search did not answer", extra={"source": label, "status": resp.status_code})
        return {"state": "failed", **error_fields(code="upstream", detail=f"HTTP {resp.status_code} from {HOST}")}, None
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        log.warning("github email search unreadable", extra={"source": label})
        return {"state": "failed", **error_fields(code="bad_response", detail=f"Unreadable response from {HOST}")}, None
    return {"state": "ok"}, payload


async def commits(client: httpx.AsyncClient, email: str) -> dict:
    """{source: {state, ...}, accounts, unattributed}."""
    source, payload = await _search(client, "github_commits", "/search/commits",
                                    {"q": f"author-email:{email}", "per_page": str(PER_PAGE)})
    if payload is None:
        return {"source": source, "accounts": [], "unattributed": read_commits({}, email)["unattributed"]}
    read = read_commits(payload, email)
    found = bool(read["accounts"]) or read["unattributed"]["commits_seen"] > 0
    source = {"state": "ok" if found else "none", "total": read["total"], "seen": read["seen"],
              "incomplete": read["incomplete"], "skipped": read["skipped"]}
    if not found and read["skipped"]:
        # "none" because every hit was set aside is not the same as no hit at all.
        source["only_skipped"] = True
        source["note"] = ONLY_SKIPPED.format(n=read["skipped"], s="" if read["skipped"] == 1 else "s")
    return {"source": source, "accounts": read["accounts"], "unattributed": read["unattributed"]}


async def users(client: httpx.AsyncClient, email: str) -> dict:
    """{source: {state, ...}, accounts}."""
    source, payload = await _search(client, "github_users", "/search/users",
                                    {"q": f"{email} in:email", "per_page": str(MAX_PROFILE_ROWS)})
    if payload is None:
        return {"source": source, "accounts": []}
    read = read_users(payload)
    return {"source": {"state": "ok" if read["accounts"] else "none", "total": read["total"],
                       "seen": len(read["accounts"])},
            "accounts": read["accounts"]}

