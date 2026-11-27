"""
Commit emails on GitLab, Codeberg and Gitea.com: the author names and addresses written on
recent commits in one account's own public repositories. On a click, one account at a time.

The GitHub deep lookup (modules/github.py) does this for GitHub. This is the same reading, with
the same caution, for three forges whose public API answers without a key (checked 2026-11-27):

  gitlab     gitlab.com     GET /api/v4/users?username={u}
                            GET /api/v4/users/{id}/projects?order_by=last_activity_at&per_page=20
                            GET /api/v4/projects/{id}/repository/commits?per_page=30
  codeberg   codeberg.org   GET /api/v1/users/{u}
  gitea      gitea.com      GET /api/v1/users/{u}/repos?limit=10
                            GET /api/v1/repos/{u}/{repo}/commits?limit=30&stat=false&verification=false&files=false

At most MAX_REQUESTS (5) requests per uncached call: the account, its repository list, and the
commits of up to MAX_REPOS (3) repositories it owns, asked together. Fixed hosts, no redirect
followed, 512 KB read per answer (modules/profiles/base.get_json).

What a commit says is written by whoever made it. The author name, the address and the date
are typed into git by the author and no forge checks them, so every row is self-declared and
forgeable, and is labeled so. A repository also holds other people's commits (merges, patches,
a fork's whole history). So:

  * only repositories in the account's own namespace are read, originals before forks;
  * a commit is kept only when it is tied to the account, and the row says how in `how`:
      forge_attributed    the forge itself links the commit to this account (Codeberg and
                          Gitea.com: the commit's `author.login`). The forge links by address,
                          so the address is one the account holds there. The stronger tie.
      author_line_match   the author line names the account: the author name is the login or
                          the profile's display name, or the address's local part is the login.
                          This is the only tie GitLab's keyless API allows. A name is not
                          proof: anybody can commit under any name.
  * every other commit is counted in `counts.other_authors` and its author is never returned;
  * "noreply" placeholder addresses are dropped and counted in `counts.noreply`.

The answer:

  {site, site_name, username, state, cached,
   [handle, profile_url, display_name,]                       when state is "found"
   emails: [{email, name, how, how_note, self_declared: true, commits, first_commit,
             last_commit, repos: [name]}],
   emails_state: "found" | "none" | "unknown",
   complete, sections: {account, repos}, repos: [{name, url, fork, state, commits_seen}],
   counts: {repos_listed, repos_read, commits_seen, own, noreply, other_authors},
   requests, note [, error, error_code, error_detail][, retry_after]}

`state` is about the account: found, not_found, blocked, rate_limited, unknown, failed, or
not_asked for a handle the site cannot hold. A refusal is never "not_found". `emails_state` is
"none" only when everything that was asked answered (`complete`); when a part did not answer
and no address was read it is "unknown".

A complete answer and a "not found" are kept for a day, anything else for ten minutes. A host
that answers 429 is left alone for everyone until its Retry-After has passed. Nothing about the
handle, a name or an address is logged: the site, states and counts only.
"""

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from core.errors import classify, error_fields
from core.logging import get_logger
from modules.profiles import base, codeberg, gitea, gitlab

log = get_logger(__name__)


@dataclass(frozen=True)
class Forge:
    name: str           # as a person reads it
    host: str           # fixed
    kind: str           # "gitlab" or "forgejo" (Codeberg's Forgejo and Gitea share one API shape)
    handle_re: object   # the profile source's own handle rule


SITES = {
    "gitlab": Forge("GitLab", "gitlab.com", "gitlab", gitlab.HANDLE_RE),
    "codeberg": Forge("Codeberg", "codeberg.org", "forgejo", codeberg.HANDLE_RE),
    "gitea": Forge("Gitea.com", "gitea.com", "forgejo", gitea.HANDLE_RE),
}
STATES = ("found", "not_found", "blocked", "rate_limited", "unknown", "failed", "not_asked")

MAX_REQUESTS = 5              # per uncached call, all of them
MAX_REPOS = 3                 # repositories whose commits are read
COMMITS_PER_REPO = 30
GITLAB_PROJECTS = 20          # rows asked of the repository list
FORGEJO_REPOS = 10            # a Forgejo repository row is about 5 KB, a fork's twice that
MAX_EMAILS = 10
MAX_ROW_REPOS = 3
REQUEST_TIMEOUT = 8.0
TOTAL_TIMEOUT = 14.0

CACHE_TTL_OK = 24 * 3600
CACHE_TTL_PARTIAL = 600
CACHE_MAX = 1000
_cache: "OrderedDict[tuple[str, str], tuple[float, dict]]" = OrderedDict()     # (site, handle lower) -> (expires_at, answer)

BACKOFF_DEFAULT = 300
BACKOFF_MAX = 3600
_backoff: dict[str, float] = {}      # site -> the time before which it is not asked, for anyone

NOTE = ("Names, addresses and dates inside commits are typed by the author and checked by nobody. "
        "They are self-declared and can be forged. A row is a lead to check, not a confirmed address.")
HOW_NOTES = {
    "forge_attributed": "The site links these commits to this account by the address, so the account holds the address there. "
                        "The name and the dates are still the author's own words.",
    "author_line_match": "The author line names this account (its login or display name). Anybody can commit under any name, "
                         "so this ties the address to the account only weakly.",
}
_REPO_NAME_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")


def clear_cache_for_tests() -> None:
    _cache.clear()
    _backoff.clear()


def _cache_get(key: tuple[str, str]) -> dict | None:
    hit = _cache.get(key)
    if not hit:
        return None
    if time.time() > hit[0]:
        _cache.pop(key, None)
        return None
    _cache.move_to_end(key)
    return hit[1]


def _cache_put(key: tuple[str, str], val: dict, ttl: int) -> None:
    _cache[key] = (time.time() + ttl, val)
    _cache.move_to_end(key)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)


def _backing_off(site: str) -> int:
    until = _backoff.get(site)
    if until is None:
        return 0
    left = until - time.time()
    if left <= 0:
        _backoff.pop(site, None)
        return 0
    return max(1, int(left + 0.999))


def _back_off(site: str, seconds: int | None) -> int:
    wait = min(BACKOFF_MAX, max(1, seconds)) if seconds else BACKOFF_DEFAULT
    _backoff[site] = max(_backoff.get(site, 0.0), time.time() + wait)
    return wait


class _Asker:
    """Every request of one call goes through here, so the cap cannot be passed."""

    def __init__(self, client: httpx.AsyncClient, site: str):
        self.client, self.site, self.used, self.retry_after = client, site, 0, None

    async def get(self, url: str, params: dict | None = None, absent: tuple[int, ...] = (404,)) -> tuple[str, object, dict]:
        """(state, parsed body, error fields). State: ok, not_found, blocked, rate_limited,
        unknown or failed. Never raises, and an error never carries the address asked."""
        if self.used >= MAX_REQUESTS:
            return "unknown", None, {}
        self.used += 1
        try:
            reply = await asyncio.wait_for(base.get_json(self.client, url, params), REQUEST_TIMEOUT)
        except base.SourceError as e:
            return "failed", None, error_fields(code=e.code, detail=e.detail)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            # The class name only: an exception message can carry the URL, and the URL the handle.
            return "failed", None, error_fields(code=classify(e), detail=type(e).__name__)
        stop = base.settle(reply, not_found=absent)
        if stop is None:
            return "ok", reply.data, {}
        if stop.state == "rate_limited":
            self.retry_after = _back_off(self.site, stop.retry_after)
        return stop.state, None, stop.error or {}


def _rows(payload) -> list[dict]:
    return [x for x in payload if isinstance(x, dict)] if isinstance(payload, list) else []


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _repo_name_ok(name) -> bool:
    return isinstance(name, str) and 0 < len(name) <= 100 and set(name) <= _REPO_NAME_OK and name not in (".", "..")


def is_own(author_name: str, author_email: str, login: str, display_name: str) -> bool:
    """The author line names the account: its login or display name as the author name, or the
    login as the address's local part. The same rule as modules/github.py."""
    name = author_name.strip().casefold()
    local = author_email.split("@")[0].strip().casefold()
    own = {n for n in (login.casefold(), display_name.strip().casefold()) if n}
    return name in own or local == login.casefold()


# ---- one forge at a time: the account, its repositories, one repository's commits ---------

async def _gitlab_account(ask: _Asker, forge: Forge, username: str) -> tuple[str, dict, dict]:
    state, data, err = await ask.get(f"https://{forge.host}/api/v4/users", {"username": username}, absent=())
    if state != "ok":
        return state, {}, err
    if not isinstance(data, list):
        return "unknown", {}, {}
    if not data:
        return "not_found", {}, {}      # GitLab's own answer for a name nobody holds
    row = next((r for r in _rows(data) if _text(r.get("username")).lower() == username.lower()), None)
    uid = row.get("id") if row else None
    if row is None or not forge.handle_re.fullmatch(row["username"]) or not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
        return "unknown", {}, {}
    return "found", {"handle": row["username"], "display_name": base.clean(row.get("name"), base.NAME_MAX), "id": uid}, {}


async def _gitlab_repos(ask: _Asker, forge: Forge, account: dict) -> tuple[str, list[dict], dict]:
    state, data, err = await ask.get(f"https://{forge.host}/api/v4/users/{account['id']}/projects",
                                     {"order_by": "last_activity_at", "per_page": str(GITLAB_PROJECTS)})
    if state != "ok":
        return state, [], err
    if not isinstance(data, list):
        return "unknown", [], {}
    repos = []
    for r in _rows(data):
        ns = r.get("namespace") if isinstance(r.get("namespace"), dict) else {}
        pid, path = r.get("id"), r.get("path")
        # The account's own namespace only: never a group's project the account is a member of.
        if ns.get("kind") != "user" or _text(ns.get("path")).lower() != account["handle"].lower():
            continue
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or not _repo_name_ok(path) or not r.get("default_branch"):
            continue
        # The keyless list does not say whether a project is a fork, so `fork` is unknown (None).
        repos.append({"name": f"{account['handle']}/{path}", "url": f"https://{forge.host}/{account['handle']}/{path}", "fork": None,
                      "_at": base.iso(r.get("last_activity_at")),
                      "_ask": (f"https://{forge.host}/api/v4/projects/{pid}/repository/commits", {"per_page": str(COMMITS_PER_REPO)})})
    return "ok", repos, {}


def _gitlab_commits(data) -> list[dict]:
    return [{"name": _text(c.get("author_name")), "email": _text(c.get("author_email")), "date": c.get("authored_date"), "linked": False}
            for c in _rows(data)]


async def _forgejo_account(ask: _Asker, forge: Forge, username: str) -> tuple[str, dict, dict]:
    state, data, err = await ask.get(f"https://{forge.host}/api/v1/users/{quote(username, safe='')}")
    if state != "ok":
        return state, {}, err
    d = data if isinstance(data, dict) else {}
    handle = d.get("login")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not forge.handle_re.fullmatch(handle):
        return "unknown", {}, {}
    return "found", {"handle": handle, "display_name": base.clean(d.get("full_name"), base.NAME_MAX)}, {}


async def _forgejo_repos(ask: _Asker, forge: Forge, account: dict) -> tuple[str, list[dict], dict]:
    handle = account["handle"]
    state, data, err = await ask.get(f"https://{forge.host}/api/v1/users/{quote(handle, safe='')}/repos", {"limit": str(FORGEJO_REPOS)})
    if state != "ok":
        return state, [], err
    if not isinstance(data, list):
        return "unknown", [], {}
    repos = []
    for r in _rows(data):
        owner = r.get("owner") if isinstance(r.get("owner"), dict) else {}
        name = r.get("name")
        if _text(owner.get("login")).lower() != handle.lower() or not _repo_name_ok(name):
            continue
        if r.get("empty") is True or r.get("private") is True or r.get("mirror") is True:
            continue        # a mirror is somebody else's history
        repos.append({"name": f"{handle}/{name}", "url": f"https://{forge.host}/{handle}/{name}", "fork": r.get("fork") is True,
                      "_at": base.iso(r.get("updated_at")),
                      "_ask": (f"https://{forge.host}/api/v1/repos/{quote(handle, safe='')}/{quote(name, safe='')}/commits",
                               {"limit": str(COMMITS_PER_REPO), "stat": "false", "verification": "false", "files": "false"})})
    return "ok", repos, {}


def _forgejo_commits(data, login: str) -> list[dict]:
    out = []
    for c in _rows(data):
        commit = c.get("commit") if isinstance(c.get("commit"), dict) else {}
        author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
        linked = c.get("author") if isinstance(c.get("author"), dict) else {}
        out.append({"name": _text(author.get("name")), "email": _text(author.get("email")), "date": author.get("date"),
                    "linked": _text(linked.get("login")).casefold() == login.casefold()})
    return out


_KINDS = {
    # kind -> (account, repositories, commit rows, statuses that mean "an empty repository")
    "gitlab": (_gitlab_account, _gitlab_repos, lambda data, login: _gitlab_commits(data), (404,)),
    "forgejo": (_forgejo_account, _forgejo_repos, _forgejo_commits, (404, 409)),
}


def pick_repos(repos: list[dict]) -> list[dict]:
    """Up to MAX_REPOS: originals before forks (unknown counts as an original), newest first."""
    newest = sorted(repos, key=lambda r: r["_at"], reverse=True)
    return sorted(newest, key=lambda r: r["fork"] is True)[:MAX_REPOS]


def collect(read: list[tuple[dict, list[dict]]], login: str, display_name: str) -> tuple[list[dict], dict]:
    """(email rows, counts) from [(repository, its commit rows)]. Pure, so the rules can be tested alone."""
    found: "OrderedDict[str, dict]" = OrderedDict()
    counts = {"commits_seen": 0, "own": 0, "noreply": 0, "other_authors": 0}
    for repo, commits in read:
        for c in commits:
            counts["commits_seen"] += 1
            how = "forge_attributed" if c["linked"] else "author_line_match" if is_own(c["name"], c["email"], login, display_name) else ""
            if not how:
                counts["other_authors"] += 1       # somebody else's commit: counted, never returned
                continue
            counts["own"] += 1
            email = base.safe_email(c["email"])
            if not email:
                counts["noreply"] += "@" in c["email"]
                continue
            when = base.iso(c["date"])
            row = found.get(email.lower())
            if row is None:
                row = found[email.lower()] = {"email": email, "name": base.clean(c["name"], base.NAME_MAX), "how": how, "commits": 0,
                                              "first_commit": when, "last_commit": when, "repos": []}
            row["commits"] += 1
            if how == "forge_attributed":
                row["how"] = how                    # the stronger tie stands
            if when:
                row["first_commit"] = min(row["first_commit"] or when, when)
                row["last_commit"] = max(row["last_commit"], when)
            if repo["name"] not in row["repos"] and len(row["repos"]) < MAX_ROW_REPOS:
                row["repos"].append(repo["name"])
    rows = sorted(found.values(), key=lambda r: (r["how"] != "forge_attributed", -r["commits"]))[:MAX_EMAILS]
    for r in rows:
        r["how_note"] = HOW_NOTES[r["how"]]
        r["self_declared"] = True
    return rows, counts


def _empty(site: str, forge: Forge, username: str, state: str, **extra) -> dict:
    return {"site": site, "site_name": forge.name, "username": username, "state": state, "cached": False, "emails": [],
            "emails_state": "none" if state == "not_found" else "unknown", "complete": state in ("not_found", "not_asked"),
            "sections": {"account": state, "repos": "not_asked"}, "repos": [],
            "counts": {"repos_listed": 0, "repos_read": 0, "commits_seen": 0, "own": 0, "noreply": 0, "other_authors": 0},
            "requests": 0, "note": NOTE, **extra}


async def _read(client: httpx.AsyncClient, site: str, forge: Forge, username: str) -> dict:
    account_of, repos_of, commits_of, empty_statuses = _KINDS[forge.kind]
    ask = _Asker(client, site)

    def limited(out: dict) -> dict:
        return {**out, "retry_after": ask.retry_after} if ask.retry_after and out["state"] == "rate_limited" else out

    state, account, err = await account_of(ask, forge, username)
    if state != "found":
        return limited(_empty(site, forge, username, state, requests=ask.used, **(err if state in ("failed", "rate_limited") else {})))

    out = _empty(site, forge, username, "found", handle=account["handle"], profile_url=f"https://{forge.host}/{account['handle']}",
                 display_name=account["display_name"])
    repos_state, repos, _err = await repos_of(ask, forge, account)
    out["counts"]["repos_listed"] = len(repos)
    picked = pick_repos(repos) if repos_state == "ok" else []
    out["sections"]["repos"] = repos_state if repos_state != "ok" else "ok" if picked else "none"

    answers = await asyncio.gather(*(ask.get(r["_ask"][0], r["_ask"][1], absent=empty_statuses) for r in picked))
    read = []
    for repo, (commit_state, data, _e) in zip(picked, answers):
        # An empty repository has no commits to read: that is an answer.
        commits = commits_of(data, account["handle"]) if commit_state == "ok" and isinstance(data, list) else []
        row_state = "ok" if commit_state == "ok" and isinstance(data, list) else "empty" if commit_state == "not_found" else \
            "unknown" if commit_state == "ok" else commit_state
        out["repos"].append({"name": repo["name"], "url": repo["url"], "fork": repo["fork"], "state": row_state, "commits_seen": len(commits)})
        if row_state == "ok":
            read.append((repo, commits))

    emails, counts = collect(read, account["handle"], account["display_name"])
    out["emails"] = emails
    out["counts"].update(counts, repos_read=len(read))
    out["complete"] = out["sections"]["repos"] in ("ok", "none") and all(r["state"] in ("ok", "empty") for r in out["repos"])
    out["emails_state"] = "found" if emails else "none" if out["complete"] else "unknown"
    out["requests"] = ask.used
    if ask.retry_after:
        out["retry_after"] = ask.retry_after
    return out


async def run_commit_emails(site: str, username: str) -> dict:
    """One account on one forge. `site` is a key of SITES and `username` has passed
    core.validate.username: the router checks both."""
    forge = SITES[site]
    if not forge.handle_re.fullmatch(username):
        return _empty(site, forge, username, "not_asked")          # not a name this site can hold: nothing is requested
    key = (site, username.lower())
    cached = _cache_get(key)
    if cached is not None:
        return {**cached, "username": username, "cached": True}
    wait = _backing_off(site)
    if wait:
        # The site said 429 to this server a moment ago. No request, and not "not found".
        return _empty(site, forge, username, "rate_limited", retry_after=wait,
                      **error_fields(code="rate_limited", detail="Waiting after HTTP 429"))
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0), follow_redirects=False) as client:
            out = await asyncio.wait_for(_read(client, site, forge, username), TOTAL_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        out = _empty(site, forge, username, "failed", **error_fields(code=classify(e), detail=type(e).__name__))
    # The site, states and counts only. The handle, the names and the addresses are never logged.
    log.info("commit emails finished", extra={"site": site, "state": out["state"], "repos_section": out["sections"]["repos"],
                                              "complete": out["complete"], "emails": len(out["emails"]), "requests": out["requests"],
                                              "commits_seen": out["counts"]["commits_seen"]})
    settled = out["state"] == "not_found" or (out["state"] == "found" and out["complete"])
    _cache_put(key, out, CACHE_TTL_OK if settled else CACHE_TTL_PARTIAL)
    return out
