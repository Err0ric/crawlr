"""Lichess: the public user record.

  GET https://lichess.org/api/user/{handle}

Recorded 2026-11-26. 200 with the user (id, username, createdAt and seenAt in milliseconds,
profile {bio, realName, location, links}, count {all, ...}, perfs {blitz: {rating}, ...}), or
404 `{"error": "Not found"}`. A closed account answers 200 with `disabled: true` and nothing
else. `profile.links` is the user's own list of links, one per line. Lichess has no pictures.
"""

import re

from . import base

ID, SITE = "lichess", "Lichess"
URL = "https://lichess.org/api/user/{}"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$")
RATED = ("bullet", "blitz", "rapid", "classical")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(username))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("username")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    about = d.get("profile") if isinstance(d.get("profile"), dict) else {}
    counts = d.get("count") if isinstance(d.get("count"), dict) else {}
    perfs = d.get("perfs") if isinstance(d.get("perfs"), dict) else {}
    listed = [base.safe_link(line) for line in str(about.get("links") or "").splitlines()[:10]]
    stats = {"games": counts.get("all")}
    for kind in RATED:
        perf = perfs.get(kind) if isinstance(perfs.get(kind), dict) else {}
        if perf.get("games") and not perf.get("prov"):
            stats[f"rating_{kind}"] = perf.get("rating")
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://lichess.org/@/{handle}", display_name=about.get("realName"), bio=about.get("bio"),
        location=about.get("location"), links=listed, created=d.get("createdAt"), last_active=d.get("seenAt"),
        accounts=[base.account_from_url(u, "listed") for u in listed if u], stats=stats, note="closed" if d.get("disabled") else ""))
