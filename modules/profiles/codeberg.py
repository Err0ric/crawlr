"""Codeberg: the public user record of the Forgejo API.

  GET https://codeberg.org/api/v1/users/{handle}

Recorded 2026-11-26. 200 with the user (login, full_name, email, avatar_url, created, location,
website, description, followers_count, following_count, starred_repos_count), or 404
`{"message": "user redirect does not exist [name: ...]"}`. `email` is the address the user
chose to show, or a "noreply" placeholder, which is dropped.
"""

import re

from . import base

ID, SITE = "codeberg", "Codeberg"
URL = "https://codeberg.org/api/v1/users/{}"
HANDLE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38}[A-Za-z0-9])?$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(username))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("login")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://codeberg.org/{handle}", display_name=d.get("full_name"), bio=d.get("description"),
        location=d.get("location"), website=d.get("website"), emails=[d.get("email")], created=d.get("created"),
        stats={"followers": d.get("followers_count"), "following": d.get("following_count"), "starred": d.get("starred_repos_count")},
        avatar=d.get("avatar_url")))
