"""Lobsters: the JSON form of a user page.

  GET https://lobste.rs/~{handle}.json

Recorded 2026-11-26. 200 with the user (username, created_at, about as HTML, avatar_url as a
path on the site, github_username, mastodon_username, karma for most accounts), or 404 (a web
page titled "User not found"). The picture address is built here from the checked handle.
"""

import re

from . import base

ID, SITE = "lobsters", "Lobsters"
URL = "https://lobste.rs/~{}.json"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,24}$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(username))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("username")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    text, links = base.html_text(d.get("about"))
    picture = d.get("avatar_url") if isinstance(d.get("avatar_url"), str) else ""
    own = re.fullmatch(rf"/avatars/{re.escape(handle)}-(\d{{2,4}})\.png", picture)
    note = "admin" if d.get("is_admin") else "moderator" if d.get("is_moderator") else ""
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://lobste.rs/~{handle}", bio=text, links=links, created=d.get("created_at"),
        accounts=[base.known_account("github", d.get("github_username"), "listed")], stats={"karma": d.get("karma")}, note=note,
        avatar=f"https://lobste.rs/avatars/{handle}-{own.group(1)}.png" if own else ""))
