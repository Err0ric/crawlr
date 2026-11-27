"""Hacker News: the official Firebase API.

  GET https://hacker-news.firebaseio.com/v0/user/{id}/created.json
  GET https://hacker-news.firebaseio.com/v0/user/{id}/karma.json
  GET https://hacker-news.firebaseio.com/v0/user/{id}/about.json

Recorded 2026-11-26. The whole record (`/v0/user/{id}.json`) carries every item the user ever
submitted (761 KB for one busy account), so the three small fields are asked for one by one.
Each answers 200 with the bare value, or `null` when there is no such user. IDs are case
sensitive: "Dang" is `null` where "dang" is a user, so the handle is asked exactly as typed.
`about` is HTML and is returned as plain text, with its links.
"""

import asyncio
import re

from . import base

ID, SITE = "hackernews", "Hacker News"
URL = "https://hacker-news.firebaseio.com/v0/user/{}/{}.json"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{2,15}$")


async def read(client, username: str) -> base.Result:
    created, karma, about = await asyncio.gather(*(base.get_json(client, URL.format(username, part)) for part in ("created", "karma", "about")))
    stop = base.settle(created)
    if stop:
        return stop
    if created.data is None:
        return base.NOT_FOUND
    if base.count(created.data) is None:
        return base.UNKNOWN
    # The other two fields are extras: one that did not answer leaves its field empty.
    text, links = base.html_text(about.data) if about.status == 200 and about.parsed else ("", [])
    points = karma.data if karma.status == 200 and karma.parsed else None
    return base.Result("found", base.profile(
        ID, SITE, username, f"https://news.ycombinator.com/user?id={username}", bio=text, links=links, created=created.data,
        stats={"karma": points}))
