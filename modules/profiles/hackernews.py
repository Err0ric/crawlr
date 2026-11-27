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


NOT_READ = "Hacker News did not answer for the {}. Unknown, not empty."


async def read(client, username: str) -> base.Result:
    created, karma, about = await asyncio.gather(*(base.get_json(client, URL.format(username, part)) for part in ("created", "karma", "about")),
                                                 return_exceptions=True)
    if isinstance(created, BaseException):
        raise created
    # Absence is a 200 with `null`, never a 404.
    stop = base.settle(created, not_found=())
    if stop:
        return stop
    if created.data is None:
        return base.NOT_FOUND
    if base.count(created.data) is None:
        return base.UNKNOWN
    # The other two fields are extras, each with its own answer. One that was not read is said
    # so, in the row's note and in the source's: an unread bio is never "no bio". Such an
    # answer is unsettled, so it is asked again soon.
    extras = {"bio": about, "karma": karma}
    for reply in extras.values():
        if isinstance(reply, asyncio.CancelledError):
            raise reply
    unread = [name for name, reply in extras.items() if isinstance(reply, BaseException) or reply.status != 200 or not reply.parsed]
    limited = [reply for reply in extras.values() if not isinstance(reply, BaseException) and reply.status == 429]
    text, links = base.html_text(about.data) if "bio" not in unread else ("", [])
    points = karma.data if "karma" not in unread else None
    row = base.profile(
        ID, SITE, username, f"https://news.ycombinator.com/user?id={username}", bio=text, links=links, created=created.data,
        stats={"karma": points}, note=" and ".join(unread) + " not read" if unread else "")
    if not unread:
        return base.Result("found", row)
    return base.Result("found", row, note=NOT_READ.format(" and the ".join(unread)), settled=False, limited=bool(limited),
                       retry_after=max((r.retry_after or 0 for r in limited), default=0) or None)
