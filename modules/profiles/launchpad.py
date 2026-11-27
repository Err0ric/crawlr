"""Launchpad: the public person record of the Launchpad web service.

  GET https://api.launchpad.net/1.0/~{name}

Recorded 2026-11-27. 200 with the person or team (name, display_name, description, karma,
date_created, is_team, is_valid, private, web_link and a set of collection links), or a 404 with
a plain text body when there is no such name. Launchpad names are lower case, so the name is
asked in lower case.

`is_valid` false means the record is not an active account: Launchpad creates such records by
itself for people named in imported bugs, translations and packages. The row says so in `note`,
because a record like that was not made by the person and proves nothing about who holds the
name. A team is noted as a team. The picture is not read: its address answers with a redirect
to another host, and no redirect is followed here.
"""

import re

from . import base

ID, SITE = "launchpad", "Launchpad"
URL = "https://api.launchpad.net/1.0/~{}"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{1,63}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,63}$")
NOT_ACTIVE = "not an active account"


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(username.lower()))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("name")
    if not isinstance(handle, str) or handle != username.lower() or not _NAME_RE.fullmatch(handle):
        return base.UNKNOWN
    note = "team" if d.get("is_team") is True else NOT_ACTIVE if d.get("is_valid") is False else ""
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://launchpad.net/~{handle}", display_name=d.get("display_name"), bio=d.get("description"),
        created=d.get("date_created"), stats={"karma": d.get("karma")}, note=note))
