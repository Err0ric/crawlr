"""GitLab: the public user lookup on gitlab.com.

  GET https://gitlab.com/api/v4/users?username={handle}

Recorded 2026-11-26. 200 with a list: one row (id, username, name, state, public_email,
avatar_url, web_url) when the account exists, `[]` when it does not. The fuller record
(`/api/v4/users/{id}`) answers 403 without a token, so it is not asked.
"""

import re

from . import base

ID, SITE = "gitlab", "GitLab"
URL = "https://gitlab.com/api/v4/users"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL, {"username": username})
    stop = base.settle(reply, not_found=())
    if stop:
        return stop
    if not isinstance(reply.data, list):
        return base.UNKNOWN
    if not reply.data:
        return base.NOT_FOUND
    row = next((r for r in reply.data if isinstance(r, dict) and str(r.get("username") or "").lower() == username.lower()), None)
    if row is None or not HANDLE_RE.fullmatch(row["username"]):
        return base.UNKNOWN
    handle = row["username"]
    state = row.get("state")
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://gitlab.com/{handle}", display_name=row.get("name"), emails=[row.get("public_email")],
        note=state if isinstance(state, str) and state != "active" else "", avatar=row.get("avatar_url")))
