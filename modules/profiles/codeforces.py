"""Codeforces: the official API's user record.

  GET https://codeforces.com/api/user.info?handles={handle}

Recorded 2026-11-26. 200 `{"status": "OK", "result": [{...}]}` (handle, firstName, lastName,
country, city, organization, rating, maxRating, friendOfCount, registrationTimeSeconds,
lastOnlineTimeSeconds, avatar), or 400 `{"status": "FAILED", "comment": "handles: User with
handle ... not found"}`. The API's own rate message is a FAILED answer whose comment speaks of
a call limit.

No picture is read: the picture host (userpic.codeforces.org) answered this tool's request with
503 and a web page on 2026-11-26, so asking would only ever report a picture that failed.
"""

import re

from . import base

ID, SITE = "codeforces", "Codeforces"
URL = "https://codeforces.com/api/user.info"
HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{3,24}$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL, {"handles": username})
    d = reply.data if isinstance(reply.data, dict) else {}
    if d.get("status") == "FAILED":
        comment = str(d.get("comment") or "").lower()
        if "not found" in comment:
            return base.NOT_FOUND
        return base.failed("rate_limited", "API call limit") if "limit" in comment else base.UNKNOWN
    stop = base.settle(reply, not_found=())
    if stop:
        return stop
    rows = d.get("result")
    user = rows[0] if d.get("status") == "OK" and isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict) else {}
    handle = user.get("handle")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    name = " ".join(base.clean(user.get(k), 50) for k in ("firstName", "lastName")).strip()
    place = ", ".join(p for p in (base.clean(user.get(k), 50) for k in ("city", "country")) if p)
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://codeforces.com/profile/{handle}", display_name=name, location=place,
        company=user.get("organization"), created=user.get("registrationTimeSeconds"), last_active=user.get("lastOnlineTimeSeconds"),
        stats={"rating": user.get("rating"), "max_rating": user.get("maxRating"), "friend_of": user.get("friendOfCount")}))
