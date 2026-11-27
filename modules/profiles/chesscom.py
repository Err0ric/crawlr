"""Chess.com: the published-data API.

  GET https://api.chess.com/pub/player/{handle}

Recorded 2026-11-26. 200 with the player (username, name, location, country as an API address
ending in the country code, followers, joined and last_online in seconds, status, avatar), or
404 `{"code": 0, "message": "User \\"...\\" not found."}`. The handle is sent in lower case, as
the API's addresses are.
"""

import re

from . import base

ID, SITE = "chesscom", "Chess.com"
URL = "https://api.chess.com/pub/player/{}"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{3,25}$")
_COUNTRY_RE = re.compile(r"/pub/country/([A-Z]{2})$")


async def read(client, username: str) -> base.Result:
    name = username.lower()
    reply = await base.get_json(client, URL.format(name))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("username")
    if not isinstance(handle, str) or handle.lower() != name or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    country = _COUNTRY_RE.search(d.get("country") if isinstance(d.get("country"), str) else "")
    status = d.get("status") if isinstance(d.get("status"), str) else ""
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://www.chess.com/member/{handle}", display_name=d.get("name"),
        location=d.get("location") or (country.group(1) if country else ""), created=d.get("joined"), last_active=d.get("last_online"),
        stats={"followers": d.get("followers")}, note="closed" if status.startswith("closed") else "", avatar=d.get("avatar")))
