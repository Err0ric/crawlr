"""dev.to: the public user lookup of the Forem API.

  GET https://dev.to/api/users/by_username?url={handle}

Recorded 2026-11-26. 200 with the user (username, name, summary, location, website_url,
joined_at as "Dec 27, 2015", twitter_username, github_username, profile_image), or 404
`{"error": "not found", "status": 404}`.
"""

import re

from . import base

ID, SITE = "devto", "dev.to"
URL = "https://dev.to/api/users/by_username"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{2,30}$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL, {"url": username})
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("username")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    accounts = [base.known_account("github", d.get("github_username"), "listed"), base.known_account("twitter", d.get("twitter_username"), "listed")]
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://dev.to/{handle}", display_name=d.get("name"), bio=d.get("summary"), location=d.get("location"),
        website=d.get("website_url"), created=d.get("joined_at"), accounts=accounts, avatar=d.get("profile_image")))
