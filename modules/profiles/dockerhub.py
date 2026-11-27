"""Docker Hub: the public account record.

  GET https://hub.docker.com/v2/users/{handle}/
  GET https://hub.docker.com/v2/orgs/{handle}      only when the first answers 308 to exactly that path

Recorded 2026-11-26. A user answers 200 (username, full_name, location, company, profile_url,
date_joined, gravatar_url, type "User"). An organization answers 308 with
`Location: /v2/orgs/{handle}`; that address is built here, on the same host, and answers 200
(orgname, type "Organization"). 404 `{"message": "User not found"}` when there is neither.
"""

import re

from . import base

ID, SITE = "dockerhub", "Docker Hub"
HOST = "https://hub.docker.com"
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,29}$")


async def read(client, username: str) -> base.Result:
    name = username.lower()
    reply = await base.get_json(client, f"{HOST}/v2/users/{name}/")
    org = reply.status in (301, 302, 307, 308) and reply.location.rstrip("/") == f"/v2/orgs/{name}"
    if org:
        reply = await base.get_json(client, f"{HOST}/v2/orgs/{name}")
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("orgname") if org else d.get("username")
    if not isinstance(handle, str) or handle.lower() != name:
        return base.UNKNOWN
    return base.Result("found", base.profile(
        ID, SITE, name, f"https://hub.docker.com/u/{name}", display_name=d.get("full_name"), location=d.get("location"),
        company=d.get("company"), website=d.get("profile_url"), emails=[d.get("gravatar_email")], created=d.get("date_joined"),
        note="organization" if org else "", avatar=d.get("gravatar_url")))
