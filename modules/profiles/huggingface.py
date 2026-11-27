"""Hugging Face: the Hub API's public user overview.

  GET https://huggingface.co/api/users/{handle}/overview

Recorded 2026-11-26. 200 with the user (user, fullname, details, avatarUrl, createdAt,
numModels, numDatasets, numSpaces, numFollowers, numFollowing, numLikes, orgs), or 404
`{"error": "This user does not exist"}`. A handle typed in another case answers 307 to the
same path with the site's spelling ("chris" to "/api/users/Chris/overview"); that one address is
built here, on the same host, and asked once. The organizations the user shows are returned as
items, each with an address built here from its checked name.
"""

import re

from . import base

ID, SITE = "huggingface", "Hugging Face"
URL = "https://huggingface.co/api/users/{}/overview"
HANDLE_RE = re.compile(r"^(?!.*(?:--|\.\.))[A-Za-z0-9](?:[A-Za-z0-9._-]{0,40}[A-Za-z0-9])?$")
_PATH_RE = re.compile(r"^/api/users/([^/?#]{1,64})/overview$")


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(username))
    moved = _PATH_RE.fullmatch(reply.location) if reply.status in (301, 302, 307, 308) else None
    if moved and moved.group(1).lower() == username.lower() and HANDLE_RE.fullmatch(moved.group(1)):
        reply = await base.get_json(client, URL.format(moved.group(1)))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("user")
    if not isinstance(handle, str) or handle.lower() != username.lower() or not HANDLE_RE.fullmatch(handle) or d.get("type", "user") != "user":
        return base.UNKNOWN
    orgs = []
    for o in d.get("orgs") if isinstance(d.get("orgs"), list) else []:
        name = o.get("name") if isinstance(o, dict) else None
        if isinstance(name, str) and HANDLE_RE.fullmatch(name):
            orgs.append(base.item(o.get("fullname") or name, f"https://huggingface.co/{name}", "organization"))
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://huggingface.co/{handle}", display_name=d.get("fullname"), bio=d.get("details"),
        created=d.get("createdAt"), items=orgs,
        stats={"followers": d.get("numFollowers"), "following": d.get("numFollowing"), "models": d.get("numModels"),
               "datasets": d.get("numDatasets"), "spaces": d.get("numSpaces"), "likes": d.get("numLikes")},
        avatar=d.get("avatarUrl")))
