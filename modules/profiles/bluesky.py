"""Bluesky: the public profile lookup for {handle}.bsky.social.

  GET https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}.bsky.social

Recorded 2026-11-14 as tests/fixtures/probe/bluesky_profile.json (HTTP 200) and
bluesky_not_found.json (HTTP 400, "Profile not found"). modules/handle_probe.py reads Bluesky
through this module too.
"""

import re

from core.boilerplate import clean_bio

from . import base

ID, SITE = "bluesky", "Bluesky"
URL = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
# A bsky.social handle is one DNS label: no underscore and no period.
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,16}[a-z0-9])$")
HANDLE_RE = re.compile(LABEL_RE.pattern, re.I)


async def read(client, username: str) -> base.Result:
    handle = f"{username.lower()}.bsky.social"
    reply = await base.get_json(client, URL, {"actor": handle})
    d = reply.data if isinstance(reply.data, dict) else {}
    if reply.status == 400 and "profile not found" in str(d.get("message") or "").lower():
        return base.NOT_FOUND
    stop = base.settle(reply, not_found=())
    if stop:
        return stop
    if str(d.get("handle") or "").lower() != handle:
        return base.UNKNOWN
    name = base.clean(d.get("displayName"), base.NAME_MAX)
    about = base.clean(d.get("description"), base.GUARD_BIO_MAX)
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://bsky.app/profile/{handle}", display_name=name, bio=clean_bio(about, "bluesky", handle, name),
        created=d.get("createdAt"),
        stats={"followers": d.get("followersCount"), "following": d.get("followsCount"), "posts": d.get("postsCount")},
        avatar=d.get("avatar")))
