"""Mastodon: the account lookup on mastodon.social, and only there.

  GET https://mastodon.social/api/v1/accounts/lookup?acct={handle}

Recorded 2026-11-26. 200 with the account, 404 `{"error": "Record not found"}` when there is
none. Only a local account is read (no "@" in `acct`). `note` and each profile field's `value`
are HTML. A field with `verified_at` is a link whose page links back with rel="me": Mastodon
checked it, so it is returned with `proof: "verified_link"`; the others are `"listed"`.
"""

import re
from urllib.parse import urlsplit

from . import base

ID, SITE = "mastodon", "Mastodon"
HOST = "mastodon.social"
URL = f"https://{HOST}/api/v1/accounts/lookup"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,30}$")


def field_links(fields) -> tuple[list[str], list[dict]]:
    """(links, linked accounts) from the profile's fields table."""
    links, accounts = [], []
    for f in fields if isinstance(fields, list) else []:
        if not isinstance(f, dict):
            continue
        text, hrefs = base.html_text(f.get("value"))
        url = base.safe_link(hrefs[0] if hrefs else text if " " not in text else "")
        if not url:
            continue
        links.append(url)
        proof = "verified_link" if f.get("verified_at") else "listed"
        linked = base.account_from_url(url, proof)
        if linked is None and proof == "verified_link":
            linked = base.account(urlsplit(url).hostname or "", "", url, proof)
        accounts.append(linked)
    return links, accounts


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL, {"acct": username})
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    handle = d.get("username")
    if not isinstance(handle, str) or handle.lower() != username.lower() or d.get("acct") != handle or not HANDLE_RE.fullmatch(handle):
        return base.UNKNOWN
    text, note_links = base.html_text(d.get("note"))
    links, accounts = field_links(d.get("fields"))
    picture = d.get("avatar_static") or d.get("avatar")
    note = "suspended" if d.get("suspended") else "bot" if d.get("bot") else ""
    return base.Result("found", base.profile(
        ID, SITE, handle, f"https://{HOST}/@{handle}", display_name=d.get("display_name"), bio=text, links=[*links, *note_links],
        created=d.get("created_at"), last_active=d.get("last_status_at"), accounts=accounts,
        stats={"followers": d.get("followers_count"), "following": d.get("following_count"), "posts": d.get("statuses_count")},
        note=note, avatar=picture, avatar_default=isinstance(picture, str) and picture.endswith("/missing.png")))
