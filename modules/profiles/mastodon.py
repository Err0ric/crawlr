"""Mastodon: the account lookup on a short, fixed list of large public instances.

  GET https://{instance}/api/v1/accounts/lookup?acct={handle}

Recorded 2026-11-26 (mastodon.social) and 2026-11-27 (the others). 200 with the account, 404
`{"error": "Record not found"}` when there is none. Only a local account is read (no "@" in
`acct`). `note` and each profile field's `value` are HTML. A field with `verified_at` is a link
whose page links back with rel="me": the instance checked it, so it is returned with
`proof: "verified_link"`; the others are `"listed"`.

`INSTANCES` is the whole list and the only place it is written. Each instance is a source of
its own in the registry (`SOURCES` here, spread into modules/profiles/__init__.py): its own
row when the handle is found there, its own state, its own cache entry and its own wait after
a 429. So an instance that refused or failed is reported as that, and never as "not found".
The same handle on two instances is two accounts, and nothing here says they are one person.

IDs: "mastodon" for mastodon.social (as before), else "mastodon_" and the host with its dots
as underscores ("mastodon_fosstodon_org"). Site names: "Mastodon", else "Mastodon (host)".
"""

import re
from urllib.parse import urlsplit

from . import base

ID, SITE = "mastodon", "Mastodon"
HOST = "mastodon.social"
# Large general or technical instances with open registration histories, each checked on
# 2026-11-27 to answer the public lookup without a key. Fixed: a handle is never asked of a
# host that is not in this tuple.
INSTANCES = (HOST, "mastodon.online", "mstdn.social", "fosstodon.org", "hachyderm.io", "infosec.exchange", "mas.to", "mastodon.world")
URL = "https://{}/api/v1/accounts/lookup"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,30}$")
_WEB_RE = re.compile(r"^https?://", re.I)


def field_links(fields) -> tuple[list[str], list[dict]]:
    """(links, linked accounts) from the profile's fields table."""
    links, accounts = [], []
    for f in fields if isinstance(fields, list) else []:
        if not isinstance(f, dict):
            continue
        text, hrefs = base.html_text(f.get("value"))
        # Only a value that is written as a web address is a link. A bare word with a dot in it
        # ("she.her") is text, so nothing is promoted to "https://she.her".
        candidate = hrefs[0] if hrefs else text
        url = base.safe_link(candidate) if _WEB_RE.match(candidate.strip()) else ""
        if not url:
            continue
        links.append(url)
        proof = "verified_link" if f.get("verified_at") else "listed"
        linked = base.account_from_url(url, proof)
        if linked is None and proof == "verified_link":
            linked = base.account(urlsplit(url).hostname or "", "", url, proof)
        accounts.append(linked)
    return links, accounts


async def read_instance(client, host: str, source: str, site: str, username: str) -> base.Result:
    reply = await base.get_json(client, URL.format(host), {"acct": username})
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
    note = "suspended" if d.get("suspended") else "moved" if d.get("moved") else "bot" if d.get("bot") else ""
    return base.Result("found", base.profile(
        source, site, handle, f"https://{host}/@{handle}", display_name=d.get("display_name"), bio=text, links=[*links, *note_links],
        created=d.get("created_at"), last_active=d.get("last_status_at"), accounts=accounts,
        stats={"followers": d.get("followers_count"), "following": d.get("following_count"), "posts": d.get("statuses_count")},
        note=note, avatar=picture, avatar_default=isinstance(picture, str) and picture.endswith("/missing.png")))


async def read(client, username: str) -> base.Result:
    """mastodon.social alone, for a caller that wants the one instance."""
    return await read_instance(client, HOST, ID, SITE, username)


class Instance:
    """One instance as a source: the ID, SITE, HANDLE_RE and read() the registry asks of a module."""

    def __init__(self, host: str):
        self.HOST = host
        self.ID = ID if host == HOST else "mastodon_" + host.replace(".", "_").replace("-", "_")
        self.SITE = SITE if host == HOST else f"{SITE} ({host})"
        self.HANDLE_RE = HANDLE_RE

    async def read(self, client, username: str) -> base.Result:
        return await read_instance(client, self.HOST, self.ID, self.SITE, username)


SOURCES = tuple(Instance(host) for host in INSTANCES)
