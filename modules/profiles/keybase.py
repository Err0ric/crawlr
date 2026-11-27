"""Keybase: the public user lookup, with the accounts the user has proven.

  GET https://keybase.io/_/api/1.0/user/lookup.json?usernames={handle}&fields=basics,profile,proofs_summary,pictures

Recorded 2026-11-26. 200 with `{"status": {"code": 0, "name": "OK"}, "them": [...]}`: one
record when the user exists, `"them": [null]` when not. `fields` keeps the PGP key bundles out
of the answer (about 9 KB instead of 100 KB).

`proofs_summary.all` lists the accounts on other sites that the user has signed a statement
for, each with the address of the public proof. Only proofs Keybase reports as passing
(`state` 1) are returned, as linked accounts with `proof: "keybase"` and `proof_url`.
"""

import re

from . import base

ID, SITE = "keybase", "Keybase"
URL = "https://keybase.io/_/api/1.0/user/lookup.json"
FIELDS = "basics,profile,proofs_summary,pictures"
HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{2,16}$")
PROOF_OK = 1
_KNOWN = {"twitter": "twitter", "github": "github", "reddit": "reddit", "hackernews": "hackernews", "facebook": "facebook"}
_DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$")


def proofs(summary) -> list[dict]:
    """The proven accounts in a `proofs_summary`, as linked accounts."""
    rows = summary.get("all") if isinstance(summary, dict) else None
    out = []
    for p in rows if isinstance(rows, list) else []:
        if not isinstance(p, dict) or p.get("state") != PROOF_OK:
            continue
        kind, tag, proof_url = str(p.get("proof_type") or ""), p.get("nametag"), p.get("proof_url") or ""
        if not isinstance(tag, str):
            continue
        if kind in _KNOWN:
            out.append(base.known_account(_KNOWN[kind], tag, "keybase", proof_url))
        elif kind in ("generic_web_site", "dns"):
            if _DOMAIN_RE.fullmatch(tag):
                out.append(base.account("DNS" if kind == "dns" else "Website", tag.lower(), f"https://{tag.lower()}", "keybase", proof_url))
        else:
            # Any other service: the address Keybase gives for the account, when it is a plain link.
            url = p.get("service_url")
            group = base.clean(p.get("presentation_group"), 60) or kind
            out.append(base.account_from_url(url, "keybase", proof_url) or base.account(group, tag, url, "keybase", proof_url))
    return [a for a in out if a]


async def read(client, username: str) -> base.Result:
    name = username.lower()
    reply = await base.get_json(client, URL, {"usernames": name, "fields": FIELDS})
    stop = base.settle(reply)
    if stop:
        return stop
    data = reply.data if isinstance(reply.data, dict) else {}
    status = data.get("status") if isinstance(data.get("status"), dict) else {}
    if status.get("name") == "NOT_FOUND":
        return base.NOT_FOUND
    them = data.get("them")
    if status.get("code") != 0 or not isinstance(them, list) or len(them) != 1:
        return base.UNKNOWN
    user = them[0]
    if user is None:
        return base.NOT_FOUND
    basics = user.get("basics") if isinstance(user, dict) and isinstance(user.get("basics"), dict) else {}
    if str(basics.get("username") or "").lower() != name:
        return base.UNKNOWN
    about = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    pictures = user.get("pictures") if isinstance(user.get("pictures"), dict) else {}
    primary = pictures.get("primary") if isinstance(pictures.get("primary"), dict) else {}
    linked = proofs(user.get("proofs_summary"))
    return base.Result("found", base.profile(
        ID, SITE, name, f"https://keybase.io/{name}", display_name=about.get("full_name"), bio=about.get("bio"),
        location=about.get("location"), created=basics.get("ctime"), accounts=linked, stats={"proofs": len(linked)},
        avatar=primary.get("url")))
