"""Gravatar: the public profile at a profile address (gravatar.com/{handle}).

  GET https://api.gravatar.com/v3/profiles/{handle}

Recorded 2026-11-26. Without a key it answers 200 with the public card (display_name,
profile_url, avatar_url, location, description, job_title, company, verified_accounts), or 404
`{"error": "Profile not found"}`. The keyless allowance is small (`x-ratelimit-limit: 100`
an hour for the server's address); past it the answer is 429, which is "rate_limited".

A handle that is a 32 or 64 character hex string is not asked: that would be a lookup by the
hash of an email address, which is modules/gravatar.py's job, on an email case.
"""

import re

from . import base

ID, SITE = "gravatar", "Gravatar"
URL = "https://api.gravatar.com/v3/profiles/{}"
HANDLE_RE = re.compile(r"^(?![0-9a-fA-F]{32}$)(?![0-9a-fA-F]{64}$)[A-Za-z0-9]{1,64}$")


async def read(client, username: str) -> base.Result:
    slug = username.lower()
    reply = await base.get_json(client, URL.format(slug))
    stop = base.settle(reply)
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    if str(d.get("profile_url") or "").lower().rstrip("/") != f"https://gravatar.com/{slug}":
        return base.UNKNOWN
    accounts = []
    for a in d.get("verified_accounts") if isinstance(d.get("verified_accounts"), list) else []:
        if isinstance(a, dict) and not a.get("is_hidden"):
            accounts.append(base.account_from_url(a.get("url"), "listed") or base.account(a.get("service_label") or "", "", a.get("url"), "listed"))
    work = [base.clean(d.get(k), base.FIELD_MAX) for k in ("job_title", "company")]
    return base.Result("found", base.profile(
        ID, SITE, slug, f"https://gravatar.com/{slug}", display_name=d.get("display_name"), bio=d.get("description"),
        location=d.get("location"), company=", ".join(w for w in work if w), accounts=accounts,
        links=[a["url"] for a in accounts if a], avatar=d.get("avatar_url")))
