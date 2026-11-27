"""Wikipedia (English): does the account exist, when was it registered and how much has it edited.

  GET https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={name}&usprop=editcount|registration&format=json

Recorded 2026-11-26. 200 with `{"query": {"users": [{...}]}}`: `userid`, `name`, `editcount`
and `registration` for an account, `"missing": ""` when there is none, `"invalid": ""` for a
name no account can have. The site writes a name with a capital first letter and spaces for
underscores ("Jimbo Wales"). The link goes to the account's list of edits, which exists for
every account; a user page may not.
"""

import re

from . import base

ID, SITE = "wikipedia", "Wikipedia"
URL = "https://en.wikipedia.org/w/api.php"
# Not four numbers with dots: an address is an unregistered editor, not an account.
HANDLE_RE = re.compile(r"^(?!\d{1,3}(?:\.\d{1,3}){3}$)[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9.])?$")
_NAME_RE = re.compile(r"^[A-Za-z0-9. _-]{1,64}$")


def _same(a: str, b: str) -> bool:
    return a.replace("_", " ").lower() == b.replace("_", " ").lower()


async def read(client, username: str) -> base.Result:
    reply = await base.get_json(client, URL, {"action": "query", "list": "users", "ususers": username, "usprop": "editcount|registration", "format": "json"})
    stop = base.settle(reply, not_found=())
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    error = d.get("error") if isinstance(d.get("error"), dict) else None
    if error is not None:
        return base.failed("rate_limited" if error.get("code") == "ratelimited" else "upstream", "API error")
    users = d.get("query", {}).get("users") if isinstance(d.get("query"), dict) else None
    user = users[0] if isinstance(users, list) and len(users) == 1 and isinstance(users[0], dict) else None
    if user is None:
        return base.UNKNOWN
    if "missing" in user or "invalid" in user:
        return base.NOT_FOUND
    name = user.get("name")
    if base.count(user.get("userid")) is None or not isinstance(name, str) or not _NAME_RE.fullmatch(name) or not _same(name, username):
        return base.UNKNOWN
    return base.Result("found", base.profile(
        ID, SITE, name, f"https://en.wikipedia.org/wiki/Special:Contributions/{name.replace(' ', '_')}",
        created=user.get("registration"), stats={"edits": user.get("editcount")}))
