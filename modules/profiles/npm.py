"""npm: the packages a maintainer is listed on, from the registry's search.

  GET https://registry.npmjs.org/-/v1/search?text=maintainer:{handle}&size=20

Recorded 2026-11-26. 200 with `{"objects": [...], "total": n}`. Each package lists its
maintainers with the username and the email the registry publishes for them. The registry has
no keyless account lookup (`/-/user/org.couchdb.user:{name}` answers 401), so an account with
no package cannot be seen: `total: 0` is "unknown" here, never "not_found".
"""

import re

from . import base

ID, SITE = "npm", "npm"
URL = "https://registry.npmjs.org/-/v1/search"
SIZE = 20
HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PACKAGE_RE = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$")
NO_PACKAGES = "No package lists this maintainer. An account without packages cannot be seen."


async def read(client, username: str) -> base.Result:
    name = username.lower()
    reply = await base.get_json(client, URL, {"text": f"maintainer:{name}", "size": SIZE})
    stop = base.settle(reply, not_found=())
    if stop:
        return stop
    d = reply.data if isinstance(reply.data, dict) else {}
    rows = d.get("objects")
    if not isinstance(rows, list):
        return base.UNKNOWN
    packages, emails, latest = [], [], ""
    for row in rows:
        pkg = row.get("package") if isinstance(row, dict) and isinstance(row.get("package"), dict) else {}
        people = pkg.get("maintainers") if isinstance(pkg.get("maintainers"), list) else []
        mine = [m for m in people if isinstance(m, dict) and str(m.get("username") or "").lower() == name]
        title = pkg.get("name")
        if not mine or not isinstance(title, str) or len(title) > 214 or not PACKAGE_RE.fullmatch(title):
            continue
        packages.append(base.item(title, f"https://www.npmjs.com/package/{title}", "package"))
        emails.extend(m.get("email") for m in mine)
        latest = max(latest, base.iso(pkg.get("date")))
    if not packages:
        # Settled: asking again will not change it, so the answer may be kept for the day.
        return base.Result("unknown", note=NO_PACKAGES, settled=True)
    total = base.count(d.get("total"))
    return base.Result("found", base.profile(
        ID, SITE, name, f"https://www.npmjs.com/~{name}", emails=emails, last_active=latest, items=packages,
        stats={"packages": total if total is not None and total >= len(packages) else len(packages)}))
