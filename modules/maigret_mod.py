import asyncio
import json
import os
import shutil
import tempfile

from core.boilerplate import clean_bio
from core.errors import error_fields
from modules.sherlock import _classify_site, SORT_ORDER
from core.subprocess_guard import tool_slot, ToolBusy, busy_result, log_result, log_process

MAIGRET_AVAILABLE = shutil.which("maigret") is not None

MAIGRET_FALSE_POSITIVE_PATTERNS = [
    "op.gg", "leagueofgraphs", "u.gg", "tracker.gg",
    "lolprofile", "[leagueoflegends]",
]

MAIGRET_SEARCH_REDIRECT_PATTERNS = [
    "search?q=", "summoners/search",
]


def _is_maigret_false_positive(site_name: str, url: str) -> bool:
    name_lower = site_name.lower()
    url_lower = url.lower()
    for pat in MAIGRET_FALSE_POSITIVE_PATTERNS:
        if pat in name_lower or pat in url_lower:
            return True
    for pat in MAIGRET_SEARCH_REDIRECT_PATTERNS:
        if pat in url_lower:
            return True
    return False


# Maigret's own site tags for adult content and dating.
SENSITIVE_TAGS = ("porn", "erotic", "webcam", "dating")

_ID_KEYS = {"uid", "username", "account_id", "gaia_id"}
_NAME_KEYS = ("fullname", "name", "nickname")


def profile_signal(ids: dict | None, site: str = "", username: str = "") -> dict | None:
    """
    Maigret returns `ids` when it parsed real profile data from the page or API (a user id,
    display name, join date). That is the difference between "the URL answered" and "there is
    an account here", so only hits with it are reported as verified. One stray field (some
    sites echo their own title as a name) is not enough.
    """
    if not isinstance(ids, dict):
        return None
    fields = {k: str(v).strip() for k, v in ids.items() if not k.startswith("_") and str(v).strip()}
    has_id = any(k in _ID_KEYS or k.endswith("_id") or k.endswith("_username") for k in fields)
    if not has_id and len(fields) < 2:
        return None
    name = next((fields[k] for k in _NAME_KEYS if fields.get(k)), "")
    # Sites with no bio hand back their own template ("x is on Snapchat!"). That is not a bio.
    raw_bio = fields.get("bio") or fields.get("description") or ""
    bio = clean_bio(raw_bio, site, username or fields.get("username", ""), name)
    out = {
        "name": name[:120],
        "location": fields.get("location", "")[:120],
        "bio": bio[:300],
        "bio_boilerplate": bool(raw_bio) and not bio,
        "created_at": fields.get("created_at", "")[:40],
        "image": fields.get("image", "")[:500],
        "extractor": str(ids.get("_extractor", ""))[:60],
    }
    return {k: v for k, v in out.items() if v}


async def _run_maigret_impl(username: str, nsfw: bool = False, timeout: int = 180) -> dict:
    if not MAIGRET_AVAILABLE:
        return {"username": username, "results": [], "total": 0, "possible": 0, "verified": 0, **error_fields(code="not_installed")}

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            "maigret",
            "-J", "simple",
            "--timeout", "10",
            "--no-color",
            "--no-progressbar",
            "--no-recursion",
            "--top-sites", "500",
            "--folderoutput", tmpdir,
        ]
        # Adult and dating sites are excluded unless the investigator explicitly opts in.
        # (The old filter passed "--tags !nsfw", which is not a tag Maigret knows, so with the
        # box unticked it matched no sites at all.)
        if not nsfw:
            cmd.extend(["--exclude-tags", ",".join(SENSITIVE_TAGS)])
        # "--" ends option parsing, so the username can never be read as a flag.
        cmd.extend(["--", username])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=tmpdir,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"username": username, "results": [], "total": 0, "possible": 0, "verified": 0, **error_fields(code="timeout", message="Maigret ran out of time. Partial results were discarded.")}
        log_process("maigret", proc.returncode, stderr)

        results = []

        # Find the JSON output file
        raw = None
        for fname in sorted(os.listdir(tmpdir)):
            if fname.endswith(".json"):
                fpath = os.path.join(tmpdir, fname)
                with open(fpath) as f:
                    try:
                        raw = json.load(f)
                        break
                    except json.JSONDecodeError:
                        continue

        if raw and isinstance(raw, dict):
            # maigret simple JSON format:
            # { "SiteName": { "status": { "status": "Claimed", "site_name": "...", "tags": [...] },
            #                  "url_user": "...", "site": { "tags": [...] } } }
            for site_key, info in raw.items():
                if not isinstance(info, dict):
                    continue
                status_obj = info.get("status", {})
                if not isinstance(status_obj, dict):
                    continue
                status_val = status_obj.get("status", "")
                if str(status_val).lower() != "claimed":
                    continue

                site_name = status_obj.get("site_name", site_key)
                url = info.get("url_user", status_obj.get("url", ""))

                # Tags from status or site metadata
                tags = status_obj.get("tags", [])
                if not tags:
                    site_meta = info.get("site", {})
                    if isinstance(site_meta, dict):
                        tags = site_meta.get("tags", [])
                if isinstance(tags, list):
                    category = ", ".join(tags) if tags else ""
                else:
                    category = str(tags) if tags else ""

                confidence = _classify_site(site_name)
                profile = profile_signal(status_obj.get("ids"), site=site_name, username=username)
                row = {
                    "site": site_name,
                    "url": url,
                    "confidence": confidence,
                    "category": category,
                    "verified": profile is not None,
                }
                if profile:
                    row["profile"] = profile
                results.append(row)

        results = [r for r in results if not _is_maigret_false_positive(r["site"], r["url"])]

        results.sort(key=lambda r: (not r["verified"], SORT_ORDER.get(r["confidence"], 1)))
        possible = sum(1 for r in results if r["confidence"] != "false_positive")

        return {
            "username": username,
            "total": len(results),
            "possible": possible,
            "verified": sum(1 for r in results if r["verified"]),
            "results": results,
        }


async def run_maigret(username: str, nsfw: bool = False, timeout: int = 180) -> dict:
    """Guarded entry point: bounded by the global tool concurrency limit."""
    try:
        async with tool_slot("maigret"):
            return log_result("maigret", await _run_maigret_impl(username=username, nsfw=nsfw, timeout=timeout))
    except ToolBusy:
        return busy_result(username=username, results=[], total=0, possible=0, verified=0)
