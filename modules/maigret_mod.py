import asyncio
import json
import os
import re
import shutil
import tempfile
from urllib.parse import urlsplit

from core import adult_guard, adult_sites
from core.boilerplate import clean_bio
from core.errors import error_fields
from core.validate import registrable_domain
from modules import adult_check
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


# Maigret's own site tags for adult content and dating. The normal pass always excludes them.
# ("nsfw" is not a tag in Maigret's data today; it is listed so that it is covered if it appears.)
SENSITIVE_TAGS = ("porn", "erotic", "webcam", "dating", "nsfw")
ADULT_TAGS = SENSITIVE_TAGS
ADULT_TIMEOUT = 60        # seconds for the adult pass, on top of the normal pass
# Sites that are adult or dating whatever tags Maigret gives them (Fansly is tagged "social").
ADULT_HOSTS = frozenset(adult_sites.HOSTS)

_ID_KEYS = {"uid", "username", "account_id", "gaia_id"}
_NAME_KEYS = ("fullname", "name", "nickname")
_BIRTH_KEYS = ("birthday", "birth_date", "birthdate", "born", "dob", "date_of_birth")
_TEXT_KEYS = ("about", "status", "headline", "description", "school", "occupation", "education", "job")


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
    # Guard-only: what the minor guard's content check reads and nothing else uses. The whole bio
    # (the row shows 300 characters), the other text fields an extractor returns, a birth date
    # and an age. The server scans it (core.profile_record) and so does the page, which removes
    # `guard` before the case is stored, exported or sent to the AI.
    age = fields.get("age", "")
    guard = {
        "bio": bio[:2000] if len(bio) > 300 else "",
        "text": "\n".join(fields[k][:300] for k in _TEXT_KEYS if fields.get(k) and fields[k] != raw_bio)[:1000],
        "birthday": next((fields[k] for k in _BIRTH_KEYS if fields.get(k)), "")[:40],
        "age": age if age.isdigit() and len(age) <= 3 else "",
    }
    out["guard"] = {k: v for k, v in guard.items() if v}
    return {k: v for k, v in out.items() if v}


# --------------------------------------------------------------------------------------
# The site database Maigret is given.
#
# Left alone, Maigret updates its database on its own (~/.maigret/data.json), so the sites it
# queries are not the installed ones the filters were built from, and it has no option to
# leave a site out by name. So both passes are pinned to the installed database with --db
# (a custom database also switches the auto-update off; --no-autoupdate says so again):
#
#   normal pass   a copy of the installed database with every site core.adult_sites lists
#                 taken out, so no option or ranking can select one
#   adult pass    the installed database itself, restricted to the adult tags. It is its own
#                 run (nsfw and adult_only), made after the ordinary sources and only when
#                 core.adult_guard.gate allows it: the two passes are never one request
#
# The price: site definitions change only when the maigret package is upgraded.
# --------------------------------------------------------------------------------------
_filtered_db_path = ""


def _site_is_adult(name: str, entry) -> bool:
    if not isinstance(entry, dict):
        return False
    return bool(adult_sites.tag_category(entry.get("tags"))) or any(
        adult_sites.is_adult_site(name, str(entry.get(k) or "")) for k in ("url", "urlMain", "urlProbe"))


def filtered_database(path: str | None = None) -> dict:
    """The installed Maigret database without any adult or dating site."""
    try:
        with open(path or adult_sites.MAIGRET_DATA, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not isinstance(data.get("sites"), dict):
        return {}
    return {**data, "sites": {name: entry for name, entry in data["sites"].items() if not _site_is_adult(name, entry)}}


def normal_db_file() -> str:
    """Path of the filtered database, written once per process. "" when it cannot be built."""
    global _filtered_db_path
    if _filtered_db_path and os.path.isfile(_filtered_db_path):
        return _filtered_db_path
    data = filtered_database()
    if not data:
        return ""
    fd, path = tempfile.mkstemp(prefix="crawlr_maigret_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    _filtered_db_path = path
    return path


def adult_db_file() -> str:
    """The installed database, for the adult pass. "" when it is missing."""
    return adult_sites.MAIGRET_DATA if os.path.isfile(adult_sites.MAIGRET_DATA or "") else ""


def _base_command(tmpdir: str, db_file: str) -> list[str]:
    return [
        "maigret",
        "-J", "simple",
        "--timeout", "10",
        "--no-color",
        "--no-progressbar",
        "--no-recursion",
        "--db", db_file,
        "--no-autoupdate",
        "--folderoutput", tmpdir,
    ]


def build_command(username: str, tmpdir: str, db_file: str | None = None) -> list[str]:
    """The normal pass: the top 500 sites by rank of a database that holds no adult or dating
    site, with the adult tags excluded as well. This is the only command that runs unless the
    investigator opted in."""
    cmd = _base_command(tmpdir, db_file if db_file is not None else normal_db_file())
    cmd.extend(["--top-sites", "500", "--exclude-tags", ",".join(SENSITIVE_TAGS)])
    # "--" ends option parsing, so the username can never be read as a flag.
    cmd.extend(["--", username])
    return cmd


def build_adult_command(username: str, tmpdir: str, db_file: str | None = None) -> list[str]:
    """The adult pass: every enabled site in the installed database that carries one of the
    adult or dating tags, whatever its rank. Maigret filters by tag first and ranks afterwards,
    so --all-sites is what lifts the top-500 cut. --print-errors puts each failed site on stdout."""
    cmd = _base_command(tmpdir, db_file if db_file is not None else adult_db_file())
    cmd.extend(["--all-sites", "--tags", ",".join(ADULT_TAGS), "--print-errors"])
    cmd.extend(["--", username])
    return cmd


_SITE_COUNT = re.compile(r"Starting a search on top (\d+) sites")
_ERROR_LINE = re.compile(r"^\[\?\] (.{1,80}?): (?!https?://)", re.M)


def _sites_checked(stdout: str) -> int | None:
    """How many sites Maigret says it checked, from its own start line."""
    m = _SITE_COUNT.search(stdout or "")
    return int(m.group(1)) if m else None


def _errored_sites(stdout: str) -> list[str]:
    """Names of the sites Maigret could not check (a line "[?] Site: reason")."""
    seen: list[str] = []
    for name in _ERROR_LINE.findall(stdout or ""):
        name = name.strip()
        if name and name not in seen:
            seen.append(name)
    return seen[:200]


def _host_site(url: str) -> str:
    try:
        return registrable_domain(urlsplit(url or "").hostname or "")
    except ValueError:
        return ""


def adult_category(tags, url: str = "", name: str = "") -> str:
    """"adult", "dating" or "" for a site: from Maigret's tags, or from core.adult_sites by the
    site's name or host."""
    by_tag = adult_sites.tag_category(tags)
    listed = adult_sites.category(name, url)
    if "adult" in (by_tag, listed):
        return "adult"
    return by_tag or listed


_FOLLOWER_KEYS = ("follower_count", "followers_count", "followers", "subscriber_count", "subscribers", "fans_count")


def adult_profile(ids: dict | None, site: str = "", username: str = "") -> dict | None:
    """What an adult row may say about a profile: name, join date, follower count and a
    plain-text bio. No image, no location, nothing else Maigret extracted."""
    profile = profile_signal(ids, site=site, username=username)
    if profile is None:
        return None
    followers = next((n for n in (adult_check._count(ids.get(k)) for k in _FOLLOWER_KEYS) if n is not None), None)
    out = {
        "name": adult_guard.plain_text(profile.get("name", ""), 120),
        "created_at": profile.get("created_at", ""),
        "followers": followers,
        "bio": adult_guard.plain_text(profile.get("bio", "")),
    }
    return {k: v for k, v in out.items() if v not in ("", None)}


async def _run_pass(cmd: list[str], tmpdir: str, timeout: float) -> tuple[dict | None, str, dict | None]:
    """Run Maigret once. Returns (its JSON report or None, its stdout, error fields or None)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=tmpdir,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return None, "", error_fields(code="timeout", message="Maigret ran out of time. Partial results were discarded.")
    log_process("maigret", proc.returncode, stderr)

    raw = None
    for fname in sorted(os.listdir(tmpdir)):
        if fname.endswith(".json"):
            with open(os.path.join(tmpdir, fname)) as f:
                try:
                    raw = json.load(f)
                    break
                except json.JSONDecodeError:
                    continue
    return (raw if isinstance(raw, dict) else None), (stdout or b"").decode("utf-8", "replace"), None


def _rows(raw: dict | None, username: str, nsfw: bool) -> list[dict]:
    """Claimed sites from one Maigret report. An adult or dating row is dropped unless the
    investigator opted in, and is cut down to text metadata when it is kept."""
    results = []
    # maigret simple JSON format:
    # { "SiteName": { "status": { "status": "Claimed", "site_name": "...", "tags": [...] },
    #                  "url_user": "...", "site": { "tags": [...] } } }
    for site_key, info in (raw or {}).items():
        if not isinstance(info, dict):
            continue
        status_obj = info.get("status", {})
        if not isinstance(status_obj, dict):
            continue
        if str(status_obj.get("status", "")).lower() != "claimed":
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

        if _is_maigret_false_positive(site_name, url):
            continue
        confidence = _classify_site(site_name)
        adult = adult_category(tags, url, site_name)
        if adult:
            if not nsfw:
                continue          # never reported without the opt-in, whichever pass found it
            profile = adult_profile(status_obj.get("ids"), site=site_name, username=username)
            row = {"site": site_name, "url": url, "confidence": confidence, "category": adult,
                   "verified": profile is not None, "adult": True}
            if profile:
                row["profile"] = profile
            results.append(adult_guard.strip_media(row))
            continue

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
    return results


async def _run_maigret_impl(username: str, nsfw: bool = False, adult_only: bool = False, timeout: int = 180, adult_timeout: int = ADULT_TIMEOUT) -> dict:
    nsfw, adult_only = nsfw is True, adult_only is True
    empty = {"username": username, "results": [], "total": 0, "possible": 0, "verified": 0,
             "nsfw": nsfw, "sites_checked": 0, "adult_checked": 0, "adult_errors": []}
    if nsfw != adult_only:
        # Adult and dating sites are only ever their own pass. Mixing them into an ordinary run
        # would ask them before any profile has been read.
        return {**empty, "nsfw": False, **error_fields(code="adult_pass", message=adult_guard.PASS_MESSAGE)}
    if nsfw:
        refused = adult_guard.gate(username)
        if refused:
            # The router answers before this point. This is the second lock on the door.
            return {**empty, "nsfw": False, **adult_guard.gate_fields(refused)}
    if not MAIGRET_AVAILABLE or not (adult_db_file() if nsfw else normal_db_file()):
        # Without the installed database there is no way to know what would be queried.
        return {**empty, **error_fields(code="not_installed")}

    if not nsfw:
        # The ordinary run: one pass over a database that holds no adult or dating site.
        # (The old filter passed "--tags !nsfw", which is not a tag Maigret knows, so with the
        # box unticked it matched no sites at all.)
        with tempfile.TemporaryDirectory() as tmpdir:
            raw, stdout, failed = await _run_pass(build_command(username, tmpdir), tmpdir, timeout)
        if failed:
            return {**empty, **failed}
        results = _rows(raw, username, False)
        sites_checked = _sites_checked(stdout)
        adult = {"adult_checked": 0, "adult_errors": []}
    else:
        # The adult pass: the adult and dating tags only, with its own time limit. A failure is
        # returned both as this answer's error and under the adult_ keys the page reads.
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                raw, stdout, failed = await _run_pass(build_adult_command(username, tmpdir), tmpdir, adult_timeout)
        except Exception as e:  # noqa: BLE001 - reported as a failed pass, never raised
            raw, stdout, failed = None, "", error_fields(e, detail=type(e).__name__)
        if failed:
            return {**empty, **failed, **{f"adult_{k}": v for k, v in failed.items()}}
        # Only adult and dating rows are taken from this pass, whatever it returned.
        results = [r for r in _rows(raw, username, True) if r.get("adult")]
        sites_checked = _sites_checked(stdout)
        adult = {"adult_checked": sites_checked or 0, "adult_errors": _errored_sites(stdout)}

    results.sort(key=lambda r: (not r["verified"], SORT_ORDER.get(r["confidence"], 1)))
    possible = sum(1 for r in results if r["confidence"] != "false_positive")

    return {
        "username": username,
        "total": len(results),
        "possible": possible,
        "verified": sum(1 for r in results if r["verified"]),
        "results": results,
        "nsfw": nsfw,
        "sites_checked": sites_checked,
        **adult,
    }


async def run_maigret(username: str, nsfw: bool = False, adult_only: bool = False, timeout: int = 180) -> dict:
    """Guarded entry point: bounded by the global tool concurrency limit.

    `nsfw` with `adult_only` (both exactly True) is the adult pass: only the adult and dating
    tags, and only when core.adult_guard.gate allows it for this handle. Anything else is the
    ordinary run, which holds no such site."""
    try:
        async with tool_slot("maigret"):
            return log_result("maigret", await _run_maigret_impl(username=username, nsfw=nsfw, adult_only=adult_only, timeout=timeout))
    except ToolBusy:
        return busy_result(username=username, results=[], total=0, possible=0, verified=0)
