import asyncio
import csv
import io
import glob
import json
import tempfile
import os

from core import adult_guard, adult_sites
from core.errors import error_fields
from core.subprocess_guard import tool_slot, ToolBusy, busy_result, log_result, log_process

# Sites known to return 200 for any username (false positives)
FALSE_POSITIVE_SITES = {
    "roblox", "chess", "chess.com", "nitrotype", "runescape",
    "scratch", "wikipedia", "geocaching", "periscope",
    "livejournal", "hudsonrock", "envato", "freelancer",
    "disqus", "trakt", "vsco", "minds",
    # Adult sites (only reached with the opt-in). RocketTube answered 404 and was still
    # reported as claimed for every handle tried on 2026-11-14.
    "rockettube",
}

# Well-known platforms. Being on this list says the SITE matters to an investigator, not that
# the hit is verified: several of these (Facebook, PayPal, Instagram) answer 200 for any name.
# The UI only calls an account "confirmed" when a profile signal backs it up.
MAJOR_PLATFORMS = {
    "github", "reddit", "steam", "tiktok", "linkedin", "twitter",
    "x", "instagram", "facebook", "youtube", "twitch", "pinterest",
    "snapchat", "telegram", "discord", "spotify", "soundcloud",
    "medium", "deviantart", "flickr", "vimeo", "tumblr",
    "substack", "patreon", "cashapp", "venmo", "paypal",
    "keybase", "mastodon", "bluesky", "kick", "rumble", "threads",
}

URL_FALLBACKS = {
    "bluesky": "https://bsky.app/profile/{username}",
    "kick": "https://kick.com/{username}",
    "rumble": "https://rumble.com/user/{username}",
    "threads": "https://www.threads.net/@{username}",
    "mastodon.social": "https://mastodon.social/@{username}",
    "hackerone": "https://hackerone.com/{username}",
    "huggingface": "https://huggingface.co/{username}",
    "hugging face": "https://huggingface.co/{username}",
    "itch.io": "https://{username}.itch.io",
    "odysee": "https://odysee.com/@{username}",
    "trovo": "https://trovo.live/{username}",
    "virustotal": "https://www.virustotal.com/gui/user/{username}",
    "buymeacoffee": "https://buymeacoffee.com/{username}",
    "codecademy": "https://www.codecademy.com/profiles/{username}",
    "coderwall": "https://coderwall.com/{username}",
    "crowdin": "https://crowdin.com/profile/{username}",
    "dev.to": "https://dev.to/{username}",
    "devto": "https://dev.to/{username}",
    "f3.cool": "https://f3.cool/{username}",
    "gitee": "https://gitee.com/{username}",
    "hackthebox": "https://app.hackthebox.com/users/{username}",
    "icq": "https://icq.im/{username}",
    "linktree": "https://linktr.ee/{username}",
    "monkeytype": "https://monkeytype.com/profile/{username}",
    "npm": "https://www.npmjs.com/~{username}",
    "pypi": "https://pypi.org/user/{username}",
    "replit": "https://replit.com/@{username}",
    "slides": "https://slides.com/{username}",
    "slideshare": "https://www.slideshare.net/{username}",
    "smule": "https://www.smule.com/{username}",
    "tryhackme": "https://tryhackme.com/p/{username}",
    "unity": "https://discussions.unity.com/u/{username}",
    "unsplash": "https://unsplash.com/@{username}",
    "wattpad": "https://www.wattpad.com/user/{username}",
}


SORT_ORDER = {"major_platform": 0, "normal": 1, "false_positive": 2}


# --------------------------------------------------------------------------------------
# Adult and dating sites, and the site file Sherlock is given.
#
# Left alone, Sherlock downloads its site list at run time and skips only the entries it marks
# isNSFW. That leaves two gaps: the list that is queried is not the installed one the filter
# was built from, and unflagged adult sites (RoyalCams, datingRU) are queried on every run.
# So CrawlR hands Sherlock a site file of its own, written from the installed data:
#
#   without the opt-in   every site core.adult_sites lists is left out of the file
#   with the opt-in      the whole installed list, plus --nsfw so Sherlock keeps its flagged ones
#
# The price: site definitions change only when the sherlock-project package is upgraded.
# --------------------------------------------------------------------------------------
def _sherlock_data_path() -> str:
    return adult_sites.SHERLOCK_DATA


def _installed_sites(path: str | None = None) -> dict:
    try:
        with open(path or _sherlock_data_path(), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _entry_is_adult(name: str, entry) -> bool:
    if not isinstance(entry, dict):
        return False
    return bool(entry.get("isNSFW")) or any(adult_sites.is_adult_site(name, str(entry.get(k) or "")) for k in ("url", "urlMain", "urlProbe"))


def load_nsfw_sites(path: str | None = None) -> tuple[frozenset, frozenset]:
    """(site names in lowercase, hosts) of every site in Sherlock's installed data that is an
    adult or dating site: flagged isNSFW, or on CrawlR's own list."""
    names, hosts = set(), set()
    for name, entry in _installed_sites(path).items():
        if _entry_is_adult(name, entry):
            names.add(name.strip().lower())
            hosts.update(h for h in (adult_sites.host_of(str(entry.get(k) or "")) for k in ("url", "urlMain")) if h)
    return frozenset(names), frozenset(hosts)


NSFW_SITES, NSFW_HOSTS = load_nsfw_sites()


def is_adult_site(site: str, url: str = "") -> bool:
    """Is this row from an adult or dating site? Decided by core.adult_sites, by name or by the
    host of the row's URL, not only by Sherlock's own flag."""
    return (site or "").strip().lower() in NSFW_SITES or adult_sites.is_adult_site(site, url)


def site_data(nsfw: bool = False, path: str | None = None) -> dict:
    """The site list Sherlock is run against. Without the opt-in it holds no adult or dating site."""
    data = _installed_sites(path)
    if nsfw is True:
        return data
    return {name: entry for name, entry in data.items() if not _entry_is_adult(name, entry)}


def write_site_file(directory: str, nsfw: bool = False) -> str:
    """Write the site list for one run into `directory` and return its path."""
    path = os.path.join(directory, "crawlr_sites.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(site_data(nsfw), fh)
    return path


def build_command(username: str, nsfw: bool = False, site_file: str = "") -> list[str]:
    cmd = ["sherlock", "--csv", "--timeout", "15", "--no-color", "--print-found"]
    if site_file:
        cmd.extend(["--json", site_file])
    if nsfw:
        cmd.append("--nsfw")
    # "--" ends option parsing, so a value like "--proxy" can never be read as a flag.
    cmd.extend(["--", username])
    return cmd


def _classify_site(site_name: str) -> str:
    """Return 'false_positive', 'major_platform', or 'normal'."""
    name_lower = site_name.lower().strip()
    if any(fp in name_lower for fp in FALSE_POSITIVE_SITES):
        return "false_positive"
    if name_lower in MAJOR_PLATFORMS or any(name_lower.startswith(hc + " ") or name_lower.startswith(hc + ".") for hc in MAJOR_PLATFORMS):
        return "major_platform"
    return "normal"


async def _run_sherlock_impl(username: str, nsfw: bool = False, timeout: int = 300) -> dict:
    nsfw = nsfw is True
    # What every answer says about the adult mode, failures included.
    mode = {"nsfw": nsfw, "adult_checked": len(NSFW_SITES) if nsfw else 0}
    if nsfw:
        reason = adult_guard.minor_indicated(username)
        if reason:
            # The router answers 400 before this point. This is the second lock on the door.
            return {"username": username, "results": [], "total": 0, "possible": 0, "nsfw": False, "adult_checked": 0,
                    **error_fields(code=adult_guard.ERROR_CODE, message=adult_guard.MESSAGE, detail=reason)}
    if not site_data(nsfw):
        # Without the installed site list there is no way to know what would be queried.
        return {"username": username, "results": [], "total": 0, "possible": 0, **mode, **error_fields(code="not_installed")}
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            proc = await asyncio.create_subprocess_exec(
                *build_command(username, nsfw, write_site_file(tmpdir, nsfw)),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tmpdir,
            )
        except FileNotFoundError:
            return {"username": username, "results": [], "total": 0, "possible": 0, **mode, **error_fields(code="not_installed")}
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {"username": username, "results": [], "total": 0, "possible": 0, **mode, **error_fields(code="timeout", message="Sherlock ran out of time. Partial results were discarded.")}
        log_process("sherlock", proc.returncode, stderr)

        results = []
        # Read whatever CSV sherlock wrote rather than building a path from user input.
        for csv_path in sorted(glob.glob(os.path.join(tmpdir, "*.csv")))[:1]:
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("exists") == "Claimed":
                        site = row.get("name", "")
                        url = row.get("url_user", "")
                        if not url:
                            fallback_key = site.lower().strip()
                            if fallback_key in URL_FALLBACKS:
                                url = URL_FALLBACKS[fallback_key].format(username=username)
                        adult = is_adult_site(site, url)
                        if adult and not nsfw:
                            # Sherlock leaves these sites out without --nsfw. If one shows
                            # up anyway, it is not reported.
                            continue
                        confidence = _classify_site(site)
                        item = {
                            "site": site,
                            "url": url,
                            "response_time": round(float(row.get("response_time_s") or 0), 2),
                            "confidence": confidence,
                        }
                        if adult:
                            item["adult"] = True
                        results.append(item)

        # Sort: major platforms first, then the rest, then known false positives
        results.sort(key=lambda r: SORT_ORDER.get(r["confidence"], 1))
        possible = sum(1 for r in results if r["confidence"] != "false_positive")

        return {
            "username": username,
            "total": len(results),
            "possible": possible,
            "results": results,
            **mode,
        }


async def run_sherlock(username: str, nsfw: bool = False, timeout: int = 300) -> dict:
    """Guarded entry point: bounded by the global tool concurrency limit.

    `nsfw` is the adult site opt-in. It is off unless the caller passes exactly True."""
    try:
        async with tool_slot("sherlock"):
            return log_result("sherlock", await _run_sherlock_impl(username=username, nsfw=nsfw, timeout=timeout))
    except ToolBusy:
        return busy_result(username=username, results=[], nsfw=nsfw is True, adult_checked=0)
