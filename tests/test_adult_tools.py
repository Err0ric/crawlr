"""The adult and dating opt-in for Sherlock and Maigret, and the minor guard on every path.
The tools are never started: the process layer is faked and the command lines are read. No network."""

import asyncio
import csv
import io
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from core import adult_guard, adult_sites
from main import app
import middleware.rate_limit as rl
from modules import adult_check as ac
from modules import maigret_mod as mm
from modules import sherlock as sh
import routers.recon as recon

ADULT_TAGS = {"porn", "nsfw", "dating", "webcam"}


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _limits(monkeypatch):
    for path in ("/api/recon/sherlock", "/api/recon/maigret", "/api/recon/adult-check"):
        monkeypatch.setitem(rl.RATE_LIMITS, path, (1000, 60))
    ac.clear_cache_for_tests()


def no_adult_check(monkeypatch):
    """Fail the test if the adult check is about to open a connection."""
    def boom(*a, **k):
        raise AssertionError("the adult check was about to make a request")
    monkeypatch.setattr(ac, "_client", boom)


def media_leaks(value, path="") -> list[str]:
    """Every key or value in a response that looks like an image or media reference."""
    bad = []
    if isinstance(value, dict):
        for key, item in value.items():
            if re.search(r"image|avatar|thumb|banner|photo|picture|preview|poster", str(key), re.I):
                bad.append(f"{path}.{key}")
            bad += media_leaks(item, f"{path}.{key}")
    elif isinstance(value, list):
        for n, item in enumerate(value):
            bad += media_leaks(item, f"{path}[{n}]")
    elif isinstance(value, str):
        if re.search(r"\.(?:jpe?g|png|webp|gif|avif|svg|mp4|webm|mov|m3u8)\b", value, re.I) or re.search(r"/(?:avatars?|thumbs?|thumbnails?|banners?)/", value, re.I):
            bad.append(f"{path}={value[:60]}")
    return bad


# ---- Sherlock ---------------------------------------------------------------------------

SHERLOCK_ROWS = [
    ("GitHub", "https://github.com/jdoe", "Claimed"),
    ("Pornhub", "https://pornhub.com/users/jdoe", "Claimed"),
    ("ChaturBate", "https://chaturbate.com/jdoe", "Claimed"),
    ("Renamed Entry", "https://www.xvideos.com/profiles/jdoe", "Claimed"),      # adult by host, under a name the installed data does not have
    ("Reddit", "https://www.reddit.com/user/jdoe", "Claimed"),
    ("RoyalCams", "https://royalcams.com/profile/jdoe", "Claimed"),            # adult, but Sherlock's data does not flag it
    ("datingRU", "http://dating.ru/jdoe", "Claimed"),                          # dating, same
    ("xHamster", "https://xhamster.com/users/jdoe", "Available"),
]


SITE_FILES: list = []      # the site file of every Sherlock run in the last run_sherlock call


def run_sherlock(monkeypatch, username="jdoe", **kwargs):
    seen = []
    files = SITE_FILES
    files.clear()

    class Proc:
        returncode = 0
        async def communicate(self): return b"", b""

    async def fake_exec(*argv, cwd=None, **kw):
        seen.append(list(argv))
        # the site file Sherlock was handed, read while it still exists
        files.append(json.loads(Path(argv[argv.index("--json") + 1]).read_text(encoding="utf-8")) if "--json" in argv else None)
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["username", "name", "url_main", "url_user", "exists", "http_status", "response_time_s"])
        for name, url, exists in SHERLOCK_ROWS:
            w.writerow([username, name, "", url, exists, "200", "0.5"])
        Path(cwd, f"{username}.csv").write_text(out.getvalue())
        return Proc()

    monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", fake_exec)
    return asyncio.run(sh._run_sherlock_impl(username, **kwargs)), seen


def test_sherlock_data_marks_the_adult_sites():
    data = json.loads(Path(sh._sherlock_data_path()).read_text(encoding="utf-8"))
    flagged = {k.lower() for k, v in data.items() if isinstance(v, dict) and v.get("isNSFW")}
    assert len(flagged) >= 15 and flagged <= sh.NSFW_SITES
    assert {"pornhub", "xhamster", "chaturbate", "xvideos"} <= sh.NSFW_SITES
    # Sherlock's own flag misses these two. CrawlR's list does not.
    assert not data["RoyalCams"].get("isNSFW") and not data["datingRU"].get("isNSFW")
    assert {"royalcams", "datingru"} <= sh.NSFW_SITES and {"royalcams.com", "dating.ru"} <= sh.NSFW_HOSTS
    assert sh.is_adult_site("Pornhub") and sh.is_adult_site("PORNHUB ") and sh.is_adult_site("Other", "https://de.xhamster.com/users/x")
    assert sh.is_adult_site("RoyalCams") and sh.is_adult_site("x", "http://dating.ru/someone")
    assert not sh.is_adult_site("GitHub", "https://github.com/x") and not sh.is_adult_site("", "")


def assert_no_adult_site(site_file: dict):
    assert len(site_file) >= 400 and "GitHub" in site_file and "Reddit" in site_file
    for name, entry in site_file.items():
        if not isinstance(entry, dict):
            continue
        assert not entry.get("isNSFW"), name
        for key in ("url", "urlMain", "urlProbe"):
            assert not adult_sites.is_adult_site(name, str(entry.get(key) or "")), (name, key)
    for name in ("RoyalCams", "datingRU", "Pornhub", "xHamster", "ChaturBate", "Chatujme.cz"):
        assert name not in site_file, name


def test_sherlock_without_the_opt_in_is_handed_a_site_file_with_no_adult_site(monkeypatch):
    no_adult_check(monkeypatch)
    out, seen = run_sherlock(monkeypatch)
    assert len(seen) == 1
    argv = seen[0]
    # Sherlock is run against CrawlR's own site file, not the list it would download.
    site_file_path = argv[argv.index("--json") + 1]
    assert argv == ["sherlock", "--csv", "--timeout", "15", "--no-color", "--print-found", "--json", site_file_path, "--", "jdoe"]
    assert "--nsfw" not in argv and "--site" not in argv and "--ignore-exclusions" not in argv
    assert_no_adult_site(SITE_FILES[0])
    assert SITE_FILES[0] == sh.site_data(False)
    assert not Path(site_file_path).exists()                      # written into the run's own temp folder
    # And if a row for such a site shows up anyway, it is not reported.
    assert [r["site"] for r in out["results"]] == ["GitHub", "Reddit"]
    assert not any("adult" in r for r in out["results"])
    assert (out["nsfw"], out["adult_checked"], out["total"]) == (False, 0, 2)


def test_sherlock_with_the_opt_in_gets_the_whole_list_and_marks_adult_rows(monkeypatch):
    out, seen = run_sherlock(monkeypatch, nsfw=True)
    argv = seen[0]
    assert argv[:6] == ["sherlock", "--csv", "--timeout", "15", "--no-color", "--print-found"] and argv[6] == "--json"
    assert argv[8:] == ["--nsfw", "--", "jdoe"]
    installed = json.loads(Path(sh._sherlock_data_path()).read_text(encoding="utf-8"))
    assert SITE_FILES[0] == installed and {"RoyalCams", "datingRU", "Pornhub"} <= set(SITE_FILES[0])
    by = {r["site"]: r for r in out["results"]}
    assert set(by) == {"GitHub", "Reddit", "Pornhub", "ChaturBate", "Renamed Entry", "RoyalCams", "datingRU"}
    assert all(by[s].get("adult") is True for s in ("Pornhub", "ChaturBate", "Renamed Entry", "RoyalCams", "datingRU"))
    assert "adult" not in by["GitHub"] and "adult" not in by["Reddit"]
    assert out["nsfw"] is True and out["adult_checked"] == len(sh.NSFW_SITES) == len(installed) - len(sh.site_data(False))
    assert media_leaks(out) == []


def test_sherlock_does_not_run_without_its_installed_site_list(monkeypatch):
    async def never(*a, **k):
        raise AssertionError("sherlock was started with no site file")
    monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", never)
    monkeypatch.setattr(sh, "_sherlock_data_path", lambda: "/nonexistent/data.json")
    assert sh.site_data(False) == {} and sh.load_nsfw_sites("/nonexistent/data.json") == (frozenset(), frozenset())
    assert asyncio.run(sh._run_sherlock_impl("jdoe"))["error_code"] == "not_installed"


def test_an_adult_site_that_claims_every_handle_is_rated_a_false_positive():
    # Recorded on 2026-11-14: RocketTube answered 404 and Sherlock still reported it as claimed.
    assert sh._classify_site("RocketTube") == "false_positive" and sh.is_adult_site("RocketTube")
    assert sh._classify_site("Pornhub") == "normal"


def test_sherlock_opt_in_must_be_exactly_true(monkeypatch):
    for value in (None, 0, "", "true", 1, "yes"):
        out, seen = run_sherlock(monkeypatch, nsfw=value)
        assert "--nsfw" not in seen[0] and out["nsfw"] is False, value
        assert_no_adult_site(SITE_FILES[0])
    import inspect
    assert inspect.signature(sh.run_sherlock).parameters["nsfw"].default is False
    assert inspect.signature(sh._run_sherlock_impl).parameters["nsfw"].default is False
    assert recon.SherlockRequest(username="jdoe").nsfw is False and recon.MaigretRequest(username="jdoe").nsfw is False


def test_sherlock_module_refuses_a_minor_handle_before_starting_the_tool(monkeypatch):
    async def never(*a, **k):
        raise AssertionError("sherlock was started")
    monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", never)
    out = asyncio.run(sh.run_sherlock("jake13", nsfw=True))
    assert out["error_code"] == "minor_guard" and out["results"] == [] and out["nsfw"] is False
    assert out["error_detail"] == adult_guard.REASONS["number"]


def test_sherlock_failures_still_say_which_mode_ran(monkeypatch):
    async def missing(*a, **k):
        raise FileNotFoundError("sherlock")
    monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", missing)
    out = asyncio.run(sh._run_sherlock_impl("jdoe", nsfw=True))
    assert out["error_code"] == "not_installed" and out["nsfw"] is True


# ---- Maigret ----------------------------------------------------------------------------

def claimed(name, url, tags, ids=None):
    return {"status": {"status": "Claimed", "site_name": name, "tags": tags, "ids": ids or {}}, "url_user": url}


NORMAL_REPORT = {
    "GitHub": claimed("GitHub", "https://github.com/jdoe", ["coding"], {"uid": "1", "fullname": "A Person", "image": "https://cdn.example/gh.png"}),
    "Facebook": claimed("Facebook", "https://facebook.com/jdoe", ["social"]),
    # None of these should be in a normal pass. If one is, it is dropped without the opt-in.
    "Tinder": claimed("Tinder", "https://www.tinder.com/@jdoe", ["dating"]),
    "Leaky": claimed("Leaky", "https://leaky.example/jdoe", ["PORN", "video"]),
    "Fansly": claimed("Fansly", "https://fansly.com/jdoe", ["sharing", "social"]),      # adult by host, not by tag
    "Nope": {"status": {"status": "Available", "site_name": "Nope"}, "url_user": "https://nope.example/jdoe"},
}
ADULT_REPORT = {
    "Xvideos": claimed("Xvideos", "https://xvideos.com/profiles/jdoe", ["porn"], {
        "uid": "8246427", "username": "jdoe", "fullname": "Sam Example", "gender": "Man", "country": "Tokelau",
        "follower_count": "5,224", "created_at": "2013-07-21 00:00:00 UTC", "image": "https://cdn.example/x/avatar.jpg",
        "bio": "see my clips at https://cdn.example/x/clip.mp4", "_extractor": "XVideos profile"}),
    "ChaturBate": claimed("ChaturBate", "https://chaturbate.com/jdoe/", ["porn", "streaming", "video", "webcam"],
                          {"uid": "7", "name": "Sam", "bio": "Just here to chat.", "image": "https://cdn.example/c/thumb.webp", "location": "Somewhere"}),
    "RamblerDating": claimed("RamblerDating", "https://dating.rambler.ru/page/jdoe", ["dating", "ru"]),
    "massagerepublic.com": claimed("massagerepublic.com", "https://massagerepublic.com/u/jdoe", ["ae", "dating", "erotic"]),
    # A row with no adult tag has no business in the adult pass and is not taken from it.
    "Stray": claimed("Stray", "https://stray.example/jdoe", ["forum"]),
    "Gone": {"status": {"status": "Available", "site_name": "Gone", "tags": ["porn"]}, "url_user": "https://gone.example/jdoe"},
}
NORMAL_STDOUT = "[-] Starting a search on top 508 sites from the Maigret database...\n[*] Checking username jdoe on:\n[+] GitHub: https://github.com/jdoe\n"
ADULT_STDOUT = (
    "[-] Starting a search on top 66 sites from the Maigret database...\n[*] Checking username jdoe on:\n"
    "[?] Livejasmin: Connecting failure error: Cannot connect to host\n"
    "[?] massagerepublic.example: Bot protection error: Cloudflare challenge page\n"
    "[+] Xvideos: https://xvideos.com/profiles/jdoe\n ├─uid: 8246427\n"
    "[?] Similar: https://similar.example/jdoe\n"
    "[?] Dating.Ru: Unexpected error: [Errno 54] Connection reset by peer\n"
    "[!] Too many errors of type \"Unexpected\" (3.03%)\n"
)


def run_maigret(monkeypatch, username="jdoe", adult_hangs=False, adult_missing=False, **kwargs):
    seen = []

    class Proc:
        returncode = 0

        def __init__(self, stdout, hang=False):
            self._stdout, self._hang, self.killed = stdout, hang, False

        async def communicate(self):
            if self._hang:
                await asyncio.sleep(30)
            return self._stdout.encode(), b""

        def kill(self): self.killed = True
        async def wait(self): return 0

    async def fake_exec(*argv, cwd=None, **kw):
        argv = list(argv)
        seen.append(argv)
        adult = "--tags" in argv
        if adult and adult_missing:
            raise OSError("exec failed")
        report = ADULT_REPORT if adult else NORMAL_REPORT
        Path(cwd, f"report_{username}_simple.json").write_text(json.dumps(report))
        return Proc(ADULT_STDOUT if adult else NORMAL_STDOUT, hang=adult and adult_hangs)

    monkeypatch.setattr(mm, "MAIGRET_AVAILABLE", True)
    monkeypatch.setattr(mm.asyncio, "create_subprocess_exec", fake_exec)
    return asyncio.run(mm._run_maigret_impl(username, **kwargs)), seen


def option(argv, flag):
    return argv[argv.index(flag) + 1]


def test_maigret_without_the_opt_in_runs_one_pass_that_excludes_every_adult_tag(monkeypatch):
    no_adult_check(monkeypatch)
    out, seen = run_maigret(monkeypatch)
    assert len(seen) == 1                                           # no adult pass
    argv = seen[0]
    assert ADULT_TAGS | {"erotic"} <= set(option(argv, "--exclude-tags").split(","))
    assert option(argv, "--top-sites") == "500"
    assert "--tags" not in argv and "--all-sites" not in argv and "-a" not in argv and "--site" not in argv and "--use-disabled-sites" not in argv
    assert argv[-2:] == ["--", "jdoe"]
    # Defence in depth: an adult or dating row that came back anyway is dropped, by tag or by host.
    assert [r["site"] for r in out["results"]] == ["GitHub", "Facebook"]
    assert not any("adult" in r for r in out["results"])
    assert (out["nsfw"], out["sites_checked"], out["adult_checked"], out["adult_errors"]) == (False, 508, 0, [])
    assert "adult_error" not in out and "error" not in out


def test_maigret_with_the_opt_in_adds_an_adult_pass_over_the_full_tag_list(monkeypatch):
    out, seen = run_maigret(monkeypatch, nsfw=True)
    assert len(seen) == 2
    normal, adult = seen
    # the normal pass is exactly what runs without the opt-in
    assert normal == mm.build_command("jdoe", option(normal, "--folderoutput"))
    assert "--exclude-tags" in normal and "--tags" not in normal and option(normal, "--top-sites") == "500"
    # the adult pass: only the adult tags, every site that carries one, not the top 500
    assert ADULT_TAGS <= set(option(adult, "--tags").split(","))
    assert "--all-sites" in adult and "--top-sites" not in adult and "--exclude-tags" not in adult and "--print-errors" in adult
    assert "--use-disabled-sites" not in adult and adult[-2:] == ["--", "jdoe"]
    for argv in seen:                                               # the limits both passes share
        assert option(argv, "--timeout") == "10" and "--no-recursion" in argv and option(argv, "-J") == "simple"

    by = {r["site"]: r for r in out["results"]}
    assert set(by) == {"GitHub", "Facebook", "Tinder", "Leaky", "Fansly", "Xvideos", "ChaturBate", "RamblerDating", "massagerepublic.com"}
    assert "Stray" not in by and "Gone" not in by
    for site in ("Xvideos", "ChaturBate", "RamblerDating", "massagerepublic.com", "Tinder", "Leaky", "Fansly"):
        assert by[site]["adult"] is True and by[site]["category"] in ("adult", "dating"), site
    assert {s: by[s]["category"] for s in ("Xvideos", "ChaturBate", "massagerepublic.com", "RamblerDating", "Tinder", "Leaky", "Fansly")} == {
        "Xvideos": "adult", "ChaturBate": "adult", "massagerepublic.com": "adult", "RamblerDating": "dating", "Tinder": "dating",
        "Leaky": "adult", "Fansly": "adult"}
    assert "adult" not in by["GitHub"] and by["GitHub"]["category"] == "coding"
    # text metadata only: name, join date, follower count and a plain bio
    assert by["Xvideos"]["profile"] == {"name": "Sam Example", "created_at": "2013-07-21 00:00:00 UTC", "followers": 5224}
    assert by["ChaturBate"]["profile"] == {"name": "Sam", "bio": "Just here to chat."}
    assert by["Xvideos"]["verified"] is True and by["RamblerDating"]["verified"] is False and "profile" not in by["RamblerDating"]
    adult_rows = [r for r in out["results"] if r.get("adult")]
    assert media_leaks(adult_rows) == [] and "cdn.example/x" not in json.dumps(adult_rows) and "cdn.example/c" not in json.dumps(adult_rows)
    for r in adult_rows:
        assert set(r) <= {"site", "url", "confidence", "category", "verified", "adult", "profile"}
        assert set(r.get("profile", {})) <= {"name", "created_at", "followers", "bio"}
    # the normal rows are untouched (the avatar matcher still needs their picture)
    assert by["GitHub"]["profile"]["image"] == "https://cdn.example/gh.png"

    assert (out["nsfw"], out["sites_checked"], out["adult_checked"]) == (True, 508 + 66, 66)
    assert out["adult_errors"] == ["Livejasmin", "massagerepublic.example", "Dating.Ru"]        # a "[?] name: url" line is a similar-name hit, not an error
    assert "adult_error" not in out and out["total"] == len(out["results"]) == 9 and out["verified"] == 3


def test_a_failed_adult_pass_keeps_the_normal_pass(monkeypatch):
    out, seen = run_maigret(monkeypatch, nsfw=True, adult_hangs=True, adult_timeout=0.2)
    assert len(seen) == 2
    kept = {"GitHub", "Facebook", "Tinder", "Leaky", "Fansly"}                  # everything the normal pass returned
    assert {r["site"] for r in out["results"]} == kept and out["results"][0]["site"] == "GitHub"
    assert (out["total"], out["verified"], out["sites_checked"], out["adult_checked"], out["adult_errors"]) == (5, 1, 508, 0, [])
    assert (out["adult_error_code"], out["adult_error"]) == ("timeout", "Maigret ran out of time. Partial results were discarded.")
    assert "adult_error_detail" in out and "error" not in out and "error_code" not in out and out["nsfw"] is True

    out, _ = run_maigret(monkeypatch, nsfw=True, adult_missing=True)
    assert {r["site"] for r in out["results"]} == kept
    assert out["adult_error_code"] == "unreachable" and out["adult_error_detail"] == "OSError" and "error" not in out


def test_the_adult_pass_has_its_own_time_limit_inside_the_one_tool_slot():
    import inspect
    assert inspect.signature(mm._run_maigret_impl).parameters["adult_timeout"].default == mm.ADULT_TIMEOUT == 60
    assert inspect.signature(mm._run_maigret_impl).parameters["timeout"].default == 180
    src = inspect.getsource(mm.run_maigret)
    assert src.count("tool_slot(") == 1 and "gather" not in inspect.getsource(mm._run_maigret_impl)      # one after the other


def test_maigret_opt_in_must_be_exactly_true_and_a_minor_handle_never_starts_it(monkeypatch):
    for value in (None, 0, "true", 1):
        out, seen = run_maigret(monkeypatch, nsfw=value)
        assert len(seen) == 1 and out["nsfw"] is False, value

    async def never(*a, **k):
        raise AssertionError("maigret was started")
    monkeypatch.setattr(mm.asyncio, "create_subprocess_exec", never)
    out = asyncio.run(mm.run_maigret("born2012", nsfw=True))
    assert out["error_code"] == "minor_guard" and out["results"] == [] and out["nsfw"] is False


def test_maigret_itself_selects_no_adult_site_for_the_normal_pass_and_only_adult_sites_for_the_adult_pass():
    """Feed the two command lines, and the database each one names, to Maigret's own site selection."""
    sites = pytest.importorskip("maigret.sites")
    from maigret.db_updater import BUNDLED_DB_PATH
    import sys

    normal = mm.build_command("jdoe", "/tmp/x")
    adult = mm.build_adult_command("jdoe", "/tmp/x")
    # both passes are pinned: a named database, and no update on the way
    for argv in (normal, adult):
        assert Path(option(argv, "--db")).is_file() and "--no-autoupdate" in argv
    assert Path(option(adult, "--db")).samefile(BUNDLED_DB_PATH) and Path(option(adult, "--db")).samefile(adult_sites.MAIGRET_DATA)
    assert not Path(option(normal, "--db")).samefile(BUNDLED_DB_PATH)

    # The normal pass: its database holds no adult or dating site at all, so nothing can select one.
    db = sites.MaigretDatabase().load_from_path(option(normal, "--db"))
    for site in db.sites:
        assert not ({t.lower() for t in site.tags} & set(adult_sites.ADULT_TAGS)), site.name
        assert not adult_sites.is_adult_site(site.name, site.url or ""), site.name
        assert not adult_sites.is_adult_site(url=site.url_main or ""), site.name
    for gone in ("RoyalCams", "Dating.Ru", "MeetMe", "Fansly", "Justforfans", "Admire Me", "OnlyFans", "Tinder", "Pornhub", "xHamster"):
        assert gone not in db.sites_dict, gone
    picked = db.ranked_sites_dict(top=int(option(normal, "--top-sites")), excluded_tags=option(normal, "--exclude-tags").split(","),
                                  disabled=False, id_type="username")
    assert len(picked) >= 400 and {"GitHub", "Reddit"} <= set(picked)
    for site in picked.values():
        assert mm.adult_category(site.tags, (site.url or "").replace("{username}", "x"), site.name) == "", site.name
    # even with every filter option taken away, that database cannot produce one
    everything = db.ranked_sites_dict(top=sys.maxsize, disabled=True, id_type="username")
    assert not any(adult_sites.is_adult_site(s.name, s.url or "") for s in everything.values())

    # The adult pass: the installed database, every site with an adult tag, not the top 500.
    full_db = sites.MaigretDatabase().load_from_path(option(adult, "--db"))
    tags = option(adult, "--tags").split(",")
    full = full_db.ranked_sites_dict(top=sys.maxsize, tags=tags, disabled=False, id_type="username")        # what --all-sites does
    assert len(full) >= 50 and all({t.lower() for t in s.tags} & set(tags) for s in full.values())
    assert all(adult_sites.is_adult_site(s.name, s.url or "") for s in full.values())
    top500 = full_db.ranked_sites_dict(top=500, disabled=False, id_type="username")
    reached_before = [s for s in top500.values() if {t.lower() for t in s.tags} & ADULT_TAGS]
    assert len(reached_before) < len(full) and {"OnlyFans", "ChaturBate", "Tinder", "xHamster"} <= set(full)
    # The unpinned top 500 used to include an untagged dating site. That is the leak this closes.
    assert "MeetMe" in top500 and "MeetMe" not in picked


def test_maigret_does_not_run_without_its_installed_database(monkeypatch):
    async def never(*a, **k):
        raise AssertionError("maigret was started with no database")
    monkeypatch.setattr(mm, "MAIGRET_AVAILABLE", True)
    monkeypatch.setattr(mm.asyncio, "create_subprocess_exec", never)
    monkeypatch.setattr(mm, "normal_db_file", lambda: "")
    assert asyncio.run(mm._run_maigret_impl("jdoe"))["error_code"] == "not_installed"
    assert mm.filtered_database("/nonexistent/data.json") == {}


def test_the_filtered_database_is_written_once_and_rebuilt_if_it_disappears(monkeypatch):
    first = mm.normal_db_file()
    assert first and mm.normal_db_file() == first
    Path(first).unlink()
    second = mm.normal_db_file()
    assert second and Path(second).is_file()
    assert "RoyalCams" not in json.loads(Path(second).read_text(encoding="utf-8"))["sites"]


def test_adult_category_and_error_lines():
    assert mm.adult_category(["porn"]) == "adult" and mm.adult_category(["dating", "ru"]) == "dating"
    assert mm.adult_category(["dating", "webcam"]) == "adult" and mm.adult_category(["Erotic"]) == "adult"
    assert mm.adult_category(["social"], "https://justfor.fans/x") == "adult" and mm.adult_category([], "https://tinder.com/@x") == "dating"
    assert mm.adult_category(["social"], "", "RoyalCams") == "adult" and mm.adult_category([], "http://dating.ru/x") == "dating"
    assert mm.adult_category(["social"], "https://github.com/x") == "" and mm.adult_category(None) == "" and mm.adult_category("porn") == ""
    assert mm._sites_checked("nothing here") is None and mm._errored_sites("") == []


# ---- the guard on all three HTTP paths ----------------------------------------------------

def spy(monkeypatch):
    """Replace the three runners with recorders. Returns the list of calls."""
    calls = []

    def recorder(name):
        async def run(username, **kw):
            calls.append((name, username, kw))
            return {"username": username, "results": [], "total": 0}
        return run

    monkeypatch.setattr(recon, "run_sherlock", recorder("sherlock"))
    monkeypatch.setattr(recon, "run_maigret", recorder("maigret"))
    monkeypatch.setattr(recon, "run_adult_check", recorder("adult-check"))
    return calls


@pytest.mark.parametrize("handle", ["jake13", "born2012", "17f", "schoolgirl", "teen_16", "k1d"])
def test_every_adult_path_answers_400_minor_guard(c, monkeypatch, handle):
    calls = spy(monkeypatch)
    reason = adult_guard.minor_indicated(handle)
    for path, body in (("/api/recon/sherlock", {"username": handle, "nsfw": True}),
                       ("/api/recon/maigret", {"username": handle, "nsfw": True}),
                       ("/api/recon/adult-check", {"username": handle})):
        r = c.post(path, json=body)
        got = r.json()
        assert r.status_code == 400, path
        assert (got["error_code"], got["code"], got["error_detail"], got["reason"]) == ("minor_guard", "minor_guard", reason, reason), path
        assert got["detail"] == got["error"] == adult_guard.MESSAGE and handle not in json.dumps(got)
    assert calls == []                                              # nothing was run


def test_without_the_opt_in_nothing_changes_for_any_handle(c, monkeypatch):
    calls = spy(monkeypatch)
    no_adult_check(monkeypatch)
    for handle in ("jake13", "torvalds"):
        assert c.post("/api/recon/sherlock", json={"username": handle}).status_code == 200
        assert c.post("/api/recon/maigret", json={"username": handle}).status_code == 200
        assert c.post("/api/recon/maigret", json={"username": handle, "nsfw": False}).status_code == 200
    assert [(n, u, kw) for n, u, kw in calls] == [
        ("sherlock", "jake13", {"nsfw": False}), ("maigret", "jake13", {"nsfw": False}), ("maigret", "jake13", {"nsfw": False}),
        ("sherlock", "torvalds", {"nsfw": False}), ("maigret", "torvalds", {"nsfw": False}), ("maigret", "torvalds", {"nsfw": False})]
    assert not any(n == "adult-check" for n, _, _ in calls)


def test_the_opt_in_reaches_the_tools_for_an_ordinary_handle(c, monkeypatch):
    calls = spy(monkeypatch)
    assert c.post("/api/recon/sherlock", json={"username": "torvalds", "nsfw": True}).status_code == 200
    assert c.post("/api/recon/maigret", json={"username": "@torvalds", "nsfw": True}).status_code == 200
    assert c.post("/api/recon/adult-check", json={"username": "torvalds"}).status_code == 200
    assert calls == [("sherlock", "torvalds", {"nsfw": True}), ("maigret", "torvalds", {"nsfw": True}), ("adult-check", "torvalds", {})]
    # the handle is validated before the guard and before any tool
    for path in ("/api/recon/sherlock", "/api/recon/maigret", "/api/recon/adult-check"):
        assert c.post(path, json={"username": "--proxy", "nsfw": True}).status_code == 400
        assert c.post(path, json={"username": "a b", "nsfw": True}).json().get("error_code") != "minor_guard"
    assert len(calls) == 3


def test_the_guard_cannot_be_switched_off_by_a_request(c, monkeypatch):
    calls = spy(monkeypatch)
    for extra in ({"force": True}, {"override": True}, {"skip_guard": True}, {"adult_confirmed": True}, {"age_verified": True}):
        for path in ("/api/recon/sherlock", "/api/recon/maigret", "/api/recon/adult-check"):
            r = c.post(path, json={"username": "jake13", "nsfw": True, **extra}, headers={"X-Force": "1", "X-Adult-Override": "true"})
            assert r.status_code == 400 and r.json()["error_code"] == "minor_guard", (path, extra)
    assert calls == []


def test_expensive_adult_paths_have_their_own_rate_limits(monkeypatch):
    monkeypatch.undo()
    for path in ("/api/recon/sherlock", "/api/recon/maigret", "/api/recon/adult-check"):
        group, limit, window = rl.match_limit(path)
        assert group == path and limit <= 10 and window == 60
