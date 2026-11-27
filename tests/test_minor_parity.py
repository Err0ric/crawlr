"""The two engines of the minor guard give the same answer.

core/minor_rules.py and static/v2/js/minorscan.js both load static/v2/data/minor-rules.json.
Here every fixture handle and bio, the owner's cases and a seeded fuzz set go through both, and
any difference in any field fails. Node is required: without it this fails, it does not skip.
No network.
"""

import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from core import minor_rules as mr

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "minor"
RUNNER = ROOT / "tests" / "js" / "minor_runner.mjs"
HANDLES = json.loads((FIX / "handles.json").read_text(encoding="utf-8"))
BIOS = json.loads((FIX / "bios.json").read_text(encoding="utf-8"))


def _ymd(text: str) -> tuple[int, int, int]:
    y, m, d = text.split("-")
    return int(y), int(m), int(d)


def run_js(payload: dict) -> dict:
    node = shutil.which("node")
    if not node:
        pytest.fail("node is not installed: the parity test needs it to run the JavaScript engine")
    done = subprocess.run([node, str(RUNNER)], input=json.dumps(payload), capture_output=True, text=True, timeout=120, cwd=str(ROOT))
    if done.returncode != 0:
        pytest.fail(f"the JavaScript runner failed: {done.stderr[-600:]}")
    return json.loads(done.stdout)


def run_py(payload: dict) -> dict:
    engine = mr.load()
    today = _ymd(payload["today"])
    return {
        "handles": [{"token": engine.handle_token(h), "soft": engine.soft_birth_year(h, today), "years": engine.soft_bare_years(h)} for h in payload.get("handles", [])],
        "scans": [engine.scan(s["profiles"], s["handle"], _ymd(s.get("today") or payload["today"])) for s in payload.get("scans", [])],
    }


def assert_same(payload: dict) -> dict:
    py, js = run_py(payload), run_js(payload)
    assert len(py["handles"]) == len(js["handles"]) and len(py["scans"]) == len(js["scans"])
    for handle, a, b in zip(payload.get("handles", []), py["handles"], js["handles"]):
        assert a == b, (handle, a, b)
    for scan, a, b in zip(payload.get("scans", []), py["scans"], js["scans"]):
        for key in ("blocked", "kind", "soft", "soft_years", "read"):
            assert a[key] == b[key], (key, scan, a, b)
        assert a["signal"] == b["signal"], (scan, a["signal"], b["signal"])
        assert len(a["signals"]) == len(b["signals"]), (scan, a["signals"], b["signals"])
        for x, y in zip(a["signals"], b["signals"]):
            for key in ("strength", "kind", "rule", "source", "snippet", "url"):
                assert x[key] == y[key], (key, scan, x, y)
    return py


def fixture_scans() -> list[dict]:
    one = lambda bio: {"handle": BIOS["handle"], "profiles": [{"source": BIOS["source"], "url": "https://example.org/p", "bio": bio}]}
    scans = [one(row["bio"]) for group in ("block", "weak", "clean") for row in BIOS[group]]
    # Every bio again under a handle that carries a soft birth year, and as a display name.
    scans += [{**one(row["bio"]), "handle": "mike2010"} for group in ("block", "weak", "clean") for row in BIOS[group]]
    scans += [{"handle": "mike2010", "profiles": [{"source": "Name", "url": "", "name": row["bio"]}]} for group in ("block", "weak", "clean") for row in BIOS[group]]
    # ...under a handle with bare years, and as further profile text
    scans += [{"handle": "sam_16yrs", "profiles": [{"source": "Text", "url": "", "text": row["bio"]}]} for group in ("block", "weak", "clean") for row in BIOS[group]]
    scans += [{"handle": c["handle"], "profiles": c["profiles"]} for c in BIOS["cases"]]
    return scans


def test_every_fixture_gets_the_same_answer_from_both_engines():
    handles = [c["handle"] for c in HANDLES["cases"]] + [c["handle"] for c in HANDLES["soft"]] + ["sam_16yrs", "10yrs_exp"]
    scans = fixture_scans()
    assert len(HANDLES["cases"]) >= 100 and len(BIOS["block"]) + len(BIOS["weak"]) + len(BIOS["clean"]) >= 60
    assert_same({"today": HANDLES["today"], "handles": handles, "scans": scans})


def test_the_answers_agree_on_other_dates():
    # The year arithmetic is the part most likely to drift: the same fixtures on four other days.
    scans = fixture_scans()
    handles = [c["handle"] for c in HANDLES["soft"]]
    for today in ("2026-06-30", "2026-07-01", "2027-01-01", "2031-03-09"):
        assert_same({"today": today, "handles": handles, "scans": scans})


HANDLE_PARTS = ["age", "aged", "my", "im", "of", "mom", "dad", "stone", "8", "12", "exp", "yo", "y", "o", "yr", "yrs", "year", "years", "old", "of", "under", "pre", "teen", "jail", "bait", "b41t", "und3r", "th",
                "1", "0", "7", "9", "13", "15", "16", "17", "18", "21", "017", "2008", "2010", "2019", "2021", "1999", ".", "_", "-", "/", "@", "x", "k", "a", "e", "mike", "sam", "A", "YO", " "]


def test_fuzz_handles_agree():
    rng = random.Random(20261122)
    handles = ["".join(rng.choice(HANDLE_PARTS) for _ in range(rng.randint(1, 6))) for _ in range(30000)]
    got = assert_same({"today": "2026-11-22", "handles": handles, "scans": []})
    # The set exercises the rules: every answer occurs many times.
    for token in ("age", "word", None):
        assert sum(1 for h in got["handles"] if h["token"] == token) > 100, token
    assert sum(1 for h in got["handles"] if h["soft"]) > 200 and sum(1 for h in got["handles"] if h["years"]) > 200


BIO_PARTS = ["i'm", "I’m", "im", "i am", "15", "16", "17", "18", "13", "9", "2029", "2031", "2010", "2008", "'29", "'09", "class of", "c/o", "co", "high school", "HS", "Lincoln High", "lincoln high", "LHS", "'28", "\U0001f382", "5/14/2011", "3/4/10", "\uff11\uff15", "\U0001d7cf\U0001d7d3", "fifteen", "turned", "just", "Rex is",
             "whisky", "he/him", "they/them", "and bored", "(almost 18)",
             "middle school", "8th grade", "grade 9", "year 9", "freshman", "sophomore", "junior", "senior", "student", "teacher", "mom of", "my son", "born", "b.", "dob", "baby",
             "yo", "y/o", "years old", "year old", "age", "aged", "turning", "minor", "teen", "under 18", "13+", "18+", "she/her", "f", "m", "|", "•", "·", ",", "/", "-", ".", "!", "\n",
             "\U0001f338", "✨", "é", "日本", "‍", "️", " ", "college", "university", "alumni", "since", "at", "in", "a", "the", "of", "dog", "est.", "#", "$", "%", "k", "th", "GCSEs", "school"]


def test_fuzz_bios_agree():
    rng = random.Random(1122)
    scans = []
    for _ in range(6000):
        text = "".join(rng.choice(BIO_PARTS) + rng.choice([" ", " ", " ", ""]) for _ in range(rng.randint(1, 12)))
        field = rng.choice(["bio", "bio", "bio", "name", "text"])
        scans.append({"handle": rng.choice(["sam_rivera", "mike2010", "ana_2011", "x", "sam_16yrs"]), "profiles": [{"source": "S", "url": "", field: text}]})
    got = assert_same({"today": "2026-11-22", "handles": [], "scans": scans})
    for kind in ("age", "school", "birth", "soft", ""):
        assert sum(1 for r in got["scans"] if r["kind"] == kind) > 50, kind


def test_the_page_and_the_server_read_the_same_text_from_the_same_answers():
    """One case, as the ordinary sources answer it: what the server keeps for the content check
    and what the page reads are the same entries, with the same fields, in the same order."""
    from core import profile_record as pr
    h = "river_stone"
    long_bio = "Hello there. " * 30 + "i'm 15 \U0001f338"
    answers = {
        "sherlock": {"results": [{"site": "GitHub", "url": f"https://github.com/{h}"}]},
        "maigret": {"results": [
            {"site": "Gitlab", "url": f"https://gitlab.com/{h}", "verified": True, "confidence": "normal",
             "profile": {"name": "River S", "bio": long_bio[:300], "location": "Leeds", "guard": {"bio": long_bio, "text": "about me\nLincoln High", "birthday": "2011-03-02", "age": "15"}}},
            {"site": "Noisy", "url": f"https://noisy.example/{h}", "verified": True, "confidence": "false_positive", "profile": {"bio": "i'm 15"}},
            {"site": "Pornhub", "url": f"https://www.pornhub.com/users/{h}", "verified": True, "adult": True, "profile": {"bio": "i'm 15"}},
            {"site": "Fansly", "url": f"https://fansly.com/{h}", "verified": True, "profile": {"bio": "i'm 15"}},
            {"site": "Bare", "url": f"https://bare.example/{h}", "verified": False},
        ]},
        "github": {"found": True, "profile_url": f"https://github.com/{h}", "name": "River Stone", "bio": "Builds things.", "company": "Lincoln High School", "location": "9th grade", "email": "x@example.org"},
        "platform_check": {"results": [{"platform": "Reddit", "state": "found", "url": f"https://www.reddit.com/user/{h}", "display_name": "", "bio": "likes maps"},
                                       {"platform": "Twitch", "state": "blocked", "url": f"https://twitch.tv/{h}", "bio": "i'm 15"}]},
        "enricher": {"profiles": [{"platform": "Instagram", "url": f"https://www.instagram.com/{h}/", "display_name": "River", "bio": "16 | junior in high school"},
                                  {"platform": "OnlyFans", "url": f"https://onlyfans.com/{h}", "bio": "i'm 15"},
                                  {"platform": "Empty", "url": "https://empty.example/u", "display_name": "", "bio": ""}]},
    }
    # The profile sources (POST /api/recon/profiles): scanned after the ordered sources, on both sides.
    profiles = {"profiles": [
        {"site": "Mastodon", "source": "mastodon", "state": "found", "url": f"https://mastodon.social/@{h}", "display_name": "River S.", "bio": long_bio[:300], "company": "Lincoln High", "location": "Leeds", "guard": {"bio": long_bio}},
        {"site": "Lichess", "source": "lichess", "state": "found", "url": f"https://lichess.org/@/{h}", "display_name": "", "bio": "class of 2029"},
        {"site": "Keybase", "source": "keybase", "state": "blocked", "url": f"https://keybase.io/{h}", "bio": "i'm 15"},
        {"site": "Empty", "source": "npm", "state": "found", "url": "https://www.npmjs.com/~x", "display_name": "", "bio": ""},
    ], "sources": {}}
    # The names on commits (POST /api/recon/commit-emails), keyed in the page's case by the account
    # row. The router records one row per found answer with rows, after the profile sources.
    from modules.commit_emails import guard_profile
    mail = lambda address, name: {"email": address, "name": name, "how": "author_line_match", "self_declared": True, "commits": 1, "repos": []}      # noqa: E731
    commits = {
        "acct:gitlab": {"site": "gitlab", "site_name": "GitLab", "username": h, "state": "found", "handle": h, "profile_url": f"https://gitlab.com/{h}", "display_name": "River S",
                        "emails": [mail("river@example.org", "River S"), mail("r.stone@example.com", "River Stone, 15yo"), mail("rs@example.net", "River Stone, 15yo"),
                                   mail("old@example.org", ""), mail("long@example.org", "\U0001f338" * 120)], "emails_state": "found"},
        "acct:codeberg": {"site": "codeberg", "site_name": "Codeberg", "username": h, "state": "found", "handle": h, "profile_url": f"https://codeberg.org/{h}", "display_name": "i'm 15",
                          "emails": [], "emails_state": "none"},
        "acct:gitea.com": {"site": "gitea", "site_name": "Gitea.com", "username": h, "state": "found", "handle": h, "profile_url": f"https://gitea.com/{h}", "display_name": "",
                           "emails": [mail(f"m{i}@example.org", f"Mara Lind {i}") for i in range(12)], "emails_state": "found"},
        "acct:nowhere": {"site": "gitlab", "site_name": "GitLab", "username": h, "state": "not_found", "emails": [mail("x@example.org", "i'm 15")], "emails_state": "none"},
        "acct:down": {"site": "codeberg", "site_name": "Codeberg", "username": h, "state": "failed", "profile_url": f"https://codeberg.org/{h}", "emails": [mail("x@example.org", "i'm 15")],
                      "emails_state": "unknown", "error": "The source took too long to answer.", "error_code": "timeout", "error_detail": "ConnectTimeout"},
    }
    # What two archived copies said (POST /api/recon/archive-diff), keyed the same way. The router
    # records the text of every answer that carries any, in pieces of at most 2000 characters, under
    # "Internet Archive" with the address of the older capture; the page reads the same from its case.
    from modules.archive_diff import guard_texts
    snap = lambda url, ts: f"https://web.archive.org/web/{ts.replace('-', '').replace(':', '').replace('T', '').replace('Z', '')}/{url}"      # noqa: E731
    side = lambda url, ts, title, state="ok": {"state": state, "timestamp": ts, "asked": ts, "exact": True, "url": snap(url, ts), "bytes": 900 if state == "ok" else 0,      # noqa: E731
                                                 "truncated": False, "title": title, "text_lines": 9 if state == "ok" else 0, "links": 2 if state == "ok" else 0}
    part = lambda text=(), links=(): {"text": list(text), "text_total": len(text), "links": list(links), "links_total": len(links)}      # noqa: E731
    kb, lc = f"https://keybase.io/{h}", f"https://lichess.org/@/{h}"
    long_lines = [f"line {i} " + "\U0001f338" * 280 for i in range(9)]
    diffs = {
        "acct:keybase": {"url": kb, "state": "ok", "from": side(kb, "2019-03-04T05:06:07Z", f"{h} (River Stone) on Keybase"), "to": side(kb, "2024-01-02T03:04:05Z", f"{h} on Keybase"),
                         "removed": part(["River Stone", "Lincoln High, class of 2029", *long_lines], [{"url": "https://social.example.net/@river", "external": True}]),
                         "added": part(["R S", "<b>not markup</b>"]), "complete": True, "swapped": False, "cached": False},
        "acct:lichess": {"url": lc, "state": "same", "from": side(lc, "2021-01-01T00:00:00Z", "river_stone, 15 \u2022 lichess.org"), "to": side(lc, "2021-06-01T00:00:00Z", "river_stone, 15 \u2022 lichess.org"),
                         "removed": part(), "added": part(), "complete": True, "swapped": False, "cached": True},
        "acct:npm": {"url": f"https://www.npmjs.com/~{h}", "state": "none", "missing": ["to"], "from": side(f"https://www.npmjs.com/~{h}", "2020-02-02T02:02:02Z", "npm profile of river"),
                     "to": {**side(f"https://www.npmjs.com/~{h}", "2022-02-02T02:02:02Z", "", "none"), "reason": "redirect", "note": "That capture is a redirect to another page, not the profile itself."},
                     "removed": part(), "added": part(), "complete": False, "swapped": False, "cached": False},
        "acct:down": {"url": kb, "state": "failed", "from": side(kb, "2019-03-04T05:06:07Z", "", "failed"), "to": side(kb, "2024-01-02T03:04:05Z", "", "failed"), "removed": part(), "added": part(),
                      "complete": False, "swapped": False, "cached": False, "error": "The source took too long to answer.", "error_code": "timeout", "error_detail": "ReadTimeout"},
        "acct:refused": {"url": "", "state": "refused", "from": None, "to": None, "removed": part(), "added": part(), "complete": False, "reason": "adult_site",
                         "note": "CrawlR does not look up archived copies of pages on adult or dating sites.", "cached": False},
    }
    engine = mr.load()
    server = [e for name, _ in engine.text_order for e in pr.entries_of(name, answers[name])] + pr.entries_of("profiles", profiles)
    server += pr.entries_of("profiles", {"profiles": [row for row in map(guard_profile, commits.values()) if row]})
    before_archive = len(server)
    for answer in diffs.values():        # as routers/recon_identity.py records one answer
        texts = guard_texts(answer)
        if texts:
            first = answer.get("from") or answer.get("to") or {}
            server += pr.entries_of("profiles", {"profiles": [{"state": "found", "site": "Internet Archive", "url": first.get("url", ""), "bio": text} for text in texts]})
    # The page's case holds an archive diff under the profile address it was asked for (the server echoes it as `url`).
    collected = {page: answers[name] for name, page in [("sherlock", "sherlock"), *engine.text_order]} | {"profiles": profiles, "commitEmails": commits, "archiveDiffs": diffs}
    node = shutil.which("node")
    assert node, "node is not installed: the parity test needs it"
    done = subprocess.run([node, str(ROOT / "tests" / "js" / "texts_runner.mjs")], input=json.dumps(collected), capture_output=True, text=True, timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stderr[-600:]
    page = json.loads(done.stdout)
    archive = server[before_archive:]
    assert [e["source"] for e in server] == ["Gitlab", "GitHub", "Reddit", "Instagram", "Mastodon", "Lichess", "GitLab", "Gitea.com"] + ["Internet Archive"] * len(archive)
    # The titles, then the removed lines, then the added ones, cut into pieces at the same line on both sides.
    assert len(archive) == 4 and [e["url"] for e in archive] == [snap(kb, "2019-03-04T05:06:07Z")] * 2 + [snap(lc, "2021-01-01T00:00:00Z"), snap(f"https://www.npmjs.com/~{h}", "2020-02-02T02:02:02Z")]
    assert archive[0]["bio"].split("\n")[:4] == [f"{h} (River Stone) on Keybase", f"{h} on Keybase", "River Stone", "Lincoln High, class of 2029"] and archive[1]["bio"].endswith("R S\n<b>not markup</b>")
    assert all(len(e["bio"]) <= 2000 and e["name"] == "" and e["text"] == "" for e in archive) and archive[2]["bio"] == "river_stone, 15 \u2022 lichess.org" and archive[3]["bio"] == "npm profile of river"
    # The profile's name, then the other author names once each, at most 100 characters of a name and ten rows; never an address.
    assert server[6] == {"source": "GitLab", "url": f"https://gitlab.com/{h}", "name": "River S", "bio": "River Stone, 15yo\n" + "\U0001f338" * 100, "text": ""}
    assert server[7]["name"] == "" and server[7]["bio"].split("\n") == [f"Mara Lind {i}" for i in range(10)]
    assert "@example" not in json.dumps(server[6:])
    assert server[4]["bio"] == long_bio and server[4]["text"] == "Lincoln High\nLeeds"
    assert page == server
    assert server[0]["bio"] == long_bio and server[0]["text"] == "Leeds\nabout me\nLincoln High" and server[1]["text"] == "Lincoln High School\n9th grade"
    # And both then reach the same verdict from it.
    assert_same({"today": "2026-11-22", "handles": [], "scans": [{"handle": h, "profiles": server}]})
