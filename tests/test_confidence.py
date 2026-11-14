import asyncio
import json

import pytest

from modules import maigret_mod as mm
from modules.sherlock import _classify_site


@pytest.mark.parametrize("site,expected", [
    ("GitHub", "major_platform"), ("X", "major_platform"), ("Twitter", "major_platform"), ("Steam Community", "major_platform"),
    ("mastodon.social", "major_platform"),
    # "x" used to match as a substring, so these were all rated high confidence
    ("MixCloud", "normal"), ("Letterboxd", "normal"), ("pixelfed.social", "normal"), ("Xbox Gamertag", "normal"), ("Dropbox", "normal"),
    ("Chess", "false_positive"), ("Roblox", "false_positive"),
])
def test_site_classification(site, expected):
    assert _classify_site(site) == expected


@pytest.mark.parametrize("ids,verified", [
    ({"uid": "1024025", "fullname": "Linus Torvalds", "location": "Portland, OR", "_extractor": "GitHub API"}, True),
    ({"twitch_channel_id": "16537005", "twitch_username": "torvalds", "_extractor": "TwitchTracker"}, True),
    ({"fullname": "ToRvaLDs", "image": "https://cdn.example/x.jpg", "_extractor": "Telegram"}, True),
    ({"fullname": "VK | VK", "_extractor": "VK closed user profile"}, False),   # the site's own title, not a profile
    ({"_extractor": "Something"}, False),
    ({}, False),
    (None, False),
    ("garbage", False),
])
def test_profile_signal(ids, verified):
    assert (mm.profile_signal(ids) is not None) is verified


def test_profile_signal_extracts_display_fields():
    p = mm.profile_signal({"uid": "1", "fullname": "Patrick Example", "description": "bio text", "created_at": "2011", "image": "https://i.example/a.png", "_extractor": "Facebook user profile"})
    assert p == {"name": "Patrick Example", "bio": "bio text", "created_at": "2011", "image": "https://i.example/a.png", "extractor": "Facebook user profile"}


REPORT = {
    "GitHub": {"status": {"status": "Claimed", "site_name": "GitHub", "tags": ["coding"], "ids": {"uid": "1", "fullname": "A Person"}}, "url_user": "https://github.com/jdoe"},
    "Facebook": {"status": {"status": "Claimed", "site_name": "Facebook", "tags": ["social"], "ids": {}}, "url_user": "https://facebook.com/jdoe"},
    "Paypal": {"status": {"status": "Claimed", "site_name": "Paypal", "tags": ["finance"]}, "url_user": "https://paypal.me/jdoe"},
    "Nope": {"status": {"status": "Available", "site_name": "Nope"}, "url_user": "https://nope.example/jdoe"},
}


def _run_maigret(monkeypatch, **kwargs):
    seen = {}

    class Proc:
        returncode = 0
        async def communicate(self): return b"", b""

    async def fake_exec(*argv, cwd=None, **kw):
        seen["argv"] = list(argv)
        with open(f"{cwd}/report_jdoe_simple.json", "w") as f:
            json.dump(REPORT, f)
        return Proc()

    monkeypatch.setattr(mm, "MAIGRET_AVAILABLE", True)
    monkeypatch.setattr(mm.asyncio, "create_subprocess_exec", fake_exec)
    return asyncio.run(mm._run_maigret_impl("jdoe", **kwargs)), seen["argv"]


def test_maigret_only_marks_hits_with_profile_data_as_verified(monkeypatch):
    out, _ = _run_maigret(monkeypatch)
    by = {r["site"]: r for r in out["results"]}
    assert set(by) == {"GitHub", "Facebook", "Paypal"}
    assert by["GitHub"]["verified"] is True and by["GitHub"]["profile"]["name"] == "A Person"
    # famous sites with no parsed profile are leads, not confirmations
    assert by["Facebook"]["verified"] is False and by["Paypal"]["verified"] is False
    assert out["verified"] == 1 and out["possible"] == 3 and "confirmed" not in out
    assert out["results"][0]["site"] == "GitHub"            # verified hits sort first


def test_adult_sites_are_excluded_by_default(monkeypatch):
    _, argv = _run_maigret(monkeypatch)
    excluded = argv[argv.index("--exclude-tags") + 1].split(",")
    assert {"porn", "erotic", "webcam", "dating"} <= set(excluded)
    assert "--tags" not in argv and "!nsfw" not in argv     # the old filter matched no sites at all
    _, argv = _run_maigret(monkeypatch, nsfw=True)           # explicit opt-in
    assert "--exclude-tags" not in argv


def test_adult_sites_default_is_off_at_every_layer():
    import inspect
    from routers.recon import MaigretRequest
    assert MaigretRequest(username="jdoe").nsfw is False
    assert inspect.signature(mm.run_maigret).parameters["nsfw"].default is False
    assert inspect.signature(mm._run_maigret_impl).parameters["nsfw"].default is False


def test_adult_sites_default_is_off_in_the_ui():
    src = open("static/v2/js/investigate.js").read()
    assert 'label: "include adult and dating sites", on: false' in src
    assert 'srcState["maigret.nsfw"] === true' in src
    assert 'srcState["maigret.nsfw"] !== false' not in src


# ---- the AI prompt uses the ledger's vocabulary ---------------------------------------
from routers.analyze import AnalyzeRequest, investigation_prompt


def _data(**body):
    return investigation_prompt(AnalyzeRequest(**body)).split("Collected data:")[1]


def test_prompt_groups_accounts_by_ledger_tier():
    data = _data(target="torvalds", accounts=[
        {"site": "GitHub", "url": "https://github.com/torvalds", "status": "linked", "note": "GitHub's own record for this handle"},
        {"site": "Snapchat", "url": "https://www.snapchat.com/add/torvalds", "status": "matches", "note": "name on profile: Linus Torvalds"},
        {"site": "Medium", "url": "https://medium.com/@torvalds", "status": "different", "note": "name on profile: Patricia Torvalds"},
        {"site": "PayPal", "url": "https://paypal.me/torvalds", "status": "unverified"},
    ])
    linked, rest = data.split("EXISTS (MATCHES) accounts (1)")
    matches, rest = rest.split("EXISTS (DIFFERENT PERSON) accounts (1)")
    different, unverified = rest.split("UNVERIFIED accounts (1)")
    assert "LINKED accounts (1)" in linked and "GitHub" in linked and "Snapchat" not in linked
    assert "Snapchat" in matches and "Patricia" not in matches
    assert "Patricia Torvalds" in different and "other people who share the handle, not the target" in different
    assert "PayPal" in unverified


def test_prompt_tells_the_model_what_each_group_allows():
    prompt = investigation_prompt(AnalyzeRequest(target="t"))
    assert "LINKED, EXISTS (MATCHES), EXISTS (DIFFERENT PERSON) and UNVERIFIED" in prompt
    assert "Never use their names, locations, bios or links to describe the target" in prompt
    assert "CONFIRMED" not in prompt and "POSSIBLE" not in prompt


@pytest.mark.parametrize("old,new", [("confirmed", "EXISTS (MATCHES) accounts (1)"), ("possible", "UNVERIFIED accounts (1)"), ("nonsense", "UNVERIFIED accounts (1)")])
def test_old_and_unknown_statuses_never_become_linked(old, new):
    data = _data(target="t", accounts=[{"site": "Bluesky", "status": old}])
    assert new in data and "LINKED" not in data


def test_breaches_in_the_prompt_accept_both_shapes():
    old = _data(target="a@example.org", hibp={"breaches": ["Adobe", "LinkedIn"]})
    assert "Breach check found 2 breaches: Adobe, LinkedIn" in old
    new = _data(target="a@example.org", hibp={"breaches": [
        {"name": "LinkedIn", "date": "2012-05-05", "year": 2012, "data_classes": ["Email addresses", "Passwords"]},
        {"name": "Undated", "date": "", "year": None}]})
    assert "Breach check found 2 breaches: LinkedIn (2012), Undated" in new


def test_deep_dive_and_correlate_breach_lines_accept_objects():
    from routers.analyze import _breach_names, _summarize_target_data
    assert _breach_names({"breaches": [{"name": "Evite", "date": "2019-02-28"}, "Old"]}) == ["Evite (2019)", "Old"]
    assert "Breaches: Evite (2019)" in _summarize_target_data("a@example.org", {"hibp": {"breaches": [{"name": "Evite", "year": 2019}]}})


def test_hash_prompt_is_about_the_file_not_a_person():
    prompt = investigation_prompt(AnalyzeRequest(target="44d88612fea8a8f36de82e1278abb02f", target_type="hash", hash={
        "hash_type": "MD5", "verdict": "TEST_FILE", "known_test_file": {"name": "EICAR antivirus test file", "note": ""},
        "family": "", "detection": None, "community_tags": ["TrojanSpy"]}))
    assert "This target is a file hash, not a person" in prompt
    data = prompt.split("Collected data:")[1]
    assert "verdict: TEST_FILE" in data and "it is not malware" in data
    assert "detection ratio: none available from keyless sources" in data
    assert "Community tags (free text" in data and "TrojanSpy" in data


def test_person_targets_keep_the_identity_question():
    prompt = investigation_prompt(AnalyzeRequest(target="jdoe", target_type="username"))
    assert "not a person" not in prompt and "## Identity assessment" in prompt


def test_platform_check_states_reach_the_prompt():
    data = _data(target="jdoe", platform_check={"results": [
        {"platform": "Instagram", "url": "https://www.instagram.com/jdoe/", "state": "found", "found": True, "display_name": "J Doe"},
        {"platform": "LinkedIn", "url": "https://www.linkedin.com/in/jdoe", "state": "blocked", "found": None, "evidence": "login wall"},
        {"platform": "X", "url": "https://x.com/jdoe", "state": "not_found", "found": False}]})
    assert "read a profile page" in data and "Instagram" in data and "name on profile: J Doe" in data
    assert "blocked or could not tell on (unknown, not absent): LinkedIn [login wall]" in data
    assert "found no profile on: X" in data


def test_blocked_and_partial_sources_are_never_listed_as_successful():
    data = _data(target="jdoe", source_status={
        "Sherlock": "ok", "GitHub": "not found",
        "Platform check": "blocked: blocked by every site checked",
        "Avatar comparison": "failed: no image could be read",
        "Hash lookup": "partial: 2 of 4 sources answered"})
    ok_line = next(l for l in data.splitlines() if l.startswith("Sources that ran successfully"))
    assert "Sherlock" in ok_line and "GitHub" in ok_line
    assert "Platform check" not in ok_line and "Avatar comparison" not in ok_line and "Hash lookup" not in ok_line
    failed = next(l for l in data.splitlines() if l.startswith("Sources that FAILED"))
    assert "Platform check (blocked by every site checked)" in failed and "Avatar comparison (no image could be read)" in failed
    partial = next(l for l in data.splitlines() if l.startswith("Sources that answered only IN PART"))
    assert "Hash lookup (partial: 2 of 4 sources answered)" in partial and "unknown, not a negative result" in partial
