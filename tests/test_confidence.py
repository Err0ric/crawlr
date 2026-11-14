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
