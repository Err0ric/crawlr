"""Platform marketing text must never be shown as a person's bio. No network."""
import asyncio

import httpx
import pytest

from core.boilerplate import clean_bio, is_boilerplate_bio
from modules import enricher, maigret_mod, profile_scraper

# The exact strings the live audit found in the "What we know" panel, for username torvalds.
AUDIT = [
    ("Twitch", "torvalds", "torvalds streams live on Twitch! Check out their videos, sign up to chat, and join their community."),
    ("Patreon", "Torvalds", "Join Torvalds on Patreon for exclusive content and member-only benefits from your favorite creators. Get access today!"),
    ("TikTok", "Torvalds", "@torvalds 6 Followers, 80 Following, 0 Likes - Watch awesome short videos created by Torvalds"),
    ("Facebook", "Patrick Torvalds", "Patrick Torvalds is on Facebook. Join Facebook to connect with Patrick Torvalds and others you may know. Facebook gives people the power to share and makes the world more open and connected."),
    ("Snapchat", "Linus Torvalds", "Linus Torvalds is on Snapchat! (@torvalds)"),
]


@pytest.mark.parametrize("platform,name,text", AUDIT)
def test_audit_strings_are_boilerplate(platform, name, text):
    assert is_boilerplate_bio(text, platform, "torvalds", name)
    assert clean_bio(text, platform, "torvalds", name) == ""


@pytest.mark.parametrize("platform,name,text", AUDIT)
def test_audit_strings_are_caught_with_no_context(platform, name, text):
    # Maigret and the profile scraper do not always know the platform, handle or name.
    assert is_boilerplate_bio(text)
    assert is_boilerplate_bio(text, platform)
    assert is_boilerplate_bio(text, username="torvalds")


@pytest.mark.parametrize("platform,username,name,text", [
    ("Twitch", "some_streamer", "Some_Streamer", "Some_Streamer streams live on Twitch! Check out their videos, sign up to chat, and join their community."),
    ("Twitch", "", "", "Twitch is the world's leading video platform and community for gamers."),
    ("TikTok", "a.b_c", "A B", "@a.b_c 1.2M Followers, 1,024 Following, 96.8m Likes - Watch awesome short videos created by A B"),
    ("TikTok", "x", "", "No bio yet"),
    ("Facebook", "jd", "Jane Doe", "Jane Doe is on Facebook. Join Facebook to connect with Jane Doe and others you may know. Facebook gives people the power to share and..."),
    ("Snapchat", "jd", "Jane Doe", "Jane Doe is on Snapchat!"),
    ("YouTube", "x", "", "Share your videos with friends, family, and the world"),
    ("YouTube", "x", "", "Enjoy the videos and music you love, upload original content, and share it all with friends, family, and the world on YouTube."),
    ("Instagram", "torvalds", "Sam Example", "227 Followers, 432 Following, 91 Posts - See Instagram photos and videos from Sam Example (@torvalds)"),
    ("Instagram", "instagram", "Instagram", "686M Followers, 172 Following, 8,646 Posts - See Instagram photos and videos from Instagram (@instagram)"),
    ("Instagram", "torvalds", "Sam Example", '12 Followers, 34 Following, 5 Posts - Sam Example (@torvalds) on Instagram: ""'),
    ("X", "jane", "", "The latest posts from @jane"),
    ("Twitter", "jane", "Jane Doe", "The latest Tweets from Jane Doe (@jane)."),
    ("X", "err0ric", "", "319 followers · 981 following. Joined Sep 2022. See the latest conversations with @err0ric"),
    ("Threads", "torvalds", "", "40 Followers • 0 Threads. See the latest conversations with @torvalds."),
    ("Pinterest", "torvalds", "Marco Migozzi", "See what Marco Migozzi (torvalds) has discovered on Pinterest, the world's biggest collection of ideas."),
    ("SoundCloud", "torvalds", "Torvalds Torvalds", "Listen to Torvalds Torvalds | SoundCloud is an audio platform that lets you listen to what you love and share the sounds you create."),
    ("Linktree", "jd", "", "Linktree. Make your link do more."),
    ("Linktree", "jd", "", "View jd’s Linktree to discover and stream music from top platforms like YouTube, Spotify here."),
    ("Medium", "torvalds", "Patricia Torvalds", "Read writing from Patricia Torvalds on Medium."),
    ("Medium", "torvalds", "Patricia Torvalds", "Read writing from Patricia Torvalds on Medium. Every day, Patricia Torvalds and thousands of other voices read, write, and share important stories on Medium."),
    ("Reddit", "x", "", "Reddit is a network of communities where people can dive into their interests, hobbies and passions. There's a community for whatever you're interested in on Reddit."),
    ("GitHub", "Err0ric", "", "Err0ric has 12 repositories available. Follow their code on GitHub."),
    ("GitHub", "new-user", "", "new-user has 1 repository available. Follow their code on GitHub."),
    ("Cash App", "jd", "", "Pay $jd on Cash App"),
    ("CashApp", "jd", "", "Instantly exchange money for free on Cash App"),
    ("OnlyFans", "x", "", "OnlyFans is the social platform revolutionizing creator and fan connections. The site is inclusive of artists and content creators from all genres and allows them to monetize their content while developing authentic relationships with their fanbase."),
    ("Telegram", "torvalds", "ToRvaLDs", "You can contact @torvalds right away."),
])
def test_templates_fit_any_account(platform, username, name, text):
    assert is_boilerplate_bio(text, platform, username, name), text
    assert is_boilerplate_bio(text), text          # and without being told who it is


@pytest.mark.parametrize("platform,username,name,text", [
    ("DailyMotion", "torvalds", "RCL", "linux env"),
    ("Bluesky", "torvalds", "", "https://deadspace.wtf"),
    ("Warpcast", "torvalds", "elec7rik", "caesar cipher expert, bell curve memes enthusiast, learning multiplication tables, posts frogs all the time, scared of em irl"),
    ("GitHub", "torvalds", "Linus Torvalds", "Creator of Linux and Git"),
    ("X", "x", "X", "what's happening?!"),
    ("Twitch", "jd", "", "I stream on Twitch every Friday"),
    ("Twitch", "jd", "", "Twitch partner. Join the community!"),
    ("Patreon", "jd", "", "Join me on Patreon for early episodes"),
    ("Instagram", "jd", "", "Follow me on Instagram and TikTok"),
    ("GitHub", "jd", "", "Follow my code on GitHub."),
    ("Facebook", "jd", "Jane Doe", "Jane Doe is on Facebook way too much"),
    ("Snapchat", "jd", "", "Snapchat: jd_real"),
    ("Telegram", "jd", "", "You can contact me on Telegram"),
    ("Medium", "jd", "", "I read writing from all over"),
    ("Linktree", "jd", "", "see my linktree"),
    ("Threads", "err0ric", "", "🤘 💻"),
    ("", "", "", "hi"),
    ("", "", "", "dev"),
    ("TikTok", "jd", "", "12 followers and counting"),
    ("YouTube", "jd", "", "I share my videos with friends"),
    ("Reddit", "jd", "", "Reddit mod, sysadmin"),
])
def test_real_bios_pass_through(platform, username, name, text):
    assert not is_boilerplate_bio(text, platform, username, name)
    assert clean_bio(text, platform, username, name) == text
    assert clean_bio(text) == text


@pytest.mark.parametrize("platform,username,name,text,expected", [
    ("TikTok", "torvalds", "Torvalds", "@torvalds 6 Followers, 80 Following, 0 Likes - kernel hacker, torvalds fan Watch awesome short videos created by Torvalds", "kernel hacker, torvalds fan"),
    ("TikTok", "dev", "", "@dev 1.2M Followers, 80 Following, 3.4M Likes - I write C. Ask @dev anything", "I write C. Ask @dev anything"),
    ("Instagram", "Err0ric", "Eric Henderson", '867 Followers, 1,626 Following, 97 Posts - Eric Henderson (@Err0ric) on Instagram: "Tacoma, WA\nCybersec"', "Tacoma, WA Cybersec"),
    ("Threads", "err0ric", "", "117 Followers • 0 Threads • 🤘 💻. See the latest conversations with @err0ric.", "🤘 💻"),
    ("Twitter", "jane", "Jane Doe", "The latest Tweets from Jane Doe (@jane). Building things. Seattle", "Building things. Seattle"),
    ("Medium", "torvalds", "Patricia Torvalds", "Read writing from Patricia Torvalds on Medium. Engineer and writer. Every day, Patricia Torvalds and thousands of other voices read, write, and share important stories on Medium.", "Engineer and writer."),
])
def test_boilerplate_wrapper_is_cut_and_the_real_bio_kept(platform, username, name, text, expected):
    assert clean_bio(text, platform, username, name) == expected
    assert clean_bio(text) == expected
    assert not is_boilerplate_bio(text, platform, username, name)


@pytest.mark.parametrize("platform,username,name,text", [
    # a display name with sentence punctuation is only matched when the caller knows it
    ("Patreon", "j.doe", "J. Doe & Co.", "Join J. Doe & Co. on Patreon for exclusive content and member-only benefits from your favorite creators. Get access today!"),
    # a "bio" that is only the platform's name or the handle echoed back
    ("Twitch", "torvalds", "", "Twitch"),
    ("Twitch", "torvalds", "", "@torvalds"),
    ("Twitch", "torvalds", "", "torvalds | Twitch"),
])
def test_matches_that_need_to_know_the_account(platform, username, name, text):
    assert is_boilerplate_bio(text, platform, username, name)
    assert not is_boilerplate_bio(text)


def test_odd_input():
    assert clean_bio(None) == "" and clean_bio("") == "" and clean_bio("   ") == ""
    assert not is_boilerplate_bio("") and not is_boilerplate_bio(None)   # nothing there is not boilerplate
    assert clean_bio("  real   bio\n here ") == "real bio here"
    # html entities, as they arrive from a meta tag that was not unescaped
    assert is_boilerplate_bio("Linus Torvalds is on Snapchat! (&#064;torvalds)", "Snapchat", "torvalds")
    # a username full of regex characters cannot break the match
    assert clean_bio("a+b(c streams live on Twitch! Check out their videos, sign up to chat, and join their community.", "Twitch", "a+b(c") == ""


# --- where the filter is applied -----------------------------------------------------------

TWITCH_PAGE = """<html><head><meta property="og:title" content="torvalds - Twitch">
<meta property="og:description" content="torvalds streams live on Twitch! Check out their videos, sign up to chat, and join their community."></head></html>"""
PATREON_PAGE = """<html><head><meta property="og:title" content="Torvalds | Patreon">
<meta property="og:description" content="Join Torvalds on Patreon for exclusive content and member-only benefits from your favorite creators. Get access today!"></head></html>"""
TIKTOK_PAGE = """<script>{"webapp.user-detail":{"userInfo":{"user":{"id":"1","uniqueId":"torvalds","nickname":"Torvalds","signature":""}},
"shareMeta":{"title":"Torvalds on TikTok","desc":"@torvalds 6 Followers, 80 Following, 0 Likes - Watch awesome short videos created by Torvalds"},"statusCode":0}}</script>"""
YOUTUBE_PAGE = """<html><head><meta property="og:title" content="Eric">
<meta property="og:description" content="Homelab and wardriving videos."></head></html>"""


def _fake_pages(monkeypatch, module, pages):
    real = httpx.AsyncClient

    def handler(request: httpx.Request):
        for needle, body in pages.items():
            if needle in str(request.url):
                return httpx.Response(200, text=body)
        return httpx.Response(404, text="")

    monkeypatch.setattr(module.httpx, "AsyncClient", lambda *a, **k: real(transport=httpx.MockTransport(handler)))


def test_enricher_blanks_boilerplate_bios_and_flags_them(monkeypatch):
    _fake_pages(monkeypatch, enricher, {"twitch.tv": TWITCH_PAGE, "patreon.com": PATREON_PAGE, "tiktok.com": TIKTOK_PAGE, "youtube.com": YOUTUBE_PAGE})
    out = asyncio.run(enricher.run_enricher("torvalds", ["Twitch", "Patreon", "TikTok", "YouTube"]))
    by = {p["platform"]: p for p in out["profiles"]}
    assert out["total"] == 4 and set(by) == {"Twitch", "Patreon", "TikTok", "YouTube"}
    for platform in ("Twitch", "Patreon", "TikTok"):
        assert by[platform]["bio"] == "" and by[platform]["bio_boilerplate"] is True, platform
        assert by[platform]["display_name"]                 # the name read from the page is kept
    assert by["YouTube"]["bio"] == "Homelab and wardriving videos."
    assert "bio_boilerplate" not in by["YouTube"]


def test_enricher_reads_the_tiktok_bio_the_person_wrote(monkeypatch):
    page = TIKTOK_PAGE.replace('"signature":""', '"signature":"kernel things\\nno DMs"')
    _fake_pages(monkeypatch, enricher, {"tiktok.com": page})
    out = asyncio.run(enricher.run_enricher("torvalds", ["TikTok"]))
    assert out["profiles"][0]["bio"] == "kernel things no DMs"
    assert "bio_boilerplate" not in out["profiles"][0]


def test_profile_scraper_drops_boilerplate():
    data = profile_scraper._scrape_profile(TWITCH_PAGE.replace('">', '" />'), "https://www.twitch.tv/torvalds", site="Twitch")
    assert data["bio"] == "" and data["bio_boilerplate"] is True
    real = profile_scraper._scrape_profile('<meta property="og:title" content="RCL - Dailymotion" /><meta property="og:description" content="linux env" />', "https://www.dailymotion.com/torvalds", site="DailyMotion")
    assert real["bio"] == "linux env" and "bio_boilerplate" not in real


def test_maigret_profiles_drop_boilerplate_bios():
    fb = maigret_mod.profile_signal({"uid": "1", "fullname": "Patrick Torvalds", "bio": AUDIT[3][2]}, site="Facebook", username="torvalds")
    assert "bio" not in fb and fb["bio_boilerplate"] is True and fb["name"] == "Patrick Torvalds"
    snap = maigret_mod.profile_signal({"username": "torvalds", "name": "Linus Torvalds", "bio": AUDIT[4][2]})
    assert "bio" not in snap and snap["bio_boilerplate"] is True
    real = maigret_mod.profile_signal({"uid": "1", "name": "RCL", "bio": "linux env"}, site="DailyMotion", username="torvalds")
    assert real["bio"] == "linux env" and "bio_boilerplate" not in real
