"""Link verifier. Pages come from tests/fixtures/links through a mock transport: no network."""

import asyncio
import gzip
import json
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import netguard as ng
from main import app
import middleware.rate_limit as rl
from middleware.rate_limit import match_limit
from modules import link_verify as lv

FIXTURES = Path(__file__).parent / "fixtures" / "links"
PUBLIC_IP = "93.184.216.34"
NOBODY = "qzx7vk2mwp9rtb4ynh6jds3lfg8cae"       # the random 30-character handle the fixtures were recorded with
PHRASES = set(lv.EVIDENCE.values())


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


TEST_SITES = {"example.org", "example.net", "example.com"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    lv.clear_cache_for_tests()
    # The verifier only opens links on sites its tools know. The reserved example domains
    # stand in for such a site in these tests.
    monkeypatch.setattr(lv, "KNOWN_SITES", lv.KNOWN_SITES | TEST_SITES)
    yield
    lv.clear_cache_for_tests()


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


def serve(monkeypatch, routes: dict, calls: list | None = None, dns: dict | None = None):
    """routes: "host/path" -> (status, body) | (status, body, headers) | httpx.Response | callable(request).

    A redirect is (301, "", {"location": ...}). Every name resolves to a public address unless
    `dns` says otherwise, so the guard runs for real and nothing leaves the machine.
    """
    table = dns or {}

    async def getaddrinfo(self, host, port, **kw):
        ips = table.get(host, [PUBLIC_IP])
        if not ips:
            raise socket.gaierror("nope")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(ng, "_public_dns_blocking", lambda host: [])

    def handler(request: httpx.Request):
        if calls is not None:
            calls.append(request)
        key = request.headers["host"] + request.url.path
        hit = routes.get(key)
        if hit is None:
            return httpx.Response(404, text="nope")
        if callable(hit):
            return hit(request)
        if isinstance(hit, httpx.Response):
            return hit
        status, body, *rest = hit
        return httpx.Response(status, text=body, headers={"content-type": "text/html; charset=utf-8", **(rest[0] if rest else {})})

    monkeypatch.setattr(lv, "_inner_transport", lambda: httpx.MockTransport(handler))


def run(username, links):
    return asyncio.run(lv.run_link_verify(username, links))["results"]


def one(username, url, site="Site"):
    return run(username, [{"id": "a", "site": site, "url": url}])[0]


# ---- the pure classifier, against what the sites really sent --------------------------

RECORDED = [
    # site, handle, requested, status, final url, fixture, headers, state, evidence key
    ("GitHub", "torvalds", "https://www.github.com/torvalds", 200, "https://github.com/torvalds", "github_found.html", {}, "verified", "site_marker"),
    ("GitHub", NOBODY, f"https://www.github.com/{NOBODY}", 404, f"https://github.com/{NOBODY}", "github_404.html", {}, "not_found", "http_404"),
    ("GitLab", "torvalds", "https://gitlab.com/torvalds", 200, "https://gitlab.com/torvalds", "gitlab_found.html", {}, "verified", "site_marker"),
    ("GitLab", NOBODY, f"https://gitlab.com/{NOBODY}", 403, "https://gitlab.com/users/sign_in", "gitlab_challenge.html", {"cf-mitigated": "challenge"}, "blocked", "challenge"),
    ("BitBucket", "torvalds", "https://bitbucket.org/torvalds/", 200, "https://bitbucket.org/torvalds/workspace/repositories/", "bitbucket_found.html", {}, "verified", "site_marker"),
    ("BitBucket", NOBODY, f"https://bitbucket.org/{NOBODY}/", 404, f"https://bitbucket.org/{NOBODY}/", "bitbucket_404.html", {}, "not_found", "http_404"),
    ("Reddit", "spez", "https://www.reddit.com/user/spez", 200, "https://www.reddit.com/user/spez/", "reddit_js_challenge.html", {}, "blocked", "challenge"),
    ("Keybase", "chris", "https://keybase.io/chris", 200, "https://keybase.io/chris", "keybase_found.html", {}, "verified", "site_marker"),
    ("Keybase", NOBODY, f"https://keybase.io/{NOBODY}", 404, f"https://keybase.io/{NOBODY}", "keybase_404.txt", {}, "not_found", "http_404"),
    ("DeviantArt", "spyed", "https://www.deviantart.com/spyed", 403, "https://www.deviantart.com/spyed", "deviantart_403.html", {}, "blocked", "challenge"),
    ("Telegram", "durov", "https://t.me/durov", 200, "https://t.me/durov", "telegram_found.html", {}, "verified", "site_marker"),
    ("Telegram", NOBODY, f"https://t.me/{NOBODY}", 200, f"https://t.me/{NOBODY}", "telegram_unclaimed.html", {}, "not_found", "soft_404"),
    ("Snapchat", "teamsnapchat", "https://www.snapchat.com/add/teamsnapchat", 200, "https://www.snapchat.com/@teamsnapchat", "snapchat_found.html", {}, "verified", "site_marker"),
    ("Snapchat", NOBODY, f"https://www.snapchat.com/add/{NOBODY}", 404, f"https://www.snapchat.com/@{NOBODY}", "snapchat_404.html", {}, "not_found", "http_404"),
    ("CashApp", "cashapp", "https://cash.app/$cashapp", 404, "https://cash.app/$cashapp", "cashapp_404.html", {}, "unknown", "ambiguous_page"),
]


@pytest.mark.parametrize("site,handle,requested,status,final,fixture,headers,state,key", RECORDED,
                         ids=[f"{r[0]}-{r[7]}-{r[8]}" for r in RECORDED])
def test_recorded_pages_land_in_the_right_state(site, handle, requested, status, final, fixture, headers, state, key):
    got = lv.classify(handle, requested, status, final, fx(fixture), headers)
    assert got == {"state": state, "evidence_key": key}


def test_every_state_is_covered_by_at_least_six_real_sites():
    sites = {r[0] for r in RECORDED}
    assert len(sites) >= 6
    assert {r[7] for r in RECORDED} == {"verified", "not_found", "blocked", "unknown"}


def test_a_found_page_for_another_handle_is_not_verified():
    # The same GitHub page, asked about a different handle: nothing on it names that one.
    got = lv.classify("octocat", "https://github.com/octocat", 200, "https://github.com/octocat", fx("github_found.html"))
    assert got["state"] == "unknown"


def test_a_marker_on_a_404_never_verifies():
    # GitHub's 404 page carries the requested handle in its canonical link.
    assert "canonical" in fx("github_404.html") and NOBODY in fx("github_404.html")
    got = lv.classify(NOBODY, f"https://github.com/{NOBODY}", 404, f"https://github.com/{NOBODY}", fx("github_404.html"))
    assert got["state"] == "not_found"


def test_telegram_title_alone_is_not_a_marker():
    # Telegram puts the handle in the title of an unclaimed name too.
    body = fx("telegram_unclaimed.html")
    assert f"@{NOBODY}" in lv.page_fields("", body)["title"]
    assert lv.classify(NOBODY, f"https://t.me/{NOBODY}", 200, f"https://t.me/{NOBODY}", body)["state"] == "not_found"


def test_a_bare_200_is_unknown_never_a_guess():
    page = "<html><head><title>Welcome</title></head><body>hello</body></html>"
    for url in ("https://example.org/u/torvalds", "https://github.com/torvalds", "https://www.instagram.com/torvalds/"):
        assert lv.classify("torvalds", url, 200, url, page)["state"] == "unknown", url


# ---- the generic reading --------------------------------------------------------------

def page(title="", extra=""):
    return f"<html><head><title>{title}</title>{extra}</head><body>x</body></html>"


@pytest.mark.parametrize("title,extra,final,state,key", [
    ("torvalds | Example", "", "https://example.org/u/torvalds", "verified", "page_names_handle"),
    ("torvalds", "", "https://example.org/u/torvalds", "verified", "page_names_handle"),
    ("Linus Torvalds (@torvalds) | Example", "", "https://example.org/u/torvalds", "verified", "page_names_handle"),
    ("Linus Torvalds (torvalds) - Example", "", "https://example.org/u/torvalds", "verified", "page_names_handle"),
    ("Profile", '<meta property="og:title" content="Torvalds (@TORVALDS)">', "https://example.org/u/torvalds", "verified", "page_names_handle"),
    # og:url and canonical are built from the request: never proof
    ("Profile", '<link rel="canonical" href="https://example.org/u/torvalds">', "https://example.org/u/torvalds", "unknown", "no_marker"),
    ("Profile", '<meta property="og:url" content="https://example.org/u/torvalds">', "https://example.org/u/torvalds", "unknown", "no_marker"),
    # the handle somewhere in the title, but not where a handle goes
    ("Posts about torvalds and Linux | Example", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    ("Torvalds Family Bakery | Example", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    # part of a longer name is not the handle
    ("torvalds2 | Example", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    ("linus.torvalds | Example", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    ("Linus (@torvalds99) | Example", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    # the title names it but the address no longer does
    ("torvalds | Example", "", "https://example.org/people/9912", "unknown", "moved"),
    # an error or search page that echoes the handle
    ("Search results for @torvalds", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    ("User @torvalds does not exist", "", "https://example.org/u/torvalds", "unknown", "no_marker"),
    # a title that reads like a no-such-user page is a hint, never a verdict
    ("User not found | Example", "", "https://example.org/u/torvalds", "unknown", "unconfirmed_soft_404"),
    ("404 Not Found", "", "https://example.org/u/torvalds", "unknown", "unconfirmed_soft_404"),
    ("Sign in | Example", "", "https://example.org/u/torvalds", "blocked", "login_wall"),
])
def test_generic_markers(title, extra, final, state, key):
    got = lv.classify("torvalds", "https://example.org/u/torvalds", 200, final, page(title, extra))
    assert got == {"state": state, "evidence_key": key}


# ---- review item 1: the generic reading must not verify a page that proves nothing ----

def test_canonical_echo_on_an_error_page_is_not_verified():
    body = ('<html><head><title>ExampleSite</title><link rel="canonical" href="https://example.com/users/ghost">'
            '<meta property="og:url" content="https://example.com/users/ghost"></head>'
            "<body><h1>This user does not exist</h1></body></html>")
    got = lv.classify("ghost", "https://example.com/users/ghost", 200, "https://example.com/users/ghost", body)
    assert got["state"] == "unknown"


@pytest.mark.parametrize("handle,url,title,site", [
    ("flickr", "https://www.flickr.com/people/flickr", "Flickr", "Flickr"),               # the site's own name
    ("example", "https://example.org/u/example", "Example | Home", ""),                   # a label of its domain
    ("forum", "https://example.org/u/forum", "Forum | Example", "Forum"),                 # the name the caller gave the site
    ("user", "https://example.org/u/user", "User profile | Forum", ""),                   # stoplist
    ("user", "https://example.org/u/user", "user | Forum", ""),
    ("profile", "https://example.org/profile", "Profile (profile) | Example", ""),
    ("admin", "https://example.org/u/admin", "admin | Example", ""),
    ("null", "https://example.org/u/null", "null", ""),
    ("john", "https://example.org/u/john", "John Smith (@johnsmith99) | Example", ""),    # another person's first name
    ("john", "https://example.org/u/john", "John Smith | Example", ""),
    ("ab", "https://example.org/u/ab", "ab | Example", ""),                               # shorter than three characters
])
def test_generic_reading_refuses_handles_and_titles_that_prove_nothing(handle, url, title, site):
    got = lv.classify(handle, url, 200, url, page(title), site=site)
    assert got["state"] == "unknown", (handle, title)


def test_a_site_marker_still_verifies_a_stoplist_handle():
    # github.com/user is a real account; GitHub's own profile:username tag names it.
    body = page("user (User) · GitHub", '<meta property="profile:username" content="user">')
    assert lv.classify("user", "https://github.com/user", 200, "https://github.com/user", body)["state"] == "verified"


def test_no_rule_reads_a_tag_the_site_builds_from_the_request():
    for rule in lv.RULES:
        for key in ("found", "not_found", "looks_absent", "wall"):
            for field, _pattern in rule.get(key, []):
                assert field in lv._RULE_FIELDS and field not in ("og:url", "canonical"), rule["name"]
    assert "og:url" not in lv.page_fields("", "") and "canonical" not in lv.page_fields("", "")
    # the sites whose only marker was og:url or canonical now have none, so they cannot verify
    for host, handle, url in [("medium.com", "torvalds", "https://medium.com/@torvalds"),
                              ("patreon.com", "torvalds", "https://www.patreon.com/torvalds"),
                              ("kick.com", "torvalds", "https://kick.com/torvalds"),
                              ("vk.com", "torvalds", "https://vk.com/torvalds"),
                              ("tumblr.com", "torvalds", "https://www.tumblr.com/torvalds"),
                              ("hackerone.com", "torvalds", "https://hackerone.com/torvalds"),
                              ("launchpad.net", "torvalds", "https://launchpad.net/~torvalds"),
                              ("substack.com", "torvalds", "https://torvalds.substack.com/"),
                              ("livejournal.com", "torvalds", "https://torvalds.livejournal.com")]:
        body = page("A Site", f'<meta property="og:url" content="{url}"><link rel="canonical" href="{url}">')
        assert lv.classify(handle, url, 200, url, body)["state"] == "unknown", host


@pytest.mark.parametrize("status,state,key", [
    (404, "not_found", "http_404"), (410, "not_found", "http_410"),
    (401, "blocked", "refused"), (403, "blocked", "refused"), (429, "blocked", "refused"), (999, "blocked", "refused"),
    (500, "unknown", "http_error"), (503, "unknown", "http_error"), (400, "unknown", "http_error"),
])
def test_status_codes(status, state, key):
    got = lv.classify("torvalds", "https://example.org/u/torvalds", status, "https://example.org/u/torvalds", page("torvalds"))
    assert got == {"state": state, "evidence_key": key}


@pytest.mark.parametrize("final,state,key", [
    # a members-only site sends visitors home, and /error can be a rate limit: none is "not found"
    ("https://example.org/", "unknown", "to_homepage"),
    ("https://www.example.org", "unknown", "to_homepage"),
    ("https://example.org/404", "unknown", "to_not_found"),
    ("https://example.org/error?code=429", "unknown", "to_not_found"),
    ("https://example.org/missing", "unknown", "to_not_found"),
    ("https://example.org/errors/not-found?from=torvalds", "unknown", "to_not_found"),
    ("https://example.org/search?q=torvalds", "unknown", "to_search"),
    ("https://example.org/login?next=/u/torvalds", "blocked", "to_login"),
    ("https://example.org/users/sign_in", "blocked", "to_login"),
    ("https://example.org/signup", "blocked", "to_login"),
    ("https://accounts.example.net/o/authorize", "blocked", "to_login"),
    ("https://other.example.net/u/torvalds", "unknown", "off_site"),
])
def test_where_a_redirect_ends_decides(final, state, key):
    # The page names the handle everywhere, and it still must not be verified.
    body = page("torvalds", '<link rel="canonical" href="https://example.org/u/torvalds">')
    got = lv.classify("torvalds", "https://example.org/u/torvalds", 200, final, body)
    assert got == {"state": state, "evidence_key": key}


# ---- review item 2: not_found only from 404, 410 or a recorded rule -------------------

def fixture_backed(field: str, pattern: str) -> bool:
    """Does a recorded page in tests/fixtures/links show this marker for the handle it was recorded with?"""
    for path in FIXTURES.iterdir():
        fields = lv.page_fields("", path.read_text(encoding="utf-8"))
        if lv.re.search(pattern.replace("{u}", lv.re.escape(NOBODY)), fields.get(field, ""), lv.re.I):
            return True
    return False


def test_only_recorded_rules_can_conclude_not_found():
    able = []
    for rule in lv.RULES:
        if rule.get("not_found"):
            assert rule["src"] == "recorded", rule["name"]
            for field, pattern in rule["not_found"]:
                assert field in ("title", "og:title", "twitter:title"), rule["name"]     # never page text
                assert fixture_backed(field, pattern), (rule["name"], pattern)
            able.append(rule["name"])
    assert sorted(able) == lv.rule_counts()["can_conclude_not_found"] == ["BitBucket", "Telegram"]


def satisfy(pattern: str, handle: str) -> str:
    """Text that one of the (simple) looks_absent patterns matches, to build a page that trips it."""
    text = pattern.replace("{u}", handle)
    for old, new in (("(?:’|')", "'"), ("(?:www\\.)?", ""), ("https?", "https"), ("(?:\\?|$)", ""), ("/?\\?", "?"),
                     ("/?", ""), ("<h\\d[^>]*>", "<h1>"), ("</h\\d>", "</h1>")):
        text = text.replace(old, new)
    return lv.re.sub(r"\\(.)", r"\1", text.strip("^$"))


def test_every_unrecorded_rule_is_enumerated_and_none_returns_not_found():
    checked = 0
    # hand-written rules: trip each looks_absent marker, with HTTP 200, with and without a redirect
    for rule in lv.RULES:
        host = rule["hosts"][0]
        url = f"https://{host}/ghostuser"
        for field, pattern in rule.get("looks_absent", []):
            text = satisfy(pattern, "ghostuser")
            assert lv.re.search(pattern.replace("{u}", "ghostuser"), text, lv.re.I), (rule["name"], pattern, text)
            if field == "redirected_to":
                got = lv.classify("ghostuser", url, 200, text, page("Home"))
            elif field == "title":
                got = lv.classify("ghostuser", url, 200, url, f"<html><head><title>{text}</title></head><body></body></html>")
            else:
                got = lv.classify("ghostuser", url, 200, url, f"<html><head><title>Site</title>{text}</head><body>{text}</body></html>")
            assert got == {"state": "unknown", "evidence_key": "unconfirmed_soft_404"}, (rule["name"], pattern, got)
            checked += 1
        if rule["src"] != "recorded":
            assert not rule.get("not_found"), rule["name"]
    # Sherlock's phrases: every one, on the URL its own template describes
    for reg, rules in lv.SHERLOCK_RULES.items():
        for rule in rules:
            for phrase in rule["phrases"]:
                url = "https://" + rule["match"].pattern.strip("^$").replace("[^/?#&=]+", "ghostuser").replace("\\", "")
                body = f"<html><head><title>Site</title></head><body>{phrase}</body></html>"
                got = lv.classify("ghostuser", url, 200, url, body)
                assert got["state"] != "not_found", (rule["name"], phrase)
                checked += 1
    assert checked > 100


@pytest.mark.parametrize("url,final,title,body_text", [
    # a Ko-fi page whose name starts with "art", fetched with no redirect at all
    ("https://ko-fi.com/art-by-jane", "https://ko-fi.com/art-by-jane", "Art by Jane (@art-by-jane)", ""),
    ("https://ko-fi.com/artbyjane", "https://ko-fi.com/artbyjane", "Buy artbyjane a Coffee", "Make income from your art!"),
    # user text on a real profile that happens to quote a no-such-user phrase
    ("https://www.deviantart.com/jane-doe", "https://www.deviantart.com/jane-doe", "jane-doe - Hobbyist | DeviantArt", "My favourite error page: Llama Not Found"),
    ("https://steamcommunity.com/id/jane-doe/", "https://steamcommunity.com/id/jane-doe/", "Steam Community :: Jane", "bio: The specified profile could not be found"),
    ("https://pastebin.com/u/jane-doe", "https://pastebin.com/u/jane-doe", "jane-doe's Pastebin - Pastebin.com", "Not Found (#404)"),
    ("https://dribbble.com/jane-doe", "https://dribbble.com/jane-doe", "Jane Doe (@jane-doe) | Dribbble", "Whoops, that page is gone."),
    ("https://www.codecademy.com/profiles/jane-doe", "https://www.codecademy.com/profiles/jane-doe", "jane-doe | Codecademy", "This profile could not be found"),
    ("https://letterboxd.com/jane-doe", "https://letterboxd.com/jane-doe/", "Jane (@jane-doe) | Letterboxd", "Sorry, we can’t find the page you’ve requested."),
])
def test_user_text_and_lookalike_urls_never_make_a_real_profile_not_found(url, final, title, body_text):
    handle = url.rstrip("/").split("/")[-1]
    filler = "<p>" + "x" * (lv.HEAD_BYTES + 100) + "</p>"          # user content sits well below the page head
    body = f"<html><head><title>{title}</title></head><body>{filler}<p>{body_text}</p></body></html>"
    got = lv.classify(handle, url, 200, final, body)
    assert got["state"] != "not_found", got


def test_a_positive_marker_wins_over_an_unrecorded_phrase():
    # Even at the top of the page, an unrecorded phrase cannot outvote the site's own marker.
    body = '<html><head><title>jane-doe\'s Pastebin - Pastebin.com</title></head><body>Not Found (#404)</body></html>'
    got = lv.classify("jane-doe", "https://pastebin.com/u/jane-doe", 200, "https://pastebin.com/u/jane-doe", body)
    assert got == {"state": "verified", "evidence_key": "site_marker"}


@pytest.mark.parametrize("title", ["404 Games (@404games) - Example", "User Not Found (@unf) | Example"])
def test_a_soft_404_looking_title_never_concludes(title):
    handle = lv.re.search(r"@(\w+)", title).group(1)
    got = lv.classify(handle, f"https://example.org/u/{handle}", 200, f"https://example.org/u/{handle}", page(title))
    assert got["state"] != "not_found"


def test_sherlock_redirect_data_no_longer_concludes():
    # Codechef's errorUrl in Sherlock's data is the bare host. A redirect to another profile
    # page on that host used to match it by prefix.
    for final in ("https://www.codechef.com/users/torvalds_1", "https://www.codechef.com/", "https://www.codechef.com/users/torvalds/"):
        got = lv.classify("torvalds", "https://www.codechef.com/users/torvalds", 200, final, page("CodeChef"))
        assert got["state"] != "not_found", final
    assert all("error_url" not in r for rules in lv.SHERLOCK_RULES.values() for r in rules)


def test_recorded_no_such_user_pages_still_conclude():
    got = lv.classify(NOBODY, f"https://t.me/{NOBODY}", 200, f"https://t.me/{NOBODY}", fx("telegram_unclaimed.html"))
    assert got == {"state": "not_found", "evidence_key": "soft_404"}
    assert lv.classify("anyone", "https://example.org/u/anyone", 404, "https://example.org/u/anyone", "")["state"] == "not_found"
    assert lv.classify("anyone", "https://example.org/u/anyone", 410, "https://example.org/u/anyone", "")["state"] == "not_found"


@pytest.mark.parametrize("body,headers", [
    ("<html><head><title>Just a moment...</title></head><body></body></html>", {}),
    ("<html><head><title>Attention Required! | Cloudflare</title></head></html>", {}),
    (page("torvalds"), {"cf-mitigated": "challenge"}),
    ("<html><head><title>example.org</title></head><body><script src='https://geo.captcha-delivery.com/c.js'></script></body></html>", {}),
])
@pytest.mark.parametrize("status", [200, 403, 503])
def test_a_bot_check_is_blocked_whatever_the_status(body, headers, status):
    got = lv.classify("torvalds", "https://example.org/u/torvalds", status, "https://example.org/u/torvalds", body, headers)
    assert got == {"state": "blocked", "evidence_key": "challenge"}


def test_subdomain_profiles():
    url = "https://torvalds.substack.com/"
    assert lv.has_public_profile_url("Substack", url, "torvalds") is True
    ok = lv.classify("torvalds", url, 200, url, page("torvalds | Substack"))
    assert ok == {"state": "verified", "evidence_key": "page_names_handle"}
    gone = lv.classify("torvalds", url, 200, "https://substack.com/", page("Substack"))
    assert gone == {"state": "unknown", "evidence_key": "to_homepage"}
    typo = lv.classify("torvalds", "https://torvalds.wordpress.com/", 200, "https://wordpress.com/typo/?subdomain=torvalds", page("WordPress.com"))
    assert typo == {"state": "unknown", "evidence_key": "unconfirmed_soft_404"}


def test_platform_check_rules_are_reused_and_their_not_found_is_not_trusted():
    plat = Path(__file__).parent / "fixtures" / "platform"
    found = lv.classify("torvalds", "https://www.instagram.com/torvalds/", 200, "https://www.instagram.com/torvalds/",
                        (plat / "instagram_found.html").read_text(encoding="utf-8"))
    assert found == {"state": "verified", "evidence_key": "site_marker"}
    # Instagram serves this page for real profiles too when it dislikes the request, and
    # this module has no canary request to tell the two apart.
    missing = lv.classify("nobody", "https://www.instagram.com/nobody/", 200, "https://www.instagram.com/nobody/",
                          (plat / "instagram_error_page.html").read_text(encoding="utf-8"))
    assert missing == {"state": "unknown", "evidence_key": "ambiguous_page"}
    wall = lv.classify("zuck", "https://www.threads.net/@zuck", 200, "https://www.threads.com/login",
                       (plat / "threads_login_wall.html").read_text(encoding="utf-8"))
    assert wall["state"] == "blocked"
    li = lv.classify("someone", "https://www.linkedin.com/in/someone", 999, "https://www.linkedin.com/in/someone",
                     (plat / "linkedin_999.html").read_text(encoding="utf-8"))
    assert li == {"state": "blocked", "evidence_key": "refused"}


# ---- rule sources ---------------------------------------------------------------------

def test_rule_table_covers_the_sites_that_matter():
    counts = lv.rule_counts()
    assert counts["hand_written"] + counts["platform_check"] >= 40
    assert counts["sherlock"] >= 60
    for rule in lv.RULES:
        assert rule["hosts"] and rule["src"] in ("recorded", "sherlock", "maigret", "known"), rule["name"]
        assert rule.get("found") or rule.get("not_found") or rule.get("looks_absent") or rule.get("wall") or rule.get("walled"), rule["name"]
        for key in ("found", "not_found", "looks_absent", "wall"):
            for _field, pattern in rule.get(key, []):
                lv.re.compile(pattern.replace("{u}", "x"))
        # every positive marker names the handle: none can fire for the wrong account
        for _field, pattern in rule.get("found", []):
            assert "{u}" in pattern, rule["name"]
        assert all(registrable in lv.KNOWN_SITES for registrable in map(lv.registrable_domain, rule["hosts"]))


def test_sherlock_data_is_the_fallback_for_sites_without_a_hand_rule():
    # Letterboxd has no hand-written rule; Sherlock's data says what its missing-user page says.
    assert lv._hand_rule("letterboxd.com") is None
    rule = lv._sherlock_rule("https://letterboxd.com/torvalds")
    assert rule and rule["phrases"]
    body = page("Letterboxd", "") + "<p>" + rule["phrases"][0] + "</p>"
    # nobody recorded that page here, so the phrase is a hint and the state stays unknown
    got = lv.classify("torvalds", "https://letterboxd.com/torvalds", 200, "https://letterboxd.com/torvalds/", body)
    assert got == {"state": "unknown", "evidence_key": "unconfirmed_soft_404"}
    # the same body on a site Sherlock has no phrase for is just a page with no marker
    assert lv.classify("torvalds", "https://example.org/torvalds", 200, "https://example.org/torvalds", body) == {"state": "unknown", "evidence_key": "no_marker"}
    # and without the phrase the generic reading still applies
    ok = lv.classify("torvalds", "https://letterboxd.com/torvalds", 200, "https://letterboxd.com/torvalds/", page("Linus (@torvalds) | Letterboxd"))
    assert ok == {"state": "verified", "evidence_key": "page_names_handle"}


def test_sherlock_loader_keeps_only_rules_about_the_public_page(tmp_path):
    data = {
        "$schema": "x",
        "Probe": {"errorType": "message", "errorMsg": "no such user here", "url": "https://probe.example/{}", "urlProbe": "https://api.probe.example/{}"},
        "Post": {"errorType": "message", "errorMsg": "no such user here", "url": "https://post.example/{}", "request_method": "POST"},
        "Short": {"errorType": "message", "errorMsg": ["404", "Error!"], "url": "https://short.example/{}"},
        "Status": {"errorType": "status_code", "url": "https://status.example/{}", "urlMain": "https://status.example/"},
        "Good": {"errorType": "message", "errorMsg": ["404", "This user does not exist"], "url": "https://www.good.example/u/{}/"},
        "Redirect": {"errorType": "response_url", "errorUrl": "https://redir.example/", "url": "https://redir.example/{}"},
    }
    path = tmp_path / "data.json"
    path.write_text(json.dumps(data))
    rules = lv.load_sherlock_rules(str(path))
    assert set(rules) == {"good.example"}
    assert rules["good.example"][0]["phrases"] == ["This user does not exist"]
    assert rules["good.example"][0]["match"].match("good.example/u/someone")
    assert not rules["good.example"][0]["match"].match("good.example/groups/someone")
    assert lv.load_sherlock_rules(str(tmp_path / "missing.json")) == {}


# ---- sites with nothing to open -------------------------------------------------------

@pytest.mark.parametrize("site,url,expected", [
    ("Discord", "https://discord.com", False),
    ("Discord", "https://discord.com/", False),
    ("Discord", "https://discord.com/users/torvalds", False),
    ("anything", "https://discord.com/invite/abc", False),
    ("WhatsApp", "https://wa.me/torvalds", False),
    ("Signal", "https://signal.me/#u/torvalds", False),
    ("Signal", "https://community.signalusers.org/u/torvalds", True),
    ("Skype", "https://web.skype.com/torvalds", False),
    ("CashApp", "https://cash.app/$Err0ric", True),
    ("CashApp", "https://cash.app/Err0ric", False),
    ("CashApp", "https://cash.me/Err0ric", False),
    ("Snapchat", "https://www.snapchat.com/add/torvalds", True),
    ("Telegram", "https://t.me/torvalds", True),
    ("Example", "https://example.org", False),
    ("Example", "https://example.org/", False),
    ("Example", "https://example.org/?u=torvalds", True),
    ("WordPress", "https://torvalds.wordpress.com/", True),
    ("WordPress", "https://someoneelse.wordpress.com/", False),
    ("GitHub", "https://www.github.com/torvalds", True),
])
def test_has_public_profile_url(site, url, expected):
    assert lv.has_public_profile_url(site, url, "torvalds") is expected


# ---- review item 5: a host label is the handle only in front of the site's own name ----

@pytest.mark.parametrize("handle,url", [
    ("reddit", "https://www.reddit.com/"), ("reddit", "https://reddit.com"), ("www", "https://www.reddit.com/"),
    ("com", "https://www.reddit.com/"), ("co", "https://www.example.co.uk/"), ("example", "https://shop.example.co.uk/"),
    ("substack", "https://substack.com/"), ("www", "https://www.torvalds.substack.com/"),
])
def test_the_sites_own_name_is_not_a_profile_subdomain(handle, url):
    assert lv.has_public_profile_url("Site", url, handle) is False
    assert lv._is_homepage(url, handle) is True and lv._names_handle(url, handle) is False


def test_a_real_subdomain_handle_still_counts():
    assert lv.has_public_profile_url("Site", "https://shop.example.co.uk/", "shop") is True
    assert lv.has_public_profile_url("Site", "https://www.torvalds.substack.com/", "torvalds") is True
    assert lv.has_public_profile_url("Site", "https://torvalds.substack.com/") is False        # no handle given, nothing to match


def test_hints():
    assert lv.how_to_check("Discord") == "Discord has no public profile page. Search the handle inside the app or ask for the numeric user ID."
    for site in ("Discord", "WhatsApp", "Signal", "Skype", "CashApp", "Somewhere"):
        hint = lv.how_to_check(site)
        assert hint and chr(0x2014) not in hint and len(hint) < 160


def test_nothing_to_open_makes_no_request(monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls)
    rows = run("torvalds", [
        {"id": "acct:discord", "site": "Discord", "url": "https://discord.com"},
        {"id": "acct:home", "site": "Example", "url": "https://example.org/"},
        {"id": "acct:cash", "site": "CashApp", "url": "https://cash.app/torvalds"},
    ])
    assert calls == []
    assert [r["state"] for r in rows] == ["no_public_url"] * 3
    assert rows[0]["hint"].startswith("Discord has no public profile page.")
    assert rows[0]["evidence"] == lv.EVIDENCE["no_profile_page"]
    assert rows[1]["hint"] == lv.DEFAULT_HINT and rows[1]["evidence"] == lv.EVIDENCE["homepage_link"]
    assert rows[2]["hint"].startswith("Cash App")
    assert all(r["final_url"] == "" and r["cached"] is False for r in rows)


# ---- end to end through the guard and the mock transport ------------------------------

def test_contract_shape_and_every_state(monkeypatch):
    calls = []
    serve(monkeypatch, {
        "www.github.com/torvalds": (301, "", {"location": "https://github.com/torvalds"}),
        "github.com/torvalds": (200, fx("github_found.html")),
        "bitbucket.org/torvalds/": (302, "", {"location": "/torvalds/workspace/repositories/"}),
        "bitbucket.org/torvalds/workspace/repositories/": (200, fx("bitbucket_found.html")),
        "keybase.io/torvalds": (404, fx("keybase_404.txt")),
        "www.deviantart.com/torvalds": (403, fx("deviantart_403.html")),
        "example.org/u/torvalds": (200, page("Welcome")),
    }, calls)
    rows = run("torvalds", [
        {"id": "acct:github", "site": "GitHub", "url": "https://www.github.com/torvalds"},
        {"id": "acct:bitbucket", "site": "BitBucket", "url": "https://bitbucket.org/torvalds/"},
        {"id": "acct:keybase", "site": "Keybase", "url": "https://keybase.io/torvalds"},
        {"id": "acct:deviantart", "site": "DeviantArt", "url": "https://www.deviantart.com/torvalds"},
        {"id": "acct:example", "site": "Example", "url": "https://example.org/u/torvalds"},
        {"id": "acct:discord", "site": "Discord", "url": "https://discord.com"},
    ])
    assert [r["id"] for r in rows] == ["acct:github", "acct:bitbucket", "acct:keybase", "acct:deviantart", "acct:example", "acct:discord"]
    assert [r["state"] for r in rows] == ["verified", "verified", "not_found", "blocked", "unknown", "no_public_url"]
    assert rows[0]["final_url"] == "https://github.com/torvalds"
    assert rows[1]["final_url"] == "https://bitbucket.org/torvalds/workspace/repositories/"
    assert all(r["final_url"] == "" for r in rows[2:])
    for r in rows:
        assert set(r) - {"hint", "error_code"} == {"id", "state", "final_url", "evidence", "cached"}
        assert r["evidence"] in PHRASES and r["cached"] is False
    assert all(q.method == "GET" for q in calls)


def test_every_request_is_a_guarded_get_with_navigation_headers(monkeypatch):
    calls = []
    serve(monkeypatch, {"example.org/u/torvalds": (200, page("torvalds"))}, calls)
    assert one("torvalds", "https://example.org/u/torvalds")["state"] == "verified"
    (req,) = calls
    assert req.method == "GET" and req.url.host == PUBLIC_IP          # pinned to the vetted address
    assert req.headers["host"] == "example.org"
    assert req.headers["sec-fetch-mode"] == "navigate" and "Mozilla/5.0" in req.headers["user-agent"]
    assert req.headers["accept-encoding"] == "gzip"


def test_homepage_redirect_is_unknown_not_a_verdict(monkeypatch):
    serve(monkeypatch, {
        "example.org/u/torvalds": (302, "", {"location": "https://example.org/"}),
        "example.org/": (200, page("torvalds | Example")),
    })
    row = one("torvalds", "https://example.org/u/torvalds")
    assert (row["state"], row["evidence"], row["final_url"]) == ("unknown", lv.EVIDENCE["to_homepage"], "")


def test_login_redirect_is_blocked(monkeypatch):
    serve(monkeypatch, {
        "example.org/u/torvalds": (302, "", {"location": "/login?next=%2Fu%2Ftorvalds"}),
        "example.org/login": (200, page("torvalds")),
    })
    row = one("torvalds", "https://example.org/u/torvalds")
    assert (row["state"], row["evidence"]) == ("blocked", lv.EVIDENCE["to_login"])


def test_cloudflare_challenge_is_blocked(monkeypatch):
    serve(monkeypatch, {f"gitlab.com/{NOBODY}": (302, "", {"location": "https://gitlab.com/users/sign_in"}),
                        "gitlab.com/users/sign_in": (403, fx("gitlab_challenge.html"), {"cf-mitigated": "challenge"})})
    row = one(NOBODY, f"https://gitlab.com/{NOBODY}", "GitLab")
    assert (row["state"], row["evidence"]) == ("blocked", lv.EVIDENCE["challenge"])


def test_private_addresses_are_refused_before_any_request(monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls, dns={"rebind.example.org": ["10.0.0.5"], "mixed.example.org": [PUBLIC_IP, "127.0.0.1"]})
    # a known site whose name resolves to a private address: the guard refuses it
    rows = run("torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "https://rebind.example.org/torvalds", "https://mixed.example.org/torvalds",
    ])])
    for r in rows:
        assert (r["state"], r["evidence"], r["error_code"]) == ("unknown", lv.EVIDENCE["blocked_target"], "blocked_target")
    # literal and internal addresses are not sites the tools know, so they never reach the guard
    rows = run("torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "http://127.0.0.1/u/torvalds", "http://169.254.169.254/latest/torvalds", "http://[::1]/torvalds",
        "http://localhost/torvalds", "https://db.railway.internal/torvalds", "http://10.0.0.5/torvalds",
    ])])
    assert all((r["state"], r["evidence"]) == ("unknown", lv.EVIDENCE["unknown_site"]) for r in rows)
    assert calls == []
    # and with the allowlist out of the way the guard still refuses each of them
    monkeypatch.setattr(lv, "KNOWN_SITES", lv.KNOWN_SITES | {"127.0.0.1", "169.254.169.254", "10.0.0.5", "railway.internal"})
    rows = run("torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "http://127.0.0.1/u/torvalds", "http://169.254.169.254/latest/torvalds", "https://db.railway.internal/torvalds", "http://10.0.0.5/torvalds",
    ])])
    assert all(r["error_code"] == "blocked_target" for r in rows) and calls == []


def test_a_redirect_to_a_private_address_is_refused(monkeypatch):
    calls = []
    serve(monkeypatch, {"example.org/u/torvalds": (302, "", {"location": "http://169.254.169.254/latest/meta-data/"})}, calls)
    row = one("torvalds", "https://example.org/u/torvalds")
    assert (row["state"], row["error_code"]) == ("unknown", "blocked_target")
    assert len(calls) == 1


def test_redirects_are_limited(monkeypatch):
    calls = []
    serve(monkeypatch, {"example.org/u/torvalds": (302, "", {"location": "/u/torvalds"})}, calls)
    row = one("torvalds", "https://example.org/u/torvalds")
    assert (row["state"], row["evidence"]) == ("unknown", lv.EVIDENCE["redirect_loop"])
    assert len(calls) == lv.MAX_REDIRECTS + 1


def test_body_cap_is_honoured(monkeypatch):
    pulled = []

    class Endless(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"<html><head></head><body>"
            while True:
                pulled.append(1)
                yield b"x" * 10_000

    monkeypatch.setattr(lv, "MAX_BODY", 50_000)
    marker = b"<title>torvalds</title>"
    serve(monkeypatch, {
        "example.org/endless": lambda req: httpx.Response(200, stream=Endless(), headers={"content-type": "text/html"}),
        # a marker beyond the cap is never read
        "example.org/u/torvalds": lambda req: httpx.Response(200, content=b"<html>" + b" " * 60_000 + marker, headers={"content-type": "text/html"}),
    })
    row = one("torvalds", "https://example.org/endless")
    assert row["state"] == "unknown"
    assert len(pulled) <= 6                                   # stopped at the cap, not when the server did
    assert one("torvalds", "https://example.org/u/torvalds")["state"] == "unknown"


def test_gzip_is_decompressed_under_the_same_cap(monkeypatch):
    monkeypatch.setattr(lv, "MAX_BODY", 50_000)
    small = gzip.compress(page("torvalds | Example").encode())
    bomb = gzip.compress(b"<html><body>" + b"A" * 20_000_000)        # about 20 KB on the wire
    assert len(bomb) < lv.MAX_BODY
    seen = {}

    async def spy_fetch(client, url):
        got = await real_fetch(client, url)
        seen[url] = len(got[2])
        return got

    real_fetch = lv._fetch
    monkeypatch.setattr(lv, "_fetch", spy_fetch)
    gz = {"content-type": "text/html", "content-encoding": "gzip"}
    serve(monkeypatch, {
        "example.org/u/torvalds": lambda req: httpx.Response(200, content=small, headers=gz),
        "example.org/bomb/torvalds": lambda req: httpx.Response(200, content=bomb, headers=gz),
        "example.org/br/torvalds": lambda req: httpx.Response(200, content=b"\x8b\x00\x80junk", headers={"content-type": "text/html", "content-encoding": "br"}),
    })
    assert one("torvalds", "https://example.org/u/torvalds")["state"] == "verified"
    assert one("torvalds", "https://example.org/bomb/torvalds")["state"] == "unknown"
    assert seen["https://example.org/bomb/torvalds"] <= 50_000
    row = one("torvalds", "https://example.org/br/torvalds")
    assert (row["state"], row["evidence"]) == ("unknown", lv.EVIDENCE["unreadable"])


def test_network_failures_are_unknown_with_a_code_and_no_exception_text(monkeypatch):
    def boom(exc):
        def raiser(request):
            raise exc
        return raiser

    serve(monkeypatch, {
        "slow.example.org/torvalds": boom(httpx.ReadTimeout("secret-url-in-message")),
        "down.example.org/torvalds": boom(httpx.ConnectError("connection refused to secret-host")),
    }, dns={"gone.example.org": []})
    real_sleep = asyncio.sleep
    monkeypatch.setattr(ng.asyncio, "sleep", lambda s: real_sleep(0))     # the guard's one-second DNS retry
    rows = run("torvalds", [
        {"id": "slow", "site": "x", "url": "https://slow.example.org/torvalds"},
        {"id": "down", "site": "x", "url": "https://down.example.org/torvalds"},
        {"id": "gone", "site": "x", "url": "https://gone.example.org/torvalds"},
    ])
    assert [(r["state"], r["error_code"]) for r in rows] == [("unknown", "timeout"), ("unknown", "unreachable"), ("unknown", "dns")]
    assert "secret" not in json.dumps(rows)
    assert all(r["evidence"] in PHRASES for r in rows)


def test_a_slow_site_times_out_without_holding_up_the_rest(monkeypatch):
    monkeypatch.setattr(lv, "TOTAL_TIMEOUT", 0.2)
    real_fetch = lv._fetch

    async def fetch(client, url):
        if "slow" in url:
            await asyncio.sleep(5)
        return await real_fetch(client, url)

    serve(monkeypatch, {"example.org/u/torvalds": (200, page("torvalds"))})
    monkeypatch.setattr(lv, "_fetch", fetch)
    rows = run("torvalds", [{"id": "slow", "site": "x", "url": "https://slow.example.net/torvalds"},
                            {"id": "ok", "site": "x", "url": "https://example.org/u/torvalds"}])
    assert [(r["state"]) for r in rows] == ["unknown", "verified"]
    assert rows[0]["evidence"] == lv.EVIDENCE["timeout"]


def test_cache_hit_and_lifetimes(monkeypatch):
    calls = []
    serve(monkeypatch, {
        "example.org/u/torvalds": (200, page("torvalds")),
        "example.org/blocked/torvalds": (403, "no"),
    }, calls)
    links = [{"id": "a", "site": "x", "url": "https://example.org/u/torvalds"},
             {"id": "b", "site": "x", "url": "https://example.org/blocked/torvalds"},
             {"id": "c", "site": "x", "url": "https://example.org/gone/torvalds"}]
    first = run("torvalds", links)
    assert [r["state"] for r in first] == ["verified", "blocked", "not_found"] and not any(r["cached"] for r in first)
    assert len(calls) == 3
    # scheme and host are case-insensitive, and a fragment is never sent: the same request
    again = run("torvalds", [{"id": "a", "site": "x", "url": "HTTPS://EXAMPLE.org/u/torvalds#top"}, *links[1:]])
    assert len(calls) == 3
    assert all(r["cached"] for r in again)
    assert [{k: v for k, v in r.items() if k != "cached"} for r in again] == [{k: v for k, v in r.items() if k != "cached"} for r in first]
    # the verdict is about the pair: another handle on the same page is another question
    other = run("torv", [{"id": "a", "site": "x", "url": "https://example.org/u/torv/../torvalds"}])[0]
    assert other["cached"] is False
    # blocked and unknown are kept for ten minutes, verified and not_found for a day
    real_time = lv.time.time
    monkeypatch.setattr(lv.time, "time", lambda: real_time() + lv.CACHE_TTL_SOFT + 5)
    later = run("torvalds", links)
    assert [r["cached"] for r in later] == [True, False, True]
    monkeypatch.setattr(lv.time, "time", lambda: real_time() + lv.CACHE_TTL + 5)
    assert not any(r["cached"] for r in run("torvalds", links))


# ---- review item 3: one caller cannot plant a verdict for another URL or handle --------

def test_cache_key_is_the_exact_request_and_the_exact_handle(monkeypatch):
    calls = []
    serve(monkeypatch, {
        # the site is case-sensitive: the uppercase path is a different (missing) page
        "example.org/u/victim": (200, page("victim | Example")),
        "www.example.org/u/victim": (200, page("victim | Example")),
    }, calls)
    planted = [one("Victim", url) for url in ("http://EXAMPLE.org/U/VICTIM/#x", "https://example.org/U/VICTIM", "https://example.org/u/victim/")]
    assert all(r["state"] == "not_found" for r in planted)
    n = len(calls)
    real = one("victim", "https://example.org/u/victim")
    assert (real["state"], real["cached"]) == ("verified", False) and len(calls) == n + 1
    # www, a trailing slash, the scheme, the query and the handle's case are all part of the key
    keys = {lv._cache_key(u, url) for u, url in [
        ("victim", "https://example.org/u/victim"), ("Victim", "https://example.org/u/victim"),
        ("victim", "http://example.org/u/victim"), ("victim", "https://www.example.org/u/victim"),
        ("victim", "https://example.org/u/victim/"), ("victim", "https://example.org/U/victim"),
        ("victim", "https://example.org/u/victim?x=1"), ("victim", "https://example.org/u/victim?X=1"),
    ]}
    assert len(keys) == 8
    assert lv._cache_key("victim", "HTTPS://Example.ORG/u/victim#frag") == lv._cache_key("victim", "https://example.org/u/victim")


def test_the_same_url_twice_is_fetched_once_and_the_cache_is_bounded(monkeypatch):
    calls = []
    serve(monkeypatch, {"example.org/u/torvalds": (200, page("torvalds"))}, calls)
    rows = run("torvalds", [{"id": "a", "site": "x", "url": "https://example.org/u/torvalds"},
                            {"id": "b", "site": "y", "url": "https://example.org/u/torvalds"}])
    assert len(calls) == 1 and [r["id"] for r in rows] == ["a", "b"] and rows[0]["state"] == rows[1]["state"] == "verified"
    monkeypatch.setattr(lv, "CACHE_MAX", 3)
    run("torvalds", [{"id": str(n), "site": "x", "url": f"https://example.org/p{n}/torvalds"} for n in range(8)])
    assert len(lv._cache) == 3


def test_requests_to_one_site_are_spread_out(monkeypatch):
    live = {"now": 0, "peak": 0}
    real_fetch = lv._fetch

    async def fetch(client, url):
        live["now"] += 1
        live["peak"] = max(live["peak"], live["now"])
        await asyncio.sleep(0.01)
        try:
            return await real_fetch(client, url)
        finally:
            live["now"] -= 1

    serve(monkeypatch, {})
    monkeypatch.setattr(lv, "_fetch", fetch)
    run("torvalds", [{"id": str(n), "site": "x", "url": f"https://example.org/p{n}/torvalds"} for n in range(12)])
    assert live["peak"] <= lv.PER_SITE
    live["peak"] = 0
    monkeypatch.setattr(lv, "KNOWN_SITES", lv.KNOWN_SITES | {f"site{n}.example" for n in range(20)})
    run("torvalds", [{"id": str(n), "site": "x", "url": f"https://site{n}.example/torvalds"} for n in range(20)])
    assert lv.PER_SITE < live["peak"] <= lv.CONCURRENCY


# ---- review item 4: not a general fetcher ---------------------------------------------

def test_only_sites_the_tools_know_are_fetched(monkeypatch):
    calls = []
    serve(monkeypatch, {"github.com/torvalds": (200, fx("github_found.html"))}, calls)
    rows = run("torvalds", [
        {"id": "a", "site": "GitHub", "url": "https://attacker-controlled.example.io/torvalds"},
        {"id": "b", "site": "GitHub", "url": "https://intranet-wiki.corp.example.dev/u/torvalds"},
        {"id": "c", "site": "GitHub", "url": "https://93.184.216.34/torvalds"},
        {"id": "d", "site": "GitHub", "url": "https://github.com/torvalds"},
    ])
    assert [r["state"] for r in rows] == ["unknown", "unknown", "unknown", "verified"]
    assert all(r["evidence"] == lv.EVIDENCE["unknown_site"] and r["cached"] is False for r in rows[:3])
    assert [q.headers["host"] for q in calls] == ["github.com"]
    assert lv._cache == {} or all(key[0].startswith("https://github.com/") for key in lv._cache)


def test_the_allowlist_is_built_from_sherlock_maigret_and_platform_check(tmp_path):
    for site in ("github.com", "t.me", "cash.app", "letterboxd.com", "instagram.com", "x.com", "twitter.com",
                 "threads.net", "threads.com", "linkedin.com", "tiktok.com", "facebook.com", "bsky.app"):
        assert site in lv.KNOWN_SITES, site
    for site in ("example.org", "localhost", "127.0.0.1", "railway.internal", "", "com"):
        assert site not in lv.load_known_sites(), site
    assert len(lv.load_known_sites()) > 1000
    sherlock, maigret = tmp_path / "s.json", tmp_path / "m.json"
    sherlock.write_text(json.dumps({"$schema": "x", "A": {"url": "https://www.alpha.example/{}", "urlMain": "https://alpha.example/"}}))
    maigret.write_text(json.dumps({"sites": {
        "B": {"url": "https://{username}.beta.example/", "urlMain": "https://beta.example"},
        "C": {"url": "{urlMain}{urlSubpath}/u/{username}", "urlMain": "https://forum.gamma.example"},
        "D": {"url": "not a url"},
    }}))
    built = lv.load_known_sites(str(sherlock), str(maigret))
    assert {"alpha.example", "beta.example", "gamma.example"} <= built
    assert lv.load_known_sites(str(tmp_path / "none.json"), str(tmp_path / "none.json")) >= {"x.com", "github.com"}


def test_a_link_that_does_not_name_the_handle_is_not_opened(monkeypatch):
    calls = []
    serve(monkeypatch, {"example.org/u/torvalds": (200, page("torvalds"))}, calls)
    rows = run("torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "https://example.org/admin/export", "https://example.org/u/someoneelse", "https://example.org/u/torvalds2",
        "https://example.org/u/xtorvalds", "https://someoneelse.example.org/", "https://example.org/?next=/internal",
    ])])
    assert calls == []
    assert all((r["state"], r["evidence"], r["cached"]) == ("unknown", lv.EVIDENCE["handle_not_in_url"], False) for r in rows[:4] + rows[5:])
    assert rows[4]["state"] == "no_public_url"                       # a bare homepage that is not the handle's subdomain
    ok = run("Torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "https://example.org/u/TORVALDS", "https://torvalds.example.org/", "https://example.org/member.php?username=torvalds",
        "https://example.org/profile/torvalds.bsky.social", "https://example.org/@torvalds", "https://example.org/~torvalds/",
    ])])
    assert len(calls) == 6 and all(r["evidence"] != lv.EVIDENCE["handle_not_in_url"] for r in ok)


def test_ports_and_odd_schemes_are_never_opened(monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls)
    rows = run("torvalds", [{"id": str(n), "site": "x", "url": url} for n, url in enumerate([
        "https://example.org:8443/u/torvalds", "http://example.org:22/torvalds", "https://example.org:443/u/torvalds",
        "http://example.org:80/u/torvalds", "ftp://example.org/torvalds", "https://user:pw@example.org/u/torvalds",
        "https://example.org:notaport/u/torvalds",
    ])])
    assert calls == []
    assert all((r["state"], r["evidence"]) == ("unknown", lv.EVIDENCE["bad_link"]) for r in rows)


def test_one_site_gets_a_bounded_number_of_requests_per_minute_across_calls(monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls)
    monkeypatch.setattr(lv, "SITE_RATE", 5)
    clock = {"now": 1000.0}
    monkeypatch.setattr(lv.time, "monotonic", lambda: clock["now"])
    states = []
    for batch in range(3):                                            # three separate calls, as three requests would make
        rows = run("torvalds", [{"id": str(n), "site": "x", "url": f"https://example.org/b{batch}n{n}/torvalds"} for n in range(4)])
        states += [(r["state"], r["evidence"]) for r in rows]
    assert len(calls) == 5
    assert states[:5] == [("not_found", lv.EVIDENCE["http_404"])] * 5
    assert states[5:] == [("unknown", lv.EVIDENCE["throttled"])] * 7
    # another site is not affected, and a throttled link is not cached: it is checked once the minute has passed
    assert one("torvalds", "https://example.net/u/torvalds")["state"] == "not_found"
    clock["now"] += lv.SITE_WINDOW + 1
    row = one("torvalds", "https://example.org/b2n3/torvalds")
    assert (row["state"], row["cached"]) == ("not_found", False)
    # a cached answer costs nothing against the limit
    for _ in range(20):
        assert one("torvalds", "https://example.org/b2n3/torvalds")["cached"] is True


def test_a_call_has_an_overall_deadline(monkeypatch):
    monkeypatch.setattr(lv, "CALL_DEADLINE", 0.3)
    monkeypatch.setattr(lv, "TOTAL_TIMEOUT", 60)
    real_fetch = lv._fetch

    async def fetch(client, url):
        if "slow" in url:
            await asyncio.sleep(30)
        return await real_fetch(client, url)

    serve(monkeypatch, {"example.org/u/torvalds": (200, page("torvalds"))})
    monkeypatch.setattr(lv, "_fetch", fetch)
    started = lv.time.monotonic()
    rows = run("torvalds", [{"id": "ok", "site": "x", "url": "https://example.org/u/torvalds"},
                            *[{"id": f"slow{n}", "site": "x", "url": f"https://example.net/slow{n}/torvalds"} for n in range(6)]])
    assert lv.time.monotonic() - started < 5
    assert rows[0]["state"] == "verified"
    assert all((r["state"], r["evidence"], r["cached"]) == ("unknown", lv.EVIDENCE["timeout"], False) for r in rows[1:])
    assert all("slow" not in key[0] for key in lv._cache)             # an unfinished link is not cached


# ---- nothing from a fetched page is reflected -----------------------------------------

HOSTILE = (
    '<html><head><title>torvalds <script>alert(1)</script> INJECTED-TITLE</title>'
    '<meta property="og:title" content="torvalds | INJECTED-OG">'
    '<meta property="og:url" content="https://example.org/u/torvalds?INJECTED-URL">'
    '<link rel="canonical" href="javascript:INJECTED-CANONICAL//torvalds"></head>'
    "<body>INJECTED-BODY</body></html>"
)


def test_evidence_comes_only_from_the_closed_set(monkeypatch):
    serve(monkeypatch, {
        "example.org/u/torvalds": (200, HOSTILE, {"x-injected": "INJECTED-HEADER", "server": "INJECTED-SERVER"}),
        "example.org/a/torvalds": (404, HOSTILE),
        "example.org/b/torvalds": (403, HOSTILE),
        "example.org/c/torvalds": (500, HOSTILE),
        "example.org/d/torvalds": (302, "", {"location": "https://example.org/INJECTED-PATH/torvalds"}),
        "example.org/INJECTED-PATH/torvalds": (200, page("nothing")),
        "example.org/e/torvalds": (302, "", {"location": "https://example.org/"}),
        "example.org/": (200, HOSTILE),
    })
    rows = run("torvalds", [{"id": k, "site": "INJECTED-SITE", "url": f"https://example.org/{k}/torvalds"} for k in "uabcde"])
    assert [r["state"] for r in rows] == ["verified", "not_found", "blocked", "unknown", "unknown", "unknown"]
    for r in rows:
        assert r["evidence"] in PHRASES
        assert set(r) <= {"id", "state", "final_url", "evidence", "cached", "hint", "error_code"}
    text = json.dumps(rows)
    assert "INJECTED" not in text and "alert" not in text
    # the one verified row returns the address it was asked for, not one read from the page
    assert rows[0]["final_url"] == "https://example.org/u/torvalds"


def test_final_url_is_never_off_site(monkeypatch):
    serve(monkeypatch, {
        "example.org/u/torvalds": (302, "", {"location": "https://evil.example.net/u/torvalds"}),
        "evil.example.net/u/torvalds": (200, page("torvalds")),
        "twitter.com/torvalds": (301, "", {"location": "https://x.com/torvalds"}),
        "x.com/torvalds": (200, (Path(__file__).parent / "fixtures" / "platform" / "x_found.html").read_text(encoding="utf-8")),
    })
    off = one("torvalds", "https://example.org/u/torvalds")
    assert (off["state"], off["final_url"], off["evidence"]) == ("unknown", "", lv.EVIDENCE["off_site"])
    # the helper refuses on its own too, whatever the classifier said
    assert lv._public_final_url("https://example.org/u/torvalds", "https://evil.example.net/u/torvalds") == ""
    assert lv._public_final_url("https://example.org/u/torvalds", "https://user:pw@example.org/u/torvalds") == ""
    assert lv._public_final_url("https://example.org/u/torvalds", "javascript:alert(1)") == ""
    assert lv._public_final_url("https://example.org/u/torvalds", 'https://example.org/u/torvalds"><b>') == ""
    assert lv._public_final_url("https://example.org/u/torvalds", "https://www.example.org/u/torvalds#frag") == "https://www.example.org/u/torvalds"
    assert lv._public_final_url("https://www.threads.net/@zuck", "https://www.threads.com/@zuck") == "https://www.threads.com/@zuck"
    for state in ("not_found", "blocked", "unknown"):
        row = lv._row({"state": state, "evidence_key": "no_marker", "final_url": "https://example.org/u/torvalds"}, "https://example.org/u/torvalds")
        assert row["final_url"] == ""


def test_known_aliases_keep_their_final_url(monkeypatch):
    x_found = (Path(__file__).parent / "fixtures" / "platform" / "x_found.html").read_text(encoding="utf-8")
    handle = lv.re.search(r'property="og:url" content="https://(?:x|twitter)\.com/([A-Za-z0-9_]+)"', x_found).group(1)
    serve(monkeypatch, {
        f"twitter.com/{handle}": (301, "", {"location": f"https://x.com/{handle}"}),
        f"x.com/{handle}": (200, x_found),
    })
    row = one(handle, f"https://twitter.com/{handle}", "Twitter")
    assert (row["state"], row["final_url"]) == ("verified", f"https://x.com/{handle}")


# ---- the endpoint ---------------------------------------------------------------------

def test_endpoint(c, monkeypatch):
    serve(monkeypatch, {"bitbucket.org/torvalds/": (302, "", {"location": "/torvalds/workspace/repositories/"}),
                        "bitbucket.org/torvalds/workspace/repositories/": (200, fx("bitbucket_found.html"))})
    r = c.post("/api/recon/verify-links", json={"username": "torvalds", "links": [
        {"id": "acct:bitbucket", "site": "BitBucket", "url": "https://bitbucket.org/torvalds/"}]})
    assert r.status_code == 200
    assert r.json() == {"results": [{
        "id": "acct:bitbucket", "state": "verified",
        "final_url": "https://bitbucket.org/torvalds/workspace/repositories/",
        "evidence": lv.EVIDENCE["site_marker"], "cached": False,
    }]}


def test_endpoint_limits(c, monkeypatch):
    calls = []
    serve(monkeypatch, {}, calls)
    monkeypatch.setitem(rl.RATE_LIMITS, "/api/recon/verify-links", (1000, 60))
    link = {"id": "a", "site": "x", "url": "https://example.org/u/torvalds"}
    post = lambda body: c.post("/api/recon/verify-links", json=body)  # noqa: E731
    assert post({"username": "torvalds", "links": [link] * 26}).status_code == 422
    assert post({"username": "torvalds", "links": []}).status_code == 422
    assert post({"username": "torvalds", "links": [{**link, "id": "i" * 81}]}).status_code == 422
    assert post({"username": "torvalds", "links": [{**link, "site": "s" * 121}]}).status_code == 422
    assert post({"username": "torvalds", "links": [{**link, "url": "https://example.org/" + "u" * 600}]}).status_code == 422
    assert post({"username": "bad name; rm -rf", "links": [link]}).status_code == 400
    for url in ("ftp://example.org/torvalds", "file:///etc/passwd", "javascript:alert(1)", "//example.org/torvalds",
                "example.org/torvalds", "https://user:pw@example.org/torvalds", "gopher://example.org/",
                "https://example.org:8443/u/torvalds", "http://example.org:22/torvalds", "https://example.org:443/u/torvalds",
                "http://example.org:80/u/torvalds", "https://example.org:99999/u/torvalds"):
        r = post({"username": "torvalds", "links": [link, {**link, "id": "b", "url": url}]})
        assert r.status_code == 400, url
    assert calls == []                                    # one bad link rejects the request before any fetch
    assert post({"username": "torvalds", "links": [link] * 25}).status_code == 200
    assert len(calls) == 1


def test_rate_limit_entry():
    group, limit, window = match_limit("/api/recon/verify-links")
    assert group == "/api/recon/verify-links" and (limit, window) == (12, 60)


def test_no_em_dashes_in_what_people_read():
    for text in [*lv.EVIDENCE.values(), *lv.HINTS.values(), lv.DEFAULT_HINT]:
        assert chr(0x2014) not in text
