"""Every other server path that could reach an adult or dating site: the one list they all ask
(core.adult_sites), the enricher, the link verifier and the profile scraper. No network: the
HTTP layer is a mock transport and every name resolves to a public test address."""

import asyncio
import json
import socket
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import adult_guard, adult_sites
from core import netguard as ng
from main import app
import middleware.rate_limit as rl
from modules import adult_check as ac
from modules import enricher, link_verify as lv, platform_check as pc, profile_scraper as ps
from modules import github

PUBLIC_IP = "93.184.216.34"
REAL_ASYNC_CLIENT = httpx.AsyncClient


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    lv.clear_cache_for_tests()
    for path in ("/api/recon/verify-links", "/api/recon/enrich", "/api/recon/scrape-profiles"):
        monkeypatch.setitem(rl.RATE_LIMITS, path, (1000, 60))

    async def getaddrinfo(self, host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(ng, "_public_dns_blocking", lambda host: [])
    yield
    lv.clear_cache_for_tests()


def profile_page(handle: str) -> str:
    return f'<html><head><title>{handle} | Site</title><meta property="og:title" content="{handle}" /></head><body>x</body></html>'


def record(calls: list, respond=None):
    """A mock transport handler that notes the Host of every request."""
    def handler(request: httpx.Request):
        calls.append(request.headers["host"] + request.url.path)
        if respond:
            return respond(request)
        handle = request.url.path.rstrip("/").split("/")[-1].lstrip("@")
        return httpx.Response(200, text=profile_page(handle), headers={"content-type": "text/html; charset=utf-8"})
    return handler


# ---- the one list ---------------------------------------------------------------------------

def test_the_list_is_built_from_both_tools_the_adult_check_and_the_hand_list():
    sherlock = json.loads(Path(adult_sites.SHERLOCK_DATA).read_text(encoding="utf-8"))
    maigret = json.loads(Path(adult_sites.MAIGRET_DATA).read_text(encoding="utf-8"))["sites"]
    for name, entry in sherlock.items():
        if isinstance(entry, dict) and entry.get("isNSFW"):
            assert adult_sites.category(name) == "adult" and adult_sites.is_adult_site(url=entry["url"]), name
    for name, entry in maigret.items():
        if set(entry.get("tags") or []) & set(adult_sites.ADULT_TAGS):
            assert adult_sites.is_adult_site(name), name
            if entry.get("url"):
                assert adult_sites.is_adult_site(url=entry["url"]), name
    assert ac.HOSTS <= set(adult_sites.HOSTS) and set(adult_sites.PLATFORMS) <= set(adult_sites.HOSTS)
    for name, host, cat in adult_sites.UNFLAGGED:
        assert adult_sites.category(name) == adult_sites.category(url=f"https://{host}/x") or adult_sites.category(name) == "adult"
        assert adult_sites.is_adult_site(name) and adult_sites.is_adult_site(url=f"https://www.{host}/someone"), name
    for rule in ac.RULES:
        if rule["url"]:
            assert adult_sites.category(url=rule["url"]) == rule["category"], rule["name"]


def test_sites_the_tools_do_not_flag_are_on_the_list():
    assert adult_sites.category("RoyalCams") == "adult" and adult_sites.category(url="https://royalcams.com/profile/x") == "adult"
    assert adult_sites.category("datingRU") == "dating" and adult_sites.category(url="http://dating.ru/x") == "dating"
    assert adult_sites.category("Fansly") == "adult" and adult_sites.category("Justforfans") == "adult"
    assert adult_sites.category("MeetMe") == "dating" and adult_sites.category(url="https://e621.net/users/x") == "adult"
    assert {name for name, _, _ in adult_sites.UNFLAGGED} == {
        "RoyalCams", "datingRU", "Chatujme.cz", "Fansly", "Justforfans", "Admire Me", "Mym.fans", "www.adultism.com",
        "lemmynsfw.com", "E621", "Sexforum.ws", "Sexwin", "SexforumIXBB", "fordating.ru", "Mylove", "MeetMe"}


@pytest.mark.parametrize("name,url,expected", [
    ("", "https://onlyfans.com/x", "adult"), ("", "https://www.pornhub.com/users/x", "adult"), ("", "https://de.xhamster.com/users/x", "adult"),
    ("", "https://PT.BongaCams.com/profile/x", "adult"), ("", "https://bongacams.com/profile/x", "adult"),
    ("", "https://tinder.com/@x", "dating"), ("", "https://love.mail.ru/profile/x", "dating"), ("", "https://dating.rambler.ru/page/x", "dating"),
    ("", "http://x.shoe.org/", "dating"), ("", "onlyfans.com/x", "adult"), ("", "https://apiv3.fansly.com/api/v1/account?usernames=x", "adult"),
    ("pornhub", "", "adult"), (" Tinder ", "", "dating"), ("xHamster", "https://example.org/x", "adult"),
    # a shared domain is not the adult site that lives under it
    ("", "https://mail.ru/x", ""), ("", "https://rambler.ru/x", ""), ("", "https://other.clan.su/u", ""), ("", "https://forum.ixbb.ru/x", ""),
    # ordinary sites, and hosts that only look similar
    ("GitHub", "https://github.com/x", ""), ("", "https://www.youtube.com/@x", ""), ("", "https://www.reddit.com/user/x", ""),
    ("", "https://cash.app/$x", ""), ("", "https://www.patreon.com/x", ""), ("", "https://www.twitch.tv/x", ""), ("", "https://www.tiktok.com/@x", ""),
    ("", "https://notonlyfans.com/x", ""), ("", "https://onlyfans.com.example.org/x", ""), ("", "https://example.org/onlyfans.com/x", ""),
    ("", "", ""), ("", "not a url", ""), (None, None, ""),
])
def test_category_by_name_or_host(name, url, expected):
    assert adult_sites.category(name, url) == expected
    assert adult_sites.is_adult_site(name, url) is bool(expected)


# ---- the enricher ---------------------------------------------------------------------------

def test_the_enricher_has_no_adult_or_dating_scraper():
    assert set(enricher.SCRAPERS) == {"Reddit", "TikTok", "YouTube", "Twitch", "Patreon", "CashApp"}
    assert "OnlyFans" not in enricher.SITE_MAP and not hasattr(enricher, "_scrape_onlyfans")
    source = Path(enricher.__file__).read_text(encoding="utf-8").lower()
    for host in adult_sites.HOSTS:
        assert host not in source, host


@pytest.mark.parametrize("sites", [None, [], ["OnlyFans"], ["OnlyFans", "Fansly", "Pornhub", "Tinder"]])
def test_enrich_never_contacts_an_adult_site(c, monkeypatch, sites):
    calls = []
    monkeypatch.setattr(enricher.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(record(calls))))
    body = {"username": "torvalds"} if sites is None else {"username": "torvalds", "sherlock_sites": sites}
    r = c.post("/api/recon/enrich", json=body)
    assert r.status_code == 200
    assert not any(adult_sites.is_adult_site(url="https://" + call) for call in calls), calls
    assert not any(p["platform"] == "OnlyFans" for p in r.json()["profiles"])
    if not sites:
        assert len(calls) >= 5                                # the ordinary scrapers did run


# ---- the link verifier ------------------------------------------------------------------------

ADULT_LINKS = [
    ("Pornhub", "https://www.pornhub.com/users/{u}"), ("OnlyFans", "https://onlyfans.com/{u}"), ("xHamster", "https://xhamster.com/users/{u}"),
    ("Tinder", "https://tinder.com/@{u}"), ("ChaturBate", "https://chaturbate.com/{u}/"), ("RoyalCams", "https://royalcams.com/profile/{u}"),
    ("datingRU", "http://dating.ru/{u}"), ("Fansly", "https://fansly.com/{u}"),
]


def verify(monkeypatch, username, links, **kw):
    calls = []
    monkeypatch.setattr(lv, "_inner_transport", lambda: httpx.MockTransport(record(calls)))
    rows = asyncio.run(lv.run_link_verify(username, [{"id": str(n), "site": site, "url": url.format(u=username)} for n, (site, url) in enumerate(links)], **kw))
    return rows["results"], calls


def test_the_evidence_sentence_and_its_place_in_the_closed_set():
    keys = list(lv.EVIDENCE)
    assert lv.EVIDENCE["adult_not_checked"] == "Adult and dating sites are checked only when that mode is on, and never for a handle that suggests a minor."
    assert keys.index("adult_not_checked") == keys.index("throttled") + 1 == keys.index("no_profile_page") - 1


@pytest.mark.parametrize("handle", ["emma15f", "jake13", "born2012", "emma09", "schoolgirl", "year9_sam"])
def test_a_minor_handle_never_reaches_an_adult_site_through_verify_links(monkeypatch, handle):
    assert adult_guard.minor_indicated(handle)
    for adult in (False, True):                                   # the opt-in does not help
        lv.clear_cache_for_tests()
        rows, calls = verify(monkeypatch, handle, ADULT_LINKS + [("GitHub", "https://github.com/{u}")], adult=adult)
        for row in rows[:-1]:
            assert (row["state"], row["evidence"]) == ("unknown", lv.EVIDENCE["adult_not_checked"]), row
            assert row["final_url"] == "" and row["cached"] is False
        assert calls == ["github.com/" + handle]                  # the ordinary link is still checked


def test_without_the_opt_in_no_adult_link_is_opened_for_any_handle(monkeypatch):
    rows, calls = verify(monkeypatch, "torvalds", ADULT_LINKS + [("GitHub", "https://github.com/{u}")])
    assert [r["evidence"] for r in rows[:-1]] == [lv.EVIDENCE["adult_not_checked"]] * len(ADULT_LINKS)
    assert all(r["state"] == "unknown" for r in rows[:-1]) and calls == ["github.com/torvalds"]
    for value in (None, 0, 1, "true", "yes"):                     # the opt-in must be exactly True
        lv.clear_cache_for_tests()
        _, calls = verify(monkeypatch, "torvalds", ADULT_LINKS, adult=value)
        assert calls == [], value


def test_with_the_opt_in_an_adult_link_is_checked_and_a_cached_answer_is_not_served_without_it(monkeypatch):
    links = [("Pornhub", "https://www.pornhub.com/users/{u}"), ("Tinder", "https://tinder.com/@{u}")]
    rows, calls = verify(monkeypatch, "torvalds", links, adult=True)
    assert sorted(calls) == ["tinder.com/@torvalds", "www.pornhub.com/users/torvalds"]
    assert all(r["evidence"] != lv.EVIDENCE["adult_not_checked"] for r in rows)
    # the answers are cached now. Asking again without the opt-in still returns "not checked".
    rows, calls = verify(monkeypatch, "torvalds", links)
    assert calls == [] and [r["evidence"] for r in rows] == [lv.EVIDENCE["adult_not_checked"]] * 2
    assert all(r["state"] == "unknown" and r["final_url"] == "" for r in rows)


def test_verify_links_endpoint_takes_the_opt_in_and_keeps_the_guard(c, monkeypatch):
    calls = []
    monkeypatch.setattr(lv, "_inner_transport", lambda: httpx.MockTransport(record(calls)))
    body = lambda handle, **kw: {"username": handle, "links": [{"id": "a", "site": "Pornhub", "url": f"https://www.pornhub.com/users/{handle}"}], **kw}
    refused = lv.EVIDENCE["adult_not_checked"]
    assert c.post("/api/recon/verify-links", json=body("emma15f")).json()["results"][0]["evidence"] == refused
    assert c.post("/api/recon/verify-links", json=body("emma15f", adult=True)).json()["results"][0]["evidence"] == refused
    assert c.post("/api/recon/verify-links", json=body("torvalds")).json()["results"][0]["evidence"] == refused
    assert calls == []
    got = c.post("/api/recon/verify-links", json=body("torvalds", adult=True)).json()["results"][0]
    assert got["evidence"] != refused and calls == ["www.pornhub.com/users/torvalds"]
    from routers.recon_identity import VerifyLinksRequest
    assert VerifyLinksRequest(username="x", links=[{"id": "a", "url": "https://github.com/x"}]).adult is False


# ---- the profile scraper ----------------------------------------------------------------------

def scrape(monkeypatch, urls, respond=None):
    calls = []
    monkeypatch.setattr(ps.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(record(calls, respond))))
    return asyncio.run(ps.scrape_profiles([{"site": "x", "url": u} for u in urls])), calls


def test_the_profile_scraper_never_opens_an_adult_or_dating_site(monkeypatch):
    urls = [u.format(u="torvalds") for _, u in ADULT_LINKS] + ["https://love.mail.ru/profile/torvalds", "https://example.org/u/torvalds"]
    rows, calls = scrape(monkeypatch, urls)
    for row in rows[:-1]:
        assert (row["error_code"], row["error"]) == ("adult_site", ps.ADULT_REFUSAL), row
        assert "display_name" not in row and "bio" not in row
    assert "error" not in rows[-1] and calls == ["example.org/u/torvalds"]


def test_the_profile_scraper_does_not_follow_a_redirect_to_an_adult_site(monkeypatch):
    def respond(request):
        if request.headers["host"] == "short.example.org":
            return httpx.Response(302, headers={"location": "https://onlyfans.com/torvalds"})
        if request.headers["host"] == "hop.example.org":
            return httpx.Response(301, headers={"location": "https://example.org/u/torvalds"})
        return httpx.Response(200, text=profile_page("torvalds"), headers={"content-type": "text/html"})

    rows, calls = scrape(monkeypatch, ["https://short.example.org/a", "https://hop.example.org/b"], respond)
    assert rows[0]["error_code"] == "adult_site" and "display_name" not in rows[0]
    assert "error" not in rows[1]                                   # an ordinary redirect still works
    assert calls == ["short.example.org/a", "hop.example.org/b", "example.org/u/torvalds"]


def test_scrape_profiles_endpoint_refuses_adult_sites(c, monkeypatch):
    calls = []
    monkeypatch.setattr(ps.httpx, "AsyncClient", lambda *a, **k: REAL_ASYNC_CLIENT(transport=httpx.MockTransport(record(calls))))
    r = c.post("/api/recon/scrape-profiles", json={"urls": [{"site": "OnlyFans", "url": "https://onlyfans.com/torvalds"},
                                                            {"site": "Tinder", "url": "https://tinder.com/@torvalds"}]})
    body = r.json()
    assert r.status_code == 200 and body["scraped"] == 0 and calls == []
    assert [x["error_code"] for x in body["results"]] == ["adult_site", "adult_site"]


# ---- a link found on a GitHub profile -----------------------------------------------------------

def test_no_ordinary_server_path_has_a_fixed_adult_host_and_github_only_talks_to_github():
    # The modules that run on every investigation name their hosts in code. None is adult or dating.
    assert not any(adult_sites.is_adult_site(url=r["url"]) for r in pc.RULES) and pc.MANUAL_PLATFORMS == []
    source = Path(github.__file__).read_text(encoding="utf-8")
    assert github.API == "https://api.github.com" and github.RAW == "https://raw.githubusercontent.com"
    import re
    hosts = {h.lower() for h in re.findall(r"https?://([A-Za-z0-9.-]+)", source)}
    assert hosts <= {"api.github.com", "raw.githubusercontent.com", "github.com", "crawlr.lol", "avatars.githubusercontent.com"}, hosts
    # A link GitHub lists is returned as text. Only the caller-driven fetchers could open it, and
    # both refuse (tests above): verify-links without the opt-in, scrape-profiles always.
