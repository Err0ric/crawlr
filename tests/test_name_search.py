"""Name search, replayed from tests/fixtures/name_search. No network.

linus_torvalds.json was recorded on 2026-11-14 for a public figure and trimmed; every other
account and person in it is invented. mara_lindqvist.json is invented from top to bottom.
"""

import asyncio
import json
import logging
import re
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core import validate
from main import app
from middleware import rate_limit
from middleware.rate_limit import match_limit
from modules import name_search as ns

FIXTURES = Path(__file__).parent / "fixtures" / "name_search"
REAL_CLIENT = httpx.AsyncClient
HOSTS = {
    "www.wikidata.org": "Wikidata", "api.github.com": "GitHub", "pub.orcid.org": "ORCID",
    "api.openalex.org": "OpenAlex", "public.api.bsky.app": "Bluesky",
}
CANDIDATE_KEYS = {"source", "kind", "name", "handle", "url", "description", "location", "affiliation",
                  "name_match", "qualifier_hits"}


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


LINUS = fixture("linus_torvalds")
MARA = fixture("mara_lindqvist")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ns.clear_cache_for_tests()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    ns.clear_cache_for_tests()


def replay(monkeypatch, data: dict, calls: list | None = None, override=None):
    """Serve one recorded set. `override(source, request)` may return a Response or raise."""

    def handler(request: httpx.Request):
        source = HOSTS[request.url.host]
        if calls is not None:
            calls.append((source, request))
        if override:
            resp = override(source, request)
            if resp is not None:
                return resp
        if source == "Wikidata":
            key = "wikidata_search" if request.url.params.get("action") == "query" else "wikidata_entities"
            return httpx.Response(200, json=data[key])
        return httpx.Response(200, json=data[source.lower()])

    monkeypatch.setattr(ns.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(handler)))


def search(name: str, **qualifiers) -> dict:
    return asyncio.run(ns.run_name_search(validate.person_name(name), **qualifiers))


def by_source(out: dict, source: str) -> list[dict]:
    return [c for c in out["candidates"] if c["source"] == source]


def strings(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)
    elif isinstance(value, str):
        yield value


# ---- validator ---------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Linus Torvalds", "Linus Torvalds"),
    ("  Linus \t Torvalds ".replace("\t", " "), "Linus Torvalds"),
    ("Linus Torvalds", "Linus Torvalds"),               # no-break space
    ("Madonna", "Madonna"),
    ("Siobhán O'Brien", "Siobhán O'Brien"),
    ("Siobhan O’Brien", "Siobhan O'Brien"),            # curly apostrophe
    ("Jean-Luc Picard", "Jean-Luc Picard"),
    ("J. R. R. Tolkien", "J. R. R. Tolkien"),
    ("J.R.R. Tolkien", "J.R.R. Tolkien"),
    ("Martin Luther King Jr.", "Martin Luther King Jr."),
    ("Лев Толстой", "Лев Толстой"),   # Cyrillic
    ("山田 太郎", "山田 太郎"),                                   # Japanese
    ("李小龙", "李小龙"),                                                 # Chinese, one token
    ("محمد صلاح", "محمد صلاح"),   # Arabic
    ("सचिन तेंदुलकर", "सचिन तेंदुलकर"),   # Devanagari, with combining marks
    ("Zoë Example", "Zoë Example"),               # decomposed input comes back composed
    ("Li Na", "Li Na"),
])
def test_person_name_accepts(raw, expected):
    assert validate.person_name(raw) == expected


@pytest.mark.parametrize("raw", [
    "", " ", "A", "x" * 81, "12345", "John Smith 3", "007", "john@example.com", "https://example.com/john",
    "example.com", "www.example.com", "john.smith", "John\nSmith", "John\tSmith", "John\x00Smith", "John\x1b[0mSmith",
    "John Smith; rm -rf", 'John "Johnny" Smith', "John <b>Smith</b>", "John Smith haswbstatement:P31=Q5",
    "John -Smith", "- -", "...", "'' ''", "J", "John, Smith", "user_name", "@jsmith", "John/Smith", "John (Smith)",
])
def test_person_name_rejects(raw):
    with pytest.raises(HTTPException) as exc:
        validate.person_name(raw)
    assert exc.value.status_code == 400


# ---- parsing and handle patterns ---------------------------------------------------

def test_parse_name():
    assert ns.parse_name("Linus Torvalds") == {"given": "Linus", "middle": "", "family": "Torvalds", "suffix": "", "single_token": False}
    assert ns.parse_name("Linus Benedict Torvalds")["middle"] == "Benedict"
    assert ns.parse_name("J. R. R. Tolkien") == {"given": "J.", "middle": "R. R.", "family": "Tolkien", "suffix": "", "single_token": False}
    assert ns.parse_name("Madonna") == {"given": "Madonna", "middle": "", "family": "", "suffix": "", "single_token": True}


def handles(name: str) -> dict:
    return {h["pattern"]: h["value"] for h in ns.handle_patterns(ns.parse_name(validate.person_name(name)))}


def test_handle_patterns_for_a_plain_name():
    assert ns.handle_patterns(ns.parse_name("Linus Torvalds")) == [
        {"value": "linustorvalds", "pattern": "givenfamily"},
        {"value": "linus.torvalds", "pattern": "given.family"},
        {"value": "linus_torvalds", "pattern": "given_family"},
        {"value": "ltorvalds", "pattern": "gfamily"},
        {"value": "linust", "pattern": "givenf"},
        {"value": "torvaldslinus", "pattern": "familygiven"},
        {"value": "torvalds.linus", "pattern": "family.given"},
        {"value": "linus-torvalds", "pattern": "given-family"},
    ]


def test_handle_patterns_with_a_middle_name():
    got = handles("Linus Benedict Torvalds")
    assert len(got) == 12 == ns.MAX_HANDLES
    assert got["givenmfamily"] == "linusbtorvalds" and got["given.m.family"] == "linus.b.torvalds"
    assert got["gmfamily"] == "lbtorvalds" and got["givenmiddlefamily"] == "linusbenedicttorvalds"
    assert got["givenfamily"] == "linustorvalds"


@pytest.mark.parametrize("name,givenfamily,dotted", [
    ("Siobhán O'Brien", "siobhanobrien", "siobhan.obrien"),
    ("Siobhan O’Brien", "siobhanobrien", "siobhan.obrien"),
    ("Jean-Luc Picard", "jeanlucpicard", "jeanluc.picard"),
    ("Anna Smith-Jones", "annasmithjones", "anna.smithjones"),
    ("Renée Müller", "reneemuller", "renee.muller"),
    ("Søren Straße", "sorenstrasse", "soren.strasse"),
    ("Łukasz Ærin", "lukaszaerin", "lukasz.aerin"),
    ("J. R. R. Tolkien", "jtolkien", "j.tolkien"),
])
def test_handle_patterns_fold_accents_apostrophes_and_hyphens(name, givenfamily, dotted):
    got = handles(name)
    assert got["givenfamily"] == givenfamily and got["given.family"] == dotted


def test_handles_are_valid_usernames_lowercase_ascii_and_unique():
    for name in ("Linus Benedict Torvalds", "Siobhán O'Brien", "Al Li", "A B", "Jean-Luc Marie Picard", "Madonna"):
        rows = ns.handle_patterns(ns.parse_name(name))
        values = [r["value"] for r in rows]
        assert len(values) == len(set(values)) <= 12
        for v in values:
            assert validate.username(v) == v and v == v.lower() and v.isascii() and len(v) >= 2


def test_handles_for_scripts_with_no_ascii_form_are_empty():
    assert ns.handle_patterns(ns.parse_name("Лев Толстой")) == []
    assert ns.handle_patterns(ns.parse_name("李小龙")) == []


# ---- matching ----------------------------------------------------------------------

def test_name_match_levels():
    q = ns.Query("Linus Torvalds")
    assert q.match(["Linus Torvalds"]) == "exact"
    assert q.match(["LINUS  TORVALDS"]) == "exact"
    assert q.match(["Linus Benedict Torvalds"]) == "tokens"
    assert q.match(["Torvalds, Linus"]) == "tokens"
    assert q.match(["L. Torvalds"]) == "partial" and q.match(["L Torvalds"]) == "partial"
    assert q.match(["Torvalds, L."]) == "partial" and q.match(["L. B. Torvalds"]) == "partial"
    # A relative or a namesake business is not a candidate, even when the first letter is the same.
    for other in ("Nils Torvalds", "Leo Torvalds", "Lars Torvalds", "Torvalds Lumber", "Torvalds Ltd", "Li Torvalds"):
        assert q.match([other]) is None, other
    assert q.match(["Linus Pauling"]) is None
    assert q.match(["Linus"]) is None
    assert q.match(["Linus"], handle="linustorvalds") == "tokens"
    assert q.match(["Linus"], handle="ltorvalds") is None    # an initial is too loose to count
    assert q.match(["Someone Else", "Linus Torvalds"]) == "exact"
    assert q.match([]) is None and q.match([""]) is None


def test_name_match_ignores_accents_and_works_in_other_scripts():
    assert ns.Query("Renee Muller").match(["Renée Müller"]) == "exact"
    assert ns.Query("Siobhan O'Brien").match(["Siobhán O’Brien"]) == "exact"
    q = ns.Query("Лев Толстой")
    assert q.match(["ЛЕВ ТОЛСТОЙ"]) == "exact"
    assert q.match(["Лев Николаевич Толстой"]) == "tokens"


def test_qualifier_hits_are_whole_words():
    q = ns.Query("Mara Lindqvist", location="Gothenburg", employer="Uppsala University", keyword="marine")
    assert q.qualifier_hits("Gothenburg, Sweden", "", "") == ["location"]
    assert q.qualifier_hits("", "uppsala university; Lund", "Marine biologist") == ["employer", "keyword"]
    assert q.qualifier_hits("", "Uppsala", "submarine pilot, Gothenburgish") == []
    assert ns.Query("Mara Lindqvist").qualifier_hits("Gothenburg", "x", "y") == []
    assert ns.Query("A B", location="Malmö").qualifier_hits("Malmo, SE") == ["location"]


# ---- full results ------------------------------------------------------------------

def test_full_result_for_linus_torvalds(monkeypatch):
    calls = []
    replay(monkeypatch, LINUS, calls)
    out = search("Linus Torvalds")

    assert out["name"] == "Linus Torvalds" and out["cached"] is False
    assert out["parsed"] == {"given": "Linus", "middle": "", "family": "Torvalds", "suffix": "", "single_token": False}
    assert set(out) == {"name", "parsed", "candidates", "sources", "handles", "notable", "cached"}
    assert all(set(c) == CANDIDATE_KEYS for c in out["candidates"])

    assert out["notable"] == {
        "name": "Linus Torvalds", "description": "Finnish software engineer (born 1969)",
        "url": "https://www.wikidata.org/wiki/Q34253", "wikipedia": "https://en.wikipedia.org/wiki/Linus_Torvalds",
    }
    assert out["sources"] == {
        "Wikidata": {"state": "ok", "count": 1, "shown": 1, "total": 6},
        "GitHub": {"state": "ok", "count": 8, "shown": 8, "total": 13},
        "ORCID": {"state": "none", "count": 0, "shown": 0, "total": 0},
        "OpenAlex": {"state": "ok", "count": 2, "shown": 2, "total": 2},
        "Bluesky": {"state": "ok", "count": 2, "shown": 2, "total": None},
    }

    # The fixture's "Lena Torvalds" shares the family name and the initial. She is someone else.
    assert "Lena Torvalds" not in [c["name"] for c in out["candidates"]]
    first = out["candidates"][0]
    assert first == {
        "source": "Wikidata", "kind": "public_figure", "name": "Linus Torvalds", "handle": "Q34253",
        "url": "https://www.wikidata.org/wiki/Q34253", "description": "Finnish software engineer (born 1969)",
        "location": "", "affiliation": "", "name_match": "exact", "qualifier_hits": [],
    }
    gh = by_source(out, "GitHub")
    assert gh[0] == {
        "source": "GitHub", "kind": "account", "name": "", "handle": "torvalds", "url": "https://github.com/torvalds",
        "description": "", "location": "", "affiliation": "", "name_match": "tokens", "qualifier_hits": [],
    }
    oa = by_source(out, "OpenAlex")[0]
    assert oa["kind"] == "researcher" and oa["affiliation"] == "Linux Foundation" and oa["location"] == "US"
    assert oa["url"] == "https://openalex.org/A5083555959" and oa["description"].startswith("10 works indexed. Topics: Open Source")

    # Wikidata's full-text search also returns relatives; only names that fit are kept.
    assert [c["name"] for c in by_source(out, "Wikidata")] == ["Linus Torvalds"]
    # Bluesky: the profile named for the person and the one whose handle spells the name.
    # Profiles that only mention the name in a bio are dropped, and so is handle.invalid.
    bsky = by_source(out, "Bluesky")
    assert [(c["handle"], c["name_match"]) for c in bsky] == [
        ("penguin-notes.fixture-social.example", "exact"), ("linustorvalds.fixture-social.example", "tokens")]
    assert bsky[0]["description"] == "Parody account. Not the real one. Kernel jokes daily."
    assert bsky[0]["url"] == "https://bsky.app/profile/penguin-notes.fixture-social.example"

    # ranking: exact, then tokens, then partial
    ranks = [ns.RANK[c["name_match"]] for c in out["candidates"]]
    assert ranks == sorted(ranks)
    assert len(out["candidates"]) == 13

    # six requests: two for Wikidata, one for each other source
    assert sorted(s for s, _ in calls) == ["Bluesky", "GitHub", "ORCID", "OpenAlex", "Wikidata", "Wikidata"]


def test_requests_carry_the_name_and_nothing_else_personal(monkeypatch):
    calls = []
    replay(monkeypatch, MARA, calls)
    search("Mara Lindqvist", location="Gothenburg", employer="Uppsala University", keyword="marine")
    assert len(calls) == 6
    for source, request in calls:
        url = str(request.url).lower()
        for word in ("gothenburg", "uppsala", "marine"):
            assert word not in url, source
        assert request.headers["user-agent"] == ns.USER_AGENT
        assert "authorization" not in request.headers and "@" not in request.headers["user-agent"]
        assert "mailto" not in url and "api_key" not in url
    params = {s: r.url.params for s, r in calls if s != "Wikidata"}
    assert params["GitHub"]["q"] == 'fullname:"Mara Lindqvist" type:user' and params["GitHub"]["per_page"] == "8"
    assert params["ORCID"]["q"] == 'given-names:"Mara" AND family-name:"Lindqvist"'
    assert params["OpenAlex"]["search"] == "Mara Lindqvist"
    assert params["Bluesky"]["q"] == "Mara Lindqvist"
    wd = [r.url.params for s, r in calls if s == "Wikidata"]
    assert {p["action"] for p in wd} == {"query", "wbgetentities"}
    assert next(p for p in wd if p["action"] == "query")["srsearch"] == "Mara Lindqvist haswbstatement:P31=Q5"


def test_github_token_is_sent_to_github_only(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-value")
    calls = []
    replay(monkeypatch, LINUS, calls)
    search("Linus Torvalds")
    for source, request in calls:
        assert ("authorization" in request.headers) == (source == "GitHub")


def test_ranking_and_filtering_without_qualifiers(monkeypatch):
    replay(monkeypatch, MARA)
    out = search("Mara Lindqvist")
    got = [(c["source"], c["handle"], c["name_match"]) for c in out["candidates"]]
    assert got == [
        ("Wikidata", "Q990000103", "exact"), ("Wikidata", "Q990000101", "exact"),
        ("ORCID", "0000-0000-0000-0035", "exact"),
        ("OpenAlex", "A5990000002", "exact"), ("OpenAlex", "A5990000001", "exact"),
        ("Bluesky", "mara-lindqvist.fixture-social.example", "exact"),
        ("Wikidata", "Q990000102", "tokens"),
        ("GitHub", "mlindqvist-dev", "tokens"), ("GitHub", "maralindqvist", "tokens"),
        ("ORCID", "0000-0000-0000-004X", "tokens"),
        ("Bluesky", "mlq.fixture-social.example", "tokens"),
        ("ORCID", "0000-0000-0000-0027", "partial"),
    ]
    assert all(c["qualifier_hits"] == [] for c in out["candidates"])
    # An entity with no English label shows the spelling that matched.
    assert out["candidates"][0]["name"] == "Mara Lindqvist" and out["candidates"][0]["description"] == ""
    # `notable` prefers the exact match that has a Wikipedia article.
    assert out["notable"] == {
        "name": "Mara Lindqvist", "description": "Swedish marine biologist",
        "url": "https://www.wikidata.org/wiki/Q990000101",
        "wikipedia": "https://en.wikipedia.org/wiki/Mara_Lindqvist_(biologist)",
    }
    orcid = by_source(out, "ORCID")[0]
    assert orcid["kind"] == "researcher" and orcid["url"] == "https://orcid.org/0000-0000-0000-0035"
    assert orcid["affiliation"] == "Uppsala University; Nordic Institute of Oceanography; Example Polar Station"
    # ORCID's public email field never leaves the module.
    assert not any("@" in s or "fixture.example/" in s for s in strings(out))
    # An organisation account is not a person.
    assert "lindqvist-labs" not in [c["handle"] for c in out["candidates"]]
    assert out["sources"]["ORCID"] == {"state": "ok", "count": 3, "shown": 3, "total": 5}


def test_qualifiers_rank_within_a_match_level_and_annotate(monkeypatch):
    replay(monkeypatch, MARA)
    out = search("Mara Lindqvist", location="Gothenburg", employer="Uppsala University", keyword="marine")
    got = [(c["handle"], c["name_match"], c["qualifier_hits"]) for c in out["candidates"]]
    assert got[:6] == [
        ("A5990000001", "exact", ["employer", "keyword"]),
        ("mara-lindqvist.fixture-social.example", "exact", ["location", "keyword"]),
        ("Q990000101", "exact", ["keyword"]),
        ("0000-0000-0000-0035", "exact", ["employer"]),
        ("Q990000103", "exact", []),
        ("A5990000002", "exact", []),
    ]
    # A qualifier hit never lifts a row above a better name match.
    assert got[6] == ("Q990000102", "tokens", ["location"])
    assert [g[1] for g in got] == ["exact"] * 6 + ["tokens"] * 5 + ["partial"]


def test_caps_per_source_and_in_total(monkeypatch):
    many = json.loads(json.dumps(MARA))
    many["github"]["items"] = [{"login": f"mara-fx-{i}", "type": "User"} for i in range(20)]
    many["orcid"]["expanded-result"] = [
        {"orcid-id": f"0000-0000-0001-{i:04d}", "given-names": "Mara", "family-names": "Lindqvist", "institution-name": []}
        for i in range(20)]
    many["openalex"]["results"] = [
        {"id": f"https://openalex.org/A7{i:04d}", "display_name": "Mara Lindqvist", "works_count": 1} for i in range(20)]
    many["bluesky"]["actors"] = [
        {"handle": f"mara{i}.fixture-social.example", "displayName": "Mara Lindqvist", "description": "x" * 600} for i in range(25)]
    ids = [f"Q9900002{i:02d}" for i in range(20)]
    many["wikidata_search"]["query"]["search"] = [{"title": q} for q in ids]
    many["wikidata_entities"]["entities"] = {q: {"labels": {"en": {"value": "Mara Lindqvist"}}} for q in ids}
    replay(monkeypatch, many)
    out = search("Mara Lindqvist")
    assert len(out["candidates"]) == 30 == ns.MAX_CANDIDATES
    per = {s: len(by_source(out, s)) for s in out["sources"]}
    # Five directories with 8 rows each is 40, and the list holds 30. Each directory gives rows in
    # turn, so none with matches is cut to zero, and every one still says how many it has.
    assert per == {"Wikidata": 6, "GitHub": 6, "ORCID": 6, "OpenAlex": 6, "Bluesky": 6}
    for s, n in per.items():
        assert out["sources"][s]["state"] == "ok" and out["sources"][s]["count"] == 8 and out["sources"][s]["shown"] == n, s
    # Ranked as one list afterwards: every exact row before the GitHub rows (tokens).
    assert [c["name_match"] for c in out["candidates"]] == ["exact"] * 24 + ["tokens"] * 6
    assert [c["source"] for c in out["candidates"][24:]] == ["GitHub"] * 6
    assert all(len(c["description"]) <= 240 for c in out["candidates"])


# ---- text only ---------------------------------------------------------------------

IMAGE_RE = re.compile(r"\.(?:png|jpe?g|gif|webp|svg|avif|bmp|ico)(?:[?#]|$|\s)|avatar|cdn\.bsky\.app|gravatar", re.I)


@pytest.mark.parametrize("data,name", [(LINUS, "Linus Torvalds"), (MARA, "Mara Lindqvist")])
def test_no_image_url_anywhere_in_a_response(monkeypatch, data, name):
    assert "avatars.githubusercontent.com" in json.dumps(data) and "cdn.bsky.app" in json.dumps(data)
    replay(monkeypatch, data)
    out = search(name)
    for s in strings(out):
        assert not IMAGE_RE.search(s), s
    # Every link is one of the five profile forms, built from a checked ID.
    for c in out["candidates"]:
        assert re.match(r"^https://(www\.wikidata\.org/wiki/Q\d+|github\.com/[A-Za-z0-9-]+|orcid\.org/[\dX-]+|"
                        r"openalex\.org/A\d+|bsky\.app/profile/[a-z0-9.-]+)$", c["url"]), c["url"]


def test_descriptions_are_one_line_and_bios_keep_their_text(monkeypatch):
    replay(monkeypatch, MARA)
    bsky = by_source(search("Mara Lindqvist"), "Bluesky")[0]
    # The picture link someone put in their bio is cut; the rest is kept on one line.
    assert bsky["description"] == "Marine biologist in Gothenburg. Opinions mine. is not a bio"
    assert bsky["name"] == "Mara Lindqvist \U0001f30a"


def test_hostile_values_from_a_source_are_dropped(monkeypatch):
    bad = json.loads(json.dumps(MARA))
    bad["github"]["items"] = [{"login": "ok-login", "type": "User"}, {"login": "../../evil", "type": "User"},
                              {"login": "a b", "type": "User"}, {"login": None}, "junk"]
    bad["bluesky"]["actors"] = [
        {"handle": "evil.example/../../x", "displayName": "Mara Lindqvist"},
        {"handle": "javascript:alert(1)", "displayName": "Mara Lindqvist"},
        {"handle": "fine.fixture-social.example", "displayName": "Mara\x00 Lind‮qvist\nX", "description": 7},
    ]
    bad["openalex"]["results"] = [{"id": "https://evil.example/A1?x=", "display_name": "Mara Lindqvist"},
                                  {"id": "https://openalex.org/A12", "display_name": "Mara Lindqvist",
                                   "last_known_institutions": "nope", "topics": [None, 3], "works_count": "many"}]
    bad["wikidata_search"]["query"]["search"] = [{"title": "Q1); DROP"}, {"title": "Q990000101"}]
    bad["wikidata_entities"]["entities"]["Q990000101"]["sitelinks"]["enwiki"]["title"] = "Mara Lindqvist?x=1#y /z"
    replay(monkeypatch, bad)
    out = search("Mara Lindqvist")
    assert [c["handle"] for c in by_source(out, "GitHub")] == ["ok-login"]
    assert [c["handle"] for c in by_source(out, "Bluesky")] == []      # the control characters break the name match
    assert [c["url"] for c in by_source(out, "OpenAlex")] == ["https://openalex.org/A12"]
    assert by_source(out, "OpenAlex")[0]["description"] == ""
    assert [c["handle"] for c in by_source(out, "Wikidata")] == ["Q990000101"]
    assert out["notable"]["wikipedia"] == "https://en.wikipedia.org/wiki/Mara_Lindqvist%3Fx%3D1%23y_%2Fz"
    for s in strings(out):
        assert "\x00" not in s and "‮" not in s and "\n" not in s


# ---- states ------------------------------------------------------------------------

EMPTY = {
    "github": {"total_count": 0, "incomplete_results": False, "items": []},
    "wikidata_search": {"batchcomplete": "", "query": {"searchinfo": {"totalhits": 0}, "search": []}},
    "wikidata_entities": {"entities": {}},
    "orcid": {"expanded-result": None, "num-found": 0},
    "openalex": {"meta": {"count": 0}, "results": []},
    "bluesky": {"actors": []},
}


def test_nothing_found_is_none_for_every_source(monkeypatch):
    calls = []
    replay(monkeypatch, EMPTY, calls)
    out = search("Zzyzx Qwertyuiop")
    assert out["candidates"] == [] and out["notable"] is None
    assert {s["state"] for s in out["sources"].values()} == {"none"}
    assert all(s["count"] == 0 and "error" not in s for s in out["sources"].values())
    assert len(calls) == 5          # no second Wikidata request when the search is empty
    assert len(out["handles"]) == 8


@pytest.mark.parametrize("status", [403, 429])
def test_rate_limit_on_one_source_leaves_the_others_intact(monkeypatch, status):
    replay(monkeypatch, LINUS, override=lambda s, r: httpx.Response(status, json={"message": "API rate limit exceeded"}) if s == "GitHub" else None)
    out = search("Linus Torvalds")
    gh = out["sources"]["GitHub"]
    assert gh["state"] == "rate_limited" and gh["error_code"] == "rate_limited" and gh["count"] == 0 and gh["total"] is None
    assert gh["error"] and gh["error_detail"] == f"HTTP {status} from api.github.com"
    assert by_source(out, "GitHub") == []
    rest = {k: v["state"] for k, v in out["sources"].items() if k != "GitHub"}
    assert rest == {"Wikidata": "ok", "ORCID": "none", "OpenAlex": "ok", "Bluesky": "ok"}
    assert out["notable"]["name"] == "Linus Torvalds" and len(out["candidates"]) == 5


@pytest.mark.parametrize("source", ["Wikidata", "GitHub", "ORCID", "OpenAlex", "Bluesky"])
def test_each_source_reports_rate_limited_failed_and_never_none(monkeypatch, source):
    def limited(s, r):
        return httpx.Response(429, text="slow down") if s == source else None

    def broken(s, r):
        return httpx.Response(500, text="oops") if s == source else None

    def garbage(s, r):
        return httpx.Response(200, text="<html>not json</html>") if s == source else None

    def wrong_shape(s, r):
        return httpx.Response(200, json=["unexpected"]) if s == source else None

    def refused(s, r):
        if s == source:
            raise httpx.ConnectError("connection refused")

    def slow(s, r):
        if s == source:
            raise httpx.ReadTimeout("timed out")

    for override, state, code in [(limited, "rate_limited", "rate_limited"), (broken, "failed", "upstream"),
                                  (garbage, "failed", "bad_response"), (wrong_shape, "failed", "bad_response"),
                                  (refused, "failed", "unreachable"), (slow, "failed", "timeout")]:
        ns.clear_cache_for_tests()
        replay(monkeypatch, MARA, override=override)
        out = search("Mara Lindqvist")
        got = out["sources"][source]
        assert (got["state"], got["error_code"]) == (state, code), override.__name__
        assert got["count"] == 0 and got["error"] and "error_detail" in got
        assert "Mara" not in got["error_detail"] and "Lindqvist" not in got["error_detail"]
        assert by_source(out, source) == []
        others = [v["state"] for k, v in out["sources"].items() if k != source]
        assert others == ["ok"] * 4, override.__name__
        if source == "Wikidata":
            assert out["notable"] is None


def test_wikidata_failing_on_its_second_request_is_failed(monkeypatch):
    def override(s, r):
        if s == "Wikidata" and r.url.params.get("action") == "wbgetentities":
            return httpx.Response(503, text="busy")

    replay(monkeypatch, LINUS, override=override)
    out = search("Linus Torvalds")
    assert out["sources"]["Wikidata"]["state"] == "failed" and out["notable"] is None


def test_a_source_that_hangs_is_cut_off_and_reported_as_failed(monkeypatch):
    monkeypatch.setattr(ns, "SOURCE_TIMEOUT", 0.05)

    async def hang(client, q):
        await asyncio.sleep(5)

    monkeypatch.setattr(ns, "SOURCES", tuple((label, hang if label == "ORCID" else fn) for label, fn in ns.SOURCES))
    replay(monkeypatch, MARA)
    out = search("Mara Lindqvist")
    assert out["sources"]["ORCID"]["state"] == "failed" and out["sources"]["ORCID"]["error_code"] == "timeout"
    assert out["sources"]["OpenAlex"]["state"] == "ok"


def test_a_crash_inside_one_source_does_not_fail_the_search(monkeypatch):
    async def boom(client, q):
        raise RuntimeError("Mara Lindqvist should never be echoed")

    monkeypatch.setattr(ns, "SOURCES", tuple((label, boom if label == "Bluesky" else fn) for label, fn in ns.SOURCES))
    replay(monkeypatch, MARA)
    out = search("Mara Lindqvist")
    assert out["sources"]["Bluesky"]["state"] == "failed"
    assert out["sources"]["Bluesky"]["error_detail"] == "RuntimeError"
    assert len(out["candidates"]) == 10


# ---- single-token names ------------------------------------------------------------

SINGLE = {
    "github": {"total_count": 1, "incomplete_results": False,
               "items": [{"login": "Madonna", "avatar_url": "https://avatars.githubusercontent.com/u/990000201?v=4", "type": "User"}]},
    "wikidata_search": {"query": {"searchinfo": {"totalhits": 4210}, "search": [{"title": "Q1744"}, {"title": "Q990000301"}, {"title": "Q990000302"}]}},
    "wikidata_entities": {"entities": {
        "Q1744": {"labels": {"en": {"value": "Madonna"}}, "descriptions": {"en": {"value": "American singer and actress (born 1958)"}},
                  "aliases": {"en": [{"value": "Madonna Louise Ciccone"}]}, "sitelinks": {"enwiki": {"title": "Madonna"}}},
        "Q990000301": {"labels": {"en": {"value": "Madonna Fixture"}}, "descriptions": {"en": {"value": "invented person"}}},
        "Q990000302": {"labels": {"en": {"value": "Someone Else"}}, "descriptions": {"en": {"value": "invented fan of Madonna"}}},
    }},
    "bluesky": {"actors": [
        {"handle": "madonna.fixture-social.example", "displayName": "M", "avatar": "https://cdn.bsky.app/img/avatar/plain/x/y"},
        {"handle": "queenofpop.fixture-social.example", "displayName": "Madonna"},
        {"handle": "madonnafan.fixture-social.example", "displayName": "Madonna Fan Club"},
        {"handle": "other.fixture-social.example", "displayName": "Other", "description": "I love Madonna"},
    ]},
}


def test_single_token_name_is_flagged_and_asks_fewer_sources(monkeypatch):
    calls = []
    replay(monkeypatch, SINGLE, calls)
    out = search("Madonna")
    assert out["parsed"] == {"given": "Madonna", "middle": "", "family": "", "suffix": "", "single_token": True}
    assert set(out["sources"]) == {"Wikidata", "GitHub", "Bluesky"}
    assert {s for s, _ in calls} == {"Wikidata", "GitHub", "Bluesky"} and len(calls) == 4
    assert out["handles"] == [{"value": "madonna", "pattern": "name"}]
    # GitHub is asked for the one account with exactly this login, not for everyone named so.
    assert next(r for s, r in calls if s == "GitHub").url.params["q"] == "user:madonna"
    assert [(c["source"], c["handle"], c["name_match"]) for c in out["candidates"]] == [
        ("Wikidata", "Q1744", "exact"),
        ("GitHub", "Madonna", "exact"),
        ("Bluesky", "madonna.fixture-social.example", "exact"),
        ("Bluesky", "queenofpop.fixture-social.example", "exact"),
        ("Wikidata", "Q990000301", "tokens"),
    ]
    assert out["notable"]["wikipedia"] == "https://en.wikipedia.org/wiki/Madonna"
    assert out["sources"]["Wikidata"]["total"] == 4210
    assert not any(IMAGE_RE.search(s) for s in strings(out))


def test_single_token_with_no_such_github_login_is_none_not_failed(monkeypatch):
    replay(monkeypatch, SINGLE, override=lambda s, r: httpx.Response(422, json={"message": "Validation Failed"}) if s == "GitHub" else None)
    out = search("Madonna")
    assert out["sources"]["GitHub"] == {"state": "none", "count": 0, "shown": 0, "total": 0}


def test_single_token_in_a_script_with_no_ascii_form_skips_the_github_request(monkeypatch):
    calls = []
    replay(monkeypatch, {**SINGLE, "wikidata_search": EMPTY["wikidata_search"], "bluesky": EMPTY["bluesky"]}, calls)
    out = search("李小龙")
    assert out["parsed"]["single_token"] is True and out["handles"] == []
    # GitHub was not asked, so it says nothing: no entry, and above all not "none".
    assert "GitHub" not in {s for s, _ in calls}
    assert set(out["sources"]) == {"Wikidata", "Bluesky"}


def test_a_422_for_a_full_name_is_a_failure(monkeypatch):
    replay(monkeypatch, MARA, override=lambda s, r: httpx.Response(422, json={"message": "Validation Failed"}) if s == "GitHub" else None)
    assert search("Mara Lindqvist")["sources"]["GitHub"]["state"] == "failed"


# ---- cache -------------------------------------------------------------------------

def test_complete_result_is_cached_for_a_day(monkeypatch):
    calls = []
    replay(monkeypatch, LINUS, calls)
    first = search("Linus Torvalds")
    n = len(calls)
    again = search("  linus   TORVALDS ")           # same person, different typing
    assert len(calls) == n and again["cached"] is True and first["cached"] is False
    assert again["candidates"] == first["candidates"]
    (expires, _), = ns._cache.values()
    assert ns.CACHE_TTL_OK - 5 < expires - ns.time.time() <= ns.CACHE_TTL_OK == 86400


def test_cache_key_includes_the_qualifiers(monkeypatch):
    calls = []
    replay(monkeypatch, MARA, calls)
    plain = search("Mara Lindqvist")
    ranked = search("Mara Lindqvist", keyword="marine")
    assert len(calls) == 12 and ranked["cached"] is False
    assert plain["candidates"][0]["handle"] != ranked["candidates"][0]["handle"]
    assert search("Mara Lindqvist", keyword=" MARINE ")["cached"] is True and len(calls) == 12


def test_result_with_a_failed_source_is_kept_for_ten_minutes_only(monkeypatch):
    calls = []
    replay(monkeypatch, LINUS, calls, override=lambda s, r: httpx.Response(429) if s == "OpenAlex" else None)
    search("Linus Torvalds")
    (expires, _), = ns._cache.values()
    assert ns.CACHE_TTL_PARTIAL - 5 < expires - ns.time.time() <= ns.CACHE_TTL_PARTIAL == 600
    assert search("Linus Torvalds")["cached"] is True

    # Once it expires the search runs again, and a complete answer replaces it.
    now = ns.time.time()
    monkeypatch.setattr(ns.time, "time", lambda: now + 601)
    replay(monkeypatch, LINUS, calls)
    fresh = search("Linus Torvalds")
    assert fresh["cached"] is False and fresh["sources"]["OpenAlex"]["state"] == "ok"


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ns, "CACHE_MAX", 3)
    replay(monkeypatch, EMPTY)
    for family in ("Alpha", "Bravo", "Charlie", "Delta", "Echo"):
        search(f"Test {family}")
    assert len(ns._cache) == 3 and ("test alpha", "", "", "") not in ns._cache and ("test echo", "", "", "") in ns._cache


# ---- endpoint ----------------------------------------------------------------------

@pytest.fixture
def no_limit(monkeypatch):
    """These tests post more often than six times a minute; the limit has its own test."""
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "/api/recon/name-search", (10_000, 60))


def test_endpoint_returns_the_search(monkeypatch, no_limit):
    replay(monkeypatch, LINUS)
    with TestClient(app) as client:
        resp = client.post("/api/recon/name-search", json={"name": "  Linus  Torvalds ", "location": "", "employer": "", "keyword": ""})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Linus Torvalds" and body["notable"]["url"].endswith("Q34253") and len(body["candidates"]) == 13


def test_endpoint_takes_qualifiers(monkeypatch, no_limit):
    replay(monkeypatch, MARA)
    with TestClient(app) as client:
        body = client.post("/api/recon/name-search", json={"name": "Mara Lindqvist", "keyword": "marine"}).json()
    assert body["candidates"][0]["qualifier_hits"] == ["keyword"]


@pytest.mark.parametrize("body,status", [
    ({"name": ""}, 400), ({"name": "A"}, 400), ({"name": "12345"}, 400), ({"name": "john@example.com"}, 400),
    ({"name": "https://example.com/x"}, 400), ({"name": "John\nSmith"}, 400), ({"name": "x" * 81}, 400),
    ({"name": "x" * 201}, 422), ({}, 422), ({"name": None}, 422), ({"name": ["Linus Torvalds"]}, 422),
    ({"name": "Linus Torvalds", "location": "x" * 81}, 422), ({"name": "Linus Torvalds", "employer": "x" * 81}, 422),
    ({"name": "Linus Torvalds", "keyword": "x" * 81}, 422), ({"name": "Linus Torvalds", "keyword": 5}, 422),
])
def test_endpoint_validation_errors_reach_no_source(monkeypatch, no_limit, body, status):
    calls = []
    replay(monkeypatch, LINUS, calls)
    with TestClient(app) as client:
        resp = client.post("/api/recon/name-search", json=body)
    assert resp.status_code == status and calls == []
    if status == 400:
        assert resp.json()["detail"] == validate.PERSON_NAME_MSG
        assert "letters from any script" in resp.json()["detail"] and "are not accepted" in resp.json()["detail"]


def test_rate_limit_entry():
    assert match_limit("/api/recon/name-search") == ("/api/recon/name-search", 6, 60)


def test_seventh_search_in_a_minute_is_refused(monkeypatch):
    mw = rate_limit.RateLimitMiddleware(app=None)
    assert [mw.check("203.0.113.9", "/api/recon/name-search", now=100.0 + i) for i in range(6)] == [None] * 6
    assert mw.check("203.0.113.9", "/api/recon/name-search", now=107.0) is not None


# ---- logging -----------------------------------------------------------------------

def test_nothing_is_logged_with_the_name(monkeypatch, no_limit, caplog):
    secrets = ("mara", "lindqvist", "gothenburg", "uppsala", "marine")

    def override(s, r):
        if s == "GitHub":
            return httpx.Response(403, json={"message": "rate limit"})
        if s == "ORCID":
            raise httpx.ConnectError(f"cannot reach {r.url}")       # an error text that carries the name
        if s == "OpenAlex":
            return httpx.Response(500, text="Mara Lindqvist broke it")

    replay(monkeypatch, MARA, override=override)
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client:
            resp = client.post("/api/recon/name-search", json={
                "name": "Mara Lindqvist", "location": "Gothenburg", "employer": "Uppsala University", "keyword": "marine"})
            assert resp.status_code == 200
            bad = client.post("/api/recon/name-search", json={"name": "Mara Lindqvist 123"})
            assert bad.status_code == 400
    assert resp.json()["sources"]["GitHub"]["state"] == "rate_limited"
    assert any(r.name == "modules.name_search" for r in caplog.records)      # the failures were logged
    for record in caplog.records:
        fields = json.dumps({k: v for k, v in vars(record).items() if k != "exc_info"}, default=str).lower()
        text = record.getMessage().lower()
        for secret in secrets:
            assert secret not in fields and secret not in text, record
    # Nor does a failed source hand the name back inside its error detail.
    for src in resp.json()["sources"].values():
        assert "mara" not in src.get("error_detail", "").lower()


# ---- review round: one test per defect ---------------------------------------------

TEXT = json.loads((Path(__file__).parent / "fixtures" / "name_text.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("raw,folded", TEXT["fold"])
def test_fold_matches_the_shared_pairs(raw, folded):
    # tests/js/names.test.mjs asserts the same pairs against names.js.
    assert ns.fold(raw) == folded


def test_fold_keeps_the_marks_that_spell_a_name_outside_latin_greek_and_cyrillic():
    # Vowel signs, voicing marks and tone marks are letters there. Dropping them made these equal.
    for a, b in (("राम कुमार", "रोम कमीर"), ("ながの がく", "なかの かく"), ("パク ジソン", "ハク シソン"), ("สมชาย ใจดี", "สมชย จด")):
        assert ns.fold(a) != ns.fold(b), (a, b)
        assert ns.Query(a).match([b]) is None and ns.Query(a).match([a]) == "exact"
        assert len(ns.fold(a).split()) == 2          # a spacing mark no longer splits a word
    assert ns.fold("राम कुमार").split() == ["राम", "कुमार"]
    # Accents on Latin, Greek and Cyrillic letters are still ignored.
    assert ns.fold("José García") == ns.fold("Jose Garcia") and ns.fold("Ελένη") == ns.fold("Ελενη") and ns.fold("Алёна") == ns.fold("Алена")
    # The zero width non-joiner inside a Persian name is not a word break.
    assert ns.Query("علی‌رضا کریمی").match(["علیرضا کریمی"]) == "exact"


@pytest.mark.parametrize("raw,clean", TEXT["strip_images"])
def test_strip_images_matches_the_shared_pairs(raw, clean):
    assert ns.strip_images(raw) == clean


def test_a_picture_link_in_a_bio_is_dropped_whatever_follows_it(monkeypatch):
    data = json.loads(json.dumps(MARA))
    data["bluesky"]["actors"] = [{"handle": "mara.fixture-social.example", "displayName": "Mara Lindqvist",
                                  "description": "Me: ![me](https://img.fixture.example/me.png) and https://img.fixture.example/a.jpg, also https://img.fixture.example/b.webp."}]
    replay(monkeypatch, data)
    desc = by_source(search("Mara Lindqvist"), "Bluesky")[0]["description"]
    assert "img.fixture.example" not in desc and "![" not in desc and desc.startswith("Me:")


def test_a_directory_whose_rows_were_all_cut_by_the_cap_is_never_none(monkeypatch):
    # Four directories with 8 exact rows fill 32 of 30 places. Under the old cap GitHub's 8 rows
    # (tokens) were all cut and GitHub was reported as "none, count 0".
    many = json.loads(json.dumps(MARA))
    many["github"]["items"] = [{"login": f"mara-fx-{i}", "type": "User"} for i in range(8)]
    many["github"]["total_count"] = 8
    many["orcid"]["expanded-result"] = [{"orcid-id": f"0000-0000-0001-{i:04d}", "given-names": "Mara", "family-names": "Lindqvist"} for i in range(8)]
    many["openalex"]["results"] = [{"id": f"https://openalex.org/A7{i:04d}", "display_name": "Mara Lindqvist", "works_count": 1} for i in range(8)]
    many["bluesky"]["actors"] = [{"handle": f"mara{i}.fixture-social.example", "displayName": "Mara Lindqvist"} for i in range(8)]
    ids = [f"Q9900002{i:02d}" for i in range(8)]
    many["wikidata_search"]["query"]["search"] = [{"title": q} for q in ids]
    many["wikidata_entities"]["entities"] = {q: {"labels": {"en": {"value": "Mara Lindqvist"}}} for q in ids}
    replay(monkeypatch, many)
    out = search("Mara Lindqvist")
    gh = out["sources"]["GitHub"]
    assert gh == {"state": "ok", "count": 8, "shown": 6, "total": 8}
    assert len(by_source(out, "GitHub")) == 6 and len(out["candidates"]) == 30
    for label, s in out["sources"].items():
        assert s["state"] == "ok" and s["shown"] == len(by_source(out, label)) >= 1 and s["count"] == 8, label


def test_fair_cap_takes_from_every_source_in_turn():
    row = lambda s, i, m="exact": {"source": s, "handle": f"{s}{i}", "name_match": m, "qualifier_hits": []}
    a, b, c = [row("A", i) for i in range(8)], [row("B", i) for i in range(8)], [row("C", i, "partial") for i in range(2)]
    got = ns._fair_cap([a, b, c], 9)
    assert [r["handle"] for r in got] == ["A0", "A1", "A2", "A3", "B0", "B1", "B2", "C0", "C1"]
    assert [r["handle"] for r in ns._fair_cap([a, b, c], 3)] == ["A0", "B0", "C0"]
    assert len(ns._fair_cap([a, b, c], 30)) == 18            # under the cap nothing is cut


def test_a_one_word_name_with_no_ascii_form_does_not_report_github_at_all(monkeypatch):
    calls = []
    replay(monkeypatch, {**SINGLE, "wikidata_search": EMPTY["wikidata_search"], "bluesky": EMPTY["bluesky"]}, calls)
    out = search("Мадонна")
    assert "GitHub" not in out["sources"] and "GitHub" not in {s for s, _ in calls}
    assert not any(s["state"] == "not_asked" for s in out["sources"].values())
    # Every directory that was asked answered, so the result is complete and cached for a day.
    (expires, _), = ns._cache.values()
    assert expires - ns.time.time() > ns.CACHE_TTL_PARTIAL


def test_the_cache_keeps_spellings_apart(monkeypatch):
    calls = []
    replay(monkeypatch, MARA, calls)
    hyphen = search("Jean-Luc Picard")
    spaced = search("Jean Luc Picard")
    assert spaced["cached"] is False and len(calls) == 12
    assert hyphen["name"] == "Jean-Luc Picard" and spaced["name"] == "Jean Luc Picard"
    assert hyphen["parsed"]["given"] == "Jean-Luc" and spaced["parsed"] == {"given": "Jean", "middle": "Luc", "family": "Picard", "suffix": "", "single_token": False}
    assert hyphen["handles"] != spaced["handles"]
    accented, plain = search("José García"), search("Jose Garcia")
    assert plain["cached"] is False and accented["name"] == "José García" and plain["name"] == "Jose Garcia"
    # Case and spacing are still one entry, and the answer carries this request's spelling.
    again = search("  jean-luc   PICARD ")
    assert again["cached"] is True and again["name"] == "jean-luc PICARD" and again["parsed"]["family"] == "PICARD"


@pytest.mark.parametrize("name,given,family,suffix,orcid_family,handle", [
    ("John Smith Jr.", "John", "Smith", "Jr.", "Smith", "johnsmith"),
    ("John Smith jr", "John", "Smith", "jr", "Smith", "johnsmith"),
    ("John Smith III", "John", "Smith", "III", "Smith", "johnsmith"),
    ("Jane Doe PhD", "Jane", "Doe", "PhD", "Doe", "janedoe"),
    ("Jane Doe Ph.D.", "Jane", "Doe", "Ph.D.", "Doe", "janedoe"),
    ("Jane Q. Doe M.D.", "Jane", "Doe", "M.D.", "Doe", "janedoe"),
    ("Sam Lee Esq.", "Sam", "Lee", "Esq.", "Lee", "samlee"),
    ("Martin Luther King Jr. PhD", "Martin", "King", "Jr. PhD", "King", "martinking"),
])
def test_a_suffix_is_not_the_family_name(monkeypatch, name, given, family, suffix, orcid_family, handle):
    calls = []
    replay(monkeypatch, MARA, calls)
    out = search(name)
    assert (out["parsed"]["given"], out["parsed"]["family"], out["parsed"]["suffix"]) == (given, family, suffix)
    assert out["parsed"]["single_token"] is False and out["name"] == name
    orcid = next(r for s, r in calls if s == "ORCID").url.params["q"]
    assert orcid == f'given-names:"{given}" AND family-name:"{orcid_family}"'
    assert out["handles"][0] == {"value": handle, "pattern": "givenfamily"}
    assert not any(part in h["value"] for h in out["handles"] for part in ("jr", "iii", "phd", "esq"))
    # The suffix stays out of the other queries too.
    assert "Jr" not in next(r for s, r in calls if s == "GitHub").url.params["q"]


def test_suffix_edges():
    q = ns.Query("John Smith Jr.")
    assert q.match(["John Smith"]) == "exact" and q.match(["John Smith Jr"]) == "exact" and q.match(["John A. Smith Jr."]) == "tokens"
    # A suffix word in front, or a name that is only a suffix word, is a name.
    assert ns.parse_name("Iv Petrov")["family"] == "Petrov" and ns.parse_name("Iv Petrov")["suffix"] == ""
    assert ns.parse_name("Md") == {"given": "Md", "middle": "", "family": "", "suffix": "", "single_token": True}
    assert ns.parse_name("Smith Jr") == {"given": "Smith", "middle": "", "family": "", "suffix": "Jr", "single_token": True}
    # Digits are refused by the validator, so an ordinal like "3rd" never reaches the parser.
    with pytest.raises(HTTPException):
        validate.person_name("John Smith 3rd")


@pytest.mark.parametrize("raw,expected", [
    ("John Smith\t", "John Smith"), ("\n John Smith \r\n", "John Smith"),          # trimmed before the control check
    ("Gil·les Martí", "Gil·les Martí"),                                            # middle dot
    ("علی‌رضا کریمی", "علی‌رضا کریمی"),                                    # ZWNJ inside a Persian word stays
    ("ශ්‍රී ලංකා", "ශ්‍රී ලංකා"),                                          # ZWJ inside a Sinhala word stays
    ("John‍ Smith", "John Smith"), ("Jo‌hn Smith", "John Smith"),        # and is stripped anywhere else
    ("Or Cohen", "Or Cohen"), ("Anna OR Maria", "Anna OR Maria"), ("Not Sure", "Not Sure"),
])
def test_person_name_round_two_accepts(raw, expected):
    assert validate.person_name(raw) == expected


@pytest.mark.parametrize("raw", ["John\tSmith", "John\nSmith", "Z" + "́" * 5 + "algo Text", "à́̂̃̄ b", "‌‍", "· ·", "John​Smith"])
def test_person_name_round_two_rejects(raw):
    with pytest.raises(HTTPException) as exc:
        validate.person_name(raw)
    assert exc.value.detail == validate.PERSON_NAME_MSG
    for allowed in ("letters from any script", "hyphens", "apostrophes", "periods", "middle dot"):
        assert allowed in exc.value.detail


def test_four_marks_on_a_letter_are_still_a_name():
    assert validate.person_name("Nguyễn Văn An") == "Nguyễn Văn An"
    assert validate.person_name("à́̂̃ b")                     # exactly the cap


def test_a_boolean_operator_in_a_name_is_searched_as_a_word(monkeypatch):
    calls = []
    replay(monkeypatch, MARA, calls)
    out = search("Or Cohen AND")
    assert out["name"] == "Or Cohen AND"
    wikidata = next(r for s, r in calls if s == "Wikidata").url.params["srsearch"]
    openalex = next(r for s, r in calls if s == "OpenAlex").url.params["search"]
    assert wikidata == "Or Cohen and haswbstatement:P31=Q5" and openalex == "Or Cohen and"
    assert ns.plain_query("Anna OR Maria NOT Sure") == "Anna or Maria not Sure" and ns.plain_query("Or Cohen") == "Or Cohen"
