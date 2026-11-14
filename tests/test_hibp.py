"""Breach lookups, from responses recorded on 2026-11-14 (tests/fixtures/breaches). No network."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from modules import hibp

FIX = Path(__file__).parent / "fixtures" / "breaches"
CHECK = json.loads((FIX / "xon_check_email.json").read_text())
CATALOGUE = json.loads((FIX / "xon_catalogue.json").read_text())
EMAIL = "torvalds@linux-foundation.org"


def fake_client(calls, *, check=(200, CHECK), catalogue=(200, CATALOGUE)):
    """An httpx.AsyncClient stand-in that serves the two XposedOrNot endpoints."""
    class Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

        async def get(self, url, headers=None):
            kind = "catalogue" if url == hibp.CATALOGUE_URL else "check"
            calls.append(kind)
            status, body = catalogue if kind == "catalogue" else check
            if isinstance(body, Exception):
                raise body
            return httpx.Response(status, json=body, request=httpx.Request("GET", url))
    return Client


@pytest.fixture(autouse=True)
def _fresh():
    hibp.clear_cache_for_tests()
    yield
    hibp.clear_cache_for_tests()


def run(monkeypatch, calls=None, **kw):
    monkeypatch.setattr(hibp.httpx, "AsyncClient", fake_client(calls if calls is not None else [], **kw))
    return asyncio.run(hibp.run_hibp(EMAIL))


def test_breaches_carry_date_data_classes_and_link(monkeypatch):
    out = run(monkeypatch)
    assert out["total"] == 10 and out["source"] == "XposedOrNot" and out["details"] == "ok" and "error" not in out
    by = {b["name"]: b for b in out["breaches"]}
    assert set(by) == set(CHECK["breaches"][0])
    li = by["LinkedIn"]
    assert (li["date"], li["year"], li["domain"], li["verified"], li["sensitive"]) == ("2012-05-01", 2012, "linkedin.com", True, False)
    assert li["data_classes"] == ["Email addresses", "Passwords"] and li["records"] == 160042644
    assert li["url"] == "https://en.wikipedia.org/wiki/2012_LinkedIn_hack"          # the catalogue's reference
    assert by["Evite"]["url"] == "https://xposedornot.com/breach/Evite"             # none given: the source's own page
    assert by["1.4BillionRecords"]["url"].startswith("https://www.forbes.com/")
    assert by["AntiPublicCombo"]["verified"] is False and by["AntiPublicCombo"]["domain"] == ""
    assert all(set(b) >= {"name", "date", "year", "data_classes", "records", "verified", "sensitive", "domain", "url"} for b in out["breaches"])


def test_breaches_are_sorted_newest_first(monkeypatch):
    out = run(monkeypatch)
    dates = [b["date"] for b in out["breaches"]]
    assert dates == sorted(dates, reverse=True)
    assert out["breaches"][0]["name"] == "Chess-2026" and out["breaches"][-1]["name"] == "LinkedIn"


def test_undated_and_unknown_breaches_go_last():
    cat = hibp.index_catalogue(CATALOGUE)
    rows = hibp.build_breaches(["LinkedIn", "NotInTheCatalogue", "CyrusOne"], cat)
    assert [r["name"] for r in rows] == ["CyrusOne", "LinkedIn", "NotInTheCatalogue"]
    last = rows[-1]
    assert (last["date"], last["year"], last["records"], last["verified"], last["sensitive"], last["data_classes"]) == ("", None, None, None, None, [])
    assert last["url"] == "https://xposedornot.com/breach/NotInTheCatalogue"


def test_sensitive_breach_is_marked():
    row = hibp.breach_row("Zoosk-2020", hibp.index_catalogue(CATALOGUE)["zoosk-2020"])
    assert row["sensitive"] is True and row["year"] == 2020


def test_reference_url_must_be_http():
    row = hibp.breach_row("X", {"breachID": "X", "referenceURL": "javascript:alert(1)", "breachedDate": "not a date", "exposedRecords": "many"})
    assert row["url"] == "https://xposedornot.com/breach/X" and row["date"] == "" and row["records"] is None


@pytest.mark.parametrize("catalogue", [(500, {"error": "x"}), (200, {"exposedBreaches": []}), (200, httpx.ReadTimeout("slow"))])
def test_names_survive_a_failed_catalogue_lookup(monkeypatch, catalogue):
    out = run(monkeypatch, catalogue=catalogue)
    assert out["total"] == 10 and out["details"] == "unavailable" and "error" not in out
    assert sorted(b["name"] for b in out["breaches"]) == sorted(CHECK["breaches"][0])
    assert all(b["date"] == "" and b["year"] is None and b["url"].startswith("https://xposedornot.com/breach/") for b in out["breaches"])


def test_catalogue_is_fetched_once_and_failures_back_off(monkeypatch):
    calls = []
    run(monkeypatch, calls)
    run(monkeypatch, calls)
    assert calls == ["check", "catalogue", "check"]
    hibp.clear_cache_for_tests()
    calls = []
    run(monkeypatch, calls, catalogue=(503, {}))
    out = run(monkeypatch, calls, catalogue=(503, {}))
    assert calls == ["check", "catalogue", "check"] and out["details"] == "unavailable"


def test_address_in_no_breach_is_not_an_error(monkeypatch):
    calls = []
    out = run(monkeypatch, calls, check=(404, {"Error": "Not found"}))
    assert out == {"email": EMAIL, "total": 0, "source": "XposedOrNot", "breaches": [], "details": "ok"}
    assert calls == ["check"]                                   # no catalogue download for an empty answer


@pytest.mark.parametrize("check,code", [((429, {}), "rate_limited"), ((200, httpx.ConnectTimeout("slow")), "timeout"), ((500, {}), "upstream")])
def test_failed_check_is_an_error_not_a_clean_result(monkeypatch, check, code):
    out = run(monkeypatch, check=check)
    assert out["error_code"] == code and out["breaches"] == [] and "details" not in out


def test_single_breach_given_as_a_string(monkeypatch):
    out = run(monkeypatch, check=(200, {"breaches": "LinkedIn"}))
    assert out["total"] == 1 and out["breaches"][0]["year"] == 2012


def test_route_returns_the_new_shape(monkeypatch):
    monkeypatch.setattr(hibp.httpx, "AsyncClient", fake_client([]))
    with TestClient(app) as c:
        r = c.post("/api/recon/hibp", json={"email": EMAIL}, headers={"x-forwarded-for": "198.51.100.61"})
    body = r.json()
    assert r.status_code == 200 and body["total"] == 10 and body["breaches"][0]["name"] == "Chess-2026"
    assert isinstance(body["breaches"][0]["data_classes"], list)
