"""Phone lookup: offline numbering facts, the worker that reads them in a child process, the
NPA-NXX source from answers recorded on 2026-11-14 (tests/fixtures/phone), and NumLookup with
the visitor's key. No network."""

import asyncio
import functools
import json
import logging
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core import validate
from main import app
from modules import phone_lookup as pl
from modules import phone_plan as plan

FIX = Path(__file__).parent / "fixtures" / "phone"
XML = {k: (FIX / f"lcg_{k}.xml").read_text() for k in ("202_456", "202_555", "604_687")}
WHITE_HOUSE = "+1 202 456 1111"          # a public switchboard


def fake_client(calls, *, npa=None, numlookup=None):
    """A real httpx.AsyncClient on a mock transport, so the request the module builds is the
    request that is inspected and nothing reaches the network. `npa` and `numlookup` are
    (status, body) or an exception; None means that service must not be called at all."""
    def handler(request):
        base = str(request.url.copy_with(query=None))
        calls.append({"url": base, "full": str(request.url), "params": dict(request.url.params), "headers": dict(request.headers)})
        answer = npa if base == pl.NPA_URL else numlookup if request.url.host == "api.numlookupapi.com" else None
        if answer is None:
            raise RuntimeError("unexpected request")
        if isinstance(answer, Exception):
            raise answer
        status, body = answer
        return httpx.Response(status, **({"json": body} if isinstance(body, (dict, list)) else {"content": body if isinstance(body, bytes) else body.encode()}))
    return functools.partial(REAL_CLIENT, transport=httpx.MockTransport(handler))


REAL_CLIENT = httpx.AsyncClient
REAL_WORKER = pl._worker
WORKER_CALLS = []


async def inline_worker(raw, region):
    """What the worker answers, computed in this process: the tests of the facts themselves do
    not need a child process each. The worker tests below use the real one."""
    WORKER_CALLS.append((raw, region))
    try:
        return {"result": json.loads(json.dumps(plan.offline_facts(raw, region)))}
    except plan.PhoneInputError as e:
        return {"bad_input": str(e)}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    pl.clear_cache_for_tests()
    WORKER_CALLS.clear()
    monkeypatch.setattr(pl, "_worker", inline_worker)
    # Nothing in this file may reach the network: a test that needs a service installs its own fake.
    monkeypatch.setattr(pl.httpx, "AsyncClient", fake_client([]))
    yield
    pl.clear_cache_for_tests()


def look(monkeypatch, number, *, region="US", key=None, calls=None, **kw):
    monkeypatch.setattr(pl.httpx, "AsyncClient", fake_client(calls if calls is not None else [], **kw))
    return asyncio.run(pl.lookup(number, region, key))


def codes(out):
    return {f["code"]: f["level"] for f in out["findings"]}


# ---- input ---------------------------------------------------------------------------------
@pytest.mark.parametrize("raw", ["+1 202 456 1111", "(202) 456-1111", "202.456.1111", "1-800-FLOWERS", "0044 20 7946 0958",
                                 "+1 202 456 1111 ext. 22", "202-456-1111 x22", "911", "+44 (0)20 7946 0958", "  2535551234 "])
def test_validate_accepts_how_people_write_numbers(raw):
    assert validate.phone(raw) == " ".join(raw.split())


@pytest.mark.parametrize("raw", ["", "   ", "hello there", "abc 253 def 555 ghi 1234", "call me", "+", "5", "x" * 41, "2024561111<script>",
                                 "202 456 1111\n", "user@example.com", "++1 202", "1" * 41])
def test_validate_refuses_nonsense(raw):
    if raw == "202 456 1111\n":
        assert validate.phone(raw) == "202 456 1111"       # a trailing line break is trimmed, not refused
        return
    with pytest.raises(HTTPException) as e:
        validate.phone(raw)
    assert e.value.status_code == 400 and "phone number" in e.value.detail


def test_region_hint_is_two_letters():
    assert validate.phone_region(None) == "US" and validate.phone_region(" gb ") == "GB"
    for bad in ["GBR", "4", "U$"]:
        with pytest.raises(HTTPException):
            validate.phone_region(bad)
    with pytest.raises(plan.PhoneInputError):
        plan.offline_facts("020 7946 0958", "ZZ")


# ---- offline facts, per number ------------------------------------------------------------------
def test_us_geographic_number():
    o = plan.offline_facts(WHITE_HOUSE)
    n, a = o["number"], o["assignment"]
    assert o["parsed"] and o["kind"] == "number" and o["valid"] is True
    assert (n["e164"], n["international"], n["national"]) == ("+12024561111", "+1 202-456-1111", "(202) 456-1111")
    assert (n["calling_code"], n["region"], n["country"]) == (1, "US", "United States")
    assert n["possible"] and n["valid"] and n["possible_reason"] is None and n["validity_text"].startswith("Valid:")
    # The US plan cannot tell a fixed line from a mobile, and says so.
    assert n["line_type"] == "fixed_line_or_mobile" and n["line_type_text"] == "Fixed line or mobile" and "cannot say which" in n["line_type_note"]
    assert a["area"] == "Washington D.C." and "not where the phone" in a["area_note"]
    assert a["carrier"] is None and a["prefix"] == "202-456"       # the library has no carriers for the US
    assert n["utc_offsets"] in (["UTC-5"], ["UTC-4"]) and n["utc_offset_text"] == n["utc_offsets"][0] and "time_zones" not in n
    assert n["region_assumed"] is False and n["extension"] is None
    assert codes(o) == {"valid": "ok"}
    # The old top-level keys are still there, filled from the offline data.
    assert (o["valid"], o["country"], o["country_code"], o["location"], o["carrier"], o["line_type"], o["normalized"]) == (True, "United States", "US", "Washington D.C.", None, "Fixed line or mobile", "+12024561111")
    assert o["sources"]["numbering_plan"]["state"] == "ok" and "Who uses this number" in o["owner_note"]


def test_us_toll_free_belongs_to_no_country_or_place():
    o = plan.offline_facts("+1 800 356 9377")
    assert o["valid"] and o["number"]["line_type"] == "toll_free" and o["line_type"] == "Toll free"
    assert o["country_code"] is None and o["country"] == "North America (+1)"
    assert o["assignment"]["area"] is None and o["assignment"]["prefix"] is None and o["number"]["utc_offsets"] == [] and o["number"]["utc_offset_text"] is None
    assert codes(o) == {"valid": "ok", "toll_free": "info"}


def test_us_fiction_number():
    o = plan.offline_facts("+1 202 555 0143")
    assert o["number"]["fiction"] is True and codes(o) == {"fiction": "flag"}
    f = o["findings"][0]
    assert "reserved for fiction" in f["detail"] and "not in use" in f["detail"] and f["title"] == "Reserved for fiction"
    assert plan.offline_facts("+1 202 555 1212")["number"]["fiction"] is False        # 555-1212 is directory assistance
    assert plan.offline_facts("+1 202 555 0200")["number"]["fiction"] is False


def test_canadian_number():
    o = plan.offline_facts("+1 604 687 1234")
    assert (o["country"], o["country_code"], o["location"]) == ("Canada", "CA", "Vancouver, BC")
    assert o["assignment"]["prefix"] == "604-687" and o["number"]["utc_offsets"] in (["UTC-8"], ["UTC-7"])


def test_uk_landline_and_mobile():
    land = plan.offline_facts("+44 121 234 5678")
    assert (land["country_code"], land["line_type"], land["location"]) == ("GB", "Fixed line", "Birmingham")
    assert land["number"]["national"] == "0121 234 5678" and land["assignment"]["prefix"] is None and land["number"]["line_type_note"] is None
    mob = plan.offline_facts("+44 7400 123456")
    assert (mob["country_code"], mob["line_type"], mob["location"]) == ("GB", "Mobile", None)
    # The range's first assignee, with the porting caveat beside it.
    assert mob["assignment"]["carrier"] == "Three" and mob["carrier"] == "Three" and "ported" in mob["assignment"]["carrier_note"]
    assert mob["search_links"] and all(l["group"] == "search engine" for l in mob["search_links"])


@pytest.mark.parametrize("raw, where", [("+44 20 7946 0958", "London"), ("+44 7700 900123", "mobile"), ("+44 1632 960123", "no area"), ("+44 8081 570123", "freephone")])
def test_uk_drama_ranges(raw, where):
    o = plan.offline_facts(raw)
    f = next(f for f in o["findings"] if f["code"] == "fiction")
    assert f["level"] == "flag" and "Ofcom" in f["detail"] and where in f["detail"] and "reserved for fiction" in f["detail"]
    assert "valid" not in codes(o) and "invalid" not in codes(o)      # one statement, not two that disagree


@pytest.mark.parametrize("raw, who", [("+61 2 5550 1234", "ACMA"), ("+61 3 7010 9876", "ACMA"), ("+61 7 5550 0000", "ACMA"), ("+61 8 7010 4321", "ACMA"),
                                      ("+353 20 912 3456", "ComReg"), ("020 918 7654", "ComReg")])
def test_australian_and_irish_drama_ranges(raw, who):
    o = plan.offline_facts(raw, "IE" if who == "ComReg" else "US")
    f = next(f for f in o["findings"] if f["code"] == "fiction")
    assert f["level"] == "flag" and who in f["detail"] and "reserved for fiction" in f["detail"] and o["number"]["fiction"] is True


@pytest.mark.parametrize("raw", ["+61 2 5551 1234", "+61 2 7011 1234", "+61 4 5550 1234", "+61 412 345 678", "+61 491 570 156", "+353 20 812 3456", "+353 21 912 3456",
                                 "+353 1 209 1234", "+44 20 7946 1958", "+44 20 7947 0958", "+44 7700 901123", "+1 202 555 0200", "+44 121 496 1234",
                                 "+44 28 9018 0123", "+44 28 9649 6123", "+353 89 011 0123", "+61 1800 160 401"])
def test_numbers_beside_a_drama_range_are_not_flagged(raw):
    # A wrong "reserved for fiction" on a real number is worse than a missing one.
    assert plan.offline_facts(raw)["number"]["fiction"] is False


@pytest.mark.parametrize("raw, iso, carrier, area", [
    ("+49 1512 3456789", "DE", "T-Mobile", None), ("+91 98765 43210", "IN", "Airtel", None),
    ("+55 11 91234 5678", "BR", None, "São Paulo"), ("+61 412 345 678", "AU", "Optus", None)])
def test_mobiles_in_other_countries(raw, iso, carrier, area):
    o = plan.offline_facts(raw)
    assert o["valid"] and o["country_code"] == iso and o["line_type"] == "Mobile" and o["number"]["line_type"] == "mobile"
    assert o["assignment"]["carrier"] == carrier and o["assignment"]["area"] == area
    assert (o["assignment"]["carrier_note"] is not None) == (carrier is not None)


def test_premium_voip_and_personal_numbers_are_flagged():
    prem = plan.offline_facts("+1 900 234 5678")
    assert prem["line_type"] == "Premium rate" and codes(prem)["premium_rate"] == "flag"
    assert "charged at a premium" in next(f["detail"] for f in prem["findings"] if f["code"] == "premium_rate")
    voip = plan.offline_facts("+44 5600 123456")
    assert voip["line_type"] == "VoIP" and codes(voip)["voip"] == "flag" and "easy to get and discard" in voip["findings"][-1]["detail"]
    assert plan.offline_facts("+33 9 12 34 56 78")["number"]["line_type"] == "voip"
    pers = plan.offline_facts("+44 70 1234 5678")
    assert pers["line_type"] == "Personal number" and codes(pers)["personal_number"] == "flag" and "easy to get and discard" in pers["findings"][-1]["detail"]


def test_possible_and_valid_are_two_things():
    short = plan.offline_facts("+44 20 7946")
    assert short["parsed"] and short["valid"] is False and short["number"]["possible"] is False
    assert short["normalized"] is None and short["number"]["e164"] is None and short["search_links"] == []
    assert plan.offline_facts("+44 12")["number"]["possible_reason"] == "too short for the United Kingdom"
    assert plan.offline_facts("+44 20 7946 09588888")["number"]["possible_reason"] == "too long for the United Kingdom"
    # The right length, and no range that starts with these digits.
    nope = plan.offline_facts("+1 555 555 1234")
    assert nope["number"]["possible"] is True and nope["valid"] is False and "no number range" in nope["number"]["validity_text"]
    assert codes(nope) == {"invalid": "flag"} and nope["line_type"] is None and nope["assignment"]["prefix"] is None
    cc = plan.offline_facts("+999 123456789")
    assert cc["parsed"] is False and cc["valid"] is False and codes(cc) == {"invalid": "flag"} and "country code" in cc["number"]["validity_text"]


def test_extension_vanity_and_international_prefix():
    ext = plan.offline_facts("+1 202 456 1111 ext. 22")
    assert ext["number"]["extension"] == "22" and ext["number"]["e164"] == "+12024561111" and codes(ext)["extension"] == "info"
    van = plan.offline_facts("1-800-FLOWERS")
    assert van["number"]["e164"] == "+18003569377" and van["number"]["vanity"] is True and codes(van)["vanity"] == "info"
    for raw, region in [("0044 20 7946 0958", "US"), ("011 44 20 7946 0958", "US"), ("0011 44 20 7946 0958", "AU"), ("00 44 20 7946 0958", "DE")]:
        o = plan.offline_facts(raw, region)
        assert o["number"]["e164"] == "+442079460958" and o["number"]["region_assumed"] is False, raw


def test_no_country_code_uses_the_hint_and_says_so():
    us = plan.offline_facts("2535551234")
    assert us["number"]["e164"] == "+12535551234" and us["number"]["region_assumed"] is True
    assert us["number"]["assumed_text"] == "No country code given, read as a United States number."
    assert codes(us)["assumed_country"] == "info"
    gb = plan.offline_facts("0121 234 5678", "GB")
    assert gb["number"]["e164"] == "+441212345678" and gb["number"]["assumed_text"] == "No country code given, read as a United Kingdom number."
    assert plan.offline_facts("030 123456", "DE")["number"]["assumed_text"] == "No country code given, read as a number from Germany."
    # The same digits without the hint are not a United States number, and the answer says which country was tried.
    wrong = plan.offline_facts("0121 234 5678")
    assert wrong["valid"] is False and wrong["country_code"] == "US" and wrong["number"]["possible_reason"] == "too long for the United States"
    # Digits that only make a number with the country code first are read that way, and the answer says so.
    bare = plan.offline_facts("447400123456")
    assert bare["number"]["e164"] == "+447400123456" and codes(bare)["assumed_plus"] == "info" and bare["number"]["region_assumed"] is False
    assert plan.offline_facts("1 202 456 1111")["number"]["region_assumed"] is False


def test_short_codes_and_emergency_numbers_are_not_subscriber_numbers():
    e = plan.offline_facts("911")
    assert e["kind"] == "emergency" and e["valid"] is False and e["normalized"] is None and e["search_links"] == [] and e["assignment"] is None
    assert codes(e) == {"emergency": "flag"} and "not a subscriber number" in e["findings"][0]["detail"] and "the United States" in e["findings"][0]["detail"]
    assert plan.offline_facts("112", "DE")["kind"] == "emergency" and plan.offline_facts("999", "GB")["kind"] == "emergency"
    s = plan.offline_facts("611")
    assert s["kind"] == "short_code" and codes(s) == {"short_code": "info"} and s["line_type"] == "Short code"
    assert plan.offline_facts("101", "GB")["kind"] == "short_code" and plan.offline_facts("116123", "GB")["kind"] == "short_code"
    assert plan.offline_facts("12")["kind"] == "number"            # not a service: just too short
    # Five digits fit the library's catch-all pattern for text-message codes. That is not the
    # library saying what the code is, so a ZIP code is not called a service.
    for raw in ["90210", "46645", "12345"]:
        z = plan.offline_facts(raw)
        assert z["kind"] == "number" and z["valid"] is False and codes(z)["invalid"] == "flag", raw
        assert z["number"]["validity_text"] == "Not valid: not a phone number for the United States. It is too short, and it is not a service number the numbering data lists."


def test_search_links_are_free_pages_with_the_search_kind():
    links = plan.offline_facts(WHITE_HOUSE)["search_links"]
    assert [l["site"] for l in links] == ["Google", "Bing", "DuckDuckGo", "800notes", "WhoCallsMe"]
    assert all(l["kind"] == "search" and l["url"].startswith("https://") and l["label"] for l in links)
    g = links[0]["url"]
    assert g == "https://www.google.com/search?q=%22%28202%29+456-1111%22+OR+%22202-456-1111%22+OR+%22%2B1+202-456-1111%22+OR+%22%2B12024561111%22"
    assert links[3]["url"] == "https://800notes.com/Phone.aspx/1-202-456-1111"
    # No data broker, and none of the pages that wanted a login or a payment.
    text = " ".join(l["url"] + l["site"] for l in links).lower()
    for gone in ["spokeo", "whitepages", "beenverified", "truecaller", "numverify", "calleridtest", "nomorobo", "youmail", "shouldianswer"]:
        assert gone not in text


# ---- the NPA-NXX source -----------------------------------------------------------------------
def test_block_found_adds_rate_centre_and_first_assignee(monkeypatch):
    calls = []
    o = look(monkeypatch, WHITE_HOUSE, calls=calls, npa=(200, XML["202_456"]))
    a, src = o["assignment"], o["sources"]["npa_nxx"]
    assert src["state"] == "ok" and src["name"] == "Local Calling Guide" and src["asked"] == "202-456" and src["cached"] is False
    assert (a["rate_centre"], a["region"], a["company"], a["ocn"], a["block_assigned"]) == ("Washington Zone 1", "DC", "VERIZON WASHINGTON DC, INC.", "9211", True)
    assert a["evidence_url"] == "https://localcallingguide.com/lca_prefix.php?npa=202&nxx=456" and "ported" in a["carrier_note"]
    # No coordinates and no switch: the range is described, nothing is placed on a map.
    assert not any(k in str(o) for k in ("38.89", "-77.03", "WASHDCMTDS0"))
    ca = look(monkeypatch, "+1 604 687 1234", npa=(200, XML["604_687"]))
    assert (ca["assignment"]["rate_centre"], ca["assignment"]["region"], ca["assignment"]["company"]) == ("Vancouver", "BC", "TELUS COMMUNICATIONS, INC. - BC")


def test_only_the_area_code_and_exchange_leave_the_server(monkeypatch):
    calls = []
    look(monkeypatch, "+1 202 456 1111 ext. 22", calls=calls, npa=(200, XML["202_456"]))
    assert len(calls) == 1
    sent = calls[0]
    assert sent["url"] == "https://localcallingguide.com/xmlprefix.php" and sent["params"] == {"npa": "202", "nxx": "456"}
    # This is the request httpx actually built: its whole URL and every header.
    assert sent["full"] == "https://localcallingguide.com/xmlprefix.php?npa=202&nxx=456" and sent["headers"]["user-agent"] == "Crawlr/0.1"
    wire = sent["full"] + " ".join(f"{k}={v}" for k, v in sent["headers"].items())
    assert "1111" not in wire and "2024561111" not in wire and "22" not in sent["full"]


def test_block_not_listed_is_unassigned_and_a_failure_is_not(monkeypatch):
    # The recorded answer for a block the service does not list (it has no prefixdata row).
    none = look(monkeypatch, "+1 202 999 1234", npa=(200, XML["202_555"]))
    assert none["sources"]["npa_nxx"]["state"] == "none" and none["assignment"]["block_assigned"] is False
    assert codes(none)["unassigned_block"] == "flag" and none["assignment"]["company"] is None
    pl.clear_cache_for_tests()
    for answer, state, code in [(httpx.ConnectTimeout("slow"), "failed", "timeout"), ((500, "oops"), "failed", "upstream"),
                                ((200, "<html>maintenance</html>"), "failed", "bad_response"), ((429, ""), "rate_limited", "rate_limited")]:
        pl.clear_cache_for_tests()
        o = look(monkeypatch, "+1 202 999 1234", npa=answer)
        src = o["sources"]["npa_nxx"]
        assert (src["state"], src["error_code"]) == (state, code) and src["error"], answer
        assert o["assignment"]["block_assigned"] is None and "unassigned_block" not in codes(o)
        assert o["valid"] is True and o["location"] == "Washington D.C."        # the offline facts stand
        assert "slow" not in str(o) and "oops" not in str(o)


def test_block_answers_are_cached_and_a_rate_limit_pauses_the_source(monkeypatch):
    calls = []
    look(monkeypatch, WHITE_HOUSE, calls=calls, npa=(200, XML["202_456"]))
    again = look(monkeypatch, "+1 202 456 2222", calls=calls, npa=(200, XML["202_456"]))
    assert len(calls) == 1 and again["sources"]["npa_nxx"]["cached"] is True and again["assignment"]["rate_centre"] == "Washington Zone 1"
    look(monkeypatch, "+1 212 456 1234", calls=calls, npa=(429, ""))
    paused = look(monkeypatch, "+1 312 456 1234", calls=calls, npa=(200, XML["202_456"]))
    assert len(calls) == 2 and paused["sources"]["npa_nxx"]["state"] == "rate_limited"
    # Bounded, oldest out first.
    monkeypatch.setattr(pl, "NPA_CACHE_MAX", 2)
    pl.clear_cache_for_tests()
    for npa in ("202", "203", "204"):
        asyncio.run(pl.npa_nxx_lookup(npa, "456"))
    assert list(pl._npa_cache) == ["203-456", "204-456"]


def test_block_lookup_is_only_for_us_and_canadian_geographic_numbers(monkeypatch):
    for raw in ["+1 800 356 9377", "+1 888 234 5678", "+1 900 234 5678", "+1 500 234 5678", "+44 121 234 5678", "+1 242 302 1234", "+1 555 555 1234", "911", "+44 20 7946",
                "+1 202 555 1212", "+1 202 555 0143", "+1 202 555 7890", "+1 202 950 1234", "+1 202 976 1234", "+1 202 411 1234", "+1 604 555 1212"]:
        pl.clear_cache_for_tests()
        calls = []
        o = look(monkeypatch, raw, calls=calls)          # any request would fail the fake
        assert calls == [] and "npa_nxx" not in o["sources"], raw
    with pytest.raises(ValueError):
        asyncio.run(pl.npa_nxx_lookup("202", "000"))     # the service would answer with the whole area code
    assert pl.parse_npa_xml(XML["202_456"], "202", "457") is None


# ---- NumLookup: only with the visitor's key -------------------------------------------------------
NL = {"valid": True, "number": "12024561111", "country_code": "US", "location": "Washington", "carrier": "Verizon Communications", "line_type": "landline"}


def test_numlookup_absent_present_and_failing(monkeypatch):
    calls = []
    none = look(monkeypatch, WHITE_HOUSE, calls=calls, npa=(200, XML["202_456"]))
    assert "numlookup" not in none["sources"] and len(calls) == 1

    calls = []
    got = look(monkeypatch, WHITE_HOUSE, key="k-123", calls=calls, npa=(200, XML["202_456"]), numlookup=(200, NL))
    nl = got["sources"]["numlookup"]
    assert (nl["state"], nl["name"], nl["carrier"], nl["line_type"], nl["valid"]) == ("ok", "NumLookup", "Verizon Communications", "landline", True)
    # It adds to the result. The offline keys are not overwritten by it.
    assert got["carrier"] is None and got["line_type"] == "Fixed line or mobile" and got["location"] == "Washington D.C."
    sent = next(c for c in calls if "numlookupapi" in c["url"])
    assert sent["url"] in ("https://api.numlookupapi.com/v1/validate/+12024561111", "https://api.numlookupapi.com/v1/validate/%2B12024561111") and sent["params"] == {"apikey": "k-123"}

    for answer, code in [((401, {"message": "bad key"}), "auth"), (httpx.ReadTimeout("slow"), "timeout"), ((500, "x"), "upstream"), ((200, [1]), "bad_response")]:
        pl.clear_cache_for_tests()
        bad = look(monkeypatch, WHITE_HOUSE, key="k-123", npa=(200, XML["202_456"]), numlookup=answer)
        nl = bad["sources"]["numlookup"]
        assert (nl["state"], nl["error_code"]) == ("failed", code) and "carrier" not in nl
        assert bad["valid"] is True and bad["assignment"]["rate_centre"] == "Washington Zone 1" and bad["line_type"] == "Fixed line or mobile"
        assert "k-123" not in str(bad) and "bad key" not in str(bad)
    # Not asked about digits that cannot be a number.
    calls = []
    look(monkeypatch, "+44 20 7946", key="k-123", calls=calls)
    assert calls == []


# ---- the endpoint ------------------------------------------------------------------------------
def test_endpoint_shape_bad_input_and_region(monkeypatch):
    monkeypatch.setattr(pl.httpx, "AsyncClient", fake_client([], npa=(200, XML["202_456"])))
    with TestClient(app) as c:
        r = c.post("/api/phone/lookup", json={"phone": WHITE_HOUSE})
        assert r.status_code == 200
        j = r.json()
        assert {"input", "parsed", "kind", "normalized", "valid", "country", "country_code", "location", "carrier", "line_type",
                "number", "assignment", "findings", "sources", "search_links", "owner_note"} == set(j)
        assert "lookup_links" not in j and j["assignment"]["company"] == "VERIZON WASHINGTON DC, INC."
        assert c.post("/api/phone/lookup", json={"phone": "0121 234 5678", "region": "gb"}).json()["normalized"] == "+441212345678"
        assert c.post("/api/phone/lookup", json={"phone": "0121 234 5678"}).json()["valid"] is False     # the same digits read as a United States number
        for bad in [{"phone": "hello there"}, {"phone": ""}, {"phone": "abc 253 def 555 ghi 1234"}, {"phone": "2024561111", "region": "Z1"}, {"phone": "2024561111", "region": "ZZ"}]:
            r = c.post("/api/phone/lookup", json=bad)
            assert r.status_code == 400 and isinstance(r.json()["detail"], str), bad
        assert c.post("/api/phone/lookup", json={"phone": "1" * 41}).status_code == 422


def test_nothing_logs_the_number(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(pl.httpx, "AsyncClient", fake_client([], npa=httpx.ConnectTimeout("slow"), numlookup=(401, {})))
    with TestClient(app) as c:
        assert c.post("/api/phone/lookup", json={"phone": WHITE_HOUSE}, headers={"X-Numlookup-Key": "k-123"}).status_code == 200
        assert c.post("/api/phone/lookup", json={"phone": "hello 2024561111"}).status_code == 400
    text = caplog.text + " ".join(str(r.__dict__) for r in caplog.records)
    for secret in ["2024561111", "456 1111", "456-1111", "4561111", "k-123"]:
        assert secret not in text


def test_httpx_cannot_log_a_request_line_at_the_apps_levels(monkeypatch, caplog):
    # httpx logs "HTTP Request: GET <url>" at INFO, and the NumLookup URL holds the number and
    # the key. core/logging.py holds httpx and httpcore at WARNING. These are real httpx clients
    # on a mock transport, so that request-line logging is exercised and has to stay silent.
    from core.logging import configure_logging
    configure_logging()
    assert logging.getLogger("httpx").level == logging.WARNING and logging.getLogger("httpcore").level == logging.WARNING
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    caplog.set_level(logging.DEBUG)                 # the root logger, as wide open as it can be
    calls = []
    for npa, nl in [((200, XML["202_456"]), (200, NL)), ((500, "x"), (401, {})),
                    (httpx.ConnectError("could not connect to https://localcallingguide.com/xmlprefix.php?npa=202&nxx=456"),
                     httpx.ConnectError("all attempts failed for https://api.numlookupapi.com/v1/validate/+12024561111?apikey=k-123"))]:
        pl.clear_cache_for_tests()
        o = look(monkeypatch, WHITE_HOUSE, key="k-123", calls=calls, npa=npa, numlookup=nl)
        assert "k-123" not in json.dumps(o) and "apikey" not in json.dumps(o) and "validate/" not in json.dumps(o)
    assert len(calls) == 6 and any("apikey=k-123" in c["full"] for c in calls)           # the key did travel in a URL
    text = caplog.text + " ".join(str(r.__dict__) for r in caplog.records)
    for secret in ["2024561111", "k-123", "apikey", "HTTP Request", "numlookupapi", "xmlprefix"]:
        assert secret not in text, secret


# ---- the AI prompt ---------------------------------------------------------------------------
def test_prompt_describes_the_number_and_never_an_owner(monkeypatch):
    from routers.analyze import TARGET_FOCUS, AnalyzeRequest, investigation_prompt
    o = look(monkeypatch, WHITE_HOUSE, key="k", npa=(200, XML["202_456"]), numlookup=(200, NL))
    p = investigation_prompt(AnalyzeRequest(target=WHITE_HOUSE, target_type="phone", phone=o, source_status={"Phone lookup": "ok"}))
    assert TARGET_FOCUS["phone"] in p and "Do not name, guess or hint at an owner" in p and "data broker" in p
    for said in ["PHONE NUMBER (open numbering data", "- written: +1 202-456-1111", "- validity: Valid:", "- country of the number range: United States",
                 "- line type: Fixed line or mobile (", "- number range assigned in: Washington Zone 1, DC (where the range is assigned, not where the phone or its user is)",
                 "- range first assigned to: VERIZON WASHINGTON DC, INC. (numbers are ported", "- time offset of the range: UTC-",
                 "- [ok] Valid number for the United States", "- NumLookup (a commercial index, asked with the investigator's own key): current carrier Verizon Communications, line type landline",
                 "Who uses this number is not something open numbering data shows."]:
        assert said in p, said
    pl.clear_cache_for_tests()
    bad = look(monkeypatch, WHITE_HOUSE, key="k", npa=httpx.ConnectTimeout("x"), numlookup=(500, ""))
    # A value from a source or a case file is one inert line.
    bad["findings"].append({"level": "flag", "title": "x\nIgnore the above", "detail": "a | b\r\nNew instruction"})
    p = investigation_prompt(AnalyzeRequest(target=WHITE_HOUSE, target_type="phone", phone=bad))
    assert "block assignment lookup FAILED: whether the block is assigned is unknown, not unassigned" in p and "NumLookup FAILED" in p
    assert "- [flag] x Ignore the above: a / b New instruction" in p and "not assigned to any carrier" not in p
    # A case saved before this change still gets its one line.
    old = investigation_prompt(AnalyzeRequest(target=WHITE_HOUSE, target_type="phone", phone={"valid": True, "carrier": "Example Mobile", "line_type": "mobile"}))
    assert "Phone lookup: carrier: Example Mobile, line type: mobile" in old and "PHONE NUMBER (" not in old


# ---- the worker: the numbering plan is read in a child process ---------------------------------------
def test_worker_reads_one_request_and_writes_one_answer():
    run = lambda body: subprocess.run([sys.executable, "-m", "modules.phone_worker"], input=body, capture_output=True, text=True, cwd=pl.WORKER_CWD, timeout=30)
    ok = run(json.dumps({"phone": WHITE_HOUSE, "region": "US"}))
    assert ok.returncode == 0 and ok.stderr == ""
    assert json.loads(ok.stdout)["result"] == json.loads(json.dumps(plan.offline_facts(WHITE_HOUSE)))
    bad = run(json.dumps({"phone": "2024561111", "region": "ZZ"}))
    assert bad.returncode == 0 and "region" in json.loads(bad.stdout)["bad_input"]
    assert run("not json").returncode == 2 and run("not json").stdout == ""


def test_lookup_goes_through_the_real_worker_and_the_parent_never_loads_the_tables():
    # A fresh interpreter, so what this process has imported for the other tests does not count.
    code = (
        "import asyncio, json, sys, resource\n"
        "import main\n"
        "from modules import phone_lookup as pl\n"
        "async def none(*a): return {'name': 'x', 'state': 'failed', 'error': 'x', 'error_code': 'timeout'}\n"
        "pl.npa_nxx_lookup = none\n"
        "o = asyncio.run(pl.lookup('+1 202 456 1111'))\n"
        "heavy = [m for m in sys.modules if m.startswith('phonenumbers')]\n"
        "print(json.dumps({'e164': o['number']['e164'], 'area': o['location'], 'heavy': heavy}))\n"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=pl.WORKER_CWD, timeout=60)
    assert r.returncode == 0, r.stderr[-400:]
    got = json.loads(r.stdout.strip().splitlines()[-1])
    assert got["e164"] == "+12024561111" and got["area"] == "Washington D.C."
    assert got["heavy"] == []          # not the geocoder, the carrier or time zone tables, nor the library at all
    src = Path(pl.__file__).read_text()
    assert not re.search(r"^\s*(import|from)\s+(phonenumbers|modules\.phone_plan|modules import phone_plan)", src, flags=re.M)


def test_worker_failure_or_timeout_is_a_failed_source_never_not_valid(monkeypatch):
    monkeypatch.setattr(pl, "_worker", REAL_WORKER)
    for cmd, timeout, code in [([sys.executable, "-c", "import time; time.sleep(30)"], 0.4, "timeout"),
                               ([sys.executable, "-c", "import sys; sys.exit(3)"], 6, "unknown"),
                               ([sys.executable, "-c", "print('oops')"], 6, "bad_response"),
                               ([sys.executable, "-c", "print('{}')"], 6, "bad_response"),
                               (["/nonexistent/python"], 6, "not_installed")]:
        pl.clear_cache_for_tests()
        monkeypatch.setattr(pl, "WORKER_CMD", cmd)
        monkeypatch.setattr(pl, "WORKER_TIMEOUT", timeout)
        calls = []
        o = look(monkeypatch, WHITE_HOUSE, key="k-123", calls=calls)
        assert calls == []                                           # nothing else is asked
        assert o["error_code"] == code and o["error"] and o["sources"]["numbering_plan"]["state"] == "failed", cmd
        assert "valid" not in o and "number" not in o and "findings" not in o
        assert "2024561111" not in o["error"] + o["error_detail"]
        assert pl._plan_cache == {}                                   # a failure is not remembered
    with TestClient(app) as c:
        monkeypatch.setattr(pl, "WORKER_CMD", [sys.executable, "-c", "import sys; sys.exit(3)"])
        r = c.post("/api/phone/lookup", json={"phone": WHITE_HOUSE})
        assert r.status_code == 200 and r.json()["error_code"] == "unknown" and r.json()["sources"]["numbering_plan"]["state"] == "failed"


def test_plan_answers_are_cached_for_a_day_and_bounded(monkeypatch):
    look(monkeypatch, WHITE_HOUSE, npa=(200, XML["202_456"]))
    a = look(monkeypatch, "+1 (202) 456-1111", npa=(200, XML["202_456"]))        # the same number, written another way
    b = look(monkeypatch, "+1 202 456 1111", region="GB", npa=(200, XML["202_456"]))
    c = look(monkeypatch, "+1  202 456\t1111", npa=(200, XML["202_456"]))            # only the spacing differs: the same key
    assert WORKER_CALLS == [(WHITE_HOUSE, "US"), ("+1 (202) 456-1111", "US"), ("+1 202 456 1111", "GB")] and c["input"] == "+1  202 456\t1111" and a["number"]["e164"] == b["number"]["e164"] == c["number"]["e164"]
    a["findings"].clear(); a["number"]["e164"] = "x"                              # a caller cannot spoil the cached copy
    assert look(monkeypatch, WHITE_HOUSE, npa=(200, XML["202_456"]))["number"]["e164"] == "+12024561111"
    look(monkeypatch, "hello 12")                                                 # refused input is not cached either
    monkeypatch.setattr(pl.time, "time", lambda t=time.time(): t + pl.PLAN_TTL + 1)
    look(monkeypatch, WHITE_HOUSE, npa=(200, XML["202_456"]))
    assert WORKER_CALLS.count((WHITE_HOUSE, "US")) == 2
    monkeypatch.undo()
    monkeypatch.setattr(pl, "_worker", inline_worker)
    monkeypatch.setattr(pl, "PLAN_CACHE_MAX", 2)
    pl.clear_cache_for_tests()
    for raw in ["+44 121 234 5678", "+44 121 234 5679", "+44 121 234 5670"]:
        look(monkeypatch, raw)
    assert len(pl._plan_cache) == 2 and "+44 121 234 5678|US" not in pl._plan_cache and "+44 121 234 5670|US" in pl._plan_cache


def test_bad_input_from_the_worker_is_a_400_message(monkeypatch):
    with pytest.raises(pl.PhoneInputError) as e:
        look(monkeypatch, "2024561111", region="ZZ")
    assert "region" in str(e.value)


def test_at_most_two_workers_run_at_once(monkeypatch):
    live, peak = 0, 0

    async def slow(raw, region):
        nonlocal live, peak
        live += 1; peak = max(peak, live)
        await asyncio.sleep(0.05)
        live -= 1
        return await inline_worker(raw, region)

    async def many():
        monkeypatch.setattr(pl, "_worker", slow)
        return await asyncio.gather(*(pl.plan_facts(f"+44 121 234 56{i:02d}", "US") for i in range(8)))

    out = asyncio.run(many())
    assert peak == 2 == pl.WORKER_MAX and len(out) == 8 and all(o["valid"] for o in out)


# ---- the country list the page offers -----------------------------------------------------------
def test_region_list_for_the_page_matches_the_library():
    """static/v2/js/phone-regions.js is a generated copy of phone_plan.regions(). To refresh it:
    python -c "import json; from modules import phone_plan as p; print(json.dumps(p.regions(), ensure_ascii=False))"
    and paste the list into the file."""
    src = (Path(pl.WORKER_CWD) / "static" / "v2" / "js" / "phone-regions.js").read_text(encoding="utf-8")
    rows = json.loads(src[src.index("["):src.rindex("]") + 1])
    assert rows == plan.regions() and len(rows) > 200
    assert ["US", "United States"] in rows and ["GB", "United Kingdom"] in rows and all(re.fullmatch(r"[A-Z]{2}", r[0]) and r[1] for r in rows)
    assert [r[1] for r in rows] == sorted((r[1] for r in rows), key=plan._fold)


# ---- review fixes ---------------------------------------------------------------------------------
ZONE_NAME = re.compile(r"\b(?:Africa|America|Antarctica|Asia|Atlantic|Australia|Europe|Indian|Pacific|Etc)/[A-Za-z_]+")


@pytest.mark.parametrize("raw, offset", [("+372 5123 4567", ("UTC+2", "UTC+3")), ("+970 59 123 4567", ("UTC+2", "UTC+3")), ("+353 1 234 5678", ("UTC", "UTC+1")),
                                         ("+212 5 22 12 34 56", ("UTC", "UTC+1")), ("+61 3 9123 4567", ("UTC+10", "UTC+11")), ("+91 98765 43210", ("UTC+5:30",))])
def test_time_is_an_offset_and_never_a_zone_name(raw, offset, monkeypatch):
    # The library files Estonia under Europe/Bucharest, Dublin under Guernsey and London, Morocco
    # under Atlantic/Canary and Melbourne under Australia/Sydney. None of those places may be shown.
    o = look(monkeypatch, raw)
    assert o["number"]["utc_offsets"] and o["number"]["utc_offsets"][0] in offset and o["number"]["utc_offset_text"] in offset
    assert "time_zones" not in o["number"] and not ZONE_NAME.search(json.dumps(o))
    from routers.analyze import AnalyzeRequest, investigation_prompt
    p = investigation_prompt(AnalyzeRequest(target=raw, target_type="phone", phone=o))
    assert "- time offset of the range: UTC" in p and not ZONE_NAME.search(p) and "time zone" not in p


def test_offsets_are_computed_for_a_date_and_bounded():
    jan, jul = datetime(2026, 1, 15, tzinfo=timezone.utc), datetime(2026, 7, 15, tzinfo=timezone.utc)
    assert plan.utc_offsets(["Europe/Bucharest"], now=jan) == ["UTC+2"] and plan.utc_offsets(["Europe/Bucharest"], now=jul) == ["UTC+3"]
    assert plan.utc_offsets(["Europe/Guernsey", "Europe/Isle_of_Man", "Europe/London"], now=jan) == ["UTC"]        # three zones, one offset
    assert plan.utc_offsets(["Australia/Sydney", "Australia/Brisbane"], now=jan) == ["UTC+10", "UTC+11"]
    assert plan.utc_offsets(["Asia/Calcutta"], now=jan) == ["UTC+5:30"] and plan.utc_offsets(["America/St_Johns"], now=jan) == ["UTC-3:30"]
    assert plan.utc_offsets(["America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"], now=jan) == []   # more than three: not tied to a place
    assert plan.utc_offsets([], now=jan) == [] and plan.utc_offsets(["Not/AZone"], now=jan) == []
    au = plan.offline_facts("+61 2 9123 4567")["number"]
    assert au["utc_offset_text"] in ("UTC+10", "UTC+11") or " to " in au["utc_offset_text"]
    assert plan.offline_facts("+61 412 345 678")["number"]["utc_offsets"] == []                                        # an Australian mobile spans the continent


@pytest.mark.parametrize("raw, region, how", [
    ("00 44 121 234 5678", "US", "idd00"), ("00-44-121-234-5678", "US", "idd00"), ("(00) 44 121 234 5678", "US", "idd00"), ("0044 121 234 5678", "US", "idd00"), ("00 44 121 234 5678", "AU", "idd00"),
    ("00 44 121 234 5678", "GB", "idd"), ("00 44 121 234 5678", "DE", "idd"), ("011 44 121 234 5678", "US", "idd"), ("011-44-121-234-5678", "CA", "idd"),
    ("0011 44 121 234 5678", "AU", "idd"), ("0011-44-121-234-5678", "AU", "idd"), ("010 44 121 234 5678", "JP", "idd")])
def test_international_prefix_with_separators_and_per_country(raw, region, how):
    o = plan.offline_facts(raw, region)
    assert o["valid"] is True and o["number"]["e164"] == "+441212345678" and o["country_code"] == "GB" and o["number"]["region_assumed"] is False
    f = next(f for f in o["findings"] if f["code"] == "idd_prefix")
    assert f["level"] == "info" and "country code +44" in f["detail"] and "assumed_country" not in codes(o)
    if how == "idd00":
        assert f["title"] == "00 read as the international call prefix" and "most countries" in f["detail"]
    else:
        prefix = {"US": "011", "CA": "011", "AU": "0011", "JP": "010"}.get(region, "00")
        assert f["title"].startswith(f"{prefix} read as the international call prefix of ")


def test_another_countrys_prefix_is_not_guessed():
    # 0011 is Australia's prefix. Read as a United States number it is not 00 followed by country code 1.
    us = plan.offline_facts("0011 44 121 234 5678", "US")
    assert us["valid"] is False and us["number"]["e164"] is None and us["country_code"] == "US" and "idd_prefix" not in codes(us) and codes(us)["assumed_country"] == "info"
    assert not any("+11" in json.dumps(v) for v in us.values())
    assert plan.offline_facts("00 999 123 456 789", "US")["valid"] is False              # 00 and no country code that exists
    assert plan.offline_facts("011 44 121 234 5678", "GB")["valid"] is False             # 011 means nothing in the United Kingdom


def test_cache_key_keeps_inputs_that_parse_differently_apart(monkeypatch):
    slash = look(monkeypatch, "9/11")
    plain = look(monkeypatch, "911")
    assert plain["kind"] == "emergency" and slash["kind"] == "number" and slash["valid"] is False
    assert look(monkeypatch, "9/11")["kind"] == "number" and look(monkeypatch, "911")["kind"] == "emergency"
    spaced = look(monkeypatch, "00 44 121 234 5678")
    joined = look(monkeypatch, "0044 121 234 5678")
    assert [c[0] for c in WORKER_CALLS] == ["9/11", "911", "00 44 121 234 5678", "0044 121 234 5678"]
    assert spaced["input"] == "00 44 121 234 5678" and joined["input"] == "0044 121 234 5678" and set(pl._plan_cache) == {"9/11|US", "911|US", "00 44 121 234 5678|US", "0044 121 234 5678|US"}


def test_username_scans_do_not_starve_phone_lookups(monkeypatch):
    from core import subprocess_guard as guard
    src = Path(pl.__file__).read_text()
    assert "tool_slot" not in src and "subprocess_guard" not in src

    async def go():
        sem = guard._get_semaphore()
        for _ in range(guard.MAX_CONCURRENT_TOOLS):                # every tool slot is held, as by Sherlock and Maigret
            await sem.acquire()
        try:
            return await asyncio.wait_for(pl.lookup("+44 121 234 5678"), timeout=5)
        finally:
            for _ in range(guard.MAX_CONCURRENT_TOOLS):
                sem.release()

    monkeypatch.setattr(guard, "_semaphore", None)
    o = asyncio.run(go())
    monkeypatch.setattr(guard, "_semaphore", None)
    assert o["valid"] is True and "error" not in o


def test_waiting_too_long_for_a_worker_is_busy_and_a_failed_source(monkeypatch):
    async def slow(raw, region):
        await asyncio.sleep(0.6)
        return await inline_worker(raw, region)

    async def go():
        monkeypatch.setattr(pl, "_worker", slow)
        monkeypatch.setattr(pl, "WORKER_QUEUE_TIMEOUT", 0.15)
        return await asyncio.gather(*(pl.lookup(f"+44 121 234 56{i:02d}") for i in range(3)))

    out = asyncio.run(go())
    busy = [o for o in out if "error" in o]
    assert len(busy) == 1 and len([o for o in out if o.get("valid")]) == 2
    b = busy[0]
    assert b["error_code"] == "busy" and "Try again" in b["error"] and b["sources"]["numbering_plan"]["state"] == "failed" and "valid" not in b
    assert len(pl._plan_cache) == 2


def test_a_cancelled_or_timed_out_request_kills_its_worker(monkeypatch):
    monkeypatch.setattr(pl, "_worker", REAL_WORKER)
    monkeypatch.setattr(pl, "WORKER_CMD", [sys.executable, "-c", "import time; time.sleep(60)"])
    procs = []
    real = asyncio.create_subprocess_exec

    async def spawn(*a, **k):
        p = await real(*a, **k)
        procs.append(p)
        return p

    async def cancelled():
        monkeypatch.setattr(pl.asyncio, "create_subprocess_exec", spawn)
        task = asyncio.create_task(pl.lookup(WHITE_HOUSE))
        await asyncio.sleep(0.4)
        assert procs and procs[0].returncode is None               # the child is running
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.2)
        return procs[0].returncode

    assert asyncio.run(cancelled()) is not None                     # killed, not orphaned
    pl.clear_cache_for_tests(); procs.clear()

    async def timed_out():
        monkeypatch.setattr(pl, "WORKER_TIMEOUT", 0.3)
        o = await pl.lookup(WHITE_HOUSE)
        return o, procs[0].returncode

    o, code = asyncio.run(timed_out())
    assert o["error_code"] == "timeout" and code is not None
    # The semaphore place came back both times.
    monkeypatch.setattr(pl, "_worker", inline_worker)
    assert asyncio.run(pl.lookup("+44 121 234 5678"))["valid"] is True


def test_timeout_leaves_room_for_a_cold_start_and_the_app_warms_one_worker(monkeypatch):
    assert pl.WORKER_TIMEOUT == 20 and pl.WORKER_QUEUE_TIMEOUT == 10 and pl.WORKER_MAX == 2
    asyncio.run(pl.warm(delay=0))
    assert WORKER_CALLS == [("+1 202 555 0100", "US")] and pl._plan_cache == {}         # a fictional number, nothing kept
    assert plan.offline_facts(pl.WARM_NUMBER)["number"]["fiction"] is True

    async def boom(raw, region):
        raise pl.PlanUnavailable("timeout")
    monkeypatch.setattr(pl, "_worker", boom)
    asyncio.run(pl.warm(delay=0))                                                         # a failure is swallowed

    async def never_blocks():
        t = asyncio.create_task(pl.warm(delay=30))
        await asyncio.sleep(0.05)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    asyncio.run(never_blocks())
    main_src = (Path(pl.WORKER_CWD) / "main.py").read_text()
    assert "asyncio.create_task(phone_lookup.warm())" in main_src and "warm.cancel()" in main_src and "await phone_lookup.warm" not in main_src
    with TestClient(app) as c:                                                             # startup does not wait for it
        assert c.get("/api/health").status_code == 200


def test_special_exchanges_are_named_and_never_called_unassigned(monkeypatch):
    calls = []
    da = look(monkeypatch, "+1 202 555 1212", calls=calls)
    assert calls == [] and "npa_nxx" not in da["sources"] and da["assignment"]["prefix"] is None and da["assignment"]["block_assigned"] is None
    assert codes(da) == {"valid": "ok", "directory_assistance": "info"} and "directory assistance number for area code 202" in da["findings"][-1]["detail"]
    other = look(monkeypatch, "+1 202 555 7890", calls=calls)
    assert codes(other) == {"valid": "ok", "special_exchange": "info"} and "Exchange 555" in other["findings"][-1]["detail"] and calls == []
    assert codes(look(monkeypatch, "+1 202 555 0143", calls=calls)) == {"fiction": "flag"} and calls == []
    for raw in ["+1 202 976 1234", "+1 202 950 1234"]:
        o = look(monkeypatch, raw, calls=calls)
        assert "unassigned_block" not in codes(o) and calls == [] and (not o["valid"] or codes(o).get("special_exchange") == "info")
    assert plan.special_exchange("2024111234") == "411" and plan.special_exchange("2029111234") == "911" and plan.special_exchange("2024561111") == ""
    # An ordinary block is still asked about.
    look(monkeypatch, WHITE_HOUSE, calls=calls, npa=(200, XML["202_456"]))
    assert len(calls) == 1


def test_old_mexican_mobile_form_is_read_without_the_1():
    o = plan.offline_facts("+52 1 55 1234 5678")
    assert o["valid"] is True and o["number"]["e164"] == "+525512345678" and o["country_code"] == "MX"
    f = next(f for f in o["findings"] if f["code"] == "legacy_prefix")
    assert f["level"] == "info" and "until 2019" in f["detail"] and "+52 55 1234 5678" in f["detail"]
    assert "legacy_prefix" not in codes(plan.offline_facts("+52 55 1234 5678")) and plan.offline_facts("+52 55 1234 5678")["valid"] is True
    bad = plan.offline_facts("+52 1 00 1234 5678")
    assert bad["valid"] is False and "legacy_prefix" not in codes(bad)                     # the 1 was not the only thing wrong
    assert plan.offline_facts("+54 9 11 2345 6789")["valid"] is True                       # Argentina's form already works


def test_pasted_numbers_are_cleaned_the_same_way_as_in_the_page():
    """tests/fixtures/phone_text.json is asserted by this suite and by tests/js/phone.test.mjs."""
    pairs = json.loads((Path(__file__).parent / "fixtures" / "phone_text.json").read_text())["pairs"]
    assert len(pairs) >= 12
    for raw, want in pairs:
        assert validate.phone_text(raw) == want, raw.encode("unicode_escape")
        if want:
            assert validate.phone(raw) == want
    lrm = chr(0x202A) + "+1 202" + chr(0x2011) + "456" + chr(0x2013) + "1111" + chr(0x202C)
    with TestClient(app) as c:
        j = c.post("/api/phone/lookup", json={"phone": lrm}).json()
        assert j["normalized"] == "+12024561111" and j["input"] == "+1 202-456-1111"
        assert c.post("/api/phone/lookup", json={"phone": "+1 202 456 1111;ext=22"}).json()["number"]["extension"] == "22"


def test_regions_without_a_library_name_are_named():
    names = dict(plan.regions())
    assert (names["XK"], names["TA"], names["AC"]) == ("Kosovo", "Tristan da Cunha", "Ascension Island")
    assert not [code for code, name in names.items() if name == code or re.fullmatch(r"[A-Z]{2}", name)]
    assert plan.offline_facts("+383 44 123 456")["country"] == "Kosovo"


def test_block_answer_is_read_with_a_size_cap(monkeypatch):
    big = XML["202_456"].replace("</root>", "<!-- " + "x" * (pl.NPA_MAX_BYTES + 10) + " --></root>")
    o = look(monkeypatch, WHITE_HOUSE, npa=(200, big))
    assert o["sources"]["npa_nxx"]["state"] == "failed" and o["sources"]["npa_nxx"]["error_code"] == "bad_response" and o["assignment"]["block_assigned"] is None
    src = Path(pl.__file__).read_text()
    assert "client.stream(" in src and "resp.text" not in src and pl._npa_cache == {}
