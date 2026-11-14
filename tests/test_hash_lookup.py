"""Hash lookups. Source responses were recorded on 2026-11-14 (tests/fixtures/hash). No network."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from routers import hash_lookup as hl
from routers.hash_lookup import detect_hash_type

FIX = Path(__file__).parent / "fixtures" / "hash"
load = lambda name: json.loads((FIX / name).read_text())
OTX, OTX_ANALYSIS, CIRCL, UNAUTHORIZED, BEFORE = (load(n) for n in (
    "eicar_otx_general.json", "eicar_otx_analysis.json", "eicar_circl.json", "abusech_unauthorized.json", "eicar_endpoint_before.json"))

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
OTHER = "a" * 64

# What the four sources answered for EICAR on the day of the audit.
EICAR_ANSWERS = {
    "malware_bazaar": (401, UNAUTHORIZED["body"]), "threatfox": (401, UNAUTHORIZED["body"]),
    "circl": (200, CIRCL), "alienvault": (200, OTX), "alienvault_analysis": (200, OTX_ANALYSIS),
}
NOTHING = {"malware_bazaar": (200, {"query_status": "hash_not_found"}), "threatfox": (200, {"query_status": "no_result"}),
           "circl": (404, {"message": "Non existing"}), "alienvault": (200, {"pulse_info": {"count": 0, "pulses": []}}),
           "alienvault_analysis": (200, {"analysis": None})}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    hl.clear_cache_for_tests()
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    yield
    hl.clear_cache_for_tests()


def lookup(monkeypatch, h, answers, calls=None):
    async def fake_fetch(client, source, value, hash_type):
        if calls is not None:
            calls.append(source)
        got = answers[source]
        if isinstance(got, Exception):
            raise got
        return got

    monkeypatch.setattr(hl, "_fetch", fake_fetch)
    return asyncio.run(hl.lookup(h, detect_hash_type(h)))


@pytest.mark.parametrize(
    "value, expected",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
        ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", "SHA1"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256"),
        ("  d41d8cd98f00b204e9800998ecf8427e  ", "MD5"),
    ],
)
def test_detect_hash_type_valid(value, expected):
    assert detect_hash_type(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-hash",
        "d41d8cd98f00b204e9800998ecf8427",          # 31 chars
        "d41d8cd98f00b204e9800998ecf8427ez",         # non-hex char
        "0123456789abcdef0123456789abcdef0123456789abcdef",  # 48 chars
    ],
)
def test_detect_hash_type_invalid(value):
    assert detect_hash_type(value) is None


# ---- the EICAR test file ---------------------------------------------------------------

def test_the_audit_recording_is_the_bug():
    # What the endpoint said before the fix: community tags presented as malware families.
    assert BEFORE["verdict"] == "MALICIOUS" and "Tsara Brashears" in BEFORE["malware_families"]


@pytest.mark.parametrize("h", [EICAR_MD5, EICAR_SHA1, EICAR_SHA256, EICAR_MD5.upper()])
def test_eicar_is_a_test_file_by_any_hash(monkeypatch, h):
    out = lookup(monkeypatch, h.lower(), EICAR_ANSWERS)
    assert out["verdict"] == "TEST_FILE"
    assert out["known_test_file"]["name"] == "EICAR antivirus test file" and "not malware" in out["known_test_file"]["note"]
    assert out["malware_families"] == [] and out["family"] == "" and out["family_sources"] == []


def test_eicar_community_tags_are_not_families(monkeypatch):
    out = lookup(monkeypatch, EICAR_MD5, EICAR_ANSWERS)
    for name in BEFORE["malware_families"]:          # Tsara Brashears, Mitre Attack, ET, Beach Research, TrojanSpy
        assert name not in out["malware_families"] and name not in out["alienvault"]["malware_families"]
        assert name in out["community_tags"]
    assert out["alienvault"]["pulse_count"] == 50 and out["alienvault"]["whitelisted"] is True
    assert out["alienvault"]["av_detections"] == {"ClamAV": "Eicar-Test-Signature", "Microsoft Defender": "Virus:DOS/EICAR_Test_File"}


def test_eicar_file_facts_come_from_the_sources_that_have_them(monkeypatch):
    out = lookup(monkeypatch, EICAR_MD5, EICAR_ANSWERS)
    assert (out["file_name"], out["file_size"], out["file_type"]) == ("eicar.com", 68, "EICAR virus test files")
    assert out["first_seen"] <= out["last_seen"] and len(out["first_seen"]) == 10
    assert out["detection"] is None                  # no keyless source publishes a ratio
    assert out["circl"]["known_malicious"] is True and out["circl"]["known_malicious_source"] == "malshare.com"


def test_abusech_without_a_key_is_failed_not_missing(monkeypatch):
    out = lookup(monkeypatch, EICAR_MD5, EICAR_ANSWERS)
    for key in ("malware_bazaar", "threatfox"):
        assert out[key]["found"] is None and out[key]["error_code"] == "auth" and "key" in out[key]["error"]
    assert out["failed_sources"] == ["MalwareBazaar", "ThreatFox"]


# ---- families and verdicts for everything else -----------------------------------------------

def test_cloned_pulses_do_not_make_a_consensus():
    agreed, unconfirmed = hl.otx_families(OTX["pulse_info"]["pulses"])
    # Three pulses carry these names, but they are copies of one pulse.
    for name in ("Tsara Brashears", "Beach Research", "TrojanSpy", "Mitre Attack", "ET"):
        assert name in unconfirmed and name not in agreed
    assert "eicar" in unconfirmed                     # one pulse, one author


def test_two_independent_authors_make_a_family():
    pulses = [{"id": "1", "author": {"username": "a"}, "malware_families": [{"display_name": "Emotet"}, {"display_name": "Malware"}]},
              {"id": "2", "author": {"username": "b"}, "malware_families": [{"display_name": "emotet"}, {"display_name": "Malware"}]},
              {"id": "3", "author": {"username": "a"}, "malware_families": [{"display_name": "QakBot"}]},
              {"id": "4", "author": {"username": "a"}, "malware_families": [{"display_name": "QakBot"}]}]
    agreed, unconfirmed = hl.otx_families(pulses)
    assert agreed == ["Emotet"] and sorted(unconfirmed) == ["Malware", "QakBot"]


def test_family_needs_a_structured_source_and_names_who_said_it(monkeypatch):
    mb = {"query_status": "ok", "data": [{"file_name": "invoice.exe", "file_type": "exe", "file_size": 123456, "signature": "AgentTesla",
                                           "tags": ["exe", "AgentTesla", "spam"], "first_seen": "2025-03-04 10:11:12", "last_seen": "2025-06-01 00:00:00", "reporter": "r"}]}
    tf = {"query_status": "ok", "data": [{"malware_printable": "Agent Tesla", "ioc_type": "sha256_hash", "first_seen": "2025-03-05 01:00:00 UTC", "last_seen": None}]}
    out = lookup(monkeypatch, OTHER, {**NOTHING, "malware_bazaar": (200, mb), "threatfox": (200, tf)})
    assert out["verdict"] == "MALICIOUS" and out["known_test_file"] is None
    assert out["family"] == "AgentTesla" and out["family_sources"] == ["MalwareBazaar", "ThreatFox"]
    assert out["malware_families"] == ["AgentTesla"]
    assert (out["file_name"], out["file_type"], out["file_size"], out["first_seen"], out["last_seen"]) == ("invoice.exe", "exe", 123456, "2025-03-04", "2025-06-01")
    assert "spam" in out["community_tags"] and out["failed_sources"] == []


def test_pulses_alone_make_no_family_and_are_ignored_when_whitelisted(monkeypatch):
    pulses = {"pulse_info": {"count": 5, "pulses": [{"id": str(i), "author": {"username": "a"}, "tags": ["apt"], "malware_families": [{"display_name": "Some Person"}],
                                                      "created": "2026-01-02T00:00:00"} for i in range(5)]}}
    out = lookup(monkeypatch, OTHER, {**NOTHING, "alienvault": (200, pulses)})
    assert out["verdict"] == "MALICIOUS" and out["verdict_basis"] == ["5 OTX community pulses mention it"]
    assert out["family"] == "" and out["malware_families"] == [] and out["community_tags"] == ["Some Person", "apt"]
    white = {**pulses, "validation": [{"source": "whitelist", "name": "Whitelisted hash"}]}
    assert lookup(monkeypatch, OTHER, {**NOTHING, "alienvault": (200, white)})["verdict"] == "UNKNOWN"


def test_known_file_is_clean_and_no_source_is_unknown(monkeypatch):
    known = lookup(monkeypatch, OTHER, {**NOTHING, "circl": (200, {"FileName": "notepad.exe", "FileSize": "1024"})})
    assert known["verdict"] == "CLEAN" and known["file_size"] == 1024 and known["circl"]["known_malicious"] is False
    nothing = lookup(monkeypatch, OTHER, NOTHING)
    assert nothing["verdict"] == "UNKNOWN" and nothing["failed_sources"] == [] and nothing["file_size"] is None
    assert all(nothing[k]["found"] is False for k in ("malware_bazaar", "circl", "alienvault", "threatfox"))


# ---- verdicts when abuse.ch cannot be asked (the default: no ABUSECH_AUTH_KEY) --------------

NO_KEY = {**NOTHING, "malware_bazaar": (401, UNAUTHORIZED["body"]), "threatfox": (401, UNAUTHORIZED["body"])}
NOT_ASKED = "MalwareBazaar and ThreatFox could not be asked"


def test_unknown_without_a_key_says_who_was_not_asked(monkeypatch):
    out = lookup(monkeypatch, OTHER, NO_KEY)
    assert out["verdict"] == "UNKNOWN" and out["sources_answered"] == 2
    assert out["verdict_basis"] == [f"not seen by the 2 sources that answered; {NOT_ASKED}"]
    assert out["failed_sources"] == ["MalwareBazaar", "ThreatFox"]


def test_clean_without_a_key_needs_circl_and_names_the_gap(monkeypatch):
    out = lookup(monkeypatch, OTHER, {**NO_KEY, "circl": (200, {"FileName": "notepad.exe", "FileSize": "1024"})})
    assert out["verdict"] == "CLEAN"
    assert out["verdict_basis"] == ["CIRCL lists this as a known file", f"not listed as malicious by the 2 sources that answered; {NOT_ASKED}"]
    assert not any("no source lists it" in line for line in out["verdict_basis"])


def test_no_listing_is_never_clean_without_the_known_file_signal(monkeypatch):
    # CIRCL itself failed: nothing positive is left, whatever the other sources say
    out = lookup(monkeypatch, OTHER, {**NO_KEY, "circl": httpx.ReadTimeout("slow")})
    assert out["verdict"] == "UNKNOWN" and out["sources_answered"] == 1
    assert out["verdict_basis"] == ["not seen by the 1 source that answered; MalwareBazaar, CIRCL and ThreatFox could not be asked"]
    # CIRCL knows the file but a malware feed lists it: not clean
    listed = lookup(monkeypatch, OTHER, {**NO_KEY, "circl": (200, {"FileName": "x.exe", "KnownMalicious": "malshare.com"})})
    assert listed["verdict"] == "MALICIOUS"
    # every source failed
    dead = lookup(monkeypatch, OTHER, {**NO_KEY, "circl": (500, None), "alienvault": (500, None)})
    assert dead["verdict"] == "UNKNOWN" and dead["sources_answered"] == 0 and dead["verdict_basis"][0].startswith("no source answered; ")


def test_malicious_without_a_key_still_names_the_gap(monkeypatch):
    out = lookup(monkeypatch, OTHER, {**NO_KEY, "circl": (200, {"FileName": "x.exe", "KnownMalicious": "malshare.com"})})
    assert out["verdict"] == "MALICIOUS"
    assert out["verdict_basis"] == ["CIRCL lists it as known malicious (malshare.com)", NOT_ASKED]


def test_all_four_answering_says_so(monkeypatch):
    assert lookup(monkeypatch, OTHER, NOTHING)["verdict_basis"] == ["not seen by any of the 4 sources"]
    known = lookup(monkeypatch, OTHER, {**NOTHING, "circl": (200, {"FileName": "notepad.exe"})})
    assert known["verdict_basis"] == ["CIRCL lists this as a known file", "not listed as malicious by any of the 4 sources"]


def test_a_source_that_fails_is_not_a_negative(monkeypatch):
    out = lookup(monkeypatch, OTHER, {**NOTHING, "circl": httpx.ReadTimeout("slow"), "alienvault": (429, None), "alienvault_analysis": httpx.ConnectError("x")})
    assert out["circl"]["found"] is None and out["circl"]["error_code"] == "timeout"
    assert out["alienvault"]["found"] is None and out["alienvault"]["error_code"] == "rate_limited"
    assert out["failed_sources"] == ["CIRCL", "AlienVault OTX"] and out["verdict"] == "UNKNOWN"
    assert "slow" not in out["circl"]["error"]


def test_failed_analysis_page_does_not_lose_the_pulses(monkeypatch):
    out = lookup(monkeypatch, EICAR_MD5, {**EICAR_ANSWERS, "alienvault_analysis": httpx.ReadTimeout("slow")})
    assert out["alienvault"]["pulse_count"] == 50 and "error" not in out["alienvault"] and out["file_type"] == "text/plain"


# ---- route -------------------------------------------------------------------------------

def test_route_shape_and_cache(monkeypatch):
    calls = []

    async def fake_fetch(client, source, value, hash_type):
        calls.append(source)
        return EICAR_ANSWERS[source]

    monkeypatch.setattr(hl, "_fetch", fake_fetch)
    with TestClient(app) as c:
        hdr = {"x-forwarded-for": "198.51.100.62"}
        a = c.post("/api/hash/hash", json={"hash": EICAR_MD5.upper()}, headers=hdr).json()
        b = c.post("/api/hash/hash", json={"hash": EICAR_MD5}, headers=hdr).json()
        assert c.post("/api/hash/hash", json={"hash": "xyz"}, headers=hdr).status_code == 400
    assert a["verdict"] == "TEST_FILE" and a["cached"] is False and b["cached"] is True and len(calls) == 5
    for key in ("hash", "hash_type", "malware_bazaar", "circl", "alienvault", "threatfox", "virustotal_url", "malware_families", "verdict",
                "known_test_file", "family", "family_sources", "detection", "file_type", "file_name", "file_size", "first_seen", "last_seen", "community_tags"):
        assert key in a, key


def test_a_blip_is_not_cached(monkeypatch):
    calls = []

    async def fake_fetch(client, source, value, hash_type):
        calls.append(source)
        if source == "circl":
            raise httpx.ReadTimeout("slow")
        return NOTHING[source]

    monkeypatch.setattr(hl, "_fetch", fake_fetch)
    with TestClient(app) as c:
        hdr = {"x-forwarded-for": "198.51.100.63"}
        c.post("/api/hash/hash", json={"hash": OTHER}, headers=hdr)
        assert c.post("/api/hash/hash", json={"hash": OTHER}, headers=hdr).json()["cached"] is False
    assert len(calls) == 10
