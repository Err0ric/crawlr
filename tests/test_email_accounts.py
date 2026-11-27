"""Email to accounts, replayed from tests/fixtures/email_accounts. No network.

mara_tidepool.json has the shape of the GitHub search answers recorded on 2026-11-26; every
person, login, address and repository in it is invented. tor_browser_primary.asc is the
primary key packet and user ID of the Tor Browser signing key, a public project key whose
fingerprint is published, kept as a known answer for the fingerprint. The other keys are
built here, packet by packet, for an invented person.
"""

import asyncio
import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from middleware import rate_limit
from middleware.rate_limit import match_limit
from modules import email_accounts as ea
from modules import github_email as ge
from modules import openpgp_keys as pgp

FIXTURES = Path(__file__).parent / "fixtures" / "email_accounts"
REAL_CLIENT = httpx.AsyncClient
DATA = json.loads((FIXTURES / "mara_tidepool.json").read_text(encoding="utf-8"))
EMAIL = DATA["email"]
TOR_KEY = (FIXTURES / "tor_browser_primary.asc").read_text(encoding="ascii")
SOURCE_OF = {"/search/commits": "github_commits", "/search/users": "github_users"}


# ---- a throwaway key, built by hand ------------------------------------------------

def packet(tag: int, body: bytes, old: bool = False) -> bytes:
    n = len(body)
    if old:
        return bytes([0x80 | (tag << 2) | 1]) + n.to_bytes(2, "big") + body
    if n < 192:
        length = bytes([n])
    elif n < 8384:
        length = bytes([((n - 192) >> 8) + 192, (n - 192) & 0xFF])
    else:
        length = b"\xff" + n.to_bytes(4, "big")
    return bytes([0xC0 | tag]) + length + body


def armor(data: bytes, crc: bool = True) -> str:
    b64 = base64.b64encode(data).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    tail = ["=AAAA"] if crc else []
    return "\n".join(["-----BEGIN PGP PUBLIC KEY BLOCK-----", "Comment: test key", "", *lines, *tail,
                      "-----END PGP PUBLIC KEY BLOCK-----", ""])


CREATED = int(datetime(2022, 5, 17, 10, 30, tzinfo=timezone.utc).timestamp())
ED25519_OID = bytes.fromhex("2b06010401da470f01")
# A version 4 EdDSA public key body: version, creation time, algorithm 22, curve OID, one MPI.
KEY_BODY = b"\x04" + CREATED.to_bytes(4, "big") + b"\x16" + bytes([len(ED25519_OID)]) + ED25519_OID \
    + (263).to_bytes(2, "big") + b"\x40" + bytes(range(32))
RSA_BODY = b"\x04" + CREATED.to_bytes(4, "big") + b"\x01" + (2048).to_bytes(2, "big") + b"\x80" + bytes(255) \
    + (17).to_bytes(2, "big") + b"\x01\x00\x01"
SIG = b"\x04\x13\x16\x08" + bytes(20)                 # a positive certification, body not checked
REVOCATION = b"\x04\x20\x16\x08" + bytes(20)
UID = "Mara Lindqvist (field notes) <mara@tidepool.example>".encode()
MARA_KEY = armor(packet(6, KEY_BODY) + packet(13, UID) + packet(2, SIG)
                 + packet(13, b"<mara@tidepool.example>") + packet(14, KEY_BODY) + packet(2, SIG))
MARA_FPR = hashlib.sha1(b"\x99" + len(KEY_BODY).to_bytes(2, "big") + KEY_BODY).hexdigest().upper()


# ---- replay ------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    ea.clear_cache_for_tests()
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    yield
    ea.clear_cache_for_tests()


def replay(monkeypatch, calls: list | None = None, override=None, commits=None, users=None, key=None):
    """Serve the recorded answers. `override(source, request)` may return a Response or raise."""

    def handler(request: httpx.Request):
        if request.url.host == "keys.openpgp.org":
            source = "openpgp"
        else:
            assert request.url.host == "api.github.com"
            source = SOURCE_OF[request.url.path]
        if calls is not None:
            calls.append((source, request))
        if override:
            resp = override(source, request)
            if resp is not None:
                return resp
        if source == "openpgp":
            if key is None:
                return httpx.Response(404, text=DATA["openpgp_404"])
            return httpx.Response(200, text=key, headers={"content-type": "application/pgp-keys"})
        if source == "github_commits":
            return httpx.Response(200, json=DATA["commits"] if commits is None else commits)
        return httpx.Response(200, json=DATA["users"] if users is None else users)

    monkeypatch.setattr(ea.httpx, "AsyncClient", lambda *a, **k: REAL_CLIENT(transport=httpx.MockTransport(handler)))


def run(email: str = EMAIL) -> dict:
    return asyncio.run(ea.run_email_accounts(email))


def all_urls(value) -> list[str]:
    if isinstance(value, dict):
        return [u for v in value.values() for u in all_urls(v)]
    if isinstance(value, list):
        return [u for v in value for u in all_urls(v)]
    return [value] if isinstance(value, str) and value.startswith("http") else []


# ---- the full answer ---------------------------------------------------------------

def test_full_result(monkeypatch):
    calls = []
    replay(monkeypatch, calls, key=MARA_KEY)
    out = run()

    assert set(out) == {"email", "cached", "accounts", "unattributed", "keys", "sources"}
    assert out["email"] == EMAIL and out["cached"] is False
    assert sorted(s for s, _ in calls) == ["github_commits", "github_users", "openpgp"]      # three requests, no more
    assert {k: v["state"] for k, v in out["sources"].items()} == {"github_commits": "ok", "github_users": "ok", "openpgp": "ok"}

    mara, org = out["accounts"]
    assert set(mara) == {"login", "url", "how", "hows", "account_type", "commits_seen", "own_repo_commits", "names",
                         "first_commit", "last_commit", "dates_ignored", "commit_utc_offsets", "evidence"}
    assert mara["login"] == "mara-lind" and mara["url"] == "https://github.com/mara-lind"
    assert mara["how"] == "commit_author" and mara["account_type"] == "User"
    assert mara["commits_seen"] == 5 and mara["own_repo_commits"] == 3
    # names written in the account's own repositories come first; the rest are marked
    assert mara["names"] == [
        {"name": "Mara Lindqvist", "commits": 3, "own_repo": True},
        {"name": "Mara L.", "commits": 1, "own_repo": False},
        {"name": "not mara", "commits": 1, "own_repo": False},
    ]
    assert mara["first_commit"] == "2021-06-14T07:30:00Z" and mara["last_commit"] == "2025-02-20T07:05:00Z"
    assert mara["commit_utc_offsets"] == [{"offset": "+01:00", "commits": 2}, {"offset": "+02:00", "commits": 2}]
    assert len(mara["evidence"]) == 3
    assert mara["evidence"][0].startswith("https://github.com/mara-lind/")          # own repository first
    assert len({u.split("/commit/")[0] for u in mara["evidence"]}) == 3              # one per repository

    assert org == {"login": "tidepool-lab", "url": "https://github.com/tidepool-lab", "how": "public_profile_email",
                   "hows": ["public_profile_email"], "account_type": "Organization"}

    assert out["sources"]["github_commits"] == {"state": "ok", "total": 10, "seen": 8, "incomplete": False, "skipped": 2}
    assert out["sources"]["github_users"] == {"state": "ok", "total": 2, "seen": 2}
    assert out["sources"]["openpgp"] == {"state": "ok", "count": 1}
    assert out["keys"][0]["fingerprint"] == MARA_FPR and out["keys"][0]["how"] == "keyserver_verified_address"


def test_attributed_and_unattributed_commits_stay_apart(monkeypatch):
    replay(monkeypatch)
    out = run()
    loose = out["unattributed"]
    assert set(loose) == {"commits_seen", "names", "first_commit", "last_commit", "dates_ignored",
                          "commit_utc_offsets", "evidence"}
    assert loose["commits_seen"] == 3
    assert loose["names"] == [{"name": "M. Lindqvist", "commits": 2, "own_repo": False},
                              {"name": "root", "commits": 1, "own_repo": False}]
    assert loose["first_commit"] == "2018-01-11T04:59:59Z" and loose["last_commit"] == "2019-09-03T07:15:00Z"
    assert all("saltmarsh-coop" in u for u in loose["evidence"]) and len(loose["evidence"]) == 3
    # no name from an unattributed commit leaks into the account row, and the other way round
    names = {n["name"] for a in out["accounts"] for n in a.get("names", [])}
    assert "root" not in names and "M. Lindqvist" not in names
    assert "Mara Lindqvist" not in {n["name"] for n in loose["names"]}


def test_an_account_found_both_ways_is_one_row(monkeypatch):
    replay(monkeypatch)
    out = run()
    logins = [a["login"].lower() for a in out["accounts"]]
    assert logins == ["mara-lind", "tidepool-lab"]                 # "Mara-Lind" in one commit is the same account
    mara = out["accounts"][0]
    assert mara["how"] == "commit_author" and mara["hows"] == ["commit_author", "public_profile_email"]
    assert mara["commits_seen"] == 5                               # the commit facts survive the merge


def test_a_date_in_the_future_is_ignored_not_reported(monkeypatch):
    replay(monkeypatch)
    mara = run()["accounts"][0]
    assert mara["dates_ignored"] == 1 and not mara["last_commit"].startswith("2060")


def test_a_bot_and_a_hit_with_another_address_are_dropped(monkeypatch):
    replay(monkeypatch)
    text = json.dumps(run())
    assert "tidepool-sync" not in text and "jonas" not in text.lower() and "kelp" not in text


def test_no_returned_url_carries_the_address_or_a_query(monkeypatch):
    replay(monkeypatch, key=MARA_KEY)
    urls = all_urls(run())
    assert len(urls) >= 9
    for url in urls:
        parts = httpx.URL(url)
        assert parts.host in ("github.com", "keys.openpgp.org") and not parts.query
        assert "@" not in url and "%40" not in url and "mara%" not in url and "search" not in url


def test_hostile_values_from_github_are_dropped_or_cleaned(monkeypatch):
    commits = json.loads(json.dumps(DATA["commits"]))
    items = commits["items"]
    items[0]["html_url"] = f"https://github.com/search?q={EMAIL}&type=commits"          # not a commit page
    items[1]["commit"]["author"]["name"] = "Mara‮\x00\nLindqvist" + "x" * 300
    items[1]["html_url"] = "https://evil.example/mara-lind/tidepool/commit/" + "a" * 40
    items[3]["author"]["login"] = "mara-lind/../../x"                                    # not a login
    items[5]["commit"]["author"]["date"] = "yesterday"
    users = {"total_count": 3, "items": [{"login": "a b", "type": "User"}, {"login": "x" * 40, "type": "User"},
                                         {"login": "ok-login", "type": "<script>"}, "junk", None]}
    replay(monkeypatch, commits=commits, users=users)
    out = run()
    text = json.dumps(out)
    assert "evil.example" not in text and "search?q" not in text and "../" not in text
    name = next(n["name"] for n in out["accounts"][0]["names"] if n["name"].startswith("Mara Lindqvist"))
    assert len(name) <= 120 and "‮" not in name and "\n" not in name and "\x00" not in name
    assert out["unattributed"]["dates_ignored"] == 1
    assert [a["login"] for a in out["accounts"]] == ["mara-lind", "ok-login"]
    assert out["accounts"][1]["account_type"] == ""


# ---- states per source -------------------------------------------------------------

def test_nothing_anywhere_is_none_for_every_source(monkeypatch):
    replay(monkeypatch, commits=DATA["empty"], users=DATA["empty"])
    out = run()
    assert {k: v["state"] for k, v in out["sources"].items()} == {"github_commits": "none", "github_users": "none", "openpgp": "none"}
    assert out["accounts"] == [] and out["keys"] == [] and out["unattributed"]["commits_seen"] == 0
    assert all("error" not in s for s in out["sources"].values())


def test_only_unattributed_commits_is_ok_not_none(monkeypatch):
    commits = {"total_count": 3, "incomplete_results": False, "items": [i for i in DATA["commits"]["items"] if i["author"] is None]}
    replay(monkeypatch, commits=commits, users=DATA["empty"])
    out = run()
    assert out["sources"]["github_commits"]["state"] == "ok" and out["accounts"] == []
    assert out["unattributed"]["commits_seen"] == 3


@pytest.mark.parametrize("source", ["github_commits", "github_users"])
@pytest.mark.parametrize("status,headers", [
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"}),
    (403, {}),                                     # the secondary limit: only the message says so
    (429, {"retry-after": "30"}),
])
def test_github_rate_limit_is_rate_limited_never_none(monkeypatch, source, status, headers):
    def override(s, r):
        if s == source:
            return httpx.Response(status, json=DATA["rate_limit_body"], headers=headers)

    replay(monkeypatch, override=override, key=MARA_KEY)
    out = run()
    src = out["sources"][source]
    assert src["state"] == "rate_limited" and src["error_code"] == "rate_limited" and src["retry_after"] >= 1
    assert "203.0.113.9" not in json.dumps(src)                    # GitHub's message is not passed on
    other = "github_users" if source == "github_commits" else "github_commits"
    assert out["sources"][other]["state"] == "ok" and out["sources"]["openpgp"]["state"] == "ok"
    if status == 429:
        assert src["retry_after"] == 30


@pytest.mark.parametrize("source", ["github_commits", "github_users"])
def test_github_failures_are_failed(monkeypatch, source):
    def fails(resp_or_exc):
        def override(s, r):
            if s == source:
                if isinstance(resp_or_exc, Exception):
                    raise resp_or_exc
                return resp_or_exc
        ea.clear_cache_for_tests()
        replay(monkeypatch, override=override)
        return run()["sources"][source]

    assert fails(httpx.Response(500, text="boom"))["error_code"] == "upstream"
    assert fails(httpx.Response(422, json={"message": "Validation Failed"}))["state"] == "failed"
    assert fails(httpx.Response(403, json={"message": "Forbidden"}))["state"] == "failed"      # a 403 that is no rate limit
    assert fails(httpx.Response(200, text="<html>"))["error_code"] == "bad_response"
    assert fails(httpx.Response(200, json={"message": "no items"}))["error_code"] == "bad_response"
    assert fails(httpx.Response(302, headers={"location": "https://elsewhere.example/"}))["state"] == "failed"
    timeout = fails(httpx.ConnectTimeout(f"timed out for {EMAIL}"))
    assert timeout["state"] == "failed" and timeout["error_code"] == "timeout" and EMAIL not in json.dumps(timeout)


def test_openpgp_states(monkeypatch):
    def state(resp_or_exc):
        def override(s, r):
            if s == "openpgp":
                if isinstance(resp_or_exc, Exception):
                    raise resp_or_exc
                return resp_or_exc
        ea.clear_cache_for_tests()
        replay(monkeypatch, override=override)
        out = run()
        assert out["keys"] == [] and out["sources"]["github_commits"]["state"] == "ok"
        return out["sources"]["openpgp"]

    assert state(httpx.Response(404, text=DATA["openpgp_404"])) == {"state": "none"}
    limited = state(httpx.Response(429, text="Too Many Requests", headers={"retry-after": "12"}))
    assert limited["state"] == "rate_limited" and limited["retry_after"] == 12 and limited["error_code"] == "rate_limited"
    assert state(httpx.Response(503, text="down"))["error_code"] == "upstream"
    assert state(httpx.Response(200, text="not a key at all"))["error_code"] == "bad_response"
    assert state(httpx.Response(200, text="x" * (pgp.MAX_BYTES + 10)))["error_code"] == "bad_response"
    assert state(httpx.Response(301, headers={"location": "https://elsewhere.example/"}))["state"] == "failed"
    gone = state(httpx.ConnectError(f"cannot reach the keyserver for {EMAIL}"))
    assert gone["state"] == "failed" and EMAIL not in json.dumps(gone)


def test_a_source_that_hangs_is_cut_off_and_the_rest_answer(monkeypatch):
    monkeypatch.setattr(ea, "SOURCE_TIMEOUT", 0.05)

    async def hang(client, email):
        await asyncio.sleep(5)

    monkeypatch.setattr(ea.github_email, "users", hang)
    replay(monkeypatch)
    out = run()
    assert out["sources"]["github_users"]["state"] == "failed" and out["sources"]["github_users"]["error_code"] == "timeout"
    assert out["sources"]["github_commits"]["state"] == "ok" and out["accounts"][0]["login"] == "mara-lind"


# ---- requests ----------------------------------------------------------------------

def test_requests_go_to_two_fixed_hosts_with_the_address_encoded(monkeypatch):
    calls = []
    replay(monkeypatch, calls)
    run("mara+notes@tidepool.example")
    by = {s: r for s, r in calls}
    assert by["github_commits"].url.params["q"] == "author-email:mara+notes@tidepool.example"
    assert by["github_commits"].url.params["per_page"] == "100"
    assert by["github_users"].url.params["q"] == "mara+notes@tidepool.example in:email"
    assert b"mara%2Bnotes%40tidepool.example" in by["github_commits"].url.raw_path     # the plus is not sent as a space
    assert by["openpgp"].url.raw_path == b"/vks/v1/by-email/mara%2Bnotes%40tidepool.example"
    assert all("authorization" not in r.headers for _, r in calls)


def test_the_token_goes_to_github_only(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token-value")
    calls = []
    replay(monkeypatch, calls)
    run()
    for source, request in calls:
        if source == "openpgp":
            assert "authorization" not in request.headers
        else:
            assert request.headers["authorization"] == "Bearer test-token-value"


# ---- cache -------------------------------------------------------------------------

def test_complete_result_is_cached_for_a_day(monkeypatch):
    calls = []
    replay(monkeypatch, calls)
    first = run()
    again = run(EMAIL.upper().replace("TIDEPOOL.EXAMPLE", "tidepool.example"))
    assert len(calls) == 3 and again["cached"] is True and again["accounts"] == first["accounts"]
    now = ea.time.time()
    monkeypatch.setattr(ea.time, "time", lambda: now + 86401)
    run()
    assert len(calls) == 6


def test_result_with_a_source_that_did_not_answer_is_kept_ten_minutes(monkeypatch):
    calls = []
    replay(monkeypatch, calls, override=lambda s, r: httpx.Response(403, json=DATA["rate_limit_body"]) if s == "github_users" else None)
    assert run()["sources"]["github_users"]["state"] == "rate_limited"
    assert run()["cached"] is True and len(calls) == 3
    now = ea.time.time()
    monkeypatch.setattr(ea.time, "time", lambda: now + 601)
    run()
    assert len(calls) == 6


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ea, "CACHE_MAX", 3)
    replay(monkeypatch)
    for i in range(6):
        run(f"mara{i}@tidepool.example")
    assert len(ea._cache) == 3


# ---- the OpenPGP reader ------------------------------------------------------------

def test_known_fingerprint_of_a_published_key():
    (key,) = pgp.parse_keys(TOR_KEY)
    assert key["fingerprint"] == "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"       # as the project publishes it
    assert key["key_id"] == "4E2C6E8793298290" and key["created"] == "2014-12-15T09:54:02Z"
    assert key["algorithm"] == "RSA" and key["bits"] == 4096 and key["version"] == 4
    assert key["user_ids"] == [{"name": "Tor Browser Developers", "email": "torbrowser@torproject.org", "comment": "signing key"}]


def test_generated_key_is_read_in_full():
    (key,) = pgp.parse_keys(MARA_KEY)
    assert key == {
        "parsed": True, "version": 4, "fingerprint": MARA_FPR, "key_id": MARA_FPR[-16:],
        "created": "2022-05-17T10:30:00Z", "algorithm": "EdDSA", "bits": None, "curve": "Ed25519",
        "url": f"https://keys.openpgp.org/vks/v1/by-fingerprint/{MARA_FPR}",
        "user_ids": [{"name": "Mara Lindqvist", "email": "mara@tidepool.example", "comment": "field notes"},
                     {"name": "", "email": "mara@tidepool.example", "comment": ""}],
        "subkeys": 1, "revoked": False,
    }
    assert len(MARA_FPR) == 40
    # No key material in what is returned.
    assert base64.b64encode(bytes(range(32))).decode()[:20] not in json.dumps(key)


def test_old_format_packets_long_lengths_and_no_crc_line():
    long_uid = ("Mara Lindqvist <mara@tidepool.example> " + "x" * 300).encode()          # a two-byte new-format length
    data = packet(6, RSA_BODY, old=True) + packet(13, long_uid) + packet(13, UID, old=True)
    (key,) = pgp.parse_keys(armor(data, crc=False).replace("\n", "\r\n"))
    assert key["algorithm"] == "RSA" and key["bits"] == 2048 and key["curve"] == ""
    assert key["fingerprint"] == hashlib.sha1(b"\x99" + len(RSA_BODY).to_bytes(2, "big") + RSA_BODY).hexdigest().upper()
    assert [u["email"] for u in key["user_ids"]] == ["", "mara@tidepool.example"]       # the over-long one is clipped, not trusted
    assert all(len(u["name"]) <= 120 for u in key["user_ids"])


def test_a_revoked_key_says_so_and_a_certification_does_not():
    (revoked,) = pgp.parse_keys(armor(packet(6, KEY_BODY) + packet(2, REVOCATION) + packet(13, UID)))
    (fine,) = pgp.parse_keys(armor(packet(6, KEY_BODY) + packet(13, UID) + packet(2, REVOCATION)))   # a user ID revocation slot
    assert revoked["revoked"] is True and fine["revoked"] is False


@pytest.mark.parametrize("version", [3, 5, 6])
def test_other_key_versions_are_reported_unparsed_not_guessed(version):
    body = bytes([version]) + KEY_BODY[1:]
    (key,) = pgp.parse_keys(armor(packet(6, body) + packet(13, UID)))
    assert key["parsed"] is False and key["version"] == version and "fingerprint" not in key and "url" not in key
    assert key["user_ids"][0]["name"] == "Mara Lindqvist"


def test_several_keys_and_a_photo_packet():
    data = packet(6, KEY_BODY) + packet(13, UID) + packet(17, b"\x10\x00\x01" + b"JFIF" * 50) + packet(6, RSA_BODY) + packet(13, UID)
    keys = pgp.parse_keys(armor(data))
    assert [k["algorithm"] for k in keys] == ["EdDSA", "RSA"]
    assert "JFIF" not in json.dumps(keys) and base64.b64encode(b"JFIF" * 3).decode() not in json.dumps(keys)
    many = pgp.parse_keys(armor(b"".join(packet(6, KEY_BODY) for _ in range(9))))
    assert len(many) == pgp.MAX_KEYS


def test_user_id_text_is_cleaned():
    uid = "Mara\x00 ‮Lindqvist\n<mara@tidepool.example>".encode() + b"\xff\xfe"
    (key,) = pgp.parse_keys(armor(packet(6, KEY_BODY) + packet(13, uid)))
    name = key["user_ids"][0]["name"]
    assert "\x00" not in name and "‮" not in name and "\n" not in name and name.startswith("Mara")


@pytest.mark.parametrize("text", [
    "", "No key found", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!not base64!!!\n-----END PGP PUBLIC KEY BLOCK-----",
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----",
    armor(b"\x00\x01\x02\x03"),                          # not a packet header
    armor(packet(6, KEY_BODY)[:-5]),                     # truncated body
    armor(b"\xc6"),                                      # header with no length
    armor(b"\xc6\xff\x00\x00"),                          # five-byte length cut short
    armor(b"\xc6\xe1" + bytes(4)),                       # partial body length
    armor(packet(13, UID) + packet(2, SIG)),             # packets, but no key among them
    armor(bytes([0x99, 0xFF, 0xFF]) + bytes(10)),        # old format length past the end
    "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----",
])
def test_garbage_is_unreadable_and_never_a_crash(text):
    with pytest.raises(pgp._Unreadable):
        pgp.parse_keys(text)


def test_random_bytes_never_raise_anything_else():
    import random
    rng = random.Random(3)
    for _ in range(300):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 120)))
        try:
            pgp.parse_keys(armor(blob))
        except pgp._Unreadable:
            pass


def test_an_unparsed_key_still_makes_the_source_ok(monkeypatch):
    v6 = armor(packet(6, b"\x06" + KEY_BODY[1:]) + packet(13, UID))
    replay(monkeypatch, key=v6)
    out = run()
    assert out["sources"]["openpgp"] == {"state": "ok", "count": 1}
    assert out["keys"][0]["parsed"] is False and out["keys"][0]["version"] == 6


# ---- endpoint ----------------------------------------------------------------------

@pytest.fixture
def no_limit(monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "/api/recon/email-accounts", (10_000, 60))


def test_endpoint_returns_the_lookup(monkeypatch, no_limit):
    replay(monkeypatch, key=MARA_KEY)
    with TestClient(app) as client:
        resp = client.post("/api/recon/email-accounts", json={"email": f"  {EMAIL} "})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"email", "cached", "accounts", "unattributed", "keys", "sources"}
    assert body["email"] == EMAIL and body["accounts"][0]["login"] == "mara-lind" and body["keys"][0]["fingerprint"] == MARA_FPR
    assert set(body["sources"]) == {"github_commits", "github_users", "openpgp"}


@pytest.mark.parametrize("body,status", [
    ({"email": ""}, 400), ({"email": "mara"}, 400), ({"email": "mara@tidepool"}, 400), ({"email": "-x@tidepool.example"}, 400),
    ({"email": "mara lind@tidepool.example"}, 400), ({"email": "mara@tidepool.example\nx"}, 400),
    ({"email": "mara@tidepool.example org:x"}, 400), ({"email": "mara@tide/pool.example"}, 400),
    ({"email": "a" * 321}, 422), ({}, 422), ({"email": None}, 422), ({"email": [EMAIL]}, 422),
])
def test_endpoint_validation_errors_reach_no_source(monkeypatch, no_limit, body, status):
    calls = []
    replay(monkeypatch, calls)
    with TestClient(app) as client:
        resp = client.post("/api/recon/email-accounts", json=body)
    assert resp.status_code == status and calls == []


def test_rate_limit_entry():
    assert match_limit("/api/recon/email-accounts") == ("/api/recon/email-accounts", 5, 60)
    mw = rate_limit.RateLimitMiddleware(app=None)
    assert [mw.check("203.0.113.9", "/api/recon/email-accounts", now=100.0 + i) for i in range(5)] == [None] * 5
    assert mw.check("203.0.113.9", "/api/recon/email-accounts", now=106.0) is not None


# ---- logging -----------------------------------------------------------------------

def test_nothing_sensitive_is_logged(monkeypatch, no_limit, caplog):
    secrets = ("mara", "lindqvist", "tidepool", "saltmarsh", "harbor-works", MARA_FPR.lower(), "203.0.113.9")

    def override(s, r):
        if s == "github_users":
            return httpx.Response(403, json=DATA["rate_limit_body"], headers={"x-ratelimit-remaining": "0"})
        if s == "openpgp":
            raise httpx.ConnectError(f"cannot reach {r.url}")          # an error text that carries the address

    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client:
            replay(monkeypatch, override=override)
            resp = client.post("/api/recon/email-accounts", json={"email": EMAIL})
            ea.clear_cache_for_tests()
            replay(monkeypatch, key=MARA_KEY)
            ok = client.post("/api/recon/email-accounts", json={"email": EMAIL})
            bad = client.post("/api/recon/email-accounts", json={"email": "mara@@tidepool.example"})
    assert resp.status_code == 200 and ok.status_code == 200 and bad.status_code == 400
    assert resp.json()["sources"]["github_users"]["state"] == "rate_limited"
    assert resp.json()["sources"]["openpgp"]["state"] == "failed"
    ours = [r for r in caplog.records if r.name.startswith("modules.")]
    assert {r.name for r in ours} >= {"modules.email_accounts", "modules.github_email", "modules.openpgp_keys"}
    for record in caplog.records:
        fields = json.dumps({k: v for k, v in vars(record).items() if k != "exc_info"}, default=str).lower()
        text = record.getMessage().lower()
        for secret in secrets:
            assert secret not in fields and secret not in text, record
    for src in resp.json()["sources"].values():
        assert "mara" not in json.dumps(src).lower()


def test_read_commits_alone_takes_a_fixed_clock():
    read = ge.read_commits(DATA["commits"], EMAIL, now=datetime(2024, 1, 1, tzinfo=timezone.utc))
    # with the clock in 2024 the two later commits are in the future too
    assert read["accounts"][0]["dates_ignored"] == 3 and read["accounts"][0]["last_commit"] == "2023-04-02T19:10:05Z"
