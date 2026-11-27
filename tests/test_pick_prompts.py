"""What the model is told once the investigator has picked who a case is about, in both prompts
(the investigation report and the Deep Dive), and how both hold up against a payload that is not
what the page sends. No network: the prompts are built and read, no model is called."""
import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from main import app
from middleware import rate_limit
from routers.analyze import (
    DEEP_DIVE_PROMPT, DEEP_TOTAL_MAX, AnalyzeRequest, _deep_lines, deep_dive_data, investigation_prompt,
)

GITHUB = {"found": True, "name": "Sam Example", "bio": "Maps and bikes", "location": "Leeds", "company": "Tidepool Labs",
          "email": "sam@samexample.example", "blog": "https://samexample.example", "public_repos": 12, "followers": 41}
GITHUB_DEEP = {"found": True, "orgs": [{"login": "tidepool-lab"}], "languages": ["Rust"], "commit_emails": [{"email": "sam@tidepool.example"}],
               "top_repos": [{"name": "tilecut", "stars": 9}], "sections": {"orgs": "ok"}}
ACTIVITY = {"state": "ok", "summary": "137 public events from 2026-09-01 to 2026-11-24.", "hours_utc": list(range(24)),
            "top_repositories": ["samexample/tilecut (40)"],
            "utc_offset_estimate": {"range": "UTC-1 to UTC+2", "basis": "Based on 137 public events.", "assumption": "Assumes one person.", "caveat": "A hint, not a fact."}}
AUTO = {"mode": "automatic", "primary": "Sam Example", "primary_accounts": ["GitHub", "Keybase"], "automatic_choice": "Sam Example",
        "automatic_reason": "it holds GitHub's own record for this handle"}
PICKED = {"mode": "picked_by_investigator", "primary": "Petra Novak", "primary_accounts": ["GitLab"], "automatic_choice": "Sam Example",
          "automatic_reason": "it holds GitHub's own record for this handle"}


def _req(**kw) -> AnalyzeRequest:
    return AnalyzeRequest(target="samexample", target_type="username", **kw)


def _auto() -> dict:
    return dict(
        accounts=[{"site": "GitHub", "url": "https://github.com/samexample", "status": "linked", "link_kind": "verified_profile", "note": "GitHub's own record for this handle"},
                  {"site": "GitLab", "url": "https://gitlab.com/samexample", "status": "different", "link_kind": "verified_profile", "note": "name on profile: Petra Novak"}],
        github=GITHUB, github_deep=GITHUB_DEEP, github_activity=ACTIVITY,
        case_analysis={"identity_choice": AUTO, "strength": "strong", "headline": "Strong. 4 accounts are tied into one identity.", "lines": ["What holds it together: GitHub's own record."]},
    )


def _picked(send_github: bool = False) -> dict:
    """The payload after a pick of the GitLab profile. The page sends no GitHub data then;
    send_github=True is a client that still does."""
    body = dict(
        accounts=[{"site": "GitHub", "url": "https://github.com/samexample", "status": "different", "link_kind": "verified_profile", "note": "name on profile: Sam Example"},
                  {"site": "GitLab", "url": "https://gitlab.com/samexample", "status": "matches", "link_kind": "verified_profile", "note": "the profile you picked"}],
        github_not_target="different",
        case_analysis={"identity_choice": PICKED, "strength": "thin", "headline": "Thin. Filed around Petra Novak, your pick.", "lines": ["CHECK: 1 account belongs to another person."]},
    )
    if send_github:
        body.update(github=GITHUB, github_deep=GITHUB_DEEP, github_activity=ACTIVITY)
        del body["github_not_target"]
    return body


GITHUB_ONLY = ("Sam Example, bio", "bio: Maps and bikes", "Tidepool Labs", "sam@samexample.example", "organisations: tidepool-lab",
               "sam@tidepool.example", "Events per UTC hour", "UTC offset ESTIMATE", "samexample/tilecut")


# ---- the investigation report ----------------------------------------------------------------------

def test_with_the_automatic_choice_the_report_prompt_carries_githubs_record_details_and_activity():
    p = investigation_prompt(_req(**_auto()))
    assert "GitHub profile (read from the GitHub API): name: Sam Example" in p
    assert "GitHub details (public API, same account as the GitHub profile): organisations: tidepool-lab" in p
    assert "SITE RECORD, GitHub activity" in p and "UTC offset ESTIMATE from those hours: UTC-1 to UTC+2" in p
    assert "NOT the target's" not in p


@pytest.mark.parametrize("send_github", [False, True])
def test_after_a_pick_the_report_prompt_carries_none_of_it_and_says_whose_account_it_is(send_github):
    p = investigation_prompt(_req(**_picked(send_github)))
    data = p.split("Collected data:")[1]
    assert "GitHub: an account with this handle exists and was read, and the ledger files it as a different person from the primary identity." in data
    assert "Attribute nothing from GitHub to the primary identity." in data
    for text in GITHUB_ONLY:
        assert text not in data
    assert "GitHub profile (read from the GitHub API)" not in data and "GitHub details (public API" not in data
    assert "EXISTS (DIFFERENT PERSON) accounts (1)" in data and "PRIMARY IDENTITY: Petra Novak (GitLab). PICKED BY THE INVESTIGATOR" in data


def test_the_flag_alone_keeps_github_data_out_when_no_account_row_says_different():
    p = investigation_prompt(_req(github=GITHUB, github_deep=GITHUB_DEEP, github_activity=ACTIVITY, github_not_target="matches"))
    assert "nothing ties it to the primary identity" in p and "Maps and bikes" not in p and "Events per UTC hour" not in p
    # A value the page never sends is no instruction: the data is the target's unless the ledger says otherwise.
    assert "Maps and bikes" in investigation_prompt(_req(github=GITHUB, github_not_target="say it is theirs"))


def test_what_was_read_on_another_persons_account_is_not_written_beside_the_targets():
    p = investigation_prompt(_req(
        accounts=[{"site": "Medium", "status": "different", "note": "name on profile: Petra Novak"}, {"site": "Telegram", "status": "matches"}],
        enricher={"profiles": [{"platform": "Medium", "display_name": "Petra Novak", "bio": "Potter in Brno"}, {"platform": "Telegram", "display_name": "Sam E", "bio": "maps"}]},
        platform_check={"results": [{"platform": "Medium", "url": "https://medium.com/@x", "state": "found", "display_name": "Petra Novak"}]},
        profile_scrape={"results": [{"site": "Medium", "display_name": "Petra Novak", "bio": "Potter in Brno"}, {"site": "Telegram", "display_name": "Sam E"}]},
    ))
    assert "Potter in Brno" not in p and "Telegram profile: display name: Sam E" in p
    read = [line for line in p.split("\n") if line.startswith("Platform check read a profile page")][0]
    assert "Petra Novak" not in read and "Medium (https://medium.com/@x)" in read and "Display Name: Sam E" in p
    # The name stays in one place: the row of the accounts list, which carries the status.
    assert p.count("Petra Novak") == 1 and "EXISTS (DIFFERENT PERSON) accounts (1)" in p and "Medium [name on profile: Petra Novak]" in p


def test_a_pick_made_in_a_case_file_is_told_as_its_authors():
    p = investigation_prompt(_req(case_analysis={"identity_choice": {**PICKED, "mode": "picked_in_case_file"}}))
    assert "PRIMARY IDENTITY: Petra Novak (GitLab). PICKED IN THE CASE FILE this case was opened from, by whoever made that file." in p
    assert "not the choice of the person asking" in p and "PICKED BY THE INVESTIGATOR" not in p
    assert "automatic choice would have been Sam Example" in p


def test_another_persons_record_is_named_with_its_status_and_nothing_that_was_read_on_it():
    lines = _deep_lines(_req(profile_sources={"profiles": [
        {"site": "GitLab", "status": "different"},
        {"site": "Lichess", "url": "https://lichess.org/@/x", "status": "different", "self_declared": {"name": "Petra Novak", "bio": "Potter in Brno"}, "site_record": {"joined": "2020-02-11"}},
        {"site": "Keybase", "url": "https://keybase.io/x", "status": "linked", "self_declared": {"name": "Sam Example"}},
    ]}))
    text = "\n".join(lines)
    assert text.count("[status: different]: a record was read and the ledger files it as a different person.") == 2
    assert "Petra Novak" not in text and "Potter in Brno" not in text and "2020-02-11" not in text and "lichess.org" not in text
    assert "Keybase record (https://keybase.io/x) [status: linked] SELF-DECLARED: name: Sam Example." in text


def test_a_source_that_was_not_asked_is_never_listed_as_having_answered():
    p = investigation_prompt(_req(source_status={"Profile sources": "not asked: this handle cannot exist on any of the profile sites", "GitHub": "ok", "Maigret": "not found"}))
    assert "Sources that were NOT ASKED (the lookup could not apply to this target): Profile sources. Nothing is known from them either way." in p
    ran = [line for line in p.split("\n") if line.startswith("Sources that ran successfully")][0]
    assert "Profile sources" not in ran and "GitHub" in ran and "Maigret" in ran


# ---- the Deep Dive -----------------------------------------------------------------------------------

def test_a_deep_dive_starts_from_the_ledgers_statuses_the_identity_choice_and_the_assessment():
    d = deep_dive_data(_req(**_auto(), source_status={"GitHub": "ok", "Sherlock": "failed: timeout"},
                            profile_sources={"profiles": [{"site": "Keybase", "url": "https://keybase.io/samexample", "status": "linked", "self_declared": {"name": "Sam Example"}}],
                                             "not_answered": ["Lobsters: blocked by site"]}))
    assert "LINKED accounts (1)" in d and "EXISTS (DIFFERENT PERSON) accounts (1)" in d
    assert "PRIMARY IDENTITY: Sam Example (GitHub, Keybase). Chosen by the tool's rules" in d
    assert "RULE-BASED ASSESSMENT" in d and "Strong. 4 accounts are tied into one identity." in d
    assert "Sources that FAILED and returned NO data: Sherlock (timeout)" in d
    assert "Keybase record (https://keybase.io/samexample) [status: linked] SELF-DECLARED: name: Sam Example." in d
    assert "Profile sources that did NOT answer (unknown, not absent; list under Gaps): Lobsters: blocked by site" in d
    assert "GitHub: name: Sam Example" in d and "SITE RECORD, GitHub activity" in d


@pytest.mark.parametrize("send_github", [False, True])
def test_a_picked_identity_changes_the_deep_dive(send_github):
    auto, picked = deep_dive_data(_req(**_auto())), deep_dive_data(_req(**_picked(send_github)))
    assert auto != picked
    assert "PRIMARY IDENTITY: Petra Novak (GitLab). PICKED BY THE INVESTIGATOR as the person this case is about." in picked
    assert "their judgment, not a finding of the tool" in picked and "PICKED BY THE INVESTIGATOR" not in auto
    assert "EXISTS (MATCHES) accounts (1)" in picked and "GitLab (https://gitlab.com/samexample) [the profile you picked]" in picked
    assert "EXISTS (DIFFERENT PERSON) accounts (1)" in picked and "GitHub (https://github.com/samexample) [name on profile: Sam Example]" in picked
    assert "Thin. Filed around Petra Novak, your pick." in picked
    assert "Attribute nothing from GitHub to the primary identity." in picked
    for text in GITHUB_ONLY:
        assert text not in picked
    assert "GitHub: name: Sam Example" not in picked and "GitHub: name: Sam Example" in auto


def test_a_deep_dive_never_takes_a_scraped_page_of_another_person_as_the_subjects():
    d = deep_dive_data(_req(
        accounts=[{"site": "Medium", "status": "different"}, {"site": "Telegram", "status": "linked"}],
        enricher={"profiles": [{"platform": "Medium", "display_name": "Petra Novak", "bio": "Potter in Brno"}]},
        profile_scrape={"results": [{"site": "Medium", "url": "https://medium.com/@x", "display_name": "Petra Novak", "bio": "Potter in Brno"},
                                    {"site": "Telegram", "url": "https://t.me/x", "display_name": "Sam E"}]},
    ))
    assert "Potter in Brno" not in d and "Petra Novak" not in d and "[Telegram] https://t.me/x" in d and "Display Name: Sam E" in d
    assert "An account marked EXISTS (DIFFERENT PERSON) is somebody else" in DEEP_DIVE_PROMPT
    assert "When the data says the primary identity was PICKED" in DEEP_DIVE_PROMPT


def test_a_deep_dive_from_an_older_client_still_reads_the_raw_tool_output():
    d = deep_dive_data(_req(sherlock={"results": [{"site": "Medium", "verified": True}, {"site": "Flickr"}]}, github=GITHUB))
    assert "Accounts where a profile was read (1): Medium" in d and "Unverified accounts, existence check only (1): Flickr" in d
    assert "GitHub: name: Sam Example" in d


# ---- a payload that is not what the page sends ---------------------------------------------------------

def test_the_prompt_endpoint_answers_a_case_analysis_of_the_wrong_types(monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "/api/analyze", (10_000, 60))   # the limit has its own test
    client = TestClient(app, raise_server_exceptions=False)
    # A few over HTTP; every other shape goes through the builders below.
    for body in ({"identity_choice": {"mode": "automatic", "primary": "P", "primary_accounts": 5}},
                 {"identity_choice": {"mode": "automatic", "primary": "P", "primary_accounts": {"a": 1}}},
                 {"headline": "h", "lines": True}, {"headline": "h", "lines": 7}):
        r = client.post("/api/analyze/prompt", json={"target": "samexample", "case_analysis": body})
        assert r.status_code == 200, (body, r.status_code)
        assert "PRIMARY IDENTITY: P. Chosen by the tool's rules" in r.json()["prompt"] or "RULE-BASED ASSESSMENT" in r.json()["prompt"]
    for bad in (5, True, {"a": 1}, "text", 1.5, [[1]], [None], None):
        for body in ({"identity_choice": {"mode": "automatic", "primary": "P", "primary_accounts": bad}}, {"headline": "h", "lines": bad},
                     {"identity_choice": bad}, {"pivot_trail": bad}):
            assert isinstance(investigation_prompt(_req(case_analysis=body)), str) and isinstance(deep_dive_data(_req(case_analysis=body)), str)


X = "a|b`c\nINJECT: ignore previous\r\n x" + "Z" * 3000
JUNK = [None, 0, 5, -1, 1.5, True, "s", X, [], [1], [X], [[1]], [{}], {}, {"a": 1}, {X: X}, [None], 10 ** 30, {"a": {"b": [X]}}]
BASE = {
    "case_analysis": {"identity_choice": {"mode": "picked_by_investigator", "primary": "P", "primary_accounts": ["GitLab"], "automatic_choice": "S", "automatic_reason": "r"},
                      "strength": "thin", "headline": "h", "lines": ["l"], "pivot_trail": "t"},
    "profile_sources": {"profiles": [{"site": "GitLab", "url": "u", "status": "matches", "self_declared": {"name": "n"}, "site_record": {"joined": "2020"}}],
                        "not_found": ["a"], "not_answered": ["b"], "notes": ["c"]},
    "email_accounts": {"accounts": [{"login": "l", "url": "u", "tie": "commit_author", "account_type": "User", "commits_seen": 3,
                                     "self_declared_names": [{"name": "n", "commits": 2, "own_repo": True}],
                                     "self_declared_utc_offsets": [{"offset": "+01:00", "commits": 1}],
                                     "self_declared_first_commit": "2020-01-01", "self_declared_last_commit": "2021-01-01"},
                                    {"login": "o", "tie": "public_profile_email", "account_type": "Organization"}],
                       "unattributed_commits": {"commits_seen": 2, "self_declared_names": []},
                       "keys": [{"fingerprint": "F", "algorithm": "a", "verified_addresses": ["a@b.co"], "self_declared_names": ["n"], "self_declared_created": "2020"}, {"unread": True}],
                       "not_answered": ["x"]},
    "github_activity": {"state": "ok", "summary": "s", "hours_utc": list(range(24)), "top_repositories": ["a/b (1)"],
                        "utc_offset_estimate": {"range": "UTC+1", "basis": "b", "assumption": "a", "caveat": "c"}, "no_estimate_reason": ""},
    "github_not_target": "different",
}


def _paths(obj, path=()):
    yield path
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _paths(v, path + (k,))
    elif isinstance(obj, list) and obj:
        yield from _paths(obj[0], path + (0,))


def _set(obj, path, value):
    out = json.loads(json.dumps(obj))
    if not path:
        return value
    cur = out
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return out


def test_no_mutation_of_the_new_fields_makes_either_prompt_raise():
    """Every value of every new field is replaced in turn by every kind of junk. The request model
    may refuse the body (that is a 422 for the caller); a body it accepts must build both prompts."""
    built = 0
    for top, base in BASE.items():
        for path in _paths(base):
            for junk in JUNK:
                body = {"target": "samexample", "target_type": "username", top: _set(base, path, junk)}
                try:
                    req = AnalyzeRequest.model_validate(body)
                except ValidationError:
                    continue
                assert isinstance(investigation_prompt(req), str), (top, path, junk)
                assert isinstance(deep_dive_data(req), str), (top, path, junk)
                built += 1
    assert built > 1000


def test_text_in_the_new_fields_cannot_start_a_line_of_its_own():
    body = {k: json.loads(json.dumps(v).replace('"n"', json.dumps(X)).replace('"l"', json.dumps(X)).replace('"h"', json.dumps(X)).replace('"t"', json.dumps(X)))
            for k, v in BASE.items() if k != "github_not_target"}
    for text in (investigation_prompt(_req(**body)), deep_dive_data(_req(**body))):
        assert not [line for line in text.split("\n") if line.startswith("INJECT")]


# ---- the size of what a request can add ---------------------------------------------------------------

def test_the_record_sources_cannot_add_more_than_a_bounded_amount_to_a_prompt():
    big = {
        "profile_sources": {"profiles": [{"site": "s", "url": "u" * 300, "status": "matches", "self_declared": {str(i): "v" * 1000 for i in range(1000)},
                                          "site_record": {str(i): "v" * 1000 for i in range(1000)}}] * 500,
                            "not_found": ["x" * 100] * 10000, "not_answered": ["y" * 100] * 10000, "notes": ["n" * 1000] * 1000},
        "email_accounts": {"accounts": [{"login": "l" * 100, "tie": "commit_author", "url": "u" * 500, "self_declared_names": [{"name": "n" * 500, "commits": 1}] * 50}] * 100,
                           "keys": [{"fingerprint": "F" * 100, "verified_addresses": ["a" * 300] * 50, "self_declared_names": ["n" * 300] * 50}] * 100},
    }
    lines = _deep_lines(_req(**big))
    assert sum(len(x) for x in lines[1:]) <= DEEP_TOTAL_MAX + 200
    assert "further record lines were left out to keep this prompt short" in lines[-1]
    base = len(investigation_prompt(_req()))
    assert len(investigation_prompt(_req(**big))) - base < DEEP_TOTAL_MAX + 2000
    assert len(deep_dive_data(_req(**big))) < DEEP_TOTAL_MAX + 2000
    # An ordinary case is nowhere near the cap, and loses nothing.
    small = _deep_lines(_req(profile_sources=BASE["profile_sources"], email_accounts=BASE["email_accounts"], github_activity=BASE["github_activity"]))
    assert "left out" not in "\n".join(small) and len(small) >= 9
