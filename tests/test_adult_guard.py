"""The minor guard (the handle check, the content check, the gate in front of every adult pass)
and the text-only output rules for adult rows. No network.

The rules themselves are in static/v2/data/minor-rules.json; the fixtures are in
tests/fixtures/minor and are also run through the JavaScript engine (test_minor_parity.py)."""

import inspect
import json
import logging
from datetime import date
from pathlib import Path

import pytest

from core import adult_guard as ag
from core import minor_rules as mr
from core import profile_record as pr

FIX = Path(__file__).parent / "fixtures" / "minor"
HANDLES = json.loads((FIX / "handles.json").read_text(encoding="utf-8"))
RULES = json.loads(mr.RULES_PATH.read_text(encoding="utf-8"))
BIOS = json.loads((FIX / "bios.json").read_text(encoding="utf-8"))
TODAY = date(2026, 11, 22)


@pytest.fixture(autouse=True)
def _pin(monkeypatch):
    # Everything that depends on today is relative to this date, so the cases do not age.
    monkeypatch.setattr(ag, "_today", lambda: TODAY)
    pr.clear()
    yield
    pr.clear()


# ---- stage 1: the handle ---------------------------------------------------------------

# The owner's examples that must block, and the handles that must run.
OWNER_BLOCK = ["15yo_alex", "age14jay", "16yrsold", "14yo", "15y/o", "15_y_o", "age16", "13yearsold", "8yo", "17_years_old"]
OWNER_RUN = ["10yrs_exp", "12years_sober", "15yrsInfosec", "2yrs_sober", "5years", "7yo", "3yo_dad", "gamer13", "sk8r_15", "10outof10", "err0ric17", "team14", "1337", "2015ford", "mike1999", "mike2010"]
# Years with no "old" are a weak signal: they run alone and block only with a sign in a profile.
# (16yrs was on the owner's first block list; by the later decision it is weak and 16yrsold blocks.)
WEAK_YEARS = ["16yrs", "15yrs_x", "12years", "15_years", "john15yrs"]
# The reviewer's lists: "age" inside a phrase, and an age about someone else.
PHRASES_RUN = ["stone_age_12", "new_age_17", "ice.age.9", "golden_age16", "sage16", "mage17", "teenage16", "average15", "page14", "stage15", "image16", "1year", "age5", "mom_of_16yo", "dad_of_15yo", "l5yo"]
# Handles the old rules refused and the new ones do not: a bare number, a year, a school word.
NO_LONGER_BLOCKED = ["emma09", "user2012", "apollo13", "kidrock", "canteen", "jake13", "15jake", "anna15", "born2012", "classof2029", "2k10",
                     "year9", "grade7", "sixteen", "teen", "minor", "kid", "schoolgirl", "f15", "m16", "im16", "turning15", "17f", "u18", "under18", "yo15", "15y", "y15"]


@pytest.mark.parametrize("handle", OWNER_BLOCK + ["9yo", "017yo", "user15yo", "x_age_16", "my_age_14", "aged15", "age_14", "@15yo_Alex", "AGE14JAY", "16yr_old", "16yearold"])
def test_an_explicit_age_under_18_in_the_handle_blocks(handle):
    assert ag.minor_indicated(handle) == ag.REASONS["age"], handle


@pytest.mark.parametrize("handle", ["underage", "preteen", "jailbait", "j41lb41t", "pr3t33n", "und3rage", "pre.teen", "under_age"])
def test_three_words_block_with_digits_read_as_letters(handle):
    assert ag.minor_indicated(handle) == ag.REASONS["word"], handle


@pytest.mark.parametrize("handle", OWNER_RUN + WEAK_YEARS + PHRASES_RUN + NO_LONGER_BLOCKED + ["18yo", "21yo", "15yoga", "15yogurt", "16years_of_code", "thunderage", "age160", "age18", "100yo"])
def test_a_bare_number_or_an_ordinary_word_never_blocks(handle):
    assert ag.minor_indicated(handle) is None, (handle, ag.minor_indicated(handle))


@pytest.mark.parametrize("case", HANDLES["cases"], ids=lambda c: c["handle"] or "empty")
def test_every_fixture_handle(case):
    assert mr.load().handle_token(case["handle"]) == case["token"], case
    assert ag.minor_indicated(case["handle"]) == (ag.REASONS[case["token"]] if case["token"] else None)


def test_the_fixture_holds_both_directions():
    tokens = [c["token"] for c in HANDLES["cases"]]
    assert tokens.count("age") >= 25 and tokens.count("word") >= 8 and tokens.count(None) >= 60
    listed = {c["handle"] for c in HANDLES["cases"]}
    assert set(OWNER_BLOCK + OWNER_RUN + ["16yrs", "15yrs_x", "12years"]) <= listed      # the owner's lists are in the shared fixture, so both engines run them


@pytest.mark.parametrize("handle", WEAK_YEARS)
def test_bare_years_in_a_handle_are_weak_they_run_alone_and_block_with_a_sign_in_a_profile(handle):
    engine = mr.load()
    assert engine.handle_token(handle) is None and 8 <= engine.soft_bare_years(handle) <= 17
    one = lambda bio: engine.scan([{"source": "GitHub", "url": "", "bio": bio}], handle, TODAY)
    clean, weak = one("Go and Rust. Coffee."), one("freshman")
    assert not clean["blocked"] and clean["soft_years"] == engine.soft_bare_years(handle) and clean["soft"] is None
    assert weak["blocked"] and weak["kind"] == "soft" and weak["signal"]["snippet"] == "freshman"
    for under_floor in ("2yrs_sober", "5years", "7yo", "1year"):
        assert engine.soft_bare_years(under_floor) is None and not engine.scan([{"source": "S", "bio": "freshman"}], under_floor, TODAY)["blocked"]


def test_a_strong_signal_is_never_lost_behind_the_cap():
    engine = mr.load()
    many = [{"source": f"Site {i}", "url": "", "bio": "freshman, fifteen"} for i in range(20)] + [{"source": "Instagram", "url": "", "bio": "I'm 15"}]
    r = engine.scan(many, "river_stone", TODAY)
    assert r["blocked"] and r["kind"] == "age" and r["signal"]["source"] == "Instagram"
    assert len(r["signals"]) == engine.signals_max and r["signal"] in r["signals"]


def test_the_reason_is_a_fixed_sentence_that_never_repeats_the_handle_or_mentions_a_number_in_it():
    assert {ag.minor_indicated(c["handle"]) for c in HANDLES["cases"] if c["token"]} == {ag.REASONS["age"], ag.REASONS["word"]}
    for text in [*ag.REASONS.values(), *ag.CONTENT_REASONS.values(), ag.MESSAGE, ag.MAINSTREAM_MESSAGE]:
        assert "{" not in text and "%" not in text
        assert "number" not in text.lower() and "starts or ends" not in text and "10 to 17" not in text, text
    assert "zq9" not in ag.minor_indicated("zq9_15yo_zq9")


def test_the_soft_birth_year_follows_the_calendar(monkeypatch):
    for case in HANDLES["soft"]:
        assert ag.soft_birth_year(case["handle"]) == case["soft"], case
    # 2026: only a year that makes the person under 18 today counts (2009 on), and 2020 is six years back.
    assert ag.soft_birth_year("mike2009") == 2009 and ag.soft_birth_year("mike2008") is None
    assert ag.soft_birth_year("mike2020") == 2020 and ag.soft_birth_year("mike2021") is None
    # It never blocks by itself.
    assert all(ag.minor_indicated(c["handle"]) is None for c in HANDLES["soft"])
    # Nothing is hard-coded: five years on the window has moved with the date.
    monkeypatch.setattr(ag, "_today", lambda: date(2031, 1, 1))
    assert ag.soft_birth_year("mike2010") is None and ag.soft_birth_year("mike2013") is None and ag.soft_birth_year("mike2014") == 2014 and ag.soft_birth_year("mike2025") == 2025


def test_today_is_the_real_date_by_default(monkeypatch):
    monkeypatch.undo()
    assert ag._today() == date.today()
    year = date.today().year
    assert ag.soft_birth_year(f"sam_{year - 10}") == year - 10 and ag.soft_birth_year(f"sam_{year - 30}") is None


def test_there_is_no_override():
    assert list(inspect.signature(ag.minor_indicated).parameters) == ["username"]
    assert list(inspect.signature(ag.refusal).parameters) == ["username"]
    assert list(inspect.signature(ag.gate).parameters) == ["username"]
    assert ag.minor_indicated("") is None and ag.minor_indicated(None) is None


def test_refusal_carries_the_error_fields_and_the_ui_keys():
    assert ag.refusal("torvalds") is None and ag.refusal("jake13") is None
    body = ag.refusal("jake_15yo")
    assert body == {"detail": ag.MESSAGE, "code": "minor_guard", "reason": ag.REASONS["age"],
                    "error": ag.MESSAGE, "error_code": "minor_guard", "error_detail": ag.REASONS["age"]}
    assert "jake" not in str(body).lower()


# ---- the rules file ----------------------------------------------------------------------

def test_the_rules_file_is_the_only_copy_and_both_engines_read_it():
    root = Path(__file__).parent.parent
    assert mr.RULES_PATH == root / "static" / "v2" / "data" / "minor-rules.json" and mr.RULES_PATH.is_file()
    copies = [p for p in root.rglob("minor*rules*.json") if not {".venv", "node_modules", ".claude", ".git"} & set(p.relative_to(root).parts)]
    assert copies == [mr.RULES_PATH]
    assert "minor-rules.json" in (root / "static" / "v2" / "js" / "minorscan.js").read_text(encoding="utf-8")
    # Neither engine holds a pattern of its own: no regex syntax for an age or a school word in the code.
    for path in (root / "core" / "minor_rules.py", root / "core" / "adult_guard.py", root / "static" / "v2" / "js" / "minorscan.js", root / "static" / "v2" / "js" / "adult.js"):
        code = path.read_text(encoding="utf-8")
        for word in ("yrs?", "years?", "high ?school", "1[0-7]", "[._-]*"):
            assert word not in code, (path.name, word)


def test_the_rules_stay_inside_the_shared_regex_subset():
    doc = json.loads(mr.RULES_PATH.read_text(encoding="utf-8"))
    assert doc["version"] == 1 and doc["flags"] == "" and "regex_subset" in doc
    patterns = [*doc["macros"].values(), *doc["handle"]["age"]["patterns"].values(), doc["handle"]["words"]["pattern"], doc["handle"]["soft_year"]["pattern"],
                doc["content"]["birth"]["field_pattern"], doc["content"]["birth"]["age_field_pattern"],
                *(x["pattern"] for x in doc["content"]["contexts"].values()), *(r["pattern"] for r in doc["content"]["rules"])]
    assert len(patterns) > 50
    for p in patterns:
        for banned in ("\\d", "\\w", "\\s", "\\D", "\\W", "\\S", "\\p", "(?P", "(?i", "(?x", "(?<=", "\\1", "\\2", "++", "*+", "?+", "\\A", "\\Z", "\\z"):
            assert banned not in p, (banned, p)
        assert all(ord(ch) < 128 for ch in p), p


@pytest.mark.parametrize("broken", [
    lambda d: d.update(version=2),
    lambda d: d.pop("handle"),
    lambda d: d["content"]["rules"].append({"id": "x", "kind": "age", "strength": "strong", "fields": ["bio"], "value": "none", "pattern": "("}),
    lambda d: d["content"]["rules"][0].update(unless=[["no_such_context", "clause"]]),
    lambda d: d["macros"].pop("AGE"),
])
def test_a_rules_file_that_does_not_validate_is_refused(broken):
    doc = json.loads(mr.RULES_PATH.read_text(encoding="utf-8"))
    broken(doc)
    with pytest.raises(mr.RulesError):
        mr.Engine(doc)


def test_without_the_rules_every_adult_pass_is_refused(monkeypatch, tmp_path):
    with pytest.raises(mr.RulesError):
        mr.load(tmp_path / "missing.json")
    (tmp_path / "bad.json").write_text("{not json")
    with pytest.raises(mr.RulesError):
        mr.load(tmp_path / "bad.json")
    monkeypatch.setattr(mr, "ENGINE", None)
    pr.note("torvalds", "maigret", {"results": []})
    assert ag.minor_indicated("torvalds") == ag.REASONS["rules"]
    status, body = ag.gate("torvalds")
    assert status == 400 and body["error_code"] == "minor_guard" and body["reason"] == ag.REASONS["rules"]
    assert ag.soft_birth_year("mike2010") is None


# ---- stage 2: the profiles ---------------------------------------------------------------

def scan(bio, handle=None, **extra):
    return mr.load().scan([{"source": BIOS["source"], "url": "https://example.org/p", "bio": bio, **extra}], handle or BIOS["handle"], TODAY)


def test_the_fixture_is_large_enough_and_split_three_ways():
    assert len(BIOS["block"]) >= 40 and len(BIOS["weak"]) >= 15 and len(BIOS["clean"]) >= 60
    assert len(BIOS["block"]) + len(BIOS["weak"]) + len(BIOS["clean"]) >= 60


@pytest.mark.parametrize("row", BIOS["block"], ids=lambda r: r["bio"][:40])
def test_a_strong_signal_blocks_alone(row):
    r = scan(row["bio"])
    assert r["blocked"] and r["kind"] == row["kind"] and r["signal"]["strength"] == "strong", (row, r["signals"])
    assert r["signal"]["source"] == BIOS["source"] and 0 < len(r["signal"]["snippet"]) <= 60 and "\n" not in r["signal"]["snippet"]


@pytest.mark.parametrize("row", BIOS["weak"], ids=lambda r: r["bio"][:40])
def test_a_weak_signal_blocks_only_with_a_soft_birth_year_in_the_handle(row):
    alone = scan(row["bio"])
    assert not alone["blocked"] and alone["signals"] and all(s["strength"] == "weak" for s in alone["signals"]), (row, alone["signals"])
    both = scan(row["bio"], handle="mike2010")
    assert both["blocked"] and both["kind"] == "soft" and both["soft"] == 2010 and both["signal"]["strength"] == "weak"
    years = scan(row["bio"], handle="sam_16yrs")
    assert years["blocked"] and years["kind"] == "soft" and years["soft_years"] == 16 and years["soft"] is None


@pytest.mark.parametrize("row", BIOS["clean"], ids=lambda r: r["bio"][:40] or "empty")
def test_ordinary_text_gives_no_signal_at_all(row):
    for handle in (None, "mike2010", "sam_16yrs"):
        r = scan(row["bio"], handle=handle)
        assert not r["blocked"] and r["signals"] == [], (row, r["signals"])


@pytest.mark.parametrize("case", BIOS["cases"], ids=lambda c: c["name"][:50])
def test_the_named_cases(case):
    r = mr.load().scan(case["profiles"], case["handle"], TODAY)
    assert (r["blocked"], r["kind"]) == (case["blocked"], case["kind"]), (case["name"], r["signals"])
    for key in ("source", "snippet"):
        if key in case:
            assert r["signal"][key] == case[key]
    for key in ("soft", "soft_years", "read"):
        if key in case:
            assert r[key] == case[key]
    if r["signal"]:
        assert len(r["signal"]["snippet"]) <= 60 and len(r["signal"]["source"]) <= 80


def test_class_years_are_relative_to_today():
    # Asserted against the date it is given, so it does not start failing in a later year.
    engine = mr.load()
    one = lambda bio, today, handle="river_stone": engine.scan([{"source": "S", "url": "", "bio": bio}], handle, today)
    for year in (2026, 2031, 2040):
        today = date(year, 11, 22)
        near, far, past = f"class of {year + 3}", f"class of {year + 5}", f"class of {year - 2}"
        assert not one(near, today)["blocked"] and one(near, today)["signals"][0]["strength"] == "weak"
        assert one(f"{near} \u00b7 Lincoln High", today)["blocked"] and one(f"{near} | 9th grade", today)["blocked"]
        assert one(far, today)["blocked"] and one(far, today)["kind"] == "school"
        assert one(past, today)["signals"] == [] and one(f"class of {year + 13}", today)["signals"] == []
        assert one(near, today, handle=f"mike{year - 16}")["kind"] == "soft"
        # This year's class counts until the end of June.
        assert one(f"class of {year} | high school", date(year, 6, 30))["blocked"] and one(f"class of {year} | high school", date(year, 7, 1))["kind"] != "school"
        assert one(f"born {year - 16}", today)["kind"] == "birth" and one(f"born {year - 19}", today)["signals"] == []


def test_adult_content_notices_do_not_cancel_a_signal():
    assert scan("18+ only | i'm 15")["blocked"] and scan("adults only. 8th grade")["blocked"]
    assert scan("18+")["signals"] == [] and scan("21+ | adults only")["signals"] == []


# ---- the record of the ordinary sources ----------------------------------------------------

BLOCKING = "16 | junior in high school"
OK = {"results": []}


def test_nothing_on_record_means_run_the_ordinary_sources_first():
    status, body = ag.gate("torvalds")
    assert status == 409 and body["error_code"] == body["code"] == "mainstream_first" and body["detail"] == body["error"] == ag.MAINSTREAM_MESSAGE


def test_the_profile_readers_are_named_once_in_the_rules_file():
    doc = json.loads(mr.RULES_PATH.read_text(encoding="utf-8"))
    assert doc["sources"]["profile_readers"] == [["maigret", "maigret"], ["platform_check", "platformCheck"]]
    assert pr.profile_readers() == ("maigret", "platform_check") and pr.text_order() == ("maigret", "github", "platform_check", "enricher")
    js = (Path(__file__).parent.parent / "static" / "v2" / "js" / "adult.js").read_text(encoding="utf-8")
    assert "sourceRoles()" in js and '"maigret", "platformCheck"' not in js      # the page reads the same list, and names no source of its own


@pytest.mark.parametrize("source", ["sherlock", "github", "enricher"])
def test_a_source_that_reads_no_profiles_does_not_open_the_gate(source):
    # Unknown is not clean: Sherlock, GitHub or enrichment alone leaves nothing to check.
    pr.note("torvalds", source, {"results": [], "found": True, "profiles": []})
    assert ag.gate("torvalds")[0] == 409 and pr.completed("torvalds") == [source] and not pr.ran("torvalds")


@pytest.mark.parametrize("source", ["maigret", "platform_check"])
def test_a_profile_reader_that_answered_opens_the_gate_for_a_clean_handle(source):
    pr.note("Torvalds", source, OK)
    assert ag.gate("torvalds") is None and ag.gate("@TORVALDS") is None      # the key ignores case and a leading @
    assert ag.gate("someone_else")[0] == 409


def test_a_failed_text_source_is_not_a_clean_check_and_a_later_success_clears_it():
    pr.note("torvalds", "sherlock", OK)
    pr.note("torvalds", "maigret", {"results": [], "error": "x", "error_code": "timeout"})
    pr.note("torvalds", "platform_check", {"error": "x", "error_code": "upstream"})
    assert pr.outcomes("torvalds") == {"sherlock": "ok", "maigret": "failed", "platform_check": "failed"}
    assert ag.gate("torvalds")[0] == 409
    # A site that blocked the platform check is not a failure of the source.
    pr.note("torvalds", "platform_check", {"results": [{"platform": "LinkedIn", "state": "blocked"}, {"platform": "Reddit", "state": "blocked"}]})
    assert pr.outcomes("torvalds")["platform_check"] == "ok" and ag.gate("torvalds") is None
    # A failed GitHub lookup does not close it again.
    pr.note("torvalds", "github", {"error": "rate limited", "error_code": "rate_limited"})
    assert ag.gate("torvalds") is None and pr.outcomes("torvalds")["github"] == "failed"
    pr.note("torvalds", "handle_probe", OK)
    assert "handle_probe" not in pr.outcomes("torvalds")


@pytest.mark.parametrize("source,answer,site", [
    ("enricher", {"profiles": [{"platform": "Instagram", "url": "https://www.instagram.com/river_stone/", "display_name": "River", "bio": BLOCKING}]}, "Instagram"),
    ("maigret", {"results": [{"site": "Gitlab", "url": "https://gitlab.com/river_stone", "verified": True, "confidence": "normal", "profile": {"name": "River", "bio": BLOCKING}}]}, "Gitlab"),
    ("platform_check", {"results": [{"platform": "Reddit", "state": "found", "url": "https://www.reddit.com/user/river_stone", "display_name": "", "bio": BLOCKING}]}, "Reddit"),
    ("github", {"found": True, "profile_url": "https://github.com/river_stone", "name": "River", "bio": BLOCKING}, "GitHub"),
])
def test_a_blocking_bio_on_record_refuses_the_adult_pass_with_the_source_and_the_snippet(source, answer, site):
    pr.note("river_stone", "maigret", OK)
    assert ag.gate("river_stone") is None
    pr.note("river_stone", source, answer)
    status, body = ag.gate("River_Stone")
    assert status == 400 and body["error_code"] == body["code"] == "minor_guard" and body["detail"] == ag.MESSAGE
    assert (body["kind"], body["source"], body["snippet"]) == ("age", site, BLOCKING) and body["reason"] == ag.CONTENT_REASONS["age"]
    assert body["url"].startswith("https://") and "river" not in body["reason"].lower()
    fields = ag.gate_fields((status, body))
    assert fields["error_code"] == "minor_guard" and fields["block_source"] == site and fields["block_snippet"] == BLOCKING


def test_a_block_is_sticky_and_text_is_never_overwritten():
    reddit = lambda bio: {"results": [{"platform": "Reddit", "state": "found", "url": "https://www.reddit.com/user/river_stone", "bio": bio}]}
    pr.note("river_stone", "platform_check", reddit("im 15"))
    assert ag.gate("river_stone")[0] == 400
    # The same source asked again about fewer sites, or answering with a clean bio: still blocked.
    pr.note("river_stone", "platform_check", {"results": []})
    assert ag.gate("river_stone")[1]["snippet"] == "im 15"
    pr.note("river_stone", "platform_check", reddit("Photos."))
    pr.note("river_stone", "maigret", OK)
    assert ag.gate("river_stone")[0] == 400 and [e["bio"] for e in pr.texts("river_stone")] == ["im 15", "Photos."]
    # Without a verdict asked in between, the union alone keeps the text: a Maigret re-run with fewer rows.
    rows = lambda *bios: {"results": [{"site": f"Site{i}", "url": f"https://site{i}.example/u", "verified": True, "profile": {"bio": b}} for i, b in enumerate(bios)]}
    pr.note("lake_view", "maigret", rows("hello", "8th grade"))
    pr.note("lake_view", "maigret", rows("hello"))
    assert ag.gate("lake_view")[1]["snippet"] == "8th grade"


def test_the_verdict_is_computed_once_per_change_of_the_record(monkeypatch):
    calls = []
    real = ag.content_check
    monkeypatch.setattr(ag, "content_check", lambda u: (calls.append(u), real(u))[1])
    pr.note("torvalds", "maigret", OK)
    for _ in range(50):
        assert ag.gate("torvalds") is None
    assert len(calls) == 1
    pr.note("torvalds", "github", {"found": True, "profile_url": "https://github.com/torvalds", "bio": "Kernel."})
    for _ in range(50):
        assert ag.gate("torvalds") is None
    assert len(calls) == 2


def test_the_record_is_bounded_and_never_drops_text_that_carries_a_signal():
    rows = lambda start, n, bio="hello": {"results": [{"site": f"Site{i}", "url": f"https://s{i}.example/u", "verified": True, "profile": {"bio": f"{bio} {i}"}} for i in range(start, start + n)]}
    pr.note("busy", "maigret", {"results": [{"site": "First", "url": "https://first.example/u", "verified": True, "profile": {"bio": "i'm 15"}}]})
    for batch in range(10):
        pr.note("busy", "maigret", rows(batch * 100, 100))
        pr.note("busy", "enricher", {"profiles": [{"platform": f"P{i}", "url": f"https://p{i}.example/u", "bio": f"text {i}"} for i in range(batch * 100, batch * 100 + 100)]})
    kept = pr.texts("busy")
    assert len(kept) <= pr.MAX_RECORD and sum(1 for e in kept if e["source"].startswith("Site") or e["source"] == "First") <= pr.MAX_ENTRIES
    assert kept[0]["bio"] == "i'm 15" and ag.gate("busy")[1]["snippet"] == "i'm 15"          # the oldest text, kept because it carries a signal
    # A record stuffed with signal text is capped hard too, and a scan of a full record is quick.
    import time
    pr.note("hostile", "maigret", rows(0, 3000, "i'm 15 and this is profile"))
    assert len(pr.texts("hostile")) <= pr.MAX_ENTRIES * 2
    t0 = time.perf_counter()
    assert ag.gate("hostile")[0] == 400
    for _ in range(40):
        ag.gate("hostile")
    assert time.perf_counter() - t0 < 2.0


def test_the_soft_signals_in_the_handle_combine_with_a_weak_signal_on_record():
    gh = lambda h, bio: pr.note(h, "github", {"found": True, "profile_url": f"https://github.com/{h}", "name": "Mike", "bio": bio})
    for h in ("mike2010", "sam_16yrs", "river_stone", "mike2011"):
        pr.note(h, "maigret", OK)
    gh("mike2011", "Go and Rust. Coffee.")
    assert ag.gate("mike2011") is None
    gh("mike2010", "class of 2029")
    status, body = ag.gate("mike2010")
    assert status == 400 and (body["kind"], body["source"], body["snippet"]) == ("soft", "GitHub", "class of 2029") and body["reason"] == ag.CONTENT_REASONS["soft"]
    assert body["reason"] == "A profile found for this handle suggests a minor, and the handle carries a matching age or birth year."
    gh("sam_16yrs", "freshman")
    assert ag.gate("sam_16yrs")[1]["kind"] == "soft"                # bare years in the handle are the other soft signal
    gh("river_stone", "class of 2029")
    assert ag.gate("river_stone") is None


def test_the_handle_check_still_runs_first():
    pr.note("alex_15yo", "maigret", OK)
    status, body = ag.gate("alex_15yo")
    assert status == 400 and body["reason"] == ag.REASONS["age"] and "kind" not in body


def test_the_record_expires_and_the_store_is_bounded(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(pr, "_now", lambda: clock[0])
    pr.note("torvalds", "maigret", OK)
    clock[0] += pr.TTL - 1
    assert ag.gate("torvalds") is None
    clock[0] += 2
    assert ag.gate("torvalds")[0] == 409 and pr.texts("torvalds") == [] and pr.completed("torvalds") == []
    assert pr.TTL == 30 * 60
    # Bounded: the oldest handle goes first.
    monkeypatch.setattr(pr, "MAX_HANDLES", 3)
    for h in ("h1", "h2", "h3", "h4"):
        pr.note(h, "maigret", OK)
    assert not pr.ran("h1") and pr.ran("h2") and pr.ran("h4") and len(pr._store) == 3
    # Text is clipped and only the fields the scan reads are kept.
    pr.note("h4", "github", {"found": True, "profile_url": "https://github.com/h4", "name": "n" * 900, "bio": "b" * 5000, "company": "Example Corp", "location": "Leeds",
                             "email": "x@example.org", "avatar_url": "https://example.org/a.png"})
    (entry,) = pr.texts("h4")
    assert set(entry) == {"source", "url", "name", "bio", "text"} and len(entry["name"]) == pr.NAME_MAX and len(entry["bio"]) == pr.BIO_MAX and entry["text"] == "Example Corp\nLeeds"


# ---- the visitor's session ------------------------------------------------------------------

def test_a_session_id_is_random_server_issued_and_nothing_else_is_accepted():
    a, new_a = pr.open_session("")
    b, new_b = pr.open_session(None)
    assert new_a and new_b and a != b and len(a) == 43 and pr._SESSION_SHAPE.match(a) and pr.SESSION_BYTES * 8 >= 128
    assert pr.open_session(a) == (a, False)                           # the server's own ID is kept
    for made_up in ("A" * 43, a[:-1] + ("A" if a[-1] != "A" else "B"), "short", "x" * 500, a + a, "../../etc/passwd", a.upper() if a.upper() != a else a.lower()):
        got, issued = pr.open_session(made_up)
        assert issued and got != made_up and made_up not in pr._sessions, made_up


def test_the_record_belongs_to_the_session_that_made_it():
    first, _ = pr.open_session("")
    second, _ = pr.open_session("")
    pr.bind(first)
    pr.note("river_stone", "maigret", {"results": [{"site": "Gitlab", "url": "https://gitlab.com/river_stone", "verified": True, "profile": {"bio": BLOCKING}}]})
    assert ag.gate("river_stone")[0] == 400 and pr.ran("river_stone")
    pr.bind(second)                                                   # another visitor: neither the block nor the run leaks
    assert ag.gate("river_stone")[0] == 409 and not pr.ran("river_stone") and pr.texts("river_stone") == []
    pr.note("river_stone", "maigret", OK)
    assert ag.gate("river_stone") is None                             # the second visitor's own clean run
    pr.bind(first)
    assert ag.gate("river_stone")[1]["snippet"] == BLOCKING           # and the first visitor's block stands
    pr.bind("")                                                       # no session at all: an ID nobody else has
    assert ag.gate("river_stone")[0] == 409
    pr.note("river_stone", "maigret", OK)
    pr.bind("")
    assert ag.gate("river_stone")[0] == 409                           # and two such requests do not share one


def test_sessions_expire_with_the_record_and_are_bounded(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(pr, "_now", lambda: clock[0])
    sid, _ = pr.open_session("")
    clock[0] += pr.TTL - 1
    assert pr.open_session(sid) == (sid, False)                       # seen again: it lives on
    clock[0] += pr.TTL + 1
    again, issued = pr.open_session(sid)
    assert issued and again != sid and sid not in pr._sessions
    monkeypatch.setattr(pr, "MAX_SESSIONS", 3)
    ids = [pr.open_session("")[0] for _ in range(5)]
    assert len(pr._sessions) == 3 and ids[0] not in pr._sessions and ids[-1] in pr._sessions
    assert pr.open_session(ids[0])[1] is True                         # an evicted ID is not a session any more


def test_the_record_keeps_no_adult_site_and_no_noisy_site_and_reads_the_guard_fields():
    long_bio = "x" * 400 + " i'm 15 " + "y" * 100
    pr.note("jdoe", "maigret", {"results": [
        {"site": "Pornhub", "url": "https://www.pornhub.com/users/jdoe", "verified": True, "adult": True, "profile": {"bio": "i'm 15"}},
        {"site": "Fansly", "url": "https://fansly.com/jdoe", "verified": True, "profile": {"bio": "i'm 15"}},
        {"site": "Noisy", "url": "https://noisy.example/jdoe", "verified": True, "confidence": "false_positive", "profile": {"bio": "i'm 15"}},
        {"site": "Gitlab", "url": "https://gitlab.com/jdoe", "verified": True, "profile": {"name": "J Doe", "bio": long_bio[:300], "location": "Leeds",
                                                                                           "guard": {"bio": long_bio, "text": "Lincoln High School", "birthday": "2010-08-14", "age": "15"}}},
    ]})
    (entry,) = pr.texts("jdoe")
    assert (entry["source"], entry["bio"], entry["text"], entry["birthday"], entry["age"]) == ("Gitlab", long_bio, "Leeds\nLincoln High School", "2010-08-14", "15")
    assert ag.gate("jdoe")[1]["snippet"].count("i'm 15") == 1           # read past the 300 characters a row shows


def test_maigret_hands_the_guard_the_whole_bio_and_the_other_text_fields():
    from modules import maigret_mod as mm
    bio = "Hello there. " * 30 + "i'm 15"
    p = mm.profile_signal({"uid": "1", "fullname": "A Person", "bio": bio, "about": "8th grade", "school": "Lincoln High", "occupation": "student", "birthday": "2011-02-03", "age": "15", "location": "Leeds"}, site="Example", username="jdoe")
    assert len(p["bio"]) == 300 and "i'm 15" not in p["bio"] and "birthday" not in p and "age" not in p
    assert p["guard"] == {"bio": bio.strip(), "text": "8th grade\nLincoln High\nstudent", "birthday": "2011-02-03", "age": "15"}
    assert "guard" not in mm.profile_signal({"uid": "1", "fullname": "A Person", "bio": "short"}, site="Example", username="jdoe")
    # An adult row never carries it.
    assert "guard" not in (mm.adult_profile({"uid": "1", "fullname": "A Person", "bio": bio, "age": "15"}, site="Example", username="jdoe") or {})


def _blocks(caplog):
    return [r for r in caplog.records if r.getMessage() == "minor guard block"]


def test_every_block_is_logged_with_its_rule_id_and_nothing_about_the_target(caplog):
    caplog.set_level(logging.INFO)
    # the handle check: the pattern that fired
    for handle, rule, kind in (("zq15yo_alex", "handle.age_then_yo", "age"), ("zq16yrsold", "handle.age_then_years_old", "age"),
                               ("age14zqjay", "handle.word_then_age", "age"), ("zqjailbait", "handle.words", "word")):
        caplog.clear()
        assert ag.gate(handle)[0] == 400
        (line,) = _blocks(caplog)
        assert (line.stage, line.rule, line.kind) == ("handle", rule, kind), handle
    # the content check: a strong rule, then a weak rule with the soft signal it needed
    caplog.clear()
    pr.note("zqriver", "maigret", OK)
    pr.note("zqriver", "github", {"found": True, "profile_url": "https://github.com/zqriver", "name": "Zq", "bio": "zqsecret high school student"})
    pr.note("zq2012", "maigret", OK)
    pr.note("zq2012", "github", {"found": True, "profile_url": "https://github.com/zq2012", "name": "Zq", "bio": "zqsecret class of 2029"})
    pr.note("sam_16yrs", "maigret", OK)
    pr.note("sam_16yrs", "github", {"found": True, "profile_url": "https://github.com/sam_16yrs", "name": "Zq", "bio": "freshman"})
    for handle in ("zqriver", "zq2012", "sam_16yrs", "zqriver", "zqriver"):      # a block is one line, however often it then refuses
        assert ag.gate(handle)[0] == 400
    lines = _blocks(caplog)
    assert [(r.stage, r.rule, r.kind, r.strength, getattr(r, "with", None)) for r in lines] == [
        ("content", "high_school_student", "school", "strong", None),
        ("content", "class_year", "soft", "weak", "soft_year"),
        ("content", "class_word", "soft", "weak", "soft_years"),
    ]
    # a pass that runs, and a pass refused because nothing is on record, are not blocks
    caplog.clear()
    pr.note("zqclean", "maigret", OK)
    assert ag.gate("zqclean") is None and ag.gate("zqnobody")[0] == 409 and _blocks(caplog) == []
    # every rule ID is a name from the rules file
    names = {r["id"] for r in RULES["content"]["rules"]} | {"birth_field", "age_field"} | {f"handle.{n}" for n in RULES["handle"]["age"]["patterns"]} | {"handle.words"}
    assert {"high_school_student", "class_year", "class_word", "handle.age_then_yo", "handle.words"} <= names


def test_a_block_line_holds_no_handle_snippet_site_or_address(caplog):
    caplog.set_level(logging.DEBUG)
    pr.note("zqriver", "maigret", OK)
    pr.note("zqriver", "github", {"found": True, "profile_url": "https://github.com/zqriver", "name": "Zq", "bio": "zqsecret high school student"})
    ag.gate("zqriver"), ag.gate("zq15yo_alex")
    lines = _blocks(caplog)
    assert len(lines) == 2
    text = " ".join(r.getMessage() + str(r.__dict__) for r in caplog.records).lower()
    for word in ("zqriver", "zq15yo", "zqsecret", "student\"", "github"):
        assert word not in text.replace("high_school_student", ""), word


def test_without_the_rules_the_refusal_is_logged_as_that(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(mr, "ENGINE", None)
    assert ag.gate("zqanyone")[0] == 400
    (line,) = _blocks(caplog)
    assert (line.stage, line.rule, line.kind) == ("handle", "rules_unavailable", "rules")


def test_nothing_in_the_record_is_logged(caplog):
    caplog.set_level(logging.DEBUG)
    sid, _ = pr.open_session("")
    pr.bind(sid)
    pr.note("quietperson", "maigret", OK)
    pr.note("quietperson", "github", {"found": True, "profile_url": "https://github.com/quietperson", "name": "Quiet Person", "bio": "zqsecret " + BLOCKING})
    ag.gate("quietperson")
    pr.texts("quietperson"), pr.ran("quietperson")
    text = " ".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert "quietperson" not in text and "zqsecret" not in text and "junior in high" not in text and sid not in text
    for name in ("core/profile_record.py", "middleware/run_session.py"):
        code = (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
        assert "import logging" not in code and "log." not in code and "print(" not in code, name


# ---- text-only output rules ------------------------------------------------------------

def test_strip_media_removes_image_keys_and_media_addresses_at_any_depth():
    row = {
        "site": "Image Fap", "url": "https://www.imagefap.com/profile/someone", "adult": True,
        "image": "https://cdn.example/a", "avatar_url": "https://cdn.example/b", "thumbnail": "x", "Banner": {"u": "y"},
        "profile": {"name": "Sam Example", "image": "https://cdn.example/c.jpg", "bio": "hello", "preview": ["a"],
                    "link": "https://cdn.example/clip.mp4?token=1", "followers": 3},
        "extra": ["plain", "https://cdn.example/pic.webp", {"photo": 1, "note": "kept"}],
    }
    assert ag.strip_media(row) == {
        "site": "Image Fap", "url": "https://www.imagefap.com/profile/someone", "adult": True,
        "profile": {"name": "Sam Example", "bio": "hello", "followers": 3},
        "extra": ["plain", {"note": "kept"}],
    }
    assert row["image"] == "https://cdn.example/a"        # the input is not changed


@pytest.mark.parametrize("text,expected", [
    ("Just here to chat.  Coffee first.", "Just here to chat. Coffee first."),
    ("line one\nline two", "line one line two"),
    ("see https://example.com/me", ""),
    ("my pics at example.com/me", ""),
    ("www.example.org", ""),
    ("<b>Hi</b> there", ""),
    ("look: photo.jpg", ""),
    ("", ""), (None, ""), (12, ""),
    ("x" * 400, "x" * 300),
])
def test_plain_text_keeps_prose_and_drops_links_and_markup(text, expected):
    assert ag.plain_text(text) == expected
