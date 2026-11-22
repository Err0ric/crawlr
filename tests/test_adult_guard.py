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
OWNER_BLOCK = ["14yo", "15y/o", "15_y_o", "age16", "16yrs", "16yrsold", "13yearsold", "15yo_alex", "age14jay"]
OWNER_RUN = ["gamer13", "sk8r_15", "10outof10", "err0ric17", "team14", "1337", "2015ford", "mike1999", "mike2010"]
# Handles the old rules refused and the new ones do not: a bare number, a year, a school word.
NO_LONGER_BLOCKED = ["emma09", "user2012", "apollo13", "kidrock", "canteen", "jake13", "15jake", "anna15", "born2012", "classof2029", "2k10",
                     "year9", "grade7", "sixteen", "teen", "minor", "kid", "schoolgirl", "f15", "m16", "im16", "turning15", "17f", "u18", "under18", "yo15", "15y", "y15"]


@pytest.mark.parametrize("handle", OWNER_BLOCK + ["9yo", "017yo", "user15yo", "x_age_16", "aged15", "age_14", "@15yo_Alex", "AGE14JAY"])
def test_an_explicit_age_under_18_in_the_handle_blocks(handle):
    assert ag.minor_indicated(handle) == ag.REASONS["age"], handle


@pytest.mark.parametrize("handle", ["underage", "preteen", "jailbait", "j41lb41t", "pr3t33n", "und3rage", "pre.teen", "under_age"])
def test_three_words_block_with_digits_read_as_letters(handle):
    assert ag.minor_indicated(handle) == ag.REASONS["word"], handle


@pytest.mark.parametrize("handle", OWNER_RUN + NO_LONGER_BLOCKED + ["page14", "stage15", "image16", "18yo", "21yo", "15yoga", "15yogurt", "16years_of_code", "thunderage", "age160", "age18", "100yo"])
def test_a_bare_number_or_an_ordinary_word_never_blocks(handle):
    assert ag.minor_indicated(handle) is None, (handle, ag.minor_indicated(handle))


@pytest.mark.parametrize("case", HANDLES["cases"], ids=lambda c: c["handle"] or "empty")
def test_every_fixture_handle(case):
    assert mr.load().handle_token(case["handle"]) == case["token"], case
    assert ag.minor_indicated(case["handle"]) == (ag.REASONS[case["token"]] if case["token"] else None)


def test_the_fixture_holds_both_directions():
    tokens = [c["token"] for c in HANDLES["cases"]]
    assert tokens.count("age") >= 25 and tokens.count("word") >= 8 and tokens.count(None) >= 60


def test_the_reason_is_a_fixed_sentence_that_never_repeats_the_handle_or_mentions_a_number_in_it():
    assert {ag.minor_indicated(c["handle"]) for c in HANDLES["cases"] if c["token"]} == {ag.REASONS["age"], ag.REASONS["word"]}
    for text in [*ag.REASONS.values(), *ag.CONTENT_REASONS.values(), ag.MESSAGE, ag.MAINSTREAM_MESSAGE]:
        assert "{" not in text and "%" not in text
        assert "number" not in text.lower() and "starts or ends" not in text and "10 to 17" not in text, text
    assert "zq9" not in ag.minor_indicated("zq9_15yo_zq9")


def test_the_soft_birth_year_follows_the_calendar(monkeypatch):
    for case in HANDLES["soft"]:
        assert ag.soft_birth_year(case["handle"]) == case["soft"], case
    # 2026: someone born in 2008 may still be 17, and 2020 is six years back.
    assert ag.soft_birth_year("mike2008") == 2008 and ag.soft_birth_year("mike2007") is None
    assert ag.soft_birth_year("mike2020") == 2020 and ag.soft_birth_year("mike2021") is None
    # It never blocks by itself.
    assert all(ag.minor_indicated(c["handle"]) is None for c in HANDLES["soft"])
    # Nothing is hard-coded: five years on the window has moved with the date.
    monkeypatch.setattr(ag, "_today", lambda: date(2031, 1, 1))
    assert ag.soft_birth_year("mike2010") is None and ag.soft_birth_year("mike2013") == 2013 and ag.soft_birth_year("mike2025") == 2025


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
    pr.note("torvalds", "sherlock", {"results": []})
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


@pytest.mark.parametrize("row", BIOS["clean"], ids=lambda r: r["bio"][:40] or "empty")
def test_ordinary_text_gives_no_signal_at_all(row):
    for handle in (None, "mike2010"):
        r = scan(row["bio"], handle=handle)
        assert not r["blocked"] and r["signals"] == [], (row, r["signals"])


@pytest.mark.parametrize("case", BIOS["cases"], ids=lambda c: c["name"][:50])
def test_the_named_cases(case):
    r = mr.load().scan(case["profiles"], case["handle"], TODAY)
    assert (r["blocked"], r["kind"]) == (case["blocked"], case["kind"]), (case["name"], r["signals"])
    for key in ("source", "snippet"):
        if key in case:
            assert r["signal"][key] == case[key]
    for key in ("soft", "read"):
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


def test_nothing_on_record_means_run_the_ordinary_sources_first():
    status, body = ag.gate("torvalds")
    assert status == 409 and body["error_code"] == body["code"] == "mainstream_first" and body["detail"] == body["error"] == ag.MAINSTREAM_MESSAGE
    # A follow-up source alone is not a mainstream pass, and neither is a source that failed.
    pr.note("torvalds", "enricher", {"profiles": []})
    pr.note("torvalds", "maigret", {"results": [], "error_code": "timeout", "error": "x"})
    pr.note("torvalds", "handle_probe", {"results": []})
    assert ag.gate("torvalds")[0] == 409 and pr.completed("torvalds") == ["enricher"]


@pytest.mark.parametrize("source", pr.MAINSTREAM)
def test_one_ordinary_source_on_record_opens_the_gate_for_a_clean_handle(source):
    pr.note("Torvalds", source, {"results": [], "found": False})
    assert ag.gate("torvalds") is None and ag.gate("@TORVALDS") is None      # the key ignores case and a leading @
    assert ag.gate("someone_else")[0] == 409


@pytest.mark.parametrize("source,answer,site", [
    ("enricher", {"profiles": [{"platform": "Instagram", "url": "https://www.instagram.com/river_stone/", "display_name": "River", "bio": BLOCKING}]}, "Instagram"),
    ("maigret", {"results": [{"site": "Gitlab", "url": "https://gitlab.com/river_stone", "verified": True, "confidence": "normal", "profile": {"name": "River", "bio": BLOCKING}}]}, "Gitlab"),
    ("platform_check", {"results": [{"platform": "Reddit", "state": "found", "url": "https://www.reddit.com/user/river_stone", "display_name": "", "bio": BLOCKING}]}, "Reddit"),
    ("github", {"found": True, "profile_url": "https://github.com/river_stone", "name": "River", "bio": BLOCKING}, "GitHub"),
])
def test_a_blocking_bio_on_record_refuses_the_adult_pass_with_the_source_and_the_snippet(source, answer, site):
    pr.note("river_stone", "sherlock", {"results": []})
    assert ag.gate("river_stone") is None
    pr.note("river_stone", source, answer)
    status, body = ag.gate("River_Stone")
    assert status == 400 and body["error_code"] == body["code"] == "minor_guard" and body["detail"] == ag.MESSAGE
    assert (body["kind"], body["source"], body["snippet"]) == ("age", site, BLOCKING) and body["reason"] == ag.CONTENT_REASONS["age"]
    assert body["url"].startswith("https://") and "river" not in body["reason"].lower()
    fields = ag.gate_fields((status, body))
    assert fields["error_code"] == "minor_guard" and fields["block_source"] == site and fields["block_snippet"] == BLOCKING
    # A later run that returns a clean bio for that source replaces the text.
    clean = json.loads(json.dumps(answer).replace(BLOCKING, "Go and Rust"))
    pr.note("river_stone", source, clean)
    assert ag.gate("river_stone") is None


def test_the_soft_year_in_the_handle_combines_with_a_weak_signal_on_record():
    pr.note("mike2010", "github", {"found": True, "profile_url": "https://github.com/mike2010", "name": "Mike", "bio": "Go and Rust. Coffee."})
    assert ag.gate("mike2010") is None
    pr.note("mike2010", "github", {"found": True, "profile_url": "https://github.com/mike2010", "name": "Mike", "bio": "class of 2029"})
    status, body = ag.gate("mike2010")
    assert status == 400 and (body["kind"], body["source"], body["snippet"]) == ("soft", "GitHub", "class of 2029") and body["reason"] == ag.CONTENT_REASONS["soft"]
    pr.note("river_stone", "github", {"found": True, "profile_url": "https://github.com/river_stone", "bio": "class of 2029"})
    assert ag.gate("river_stone") is None


def test_the_handle_check_still_runs_first():
    pr.note("alex_15yo", "sherlock", {"results": []})
    status, body = ag.gate("alex_15yo")
    assert status == 400 and body["reason"] == ag.REASONS["age"] and "kind" not in body


def test_the_record_expires_and_is_bounded(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(pr, "_now", lambda: clock[0])
    pr.note("torvalds", "sherlock", {"results": []})
    clock[0] += pr.TTL - 1
    assert ag.gate("torvalds") is None
    clock[0] += 2
    assert ag.gate("torvalds")[0] == 409 and pr.texts("torvalds") == [] and pr.completed("torvalds") == []
    assert pr.TTL == 30 * 60
    # Bounded: the oldest handle goes first.
    monkeypatch.setattr(pr, "MAX_HANDLES", 3)
    for h in ("h1", "h2", "h3", "h4"):
        pr.note(h, "sherlock", {"results": []})
    assert not pr.ran("h1") and pr.ran("h2") and pr.ran("h4") and len(pr._store) == 3 and all(k.endswith(("|h2", "|h3", "|h4")) for k in pr._store)
    # Text is clipped and only the fields the scan reads are kept.
    pr.note("h4", "github", {"found": True, "profile_url": "https://github.com/h4", "name": "n" * 900, "bio": "b" * 5000, "email": "x@example.org", "avatar_url": "https://example.org/a.png"})
    (entry,) = pr.texts("h4")
    assert set(entry) == {"source", "url", "name", "bio"} and len(entry["name"]) == pr.NAME_MAX and len(entry["bio"]) == pr.BIO_MAX


def test_the_record_belongs_to_the_caller_who_made_it():
    # One client's run says nothing to another: not that the handle was looked up, and not what was found.
    pr.bind("203.0.113.7")
    pr.note("river_stone", "sherlock", {"results": []})
    pr.note("river_stone", "github", {"found": True, "profile_url": "https://github.com/river_stone", "bio": BLOCKING})
    assert ag.gate("river_stone")[0] == 400 and pr.ran("river_stone")
    pr.bind("198.51.100.9")
    assert ag.gate("river_stone")[0] == 409 and not pr.ran("river_stone") and pr.texts("river_stone") == []
    pr.note("river_stone", "sherlock", {"results": []})
    assert ag.gate("river_stone") is None                          # the second client's own clean run
    pr.bind("203.0.113.7")
    assert ag.gate("river_stone")[1]["snippet"] == BLOCKING        # and the first client's block stands
    pr.bind("")


def test_the_record_keeps_no_adult_site_and_no_noisy_site():
    pr.note("jdoe", "maigret", {"results": [
        {"site": "Pornhub", "url": "https://www.pornhub.com/users/jdoe", "verified": True, "adult": True, "profile": {"bio": "i'm 15"}},
        {"site": "Fansly", "url": "https://fansly.com/jdoe", "verified": True, "profile": {"bio": "i'm 15"}},
        {"site": "Noisy", "url": "https://noisy.example/jdoe", "verified": True, "confidence": "false_positive", "profile": {"bio": "i'm 15"}},
        {"site": "Gitlab", "url": "https://gitlab.com/jdoe", "verified": True, "profile": {"name": "J Doe", "bio": "", "birthday": "2010-08-14", "age": "15"}},
    ]})
    assert [(e["source"], e.get("birthday"), e.get("age")) for e in pr.texts("jdoe")] == [("Gitlab", "2010-08-14", "15")]
    assert ag.gate("jdoe")[1]["kind"] == "birth"


def test_nothing_in_the_record_is_logged(caplog):
    caplog.set_level(logging.DEBUG)
    pr.note("quietperson", "github", {"found": True, "profile_url": "https://github.com/quietperson", "name": "Quiet Person", "bio": "zqsecret " + BLOCKING})
    ag.gate("quietperson")
    pr.texts("quietperson"), pr.ran("quietperson")
    text = " ".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert "quietperson" not in text and "zqsecret" not in text and "junior in high" not in text
    code = (Path(__file__).parent.parent / "core" / "profile_record.py").read_text(encoding="utf-8")
    assert "import logging" not in code and "log." not in code and "print(" not in code


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
