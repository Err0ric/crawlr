"""The minor guard and the text-only output rules for adult rows. No network."""

from datetime import date

import pytest

from core import adult_guard as ag


@pytest.fixture(autouse=True)
def _pin_today(monkeypatch):
    # The year rules are relative to today. Pin it so the cases below do not age.
    monkeypatch.setattr(ag, "_today", lambda: date(2026, 11, 14))


MUST_BLOCK = [
    # a stated age next to an age word, any order, any separator
    "13yo", "sam13yo", "15_yo", "15-yo", "jess.16.yo", "14yrs", "14yr", "16yearsold", "12_years_old", "9yo", "13y.o",
    "age14", "aged15", "age_16", "my.age.17", "myage14", "im16", "im_15", "iam17", "i_am_13", "under18", "u18",
    # an age next to a gender letter
    "17f", "16m", "f15", "m16", "anna_17f", "15.f", "f_14", "m-17", "x_16m",
    # written out
    "sixteen", "sweet_sixteen", "thirteen", "fourteen", "fifteen", "seventeen", "s1xteen", "twelveyo", "age_eleven",
    # a year that makes the person under 18 in 2026
    "born2012", "2011baby", "_2010", "sam_2010", "2013", "amy2013", "2013amy", "x2009x", "kay.2008", "born_2015", "jo2020", "2020",
    # a year from the last five blocks only next to a birth marker
    "born2025", "born_2024", "2023baby", "2022_baby", "bday2021", "birthday.2026", "b.2024", "b_2023", "2025born", "sam_b.2022",
    "classof2028", "class_of_2027", "co2029",
    # two-digit birth years with a leading zero at either end (2008 and 2009 in 2026)
    "emma09", "08emma", "liz_08", "09.sam", "kay-09",
    # two digits next to a birth marker, whatever the year in the last 18
    "born09", "born_08", "born19", "baby24", "bday.12", "b.09", "14born", "born26",
    # "2k" years
    "2k9", "2k09", "emma_2k10", "sam2k08", "2k20liz", "nba2k16",
    # two-digit class years, this year or later
    "classof27", "class_of_26", "co27", "c.o.30", "classof41",
    # grades 1 to 5 and ordinals, UK school years
    "grade_5", "5thgrade", "grade1", "1stgrade", "2nd_grade", "3rdgrader", "fifthgrade", "first_grade",
    "year7", "year_11", "yr9", "sam.yr10", "year8girl",
    # an age after a word that announces one, with or without a letter after it
    "turning15", "almost16x", "only_14", "just13b", "barely17", "age15x", "im16b", "aged_14k", "i_am_13lol", "myage15z",
    "quinceanera", "misquinceanos",
    # a bare number from 10 to 17 at either end
    "jake13", "15jake", "lily_10", "17.max", "emma17", "_12_", "apollo13",
    # school and minor words
    "minor", "im_a_minor", "underage", "preteen", "tween", "kid", "coolkid", "the_kid", "child", "wildchild",
    "schoolgirl", "school_girl", "schoolboy", "highschool", "high.school.guy", "middleschool", "freshman", "sophomore",
    "loli", "shota", "jailbait", "juniorhigh",
    "grade6", "grade_12", "7thgrade", "9th_grade", "8grader", "grader10", "sixthgrade",
    "teen", "teengirl", "teen17", "teen_16", "justateen", "teenager", "teen2019",
    # digits used as letters, and separators inside the word
    "k1d", "k.i.d", "m1n0r", "l0li", "l0l1", "t33n", "7een", "ch1ld", "sch00lgirl", "j41lb41t", "5hota",
    # case and a leading @ make no difference
    "Teen", "@Jake13", "BORN2012", "17F",
]

MUST_NOT_BLOCK = [
    "torvalds", "Err0ric", "user1999", "agent47", "r2d2", "x86_64", "john1985", "route66", "studio54", "2fast", "catch22",
    "teen19", "teen18", "teens18", "teenager19",
    "eighteen", "nineteen", "e1ghteen",
    "jane_doe", "a", "x", "0", "007", "h4x0r", "l33t", "neo", "max_power", "dr.who", "2pac", "50cent", "blink182", "sum41",
    "user2007", "born1990", "1985baby", "sam_2000",
    "user2025", "john2024", "jo2026", "2025", "sam_2021", "x2022x", "est2024", "est.2023", "since2025", "web2023", "bob2024", "b2024", "20071", "120100", "y2k", "mp3", "win95", "ps5", "area51",
    "18f", "f18", "m21", "25m", "f1", "m3", "m4a1", "2m", "5g", "24yo", "30yrs", "age18", "age21", "im18", "im_30",
    "page3", "stage4", "f150", "m1911", "x_16bit_x", "x_64bit",
    "between", "inbetween", "upgrade7", "classof1999", "class_of_2005",
    "1017", "x1700", "100", "170", "18", "19", "99", "user18", "18user",
    "kind", "kindred", "mentor", "lola", "shot", "tennis",
    # two-digit years that are adults: 2000 to 2007 with a zero, and anything read as an age of 18 or more
    "emma07", "06emma", "liz_05", "00sam", "agent_07", "emma18", "emma19", "20emma", "sam_21", "liz26", "emma99", "85sam",
    "born05", "born99", "baby85", "born_07", "b.90", "2k24", "nba2k24", "sam2k07", "2k", "y2k", "2k5",
    "classof25", "co99", "class_of_05", "co2", "disco27", "retrograde5", "upgrade3",
    "year2000", "year1", "year6", "newyear7", "yr2", "goodyear9",
    "turning18", "almost21", "just1", "only2", "barely18", "quince",
]


@pytest.mark.parametrize("handle", MUST_BLOCK)
def test_handles_that_suggest_a_minor_are_blocked(handle):
    reason = ag.minor_indicated(handle)
    assert reason in ag.REASONS.values(), handle


@pytest.mark.parametrize("handle", MUST_NOT_BLOCK)
def test_ordinary_handles_are_not_blocked(handle):
    assert ag.minor_indicated(handle) is None, (handle, ag.minor_indicated(handle))


@pytest.mark.parametrize("handle,key", [
    ("13yo", "age"), ("f15", "age"), ("under18", "age"), ("born2012", "birth_year"), ("classof2028", "class_year"),
    ("jake13", "number"), ("schoolgirl", "word"), ("teen", "word"), ("sixteen", "word"), ("grade7", "word"),
])
def test_the_reason_says_which_rule_fired(handle, key):
    assert ag.minor_indicated(handle) == ag.REASONS[key]


def test_the_reason_is_a_fixed_sentence_that_never_repeats_the_handle():
    assert {ag.minor_indicated(h) for h in MUST_BLOCK} == set(ag.REASONS.values())
    assert all("{" not in r and "%" not in r for r in ag.REASONS.values())
    assert "zq9" not in ag.minor_indicated("zq9_kid_zq9")


def test_the_year_rule_follows_the_calendar(monkeypatch):
    # In 2026 someone born in 2008 may still be 17, and someone born in 2007 is an adult.
    assert ag.minor_indicated("sam_2008") == ag.REASONS["birth_year"]
    assert ag.minor_indicated("sam_2007") is None
    # Nothing is hard-coded: five years on, 2012 is the last year that is blocked.
    monkeypatch.setattr(ag, "_today", lambda: date(2031, 1, 1))
    assert ag.minor_indicated("sam_2008") is None and ag.minor_indicated("sam_2012") is None
    assert ag.minor_indicated("sam_2013") == ag.REASONS["birth_year"]
    assert ag.minor_indicated("classof2031") == ag.REASONS["class_year"]
    monkeypatch.setattr(ag, "_today", lambda: date(2050, 6, 1))
    assert ag.minor_indicated("classof2028") is None and ag.minor_indicated("born2012") is None


def test_a_recent_year_needs_a_birth_marker():
    # 2026: ages 6 to 17 are the years 2009 to 2020, and 2008 may still be 17.
    for year in range(2008, 2021):
        assert ag.minor_indicated(f"sam_{year}") == ag.REASONS["birth_year"], year
    for year in range(2021, 2027):
        assert ag.minor_indicated(f"sam_{year}") is None and ag.minor_indicated(f"{year}sam") is None, year
        assert ag.minor_indicated(f"born{year}") == ag.minor_indicated(f"{year}_baby") == ag.REASONS["birth_year"], year
    assert ag.minor_indicated("born2027") is None and ag.minor_indicated("born1990") is None
    assert ag.minor_indicated("est2024") is None and ag.minor_indicated("bob2024") is None      # "est" and a name ending in b are not markers


def test_short_years_follow_the_calendar(monkeypatch):
    assert ag.minor_indicated("emma09") == ag.minor_indicated("2k09") == ag.minor_indicated("born09") == ag.REASONS["birth_year"]
    assert ag.minor_indicated("classof27") == ag.minor_indicated("co27") == ag.REASONS["class_year"]
    assert ag.minor_indicated("year9") == ag.minor_indicated("grade_3") == ag.REASONS["word"]
    assert ag.minor_indicated("turning15") == ag.REASONS["age"]
    # 2030: 2009 is 21, 2008 is 22, and classof27 has passed
    monkeypatch.setattr(ag, "_today", lambda: date(2030, 3, 1))
    for handle in ("emma09", "08emma", "2k09", "born09", "classof27", "co27"):
        assert ag.minor_indicated(handle) is None, handle
    assert ag.minor_indicated("born13") == ag.minor_indicated("2k13") == ag.REASONS["birth_year"]
    assert ag.minor_indicated("classof30") == ag.REASONS["class_year"]
    # 2090: "born95" is 1995, not 2095
    assert ag.minor_indicated("born95") is None


def test_today_is_the_real_date_by_default(monkeypatch):
    monkeypatch.undo()
    assert ag._today() == date.today()
    this_year = date.today().year
    assert ag.minor_indicated(f"sam_{this_year - 10}") == ag.REASONS["birth_year"]
    assert ag.minor_indicated(f"sam_{this_year - 2}") is None and ag.minor_indicated(f"born{this_year - 2}") == ag.REASONS["birth_year"]
    assert ag.minor_indicated(f"sam_{this_year - 30}") is None


def test_numbers_are_read_from_the_handle_as_written():
    # "x86_64" must not become the number 8664, and "1_7" is not the number 17.
    assert ag.minor_indicated("x86_64") is None and ag.minor_indicated("a1_7b") is None
    # Leetspeak is only applied to words: "f15" stays an age, it is not read as "fis".
    assert ag.minor_indicated("f15") == ag.REASONS["age"]


def test_there_is_no_override():
    import inspect
    assert list(inspect.signature(ag.minor_indicated).parameters) == ["username"]
    assert list(inspect.signature(ag.refusal).parameters) == ["username"]
    assert ag.minor_indicated("") is None and ag.minor_indicated(None) is None


def test_refusal_carries_the_error_fields_and_the_ui_keys():
    assert ag.refusal("torvalds") is None
    body = ag.refusal("jake13")
    assert body == {"detail": ag.MESSAGE, "code": "minor_guard", "reason": ag.REASONS["number"],
                    "error": ag.MESSAGE, "error_code": "minor_guard", "error_detail": ag.REASONS["number"]}
    assert "jake" not in str(body).lower()


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
