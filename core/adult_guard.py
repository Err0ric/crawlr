"""
Minor guard for the adult and dating site mode.

The opt-in mode asks adult and dating sites whether a handle exists. That must never be
pointed at someone who may be a child, so every server path that can reach such a site calls
`minor_indicated` first and refuses when the handle itself suggests a minor.

It is deliberately conservative. A false positive only hides the adult group for that handle
("apollo13" and "kidrock" are refused); a false negative is the thing to avoid. There is no
override: no parameter, header or setting turns this off.

What blocks:

  * an age under 18 next to an age word or a gender letter, in any order and with any
    separator: 13yo, 15_yo, age14, im16, 17f, f15, m16, 14yrs, under18, and the ages
    thirteen to seventeen written out
  * a four-digit year standing on its own that implies an age from 6 to 17 today (18 years
    back is included: the birthday may not have come yet): born2012, 2011baby, _2010, 2013
    as a prefix or suffix. A year that implies an age under 6 is usually the year the
    account was made (user2025), so it blocks only next to a birth marker: born2023,
    2024baby, bday2022, b.2021. Also a "class of" year that has not passed yet
  * the same years written short: 2k09 and 2k10, a zero-led two digits at either end
    (emma09, 08emma), any two digits next to a birth marker (born09, baby19), and a
    two-digit class year (classof27, co27)
  * a bare number from 10 to 17 at the start or the end of the handle
  * school and minor words: minor, underage, preteen, tween, kid, child, schoolgirl,
    schoolboy, highschool, middleschool, grade 1 to 12, UK school years (year7 to year11,
    yr9), freshman, sophomore, quinceanera, loli, shota,
    jailbait, and "teen" unless 18 or 19 follows it (teen18, teen19)

Words are matched after separators are removed and digits used as letters are read as
letters (k1d, l0li, t33n). Numbers are matched on the handle as written.

The reason returned is one of the fixed sentences in REASONS. It never repeats the handle.
"""

import re
from datetime import date

from core.errors import error_fields

ERROR_CODE = "minor_guard"
MESSAGE = "This handle may belong to a minor, so adult and dating sites are not checked for it."

REASONS = {
    "age": "The handle states an age under 18.",
    "birth_year": "The handle carries a year that would make the person under 18.",
    "class_year": "The handle carries a school class year that has not passed yet.",
    "number": "The handle starts or ends with a number from 10 to 17.",
    "word": "The handle contains a word that suggests a minor.",
}

ADULT_AGE = 18
_SEP = r"[._-]*"

# --- ages, on the handle as written (lowercase) -------------------------------------------
# 13yo, 15_yo, 14yrs, 16yearsold, 9y.o
_AGE_THEN_WORD = re.compile(rf"(?<!\d)(\d{{1,2}}){_SEP}(?:yo|y[._-]o|yrs?|years?|y(?![a-z]))")
# age14, aged15. Inside a longer word ("page3", "stage4") only two-digit ages count.
_WORD_THEN_AGE = re.compile(rf"(?<![a-z])aged?{_SEP}(\d{{1,2}})(?!\d)")
_INNER_AGE = re.compile(rf"aged?{_SEP}(1[0-7])(?!\d)")
# im16, i_am_15, iam17
_IM_AGE = re.compile(rf"(?<![a-z])i{_SEP}a?m{_SEP}(\d{{1,2}})(?!\d)")
# 17f, 16_m, f15, m16: a gender letter that is not part of a longer word
_AGE_THEN_SEX = re.compile(rf"(?<!\d)(\d{{1,2}}){_SEP}[fm](?![a-z])")
_SEX_THEN_AGE = re.compile(rf"(?<![a-z])[fm]{_SEP}(\d{{1,2}})(?!\d)")
# turning15, almost16x, only_14, just13: an age after a word that announces one
_NEAR_AGE = re.compile(rf"(?:turning|turned|almost|nearly|only|just|barely){_SEP}(\d{{1,2}})(?!\d)")
_UNDER_18 = re.compile(rf"under{_SEP}18(?!\d)|(?<![a-z])u{_SEP}18(?!\d)")
# Single digits next to a letter are everywhere (f1, m4, 2m), so those rules start at 8.
_LETTER_MIN_AGE = 8

# --- years and bare numbers, on the handle as written ----------------------------------------
_YEAR = re.compile(r"(?<!\d)((?:19|20)\d{2})(?!\d)")
# A year from the last few years is far more often the year an account was made than a birth
# year (user2025), so it only counts next to a birth marker: born2023, 2024baby, b.2022.
_MARKED_YEAR = re.compile(
    rf"(?:(?:born|birthday|bday|baby|kid){_SEP}|(?<![a-z])b[._-]+)(20\d{{2}})(?!\d)"
    rf"|(?<!\d)(20\d{{2}}){_SEP}(?:born|birthday|bday|baby|kid)"
)
MIN_PLAIN_AGE = 6         # a bare year must imply at least this age to count as a birth year
_CLASS_YEAR = re.compile(rf"(?:class{_SEP}(?:of)?|(?<![a-z])c{_SEP}o){_SEP}(20\d{{2}})(?!\d)")
# classof27, co27: a two-digit class year, read as 20xx, from this year up to CLASS_AHEAD years on
_CLASS_YEAR2 = re.compile(rf"(?:class{_SEP}(?:of)?|(?<![a-z])c{_SEP}o){_SEP}(\d{{2}})(?!\d)")
CLASS_AHEAD = 15
# emma09, 08emma, liz_08: a two-digit year with a leading zero at either end, read as 200x.
# Without the zero a two-digit number is read as an age: 10 to 17 block as a number, and 18
# and up are an adult's age far more often than a birth year.
_EDGE_YEAR2 = re.compile(r"^(0\d)(?!\d)|(?<!\d)(0\d)$")
# born09, baby19, 12born: any two-digit year next to a birth marker. Read as 20xx when that
# is not in the future, else 19xx.
_MARKED_YEAR2 = re.compile(
    rf"(?:(?:born|birthday|bday|baby){_SEP}|(?<![a-z])b[._-]+)(\d{{2}})(?!\d)"
    rf"|(?<!\d)(\d{{2}}){_SEP}(?:born|birthday|bday|baby)"
)
# 2k9, 2k09, emma_2k10: the year 2009, 2010
_YEAR_2K = re.compile(r"(?<!\d)2k(\d{1,2})(?!\d)")
# year7 to year11, yr9: UK school years
_SCHOOL_YEAR = re.compile(rf"(?<![a-z])(?:year|yr){_SEP}(?:1[01]|[7-9])(?!\d)")
_EDGE_NUMBER = re.compile(r"^(?:1[0-7])(?!\d)|(?<!\d)(?:1[0-7])$")

# --- words, on the handle with separators removed and digits read as letters ------------------
_LEET_I = str.maketrans("013457", "oieast")
_LEET_L = str.maketrans("013457", "oleast")
_WORDS = re.compile(
    r"minor|underage|preteen|(?<!be)tween|kid|child|schoolgirl|schoolboy|highschool|middleschool"
    r"|juniorhigh|jrhigh|freshman|sophomore|loli|shota|jailbait"
    r"|thirteen|fourteen|fifteen|sixteen|seventeen"
    r"|(?:first|second|third|fourth|fifth|sixth|seventh|eighth|ninth|tenth|eleventh|twelfth)grade"
    r"|quincean"
    r"|(?:ten|eleven|twelve)(?:yo|yrs?|years?)|aged?(?:ten|eleven|twelve)"
)
# grade1, grade_12, 5thgrade, 2ndgrade, 9grader: the number as written, separators removed
_GRADE = re.compile(r"(?<!up)(?<!retro)grader?(?:1[0-2]|[1-9])(?!\d)|(?<!\d)(?:1[0-2]|[1-9])(?:st|nd|rd|th)?grade")
# "teen" (also t33n, 7een), but not eighteen or nineteen, and not teen18 or teen19
_TEEN = re.compile(r"(?<!eigh)(?<!nine)(?<!e1gh)(?<!n1ne)[t7][e3][e3]n(?!(?:s|age|ager|agers)?1[89](?!\d))")


def _today() -> date:
    """The current date. A function so the tests can pin the year."""
    return date.today()


def _is_minor_age(text: str, floor: int = 1) -> bool:
    return floor <= int(text) < ADULT_AGE


def minor_indicated(username: str) -> str | None:
    """A short reason when the handle suggests a minor, else None."""
    raw = (username or "").strip().lstrip("@").lower()
    if not raw:
        return None

    # 1. a stated age
    if any(_is_minor_age(m.group(1)) for rx in (_AGE_THEN_WORD, _WORD_THEN_AGE, _INNER_AGE) for m in rx.finditer(raw)):
        return REASONS["age"]
    if any(_is_minor_age(m.group(1), _LETTER_MIN_AGE) for rx in (_IM_AGE, _AGE_THEN_SEX, _SEX_THEN_AGE, _NEAR_AGE) for m in rx.finditer(raw)):
        return REASONS["age"]
    if _UNDER_18.search(raw):
        return REASONS["age"]

    # 2. a year. Someone born 18 years ago may not have had this year's birthday yet, so that
    # year is still counted as under 18.
    this_year = _today().year
    if any(int(m.group(1)) >= this_year for m in _CLASS_YEAR.finditer(raw)):
        return REASONS["class_year"]
    if any(this_year <= 2000 + int(m.group(1)) <= this_year + CLASS_AHEAD for m in _CLASS_YEAR2.finditer(raw)):
        return REASONS["class_year"]
    if any(this_year - ADULT_AGE <= int(m.group(1)) <= this_year - MIN_PLAIN_AGE for m in _YEAR.finditer(raw)):
        return REASONS["birth_year"]
    if any(this_year - MIN_PLAIN_AGE < int(m.group(1) or m.group(2)) <= this_year for m in _MARKED_YEAR.finditer(raw)):
        return REASONS["birth_year"]

    # the same years written short: 2k09, a zero-led two digits at either end, born09
    plain = lambda year: this_year - ADULT_AGE <= year <= this_year - MIN_PLAIN_AGE
    if any(plain(2000 + int(m.group(1))) for m in _YEAR_2K.finditer(raw)):
        return REASONS["birth_year"]
    if any(plain(2000 + int(m.group(1) or m.group(2))) for m in _EDGE_YEAR2.finditer(raw.strip("._-"))):
        return REASONS["birth_year"]
    for m in _MARKED_YEAR2.finditer(raw):
        year = 2000 + int(m.group(1) or m.group(2))
        if year > this_year:
            year -= 100
        if this_year - year <= ADULT_AGE:
            return REASONS["birth_year"]

    # 3. a bare number from 10 to 17 at either end
    if _EDGE_NUMBER.search(raw.strip("._-")):
        return REASONS["number"]

    # 4. words
    joined = re.sub(r"[._-]+", "", raw)
    if _SCHOOL_YEAR.search(raw) or _TEEN.search(joined) or _GRADE.search(joined):
        return REASONS["word"]
    if any(_WORDS.search(joined.translate(table)) for table in (_LEET_I, _LEET_L)):
        return REASONS["word"]
    return None


def refusal(username: str) -> dict | None:
    """The body of the HTTP 400 a router sends when the guard blocks, or None when it does not.

    `detail` and `code` are what the UI's `post` helper reads; the other three keys are the
    usual core.errors fields.
    """
    reason = minor_indicated(username)
    if reason is None:
        return None
    return {"detail": MESSAGE, "code": ERROR_CODE, "reason": reason,
            **error_fields(code=ERROR_CODE, message=MESSAGE, detail=reason)}


# --------------------------------------------------------------------------------------
# Output rules for adult and dating rows: text only, never an image or media address.
# --------------------------------------------------------------------------------------
_MEDIA_KEY = re.compile(r"image|avatar|thumb|banner|photo|picture|cover|preview|poster|media|video|logo|icon", re.I)
_MEDIA_VALUE = re.compile(r"\.(?:jpe?g|png|webp|gif|avif|bmp|svg|mp4|m4v|webm|mov|m3u8)(?:$|[?#&/\s\"'])", re.I)
_LINK = re.compile(r"https?://|www\.|\b[\w-]+\.(?:com|net|org|io|me|tv|co|ly|gg|xxx|fans)\b/?", re.I)
_TAG = re.compile(r"<[^>]{1,200}>")
BIO_MAX = 300


def strip_media(value):
    """A copy of `value` without any key that names an image or media field and without any
    string that is a media address. Applied to every adult row before it leaves the server."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if _MEDIA_KEY.search(str(key)):
                continue
            if isinstance(item, str) and _MEDIA_VALUE.search(item):
                continue
            out[key] = strip_media(item)
        return out
    if isinstance(value, (list, tuple)):
        return [strip_media(item) for item in value if not (isinstance(item, str) and _MEDIA_VALUE.search(item))]
    return value


def plain_text(text, limit: int = BIO_MAX) -> str:
    """`text` when it is plain prose, else "". A bio that carries markup or a link is dropped
    whole: on these sites a link in a bio usually points at media."""
    if not isinstance(text, str):
        return ""
    flat = re.sub(r"\s+", " ", text).strip()
    if not flat or _TAG.search(flat) or _LINK.search(flat) or _MEDIA_VALUE.search(flat):
        return ""
    return flat[:limit]
