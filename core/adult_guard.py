"""
Minor guard for the adult and dating site mode.

The opt-in mode asks adult and dating sites whether a handle exists. That must never be
pointed at someone who may be a child. The guard has two stages, and every server path that
can reach such a site calls `gate` first. There is no override: no parameter, header or
setting turns either stage off.

  1. The handle (narrow, before anything runs). Only an age-specific token for 8 to 17
     blocks (14yo, 15y/o, 15_y_o, age16, 16yrsold, 13yearsold), or one of three words
     (underage, preteen, jailbait). A bare number in a handle never blocks: gamer13, sk8r_15
     and err0ric17 are ordinary handles. Years with no "old" (10yrs_exp, 12years_sober,
     16yrs) do not block either: like a birth year, they are a soft signal for stage 2.

  2. The profiles (the main guard). The adult pass is its own request, made after the
     ordinary sources. core.profile_record keeps the profile text those sources returned for
     the handle, per visitor; `gate` refuses when no source that reads profiles (Maigret or
     the platform check) has answered for it yet (HTTP 409, "mainstream_first"): with nothing
     to read, a clean check would mean nothing. Otherwise it scans that text for a stated age under 18, a school
     level, or a birth date under 18. A year in the handle that looks like a birth year, and
     bare years (16yrs), are soft signals: they block only together with a weaker sign in a
     profile.

The rules themselves (patterns, thresholds) are in static/v2/data/minor-rules.json, applied
by core.minor_rules here and by static/v2/js/minorscan.js in the page. If that file cannot be
loaded, every adult pass is refused.

The reasons returned are the fixed sentences below. They never repeat the handle and never
mention a number in it. A content refusal also carries the site and a short quoted snippet
of the profile text that triggered it, so the investigator can check it.
"""

import re
from datetime import date

from core import minor_rules, profile_record
from core.errors import error_fields

ERROR_CODE = "minor_guard"
MESSAGE = "Adult and dating sites are not checked for this handle."
MAINSTREAM_CODE = "mainstream_first"
MAINSTREAM_MESSAGE = "Run a source that reads profiles for this handle first (Maigret or the platform check): adult and dating sites are checked only after its profiles have been read."
PASS_MESSAGE = "Adult and dating sites run as their own pass after the ordinary sources: send nsfw and adult_only together."

REASONS = {
    "age": "The handle states an age under 18.",
    "word": "The handle contains a word that marks it as a minor's.",
    "rules": "The minor rules could not be loaded.",
}
CONTENT_REASONS = {
    "age": "A profile found for this handle states an age under 18.",
    "school": "A profile found for this handle suggests a school-age person.",
    "birth": "A profile found for this handle states a birth date under 18.",
    "soft": "A profile found for this handle suggests a minor, and the handle carries a matching age or birth year.",
}


def _today() -> date:
    """The current date. A function so the tests can pin it."""
    return date.today()


def minor_indicated(username: str) -> str | None:
    """A fixed reason when the handle itself states an age under 18 or carries one of the
    three words, else None. Without the rules file everything is refused."""
    engine = minor_rules.ENGINE
    if engine is None:
        return REASONS["rules"]
    token = engine.handle_token(username)
    return REASONS[token] if token else None


def soft_birth_year(username: str) -> int | None:
    """A four-digit year in the handle that would make the person 6 to 18 today, else None.
    A soft signal: it never blocks on its own."""
    engine = minor_rules.ENGINE
    return engine.soft_birth_year(username, _today()) if engine else None


def _body(reason: str, **extra) -> dict:
    return {"detail": MESSAGE, "code": ERROR_CODE, "reason": reason, **extra,
            **error_fields(code=ERROR_CODE, message=MESSAGE, detail=reason)}


def refusal(username: str) -> dict | None:
    """Stage 1 only: the body of the HTTP 400 for a handle that fails the handle check.

    `detail` and `code` are what the UI's `post` helper reads; the other three keys are the
    usual core.errors fields.
    """
    reason = minor_indicated(username)
    return _body(reason) if reason else None


def content_check(username: str) -> dict:
    """The content check over the profile text on record for this handle."""
    return minor_rules.ENGINE.scan(profile_record.texts(username), username, _today())


def gate(username: str) -> tuple[int, dict] | None:
    """Both stages. None when an adult pass may run for this handle, else (HTTP status, body).

      400 minor_guard        the handle fails the handle check, or a profile on record for it
                             suggests a minor (the body then has kind, source, snippet, url)
      409 mainstream_first   no source that reads profiles has answered for the handle inside
                             the record's TTL, under this visitor's session
    """
    first = refusal(username)
    if first:
        return 400, first
    if not profile_record.ran(username):
        return 409, {"detail": MAINSTREAM_MESSAGE, "code": MAINSTREAM_CODE,
                     **error_fields(code=MAINSTREAM_CODE, message=MAINSTREAM_MESSAGE, detail="")}
    # One scan per change of the record, and a block stays for the record's lifetime: a later
    # answer with fewer rows cannot make the server forget what it read.
    block = profile_record.verdict(username, lambda: _content_block(username))
    if block:
        return 400, _body(CONTENT_REASONS[block["kind"]], **block)
    return None


def _content_block(username: str) -> dict | None:
    found = content_check(username)
    if not found["blocked"]:
        return None
    s = found["signal"]
    return {"kind": found["kind"], "source": s["source"], "snippet": s["snippet"], "url": s["url"]}


def gate_fields(refused: tuple[int, dict]) -> dict:
    """The same refusal as the fields a module returns (the second lock, behind the router)."""
    body = refused[1]
    out = error_fields(code=body["error_code"], message=body["error"], detail=body["error_detail"])
    for key in ("kind", "source", "snippet"):
        if key in body:
            out[f"block_{key}"] = body[key]
    return out


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
