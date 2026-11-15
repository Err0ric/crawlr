"""
What a phone number is, from open numbering data. No key needed.

Three sources, each with its own state, so one failing never blanks the others:

  numbering_plan  Google's libphonenumber (the `phonenumbers` package). Offline: nothing leaves
                  the server. Says whether the number is possible and valid for its country,
                  how it is written, its line type, and where and to whom its number RANGE was
                  assigned.
  npa_nxx         Local Calling Guide's public XML query, for United States and Canadian
                  geographic numbers only. It is asked for the area code and exchange (NPA and
                  NXX, the first six digits) and NEVER for the full number: the last four digits
                  do not leave the server. Answers are cached per NPA-NXX for 7 days.
  numlookup       Optional. Only when the visitor sent their own NumLookup key, the number goes
                  to that service, which is what the key is for. It adds the current carrier.

Everything here describes the number and its range. Nothing says who uses the number or where
that person is, and no source that would is asked. The outbound search links are built here
and opened by the investigator; CrawlR never fetches them.

Nothing in this module logs the number.
"""

import asyncio
import html
import re
import time
from collections import OrderedDict
from urllib.parse import quote, quote_plus

import httpx
import phonenumbers as pn
from phonenumbers import shortnumberinfo

from core.errors import classify, classify_status, error_fields

PLAN_SOURCE = "Numbering plan"
NPA_SOURCE = "Local Calling Guide"
NUMLOOKUP_SOURCE = "NumLookup"

NPA_URL = "https://localcallingguide.com/xmlprefix.php"
NPA_PAGE = "https://localcallingguide.com/lca_prefix.php?npa={npa}&nxx={nxx}"
NUMLOOKUP_URL = "https://api.numlookupapi.com/v1/validate/{number}"
HEADERS = {"User-Agent": "Crawlr/0.1"}

NPA_TIMEOUT = 8
NPA_TTL = 7 * 24 * 3600
NPA_CACHE_MAX = 5000
NPA_PAUSE = 120                # after a rate limit, do not ask again for this long
NPA_MAX_BYTES = 200_000
NUMLOOKUP_TIMEOUT = 10

AREA_NOTE = "Where this number range is assigned. It is not where the phone or the person using it is."
CARRIER_NOTE = ("The carrier this number range was first assigned to. Numbers are ported between carriers, "
                "so it may not be the current one.")
OWNER_NOTE = "Who uses this number is not something open numbering data shows."

_npa_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_npa_pause_until = 0.0


def clear_cache_for_tests() -> None:
    global _npa_pause_until
    _npa_cache.clear()
    _npa_pause_until = 0.0


class PhoneInputError(ValueError):
    """The text cannot be read as a phone number at all. The router answers 400 with the message."""


# ---- plain words ------------------------------------------------------------------------
T = pn.PhoneNumberType
LINE_TYPES = {
    T.FIXED_LINE: ("fixed_line", "Fixed line"),
    T.MOBILE: ("mobile", "Mobile"),
    T.FIXED_LINE_OR_MOBILE: ("fixed_line_or_mobile", "Fixed line or mobile"),
    T.TOLL_FREE: ("toll_free", "Toll free"),
    T.PREMIUM_RATE: ("premium_rate", "Premium rate"),
    T.SHARED_COST: ("shared_cost", "Shared cost"),
    T.VOIP: ("voip", "VoIP"),
    T.PERSONAL_NUMBER: ("personal_number", "Personal number"),
    T.PAGER: ("pager", "Pager"),
    T.UAN: ("uan", "Company number (UAN)"),
    T.VOICEMAIL: ("voicemail", "Voicemail access"),
    T.UNKNOWN: ("unknown", "Unknown"),
}
# Number types that belong to no place: nothing geographic is said about them.
_NON_GEO = {T.TOLL_FREE, T.PREMIUM_RATE, T.SHARED_COST, T.VOIP, T.PERSONAL_NUMBER, T.PAGER, T.UAN, T.VOICEMAIL}
# Number types a geographic block lookup makes sense for.
_GEO_TYPES = {T.FIXED_LINE, T.MOBILE, T.FIXED_LINE_OR_MOBILE}
NANP_NAME = "North America (+1)"

# Ofcom's ranges for TV and radio drama, as the first seven digits of the national number
# (the last three are free). Source: Ofcom, "Telephone numbers for use in TV and radio drama".
UK_DRAMA = {
    "1134960": "Leeds", "1144960": "Sheffield", "1154960": "Nottingham", "1164960": "Leicester",
    "1174960": "Bristol", "1184960": "Reading", "1214960": "Birmingham", "1314960": "Edinburgh",
    "1414960": "Glasgow", "1514960": "Liverpool", "1614960": "Manchester", "2079460": "London",
    "1914980": "Tyneside, Durham and Sunderland", "2896496": "Northern Ireland", "2920180": "Cardiff",
    "1632960": "no area", "7700900": "mobile", "8081570": "freephone", "9098790": "premium rate",
    "3069990": "UK-wide",
}


def _plan_data():
    """The library's area, carrier, time zone and country name tables. They are large (about
    115 MB once loaded), so they are imported on the first lookup and not when the app starts."""
    from phonenumbers import carrier, geocoder, timezone
    from phonenumbers.geodata.locale import LOCALE_DATA
    return geocoder, carrier, timezone, LOCALE_DATA


def _clip(v, n: int = 80) -> str:
    return " ".join(str(v or "").split())[:n]


def _country_name(region: str | None) -> str:
    if not region or region == "001":
        return ""
    names = _plan_data()[3].get(region, {})
    name = names.get("en", "")
    if name.startswith("*"):            # "*aa" means the name is held under that other language key
        name = names.get(name[1:], "")
    return name or region


_ARTICLE = ("United ", "Netherlands", "Philippines", "Bahamas", "Gambia", "Maldives", "Czech Republic", "Dominican Republic",
            "Central African Republic", "Democratic Republic", "Republic of", "Isle of", "British ", "U.S. ", "Cayman ", "Cook ",
            "Faroe ", "Falkland ", "Marshall ", "Solomon ", "Turks ", "Northern Mariana", "Seychelles", "Comoros")


def _the(name: str) -> str:
    """A country name as it reads inside a sentence: "the United States", "Germany"."""
    return f"the {name}" if name.startswith(_ARTICLE) else name


def _country(n: pn.PhoneNumber, number_type: int) -> tuple[str, str]:
    """(ISO region or "", display name) for a parsed number. A +1 number that belongs to no
    place (toll free, premium rate) is shared by the whole plan, so no country is named."""
    region = pn.region_code_for_number(n)
    if n.country_code == 1 and (number_type in _NON_GEO or not region):
        return "", NANP_NAME
    if region == "001":
        return "", "International (not tied to one country)"
    if not region:
        region = pn.region_code_for_country_code(n.country_code)
        if region in ("ZZ", "001", None):
            return "", ""
    return region, _country_name(region)


def _finding(level: str, code: str, title: str, detail: str) -> dict:
    return {"level": level, "code": code, "title": title, "detail": detail}


def fiction_range(n: pn.PhoneNumber, number_type: int = T.FIXED_LINE_OR_MOBILE) -> str:
    """Why this number is reserved for fiction, or "". Only ranges a regulator has published."""
    nsn = str(n.national_number)
    geographic = number_type in _GEO_TYPES or number_type == T.UNKNOWN
    if n.country_code == 1 and len(nsn) == 10 and nsn[3:6] == "555" and nsn[6:8] == "01" and (geographic or nsn == "8005550199"):
        return ("In North America 555-0100 to 555-0199 is set aside for films, television and examples. "
                "It is reserved for fiction and is not in use, so nobody can be reached on it.")
    if n.country_code == 44 and len(nsn) == 10 and nsn[:7] in UK_DRAMA:
        return (f"Ofcom sets this range aside for television and radio drama ({UK_DRAMA[nsn[:7]]}). "
                "It is reserved for fiction and is not in use, so nobody can be reached on it.")
    return ""


# ---- parsing ----------------------------------------------------------------------------
def _parse(raw: str, region: str) -> tuple[pn.PhoneNumber, str]:
    """(number, how the country was decided): "given", "assumed" (the region hint was used) or
    "no_plus" (digits that only make a valid number when read as country code first)."""
    try:
        n = pn.parse(raw, region, keep_raw_input=True)
    except pn.NumberParseException as e:
        if e.error_type == pn.NumberParseException.INVALID_COUNTRY_CODE:
            raise
        raise PhoneInputError({
            pn.NumberParseException.NOT_A_NUMBER: "That does not read as a phone number. Enter digits with an optional + and country code.",
            pn.NumberParseException.TOO_SHORT_AFTER_IDD: "That is too short to be a phone number: nothing follows the international prefix.",
            pn.NumberParseException.TOO_SHORT_NSN: "That is too short to be a phone number.",
            pn.NumberParseException.TOO_LONG: "That is too long to be a phone number.",
        }.get(e.error_type, "That does not read as a phone number.")) from None
    src = n.country_code_source
    if src != pn.CountryCodeSource.FROM_DEFAULT_COUNTRY:
        return n, "given"
    digits = "" if n.extension or pn.is_alpha_number(raw) else re.sub(r"\D", "", raw)
    # "00" is the international prefix in most of the world. Where the hint region uses another
    # one (011 in North America) the library reads 00 as part of a national number.
    if re.match(r"^\(?00[1-9]", raw.strip()):
        try:
            return pn.parse("+" + re.sub(r"^\(?00", "", raw.strip()), None, keep_raw_input=True), "given"
        except pn.NumberParseException as e:
            if e.error_type == pn.NumberParseException.INVALID_COUNTRY_CODE:
                raise
    # Digits that are not a number in the hint region but are one when the country code comes
    # first ("447911123456"): people often leave the + out.
    if not pn.is_valid_number(n) and 10 <= len(digits) <= 15 and not raw.strip().startswith("0"):
        try:
            alt = pn.parse("+" + raw.strip(), None, keep_raw_input=True)
            if pn.is_valid_number(alt):
                return alt, "no_plus"
        except pn.NumberParseException:
            pass
    return n, "assumed"


def _short_code(raw: str, region: str) -> dict | None:
    """A short code or an emergency number in the hint region, or None. These are services, not
    subscriber numbers, so nothing else is looked up for them."""
    text = raw.strip()
    digits = re.sub(r"\D", "", text)
    if text.startswith("+") or not 2 <= len(digits) <= 6 or digits != re.sub(r"[\s\-.()]", "", text):
        return None
    try:
        n = pn.parse(digits, region)
    except pn.NumberParseException:
        return None
    emergency = shortnumberinfo.is_emergency_number(digits, region)
    if not emergency and not shortnumberinfo.is_valid_short_number_for_region(n, region):
        return None
    country = _country_name(region)
    if emergency:
        f = _finding("flag", "emergency", "Emergency number",
                     f"{digits} is an emergency number in {_the(country)}. It is a service, not a subscriber number, so there is nothing to look up. Do not call it to test it.")
    else:
        f = _finding("info", "short_code", "Short code",
                     f"{digits} is a short code in {_the(country)}: a service number that only works inside that country's networks. It is not a subscriber number, so there is nothing to look up.")
    return {"kind": "emergency" if emergency else "short_code", "digits": digits, "region": region, "country": country, "finding": f}


def _possible_reason(n: pn.PhoneNumber, country: str) -> tuple[bool, str]:
    r = pn.is_possible_number_with_reason(n)
    V = pn.ValidationResult
    where = country
    return r == V.IS_POSSIBLE, {
        V.IS_POSSIBLE: "",
        V.IS_POSSIBLE_LOCAL_ONLY: "it has no area code, so it can only be dialled from inside its own area",
        V.INVALID_COUNTRY_CODE: "the country code is not in use",
        V.TOO_SHORT: f"too short for {where}",
        V.TOO_LONG: f"too long for {where}",
        V.INVALID_LENGTH: f"the wrong length for {where}",
    }.get(r, "the wrong length")


def _dashed(national: str) -> str:
    return "-".join(re.findall(r"\d+", national))


def search_links(e164: str, international: str, national: str, *, nanp: bool) -> list[dict]:
    """Free pages the investigator can open. Each one sends the number to that site, and the
    group says so. Search engines get the number in its common written forms, quoted. The
    community spam-report sites are free to read without an account and cover +1 numbers only."""
    forms = []
    for f in (national, _dashed(national), international, e164):
        if f and f not in forms:
            forms.append(f)
    q = quote_plus(" OR ".join(f'"{f}"' for f in forms))
    out = [
        {"site": "Google", "url": f"https://www.google.com/search?q={q}", "group": "search engine"},
        {"site": "Bing", "url": f"https://www.bing.com/search?q={q}", "group": "search engine"},
        {"site": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={q}", "group": "search engine"},
    ]
    digits = e164.lstrip("+")
    if nanp and len(digits) == 11:
        ten = digits[1:]
        out += [
            {"site": "800notes", "url": f"https://800notes.com/Phone.aspx/1-{ten[:3]}-{ten[3:6]}-{ten[6:]}", "group": "spam reports"},
            {"site": "Should I Answer", "url": f"https://www.shouldianswer.com/phone-number/{ten}", "group": "spam reports"},
            {"site": "WhoCallsMe", "url": f"https://whocallsme.com/Phone-Number.aspx/{ten}", "group": "spam reports"},
        ]
    for row in out:
        row["kind"] = "search"
        row["label"] = "community reports of unwanted calls" if row["group"] == "spam reports" else "the number in its common written forms"
    return out


# ---- offline facts ----------------------------------------------------------------------
def offline_facts(raw: str, region: str = "US") -> dict:
    """Everything the numbering plan says, with no network. Raises PhoneInputError for text
    that is not a phone number."""
    region = (region or "US").upper()
    if region not in pn.SUPPORTED_REGIONS:
        raise PhoneInputError("The region is not a country code CrawlR knows. Use two letters, for example US or GB.")
    base = {
        "input": raw, "parsed": False, "kind": "number", "normalized": None,
        "valid": None, "country": None, "country_code": None, "location": None, "carrier": None, "line_type": None,
        "number": None, "assignment": None, "findings": [],
        "sources": {"numbering_plan": {"name": "libphonenumber", "state": "ok", "version": pn.__version__, "offline": True}},
        "search_links": [], "owner_note": OWNER_NOTE,
    }

    short = _short_code(raw, region)
    if short:
        base.update(parsed=True, kind=short["kind"], valid=False, country=short["country"], country_code=short["region"],
                    line_type="Emergency number" if short["kind"] == "emergency" else "Short code")
        base["number"] = {"short": short["digits"], "region": short["region"], "country": short["country"], "possible": False, "valid": False,
                          "validity_text": "Not a subscriber number.", "region_assumed": True,
                          "assumed_text": f"Read as a number dialled in {_the(short['country'])}."}
        base["findings"] = [short["finding"]]
        return base

    try:
        n, how = _parse(raw, region)
    except pn.NumberParseException:
        base.update(valid=False)
        base["number"] = {"possible": False, "valid": False, "possible_reason": "the country code is not in use",
                          "validity_text": "Not valid: the country code is not in use."}
        base["findings"] = [_finding("flag", "invalid", "Not a valid number", "The digits after the + do not start with a country code that is in use.")]
        return base

    number_type = pn.number_type(n)
    iso, country = _country(n, number_type)
    if how == "assumed" and pn.is_possible_number_with_reason(n) != pn.ValidationResult.IS_POSSIBLE:
        iso, country = region, _country_name(region)     # nothing fits, so name the country it was read as
    where = _the(country) if country else f"+{n.country_code}"
    possible, reason = _possible_reason(n, where)
    valid = possible and pn.is_valid_number(n)
    code, type_text = LINE_TYPES.get(number_type, LINE_TYPES[T.UNKNOWN])
    fiction = fiction_range(n, number_type)
    e164 = pn.format_number(n, pn.PhoneNumberFormat.E164)
    international = pn.format_number(pn.PhoneNumber(country_code=n.country_code, national_number=n.national_number, italian_leading_zero=n.italian_leading_zero, number_of_leading_zeros=n.number_of_leading_zeros), pn.PhoneNumberFormat.INTERNATIONAL)
    national = pn.format_number(pn.PhoneNumber(country_code=n.country_code, national_number=n.national_number, italian_leading_zero=n.italian_leading_zero, number_of_leading_zeros=n.number_of_leading_zeros), pn.PhoneNumberFormat.NATIONAL)

    if valid:
        validity_text = f"Valid: the digits fit a number range in the numbering plan of {where}."
    elif possible:
        validity_text = f"Not valid: the length is right for {where}, but no number range in its plan starts with these digits."
    else:
        validity_text = f"Not valid: {reason}."

    pn_geocoder, pn_carrier, pn_timezone, _ = _plan_data()
    zones = [z for z in pn_timezone.time_zones_for_number(n) if z and z != "Etc/Unknown"] if valid else []
    area = _clip(pn_geocoder.description_for_number(n, "en")) if valid and number_type not in _NON_GEO else ""
    if area == country:
        area = ""                       # the library fell back to the country: no finer area is known
    assigned_carrier = _clip(pn_carrier.name_for_number(n, "en")) if valid else ""

    assumed_text = ""
    if how == "assumed":
        name = _country_name(region)
        assumed_text = f"No country code given, read as a {name} number." if name.startswith("United ") else f"No country code given, read as a number from {_the(name)}."
    elif how == "no_plus":
        assumed_text = f"No + given. The digits only make a valid number when read with country code +{n.country_code} first, so they were read that way."

    findings = []
    if how == "assumed":
        findings.append(_finding("info", "assumed_country", assumed_text.rstrip("."), "Add the country code with a + (for example +44) if the number belongs somewhere else."))
    elif how == "no_plus":
        findings.append(_finding("info", "assumed_plus", f"No + given, read with country code +{n.country_code}", "The digits only make a valid number when the country code comes first, so they were read that way. Write the + to be sure."))
    if pn.is_alpha_number(raw):
        findings.append(_finding("info", "vanity", "Letters read as keypad digits", f"The letters were turned into the digits they share a key with: {national}."))
    if n.extension:
        findings.append(_finding("info", "extension", f"Extension {_clip(n.extension, 12)}", "An extension is dialled after the call connects. It belongs to the organisation's own phone system and says nothing about the number range."))
    if fiction:
        findings.append(_finding("flag", "fiction", "Reserved for fiction", fiction))
    if valid and not fiction:
        findings.append(_finding("ok", "valid", f"Valid number for {where}", "The digits fit a number range in the numbering plan. That shows the number can exist. It does not show that it is in service."))
    elif not fiction:
        findings.append(_finding("flag", "invalid", f"Not a valid number for {where}", (lambda t: t[:1].upper() + t[1:])(validity_text.replace("Not valid: ", ""))))
    type_note = ""
    if valid:
        if number_type == T.FIXED_LINE_OR_MOBILE:
            type_note = f"The numbering plan of {where} does not keep fixed lines and mobiles in separate ranges, so the number alone cannot say which this is."
        elif number_type == T.TOLL_FREE:
            findings.append(_finding("info", "toll_free", "Toll-free number", "Calls are paid for by whoever holds the number, usually an organisation. A toll-free number is not tied to a place."))
        elif number_type == T.PREMIUM_RATE:
            findings.append(_finding("flag", "premium_rate", "Premium-rate number", "Calls to this number are charged at a premium. Missed-call and call-back scams often use these ranges."))
        elif number_type == T.VOIP:
            findings.append(_finding("flag", "voip", "VoIP number", "VoIP numbers are easy to get and discard, and are not tied to a place or a SIM card."))
        elif number_type == T.PERSONAL_NUMBER:
            findings.append(_finding("flag", "personal_number", "Personal number", "A personal number forwards calls to another line. It is easy to get and discard, hides where calls end up, and in some countries costs more to call."))
        elif number_type == T.SHARED_COST:
            findings.append(_finding("info", "shared_cost", "Shared-cost number", "The caller and the holder of the number split the cost of a call. It is not tied to a place."))
        elif number_type == T.PAGER:
            findings.append(_finding("info", "pager", "Pager number", "This range is assigned to pagers, not to phones that can be answered."))
        elif number_type == T.UAN:
            findings.append(_finding("info", "uan", "Company number", "A universal access number: one number for an organisation, routed to its offices. It is not tied to a place."))
        elif number_type == T.VOICEMAIL:
            findings.append(_finding("info", "voicemail", "Voicemail access number", "This range reaches a voicemail service, not a person."))

    base["findings"] = findings
    if not possible:
        e164 = international = ""       # digits that cannot be a number have no standard form
    base.update(parsed=True, normalized=e164 or None, valid=valid, country=country or None, country_code=iso or None,
                location=area or None, carrier=assigned_carrier or None, line_type=type_text if valid else None)
    base["number"] = {
        "e164": e164 or None, "international": international or None, "national": national,
        "extension": _clip(n.extension, 12) or None, "calling_code": n.country_code, "region": iso or None, "country": country or None,
        "possible": possible, "possible_reason": reason or None, "valid": valid, "validity_text": validity_text,
        "line_type": code if valid else "unknown", "line_type_text": type_text if valid else "Unknown", "line_type_note": type_note or None,
        "region_assumed": how == "assumed", "assumed_text": assumed_text or None,
        "time_zones": zones[:3] if len(zones) <= 3 else [], "time_zone_count": len(zones),
        "vanity": pn.is_alpha_number(raw), "fiction": bool(fiction),
    }
    nsn = str(n.national_number)
    nanp_block = n.country_code == 1 and len(nsn) == 10 and iso in ("US", "CA") and number_type in _GEO_TYPES and bool(re.fullmatch(r"[2-9]\d\d[2-9]\d\d\d{4}", nsn))
    base["assignment"] = {
        "area": area or None, "area_note": AREA_NOTE if area else None,
        "carrier": assigned_carrier or None, "carrier_note": CARRIER_NOTE if assigned_carrier else None,
        "prefix": f"{nsn[:3]}-{nsn[3:6]}" if nanp_block else None,
        "rate_centre": None, "region": None, "company": None, "ocn": None, "block_assigned": None, "evidence_url": None,
    }
    if possible:
        base["search_links"] = search_links(e164, international, national, nanp=n.country_code == 1 and len(nsn) == 10)
    return base


# ---- NPA-NXX: who a North American block was assigned to --------------------------------------
_BLOCK_RE = re.compile(r"<prefixdata>(.*?)</prefixdata>", re.S)
_TAG_RE = re.compile(r"<([a-z-]+)>([^<]*)</\1>")


def parse_npa_xml(text: str, npa: str, nxx: str) -> dict | None:
    """The block's row from a Local Calling Guide answer, or None when it lists no such block.
    Raises ValueError when the text is not that service's answer. Read with a pattern, not an
    XML parser: the document declares entities, and nothing in it needs to be expanded."""
    if "<root>" not in text or "<inputdata>" not in text:
        raise ValueError("not a prefix answer")
    rows = []
    for block in _BLOCK_RE.findall(text):
        row = {k: html.unescape(v).strip() for k, v in _TAG_RE.findall(block)}
        if row.get("npa") == npa and row.get("nxx") == nxx:
            rows.append(row)
    if not rows:
        return None
    row = next((r for r in rows if r.get("x") == "A"), rows[0])
    return {"rate_centre": _clip(row.get("rc")), "region": _clip(row.get("region"), 8), "company": _clip(row.get("company-name")), "ocn": _clip(row.get("ocn"), 8)}


async def npa_nxx_lookup(npa: str, nxx: str) -> dict:
    """{state: ok | none | failed | rate_limited, ...}. Only the area code and the exchange are
    sent. `none` means the service answered and lists no such block; a failure is never that."""
    global _npa_pause_until
    if not (re.fullmatch(r"[2-9]\d\d", npa or "") and re.fullmatch(r"[2-9]\d\d", nxx or "")):
        raise ValueError("npa and nxx must be three digits each")
    key = f"{npa}-{nxx}"
    src = {"name": NPA_SOURCE, "asked": key}
    now = time.time()
    hit = _npa_cache.get(key)
    if hit and now - hit[0] < NPA_TTL:
        _npa_cache.move_to_end(key)
        return {**src, **hit[1], "cached": True}
    if now < _npa_pause_until:
        return {**src, "state": "rate_limited", **error_fields(code="rate_limited")}
    try:
        async with httpx.AsyncClient(timeout=NPA_TIMEOUT) as client:
            resp = await client.get(NPA_URL, params={"npa": npa, "nxx": nxx}, headers=HEADERS)
        if resp.status_code != 200:
            code = classify_status(resp.status_code)
            if code == "rate_limited":
                _npa_pause_until = time.time() + NPA_PAUSE
            return {**src, "state": "rate_limited" if code == "rate_limited" else "failed", **error_fields(code=code, detail=f"HTTP {resp.status_code}")}
        text = resp.text
        if len(text) > NPA_MAX_BYTES:
            raise ValueError("answer too large")
        row = parse_npa_xml(text, npa, nxx)
    except Exception as e:
        return {**src, "state": "failed", **error_fields(code=classify(e), detail=type(e).__name__)}
    answer = {"state": "ok", **row} if row else {"state": "none"}
    _npa_cache[key] = (time.time(), answer)
    while len(_npa_cache) > NPA_CACHE_MAX:
        _npa_cache.popitem(last=False)
    return {**src, **answer, "cached": False}


# ---- NumLookup: only with the visitor's own key ------------------------------------------------
async def numlookup(e164: str, key: str) -> dict:
    """{state: ok | failed, ...}. The one place the full number leaves the server, and only
    because the visitor supplied a key for exactly this."""
    src = {"name": NUMLOOKUP_SOURCE}
    try:
        async with httpx.AsyncClient(timeout=NUMLOOKUP_TIMEOUT) as client:
            resp = await client.get(NUMLOOKUP_URL.format(number=quote(e164, safe="+")), params={"apikey": key}, headers=HEADERS)
        if resp.status_code != 200:
            code = "auth" if resp.status_code in (401, 403) else classify_status(resp.status_code)
            return {**src, "state": "failed", **error_fields(code=code, detail=f"HTTP {resp.status_code}",
                                                             message="NumLookup rejected the key. Update or clear it in Settings." if code == "auth" else None)}
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("unexpected answer")
    except Exception as e:
        return {**src, "state": "failed", **error_fields(code=classify(e), detail=type(e).__name__)}
    valid = data.get("valid")
    return {**src, "state": "ok", "valid": valid if isinstance(valid, bool) else None,
            "carrier": _clip(data.get("carrier")) or None, "line_type": _clip(data.get("line_type"), 40) or None}


# ---- the lookup ---------------------------------------------------------------------------
async def lookup(raw: str, region: str = "US", numlookup_key: str | None = None) -> dict:
    out = offline_facts(raw, region)
    num, asg = out.get("number") or {}, out.get("assignment") or {}
    jobs = {}
    if asg.get("prefix"):
        npa, nxx = asg["prefix"].split("-")
        jobs["npa_nxx"] = npa_nxx_lookup(npa, nxx)
    if numlookup_key and num.get("e164") and num.get("possible"):
        jobs["numlookup"] = numlookup(num["e164"], numlookup_key)
    if jobs:
        for name, res in zip(jobs, await asyncio.gather(*jobs.values())):
            out["sources"][name] = res

    block = out["sources"].get("npa_nxx")
    if block and block["state"] in ("ok", "none"):
        npa, nxx = asg["prefix"].split("-")
        asg["evidence_url"] = NPA_PAGE.format(npa=npa, nxx=nxx)
        asg["block_assigned"] = block["state"] == "ok"
        if block["state"] == "ok":
            asg.update(rate_centre=block.get("rate_centre") or None, region=block.get("region") or None,
                       company=block.get("company") or None, ocn=block.get("ocn") or None)
            if asg["company"]:
                asg["carrier_note"] = CARRIER_NOTE
        else:
            out["findings"].append(_finding(
                "info" if num.get("fiction") else "flag", "unassigned_block", f"The {asg['prefix']} block is not assigned",
                f"{NPA_SOURCE} lists no carrier for area code {npa}, exchange {nxx}. A working number should not start with these six digits, though caller ID can be made to show any number."))
    nl = out["sources"].get("numlookup")
    if nl and nl["state"] == "ok" and nl.get("valid") is False and num.get("valid"):
        out["findings"].append(_finding("info", "numlookup_invalid", "NumLookup calls this number invalid", "The numbering plan has a range for it, and NumLookup does not recognise it. The two disagree, so treat validity as unsettled."))
    return out

