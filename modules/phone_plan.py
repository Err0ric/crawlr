"""
What the numbering plan says about a phone number, with no network: Google's libphonenumber
(the `phonenumbers` package). Whether the number is possible and valid for its country, how it
is written, its line type, the area and carrier its number RANGE was assigned to, its time
zones, and the special ranges it may sit in (toll free, premium rate, VoIP, fiction, short
codes, emergency numbers).

The library's area, carrier and time zone tables take about 115 MB once loaded. The web process
never imports this module: modules/phone_lookup.py runs it in a short-lived child process
(modules/phone_worker.py), so that memory is given back when the child exits. This module
imports nothing from the rest of the app, which keeps the child quick to start.

Everything here describes the number and its range, never who uses it. Nothing here logs.
"""

import re
from urllib.parse import quote_plus

import phonenumbers as pn
from phonenumbers import shortnumberinfo

PLAN_NAME = "libphonenumber"
AREA_NOTE = "Where this number range is assigned. It is not where the phone or the person using it is."
CARRIER_NOTE = ("The carrier this number range was first assigned to. Numbers are ported between carriers, "
                "so it may not be the current one.")
OWNER_NOTE = "Who uses this number is not something open numbering data shows."


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
# The Northern Ireland range is left out on purpose: two copies of the list disagree about it
# (028 9018 0XXX and 028 9649 6XXX), and a wrong flag on a real number is worse than none.
UK_DRAMA = {
    "1134960": "Leeds", "1144960": "Sheffield", "1154960": "Nottingham", "1164960": "Leicester",
    "1174960": "Bristol", "1184960": "Reading", "1214960": "Birmingham", "1314960": "Edinburgh",
    "1414960": "Glasgow", "1514960": "Liverpool", "1614960": "Manchester", "2079460": "London",
    "1914980": "Tyneside, Durham and Sunderland", "2920180": "Cardiff",
    "1632960": "no area", "7700900": "mobile", "8081570": "freephone", "9098790": "premium rate",
    "3069990": "UK-wide",
}
# ACMA's geographic ranges for film, television and radio: (0X) 5550 XXXX and (0X) 7010 XXXX in
# each of the four areas, as the first five digits of the national number. ACMA also lists single
# mobile, freephone and local-rate numbers; those are left out, because one wrong digit would
# flag a real person's number.
AU_DRAMA = {f"{area}{block}" for area in "2378" for block in ("5550", "7010")}
# ComReg sets 020 91X XXXX aside for drama. 020 is not an area code in use in Ireland.
IE_DRAMA = "2091"


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
    return name or _EXTRA_NAMES.get(region, region)


# Regions the library can read numbers for and has no English name for.
_EXTRA_NAMES = {"XK": "Kosovo", "TA": "Tristan da Cunha", "AC": "Ascension Island"}

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
    if n.country_code == 61 and len(nsn) == 9 and nsn[:5] in AU_DRAMA:
        return ("The Australian regulator (ACMA) sets this range aside for film, television and radio. "
                "It is reserved for fiction and is not in use, so nobody can be reached on it.")
    if n.country_code == 353 and len(nsn) == 9 and nsn.startswith(IE_DRAMA):
        return ("The Irish regulator (ComReg) sets 020 91X XXXX aside for drama. "
                "It is reserved for fiction and is not in use, so nobody can be reached on it.")
    return ""


# ---- parsing ----------------------------------------------------------------------------
_IDD_00 = re.compile(r"^\(?\s*00\s*\)?[\s\-./]*(?=[1-9])")


def _parse(raw: str, region: str) -> tuple[pn.PhoneNumber, str, str]:
    """(number, how the country was decided, the international prefix that was read).
    how is "given" (a + or a country code the library recognised), "idd" (the international call
    prefix of the chosen country: 00 in most, 011 in North America, 0011 in Australia, 010 in
    Japan; the library knows each one), "idd00" (00 where the chosen country uses another
    prefix, read as international because 00 is what most of the world dials), "no_plus"
    (digits that only make a valid number when read as country code first) or "assumed" (the
    chosen country was used)."""
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
    if src == pn.CountryCodeSource.FROM_NUMBER_WITH_IDD:
        meta = pn.PhoneMetadata.metadata_for_region(region, None)
        m = re.match(meta.international_prefix, re.sub(r"\D", "", raw)) if meta and meta.international_prefix else None
        return n, "idd", m.group(0) if m else ""
    if src != pn.CountryCodeSource.FROM_DEFAULT_COUNTRY:
        return n, "given", ""
    digits = "" if n.extension or pn.is_alpha_number(raw) else re.sub(r"\D", "", raw)
    # 00 is the international prefix in most of the world, and people write it with a space or a
    # dash after it. Where the chosen country dials something else (011 in North America) the
    # library reads 00 as part of a national number, so it is tried here as international. It is
    # only taken when what follows is a possible number: "0011 44 ..." is Australia's prefix, not
    # 00 followed by country code 1.
    m = _IDD_00.match(raw.strip())
    if m:
        try:
            alt = pn.parse("+" + raw.strip()[m.end():], None, keep_raw_input=True)
            if pn.is_possible_number_with_reason(alt) == pn.ValidationResult.IS_POSSIBLE:
                return alt, "idd00", "00"
        except pn.NumberParseException:
            pass
    # Digits that are not a number in the hint region but are one when the country code comes
    # first ("447911123456"): people often leave the + out.
    if not pn.is_valid_number(n) and 10 <= len(digits) <= 15 and not raw.strip().startswith("0"):
        try:
            alt = pn.parse("+" + raw.strip(), None, keep_raw_input=True)
            if pn.is_valid_number(alt):
                return alt, "no_plus", ""
        except pn.NumberParseException:
            pass
    return n, "assumed", ""


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
    # The library's short-number data has to say what the code is. Its catch-all pattern for
    # text-message codes (any five or six digits in the United States) is not that: "90210"
    # fits it and is nobody's service.
    listed = shortnumberinfo.is_valid_short_number_for_region(n, region) and (
        shortnumberinfo.is_carrier_specific_for_region(n, region)
        or shortnumberinfo.expected_cost_for_region(n, region) != shortnumberinfo.ShortNumberCost.UNKNOWN_COST
        or not shortnumberinfo.is_sms_service_for_region(n, region))
    if not emergency and not listed:
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
            {"site": "WhoCallsMe", "url": f"https://whocallsme.com/Phone-Number.aspx/{ten}", "group": "spam reports"},
        ]
    for row in out:
        row["kind"] = "search"
        row["label"] = "community reports of unwanted calls" if row["group"] == "spam reports" else "the number in its common written forms"
    return out


def _offset_name(minutes: int) -> str:
    if minutes == 0:
        return "UTC"
    h, m = divmod(abs(minutes), 60)
    return f"UTC{'+' if minutes > 0 else '-'}{h}{f':{m:02d}' if m else ''}"


def utc_offsets(zones: list[str], now=None) -> list[str]:
    """The UTC offsets a number range covers today, smallest first: ["UTC+2"], or several for a
    range that spans them. The library names each range by a representative time zone, and that
    zone's city is often in another country (Estonia is filed under Europe/Bucharest), so a zone
    name is never shown: only the offset is true of the range. Empty when there are more than
    three offsets (the range is not tied to a place) or no time zone database is installed."""
    from datetime import datetime, timezone as _utc
    from zoneinfo import ZoneInfo
    now = now or datetime.now(_utc.utc)
    minutes = set()
    for z in zones:
        try:
            minutes.add(int(ZoneInfo(z).utcoffset(now).total_seconds() // 60))
        except Exception:
            return []
    return [_offset_name(m) for m in sorted(minutes)] if 0 < len(minutes) <= 3 else []


# Exchanges in North America that no carrier holds as an ordinary block. The block source lists
# nothing for them, which must not be read as "this number cannot exist".
def special_exchange(nsn: str) -> str:
    nxx = nsn[3:6]
    return nxx if nxx in ("555", "950", "976") or nxx[1:] == "11" else ""


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
        "sources": {"numbering_plan": {"name": PLAN_NAME, "state": "ok", "version": pn.__version__, "offline": True}},
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
        n, how, idd = _parse(raw, region)
    except pn.NumberParseException:
        base.update(valid=False)
        base["number"] = {"possible": False, "valid": False, "possible_reason": "the country code is not in use",
                          "validity_text": "Not valid: the country code is not in use."}
        base["findings"] = [_finding("flag", "invalid", "Not a valid number", "The digits after the + do not start with a country code that is in use.")]
        return base

    # Mexican mobiles were written with a 1 after +52 until 2019, and still are. The library
    # documents the change and no longer accepts the 1, so it is taken off when that is the only
    # thing wrong with the number.
    legacy = ""
    old = str(n.national_number)
    if n.country_code == 52 and len(old) == 11 and old.startswith("1") and not pn.is_valid_number(n):
        alt = pn.PhoneNumber(country_code=52, national_number=int(old[1:]), extension=n.extension)
        if pn.is_valid_number(alt):
            n, legacy = alt, "1"

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
    elif how == "assumed" and len(re.sub(r"\D", "", raw)) <= 6:
        validity_text = f"Not valid: not a phone number for {where}. It is too short, and it is not a service number the numbering data lists."
    else:
        validity_text = f"Not valid: {reason}."

    pn_geocoder, pn_carrier, pn_timezone, _ = _plan_data()
    zones = [z for z in pn_timezone.time_zones_for_number(n) if z and z != "Etc/Unknown"] if valid else []
    area = _clip(pn_geocoder.description_for_number(n, "en")) if valid and number_type not in _NON_GEO else ""
    if area == country:
        area = ""                       # the library fell back to the country: no finer area is known
    assigned_carrier = _clip(pn_carrier.name_for_number(n, "en")) if valid else ""
    offsets = utc_offsets(zones)

    assumed_text = ""
    if how == "assumed":
        name = _country_name(region)
        assumed_text = f"No country code given, read as a {name} number." if name.startswith("United ") else f"No country code given, read as a number from {_the(name)}."
    elif how == "no_plus":
        assumed_text = f"No + given. The digits only make a valid number when read with country code +{n.country_code} first, so they were read that way."

    findings = []
    if how == "assumed":
        findings.append(_finding("info", "assumed_country", assumed_text.rstrip("."), "Add the country code with a + (for example +44) if the number belongs somewhere else."))
    elif how == "idd":
        findings.append(_finding("info", "idd_prefix", f"{idd or 'The prefix'} read as the international call prefix of {_the(_country_name(region))}",
                                 f"The digits after it were read as country code +{n.country_code} and the number. Writing the number with a + means the same in every country."))
    elif how == "idd00":
        findings.append(_finding("info", "idd_prefix", "00 read as the international call prefix",
                                 f"00 is what most countries dial before a country code, though not {_the(_country_name(region))}. The digits after it were read as country code +{n.country_code} and the number. Write the number with a + to be sure."))
    elif how == "no_plus":
        findings.append(_finding("info", "assumed_plus", f"No + given, read with country code +{n.country_code}", "The digits only make a valid number when the country code comes first, so they were read that way. Write the + to be sure."))
    if legacy:
        findings.append(_finding("info", "legacy_prefix", "Read without the old mobile 1 after +52",
                                 f"Mexican mobile numbers were written with a 1 after the country code until 2019, and often still are. The 1 is no longer part of the number, so it was read as {international}."))
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
        "utc_offsets": offsets, "utc_offset_text": (offsets[0] if len(offsets) == 1 else f"{offsets[0]} to {offsets[-1]}") if offsets else None,
        "vanity": pn.is_alpha_number(raw), "fiction": bool(fiction),
    }
    nsn = str(n.national_number)
    nanp_geo = n.country_code == 1 and len(nsn) == 10 and iso in ("US", "CA") and number_type in _GEO_TYPES and bool(re.fullmatch(r"[2-9]\d\d[2-9]\d\d\d{4}", nsn))
    special = special_exchange(nsn) if nanp_geo else ""
    # The block source is asked about ordinary geographic blocks only: not a special exchange,
    # and (by the line type) not a toll-free, premium or other non-geographic area code.
    nanp_block = nanp_geo and not special
    if special == "555" and nsn[6:] == "1212":
        findings.append(_finding("info", "directory_assistance", "Directory assistance",
                                 f"{nsn[:3]}-555-1212 is the directory assistance number for area code {nsn[:3]}. It is a service, not a subscriber's line."))
    elif special and not fiction:
        findings.append(_finding("info", "special_exchange", "Special-use exchange",
                                 f"Exchange {special} is set aside for special services in North America. No carrier holds it as an ordinary block, so no block assignment is looked up."))
    base["assignment"] = {
        "area": area or None, "area_note": AREA_NOTE if area else None,
        "carrier": assigned_carrier or None, "carrier_note": CARRIER_NOTE if assigned_carrier else None,
        "prefix": f"{nsn[:3]}-{nsn[3:6]}" if nanp_block else None,
        "rate_centre": None, "region": None, "company": None, "ocn": None, "block_assigned": None, "evidence_url": None,
    }
    if possible:
        base["search_links"] = search_links(e164, international, national, nanp=n.country_code == 1 and len(nsn) == 10)
    return base


def _fold(name: str) -> str:
    """A name without its accents, for sorting: Åland sorts with the A names."""
    import unicodedata
    return "".join(ch for ch in unicodedata.normalize("NFKD", name) if not unicodedata.combining(ch)).lower()


def regions() -> list[list[str]]:
    """[ISO code, country name] for every region the library can read a number in, by name.
    static/v2/js/phone-regions.js is a generated copy of this (a test fails if they drift)."""
    rows = [[r, _country_name(r)] for r in pn.SUPPORTED_REGIONS]
    return sorted((r for r in rows if r[1] and r[1] != r[0]), key=lambda r: _fold(r[1]))
