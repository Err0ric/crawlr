"""
File hash lookup against four free sources: MalwareBazaar, CIRCL hashlookup, AlienVault OTX
and ThreatFox.

What each source can and cannot say:

  MalwareBazaar  a malware sample database. A hit is a confirmed sample, with a family
                 name ("signature"), file type, size and first/last seen dates.
  ThreatFox      indicators tied to a named malware family, with first/last seen dates.
  CIRCL          a known-file database (NSRL and others). A hit only means the file is
                 known; `KnownMalicious` names the malware feed that lists it, if any.
  OTX            community "pulses". Anyone can publish one and attach any free text as a
                 tag or a "malware family", so those are community tags, not a verdict.
                 Its static analysis page does carry structured facts (file type, size and
                 what ClamAV and Microsoft Defender call the file).

So a family name in the headline comes only from MalwareBazaar, ThreatFox, or an OTX family
that independent pulses agree on. Everything else is returned as `community_tags`.

abuse.ch (MalwareBazaar and ThreatFox) answers HTTP 401 without an Auth-Key since 2025.
The key is free. Set ABUSECH_AUTH_KEY on the server to use it; without it both sources are
reported as failed, never as "not found".
"""

import asyncio
import os
import re
import time
from collections import OrderedDict

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.errors import classify_status, error_fields

router = APIRouter()

TIMEOUT = 15
CACHE_TTL = 3600
CACHE_MAX = 500
_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()

SOURCE_NAMES = {"malware_bazaar": "MalwareBazaar", "circl": "CIRCL", "alienvault": "AlienVault OTX", "threatfox": "ThreatFox"}

# The EICAR test file: 68 bytes of text that every antivirus product detects on purpose.
# https://www.eicar.org/download-anti-malware-testfile/
EICAR = {
    "name": "EICAR antivirus test file",
    "note": "A harmless 68-byte text string that antivirus products flag on purpose, so people can check "
            "a scanner is working. Every scanner detects it and many threat feeds list it. It is not malware.",
}
KNOWN_TEST_FILES = {
    "44d88612fea8a8f36de82e1278abb02f": EICAR,
    "3395856ce81f2b7382dee72602f798b642f14140": EICAR,
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": EICAR,
}

# OTX "malware family" entries that are plainly not families. The consensus rule below does
# most of the work; this only stops the commonest filler from ever reaching a headline.
NOT_A_FAMILY = {"", "unknown", "malware", "trojan", "virus", "mitre attack", "et", "maltiverse", "other"}


class HashRequest(BaseModel):
    hash: str = Field(max_length=128)


def clear_cache_for_tests() -> None:
    _cache.clear()


def detect_hash_type(h: str) -> str | None:
    h = h.strip().lower()
    if not re.match(r'^[a-f0-9]+$', h):
        return None
    length = len(h)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA1"
    elif length == 64:
        return "SHA256"
    return None


def _failed(status: int, source: str) -> dict:
    """A source that answered with an error status. `found` is None: not a negative result."""
    if status == 401 and source in ("malware_bazaar", "threatfox") and not os.getenv("ABUSECH_AUTH_KEY"):
        return {"found": None, **error_fields(code="auth", message=f"{SOURCE_NAMES[source]} now needs a free abuse.ch key. It was not checked.", detail="HTTP 401 without an Auth-Key")}
    return {"found": None, **error_fields(code=classify_status(status), detail=f"{SOURCE_NAMES[source]} returned HTTP {status}")}


def _text(value, limit: int = 200) -> str:
    return str(value).strip()[:limit] if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ""


def _int(value) -> int | None:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def _day(value) -> str:
    """The date part of a source timestamp ("2021-03-04 10:11:12 UTC", ISO 8601), or ""."""
    m = re.match(r"\d{4}-\d{2}-\d{2}", str(value or ""))
    return m.group(0) if m else ""


def _join(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def _family_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _add(items: list[str], value: str) -> None:
    value = value.strip()
    if value and _family_key(value) not in {_family_key(x) for x in items}:
        items.append(value)


# ---- one parser per source: (HTTP status, decoded body) -> result -------------------------

def parse_malwarebazaar(status: int, body) -> dict:
    if status != 200:
        return _failed(status, "malware_bazaar")
    body = body if isinstance(body, dict) else {}
    query_status = body.get("query_status")
    if query_status == "ok" and body.get("data"):
        entry = body["data"][0]
        return {
            "found": True,
            "malicious": True,
            "file_name": entry.get("file_name"),
            "file_type": entry.get("file_type"),
            "file_type_mime": entry.get("file_type_mime"),
            "file_size": entry.get("file_size"),
            "signature": entry.get("signature"),
            "tags": entry.get("tags"),
            "first_seen": entry.get("first_seen"),
            "last_seen": entry.get("last_seen"),
            "reporter": entry.get("reporter"),
        }
    if query_status in ("hash_not_found", "no_results"):
        return {"found": False}
    return {"found": None, **error_fields(code="bad_response", detail=f"MalwareBazaar query_status: {_text(query_status, 80)}")}


def parse_circl(status: int, body) -> dict:
    if status == 404:
        return {"found": False}
    if status != 200:
        return _failed(status, "circl")
    body = body if isinstance(body, dict) else {}
    known = body.get("KnownMalicious")
    return {
        "found": True,
        "file_name": body.get("FileName"),
        "file_size": body.get("FileSize"),
        "known_malicious": bool(known),
        # CIRCL fills KnownMalicious with the name of the malware feed that lists the file.
        "known_malicious_source": _text(known, 80) if isinstance(known, str) else "",
        "mimetype": _text(body.get("mimetype"), 80),
        "db": _text(body.get("db"), 40),
    }


def otx_families(pulses: list[dict]) -> tuple[list[str], list[str]]:
    """Split the family names on OTX pulses into (agreed, unconfirmed).

    A name is agreed when at least two independent pulses by different authors carry it.
    A clone of a pulse is not independent of the original, so clones are folded into the
    pulse they were copied from before counting."""
    seen: dict[str, dict] = {}
    for p in pulses:
        root = str(p.get("cloned_from") or p.get("id") or "")
        author = str((p.get("author") or {}).get("username") or "")
        for mf in p.get("malware_families") or []:
            name = _text((mf or {}).get("display_name") or (mf or {}).get("id"), 80) if isinstance(mf, dict) else _text(mf, 80)
            if not name:
                continue
            row = seen.setdefault(_family_key(name), {"name": name, "roots": set(), "authors": set()})
            row["roots"].add(root)
            row["authors"].add(author)
    agreed, unconfirmed = [], []
    for row in seen.values():
        ok = len(row["roots"]) >= 2 and len(row["authors"]) >= 2 and row["name"].lower() not in NOT_A_FAMILY
        (agreed if ok else unconfirmed).append(row["name"])
    return agreed, unconfirmed


def parse_otx(status: int, body, analysis_status: int = 0, analysis_body=None) -> dict:
    if status == 404:
        return {"found": False, "pulse_count": 0, "malware_families": []}
    if status != 200:
        return _failed(status, "alienvault")
    body = body if isinstance(body, dict) else {}
    info = body.get("pulse_info") or {}
    pulses = [p for p in info.get("pulses") or [] if isinstance(p, dict)]
    count = _int(info.get("count")) or 0
    agreed, unconfirmed = otx_families(pulses)

    tag_counts: dict[str, int] = {}
    for p in pulses:
        for tag in {_text(t, 40).lower() for t in p.get("tags") or []}:
            if tag:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    tags = [t for t, n in sorted(tag_counts.items(), key=lambda kv: (-kv[1], kv[0])) if n >= 2]

    created = sorted(d for d in (_day(p.get("created")) for p in pulses) if d)
    modified = sorted(d for d in (_day(p.get("modified")) for p in pulses) if d)
    out = {
        "found": count > 0,
        "pulse_count": count,
        "malware_families": agreed[:5],
        "community_families": unconfirmed[:20],
        "pulse_tags": tags[:20],
        "pulse_names": [_text(p.get("name"), 120) for p in pulses[:5] if p.get("name")],
        "first_pulse": created[0] if created else "",
        "last_pulse": modified[-1] if modified else "",
        # OTX keeps its own list of hashes that are known and harmless.
        "whitelisted": any(isinstance(v, dict) and v.get("source") == "whitelist" for v in body.get("validation") or []),
        "file_type": "", "file_size": None, "av_detections": {},
    }
    if analysis_status == 200 and isinstance(analysis_body, dict):
        analysis = analysis_body.get("analysis") or {}
        facts = ((analysis.get("info") or {}).get("results") or {}) if isinstance(analysis, dict) else {}
        out["file_type"] = _text(facts.get("file_type"), 120)
        out["file_size"] = _int(facts.get("filesize"))
        for engine, label in (("clamav", "ClamAV"), ("msdefender", "Microsoft Defender"), ("avast", "Avast")):
            hit = (((analysis.get("plugins") or {}).get(engine) or {}).get("results") or {}).get("detection")
            if isinstance(hit, str) and hit.strip():
                out["av_detections"][label] = hit.strip()[:120]
    return out


def parse_threatfox(status: int, body) -> dict:
    if status != 200:
        return _failed(status, "threatfox")
    body = body if isinstance(body, dict) else {}
    query_status = body.get("query_status")
    if query_status == "ok" and isinstance(body.get("data"), list) and body["data"]:
        entries = [e for e in body["data"] if isinstance(e, dict)]
        malware_names, ioc_types = [], []
        for e in entries[:5]:
            mname = e.get("malware_printable")
            if mname and mname not in malware_names:
                malware_names.append(mname)
            itype = e.get("ioc_type")
            if itype and itype not in ioc_types:
                ioc_types.append(itype)
        first = sorted(d for d in (_day(e.get("first_seen")) for e in entries) if d)
        last = sorted(d for d in (_day(e.get("last_seen")) for e in entries) if d)
        return {
            "found": True,
            "malware_names": malware_names,
            "ioc_types": ioc_types,
            "count": len(entries),
            "first_seen": first[0] if first else "",
            "last_seen": last[-1] if last else "",
        }
    if query_status in ("no_result", "no_results"):
        return {"found": False}
    return {"found": None, **error_fields(code="bad_response", detail=f"ThreatFox query_status: {_text(query_status, 80)}")}


# ---- assembling the answer ---------------------------------------------------------------

def assemble(h: str, hash_type: str, malware_bazaar: dict, circl: dict, alienvault: dict, threatfox: dict) -> dict:
    """Pure function: the four source results in, the endpoint's response out."""
    known_test_file = KNOWN_TEST_FILES.get(h)

    # Families, from structured sources only. Each name remembers who said it.
    named: list[tuple[str, str]] = []
    if malware_bazaar.get("found") and _text(malware_bazaar.get("signature"), 80):
        named.append((_text(malware_bazaar["signature"], 80), "MalwareBazaar"))
    if threatfox.get("found"):
        named += [(_text(n, 80), "ThreatFox") for n in threatfox.get("malware_names", []) if _text(n, 80)]
    if alienvault.get("found"):
        named += [(n, "AlienVault OTX") for n in alienvault.get("malware_families", [])]

    families: list[str] = []
    sources_for: dict[str, list[str]] = {}
    for name, source in named:
        _add(families, name)
        who = sources_for.setdefault(_family_key(name), [])
        if source not in who:
            who.append(source)
    # The headline family is the one most sources agree on; ties go to the earlier source.
    family = max(families, key=lambda n: len(sources_for[_family_key(n)]), default="")
    family_sources = sources_for.get(_family_key(family), []) if family else []

    community_tags: list[str] = []
    for value in alienvault.get("community_families", []) + [t for t in (malware_bazaar.get("tags") or []) if isinstance(t, str)] + alienvault.get("pulse_tags", []):
        _add(community_tags, _text(value, 60))

    if known_test_file:
        # Whatever the feeds call it, a test file has no malware family.
        for name in families:
            _add(community_tags, name)
        families, family, family_sources = [], "", []

    reasons = []
    if malware_bazaar.get("found"):
        reasons.append("MalwareBazaar holds this sample")
    if circl.get("known_malicious"):
        reasons.append("CIRCL lists it as known malicious" + (f" ({circl['known_malicious_source']})" if circl.get("known_malicious_source") else ""))
    if threatfox.get("found"):
        reasons.append("ThreatFox lists it as an indicator")
    if alienvault.get("av_detections"):
        reasons.append("detected by " + " and ".join(alienvault["av_detections"]) + " in OTX's analysis")
    # Pulses are community reports. Three or more are treated as a signal, unless OTX itself
    # lists the hash as known and harmless.
    if alienvault.get("found") and alienvault.get("pulse_count", 0) >= 3 and not alienvault.get("whitelisted"):
        reasons.append(f"{alienvault['pulse_count']} OTX community pulses mention it")

    # Coverage: a verdict is only as good as the sources that answered. A source that failed
    # (or was never asked, like abuse.ch without a key) is named in the basis, so "nothing
    # found" can never read as "all four sources looked and found nothing".
    results = {"malware_bazaar": malware_bazaar, "circl": circl, "alienvault": alienvault, "threatfox": threatfox}
    failed_sources = [SOURCE_NAMES[k] for k, v in results.items() if v.get("error")]
    answered = len(results) - len(failed_sources)
    not_asked = f"{_join(failed_sources)} could not be asked" if failed_sources else ""
    answered_text = f"the {answered} source{'' if answered == 1 else 's'} that answered" if failed_sources else f"any of the {answered} sources"

    if known_test_file:
        verdict = "TEST_FILE"
        reasons = [f"Recognised by its hash as the {known_test_file['name']}"]
    elif reasons:
        verdict = "MALICIOUS"
        if not_asked:
            reasons.append(not_asked)
    elif circl.get("found") is True and not circl.get("known_malicious"):
        # CLEAN needs a positive signal: CIRCL's known-file database holds the file. The
        # absence of a malware listing alone is never enough.
        verdict = "CLEAN"
        reasons = ["CIRCL lists this as a known file", f"not listed as malicious by {answered_text}" + (f"; {not_asked}" if not_asked else "")]
    elif not answered:
        verdict = "UNKNOWN"
        reasons = [f"no source answered; {not_asked}"]
    else:
        verdict = "UNKNOWN"
        reasons = [f"not seen by {answered_text}" + (f"; {not_asked}" if not_asked else "")]

    first = lambda *values: next((v for v in values if v), "")
    file_size = next((n for n in (_int(malware_bazaar.get("file_size")), _int(circl.get("file_size")), alienvault.get("file_size")) if n is not None), None)
    return {
        "hash": h,
        "hash_type": hash_type,
        **results,
        "virustotal_url": f"https://www.virustotal.com/gui/file/{h}",
        "malware_families": families,
        "verdict": verdict,
        "verdict_basis": reasons,
        "known_test_file": dict(known_test_file) if known_test_file else None,
        "family": family,
        "family_sources": family_sources,
        # No keyless source publishes a detection ratio, so this stays null.
        "detection": None,
        "file_type": first(_text(malware_bazaar.get("file_type"), 80), alienvault.get("file_type"), circl.get("mimetype")),
        "file_name": first(_text(malware_bazaar.get("file_name")), _text(circl.get("file_name"))),
        "file_size": file_size,
        "first_seen": first(_day(malware_bazaar.get("first_seen")), threatfox.get("first_seen"), alienvault.get("first_pulse")),
        "last_seen": first(_day(malware_bazaar.get("last_seen")), threatfox.get("last_seen"), alienvault.get("last_pulse")),
        "community_tags": community_tags[:20],
        "failed_sources": failed_sources,
        "sources_answered": answered,
    }


# ---- network -----------------------------------------------------------------------------

async def _fetch(client: httpx.AsyncClient, source: str, h: str, hash_type: str) -> tuple[int, object]:
    """One request to one source. Returns (HTTP status, decoded JSON or None)."""
    abusech = {"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]} if os.getenv("ABUSECH_AUTH_KEY") else {}
    if source == "malware_bazaar":
        resp = await client.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": h}, headers=abusech)
    elif source == "circl":
        resp = await client.get(f"https://hashlookup.circl.lu/lookup/{hash_type.lower()}/{h}", headers={"Accept": "application/json"})
    elif source == "alienvault":
        resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general", headers={"Accept": "application/json"})
    elif source == "alienvault_analysis":
        resp = await client.get(f"https://otx.alienvault.com/api/v1/indicators/file/{h}/analysis", headers={"Accept": "application/json"})
    elif source == "threatfox":
        resp = await client.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_hash", "hash": h}, headers=abusech)
    else:
        raise ValueError(source)
    try:
        body = resp.json()
    except ValueError:
        if resp.status_code == 200:
            raise
        body = None
    return resp.status_code, body


async def lookup(h: str, hash_type: str) -> dict:
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        async def one(source: str):
            try:
                return await _fetch(client, source, h, hash_type)
            except Exception as e:
                return e

        mb, ci, ox, oxa, tf = await asyncio.gather(*(one(s) for s in ("malware_bazaar", "circl", "alienvault", "alienvault_analysis", "threatfox")))

    failed = lambda exc: {"found": None, **error_fields(exc)}
    # The analysis page is an extra: if it fails the pulse data is still used.
    analysis = oxa if not isinstance(oxa, Exception) else (0, None)
    return assemble(
        h, hash_type,
        failed(mb) if isinstance(mb, Exception) else parse_malwarebazaar(*mb),
        failed(ci) if isinstance(ci, Exception) else parse_circl(*ci),
        failed(ox) if isinstance(ox, Exception) else parse_otx(*ox, *analysis),
        failed(tf) if isinstance(tf, Exception) else parse_threatfox(*tf),
    )


@router.post("/hash")
async def hash_lookup(req: HashRequest):
    h = req.hash.strip().lower()
    hash_type = detect_hash_type(h)
    if not hash_type:
        raise HTTPException(status_code=400, detail="Invalid hash. Must be MD5 (32), SHA1 (40), or SHA256 (64) hex characters.")

    hit = _cache.get(h)
    if hit and time.time() - hit[0] < CACHE_TTL:
        _cache.move_to_end(h)
        return {**hit[1], "cached": True}

    result = await lookup(h, hash_type)
    # A missing abuse.ch key is a standing condition, not a blip, so that answer may be cached.
    # Any other failure is not cached: the next request should try the source again.
    blips = [k for k in SOURCE_NAMES if result[k].get("error") and result[k].get("error_code") != "auth"]
    if not blips:
        _cache[h] = (time.time(), result)
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)
    return {**result, "cached": False}
