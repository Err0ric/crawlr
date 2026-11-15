"""
What a phone number is, from open numbering data. No key needed.

Three sources, each with its own state, so one failing never blanks the others:

  numbering_plan  Google's libphonenumber (the `phonenumbers` package). Offline: nothing leaves
                  the server. Says whether the number is possible and valid for its country,
                  how it is written, its line type, and where and to whom its number RANGE was
                  assigned. Its tables are large, so it runs in a short-lived child process
                  (modules/phone_worker.py, logic in modules/phone_plan.py) and this process
                  never imports them. Answers are cached here for a day. A worker that fails
                  or times out is this source failing: it is never read as "not valid".
  npa_nxx         Local Calling Guide's public XML query, for United States and Canadian
                  geographic numbers only. It is asked for the area code and exchange (NPA and
                  NXX, the first six digits) and NEVER for the full number: the last four digits
                  do not leave the server. Answers are cached per NPA-NXX for 7 days.
  numlookup       Optional. Only when the visitor sent their own NumLookup key, the number goes
                  to that service, which is what the key is for. It adds the current carrier.

Everything here describes the number and its range. Nothing says who uses the number or where
that person is, and no source that would is asked. The outbound search links are built by the
plan module and opened by the investigator; CrawlR never fetches them.

Nothing in this module logs the number.
"""


import asyncio
import copy
import html
import json
import re
import sys
import time
from collections import OrderedDict
from pathlib import Path
from urllib.parse import quote

import httpx

from core.errors import classify, classify_status, error_fields
from core.subprocess_guard import ToolBusy, tool_slot

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

CARRIER_NOTE = ("The carrier this number range was first assigned to. Numbers are ported between carriers, "
                "so it may not be the current one.")

# The numbering plan is read in a child process (see modules/phone_worker.py).
WORKER_CMD = [sys.executable, "-m", "modules.phone_worker"]
WORKER_CWD = str(Path(__file__).resolve().parent.parent)
WORKER_TIMEOUT = 6             # seconds; a lookup takes a fraction of one
WORKER_MAX = 2                 # workers at once: each holds about 130 MB while it runs
WORKER_MAX_BYTES = 100_000
PLAN_TTL = 24 * 3600
PLAN_CACHE_MAX = 2000
PLAN_FAILED = "The numbering data could not be read on the server. Try again in a moment."

_npa_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_npa_pause_until = 0.0
_plan_cache: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_worker_sem: asyncio.Semaphore | None = None


def clear_cache_for_tests() -> None:
    global _npa_pause_until, _worker_sem
    _npa_cache.clear()
    _plan_cache.clear()
    _npa_pause_until = 0.0
    _worker_sem = None             # a semaphore belongs to the event loop that first used it


class PhoneInputError(ValueError):
    """The text cannot be read as a phone number at all. The router answers 400 with the message."""


class PlanUnavailable(Exception):
    """The numbering plan could not be read: the worker failed, timed out or was not given a slot.
    Carries an error code. It is a failed source, never an answer about the number."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


# ---- the numbering plan, read in a child process ------------------------------------------------
async def _worker(raw: str, region: str) -> dict:
    """One request to one short-lived worker. The number goes in on stdin, never on the command
    line, and the worker's stderr is discarded, so the number cannot reach a process list or a log."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *WORKER_CMD, cwd=WORKER_CWD,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError as e:
        raise PlanUnavailable("not_installed", type(e).__name__) from None
    try:
        out, _ = await asyncio.wait_for(proc.communicate(json.dumps({"phone": raw, "region": region}).encode()), timeout=WORKER_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise PlanUnavailable("timeout", "worker timed out") from None
    if proc.returncode != 0 or len(out) > WORKER_MAX_BYTES:
        raise PlanUnavailable("unknown", f"worker exit {proc.returncode}")
    try:
        answer = json.loads(out)
    except ValueError:
        raise PlanUnavailable("bad_response", "worker answer was not JSON") from None
    if not isinstance(answer, dict) or not (isinstance(answer.get("result"), dict) or isinstance(answer.get("bad_input"), str)):
        raise PlanUnavailable("bad_response", "worker answer had no result")
    return answer


async def plan_facts(raw: str, region: str) -> dict:
    """The offline facts for a number, from the cache or from a worker. Raises PhoneInputError
    for text that is not a phone number and PlanUnavailable when the plan could not be read.
    At most WORKER_MAX workers run at once, inside the limit every external tool shares."""
    global _worker_sem
    key = f"{re.sub(r'[^0-9a-z+#*;=,x]', '', raw.lower())}|{region}"
    hit = _plan_cache.get(key)
    if hit and time.time() - hit[0] < PLAN_TTL:
        _plan_cache.move_to_end(key)
        return {**copy.deepcopy(hit[1]), "input": raw}
    if _worker_sem is None:
        _worker_sem = asyncio.Semaphore(WORKER_MAX)
    try:
        async with _worker_sem:
            async with tool_slot("phone_plan"):
                answer = await _worker(raw, region)
    except ToolBusy:
        raise PlanUnavailable("busy") from None
    if "result" not in answer:
        raise PhoneInputError(answer["bad_input"][:300])
    _plan_cache[key] = (time.time(), answer["result"])
    while len(_plan_cache) > PLAN_CACHE_MAX:
        _plan_cache.popitem(last=False)
    return copy.deepcopy(answer["result"])


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


def _finding(level: str, code: str, title: str, detail: str) -> dict:
    return {"level": level, "code": code, "title": title, "detail": detail}


def _clip(v, n: int = 80) -> str:
    return " ".join(str(v or "").split())[:n]


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
    try:
        out = await plan_facts(raw, region)
    except PlanUnavailable as e:
        # The plan could not be read, so nothing is known: not "valid", not "not valid". The whole
        # lookup is a failed source, and nothing else is asked, because the plan decides what to ask.
        err = error_fields(code=e.code, detail=e.detail, message=PLAN_FAILED if e.code != "busy" else None)
        return {"input": raw, **err, "sources": {"numbering_plan": {"name": "libphonenumber", "state": "failed", **err}}}
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

