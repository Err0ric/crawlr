"""
Native passive harvester: hosts and email addresses for a domain from free,
keyless public sources, queried in parallel. Replaces the theHarvester
subprocess, which was never installed in production (the PyPI package of that
name is a 2019 stub with no CLI).

Sources
  crt.sh        certificate transparency
  CertSpotter   certificate transparency
  HackerTarget  passive DNS host search
  RapidDNS      passive DNS (HTML)
  URLScan       public scan results
  AlienVault    OTX passive DNS
  Anubis        subdomain database
  Wayback       archived URLs (hosts, plus any addresses that appear in them)

Every source is best-effort: a slow, rate-limited or failed source is
reported in `sources` and skipped, never fatal. Response shape is backward
compatible with the old module: {domain, hosts[], emails[], ...}.
"""

import asyncio
import json
import re
import time
from urllib.parse import unquote, urlsplit

import httpx

from core.logging import get_logger
from core.subprocess_guard import log_result

log = get_logger(__name__)

UA = "Mozilla/5.0 (compatible; CrawlR/1.0; +https://crawlr.lol)"
SOURCE_TIMEOUT = 20.0
OVERALL_TIMEOUT = 35.0
MAX_HOSTS = 1000

# Webmail and other shared domains: harvesting these is pointless and noisy.
SHARED_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net",
    "mail.com", "zoho.com", "yandex.com", "yandex.ru", "qq.com", "163.com", "comcast.net", "att.net", "verizon.net",
    "fastmail.com", "tutanota.com", "hey.com",
}


# ---- helpers ---------------------------------------------------------------

def _clean_host(h: str, domain: str) -> str | None:
    h = str(h or "").strip().lower().rstrip(".")
    if h.startswith("*."):
        h = h[2:]
    if "://" in h:
        h = urlsplit(h).hostname or ""
    h = h.split(":")[0]
    if not h or " " in h or "@" in h:
        return None
    if h == domain or h.endswith("." + domain):
        return h
    return None


def _email_re(domain: str) -> re.Pattern:
    return re.compile(r"[a-z0-9][a-z0-9._%+\-]{0,63}@(?:[a-z0-9\-]+\.)*" + re.escape(domain), re.I)


# ---- parsers (pure, unit-tested) -----------------------------------------------

def parse_crtsh(payload: list, domain: str) -> set[str]:
    out = set()
    for row in payload or []:
        for name in str(row.get("name_value", "")).splitlines():
            h = _clean_host(name, domain)
            if h:
                out.add(h)
    return out


def parse_certspotter(payload: list, domain: str) -> set[str]:
    out = set()
    for row in payload or []:
        for name in row.get("dns_names", []) or []:
            h = _clean_host(name, domain)
            if h:
                out.add(h)
    return out


def parse_hackertarget(text: str, domain: str) -> set[str]:
    if not text or "error" in text[:40].lower() or "api count exceeded" in text.lower():
        return set()
    out = set()
    for line in text.splitlines():
        h = _clean_host(line.split(",")[0], domain)
        if h:
            out.add(h)
    return out


def parse_rapiddns(html: str, domain: str) -> set[str]:
    pat = re.compile(r"(?:[a-z0-9\-_]+\.)+" + re.escape(domain), re.I)
    return {h for h in (_clean_host(m, domain) for m in pat.findall(html or "")) if h}


def parse_urlscan(payload: dict, domain: str) -> set[str]:
    out = set()
    for r in (payload or {}).get("results", []) or []:
        for key in ("page", "task"):
            h = _clean_host((r.get(key) or {}).get("domain", ""), domain)
            if h:
                out.add(h)
    return out


def parse_otx(payload: dict, domain: str) -> set[str]:
    return {h for h in (_clean_host(r.get("hostname", ""), domain) for r in (payload or {}).get("passive_dns", []) or []) if h}


def parse_anubis(payload: list, domain: str) -> set[str]:
    return {h for h in (_clean_host(x, domain) for x in (payload or []) if isinstance(x, str)) if h}


def parse_wayback(payload: list, domain: str) -> tuple[set[str], set[str]]:
    hosts, emails = set(), set()
    erx = _email_re(domain)
    for row in (payload or [])[1:]:  # first row is the column header
        url = row[0] if isinstance(row, list) and row else str(row)
        h = _clean_host(urlsplit(url).hostname or "", domain)
        if h:
            hosts.add(h)
        for e in erx.findall(unquote(url)):
            emails.add(e.lower())
    return hosts, emails


# ---- fetchers ----------------------------------------------------------------------

async def _get(client: httpx.AsyncClient, url: str, as_json: bool = True):
    r = await client.get(url, timeout=SOURCE_TIMEOUT)
    if r.status_code == 429:
        raise RuntimeError("rate limited")
    r.raise_for_status()
    if not as_json:
        return r.text
    try:
        return r.json()
    except json.JSONDecodeError:
        raise RuntimeError("non-JSON response")


async def _src_crtsh(c, d):        return parse_crtsh(await _get(c, f"https://crt.sh/?q=%25.{d}&output=json"), d), set()
async def _src_certspotter(c, d):  return parse_certspotter(await _get(c, f"https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names"), d), set()
async def _src_hackertarget(c, d): return parse_hackertarget(await _get(c, f"https://api.hackertarget.com/hostsearch/?q={d}", as_json=False), d), set()
async def _src_rapiddns(c, d):     return parse_rapiddns(await _get(c, f"https://rapiddns.io/subdomain/{d}?full=1", as_json=False), d), set()
async def _src_urlscan(c, d):      return parse_urlscan(await _get(c, f"https://urlscan.io/api/v1/search/?q=domain:{d}&size=500"), d), set()
async def _src_otx(c, d):          return parse_otx(await _get(c, f"https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns"), d), set()
async def _src_anubis(c, d):       return parse_anubis(await _get(c, f"https://jonlu.ca/anubis/subdomains/{d}"), d), set()
async def _src_wayback(c, d):      return parse_wayback(await _get(c, f"https://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=json&fl=original&collapse=urlkey&limit=5000"), d)

SOURCES = {
    "crt.sh": _src_crtsh,
    "CertSpotter": _src_certspotter,
    "HackerTarget": _src_hackertarget,
    "RapidDNS": _src_rapiddns,
    "URLScan": _src_urlscan,
    "AlienVault OTX": _src_otx,
    "Anubis": _src_anubis,
    "Wayback": _src_wayback,
}


# ---- entry point ----------------------------------------------------------------------

async def _run_harvester_impl(domain: str, timeout: float = OVERALL_TIMEOUT) -> dict:
    domain = str(domain or "").strip().lower().rstrip(".")
    if "@" in domain:
        domain = domain.split("@", 1)[1]
    if not domain or "." not in domain:
        return {"domain": domain, "error": "invalid domain", "hosts": [], "emails": []}
    if domain in SHARED_DOMAINS:
        return {"domain": domain, "skipped": True, "message": f"{domain} is a shared mail provider, so there's nothing useful to harvest.", "hosts": [], "emails": [], "sources": {}}

    host_srcs: dict[str, set[str]] = {}
    emails: set[str] = set()
    report: dict[str, dict] = {}

    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True) as client:
        async def one(name, fn):
            t0 = time.monotonic()
            try:
                hosts, mails = await fn(client, domain)
                for h in hosts:
                    host_srcs.setdefault(h, set()).add(name)
                emails.update(mails)
                report[name] = {"hosts": len(hosts), "emails": len(mails), "ms": int((time.monotonic() - t0) * 1000)}
            except Exception as e:  # each source is best-effort
                report[name] = {"error": f"{type(e).__name__}: {e}"[:160], "ms": int((time.monotonic() - t0) * 1000)}

        tasks = [asyncio.create_task(one(n, f)) for n, f in SOURCES.items()]
        done, pending = await asyncio.wait(tasks, timeout=timeout)
        for t in pending:
            t.cancel()
        for n in SOURCES:
            report.setdefault(n, {"error": "timed out"})

    hosts_sorted = sorted(host_srcs, key=lambda h: (-len(host_srcs[h]), h))[:MAX_HOSTS]
    ok = [n for n, r in report.items() if "error" not in r]
    log.info("harvest sources", extra={"domain": domain, "ok": ok, "failed": [n for n in report if n not in ok]})
    return {
        "domain": domain,
        "hosts": hosts_sorted,
        "host_sources": {h: sorted(host_srcs[h]) for h in hosts_sorted},
        "emails": sorted(emails),
        "total_hosts": len(host_srcs),
        "total_emails": len(emails),
        "total": len(host_srcs) + len(emails),
        "sources": report,
    }


async def run_harvester(domain: str, timeout: float = OVERALL_TIMEOUT) -> dict:
    return log_result("harvester", await _run_harvester_impl(domain=domain, timeout=timeout))
