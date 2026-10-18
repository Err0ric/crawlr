from fastapi import APIRouter, HTTPException, Header, Request
from core.house_key import resolve_ai_key
from middleware.observability import client_ip
from pydantic import BaseModel
from typing import Optional
from modules.ai_provider import call_ai
import json
import time

router = APIRouter()


# ---- investigation report prompt ------------------------------------------------
# Tagged sections instead of markdown-inside-JSON: long reports in a JSON string break
# on unescaped quotes/newlines, especially with smaller models.
INVESTIGATION_PROMPT = """You are a senior OSINT investigator writing a case report from automated collection results.

Write for an investigator who will act on this report. Be specific and evidence-driven:
- Use only the collected data below. Never invent accounts, names, locations or breaches.
- Cite the source for each claim in parentheses, e.g. (Sherlock), (GitHub), (HIBP).
- When evidence is thin or conflicting, say so and lower the confidence. A short honest report beats a padded one.
- Treat sites flagged as false positives or unverified as weak signals, not confirmations.

Respond in exactly this format, with nothing before or after:

<summary>
- 4 bullets, each starting with a label and a dash (e.g. "Identity –", "Footprint –", "Exposure –", "Best lead –"), max 18 words, naming specific platforms, handles, breaches or counts
</summary>
<profile>
name: likely real name, only if the data supports it, else leave blank
location: likely location, only if the data supports it, else leave blank
interests: up to 5 short comma-separated tags (e.g. developer, gaming, bug bounty)
exposure: Low, Medium or High
exposure_reason: one sentence, 15 words or fewer
</profile>
<report>
## Case summary
2-4 sentences: who or what this target most likely is, how confident you are, and the single most useful thing found.

## Identity assessment
| Attribute | Assessment | Confidence | Evidence |
|---|---|---|---|
Only rows the data actually supports, from: likely real name, location, occupation or interests, other handles or emails, age range. Use High / Medium / Low. Leave unsupported attributes out of the table and list them under Gaps instead of writing "Unknown".

## Platform footprint
| Platform | Profile URL | Confidence | Why it matters |
|---|---|---|---|
Use the profile URL exactly as it appears in the collected data; if none is given, write the handle instead. Never construct or guess a URL. At most 8 rows: the accounts most useful to an investigator, strongest first. "Why it matters" is 12 words or fewer and does not restate the source. Below the table, one line noting how many other accounts were found and any reuse of the same handle, avatar, bio or links.

## Exposure and risk
At most 3 sentences: breaches, leaked data, exposed personal details, and an OPSEC rating (Low / Medium / High exposure) with the reason.

## Investigative leads
At most 6, ranked, most valuable first. Each lead is one line starting with → and must be directly actionable: a pivot to run in CrawlR (another username, email or domain), an exact search query in backticks, or a specific URL and what to look for there. Don't list "open profile X" for every account.

## Gaps and next pivots
Bullets: each unanswered question (including attributes left out of the identity table) and the source or technique that would answer it.
</report>"""

ACTIVE_TECHNIQUES_SECTION = """In the report, add a final section "## Active techniques" (the investigator enabled them) listing account-recovery or password-reset enumeration checks worth running on the confirmed platforms, each marked with ⚠ and a one-line note on what it reveals and the risk of notifying the target."""


def parse_tagged_report(text: str) -> tuple[list[str], str]:
    """Extract (bullets, markdown report) from the tagged format, falling back to the
    legacy JSON shape and finally to raw text, so a model that ignores the format still renders."""
    import re as _re
    t = (text or "").strip()
    sm = _re.search(r"<summary>(.*?)</summary>", t, _re.S | _re.I)
    rp = _re.search(r"<report>(.*?)(?:</report>|$)", t, _re.S | _re.I)
    if sm or rp:
        bullets = [b.strip().lstrip("-•*→ ").strip() for b in (sm.group(1) if sm else "").splitlines() if b.strip().lstrip("-•*→ ").strip()]
        report = (rp.group(1) if rp else _re.sub(r"<(summary|profile)>.*?</\1>", "", t, flags=_re.S | _re.I)).strip()
        return bullets[:6], report
    cleaned = t
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
    if cleaned.endswith("```"):
        cleaned = cleaned.rsplit("```", 1)[0]
    try:
        parsed = json.loads(cleaned.strip())
        return list(parsed.get("short_summary", []))[:6], str(parsed.get("full_report", cleaned))
    except (json.JSONDecodeError, AttributeError):
        lines = [l.strip().lstrip("-•*→ ") for l in cleaned.splitlines() if l.strip() and not l.strip().startswith(("#", "|", "{", "}"))]
        return [l for l in lines if len(l) > 3][:4], cleaned


PROFILE_KEYS = {"name", "location", "interests", "exposure", "exposure_reason"}
_BLANK = {"", "-", "n/a", "none", "unknown", "blank", "not found", "leave blank"}


def parse_profile(text: str) -> dict:
    """Read the <profile> block (simple key: value lines) used for the report's dossier card.
    Missing or malformed blocks return {} and the frontend falls back to collected facts."""
    import re as _re
    m = _re.search(r"<profile>(.*?)</profile>", text or "", _re.S | _re.I)
    if not m:
        return {}
    out: dict = {}
    for line in m.group(1).splitlines():
        k, sep, v = line.partition(":")
        k = k.strip().lower().lstrip("-•* ")
        v = v.strip().strip('"').strip()
        if not sep or k not in PROFILE_KEYS or v.lower() in _BLANK or v.lower().startswith("likely real name"):
            continue
        if k == "interests":
            tags = [t.strip() for t in v.split(",") if t.strip() and t.strip().lower() not in _BLANK]
            if tags:
                out[k] = [t[:32] for t in tags[:5]]
        elif k == "exposure":
            lvl = v.split()[0].strip(".,").capitalize()
            if lvl in ("Low", "Medium", "High"):
                out[k] = lvl
        else:
            out[k] = v[:160]
    return out


class AnalyzeRequest(BaseModel):
    target: str
    sherlock: Optional[dict] = None
    holehe: Optional[dict] = None
    harvester: Optional[dict] = None
    hibp: Optional[dict] = None
    gravatar: Optional[dict] = None
    github: Optional[dict] = None
    enricher: Optional[dict] = None
    platform_check: Optional[dict] = None
    hunter: Optional[dict] = None
    shodan: Optional[dict] = None
    profile_scrape: Optional[dict] = None
    name_search: Optional[dict] = None
    active_techniques: bool = False


@router.get("/ping")
def ping():
    return {"status": "analyze router live"}


@router.post("/summarize")
async def summarize(req: AnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    key = resolve_ai_key(x_api_key, x_ai_provider, client_ip(request), "analysis")

    prompt_parts = [f"Target: {req.target}\n"]

    if req.sherlock and req.sherlock.get("results"):
        results = req.sherlock["results"]
        confirmed = [f'{r["site"]} ({r["url"]})' if r.get("url") else r["site"] for r in results if r.get("confidence") != "false_positive"]
        unverified = [r["site"] for r in results if r.get("confidence") == "false_positive"]
        high_conf = [r["site"] for r in results if r.get("confidence") == "high_confidence"]
        if confirmed:
            prompt_parts.append(
                f"Sherlock confirmed {len(confirmed)} profiles: {', '.join(confirmed[:30])}"
            )
        if high_conf:
            prompt_parts.append(
                f"HIGH-CONFIDENCE platforms (weight these heavily): {', '.join(high_conf)}"
            )
        if unverified:
            prompt_parts.append(
                f"Sherlock UNVERIFIED (known false positives, ignore or deprioritize): {', '.join(unverified)}"
            )
        prompt_parts.append(
            "NOTE: Sherlock results may include false positives from sites that return 200 for any username. "
            "Focus analysis on high-confidence platforms like GitHub, Reddit, Steam, TikTok, LinkedIn."
        )

    if req.holehe and req.holehe.get("results"):
        accounts = [r["site"] for r in req.holehe["results"]]
        prompt_parts.append(
            f"Holehe found email registered on {req.holehe['total']} services: {', '.join(accounts)}"
        )

    if req.harvester:
        hosts = req.harvester.get("hosts", [])
        emails = req.harvester.get("emails", [])
        if hosts:
            prompt_parts.append(
                f"theHarvester found {len(hosts)} subdomains/hosts: {', '.join(hosts[:20])}"
                + (f" (and {len(hosts)-20} more)" if len(hosts) > 20 else "")
            )
        if emails:
            prompt_parts.append(
                f"theHarvester found {len(emails)} emails: {', '.join(emails[:10])}"
            )

    if req.hibp and req.hibp.get("breaches"):
        breaches = req.hibp["breaches"]
        prompt_parts.append(
            f"Breach check found {len(breaches)} breaches: {', '.join(breaches[:20])}"
            + (f" (and {len(breaches)-20} more)" if len(breaches) > 20 else "")
        )

    if req.gravatar and req.gravatar.get("found"):
        g = req.gravatar
        parts = []
        if g.get("name"):
            parts.append(f"real name: {g['name']}")
        if g.get("display_name"):
            parts.append(f"display name: {g['display_name']}")
        if g.get("location"):
            parts.append(f"location: {g['location']}")
        if g.get("profile_url"):
            parts.append(f"profile: {g['profile_url']}")
        prompt_parts.append(f"Gravatar profile found — {', '.join(parts)}")

    if req.github and req.github.get("found"):
        gh = req.github
        parts = []
        if gh.get("name"):
            parts.append(f"name: {gh['name']}")
        if gh.get("bio"):
            parts.append(f"bio: {gh['bio']}")
        if gh.get("location"):
            parts.append(f"location: {gh['location']}")
        if gh.get("company"):
            parts.append(f"company: {gh['company']}")
        if gh.get("email"):
            parts.append(f"email: {gh['email']}")
        if gh.get("blog"):
            parts.append(f"blog: {gh['blog']}")
        parts.append(f"{gh.get('public_repos', 0)} repos, {gh.get('followers', 0)} followers")
        prompt_parts.append(f"GitHub profile found — {', '.join(parts)}")

    if req.enricher and req.enricher.get("profiles"):
        for p in req.enricher["profiles"]:
            parts = []
            if p.get("display_name"):
                parts.append(f"display name: {p['display_name']}")
            if p.get("bio"):
                parts.append(f"bio: {p['bio'][:200]}")
            if parts:
                prompt_parts.append(f"{p.get('platform', 'Unknown')} profile — {', '.join(parts)}")

    if req.platform_check and req.platform_check.get("results"):
        found = [r for r in req.platform_check["results"] if r.get("found")]
        not_found = [r["platform"] for r in req.platform_check["results"] if not r.get("found")]
        if found:
            found_details = [f"{r['platform']} ({r.get('url', '')})" for r in found]
            prompt_parts.append(
                f"Platform existence check confirmed {len(found)} profiles: {', '.join(found_details)}"
            )
        if not_found:
            prompt_parts.append(
                f"Platform existence check found no profile on: {', '.join(not_found)}"
            )

    if req.profile_scrape and req.profile_scrape.get("results"):
        prompt_parts.append(
            "\n== LIVE PROFILE SCRAPE DATA (Active Techniques - visited each profile URL) =="
        )
        for p in req.profile_scrape["results"]:
            if p.get("error"):
                continue
            parts = [f"Site: {p.get('site', '')}"]
            if p.get("display_name"):
                parts.append(f"Display Name: {p['display_name']}")
            if p.get("bio"):
                parts.append(f"Bio: {p['bio'][:300]}")
            if p.get("emails"):
                parts.append(f"Emails on page: {', '.join(p['emails'])}")
            if p.get("location"):
                parts.append(f"Location: {p['location']}")
            if p.get("links"):
                parts.append(f"Linked URLs: {', '.join(p['links'][:5])}")
            prompt_parts.append(" | ".join(parts))
        prompt_parts.append(
            "IMPORTANT: Cross-reference display names, bios, and linked URLs across platforms "
            "to correlate identity. Look for consistent real names, locations, linked personal sites, "
            "and email addresses that appear on multiple profiles."
        )

    if req.hunter and req.hunter.get("emails"):
        emails = [e["email"] for e in req.hunter["emails"][:15]]
        prompt_parts.append(
            f"Hunter.io found {req.hunter['total']} email addresses: {', '.join(emails)}"
        )
        if req.hunter.get("pattern"):
            prompt_parts.append(f"Email pattern: {req.hunter['pattern']}")

    if req.shodan and req.shodan.get("found"):
        s = req.shodan
        parts = []
        if s.get("org"):
            parts.append(f"org: {s['org']}")
        if s.get("os"):
            parts.append(f"OS: {s['os']}")
        if s.get("ports"):
            parts.append(f"ports: {', '.join(str(p) for p in s['ports'][:20])}")
        prompt_parts.append(f"Shodan host data: {', '.join(parts)}")
        if s.get("vulns"):
            prompt_parts.append(f"Shodan CVEs found: {', '.join(s['vulns'][:15])}")
        if s.get("services"):
            svc = [f"{sv['port']}/{sv['transport']} {sv.get('product','')}".strip() for sv in s['services'][:10]]
            prompt_parts.append(f"Services: {', '.join(svc)}")

    if req.name_search and req.name_search.get("name"):
        prompt_parts.append(
            f"This is a NAME SEARCH for real person: {req.name_search['name']}. "
            "Focus on people-search strategies: TruePeopleSearch, FastPeopleSearch, Spokeo, "
            "BeenVerified, WhitePages, Pipl, LinkedIn, Facebook. "
            "Suggest how to narrow results by location, age, or known associates."
        )

    recon_data = "\n".join(prompt_parts)

    t0 = time.time()

    ai_resp = await call_ai(
        api_key=key.api_key,
        provider=key.provider,
        model=key.model,
        max_tokens=4096,
        messages=[
            {
                "role": "user",
                "content": (
                    INVESTIGATION_PROMPT
                    + ("\n" + ACTIVE_TECHNIQUES_SECTION if req.active_techniques else "")
                    + f"\n\nTarget: {req.target}\n\nCollected data:\n{recon_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai_resp["text"]
    tokens = ai_resp["input_tokens"] + ai_resp["output_tokens"]

    short_summary, full_report = parse_tagged_report(text)
    return {
        "summary": full_report,
        "short_summary": short_summary,
        "profile": parse_profile(text),
        "model": ai_resp["model"],
        "tokens": tokens,
        "elapsed": elapsed,
        "ai_source": key.source,
        "free_remaining": key.remaining,
    }


@router.post("/deep-dive")
async def deep_dive(req: AnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    key = resolve_ai_key(x_api_key, x_ai_provider, client_ip(request), "deepdive")

    # Build recon context (same data assembly as summarize)
    prompt_parts = [f"Target: {req.target}\n"]

    if req.sherlock and req.sherlock.get("results"):
        results = req.sherlock["results"]
        confirmed = [r["site"] for r in results if r.get("confidence") != "false_positive"]
        high_conf = [r["site"] for r in results if r.get("confidence") == "high_confidence"]
        if confirmed:
            prompt_parts.append(f"Sherlock confirmed {len(confirmed)} profiles: {', '.join(confirmed[:30])}")
        if high_conf:
            prompt_parts.append(f"HIGH-CONFIDENCE platforms: {', '.join(high_conf)}")

    if req.holehe and req.holehe.get("results"):
        accounts = [r["site"] for r in req.holehe["results"]]
        prompt_parts.append(f"Holehe: email registered on {req.holehe['total']} services: {', '.join(accounts)}")

    if req.hibp and req.hibp.get("breaches"):
        prompt_parts.append(f"Breaches ({len(req.hibp['breaches'])}): {', '.join(req.hibp['breaches'][:20])}")

    if req.gravatar and req.gravatar.get("found"):
        g = req.gravatar
        parts = []
        for k in ("name", "display_name", "location", "profile_url"):
            if g.get(k):
                parts.append(f"{k}: {g[k]}")
        if parts:
            prompt_parts.append(f"Gravatar: {', '.join(parts)}")

    if req.github and req.github.get("found"):
        gh = req.github
        parts = []
        for k in ("name", "bio", "location", "company", "email", "blog"):
            if gh.get(k):
                parts.append(f"{k}: {gh[k]}")
        parts.append(f"{gh.get('public_repos', 0)} repos, {gh.get('followers', 0)} followers")
        prompt_parts.append(f"GitHub: {', '.join(parts)}")

    if req.enricher and req.enricher.get("profiles"):
        for p in req.enricher["profiles"]:
            parts = []
            if p.get("display_name"):
                parts.append(f"display name: {p['display_name']}")
            if p.get("bio"):
                parts.append(f"bio: {p['bio'][:200]}")
            if parts:
                prompt_parts.append(f"{p.get('platform', 'Unknown')}: {', '.join(parts)}")

    if req.platform_check and req.platform_check.get("results"):
        found = [r for r in req.platform_check["results"] if r.get("found")]
        if found:
            prompt_parts.append(f"Platform check confirmed: {', '.join(r['platform'] for r in found)}")

    if req.hunter and req.hunter.get("emails"):
        emails = [e["email"] for e in req.hunter["emails"][:15]]
        prompt_parts.append(f"Hunter.io emails: {', '.join(emails)}")
        if req.hunter.get("pattern"):
            prompt_parts.append(f"Email pattern: {req.hunter['pattern']}")

    if req.shodan and req.shodan.get("found"):
        s = req.shodan
        parts = []
        for k in ("org", "os", "isp", "country", "city"):
            if s.get(k):
                parts.append(f"{k}: {s[k]}")
        if s.get("ports"):
            parts.append(f"ports: {', '.join(str(p) for p in s['ports'][:20])}")
        prompt_parts.append(f"Shodan: {', '.join(parts)}")

    # Profile scrape data — the key differentiator for Deep Dive
    scrape_section = ""
    if req.profile_scrape and req.profile_scrape.get("results"):
        scrape_parts = ["\n== SCRAPED PROFILE DATA (live page visits) =="]
        for p in req.profile_scrape["results"]:
            if p.get("error"):
                continue
            lines = [f"\n[{p.get('site', '?')}] {p.get('url', '')}"]
            if p.get("display_name"):
                lines.append(f"  Display Name: {p['display_name']}")
            if p.get("bio"):
                lines.append(f"  Bio: {p['bio'][:400]}")
            if p.get("emails"):
                lines.append(f"  Emails found: {', '.join(p['emails'])}")
            if p.get("location"):
                lines.append(f"  Location: {p['location']}")
            if p.get("links"):
                lines.append(f"  Linked URLs: {', '.join(p['links'][:8])}")
            scrape_parts.append("\n".join(lines))
        scrape_section = "\n".join(scrape_parts)

    recon_data = "\n".join(prompt_parts)
    if scrape_section:
        recon_data += "\n" + scrape_section

    t0 = time.time()

    ai_resp = await call_ai(
        api_key=key.api_key,
        provider=key.provider,
        model=key.model,
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a senior OSINT intelligence analyst writing a classified-style dossier. "
                    "You have access to OSINT recon data AND live-scraped profile page content below. "
                    "Write a deep analytical report — NOT bullet points, but a proper intelligence dossier.\n\n"
                    "Produce EXACTLY these five sections with these EXACT headers (use ** bold for headers):\n\n"
                    "**SUBJECT PROFILE**\n"
                    "Write 2-3 flowing paragraphs describing this person's digital identity. "
                    "Synthesize ALL available data into a narrative: who they likely are, what they do online, "
                    "their technical sophistication, geographic indicators, professional profile, interests, "
                    "and behavioral patterns. Cross-reference display names, bios, and linked accounts "
                    "from the scraped profile data to build a coherent picture. "
                    "Do NOT use bullet points — write in analytical prose.\n\n"
                    "**CONFIDENCE MATRIX**\n"
                    "Present a table of identity inferences. Each row should be:\n"
                    "| Inference | Confidence | Evidence |\n"
                    "Include rows for: Probable Real Name, Location, Occupation/Industry, Age Range, "
                    "Primary Email, Technical Skill Level, and any other strong inferences. "
                    "Confidence must be HIGH, MEDIUM, or LOW. Evidence column must cite specific data points.\n\n"
                    "**PLATFORM CORRELATION**\n"
                    "Analyze which platforms corroborate each other. For each cluster of corroborating platforms, "
                    "explain WHAT matches (same display name? same bio text? same linked URL? same avatar?) "
                    "and what intelligence that yields. Identify any contradictions between platforms. "
                    "If scraped profile data is available, use the actual display names and bios to correlate.\n\n"
                    "**OPSEC ASSESSMENT**\n"
                    "Evaluate the target's operational security. What personal information have they leaked? "
                    "What are they doing well (separate identities, no real name, etc.)? "
                    "Rate their overall OPSEC as POOR, FAIR, MODERATE, or STRONG with justification. "
                    "Note specific mistakes: real name in username, same handle everywhere, "
                    "location in bio, employer visible, email exposed in breaches, etc.\n\n"
                    "**READY-TO-USE QUERIES**\n"
                    "Provide 5-8 copy-paste-ready search queries for manual follow-up. "
                    "Each on its own line prefixed with →. Include:\n"
                    "- Google dorks: site:, inurl:, intitle:, \"exact match\" operators\n"
                    "- Platform-specific searches\n"
                    "- Reverse email/username lookups\n"
                    "Make these SPECIFIC to the target — use their actual username, email, "
                    "inferred name, and discovered platforms. No generic templates.\n\n"
                    "IMPORTANT ANALYSIS RULES:\n"
                    "- Previous OSINT findings take priority over single-source web content. "
                    "Do not override multi-source conclusions with data from a single visited page. "
                    "If a visited page contradicts earlier findings, note the discrepancy rather than replacing the earlier conclusion.\n\n"
                    "IMPORTANT FORMATTING RULES:\n"
                    "- Use **bold** for section headers and key terms\n"
                    "- Do NOT use # markdown headers\n"
                    "- Do NOT use → bullets except in READY-TO-USE QUERIES\n"
                    "- Write SUBJECT PROFILE and OPSEC ASSESSMENT as flowing prose paragraphs\n"
                    "- Use | pipe-delimited table rows for CONFIDENCE MATRIX\n"
                    "- Keep total length 600-900 words\n\n"
                    f"Recon data:\n{recon_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai_resp["text"]
    tokens = ai_resp["input_tokens"] + ai_resp["output_tokens"]

    return {
        "summary": text,
        "model": ai_resp["model"],
        "tokens": tokens,
        "elapsed": elapsed,
        "ai_source": key.source,
        "free_remaining": key.remaining,
    }


class EmailHeaderAnalyzeRequest(BaseModel):
    header_analysis: dict


@router.post("/email-headers")
async def analyze_email_headers_ai(req: EmailHeaderAnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    key = resolve_ai_key(x_api_key, x_ai_provider, client_ip(request), "analysis")

    data = req.header_analysis
    prompt_parts = []

    # Key headers
    kh = data.get("key_headers", {})
    if kh.get("From"):
        prompt_parts.append(f"From: {kh['From']}")
    if kh.get("To"):
        prompt_parts.append(f"To: {kh['To']}")
    if kh.get("Subject"):
        prompt_parts.append(f"Subject: {kh['Subject']}")
    if kh.get("Date"):
        prompt_parts.append(f"Date: {kh['Date']}")
    if kh.get("Return-Path"):
        prompt_parts.append(f"Return-Path: {kh['Return-Path']}")
    if kh.get("Reply-To"):
        prompt_parts.append(f"Reply-To: {kh['Reply-To']}")
    if kh.get("X-Mailer"):
        prompt_parts.append(f"X-Mailer: {kh['X-Mailer']}")
    if kh.get("Message-ID"):
        prompt_parts.append(f"Message-ID: {kh['Message-ID']}")

    # Authentication
    auth = data.get("authentication", {})
    prompt_parts.append(f"\nAuthentication: SPF={auth.get('spf', 'missing')}, DKIM={auth.get('dkim', 'missing')}, DMARC={auth.get('dmarc', 'missing')}")

    # Automated verdict
    prompt_parts.append(f"Automated verdict: {data.get('verdict', 'UNKNOWN')}")

    # Sender IP and geo
    if data.get("sender_ip"):
        prompt_parts.append(f"Sender IP: {data['sender_ip']}")
    geo = data.get("ip_geolocation", {})
    for ip, g in geo.items():
        loc = ", ".join(filter(None, [g.get("city"), g.get("region"), g.get("country")]))
        prompt_parts.append(f"IP {ip}: {loc} | ISP: {g.get('isp', '?')} | Org: {g.get('org', '?')} | ASN: {g.get('asn', '?')}")

    # Anomalies
    anomalies = data.get("anomalies", [])
    if anomalies:
        prompt_parts.append(f"\nDetected anomalies ({len(anomalies)}):")
        for a in anomalies:
            prompt_parts.append(f"  [{a['severity'].upper()}] {a['type']}: {a['detail']}")

    # Hops
    hops = data.get("hops", [])
    if hops:
        prompt_parts.append(f"\nRouting: {len(hops)} hops, total delay: {data.get('total_delay_seconds', '?')}s")
        for h in hops:
            hop_desc = f"  Hop {h['hop']}: {h.get('from', '?')} -> {h.get('by', '?')}"
            if h.get("ips"):
                hop_desc += f" [{', '.join(h['ips'])}]"
            if h.get("delay_seconds") is not None:
                hop_desc += f" (+{h['delay_seconds']}s)"
            prompt_parts.append(hop_desc)

    header_data = "\n".join(prompt_parts)

    t0 = time.time()

    ai_resp = await call_ai(
        api_key=key.api_key,
        provider=key.provider,
        model=key.model,
        max_tokens=1500,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a senior email security analyst. Analyze the following parsed email header data "
                    "and provide your expert assessment.\n\n"
                    "Respond with ONLY valid JSON (no markdown fencing, no extra text) with exactly these keys:\n\n"
                    '{\n'
                    '  "summary": "One paragraph natural language summary of what the headers reveal about this email\'s origin, routing, and legitimacy.",\n'
                    '  "verdict": "LEGITIMATE | SUSPICIOUS | LIKELY PHISHING | BEC ATTEMPT",\n'
                    '  "reasons": ["reason 1", "reason 2", "reason 3"],\n'
                    '  "next_steps": ["step 1", "step 2", "step 3"]\n'
                    '}\n\n'
                    "RULES:\n"
                    "- verdict must be exactly one of: LEGITIMATE, SUSPICIOUS, LIKELY PHISHING, BEC ATTEMPT\n"
                    "- reasons: 2-3 specific reasons supporting your verdict, citing actual header data\n"
                    "- next_steps: 2-3 actionable steps for a security analyst to take\n"
                    "- summary should be 3-5 sentences, mentioning specific IPs, domains, and auth results\n"
                    "- Be decisive. If auth passes and no anomalies, say LEGITIMATE. Don't hedge.\n"
                    "- BEC ATTEMPT is for business email compromise patterns (display name spoofing of executives, "
                    "urgency in subject, reply-to redirects)\n\n"
                    f"Email header analysis data:\n{header_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai_resp["text"]
    tokens = ai_resp["input_tokens"] + ai_resp["output_tokens"]

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = {
            "summary": text,
            "verdict": "UNKNOWN",
            "reasons": [],
            "next_steps": [],
        }

    return {
        "summary": parsed.get("summary", ""),
        "verdict": parsed.get("verdict", "UNKNOWN"),
        "reasons": parsed.get("reasons", []),
        "next_steps": parsed.get("next_steps", []),
        "model": ai_resp["model"],
        "tokens": tokens,
        "elapsed": elapsed,
        "ai_source": key.source,
        "free_remaining": key.remaining,
    }


class DeepAnalysisRequest(BaseModel):
    target: str
    dns: Optional[dict] = None
    whois: Optional[dict] = None
    ssl: Optional[dict] = None
    headers: Optional[dict] = None
    subdomains: Optional[dict] = None
    asn: Optional[dict] = None
    portscan: Optional[dict] = None
    asn_detail: Optional[dict] = None
    shodan: Optional[dict] = None


@router.post("/deep")
async def deep_analysis(req: DeepAnalysisRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    key = resolve_ai_key(x_api_key, x_ai_provider, client_ip(request), "deepdive")

    prompt_parts = [f"Target: {req.target}\n"]

    if req.dns and req.dns.get("records"):
        for rtype, records in req.dns["records"].items():
            prompt_parts.append(f"DNS {rtype}: {', '.join(records[:10])}")
        if req.dns.get("cloudflare_proxied"):
            prompt_parts.append("CLOUDFLARE PROXY DETECTED on A records.")

    if req.whois and req.whois.get("found"):
        w = req.whois
        parts = []
        for k in ("registrar", "creation_date", "expiration_date", "org", "country"):
            if w.get(k):
                parts.append(f"{k}: {w[k]}")
        if w.get("name_servers"):
            parts.append(f"nameservers: {', '.join(w['name_servers'][:5])}")
        prompt_parts.append(f"WHOIS: {', '.join(parts)}")

    if req.ssl and req.ssl.get("found"):
        s = req.ssl
        parts = [f"issuer: {s.get('issuer', '')}", f"CN: {s.get('common_name', '')}"]
        if s.get("days_left") is not None:
            parts.append(f"expires in {s['days_left']} days")
        if s.get("sans"):
            parts.append(f"SANs: {', '.join(s['sans'][:10])}")
        prompt_parts.append(f"SSL: {', '.join(parts)}")

    if req.headers and req.headers.get("found"):
        h = req.headers
        prompt_parts.append(f"HTTP server: {h.get('server', 'unknown')}, grade: {h.get('grade', '?')}")
        sec = h.get("security_headers", {})
        missing = [k for k, v in sec.items() if not v.get("present")]
        if missing:
            prompt_parts.append(f"Missing security headers: {', '.join(missing)}")

    if req.subdomains and req.subdomains.get("subdomains"):
        subs = req.subdomains["subdomains"]
        names = [s["subdomain"] for s in subs]
        prompt_parts.append(f"Subdomains ({len(names)}): {', '.join(names[:20])}")

    if req.asn and req.asn.get("found"):
        a = req.asn
        parts = [f"IP: {a.get('ip', '')}"]
        if a.get("asn"):
            parts.append(f"ASN: {a['asn']}")
        if a.get("org"):
            parts.append(f"org: {a['org']}")
        prompt_parts.append(f"ASN: {', '.join(parts)}")

    if req.portscan:
        open_ports = [f"{r['port']}/{r['service']}" for r in req.portscan.get("results", []) if r.get("open")]
        if open_ports:
            prompt_parts.append(f"Open ports: {', '.join(open_ports)}")

    if req.asn_detail and req.asn_detail.get("found"):
        ad = req.asn_detail
        parts = []
        if ad.get("org"):
            parts.append(f"org: {ad['org']}")
        if ad.get("prefixes_v4"):
            parts.append(f"IPv4 prefixes: {len(ad['prefixes_v4'])}")
        if ad.get("peers"):
            parts.append(f"peers: {ad.get('total_peers', len(ad['peers']))}")
        prompt_parts.append(f"ASN Detail: {', '.join(parts)}")

    if req.shodan and not req.shodan.get("error"):
        s = req.shodan
        parts = []
        if s.get("ip"):
            parts.append(f"IP: {s['ip']}")
        if s.get("org"):
            parts.append(f"org: {s['org']}")
        ports = s.get("ports", [])
        if ports:
            port_strs = [f"{p['port']}/{p.get('transport','tcp')}" for p in ports[:15]]
            parts.append(f"services: {', '.join(port_strs)}")
        vulns = s.get("vulns", [])
        if vulns:
            parts.append(f"CVEs: {', '.join(vulns[:10])}")
        if parts:
            prompt_parts.append(f"Shodan: {', '.join(parts)}")

    recon_data = "\n".join(prompt_parts)

    t0 = time.time()

    ai_resp = await call_ai(
        api_key=key.api_key,
        provider=key.provider,
        model=key.model,
        max_tokens=3000,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a senior security analyst. You have been given OSINT reconnaissance data for a target. "
                    "Perform a deep analytical breakdown covering:\n\n"
                    "## Threat Model\n"
                    "## Attack Surface Assessment\n"
                    "## High-Value Targets (prioritized)\n"
                    "## Recommended Investigation Steps\n"
                    "## Operational Security Observations\n\n"
                    "Be specific, technical, and base every conclusion strictly on the data provided. "
                    "Do not speculate beyond what the data supports. "
                    "Use **bold** for emphasis. Use → prefix for action items. "
                    "Write in markdown with ## headers.\n\n"
                    f"Recon data:\n{recon_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai_resp["text"]
    tokens = ai_resp["input_tokens"] + ai_resp["output_tokens"]

    return {
        "summary": text,
        "model": ai_resp["model"],
        "tokens": tokens,
        "elapsed": elapsed,
        "ai_source": key.source,
        "free_remaining": key.remaining,
    }


class CorrelateRequest(BaseModel):
    targets: dict  # { "target_name": { sherlock: ..., github: ..., ... }, ... }


def _summarize_target_data(target: str, data: dict) -> str:
    """Build a concise text summary of one target's scan results."""
    parts = [f"\n[TARGET: {target}]"]

    if data.get("sherlock") and data["sherlock"].get("results"):
        results = data["sherlock"]["results"]
        confirmed = [r["site"] for r in results if r.get("confidence") != "false_positive"]
        if confirmed:
            parts.append(f"  Sherlock ({len(confirmed)} profiles): {', '.join(confirmed[:25])}")

    if data.get("holehe") and data["holehe"].get("results"):
        accounts = [r["site"] for r in data["holehe"]["results"]]
        parts.append(f"  Holehe ({len(accounts)} services): {', '.join(accounts)}")

    if data.get("github") and data["github"].get("found"):
        gh = data["github"]
        info = []
        for k in ("name", "bio", "location", "company", "email", "blog"):
            if gh.get(k):
                info.append(f"{k}: {gh[k]}")
        info.append(f"{gh.get('public_repos', 0)} repos, {gh.get('followers', 0)} followers")
        parts.append(f"  GitHub: {', '.join(info)}")

    if data.get("gravatar") and data["gravatar"].get("found"):
        g = data["gravatar"]
        info = []
        for k in ("name", "display_name", "location"):
            if g.get(k):
                info.append(f"{k}: {g[k]}")
        if info:
            parts.append(f"  Gravatar: {', '.join(info)}")

    if data.get("hibp") and data["hibp"].get("breaches"):
        parts.append(f"  Breaches: {', '.join(data['hibp']['breaches'][:15])}")

    if data.get("enricher") and data["enricher"].get("profiles"):
        for p in data["enricher"]["profiles"]:
            info = []
            if p.get("display_name"):
                info.append(f"name: {p['display_name']}")
            if p.get("bio"):
                info.append(f"bio: {p['bio'][:150]}")
            if info:
                parts.append(f"  {p.get('platform', '?')}: {', '.join(info)}")

    if data.get("platformCheck") and data["platformCheck"].get("results"):
        found = [r["platform"] for r in data["platformCheck"]["results"] if r.get("found")]
        if found:
            parts.append(f"  Platform check confirmed: {', '.join(found)}")

    if data.get("hunter") and data["hunter"].get("emails"):
        emails = [e["email"] for e in data["hunter"]["emails"][:10]]
        parts.append(f"  Hunter.io: {', '.join(emails)}")

    if data.get("shodan") and data["shodan"].get("found"):
        s = data["shodan"]
        info = []
        for k in ("org", "os", "country", "city"):
            if s.get(k):
                info.append(f"{k}: {s[k]}")
        if info:
            parts.append(f"  Shodan: {', '.join(info)}")

    return "\n".join(parts)


@router.post("/correlate")
async def correlate(req: CorrelateRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    key = resolve_ai_key(x_api_key, x_ai_provider, client_ip(request), "analysis")

    if len(req.targets) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 targets to correlate")

    target_summaries = []
    for target_name, data in req.targets.items():
        target_summaries.append(_summarize_target_data(target_name, data))

    combined_data = "\n".join(target_summaries)
    target_list = ", ".join(req.targets.keys())

    t0 = time.time()

    ai_resp = await call_ai(
        api_key=key.api_key,
        provider=key.provider,
        model=key.model,
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a senior OSINT analyst performing CROSS-TARGET CORRELATION. "
                    f"You have scan results for {len(req.targets)} separate targets: {target_list}. "
                    "Your job is to find connections, overlaps, and identity relationships BETWEEN these targets.\n\n"
                    "Produce EXACTLY these sections with ** bold headers:\n\n"
                    "**IDENTITY CORRELATION**\n"
                    "Are any of these targets the same person? Analyze shared platforms, matching usernames, "
                    "consistent display names, overlapping bios, matching locations, or linked accounts. "
                    "For each pair of targets, state whether they appear to be: SAME PERSON (high confidence), "
                    "LIKELY SAME PERSON, POSSIBLY RELATED, or NO CONNECTION FOUND. Explain your reasoning "
                    "with specific evidence (e.g. 'both have GitHub profiles with matching company field').\n\n"
                    "**CROSS-TARGET CONNECTIONS**\n"
                    "List every concrete data point that connects any two targets:\n"
                    "→ Shared platforms where both have accounts\n"
                    "→ Email addresses that appear in multiple targets' results\n"
                    "→ Matching or similar display names, bios, or locations across targets\n"
                    "→ One target's email matching another target's GitHub commit author\n"
                    "→ Linked URLs on one profile pointing to another target's accounts\n"
                    "Use → prefix for each connection found.\n\n"
                    "**UNIFIED PROFILE**\n"
                    "If targets appear to be the same person or closely related, combine all findings "
                    "into a single consolidated identity profile. Write 2-3 paragraphs synthesizing: "
                    "probable real name, location, occupation, technical interests, online behavior patterns. "
                    "If targets are unrelated, briefly profile each separately.\n\n"
                    "**CONTRADICTIONS**\n"
                    "Flag any inconsistencies between targets: different names on what should be the same person, "
                    "conflicting locations, different employers, accounts that don't cross-reference when expected. "
                    "Use → prefix for each contradiction. If none found, state 'No contradictions detected.'\n\n"
                    "**CONSOLIDATED OPSEC**\n"
                    "Rate the combined OPSEC posture across all targets as POOR, FAIR, MODERATE, or STRONG. "
                    "What is the worst privacy leak across all targets? What identity correlation is possible "
                    "because the same person used multiple handles? What could they do better? Write in prose.\n\n"
                    "FORMATTING RULES:\n"
                    "- Use **bold** for headers and key terms\n"
                    "- Use → prefix for connection items and contradictions\n"
                    "- Do NOT use # markdown headers\n"
                    "- Write UNIFIED PROFILE and CONSOLIDATED OPSEC as flowing prose\n"
                    "- Keep total length 500-800 words\n\n"
                    f"Scan data for all targets:\n{combined_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai_resp["text"]
    tokens = ai_resp["input_tokens"] + ai_resp["output_tokens"]

    return {
        "summary": text,
        "model": ai_resp["model"],
        "tokens": tokens,
        "elapsed": elapsed,
        "ai_source": key.source,
        "free_remaining": key.remaining,
    }
