from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
import anthropic
import time

router = APIRouter()


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
async def summarize(req: AnalyzeRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    prompt_parts = [f"Target: {req.target}\n"]

    if req.sherlock and req.sherlock.get("results"):
        results = req.sherlock["results"]
        confirmed = [r["site"] for r in results if r.get("confidence") != "false_positive"]
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

    client = anthropic.Anthropic(api_key=x_api_key)
    t0 = time.time()

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are an OSINT analyst. Based on the recon data below, produce this exact structure:\n\n"
                    "**Digital Footprint**\n"
                    "Brief overview of the target's online presence and notable patterns.\n\n"
                    "**Next Steps**\n"
                    "→ 2-4 specific investigative actions, one per line prefixed with →\n\n"
                    "**Identity Leads** (all inferences from public data only)\n"
                    "→ **Probable Name:** [best guess name] **(confidence: low/medium/high)** — explain your reasoning "
                    "(e.g. username contains 'john.smith', common naming pattern, matches GitHub commit author, "
                    "LinkedIn profile name, etc.)\n"
                    "→ If you can suggest alternate possible names, list them with reasoning\n"
                    "→ Suggest specific URLs to check for name confirmation: e.g. github.com/[username] commit history, "
                    "linkedin.com/in/[username], about.me/[username] bio, gravatar profile, etc.\n\n"
                    "**Phone Lookup Strategies** (public data only)\n"
                    "→ Suggest specific sites: Truecaller, Spokeo, WhitePages, BeenVerified, Pipl, NumLookup\n"
                    "→ Suggest searching the email/username on Telegram, WhatsApp, Signal user lookups\n"
                    "→ If a probable name was inferred, suggest combining name + location for reverse phone lookup\n\n"
                    + (
                        "**⚠ Active Techniques** (may alert the target — use with caution)\n"
                        "→ ⚠ ACTIVE: Try account recovery flows on detected services (e.g. Google, Apple, Microsoft) "
                        "which may reveal partial phone numbers or email addresses\n"
                        "→ ⚠ ACTIVE: Password reset enumeration on detected platforms to confirm account existence "
                        "and discover linked emails/phones\n"
                        "→ ⚠ ACTIVE: Send a connection request or follow on social platforms to access restricted profiles\n"
                        "→ ⚠ ACTIVE: Use email verification endpoints on services to confirm email registration\n"
                        "→ ⚠ ACTIVE: Try forgot-password on detected services to reveal masked recovery info\n\n"
                        if req.active_techniques else ""
                    ) +
                    "Use **bold** for emphasis. Use → prefix for all action items and leads. "
                    "Do not use markdown headers (no # symbols). Keep it concise and actionable.\n\n"
                    f"Recon data:\n{recon_data}"
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = message.content[0].text
    tokens = message.usage.input_tokens + message.usage.output_tokens

    return {
        "summary": text,
        "model": message.model,
        "tokens": tokens,
        "elapsed": elapsed,
    }


@router.post("/deep-dive")
async def deep_dive(req: AnalyzeRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

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

    client = anthropic.Anthropic(api_key=x_api_key)
    t0 = time.time()

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
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
    text = message.content[0].text
    tokens = message.usage.input_tokens + message.usage.output_tokens

    return {
        "summary": text,
        "model": message.model,
        "tokens": tokens,
        "elapsed": elapsed,
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
async def correlate(req: CorrelateRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    if len(req.targets) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 targets to correlate")

    target_summaries = []
    for target_name, data in req.targets.items():
        target_summaries.append(_summarize_target_data(target_name, data))

    combined_data = "\n".join(target_summaries)
    target_list = ", ".join(req.targets.keys())

    client = anthropic.Anthropic(api_key=x_api_key)
    t0 = time.time()

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
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
    text = message.content[0].text
    tokens = message.usage.input_tokens + message.usage.output_tokens

    return {
        "summary": text,
        "model": message.model,
        "tokens": tokens,
        "elapsed": elapsed,
    }
