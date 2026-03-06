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
