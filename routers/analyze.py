import re
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, Field

from core.ai_call import run_ai
from core.ai_text import parse_json_object, summary_and_report
from routers.recon_infra import extra_recon_lines

router = APIRouter()


# ---- investigation report prompt ------------------------------------------------
# Tagged sections instead of markdown-inside-JSON: long reports in a JSON string break
# on unescaped quotes/newlines, especially with smaller models.
INVESTIGATION_PROMPT = """You are a senior OSINT investigator writing a case report from automated collection results.

Write for an investigator who will act on this report. Be specific and evidence-driven:
- Use only the collected data below. Never invent accounts, names, locations or breaches.
- Cite the source for each claim in parentheses, e.g. (Sherlock), (GitHub), (HIBP).
- When evidence is thin or conflicting, say so and lower the confidence. A short honest report beats a padded one.
- Accounts are listed in four groups: LINKED, EXISTS (MATCHES), EXISTS (DIFFERENT PERSON) and UNVERIFIED. Use each account only as its group allows, and never move an account to a stronger group.
- LINKED accounts are tied to the primary identity by a strong signal, or are the authoritative record for the target itself. They are the only accounts you may attribute to the target.
- EXISTS (MATCHES) accounts exist and nothing on them conflicts with the primary identity. That is consistent, not proven: say what would tie each one to the target or say that nothing does yet.
- EXISTS (DIFFERENT PERSON) accounts are other people who share the handle. Never use their names, locations, bios or links to describe the target. Mention them only to say the handle is shared.
- UNVERIFIED accounts are leads to check, never facts. A site that blocked the check is unknown, not absent.
- Some sources may be listed as FAILED. A failed source gave no data: never cite it, never describe its platform as linked or existing, and never treat the failure as a negative result.

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
2-4 sentences: what this target most likely is (for a username or email, who it most likely belongs to), how confident you are, and the single most useful thing found.

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

ACTIVE_TECHNIQUES_SECTION = """In the report, add a final section "## Active techniques" (the investigator enabled them) listing account-recovery or password-reset enumeration checks worth running on the linked accounts, each marked with ⚠ and a one-line note on what it reveals and the risk of notifying the target."""


# What the report is about depends on the kind of target. A hash or a phone number is not a person,
# so the model is told not to write about identity for those.
TARGET_FOCUS = {
    "hash": (
        "This target is a file hash, not a person. Leave name, location and interests blank in the profile block. "
        "In the report write only Case summary, Exposure and risk, Investigative leads and Gaps and next pivots: "
        "what this file is, how sure the sources are, and what to do with it. Skip the identity and platform sections. "
        "Use a family name only if the data lists one; community tags are unverified free text."
    ),
    "phone": (
        "This target is a phone number. Do not guess who owns it. Leave name blank in the profile block. "
        "In the report write only Case summary, Exposure and risk, Investigative leads and Gaps and next pivots: "
        "what the line type and carrier suggest and what to check next. Skip the identity and platform sections."
    ),
    "name": (
        "This target is a person's name typed by the investigator. Nothing was collected about any one person. "
        "Do not describe anyone. Write a search plan: how to narrow people-search results for this name and what to check first."
    ),
}


def parse_tagged_report(text: str) -> tuple[list[str], str]:
    """Extract (bullets, markdown report) from the tagged format, falling back to the
    legacy JSON shape and finally to raw text, so a model that ignores the format still renders."""
    t = (text or "").strip()
    sm = re.search(r"<summary>(.*?)</summary>", t, re.S | re.I)
    rp = re.search(r"<report>(.*?)(?:</report>|$)", t, re.S | re.I)
    if sm or rp:
        bullets = [b.strip().lstrip("-•*→ ").strip() for b in (sm.group(1) if sm else "").splitlines() if b.strip().lstrip("-•*→ ").strip()]
        report = (rp.group(1) if rp else re.sub(r"<(summary|profile)>.*?</\1>", "", t, flags=re.S | re.I)).strip()
        return bullets[:6], report
    return summary_and_report(t)


PROFILE_KEYS = {"name", "location", "interests", "exposure", "exposure_reason"}
_BLANK = {"", "-", "n/a", "none", "unknown", "blank", "not found", "leave blank"}


def parse_profile(text: str) -> dict:
    """Read the <profile> block (simple key: value lines) used for the report's dossier card.
    Missing or malformed blocks return {} and the frontend falls back to collected facts."""
    m = re.search(r"<profile>(.*?)</profile>", text or "", re.S | re.I)
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


SOURCE_FIELDS = {
    "sherlock": "Sherlock", "maigret": "Maigret", "github": "GitHub", "holehe": "Holehe", "hibp": "Breach check",
    "gravatar": "Gravatar", "harvester": "Domain harvest", "hunter": "Hunter.io", "enricher": "Profile enrichment",
    "platform_check": "Platform check", "profile_scrape": "Profile scrape", "shodan": "Shodan",
}


def _ok(data: Optional[dict]) -> bool:
    """A source only counts when it ran and did not fail. An errored lookup proves nothing."""
    return bool(data) and not data.get("error") and not data.get("error_code")


def _status_lines(req) -> list[str]:
    """Tell the model which sources failed, so a failure is never read as 'not found'
    and a source that returned nothing is never described as confirming anything."""
    status: dict[str, str] = {}
    for field, label in SOURCE_FIELDS.items():
        data = getattr(req, field, None)
        if isinstance(data, dict) and (data.get("error") or data.get("error_code")):
            status[label] = f"failed: {str(data.get('error') or data.get('error_code'))[:120]}"
    for name, value in (req.source_status or {}).items():
        status[str(name)[:40]] = str(value)[:140]
    bad = ("failed", "blocked")
    failed = {k: v for k, v in status.items() if v.lower().startswith(bad)}
    partial = {k: v for k, v in status.items() if v.lower().startswith("partial")}
    ok = [k for k, v in status.items() if not v.lower().startswith(bad + ("partial",))]
    lines = []
    if ok:
        lines.append(f"Sources that ran successfully: {', '.join(sorted(ok))}")
    if partial:
        lines.append(
            "Sources that answered only IN PART: "
            + "; ".join(f"{k} ({v})" for k, v in sorted(partial.items()))
            + ". What they returned can be used. What is missing is unknown, not a negative result."
        )
    if failed:
        lines.append(
            "Sources that FAILED and returned NO data: "
            + "; ".join(f"{k} ({v.split(':', 1)[1].strip() if ':' in v else 'error'})" for k, v in sorted(failed.items()))
            + ". Treat these as unknown. Do not cite them, do not call anything from them linked or existing, "
            "and do not read a failure as evidence that an account does or does not exist. List each under Gaps."
        )
    return lines


# Old clients and saved prompts used two statuses. They map onto the weakest group that fits.
_STATUS_ALIAS = {"confirmed": "matches", "possible": "unverified"}


def _breach_names(hibp: Optional[dict], limit: int = 20) -> list[str]:
    """Breach names for a prompt. Rows are objects now (name, date, ...); old data is a list of strings."""
    out = []
    for b in ((hibp or {}).get("breaches") or [])[:limit]:
        if isinstance(b, dict):
            name = str(b.get("name") or "").strip()
            year = b.get("year") or str(b.get("date") or "")[:4]
            if name:
                out.append(f"{name} ({year})" if year else name)
        elif b:
            out.append(str(b))
    return out


def _account_lines(req) -> list[str]:
    """Account evidence, worded by how strong it is. The groups are the ledger's tiers."""
    lines: list[str] = []
    if req.accounts:
        by: dict[str, list] = {"linked": [], "matches": [], "different": [], "unverified": []}
        for a in req.accounts:
            by[_STATUS_ALIAS.get(a.status, a.status) if _STATUS_ALIAS.get(a.status, a.status) in by else "unverified"].append(a)
        fmt = lambda a: f"{a.site} ({a.url})" if a.url else a.site
        noted = lambda a: f"{fmt(a)}{' [' + a.note + ']' if a.note else ''}"
        if by["linked"]:
            lines.append(
                f"LINKED accounts ({len(by['linked'])}), tied to the primary identity by a strong signal "
                "(a cross-link, the same avatar, a shared personal site) or the authoritative record for the target itself: "
                + ", ".join(noted(a) for a in by["linked"][:30])
            )
        if by["matches"]:
            lines.append(
                f"EXISTS (MATCHES) accounts ({len(by['matches'])}), a profile was read and its name fits the primary identity "
                "or it carries no conflicting name: " + ", ".join(noted(a) for a in by["matches"][:30])
            )
            lines.append(
                "Exists means an account with this handle is there. It does not prove the account belongs to the same "
                "person; compare names, bios, avatars and links before attributing it."
            )
        if by["different"]:
            lines.append(
                f"EXISTS (DIFFERENT PERSON) accounts ({len(by['different'])}), a profile was read and the name on it conflicts "
                "with the primary identity. These are other people who share the handle, not the target: "
                + ", ".join(noted(a) for a in by["different"][:30])
            )
        if by["unverified"]:
            lines.append(
                f"UNVERIFIED accounts ({len(by['unverified'])}), a tool reported the handle exists but nothing was read "
                f"(many sites answer yes for any name, and some block the check): {', '.join(fmt(a) for a in by['unverified'][:40])}"
                + (f" (and {len(by['unverified']) - 40} more)" if len(by["unverified"]) > 40 else "")
            )
        return lines
    # Older clients send raw tool output instead of the ledger.
    rows = [r for src in (req.sherlock, getattr(req, "maigret", None)) if _ok(src) for r in (src.get("results") or [])]
    verified = [r for r in rows if r.get("verified")]
    possible = [r for r in rows if not r.get("verified") and r.get("confidence") != "false_positive"]
    noisy = [r["site"] for r in rows if r.get("confidence") == "false_positive"]
    fmt = lambda r: f'{r["site"]} ({r["url"]})' if r.get("url") else r["site"]
    if verified:
        lines.append(f"Accounts where a profile was read ({len(verified)}): {', '.join(fmt(r) for r in verified[:30])}")
    if possible:
        lines.append(
            f"UNVERIFIED accounts ({len(possible)}), existence check only, nothing was read "
            f"(many sites answer yes for any name): {', '.join(fmt(r) for r in possible[:40])}"
        )
    if noisy:
        lines.append(f"Known false-positive sites (ignore): {', '.join(noisy)}")
    return lines


class AccountEvidence(BaseModel):
    site: str = Field(max_length=120)
    url: str = Field(default="", max_length=600)
    status: str = Field(default="unverified", max_length=20)   # "linked" | "matches" | "different" | "unverified"
    sources: list[str] = Field(default_factory=list, max_length=8)
    note: str = Field(default="", max_length=200)


class AnalyzeRequest(BaseModel):
    target: str = Field(max_length=320)
    # "username", "email", "hash", "phone" or "name". Only changes the wording of the question.
    target_type: str = Field(default="", max_length=20)
    # What the UI's evidence ledger concluded, so the report and the screen agree.
    accounts: Optional[list[AccountEvidence]] = Field(default=None, max_length=400)
    # Source name -> "ok", "not found" or "failed: <reason>". Lets the model tell
    # "GitHub has no such user" apart from "GitHub could not be checked".
    source_status: Optional[dict[str, str]] = None
    sherlock: Optional[dict] = None
    maigret: Optional[dict] = None
    holehe: Optional[dict] = None
    harvester: Optional[dict] = None
    hibp: Optional[dict] = None
    gravatar: Optional[dict] = None
    github: Optional[dict] = None
    github_deep: Optional[dict] = None
    enricher: Optional[dict] = None
    platform_check: Optional[dict] = None
    hunter: Optional[dict] = None
    shodan: Optional[dict] = None
    profile_scrape: Optional[dict] = None
    name_search: Optional[dict] = None
    hash: Optional[dict] = None
    phone: Optional[dict] = None
    active_techniques: bool = False


@router.get("/ping")
def ping():
    return {"status": "analyze router live"}


def investigation_prompt(req: AnalyzeRequest) -> str:
    """The full prompt for an investigation report. Used by the AI endpoint and by the
    keyless "copy for your own AI" path, so both ask exactly the same question."""
    prompt_parts = [f"Target: {req.target}\n"]

    prompt_parts.extend(_account_lines(req))
    prompt_parts.extend(_status_lines(req))

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
                f"Passive domain harvest found {len(hosts)} subdomains/hosts: {', '.join(hosts[:20])}"
                + (f" (and {len(hosts)-20} more)" if len(hosts) > 20 else "")
            )
        if emails:
            prompt_parts.append(
                f"Passive domain harvest found {len(emails)} emails: {', '.join(emails[:10])}"
            )

    if _ok(req.hibp) and req.hibp.get("breaches"):
        breaches = req.hibp["breaches"]
        prompt_parts.append(
            f"Breach check found {len(breaches)} breaches: {', '.join(_breach_names(req.hibp))}"
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
        prompt_parts.append(f"Gravatar profile found: {', '.join(parts)}")

    if _ok(req.github) and req.github.get("found"):
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
        prompt_parts.append(f"GitHub profile (read from the GitHub API): {', '.join(parts)}")

    if req.enricher and req.enricher.get("profiles"):
        for p in req.enricher["profiles"]:
            parts = []
            if p.get("display_name"):
                parts.append(f"display name: {p['display_name']}")
            if p.get("bio"):
                parts.append(f"bio: {p['bio'][:200]}")
            if parts:
                prompt_parts.append(f"{p.get('platform', 'Unknown')} profile: {', '.join(parts)}")

    if _ok(req.platform_check) and req.platform_check.get("results"):
        rows = req.platform_check["results"]
        named = lambda r: f"{r.get('platform', '')} ({r.get('url', '')})"
        if any(r.get("state") for r in rows):
            read = [r for r in rows if r.get("state") == "found"]
            blocked = [r for r in rows if r.get("state") in ("blocked", "unknown")]
            absent = [r.get("platform", "") for r in rows if r.get("state") == "not_found"]
            if read:
                prompt_parts.append(
                    "Platform check read a profile page (a marker on the page matched) on: "
                    + ", ".join(named(r) + (f" [name on profile: {r['display_name']}]" if r.get("display_name") else "") for r in read)
                )
            if blocked:
                prompt_parts.append(
                    "Platform check was blocked or could not tell on (unknown, not absent): "
                    + ", ".join(f"{r.get('platform', '')}" + (f" [{str(r['evidence'])[:80]}]" if r.get("evidence") else "") for r in blocked)
                )
            if absent:
                prompt_parts.append(f"Platform check found no profile on: {', '.join(absent)}")
        else:
            found = [r for r in rows if r.get("found")]
            not_found = [r["platform"] for r in rows if r.get("found") is False]
            if found:
                prompt_parts.append(
                    f"Platform URL probe got a 200 response for {len(found)} profile URLs (weak signal, these sites often answer 200 for any name): {', '.join(named(r) for r in found)}"
                )
            if not_found:
                prompt_parts.append(f"Platform existence check found no profile on: {', '.join(not_found)}")

    if _ok(req.github_deep) and req.github_deep.get("found") is not False:
        gd = req.github_deep
        sections = gd.get("sections") or {}
        parts = []
        if gd.get("orgs"):
            parts.append("organisations: " + ", ".join(str(o.get("login", "")) for o in gd["orgs"][:12]))
        if gd.get("languages"):
            parts.append("languages: " + ", ".join(str(x) for x in gd["languages"][:8]))
        if gd.get("top_repos"):
            parts.append("top repos: " + ", ".join(f"{r.get('name', '')} ({r.get('stars', 0)} stars)" for r in gd["top_repos"][:5]))
        if gd.get("commit_emails"):
            parts.append("commit emails: " + ", ".join(str(e.get("email", "")) for e in gd["commit_emails"][:5]))
        if gd.get("social_accounts"):
            parts.append("linked accounts: " + ", ".join(str(a.get("url", "")) for a in gd["social_accounts"][:8]))
        if gd.get("readme_links"):
            parts.append("README links: " + ", ".join(str(u) for u in gd["readme_links"][:8]))
        if parts:
            prompt_parts.append(f"GitHub details (public API, same account as the GitHub profile): {'; '.join(parts)}")
        unknown = sorted(k for k, v in sections.items() if v in ("rate_limited", "failed"))
        if unknown:
            prompt_parts.append(f"GitHub details that could not be read (unknown, not empty): {', '.join(unknown)}")

    if _ok(req.hash):
        hs = req.hash
        verdict = str(hs.get("verdict") or "UNKNOWN").upper()
        parts = [f"type: {hs.get('hash_type', '')}", f"verdict: {verdict}"]
        test = hs.get("known_test_file")
        if verdict == "TEST_FILE" or test:
            parts.append(f"this is the {(test or {}).get('name') or 'EICAR antivirus test file'}, harmless by design; every scanner flags it and it is not malware")
        if hs.get("family"):
            parts.append(f"family: {hs['family']} (named by {', '.join(hs.get('family_sources') or []) or 'a structured source'})")
        det = hs.get("detection")
        parts.append(f"detection: {det['positives']} of {det['total']}" if isinstance(det, dict) and det.get("total") else "detection ratio: none available from keyless sources")
        for k, label in (("file_type", "file type"), ("file_name", "file name"), ("file_size", "size"), ("first_seen", "first seen"), ("last_seen", "last seen")):
            if hs.get(k):
                parts.append(f"{label}: {hs[k]}")
        if hs.get("failed_sources"):
            parts.append("sources that could not be asked (unknown, not a negative): " + ", ".join(str(x) for x in hs["failed_sources"][:8]))
        prompt_parts.append(f"Hash lookup: {'; '.join(parts)}")
        if hs.get("community_tags"):
            prompt_parts.append(
                "Community tags (free text from whoever submitted a report, unverified, never a family name): "
                + ", ".join(str(t) for t in hs["community_tags"][:12])
            )

    if _ok(req.phone):
        ph = req.phone
        parts = [f"{label}: {ph[k]}" for k, label in (("carrier", "carrier"), ("line_type", "line type"), ("location", "location"), ("country", "country")) if ph.get(k)]
        if ph.get("valid") is False:
            parts.append("reported invalid")
        prompt_parts.append(f"Phone lookup: {', '.join(parts)}" if parts else "Phone lookup returned no carrier or line type data.")

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
    return (
        INVESTIGATION_PROMPT
        + ("\n" + TARGET_FOCUS[req.target_type] if req.target_type in TARGET_FOCUS else "")
        + ("\n" + ACTIVE_TECHNIQUES_SECTION if req.active_techniques else "")
        + f"\n\nTarget: {req.target}\n\nCollected data:\n{recon_data}"
    )


@router.post("/prompt")
async def investigation_prompt_only(req: AnalyzeRequest):
    """Returns the prompt without calling any model. No key, no quota: the investigator pastes
    it into an assistant they already use."""
    return {"prompt": investigation_prompt(req)}


class ParseRequest(BaseModel):
    text: str = Field(max_length=120_000)


@router.post("/parse")
async def parse_pasted_reply(req: ParseRequest):
    """Formats a model reply the investigator pasted back in. Calls no model."""
    short_summary, full_report = parse_tagged_report(req.text)
    if not full_report.strip():
        raise HTTPException(status_code=400, detail="That reply is empty.")
    return {"summary": full_report, "short_summary": short_summary, "profile": parse_profile(req.text), "model": "pasted reply", "ai_source": "pasted", "cached": False}


@router.post("/summarize")
async def summarize(req: AnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    bucket = "analysis"
    t0 = time.time()

    ai = await run_ai(
        request, x_api_key, x_ai_provider, bucket,
        max_tokens=4096,
        messages=[{"role": "user", "content": investigation_prompt(req)}],
    )

    elapsed = round(time.time() - t0, 1)
    text = ai.text

    short_summary, full_report = parse_tagged_report(text)
    return {
        "summary": full_report,
        "short_summary": short_summary,
        "profile": parse_profile(text),
        "elapsed": elapsed,
        **ai.meta(),
    }


@router.post("/deep-dive")
async def deep_dive(req: AnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    bucket = "deepdive"

    # Build recon context (same data assembly as summarize)
    prompt_parts = [f"Target: {req.target}\n"]

    if req.sherlock and req.sherlock.get("results"):
        results = req.sherlock["results"]
        verified = [r["site"] for r in results if r.get("verified")]
        possible = [r["site"] for r in results if r.get("confidence") != "false_positive" and not r.get("verified")]
        if verified:
            prompt_parts.append(f"Accounts where a profile was read ({len(verified)}): {', '.join(verified[:30])}")
        if possible:
            prompt_parts.append(f"Unverified accounts, existence check only ({len(possible)}): {', '.join(possible[:30])}")

    if req.holehe and req.holehe.get("results"):
        accounts = [r["site"] for r in req.holehe["results"]]
        prompt_parts.append(f"Holehe: email registered on {req.holehe['total']} services: {', '.join(accounts)}")

    if req.hibp and req.hibp.get("breaches"):
        prompt_parts.append(f"Breaches ({len(req.hibp['breaches'])}): {', '.join(_breach_names(req.hibp))}")

    if req.gravatar and req.gravatar.get("found"):
        g = req.gravatar
        parts = []
        for k in ("name", "display_name", "location", "profile_url"):
            if g.get(k):
                parts.append(f"{k}: {g[k]}")
        if parts:
            prompt_parts.append(f"Gravatar: {', '.join(parts)}")

    if _ok(req.github) and req.github.get("found"):
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
            prompt_parts.append(f"Platform URL probe answered 200 (weak signal): {', '.join(r['platform'] for r in found)}")

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

    # Profile scrape data: the key differentiator for Deep Dive
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

    ai = await run_ai(
        request, x_api_key, x_ai_provider, bucket,
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    "You are a senior OSINT intelligence analyst writing a classified-style dossier. "
                    "You have access to OSINT recon data AND live-scraped profile page content below. "
                    "Write a deep analytical report, NOT bullet points, but a proper intelligence dossier.\n\n"
                    "Produce EXACTLY these five sections with these EXACT headers (use ** bold for headers):\n\n"
                    "**SUBJECT PROFILE**\n"
                    "Write 2-3 flowing paragraphs describing this person's digital identity. "
                    "Synthesize ALL available data into a narrative: who they likely are, what they do online, "
                    "their technical sophistication, geographic indicators, professional profile, interests, "
                    "and behavioral patterns. Cross-reference display names, bios, and linked accounts "
                    "from the scraped profile data to build a coherent picture. "
                    "Do NOT use bullet points: write in analytical prose.\n\n"
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
                    "Make these SPECIFIC to the target: use their actual username, email, "
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
    text = ai.text

    return {
        "summary": text,
        "elapsed": elapsed,
        **ai.meta(),
    }


class EmailHeaderAnalyzeRequest(BaseModel):
    header_analysis: dict


@router.post("/email-headers")
async def analyze_email_headers_ai(req: EmailHeaderAnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    bucket = "analysis"

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

    ai = await run_ai(
        request, x_api_key, x_ai_provider, bucket,
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
    text = ai.text

    parsed = parse_json_object(text) or {
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
        "elapsed": elapsed,
        **ai.meta(),
    }


class DeepAnalysisRequest(BaseModel):
    target: str = Field(max_length=320)
    dns: Optional[dict] = None
    whois: Optional[dict] = None
    ssl: Optional[dict] = None
    headers: Optional[dict] = None
    subdomains: Optional[dict] = None
    asn: Optional[dict] = None
    portscan: Optional[dict] = None
    asn_detail: Optional[dict] = None
    shodan: Optional[dict] = None
    email_posture: Optional[dict] = None
    dns_depth: Optional[dict] = None
    takeover: Optional[dict] = None
    lookalikes: Optional[dict] = None
    wellknown: Optional[dict] = None


@router.post("/deep")
async def deep_analysis(req: DeepAnalysisRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    bucket = "deepdive"

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
            port_strs = [f"{p.get('port', '?')}/{p.get('transport','tcp')}" if isinstance(p, dict) else f"{p}/tcp" for p in ports[:15]]
            parts.append(f"services: {', '.join(port_strs)}")
        vulns = s.get("vulns", [])
        if vulns:
            parts.append(f"CVEs: {', '.join(vulns[:10])}")
        if parts:
            prompt_parts.append(f"Shodan: {', '.join(parts)}")

    prompt_parts.extend(extra_recon_lines(req))
    recon_data = "\n".join(prompt_parts)

    t0 = time.time()

    ai = await run_ai(
        request, x_api_key, x_ai_provider, bucket,
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
    text = ai.text

    return {
        "summary": text,
        "elapsed": elapsed,
        **ai.meta(),
    }


class CorrelateRequest(BaseModel):
    targets: dict  # { "target_name": { sherlock: ..., github: ..., ... }, ... }


def _summarize_target_data(target: str, data: dict) -> str:
    """Build a concise text summary of one target's scan results."""
    parts = [f"\n[TARGET: {target}]"]

    if data.get("sherlock") and data["sherlock"].get("results"):
        results = data["sherlock"]["results"]
        hits = [r["site"] for r in results if r.get("confidence") != "false_positive"]
        if hits:
            parts.append(f"  Username enumeration, unverified ({len(hits)} sites): {', '.join(hits[:25])}")

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
        parts.append(f"  Breaches: {', '.join(_breach_names(data['hibp'], 15))}")

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
            parts.append(f"  Platform URL probe answered 200 (weak signal): {', '.join(found)}")

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
    bucket = "analysis"

    if len(req.targets) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 targets to correlate")

    target_summaries = []
    for target_name, data in req.targets.items():
        target_summaries.append(_summarize_target_data(target_name, data))

    combined_data = "\n".join(target_summaries)
    target_list = ", ".join(req.targets.keys())

    t0 = time.time()

    ai = await run_ai(
        request, x_api_key, x_ai_provider, bucket,
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
    text = ai.text

    return {
        "summary": text,
        "elapsed": elapsed,
        **ai.meta(),
    }
