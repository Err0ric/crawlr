from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel, Field
from typing import Optional
from core import validate
from core.ai_call import run_ai
from core.ai_text import summary_and_report
from core.dnspool import dns_thread
from modules.dns_lookup import run_dns
from modules.whois_lookup import run_whois
from modules.ssl_check import run_ssl
from modules.headers_check import run_headers
from modules.subdomain_enum import run_subdomains
from modules.asn_lookup import run_asn
from modules.asn_detail import run_asn_detail
from modules.port_scan import run_portscan
from modules.wayback import run_wayback
from modules.redirect_chain import run_redirect_chain
from modules.tech_fingerprint import run_tech_fingerprint
from modules.email_posture import run_email_posture
from modules.dns_depth import run_dns_depth
from modules.takeover import resolution_state, run_takeover
from modules.lookalikes import run_lookalikes
from modules.wellknown import run_wellknown
import asyncio
import httpx
import time

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str = Field(max_length=320)


class AsnRequest(BaseModel):
    asn_number: int


class IpAsnRequest(BaseModel):
    ips: list[str] = Field(max_length=200)


class ReconAnalyzeRequest(BaseModel):
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


@router.post("/dns")
async def dns_scan(req: DomainRequest):
    domain = validate.host(req.domain, allow_ip=False)
    return await run_dns(domain)


@router.post("/whois")
async def whois_scan(req: DomainRequest):
    domain = validate.host(req.domain, allow_ip=False)
    return await run_whois(domain)


@router.post("/ssl")
async def ssl_scan(req: DomainRequest):
    domain = validate.host(req.domain)
    return await run_ssl(domain)


@router.post("/headers")
async def headers_scan(req: DomainRequest):
    domain = validate.host(req.domain)
    return await run_headers(domain)


MAX_RECHECK = 60       # names rechecked per run: at most 6 queries each, on the shared DNS pool


async def confirm_not_resolving(result: dict) -> dict:
    """Recheck the certificate names the subdomain scan could not resolve.

    The scan resolves names in bulk through the system resolver and treats every failure as
    "no address", and it never looks up the apex domain at all. Neither is evidence that a
    name is gone. Each name is asked again with the strict test from modules.takeover: only
    a definite "does not exist" from two public resolvers keeps it in `not_resolving`.
    Names whose lookup failed move to `resolution_unknown`; names that resolve are dropped."""
    summary = result.get("ct_summary") if isinstance(result, dict) else None
    names = (summary or {}).get("not_resolving") or []
    if not names:
        return result
    # Bulk DNS goes through the shared pool (core.dnspool), never the default executor.
    # Names past the cap are not looked up, so nothing is claimed about them.
    names, skipped = names[:MAX_RECHECK], names[MAX_RECHECK:]
    states = await asyncio.gather(*(dns_thread(resolution_state, n) for n in names))
    summary["not_resolving"] = [n for n, s in zip(names, states) if s == "absent"]
    summary["resolution_unknown"] = [n for n, s in zip(names, states) if s == "unknown"] + skipped
    return result


def resolving_hosts(req) -> set[str]:
    """Hostnames that another check in the same request saw resolving: the target when DNS
    returned address records for it, and every subdomain that came back with an address."""
    clean = lambda v: str(v or "").strip().lower().rstrip(".")
    out: set[str] = set()
    dns_data = getattr(req, "dns", None)
    if isinstance(dns_data, dict) and not dns_data.get("error"):
        records = dns_data.get("records") or {}
        if isinstance(records, dict) and any(records.get(t) for t in ("A", "AAAA")):
            out.add(clean(dns_data.get("domain") or getattr(req, "target", "")))
    subs = getattr(req, "subdomains", None)
    if isinstance(subs, dict) and not subs.get("error"):
        for row in subs.get("subdomains") or []:
            if isinstance(row, dict) and row.get("ips"):
                out.add(clean(row.get("subdomain")))
    out.discard("")
    return out


@router.post("/subdomains")
async def subdomains_scan(req: DomainRequest):
    domain = validate.host(req.domain, allow_ip=False)
    return await confirm_not_resolving(await run_subdomains(domain))


@router.post("/asn")
async def asn_scan(req: DomainRequest):
    domain = validate.host(req.domain)
    return await run_asn(domain)


@router.post("/portscan")
async def portscan_scan(req: DomainRequest):
    domain = validate.host(req.domain)
    return await run_portscan(domain)


@router.post("/asn-detail")
async def asn_detail_scan(req: AsnRequest):
    if req.asn_number < 1:
        raise HTTPException(status_code=400, detail="Invalid ASN number")
    return await run_asn_detail(req.asn_number)


@router.post("/ip-asn")
async def batch_ip_asn(req: IpAsnRequest):
    """Batch resolve IPs to ASN/org via RIPE stat."""
    ips = sorted({ip.strip() for ip in req.ips if validate.is_ip(ip.strip())})[:30]
    results: dict[str, dict] = {}
    org_cache: dict[str, str] = {}

    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
        async def one(ip: str):
            results[ip] = {"asn": "", "org": ""}
            try:
                resp = await client.get("https://stat.ripe.net/data/network-info/data.json", params={"resource": ip})
                if resp.status_code != 200:
                    return
                asns = resp.json().get("data", {}).get("asns", [])
                if not asns:
                    return
                num = str(asns[0])
                results[ip]["asn"] = f"AS{num}"
                if num not in org_cache:
                    org_cache[num] = ""
                    rdap = await client.get(f"https://rdap.arin.net/registry/autnum/{int(num)}", headers={"Accept": "application/rdap+json"})
                    if rdap.status_code == 200:
                        org_cache[num] = rdap.json().get("name", "")
                results[ip]["org"] = org_cache[num]
            except Exception:
                pass

        await asyncio.gather(*(one(ip) for ip in ips))
        for ip, r in results.items():   # fill orgs resolved after a sibling task read the cache
            if r["asn"] and not r["org"]:
                r["org"] = org_cache.get(r["asn"][2:], "")
    return {"results": results}


class TargetRequest(BaseModel):
    target: str = Field(max_length=2000)


@router.post("/wayback")
async def wayback_scan(req: DomainRequest):
    domain = validate.host(req.domain, allow_ip=False)
    return await run_wayback(domain)


@router.post("/redirects")
async def redirect_scan(req: TargetRequest):
    return await run_redirect_chain(validate.http_url(req.target))


@router.post("/techfingerprint")
async def tech_fingerprint_scan(req: DomainRequest):
    domain = validate.host(req.domain)
    return await run_tech_fingerprint(domain)


def extra_recon_lines(req) -> list[str]:
    """Prompt lines for the newer recon checks. Only sources that ran without failing are used."""
    ok = lambda d: isinstance(d, dict) and not d.get("error")
    lines: list[str] = []
    ep = getattr(req, "email_posture", None)
    if ok(ep):
        issues = [f["title"] for f in ep.get("findings", []) if f.get("level") == "flag"]
        if ep.get("mail_enabled") is False:
            lines.append(
                "Email: the domain has no MX records, so it does not appear to send or receive mail. Missing SPF or DMARC "
                "here is a hardening note (publish the null records), not a finding." + (f" Issues: {'; '.join(issues[:6])}" if issues else "")
            )
        else:
            lines.append(f"Email security: grade {ep.get('grade', '?')}, spoofable: {ep.get('spoofable', '?')}" + (f". Issues: {'; '.join(issues[:6])}" if issues else ""))
    dd = getattr(req, "dns_depth", None)
    if ok(dd):
        lines.append(
            f"DNS: DNSSEC {'enabled' if dd.get('dnssec', {}).get('signed') and dd.get('dnssec', {}).get('ds') else 'not enabled'}, "
            f"CAA {'present' if dd.get('caa') else 'absent'}, wildcard DNS {'yes' if dd.get('wildcard', {}).get('present') else 'no'}"
        )
    tk = getattr(req, "takeover", None)
    if ok(tk) and tk.get("candidates"):
        # A candidate whose lookup failed says nothing either way, so it is left out. So is a
        # "dangling" one that another check in this same run saw resolving: the two answers
        # contradict each other, and the prompt must not assert what the screen withholds.
        live = resolving_hosts(req)
        rows = [f"{c['host']} -> {c['cname']} ({c['service']}, {c['status']})" for c in tk["candidates"]
                if isinstance(c, dict) and c.get("status") != "unknown"
                and not (c.get("status") == "dangling" and str(c.get("host") or "").strip().lower().rstrip(".") in live)][:10]
        if rows:
            lines.append(f"Subdomain takeover candidates (DNS only, unverified): {'; '.join(rows)}")
    la = getattr(req, "lookalikes", None)
    if ok(la) and la.get("results"):
        rows = [f"{r['domain']}{' (receives mail)' if r.get('mail') else ''}" for r in la["results"][:15]]
        lines.append(f"Registered lookalike domains ({la.get('registered', len(rows))}, not proof of abuse): {', '.join(rows)}")
    wk = getattr(req, "wellknown", None)
    if ok(wk):
        if wk.get("security_txt"):
            lines.append(f"security.txt present, contact: {', '.join(wk['security_txt'].get('contact', [])[:3])}")
        elif wk.get("found"):
            lines.append("No security.txt published")
        if (wk.get("robots") or {}).get("interesting"):
            lines.append(f"robots.txt disallows: {', '.join(wk['robots']['interesting'][:15])}")
    return lines


@router.post("/email-posture")
async def email_posture_scan(req: DomainRequest):
    """SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI from DNS. Does not contact mail servers."""
    return await run_email_posture(validate.host(req.domain, allow_ip=False))


@router.post("/dns-depth")
async def dns_depth_scan(req: DomainRequest):
    """CAA, DNSSEC, wildcard detection and reverse DNS."""
    return await run_dns_depth(validate.host(req.domain, allow_ip=False))


class TakeoverRequest(BaseModel):
    domain: str = Field(max_length=320)
    hosts: list[str] = Field(max_length=400)
    # CNAME targets of the zone's wildcard record, from the subdomain check. A host that only
    # repeats the wildcard is not a candidate of its own.
    wildcard_cnames: list[str] = Field(default_factory=list, max_length=8)


@router.post("/takeover")
async def takeover_scan(req: TakeoverRequest):
    """Subdomains whose CNAME points at a claimable cloud service. DNS only."""
    return await run_takeover(validate.host(req.domain, allow_ip=False), [h[:260] for h in req.hosts], [c[:260] for c in req.wildcard_cnames])


@router.post("/lookalikes")
async def lookalikes_scan(req: DomainRequest):
    """Registered typo and lookalike variants of the domain. DNS only."""
    return await run_lookalikes(validate.host(req.domain, allow_ip=False))


@router.post("/wellknown")
async def wellknown_scan(req: DomainRequest):
    """security.txt, robots.txt and the favicon hash. Three requests to the target's web server."""
    return await run_wellknown(validate.host(req.domain))


def wildcard_lines(req) -> list[str]:
    """Prompt lines about a wildcard DNS record found by the subdomain check. The subdomain
    list that follows holds real names only, so the model is told what was left out and why."""
    subs = getattr(req, "subdomains", None)
    if not isinstance(subs, dict) or subs.get("error") or not isinstance(subs.get("wildcard"), dict):
        return []
    w = subs["wildcard"]
    names = lambda key, n: [str(x)[:260] for x in (w.get(key) or []) if isinstance(x, str)][:n]
    lines = []
    if w.get("state") == "yes":
        target = ", ".join(names("cnames", 2)) or ", ".join(names("ips", 4)) or "the same answer"
        provider = w.get("provider") if isinstance(w.get("provider"), dict) else None
        try:
            left = int(w.get("suppressed") or 0)
        except (TypeError, ValueError):
            left = 0
        lines.append(
            f"WILDCARD DNS: every name under {subs.get('domain') or req.target} resolves to {target}"
            + (f" ({str(provider.get('name'))[:60]}, a third-party {str(provider.get('kind'))[:60]})" if provider and provider.get("name") else "")
            + f". A name that resolves is not proof that a host exists. {left} guessed names that only matched the wildcard were left out "
            "and are not hosts. Do not infer mail, DNS, API or admin servers from names that are not listed below."
        )
        if w.get("service") and w.get("target_state") == "absent":
            lines.append(f"The wildcard's CNAME target ({target}, {str(w['service'])[:60]}) does not resolve: one possible takeover that covers every name, unverified.")
    elif w.get("state") == "unknown":
        lines.append("Wildcard DNS could not be checked (the test lookups failed), so some guessed subdomains below may not be real hosts.")
    for p in [p for p in (w.get("parents") or []) if isinstance(p, dict)][:5]:
        lines.append(f"Wildcard DNS one level down: every name under {str(p.get('parent'))[:260]} resolves alike.")
    return lines


def recon_prompt(req: ReconAnalyzeRequest) -> str:
    """The full prompt for a recon summary. Shared by the AI endpoint and the keyless copy path."""

    prompt_parts = [f"Target domain/IP: {req.target}\n"]
    failed = [name for name in ("dns", "whois", "ssl", "headers", "subdomains", "asn", "portscan", "asn_detail", "shodan", "email_posture", "dns_depth", "takeover", "lookalikes", "wellknown")
              if isinstance(getattr(req, name), dict) and getattr(req, name).get("error")]
    if failed:
        prompt_parts.append(
            f"Checks that FAILED and returned no data: {', '.join(failed)}. Treat them as unknown: "
            "a failed check is not evidence that something is absent, closed or safe."
        )

    if req.dns and req.dns.get("records"):
        for rtype, records in req.dns["records"].items():
            prompt_parts.append(f"DNS {rtype} records: {', '.join(records[:10])}")
        if req.dns.get("cloudflare_proxied"):
            prompt_parts.append(
                "CLOUDFLARE PROXY DETECTED: The domain's A records resolve to Cloudflare IPs. "
                "The true origin server IP is hidden behind Cloudflare's reverse proxy. "
                "HTTP headers and open ports reflect Cloudflare's edge, not the origin. "
                "Consider origin IP discovery techniques: historical DNS records (SecurityTrails, ViewDNS), "
                "MX/mail server IPs, Shodan/Censys searches for the domain's SSL cert, "
                "unproxied subdomain enumeration, and DNS misconfigurations."
            )

    if req.whois and req.whois.get("found"):
        w = req.whois
        parts = []
        if w.get("registrar"):
            parts.append(f"registrar: {w['registrar']}")
        if w.get("creation_date"):
            parts.append(f"created: {w['creation_date']}")
        if w.get("expiration_date"):
            parts.append(f"expires: {w['expiration_date']}")
        if w.get("org"):
            parts.append(f"org: {w['org']}")
        if w.get("country"):
            parts.append(f"country: {w['country']}")
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
        prompt_parts.append(f"SSL Certificate: {', '.join(parts)}")

    if req.headers and req.headers.get("found"):
        h = req.headers
        prompt_parts.append(f"HTTP server: {h.get('server', 'unknown')}, security grade: {h.get('grade', '?')}")
        sec = h.get("security_headers", {})
        missing = [k for k, v in sec.items() if not v.get("present")]
        present = [k for k, v in sec.items() if v.get("present")]
        if present:
            prompt_parts.append(f"Security headers present: {', '.join(present)}")
        if missing:
            prompt_parts.append(f"Security headers MISSING: {', '.join(missing)}")

    prompt_parts.extend(wildcard_lines(req))
    if req.subdomains and req.subdomains.get("subdomains"):
        subs = req.subdomains["subdomains"]
        dns_subs = [s["subdomain"] for s in subs if s.get("source") in ("DNS", "DNS+CT")]
        ct_subs = [s["subdomain"] for s in subs if s.get("source") in ("CT", "DNS+CT")]
        # A name kept in a wildcard zone because a certificate or a DNS record attests it says so.
        all_names = [s["subdomain"] + (" (resolves only through the wildcard)" if s.get("via_wildcard") else "") for s in subs]
        prompt_parts.append(
            f"Subdomains found ({len(all_names)}): {', '.join(all_names[:20])}"
            + (f" (and {len(all_names)-20} more)" if len(all_names) > 20 else "")
        )
        if ct_subs:
            prompt_parts.append(f"CT log subdomains ({len(ct_subs)}): {', '.join(ct_subs[:15])}")

    if req.asn and req.asn.get("found"):
        a = req.asn
        parts = [f"IP: {a.get('ip', '')}"]
        if a.get("asn"):
            parts.append(f"ASN: {a['asn']}")
        if a.get("org"):
            parts.append(f"org: {a['org']}")
        if a.get("prefixes"):
            parts.append(f"prefixes: {', '.join(a['prefixes'][:5])}")
        prompt_parts.append(f"ASN/BGP: {', '.join(parts)}")

    if req.portscan and not req.portscan.get("error"):
        open_ports = [f"{r['port']}/{r['service']}" for r in (req.portscan.get("results", [])) if r.get("open")]
        if open_ports:
            prompt_parts.append(f"Open ports: {', '.join(open_ports)}")
        else:
            prompt_parts.append("Port scan: no open ports found in top 20")

    if req.asn_detail and req.asn_detail.get("found"):
        ad = req.asn_detail
        parts = [f"ASN: {ad.get('asn', '')}"]
        if ad.get("org"):
            parts.append(f"org: {ad['org']}")
        if ad.get("name"):
            parts.append(f"name: {ad['name']}")
        if ad.get("country"):
            parts.append(f"country: {ad['country']}")
        if ad.get("rir"):
            parts.append(f"RIR: {ad['rir']}")
        if ad.get("date_registered"):
            parts.append(f"registered: {ad['date_registered']}")
        prompt_parts.append(f"ASN Detail: {', '.join(parts)}")
        if ad.get("prefixes_v4"):
            prompt_parts.append(f"IPv4 Prefixes ({len(ad['prefixes_v4'])}): {', '.join(ad['prefixes_v4'][:10])}")
        if ad.get("prefixes_v6"):
            prompt_parts.append(f"IPv6 Prefixes ({len(ad['prefixes_v6'])}): {', '.join(ad['prefixes_v6'][:10])}")
        if ad.get("peers"):
            peer_strs = [f"{p['asn']} ({p['name']})" for p in ad['peers'][:10]]
            prompt_parts.append(f"Peers ({ad.get('total_peers', len(ad['peers']))}): {', '.join(peer_strs)}")

    if req.shodan and not req.shodan.get("error"):
        s = req.shodan
        parts = []
        if s.get("ip"):
            parts.append(f"IP: {s['ip']}")
        if s.get("org"):
            parts.append(f"org: {s['org']}")
        if s.get("os"):
            parts.append(f"OS: {s['os']}")
        if s.get("isp"):
            parts.append(f"ISP: {s['isp']}")
        ports = s.get("ports", [])
        if ports:
            port_strs = []
            for p in ports[:15]:
                # InternetDB lists bare port numbers; full Shodan lists objects with a product.
                if not isinstance(p, dict):
                    port_strs.append(f"{p}/tcp")
                    continue
                svc = f"{p.get('port', '?')}/{p.get('transport','tcp')}"
                if p.get("product"):
                    svc += f" ({p['product']}"
                    if p.get("version"):
                        svc += f" {p['version']}"
                    svc += ")"
                port_strs.append(svc)
            parts.append(f"services: {', '.join(port_strs)}")
        vulns = s.get("vulns", [])
        if vulns:
            parts.append(f"CVEs: {', '.join(vulns[:10])}")
        if parts:
            prompt_parts.append(f"Shodan: {', '.join(parts)}")
        shared = s.get("shared_host")
        if isinstance(shared, dict) and shared.get("provider"):
            prompt_parts.append(
                f"SHARED HOSTING: this IP is a shared {shared['provider']} edge used by many unrelated sites. "
                f"The ports, software and CVEs above belong to {shared['provider']}, not to the target's own servers, "
                "and other hostnames seen on this IP are unrelated tenants. Do not report them as the target's exposure."
            )

    prompt_parts.extend(extra_recon_lines(req))
    recon_data = "\n".join(prompt_parts)

    return (
        "You are an infrastructure security analyst. Based on the recon data below, respond with ONLY valid JSON (no markdown fencing, no extra text) with exactly two keys:\n\n"
        '{\n'
        '  "short_summary": ["bullet 1", "bullet 2", "bullet 3", "bullet 4"],\n'
        '  "full_report": "markdown string"\n'
        '}\n\n'
        "**short_summary**: Exactly 4 bullet strings. STRICT RULES:\n"
        "- Each bullet starts with a category label followed by a dash (e.g. 'Missing Headers –', 'Open Ports –', 'SSL Risk –')\n"
        "- Maximum 15 words per bullet\n"
        "- Every bullet MUST reference specific data from the scan (actual port numbers, header names, subdomain names, CVE IDs, IP addresses)\n"
        "- NO generic observations. Bad: 'Several security headers missing'. Good: 'Missing Headers – no CSP, X-Frame-Options, or HSTS detected'\n"
        "- Plain text only, no markdown\n\n"
        "**full_report**: A markdown string with this structure:\n\n"
        "## Attack Surface Summary\n"
        "Brief overview of the target's external footprint, hosting, and exposure.\n\n"
        "## Key Findings\n"
        "→ Misconfigurations, missing security headers, expiring certs, open sensitive ports\n"
        "→ Notable subdomains (dev, staging, admin panels)\n"
        "→ Technology stack inferences, hosting provider and CDN details\n"
        "→ Information leakage from headers, DNS, or WHOIS\n\n"
        "## Recommendations\n"
        "→ 3-5 specific actionable next steps for further reconnaissance or testing\n"
        "→ Suggest tools and techniques for each step\n\n"
        "Use **bold** for emphasis in the full_report. Use → prefix for action items. "
        "Keep it concise and actionable.\n\n"
        f"Recon data:\n{recon_data}"
    )


@router.post("/prompt")
async def recon_prompt_only(req: ReconAnalyzeRequest):
    """Returns the prompt without calling any model. No key and no quota."""
    return {"prompt": recon_prompt(req)}


@router.post("/summarize")
async def recon_summarize(req: ReconAnalyzeRequest, request: Request, x_api_key: str | None = Header(default=None), x_ai_provider: str = Header(default="anthropic")):
    t0 = time.time()

    ai = await run_ai(
        request, x_api_key, x_ai_provider, "analysis",
        max_tokens=2048,
        messages=[{"role": "user", "content": recon_prompt(req)}],
    )

    elapsed = round(time.time() - t0, 1)
    short_summary, full_report = summary_and_report(ai.text)

    return {
        "summary": full_report,
        "short_summary": short_summary,
        "elapsed": elapsed,
        **ai.meta(),
    }
