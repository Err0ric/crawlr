from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional
from modules.dns_lookup import run_dns
from modules.whois_lookup import run_whois
from modules.ssl_check import run_ssl
from modules.headers_check import run_headers
from modules.subdomain_enum import run_subdomains
from modules.asn_lookup import run_asn
from modules.asn_detail import run_asn_detail
from modules.port_scan import run_portscan
import anthropic
import httpx
import json
import time

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str


class AsnRequest(BaseModel):
    asn_number: int


class IpAsnRequest(BaseModel):
    ips: list[str]


class ReconAnalyzeRequest(BaseModel):
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


@router.post("/dns")
async def dns_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_dns(domain)


@router.post("/whois")
async def whois_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_whois(domain)


@router.post("/ssl")
async def ssl_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_ssl(domain)


@router.post("/headers")
async def headers_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_headers(domain)


@router.post("/subdomains")
async def subdomains_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_subdomains(domain)


@router.post("/asn")
async def asn_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_asn(domain)


@router.post("/portscan")
async def portscan_scan(req: DomainRequest):
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    return await run_portscan(domain)


@router.post("/asn-detail")
async def asn_detail_scan(req: AsnRequest):
    if req.asn_number < 1:
        raise HTTPException(status_code=400, detail="Invalid ASN number")
    return await run_asn_detail(req.asn_number)


@router.post("/ip-asn")
async def batch_ip_asn(req: IpAsnRequest):
    """Batch resolve IPs to ASN/org via RIPE stat."""
    ips = list(set(ip.strip() for ip in req.ips if ip.strip()))[:30]
    results = {}
    async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
        for ip in ips:
            try:
                resp = await client.get(
                    f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    asns = data.get("asns", [])
                    asn = f"AS{asns[0]}" if asns else ""
                    results[ip] = {"asn": asn, "org": ""}
                    if asn:
                        try:
                            asn_num = asn.replace("AS", "")
                            rdap = await client.get(
                                f"https://rdap.arin.net/registry/autnum/{asn_num}",
                                headers={"Accept": "application/rdap+json"},
                            )
                            if rdap.status_code == 200:
                                results[ip]["org"] = rdap.json().get("name", "")
                        except Exception:
                            pass
                else:
                    results[ip] = {"asn": "", "org": ""}
            except Exception:
                results[ip] = {"asn": "", "org": ""}
    return {"results": results}


@router.post("/summarize")
async def recon_summarize(req: ReconAnalyzeRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    prompt_parts = [f"Target domain/IP: {req.target}\n"]

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

    if req.subdomains and req.subdomains.get("subdomains"):
        subs = req.subdomains["subdomains"]
        dns_subs = [s["subdomain"] for s in subs if s.get("source") in ("DNS", "DNS+CT")]
        ct_subs = [s["subdomain"] for s in subs if s.get("source") in ("CT", "DNS+CT")]
        all_names = [s["subdomain"] for s in subs]
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

    if req.portscan:
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
                svc = f"{p['port']}/{p.get('transport','tcp')}"
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

    recon_data = "\n".join(prompt_parts)

    client = anthropic.Anthropic(api_key=x_api_key)
    t0 = time.time()

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
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
                ),
            }
        ],
    )

    elapsed = round(time.time() - t0, 1)
    text = message.content[0].text
    tokens = message.usage.input_tokens + message.usage.output_tokens

    try:
        parsed = json.loads(text)
        short_summary = parsed.get("short_summary", [])
        full_report = parsed.get("full_report", text)
    except (json.JSONDecodeError, KeyError):
        full_report = text
        lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]
        short_summary = lines[:3]

    return {
        "summary": full_report,
        "short_summary": short_summary,
        "model": message.model,
        "tokens": tokens,
        "elapsed": elapsed,
    }
