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
import time

router = APIRouter()


class DomainRequest(BaseModel):
    domain: str


class AsnRequest(BaseModel):
    asn_number: int


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


@router.post("/summarize")
async def recon_summarize(req: ReconAnalyzeRequest, x_api_key: str = Header(...)):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is required")

    prompt_parts = [f"Target domain/IP: {req.target}\n"]

    if req.dns and req.dns.get("records"):
        for rtype, records in req.dns["records"].items():
            prompt_parts.append(f"DNS {rtype} records: {', '.join(records[:10])}")

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
                    "You are an infrastructure security analyst. Based on the recon data below, produce this exact structure:\n\n"
                    "**Attack Surface Summary**\n"
                    "Brief overview of the target's external footprint, hosting, and exposure.\n\n"
                    "**Misconfigurations & Weaknesses**\n"
                    "→ Flag missing security headers, expiring certs, open sensitive ports, exposed services\n"
                    "→ Note any information leakage from headers, DNS, or WHOIS\n\n"
                    "**Interesting Findings**\n"
                    "→ Notable subdomains (dev, staging, admin panels)\n"
                    "→ Technology stack inferences from headers/certs/DNS\n"
                    "→ Hosting provider and CDN details\n\n"
                    "**Red Team Next Steps**\n"
                    "→ 3-5 specific actionable next steps for further reconnaissance or testing\n"
                    "→ Suggest tools and techniques for each step\n\n"
                    "Use **bold** for emphasis. Use → prefix for all action items. "
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
