from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import re
import email
import email.utils
from datetime import datetime, timezone
from typing import Optional
import httpx

router = APIRouter()


class HeaderRequest(BaseModel):
    headers: str


def parse_received_chain(raw: str) -> list[dict]:
    """Parse Received headers into a hop chain with timestamps and IPs."""
    msg = email.message_from_string(raw)
    received_headers = msg.get_all("Received", [])
    hops = []

    ip_re = re.compile(
        r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        r'|\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)'
        r'|from\s+\S+\s+\((?:\S+\s+)?\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?\)'
    )
    domain_from_re = re.compile(r'from\s+([\w.\-]+)', re.IGNORECASE)
    domain_by_re = re.compile(r'by\s+([\w.\-]+)', re.IGNORECASE)
    date_re = re.compile(r';\s*(.+)$')

    for i, hdr in enumerate(received_headers):
        hdr_clean = " ".join(hdr.split())
        hop = {"raw": hdr_clean, "hop": len(received_headers) - i}

        # Extract IPs
        ips = []
        for match in ip_re.finditer(hdr_clean):
            ip = match.group(1) or match.group(2) or match.group(3)
            if ip:
                ips.append(ip)
        hop["ips"] = ips

        # Extract from/by domains
        from_m = domain_from_re.search(hdr_clean)
        by_m = domain_by_re.search(hdr_clean)
        if from_m:
            hop["from"] = from_m.group(1)
        if by_m:
            hop["by"] = by_m.group(1)

        # Extract timestamp
        date_m = date_re.search(hdr_clean)
        if date_m:
            try:
                parsed = email.utils.parsedate_to_datetime(date_m.group(1).strip())
                hop["timestamp"] = parsed.isoformat()
                hop["_dt"] = parsed
            except Exception:
                pass

        hops.append(hop)

    # Calculate delays between hops
    hops.reverse()  # oldest first
    for i in range(1, len(hops)):
        if "_dt" in hops[i] and "_dt" in hops[i - 1]:
            delay = (hops[i]["_dt"] - hops[i - 1]["_dt"]).total_seconds()
            hops[i]["delay_seconds"] = round(delay, 1)

    # Clean internal _dt
    for h in hops:
        h.pop("_dt", None)

    return hops


def parse_auth_results(raw: str) -> dict:
    """Extract SPF, DKIM, and DMARC authentication results."""
    msg = email.message_from_string(raw)
    auth = {"spf": None, "dkim": None, "dmarc": None}

    # Check Authentication-Results header
    auth_results = msg.get_all("Authentication-Results", [])
    for ar in auth_results:
        ar_lower = ar.lower()
        if "spf=" in ar_lower:
            m = re.search(r'spf=(\w+)', ar_lower)
            if m:
                auth["spf"] = m.group(1)
        if "dkim=" in ar_lower:
            m = re.search(r'dkim=(\w+)', ar_lower)
            if m:
                auth["dkim"] = m.group(1)
        if "dmarc=" in ar_lower:
            m = re.search(r'dmarc=(\w+)', ar_lower)
            if m:
                auth["dmarc"] = m.group(1)

    # Fallback: check individual headers
    if not auth["spf"]:
        spf_header = msg.get("Received-SPF", "")
        m = re.search(r'^(pass|fail|softfail|neutral|none|temperror|permerror)', spf_header.lower())
        if m:
            auth["spf"] = m.group(1)

    if not auth["dkim"]:
        dkim_sig = msg.get("DKIM-Signature", "")
        if dkim_sig:
            auth["dkim"] = "present"

    return auth


def extract_key_headers(raw: str) -> dict:
    """Extract important headers for analysis."""
    msg = email.message_from_string(raw)
    headers = {}

    key_fields = [
        "From", "To", "Subject", "Date", "Reply-To", "Return-Path",
        "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP",
        "X-Sender-IP", "X-Source-IP", "X-Spam-Status", "X-Spam-Score",
        "X-Spam-Flag", "X-MS-Exchange-Organization-SCL",
        "X-Google-DKIM-Signature", "ARC-Authentication-Results",
        "Content-Type", "MIME-Version", "X-Priority",
        "X-Forefront-Antispam-Report", "X-Microsoft-Antispam",
    ]

    for field in key_fields:
        val = msg.get(field)
        if val:
            headers[field] = " ".join(val.split())

    return headers


def _is_private_ip(ip: str) -> bool:
    """Check if an IP is private/reserved."""
    if ip.startswith(("10.", "192.168.", "127.", "0.")):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) == 4:
            try:
                if 16 <= int(parts[1]) <= 31:
                    return True
            except ValueError:
                pass
    return False


def detect_anomalies(raw: str, key_headers: dict, auth: dict, ip_geo: dict, hops: list) -> list[dict]:
    """Detect potential spoofing and suspicious indicators."""
    anomalies = []

    # Parse From header into display name and email address
    from_header = key_headers.get("From", "")
    from_addr = ""
    from_display = ""
    if from_header:
        m = re.search(r'[\w.\-+]+@[\w.\-]+', from_header)
        if m:
            from_addr = m.group(0).lower()
        # Extract display name (text before <email>)
        dm = re.match(r'^"?([^"<]+)"?\s*<', from_header)
        if dm:
            from_display = dm.group(1).strip().strip('"')

    # 1. Display name vs email address mismatch
    if from_display and from_addr:
        # Check if display name contains an email that differs from actual address
        display_email_m = re.search(r'[\w.\-+]+@[\w.\-]+', from_display)
        if display_email_m:
            display_email = display_email_m.group(0).lower()
            if display_email != from_addr:
                anomalies.append({
                    "severity": "high",
                    "type": "display_name_email_spoof",
                    "detail": f"Display name contains email '{display_email}' but actual sender is '{from_addr}'. Classic spoofing technique.",
                })
        # Check if display name looks like a well-known company but domain doesn't match
        known_brands = {
            "paypal": "paypal.com", "google": "google.com", "apple": "apple.com",
            "microsoft": "microsoft.com", "amazon": "amazon.com", "netflix": "netflix.com",
            "facebook": "facebook.com", "meta": "meta.com", "instagram": "instagram.com",
            "twitter": "twitter.com", "linkedin": "linkedin.com", "bank": None,
            "wells fargo": "wellsfargo.com", "chase": "chase.com",
        }
        display_lower = from_display.lower()
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        for brand, expected_domain in known_brands.items():
            if brand in display_lower:
                if expected_domain and expected_domain not in from_domain:
                    anomalies.append({
                        "severity": "high",
                        "type": "brand_impersonation",
                        "detail": f"Display name mentions '{brand}' but email domain is '{from_domain}', not '{expected_domain}'.",
                    })
                    break

    # 2. Envelope vs header From mismatch
    return_path = key_headers.get("Return-Path", "").strip("<>").lower()
    if return_path and from_addr and return_path != from_addr:
        rp_domain = return_path.split("@")[-1] if "@" in return_path else ""
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        if rp_domain and from_domain and rp_domain != from_domain:
            anomalies.append({
                "severity": "high",
                "type": "envelope_mismatch",
                "detail": f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain}). Possible spoofing.",
            })

    # 3. Reply-To mismatch
    reply_to = key_headers.get("Reply-To", "")
    if reply_to and from_addr:
        m = re.search(r'[\w.\-+]+@[\w.\-]+', reply_to)
        if m:
            reply_addr = m.group(0).lower()
            if reply_addr.split("@")[-1] != from_addr.split("@")[-1]:
                anomalies.append({
                    "severity": "medium",
                    "type": "reply_to_mismatch",
                    "detail": f"Reply-To ({reply_addr}) domain differs from From ({from_addr}). Replies go to a different domain.",
                })

    # 4. Auth failures
    if auth.get("spf") in ("fail", "softfail"):
        anomalies.append({
            "severity": "high",
            "type": "spf_fail",
            "detail": f"SPF check {auth['spf']}. Sender IP not authorized for this domain.",
        })
    if auth.get("dkim") in ("fail",):
        anomalies.append({
            "severity": "high",
            "type": "dkim_fail",
            "detail": "DKIM signature verification failed. Message may have been tampered with.",
        })
    if auth.get("dmarc") in ("fail",):
        anomalies.append({
            "severity": "high",
            "type": "dmarc_fail",
            "detail": "DMARC check failed. Both SPF and DKIM alignment failed.",
        })

    # 5. X-Spam flags
    spam_status = key_headers.get("X-Spam-Status", "").lower()
    spam_flag = key_headers.get("X-Spam-Flag", "").lower()
    if "yes" in spam_status or "yes" in spam_flag:
        anomalies.append({
            "severity": "medium",
            "type": "spam_flagged",
            "detail": "Email was flagged as spam by the receiving server.",
        })

    # 6. X-Originating-IP present (webmail)
    orig_ip = key_headers.get("X-Originating-IP", "")
    if orig_ip:
        anomalies.append({
            "severity": "info",
            "type": "originating_ip",
            "detail": f"Sender's IP exposed via X-Originating-IP: {orig_ip}",
        })

    # 7. No authentication at all
    if not auth.get("spf") and not auth.get("dkim") and not auth.get("dmarc"):
        anomalies.append({
            "severity": "medium",
            "type": "no_auth",
            "detail": "No SPF, DKIM, or DMARC results found. Cannot verify sender authenticity.",
        })

    # 8. Sending IP doesn't match claimed domain (check first hop's country vs expected)
    if from_addr and ip_geo:
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
        # Check first public IP in hops
        for hop in hops:
            for ip in hop.get("ips", []):
                if not _is_private_ip(ip) and ip in ip_geo:
                    geo = ip_geo[ip]
                    hop["geo"] = geo  # Annotate hop with geo for frontend
                    break

    # 9. Unusual hop delays (> 5 minutes between hops)
    for hop in hops:
        delay = hop.get("delay_seconds")
        if delay is not None and delay > 300:
            anomalies.append({
                "severity": "medium",
                "type": "unusual_delay",
                "detail": f"Hop {hop['hop']} had a {round(delay/60, 1)} minute delay. May indicate greylisting, spam filtering, or relay issues.",
            })

    # 10. Negative delay (time travel = clock skew or manipulation)
    for hop in hops:
        delay = hop.get("delay_seconds")
        if delay is not None and delay < -60:
            anomalies.append({
                "severity": "medium",
                "type": "time_anomaly",
                "detail": f"Hop {hop['hop']} shows negative delay ({round(delay)}s). Clock skew between servers or possible header manipulation.",
            })

    return anomalies


async def geolocate_ips(ips: list[str]) -> dict:
    """Geolocate IPs using free ip-api.com batch endpoint."""
    if not ips:
        return {}

    # Filter to public IPs only
    public_ips = [ip for ip in ips if not _is_private_ip(ip)]
    if not public_ips:
        return {}

    results = {}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(
                "http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,isp,org,as,query",
                json=[{"query": ip} for ip in public_ips[:15]],
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    if entry.get("status") == "success":
                        results[entry["query"]] = {
                            "country": entry.get("country"),
                            "country_code": entry.get("countryCode"),
                            "region": entry.get("regionName"),
                            "city": entry.get("city"),
                            "isp": entry.get("isp"),
                            "org": entry.get("org"),
                            "asn": entry.get("as"),
                        }
        except Exception:
            pass

    return results


@router.post("/analyze")
async def analyze_headers(req: HeaderRequest):
    raw = req.headers.strip()
    if len(raw) < 20:
        raise HTTPException(status_code=400, detail="Headers too short. Paste the full email headers.")

    # Parse everything
    hops = parse_received_chain(raw)
    auth = parse_auth_results(raw)
    key_headers = extract_key_headers(raw)

    # Collect all unique public IPs from hops
    all_ips = []
    for hop in hops:
        for ip in hop.get("ips", []):
            if ip not in all_ips:
                all_ips.append(ip)

    # Also check X-Originating-IP
    orig_ip = key_headers.get("X-Originating-IP", "").strip("[]")
    if orig_ip and re.match(r'\d+\.\d+\.\d+\.\d+', orig_ip) and orig_ip not in all_ips:
        all_ips.append(orig_ip)

    # Geolocate IPs first (anomalies need geo data)
    ip_geo = await geolocate_ips(all_ips)

    # Detect anomalies (now with geo and hop data)
    anomalies = detect_anomalies(raw, key_headers, auth, ip_geo, hops)

    # Calculate total transit time
    total_delay = None
    if len(hops) >= 2 and "timestamp" in hops[0] and "timestamp" in hops[-1]:
        try:
            first = datetime.fromisoformat(hops[0]["timestamp"])
            last = datetime.fromisoformat(hops[-1]["timestamp"])
            total_delay = round((last - first).total_seconds(), 1)
        except Exception:
            pass

    # Determine verdict: LEGITIMATE / SUSPICIOUS / SPOOFED
    high_count = sum(1 for a in anomalies if a["severity"] == "high")
    med_count = sum(1 for a in anomalies if a["severity"] == "medium")

    spoofing_types = {"envelope_mismatch", "display_name_email_spoof", "brand_impersonation"}
    has_spoofing = any(a["type"] in spoofing_types for a in anomalies)
    auth_failed = auth.get("spf") in ("fail",) or auth.get("dmarc") in ("fail",)

    if (has_spoofing and auth_failed) or high_count >= 3:
        verdict = "SPOOFED"
    elif high_count >= 1 or (has_spoofing or auth_failed):
        verdict = "SUSPICIOUS"
    elif med_count >= 2:
        verdict = "SUSPICIOUS"
    elif auth.get("spf") == "pass" and auth.get("dkim") == "pass":
        verdict = "LEGITIMATE"
    elif auth.get("spf") == "pass" or auth.get("dkim") == "pass":
        verdict = "LEGITIMATE"
    else:
        verdict = "SUSPICIOUS"

    # Extract sender info
    sender_ip = orig_ip or None
    if not sender_ip:
        for hop in hops:
            for ip in hop.get("ips", []):
                if not _is_private_ip(ip):
                    sender_ip = ip
                    break
            if sender_ip:
                break

    return {
        "verdict": verdict,
        "hops": hops,
        "total_hops": len(hops),
        "total_delay_seconds": total_delay,
        "authentication": auth,
        "key_headers": key_headers,
        "anomalies": anomalies,
        "ip_geolocation": ip_geo,
        "sender_ip": sender_ip,
    }
