import httpx
import re


SIGNATURES = {
    "cms": {
        "WordPress": [
            lambda h, b, c: "wordpress" in h.get("x-powered-by", "").lower(),
            lambda h, b, c: "wp-content" in b or "wp-json" in b,
        ],
        "Drupal": [
            lambda h, b, c: "drupal" in h.get("x-generator", "").lower(),
            lambda h, b, c: "sites/default/files" in b,
        ],
        "Joomla": [
            lambda h, b, c: "/components/com_" in b,
        ],
        "Shopify": [
            lambda h, b, c: "x-shopid" in h,
            lambda h, b, c: "myshopify.com" in b,
        ],
        "Ghost": [
            lambda h, b, c: "x-ghost-cache" in h,
        ],
        "Squarespace": [
            lambda h, b, c: "static.squarespace.com" in b,
        ],
        "Wix": [
            lambda h, b, c: "x-wix-request-id" in h,
        ],
    },
    "server": {
        "nginx": [lambda h, b, c: "nginx" in h.get("server", "").lower()],
        "Apache": [lambda h, b, c: "apache" in h.get("server", "").lower()],
        "IIS": [lambda h, b, c: "iis" in h.get("server", "").lower()],
        "Caddy": [lambda h, b, c: "caddy" in h.get("server", "").lower()],
        "LiteSpeed": [lambda h, b, c: "litespeed" in h.get("server", "").lower()],
    },
    "language": {
        "PHP": [
            lambda h, b, c: "php" in h.get("x-powered-by", "").lower(),
            lambda h, b, c: "PHPSESSID" in c,
        ],
        "Python": [
            lambda h, b, c: any(
                x in h.get("x-powered-by", "").lower()
                for x in ["python", "django", "flask"]
            ),
        ],
        "Ruby": [
            lambda h, b, c: "phusion passenger" in h.get("x-powered-by", "").lower(),
        ],
        "Node.js": [
            lambda h, b, c: "express" in h.get("x-powered-by", "").lower(),
        ],
    },
    "cdn": {
        "Cloudflare": [lambda h, b, c: "cf-ray" in h],
        "Fastly": [lambda h, b, c: "x-served-by" in h],
        "AWS CloudFront": [lambda h, b, c: "x-amz-cf-id" in h],
        "Akamai": [lambda h, b, c: "x-check-cacheable" in h],
        "Varnish": [lambda h, b, c: "x-varnish" in h],
    },
    "frameworks": {
        "React": [lambda h, b, c: bool(re.search(r"react\.production|react\.js|react\.min\.js", b))],
        "Vue.js": [lambda h, b, c: bool(re.search(r"vue\.js|vue\.min\.js", b))],
        "Angular": [lambda h, b, c: "__ng_app__" in b or "angular.js" in b],
        "jQuery": [lambda h, b, c: bool(re.search(r"jquery\.min\.js|jquery-", b))],
        "Next.js": [lambda h, b, c: "_next/static" in b],
        "Nuxt.js": [lambda h, b, c: "nuxt.js" in b or "__nuxt" in b],
    },
    "analytics": {
        "Google Analytics": [
            lambda h, b, c: bool(re.search(r"gtag/js|ga\.js|analytics\.js", b)),
        ],
        "Meta Pixel": [lambda h, b, c: "connect.facebook.net/fbevents" in b],
        "Hotjar": [lambda h, b, c: "static.hotjar.com" in b],
        "Mixpanel": [lambda h, b, c: "cdn.mxpnl.com" in b],
    },
}

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "permissions-policy",
]


async def run_tech_fingerprint(domain: str) -> dict:
    """Fetch a URL and fingerprint its technology stack."""
    url = domain.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    result = {
        "domain": domain,
        "found": False,
        "detected_tech": {},
        "security_headers": {"present": [], "missing": []},
    }

    try:
        async with httpx.AsyncClient(
            timeout=10, follow_redirects=True, verify=False
        ) as client:
            resp = await client.get(url)

        # Lowercase headers dict for matching
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text.lower() if resp.text else ""
        cookies_str = resp.headers.get("set-cookie", "")

        # Detect technologies
        for category, techs in SIGNATURES.items():
            detected = []
            for tech_name, checks in techs.items():
                for check in checks:
                    try:
                        if check(headers_lower, body, cookies_str):
                            detected.append(tech_name)
                            break
                    except Exception:
                        continue
            if detected:
                result["detected_tech"][category] = detected
                result["found"] = True

        # Check security headers
        for header in SECURITY_HEADERS:
            if header in headers_lower:
                result["security_headers"]["present"].append(header)
            else:
                result["security_headers"]["missing"].append(header)
        if result["security_headers"]["present"] or result["security_headers"]["missing"]:
            result["found"] = True

    except Exception as e:
        result["error"] = str(e)

    return result
