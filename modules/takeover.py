"""
Subdomain takeover candidates, from DNS alone.

A subdomain that still has a CNAME to a cloud service after the resource behind it was
deleted can sometimes be claimed by someone else. This module reads the CNAME of each
subdomain it is given and reports the ones that point at such a service, split into:

  dangling   the CNAME target no longer resolves at all (strong candidate)
  pointing   the target resolves; only worth a look if the service shows an error page

It never requests the page or tries to claim anything. Every hit is a candidate to
verify by hand.
"""

import asyncio

import dns.resolver

# CNAME suffix -> service. Services where an unclaimed name can be registered by anyone.
SERVICES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku", "s3.amazonaws.com": "Amazon S3",
    "s3-website": "Amazon S3 website", "cloudfront.net": "CloudFront", "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure Cloud Service", "cloudapp.azure.com": "Azure VM",
    "trafficmanager.net": "Azure Traffic Manager", "blob.core.windows.net": "Azure Blob Storage", "azureedge.net": "Azure CDN",
    "azure-api.net": "Azure API Management", "fastly.net": "Fastly", "pantheonsite.io": "Pantheon", "ghost.io": "Ghost",
    "myshopify.com": "Shopify", "surge.sh": "Surge", "bitbucket.io": "Bitbucket", "readme.io": "ReadMe",
    "helpscoutdocs.com": "Help Scout", "zendesk.com": "Zendesk", "unbouncepages.com": "Unbounce", "netlify.app": "Netlify",
    "netlify.com": "Netlify", "vercel.app": "Vercel", "now.sh": "Vercel", "webflow.io": "Webflow", "wpengine.com": "WP Engine",
    "cargocollective.com": "Cargo", "statuspage.io": "Statuspage", "tumblr.com": "Tumblr", "wordpress.com": "WordPress.com",
    "desk.com": "Desk", "freshdesk.com": "Freshdesk", "uservoice.com": "UserVoice", "intercom.help": "Intercom",
    "launchrock.com": "LaunchRock", "strikinglydns.com": "Strikingly", "smugmug.com": "SmugMug", "fly.dev": "Fly.io",
    "onrender.com": "Render", "pages.dev": "Cloudflare Pages", "firebaseapp.com": "Firebase", "web.app": "Firebase",
    "appspot.com": "Google App Engine", "storage.googleapis.com": "Google Cloud Storage", "agilecrm.com": "Agile CRM",
    "airee.ru": "Airee", "bigcartel.com": "Big Cartel", "kinsta.cloud": "Kinsta", "ngrok.io": "ngrok", "tilda.ws": "Tilda",
}
MAX_HOSTS = 200


def match_service(cname: str) -> str | None:
    c = cname.lower().rstrip(".")
    for suffix, name in SERVICES.items():
        if c.endswith("." + suffix) or c == suffix or (suffix == "s3-website" and ".s3-website" in c):
            return name
    return None


def _check(host: str) -> dict | None:
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 3
    r.lifetime = 4
    try:
        cname = str(r.resolve(host, "CNAME")[0].target).rstrip(".").lower()
    except Exception:
        return None
    service = match_service(cname)
    if not service:
        return None
    try:
        r.resolve(cname, "A")
        resolves = True
    except dns.resolver.NXDOMAIN:
        resolves = False
    except Exception:
        resolves = True    # timeouts and empty answers are not evidence of a dangling record
    return {"host": host, "cname": cname, "service": service, "status": "pointing" if resolves else "dangling"}


async def run_takeover(domain: str, hosts: list[str]) -> dict:
    wanted = []
    for h in hosts:
        h = str(h).strip().lower().rstrip(".")
        if (h == domain or h.endswith("." + domain)) and h not in wanted:
            wanted.append(h)
    wanted = wanted[:MAX_HOSTS]
    sem = asyncio.Semaphore(25)

    async def one(h):
        async with sem:
            return await asyncio.to_thread(_check, h)

    hits = [x for x in await asyncio.gather(*(one(h) for h in wanted)) if x]
    hits.sort(key=lambda x: (x["status"] != "dangling", x["host"]))
    return {
        "domain": domain,
        "found": True,
        "checked": len(wanted),
        "dangling": sum(1 for x in hits if x["status"] == "dangling"),
        "candidates": hits,
    }
