"""
Subdomain takeover candidates, from DNS alone.

A subdomain that still has a CNAME to a cloud service after the resource behind it was
deleted can sometimes be claimed by someone else. This module reads the CNAME of each
subdomain it is given and reports the ones that point at such a service, split into:

  dangling   the CNAME target does not exist (strong candidate)
  pointing   the target resolves; only worth a look if the service shows an error page
  unknown    the lookup failed, so nothing can be said either way

"Does not exist" is a strong claim, so it is only made on a definite answer: NXDOMAIN, or
an empty answer for A, AAAA and CNAME alike, from two independent public resolvers. A
timeout, SERVFAIL or a refused query is a failed lookup. It is reported as "unknown" and
never as "does not resolve". `resolution_state` is that test, and other recon code that
wants to say a name is gone should use it too.

It never requests the page or tries to claim anything. Every hit is a candidate to
verify by hand.
"""

import asyncio

import dns.resolver

from core.dnspool import dns_thread

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


# Two resolver operators that share no infrastructure. A name is only called absent when
# both say so.
RESOLVER_SETS = (["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"])


def _resolver(nameservers: list[str]) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = list(nameservers)
    r.timeout = 3
    r.lifetime = 4
    return r


def _ask(resolver, name: str) -> str:
    """One resolver's view of a name: "resolves", "absent" or "unknown"."""
    failed = False
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(name, rtype)
            return "resolves"
        except dns.resolver.NXDOMAIN:
            return "absent"
        except dns.resolver.NoAnswer:
            continue                      # the name exists but has no record of this type
        except Exception:
            failed = True                 # timeout, SERVFAIL, refused: not an answer
    return "unknown" if failed else "absent"


def resolution_state(name: str) -> str:
    """"resolves", "absent" or "unknown" for a hostname.

    "absent" needs a definite answer (NXDOMAIN, or no A, AAAA or CNAME record) from both
    resolver sets. Any lookup failure on the way gives "unknown"."""
    first = _ask(_resolver(RESOLVER_SETS[0]), name)
    if first != "absent":
        return first
    second = _ask(_resolver(RESOLVER_SETS[1]), name)
    return second if second in ("absent", "resolves") else "unknown"


def _check(host: str) -> dict | None:
    """A candidate row for a host, None when it has no CNAME to a claimable service, or
    {"host", "status": "unknown"} when its CNAME could not be read."""
    r = _resolver(RESOLVER_SETS[0])
    try:
        cname = str(r.resolve(host, "CNAME")[0].target).rstrip(".").lower()
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception:
        return {"host": host, "status": "unknown"}
    service = match_service(cname)
    if not service:
        return None
    state = resolution_state(cname)
    status = {"absent": "dangling", "resolves": "pointing"}.get(state, "unknown")
    return {"host": host, "cname": cname, "service": service, "status": status}


async def run_takeover(domain: str, hosts: list[str]) -> dict:
    wanted = []
    for h in hosts:
        h = str(h).strip().lower().rstrip(".")
        if (h == domain or h.endswith("." + domain)) and h not in wanted:
            wanted.append(h)
    wanted = wanted[:MAX_HOSTS]
    async def one(h):
        return await dns_thread(_check, h)

    rows = [x for x in await asyncio.gather(*(one(h) for h in wanted)) if x]
    # Hosts whose CNAME could not be read are not candidates. They are counted apart so a
    # run with failed lookups does not read as "checked, nothing found".
    unchecked = sorted(x["host"] for x in rows if "cname" not in x)
    hits = [x for x in rows if "cname" in x]
    hits.sort(key=lambda x: (["dangling", "unknown", "pointing"].index(x["status"]), x["host"]))
    return {
        "domain": domain,
        "found": True,
        "checked": len(wanted) - len(unchecked),
        "dangling": sum(1 for x in hits if x["status"] == "dangling"),
        "unknown": sum(1 for x in hits if x["status"] == "unknown"),
        "unchecked": unchecked[:50],
        "candidates": hits,
    }
