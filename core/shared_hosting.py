"""
Is this address a shared edge of a hosting platform or CDN?

A site on Vercel, Cloudflare, Fastly, CloudFront, Netlify or GitHub Pages answers from an
address it shares with thousands of unrelated sites. What a scanner sees there (open ports,
other hostnames, software versions) describes the platform's edge, not the site. Recon has
to know this before it lists a stranger's hostname as part of the target's footprint.

`shared_provider` answers from four signals, strongest first:

  ip_range          the address is inside a range the platform publishes
  cname             the name is a CNAME to the platform
  hostname_pattern  a hostname seen on the address belongs to the platform
  asn               the network is announced by a CDN-only operator (weak)

The ASN signal is only used for networks that carry nothing but the CDN (Cloudflare,
Fastly). A general cloud such as AMAZON-02 or GOOGLE says nothing about sharing: a
dedicated VM and a shared edge look the same at that level.

Pure functions, no network. The ranges are hard-coded on purpose: they are small, they
change rarely, and a recon run should not depend on fetching them.
"""

import ipaddress

from core.validate import is_ip, same_site

# Published or documented IPv4 ranges, checked 2026-11-14.
IP_RANGES = {
    # https://vercel.com/docs/domains (A record 76.76.21.21) and the A records Vercel now
    # hands out for apex domains (216.198.79.1, 64.29.17.1). Vercel has no network of its own.
    "Vercel": ["76.76.21.0/24", "216.198.79.0/24", "64.29.17.0/24"],
    # https://www.cloudflare.com/ips-v4/
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    # https://api.fastly.com/public-ip-list
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
        "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
        "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ],
    # https://docs.github.com/pages (apex A records 185.199.108.153 to 185.199.111.153)
    "GitHub Pages": ["185.199.108.0/22"],
    # https://docs.netlify.com/domains (load balancer address for apex domains)
    "Netlify": ["75.2.60.5/32"],
    # CloudFront is left out here: its ranges are large and change every week
    # (https://ip-ranges.amazonaws.com/ip-ranges.json). It is detected by name instead.
}
_NETS = [(provider, ipaddress.ip_network(r)) for provider, ranges in IP_RANGES.items() for r in ranges]

# A CNAME ending in one of these means the name is served by the platform.
CNAME_SUFFIXES = {
    "vercel-dns.com": "Vercel", "vercel.app": "Vercel", "now.sh": "Vercel",
    "cloudflare.net": "Cloudflare", "pages.dev": "Cloudflare",
    "fastly.net": "Fastly", "fastlylb.net": "Fastly",
    "cloudfront.net": "CloudFront",
    "netlify.app": "Netlify", "netlify.com": "Netlify", "netlifyglobalcdn.com": "Netlify",
    "github.io": "GitHub Pages",
}

# Hostnames a scanner records on the address itself (reverse DNS, certificates).
HOSTNAME_SUFFIXES = {**CNAME_SUFFIXES, "cloudflare.com": "Cloudflare", "githubusercontent.com": "GitHub Pages"}

# Operators whose network is only their CDN. Matched against the start of the ASN org name.
CDN_ONLY_ASN_ORGS = {"cloudflare": "Cloudflare", "fastly": "Fastly"}


def _clean(name) -> str:
    return str(name or "").strip().lower().rstrip(".")


def _by_ip(ip) -> str | None:
    try:
        addr = ipaddress.ip_address(_clean(ip))
    except ValueError:
        return None
    return next((provider for provider, net in _NETS if addr.version == net.version and addr in net), None)


def _by_suffix(name: str, table: dict[str, str]) -> str | None:
    name = _clean(name)
    for suffix, provider in table.items():
        if name == suffix or name.endswith("." + suffix):
            return provider
    # Vercel's numbered DNS zones: 10c0b549a5d8fbfc.vercel-dns-017.com
    labels = name.split(".")
    if len(labels) >= 2 and labels[-1] == "com" and labels[-2].startswith("vercel-dns-") and labels[-2][11:].isdigit():
        return "Vercel"
    return None


def shared_provider(ip=None, cnames=(), hostnames=(), asn_org="") -> dict | None:
    """{"provider": "Vercel", "basis": "ip_range"} when the address is a shared platform edge, else None."""
    provider = _by_ip(ip) if ip else None
    if provider:
        return {"provider": provider, "basis": "ip_range"}
    for name in cnames or ():
        provider = _by_suffix(name, CNAME_SUFFIXES)
        if provider:
            return {"provider": provider, "basis": "cname"}
    for name in hostnames or ():
        provider = _by_suffix(name, HOSTNAME_SUFFIXES)
        if provider:
            return {"provider": provider, "basis": "hostname_pattern"}
    org = _clean(asn_org)
    for prefix, provider in CDN_ONLY_ASN_ORGS.items():
        if org.startswith(prefix):
            return {"provider": provider, "basis": "asn"}
    return None


def neighbors(target, hostnames, shared: dict | None = None) -> list[str]:
    """The hostnames on an address that are not the target and not part of its site.

    For a domain target that is every name outside its registrable domain. For an IP target
    there is no site to compare with, so names are only neighbors when the address is a
    known shared edge."""
    target = _clean(target)
    names = []
    for raw in hostnames or ():
        name = _clean(raw)
        if name and name not in names:
            names.append(name)
    if not target or is_ip(target):
        return names if shared else []
    return [n for n in names if not same_site(n, target)]


def ports_note(shared: dict | None) -> str:
    """One sentence for a result whose ports were seen on a shared edge, or ""."""
    if not shared:
        return ""
    p = shared["provider"]
    return (f"This address is a shared {p} edge. The open ports, software and CVEs seen on it belong to {p}'s servers "
            "and are the same for every site hosted there. They are not necessarily the target's own.")


def annotate(result: dict, target, cnames=(), asn_org="") -> dict:
    """Add shared_host, neighbors and ports_note to an InternetDB or Shodan style result."""
    hostnames = [h for h in result.get("hostnames") or [] if isinstance(h, str)]
    shared = shared_provider(ip=result.get("ip"), cnames=cnames, hostnames=hostnames, asn_org=asn_org)
    result["shared_host"] = shared
    result["neighbors"] = neighbors(target, hostnames, shared)
    result["ports_note"] = ports_note(shared)
    return result
