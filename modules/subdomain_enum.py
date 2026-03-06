import dns.resolver

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "relay",
    "api", "app", "dev", "staging", "test", "beta", "demo",
    "admin", "panel", "dashboard", "portal", "manage",
    "vpn", "remote", "gateway", "proxy",
    "cdn", "static", "assets", "media", "img", "images",
    "blog", "shop", "store", "docs", "wiki", "help", "support",
    "git", "gitlab", "jenkins", "ci", "build",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "auth", "login", "sso", "oauth",
    "m", "mobile", "wap",
    "cpanel", "whm", "plesk", "webmin",
    "cloud", "s3", "backup", "vault",
    "status", "monitor", "metrics", "grafana",
]


async def run_subdomains(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            found.append({"subdomain": fqdn, "ips": ips})
        except Exception:
            pass

    return {
        "domain": domain,
        "total": len(found),
        "checked": len(COMMON_SUBDOMAINS),
        "subdomains": found,
    }
