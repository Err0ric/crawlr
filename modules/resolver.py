import dns.resolver


def resolve_domain(domain: str) -> str:
    """Resolve domain to IP using public DNS (8.8.8.8, 1.1.1.1).
    Tries the domain directly, then www. prefix as fallback."""
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 5
    r.lifetime = 5

    # Try direct resolution
    for target in [domain, f"www.{domain}"]:
        try:
            answers = r.resolve(target, "A")
            return str(answers[0])
        except Exception:
            pass

    # Fallback: system resolver
    r2 = dns.resolver.Resolver()
    r2.timeout = 5
    r2.lifetime = 5
    for target in [domain, f"www.{domain}"]:
        try:
            answers = r2.resolve(target, "A")
            return str(answers[0])
        except Exception:
            pass

    raise dns.resolver.NXDOMAIN(f"Could not resolve {domain}")
