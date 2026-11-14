"""
Lookalike domains: typo, homoglyph and TLD variants of a domain that are registered.

Generates candidates the way phishing and typosquatting campaigns do, then asks DNS which
ones exist. DNS queries only; the candidate sites are never contacted. A registered
lookalike is not proof of abuse: brands register their own typos, and some are unrelated.
"""

import asyncio

import dns.resolver

from core.dnspool import dns_thread
from core.validate import registrable_domain

MAX_CANDIDATES = 260
KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl", "p": "o",
    "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm", "k": "jil", "l": "ko",
    "z": "asx", "x": "zsc", "c": "xdv", "v": "cfb", "b": "vgn", "n": "bhm", "m": "nj",
}
HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "e": ["3"], "a": ["4"], "s": ["5"],
              "m": ["rn"], "w": ["vv"], "d": ["cl"], "g": ["q"], "u": ["v"], "v": ["u"]}
TLDS = ["com", "net", "org", "co", "io", "app", "info", "biz", "online", "site", "xyz", "shop", "dev", "ai", "cc", "us", "uk", "de"]


def generate(domain: str) -> dict[str, str]:
    """Candidate domain -> the technique that produced it. Pure function."""
    reg = registrable_domain(domain)
    name, _, tld = reg.partition(".")
    out: dict[str, str] = {}

    def add(n: str, kind: str, t: str = tld):
        cand = f"{n}.{t}"
        if n and cand != reg and len(n) <= 63 and not n.startswith("-") and not n.endswith("-") and cand not in out:
            out[cand] = kind

    for i in range(len(name)):
        add(name[:i] + name[i + 1:], "missing letter")
        add(name[:i] + name[i] + name[i:], "doubled letter")
        if i < len(name) - 1 and name[i] != name[i + 1]:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], "swapped letters")
        for g in HOMOGLYPHS.get(name[i], []):
            add(name[:i] + g + name[i + 1:], "lookalike character")
        for k in KEYBOARD.get(name[i], ""):
            add(name[:i] + k + name[i + 1:], "adjacent key")
        if 0 < i < len(name) and name[i] != "-" and name[i - 1] != "-":
            add(name[:i] + "-" + name[i:], "added hyphen")
    for rn, m in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        if rn in name:
            add(name.replace(rn, m, 1), "lookalike character")
    for t in TLDS:
        if t != tld:
            add(name, "different ending", t)
    for word in ("login", "secure", "support", "mail", "my", "app"):
        add(f"{name}-{word}", "added word")
        add(f"{word}-{name}", "added word")
    # the likeliest abuse first, then cap
    order = ["lookalike character", "different ending", "missing letter", "swapped letters", "doubled letter", "added hyphen", "added word", "adjacent key"]
    ranked = sorted(out.items(), key=lambda kv: order.index(kv[1]))
    return dict(ranked[:MAX_CANDIDATES])


def _lookup(cand: str) -> dict | None:
    r = dns.resolver.Resolver()
    r.nameservers = ["8.8.8.8", "1.1.1.1"]
    r.timeout = 2
    r.lifetime = 3
    try:
        ns = sorted(str(x).rstrip(".").lower() for x in r.resolve(cand, "NS"))
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        ns = []
    try:
        a = [str(x) for x in r.resolve(cand, "A")]
    except Exception:
        a = []
    if not ns and not a:
        return None
    try:
        mx = bool(r.resolve(cand, "MX"))
    except Exception:
        mx = False
    return {"domain": cand, "ips": a[:3], "nameservers": ns[:3], "mail": mx}


async def run_lookalikes(domain: str) -> dict:
    candidates = generate(domain)
    async def one(c):
        return await dns_thread(_lookup, c)

    found = []
    for cand, res in zip(candidates, await asyncio.gather(*(one(c) for c in candidates))):
        if res:
            found.append({**res, "technique": candidates[cand]})
    # A registered lookalike that can receive mail is the more interesting kind.
    found.sort(key=lambda x: (not x["mail"], not x["ips"], x["domain"]))
    return {
        "domain": registrable_domain(domain),
        "found": True,
        "checked": len(candidates),
        "registered": len(found),
        "with_mail": sum(1 for x in found if x["mail"]),
        "results": found[:120],
    }
