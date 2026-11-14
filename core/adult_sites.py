"""
The one list of adult and dating sites.

Everything that has to know whether a site is an adult or dating site asks here: the Sherlock
and Maigret wrappers (which sites to leave out of an ordinary run, which rows to mark), the
link verifier and the profile scraper (which hosts never to open without the opt-in), and the
adult check itself. The tools' own flags are not enough on their own: Sherlock's data leaves
RoyalCams and datingRU unflagged, and Maigret tags Fansly "social".

The list is built once, at import, from four places:

  1. every site Sherlock marks isNSFW in its installed data
  2. every site Maigret tags porn, erotic, webcam, dating or nsfw in its installed data
     (disabled sites included)
  3. PLATFORMS: the sites modules/adult_check.py knows, with or without a public profile page
  4. UNFLAGGED: sites in either tool's data that are plainly adult or dating and carry no flag

A site is matched by its name in a tool's data (lowercase) or by the host of a URL. A host
matches when it equals a listed host or is a subdomain of one. A site's registrable domain is
listed too, unless a site that is not adult shares it: love.mail.ru is listed, mail.ru is not.
"""

import importlib.util
import json
import os
from urllib.parse import urlsplit

from core.validate import registrable_domain

ADULT_TAGS = ("porn", "erotic", "webcam", "dating", "nsfw")
_DATING_ONLY = {"dating"}

# The adult check's platforms. host -> category.
PLATFORMS = {
    "onlyfans.com": "adult", "fansly.com": "adult", "pornhub.com": "adult", "xhamster.com": "adult",
    "chaturbate.com": "adult", "stripchat.com": "adult", "manyvids.com": "adult", "clips4sale.com": "adult",
    "fetlife.com": "adult", "justfor.fans": "adult", "loyalfans.com": "adult",
    "tinder.com": "dating", "bumble.com": "dating", "hinge.co": "dating", "okcupid.com": "dating",
    "pof.com": "dating", "plentyoffish.com": "dating", "grindr.com": "dating",
}

# In Sherlock's or Maigret's data without an adult flag or tag. (name in the data, host, category)
UNFLAGGED = (
    ("RoyalCams", "royalcams.com", "adult"),            # Sherlock: not isNSFW
    ("datingRU", "dating.ru", "dating"),                # Sherlock: not isNSFW
    ("Chatujme.cz", "chatujme.cz", "dating"),           # Sherlock: not isNSFW (Maigret tags it dating)
    ("Fansly", "fansly.com", "adult"),                  # Maigret: tagged sharing, social
    ("Justforfans", "justfor.fans", "adult"),           # Maigret: tagged social
    ("Admire Me", "admireme.vip", "adult"),             # Maigret: tagged social
    ("Mym.fans", "mym.fans", "adult"),                  # Maigret: tagged social
    ("www.adultism.com", "adultism.com", "adult"),      # Maigret: tagged social
    ("lemmynsfw.com", "lemmynsfw.com", "adult"),        # Maigret: tagged forum
    ("E621", "e621.net", "adult"),                      # Maigret: tagged anime, art
    ("Sexforum.ws", "sexforum.ws", "adult"),            # Maigret: tagged forum
    ("Sexwin", "sexforum.win", "adult"),                # Maigret: tagged forum
    ("SexforumIXBB", "sexforum.ixbb.ru", "adult"),      # Maigret: tagged forum
    ("fordating.ru", "fordating.ru", "dating"),         # Maigret: tagged forum
    ("Mylove", "lovetalk.ru", "dating"),                # Maigret: no tag that says so
    ("MeetMe", "meetme.com", "dating"),                 # Maigret: tagged social
)


# Domains that host many unrelated sites or services. Only the adult site's own host under
# them is listed (dating.rambler.ru), never the whole domain.
SHARED_DOMAINS = frozenset({"rambler.ru", "mail.ru", "ixbb.ru", "clan.su", "ucoz.ru", "ucoz.com", "ucoz.net", "3dn.ru", "moy.su",
                            "fandom.com", "forumotion.com", "mybb.ru", "blogspot.com", "wordpress.com", "tumblr.com"})


def _package_data(package: str) -> str:
    try:
        spec = importlib.util.find_spec(package)
    except (ImportError, ValueError):
        return ""
    if not spec or not spec.origin:
        return ""
    return os.path.join(os.path.dirname(spec.origin), "resources", "data.json")


SHERLOCK_DATA = _package_data("sherlock_project")
MAIGRET_DATA = _package_data("maigret")


def _load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def host_of(url: str) -> str:
    """Lowercase host of a URL or URL template, without "www.". "" when there is none."""
    text = str(url or "").replace("{username}", "x").replace("{}", "x").strip()
    if "://" not in text:
        text = "//" + text
    try:
        host = (urlsplit(text).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _entry_hosts(entry: dict) -> set[str]:
    return {h for h in (host_of(entry.get(k) or "") for k in ("url", "urlMain", "urlProbe")) if "." in h}


def _maigret_category(tags) -> str:
    tagset = {str(t).lower() for t in tags} if isinstance(tags, (list, tuple, set)) else set()
    hit = tagset & set(ADULT_TAGS)
    if not hit:
        return ""
    return "dating" if hit <= _DATING_ONLY else "adult"


def tag_category(tags) -> str:
    """"adult", "dating" or "" from a list of Maigret tags."""
    return _maigret_category(tags)


def build(sherlock_path: str | None = None, maigret_path: str | None = None) -> tuple[dict, dict]:
    """({site name in lowercase: category}, {host: category}) from the installed site data and
    the two hand lists above."""
    names: dict[str, str] = {}
    hosts: dict[str, str] = {}
    hand_names = {name.lower(): cat for name, _, cat in UNFLAGGED}
    hand_hosts = {**PLATFORMS, **{host: cat for _, host, cat in UNFLAGGED}}

    def put(table: dict, key: str, cat: str) -> None:
        if key and (table.get(key) != "adult"):
            table[key] = cat

    def hand_listed(name: str, entry_hosts: set[str]) -> str:
        if name.lower() in hand_names:
            return hand_names[name.lower()]
        for h in entry_hosts:
            for listed, cat in hand_hosts.items():
                if h == listed or h.endswith("." + listed):
                    return cat
        return ""

    adult_entries: list[tuple[str, set[str], str]] = []
    other_domains: set[str] = set()

    sherlock = _load(sherlock_path if sherlock_path is not None else SHERLOCK_DATA)
    maigret = _load(maigret_path if maigret_path is not None else MAIGRET_DATA).get("sites")
    sources = [(name, entry, "adult" if entry.get("isNSFW") else "") for name, entry in sherlock.items() if isinstance(entry, dict)]
    sources += [(name, entry, _maigret_category(entry.get("tags"))) for name, entry in (maigret.items() if isinstance(maigret, dict) else ())
                if isinstance(entry, dict)]
    for name, entry, cat in sources:
        entry_hosts = _entry_hosts(entry)
        cat = cat or hand_listed(name, entry_hosts)
        if cat:
            adult_entries.append((name, entry_hosts, cat))
        else:
            other_domains.update(registrable_domain(h) for h in entry_hosts)

    for name, entry_hosts, cat in adult_entries:
        put(names, name.strip().lower(), cat)
        for h in entry_hosts:
            put(hosts, h, cat)
            reg = registrable_domain(h)
            if reg and reg not in other_domains and reg not in SHARED_DOMAINS:
                put(hosts, reg, cat)
    for name, host, cat in UNFLAGGED:
        put(names, name.lower(), cat)
        put(hosts, host, cat)
    for host, cat in PLATFORMS.items():
        put(hosts, host, cat)
    return names, hosts


NAMES, HOSTS = build()


def _host_category(url: str) -> str:
    host = host_of(url)
    while host and "." in host:
        if host in HOSTS:
            return HOSTS[host]
        host = host.split(".", 1)[1]          # a subdomain of a listed host is that site
    return ""


def category(name: str = "", url: str = "") -> str:
    """"adult", "dating" or "" for a site, by its name in a tool's data or by the host of a URL."""
    by_name = NAMES.get(str(name or "").strip().lower(), "")
    by_host = _host_category(url) if url else ""
    if "adult" in (by_name, by_host):
        return "adult"
    return by_name or by_host


def is_adult_site(name: str = "", url: str = "") -> bool:
    """Is this an adult or dating site? True when the name or the URL's host is on the list."""
    return bool(category(name, url))
