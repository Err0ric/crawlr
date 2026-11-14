# CrawlR

![Python](https://img.shields.io/badge/Python-3.11-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.143-green) ![License](https://img.shields.io/badge/license-MIT-purple) ![Live](https://img.shields.io/badge/live-crawlr.lol-brightgreen)

> OSINT investigation in your browser. No install, no account, no API key. Bring your own key when you want more.

**[crawlr.lol](https://crawlr.lol)**

Type a username, email, domain, IP, ASN, phone number or hash. CrawlR detects the target type, runs the right public sources in parallel, and ranks what comes back by how much it tells you. An optional AI report turns the evidence into an investigation summary with next steps.

> Screenshots are being refreshed for the v2 interface.

## Who it is for

- Security researchers and pentesters mapping a footprint or attack surface
- Incident responders checking suspicious email headers, hashes and infrastructure
- Journalists and investigators correlating usernames, emails and aliases
- CTF and Trace Labs players who need fast, consolidated OSINT

## Modes

| Mode | Input | What you get |
|---|---|---|
| **Investigate** | Username, email, name, phone, hash | Accounts, breaches, profiles and facts ranked into confirmed, flagged, likely and unverified, plus an optional AI report |
| **Recon** | Domain, IP or ASN | DNS, WHOIS, SSL, header grade, subdomains, ASN and prefixes, top-20 port check, exposure data, topology graph |
| **Headers** | Raw email headers | SPF, DKIM and DMARC results, hop-by-hop route with delays, sender origin, spoofing and phishing flags, verdict |
| **Dorks** | Name, username, email, location, employer, keywords | A Google dork built live, with site filters; open it or copy it |
| **Decoders** | Text | Base64, URL encoding, string hashing, VIN decode (NHTSA), US plate lookup |

### Investigate sources

| Source | What it does | Key |
|---|---|---|
| Sherlock | Username across 400+ sites | None |
| Maigret | Username across 3,000+ sites, with confidence | None |
| Holehe | Which services an email is registered with | None |
| Domain harvest | Hosts and addresses on an email's domain (crt.sh, CertSpotter, HackerTarget, RapidDNS, urlscan, OTX, Anubis, Wayback) | None |
| Have I Been Pwned | Breaches | None |
| GitHub | Profile, repos, linked email | None |
| Gravatar | Profile and avatar for an email | None |
| Platform check | Registration probes on major platforms | None |
| Profile scraper | Bios, display names and links from found profiles (active technique, off by default) | None |
| Hash lookup | MalwareBazaar, CIRCL, AlienVault OTX, ThreatFox | None |
| Phone lookup | Number normalization, carrier info, people-search links | Optional Numlookup key |
| Hunter.io | Email addresses and patterns for a domain | Your key |
| AI analysis and deep dive | Investigation report: identity, accounts, exposure, next moves | Free tier or your key |

### Recon sources

| Source | What it does | Key |
|---|---|---|
| DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, Cloudflare detection | None |
| WHOIS | Registrar, dates, nameservers, privacy | None |
| SSL | Issuer, SANs, expiry | None |
| HTTP headers | Server info and a security-header grade | None |
| Subdomains | DNS plus certificate transparency | None |
| ASN / BGP | IP to ASN, org, prefixes (RIPE, ARIN RDAP) | None |
| Port check | Top 20 TCP ports | None |
| InternetDB | Open ports, CVEs, hostnames (Shodan InternetDB) | None |
| Shodan | Banners, org, geo | Your key |
| Wayback, redirects, tech fingerprint | History, redirect chain, detected stack | None |
| AI summary | Attack-surface summary and next steps | Free tier or your key |

## Free tier and your own keys

Every non-AI source runs with no key. AI runs on a shared Gemini key with a small daily allowance per visitor. Add your own key in Settings for unlimited AI (Claude or Gemini) and the Hunter and Shodan sources.

| | Free | With your key |
|---|---|---|
| OSINT and recon sources | All keyless sources | Same, plus Hunter and Shodan |
| AI analysis | 5 per day | Unlimited |
| Deep dive | 1 per day | Unlimited |
| AI provider | Gemini Flash | Claude or Gemini |

**How keys are handled:** keys stay in your browser's `localStorage`. They are sent with each request to the CrawlR server, which passes them straight to the matching provider. CrawlR does not store them. Use a key with a spending limit.

## Run it yourself

```bash
git clone https://github.com/Err0ric/crawlr
cd crawlr
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # optional: GEMINI_API_KEY turns on the free AI tier
uvicorn main:app --reload --port 8000 --env-file .env
```

Open http://localhost:8000. Free-tier, quota, cache and tool-concurrency settings are documented in [`.env.example`](.env.example).

Run the tests:

```bash
pip install pytest && pytest -q
node tests/js/detect.test.mjs
```

## How it is built

FastAPI on Python 3.11 serves a vanilla JavaScript frontend (no build step) and a JSON API. The browser runs sources in parallel and ranks the results. Hosted on Railway. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the code map and [static/v2/DESIGN.md](static/v2/DESIGN.md) for the design system. The original v1 interface is still reachable at `/classic`.

## Privacy

- No accounts, no analytics, no tracking.
- Investigation history and notes stay in your browser.
- Active techniques that may notify the target (profile scraping for deep dive) are off by default and labeled.

## Responsible use

For lawful purposes only: your own accounts, authorized assessments, research, journalism and missing-persons work. You accept these terms before first use. Results come from third parties and can be wrong; treat unverified findings as leads, not facts.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Roadmap

- Reverse image search on profile pictures
- Case mode for Trace Labs competitions
- Shareable and exportable case reports
- More sources, chosen through research into comparable tools

## License and author

MIT, see [LICENSE](LICENSE). Built by Eric Henderson, [github.com/Err0ric](https://github.com/Err0ric).
