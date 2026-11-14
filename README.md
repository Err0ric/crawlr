# CrawlR

![Python](https://img.shields.io/badge/Python-3.11-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.143-green) ![License](https://img.shields.io/badge/license-MIT-purple) ![Live](https://img.shields.io/badge/live-crawlr.lol-brightgreen)

> OSINT investigation in your browser. No install, no account, no API key. Bring your own key when you want more.

**[crawlr.lol](https://crawlr.lol)**

Type a username, email, domain, IP, ASN, phone number or hash. CrawlR detects the target type, runs the right public sources in parallel, and ranks what comes back by how much it tells you. An optional AI report turns the evidence into an investigation summary with next steps.

| Investigate | Recon |
|---|---|
| ![Investigate: ranked evidence for a username](docs/screenshots/after/investigate-1440.png) | ![Recon: findings for a domain](docs/screenshots/after/recon-1440.png) |

## Who it is for

- Security researchers and pentesters mapping a footprint or attack surface
- Incident responders checking suspicious email headers, hashes and infrastructure
- Journalists and investigators correlating usernames, emails and aliases
- CTF and Trace Labs players who need fast, consolidated OSINT

## Modes

| Mode | Input | What you get |
|---|---|---|
| **Investigate** | Username, email, name, phone, hash | Accounts, breaches, profiles and facts ranked into flags, confirmed, possible and known noisy sites. A source that fails is shown as failed, never as "not found". AI report on request |
| **Recon** | Domain, IP or ASN | DNS, WHOIS, TLS, header grade, subdomains, email spoofing check, takeover candidates, lookalike domains, certificate history, ASN and prefixes, exposure data, a topology graph you can pivot from, optional top-20 port check |
| **Headers** | Raw email headers | SPF, DKIM and DMARC results, hop-by-hop route with delays, sender origin, spoofing and phishing flags, verdict |
| **Dorks** | Name, username, email, location, employer, keywords | A Google dork built live, with site filters; open it or copy it |
| **Decoders** | Text | Base64, URL encoding, string hashing, VIN decode (NHTSA) |

### Investigate sources

| Source | What it does | Key |
|---|---|---|
| Sherlock | Username across 400+ sites | None |
| Maigret | Username across the top 500 sites. Reads profile data where it can, which is what makes a hit "confirmed". Adult and dating sites are off unless you opt in | None |
| Holehe | Which services an email is registered with | None |
| Domain harvest | Hosts and addresses on an email's domain (crt.sh, CertSpotter, HackerTarget, RapidDNS, urlscan, OTX, Anubis, Wayback) | None |
| Breaches | Known breaches for an email (XposedOrNot) | None |
| GitHub | Profile, repos, linked email. Rate limits are reported as rate limits | None (optional server `GITHUB_TOKEN`) |
| Gravatar | Profile and avatar for an email | None |
| Platform check | Profile URL probes on major platforms (a weak signal, shown as possible) | None |
| Profile scraper | Bios, display names and links from found profiles (active technique, off by default) | None |
| Hash lookup | MalwareBazaar, CIRCL, AlienVault OTX, ThreatFox | None |
| Phone lookup | Number normalization, carrier info, people-search links | Optional Numlookup key |
| Hunter.io | Email addresses and patterns for a domain | Your key |
| At a glance | A short written brief built from rules, with no AI: what stands out, what is uncertain, what failed | None |
| AI analysis and deep dive | Investigation report: identity, accounts, exposure, next moves. Runs only when you ask, and shows what it costs first | Free tier, your key, or no key at all (copy the prompt into an assistant you already use) |

### Recon sources

| Source | What it does | Key |
|---|---|---|
| DNS | A, AAAA, MX, NS, TXT, CNAME, SOA, Cloudflare detection | None |
| WHOIS | Registrar, dates, nameservers, privacy | None |
| TLS | Issuer, SANs, expiry | None |
| HTTP headers | Server info and a security-header grade | None |
| Subdomains | DNS plus certificate transparency | None |
| Email security | SPF, DMARC, DKIM selectors, MTA-STS, TLS-RPT, BIMI, with a grade and a plain answer to "can this domain be spoofed?" | None |
| DNS hardening | CAA, DNSSEC, wildcard DNS, reverse DNS | None |
| Takeover candidates | Subdomains whose CNAME points at a claimable cloud service, split into dangling and pointing. DNS only | None |
| Lookalike domains | Registered typo, lookalike-character and TLD variants, mail-capable ones first. DNS only | None |
| Certificate history | Issuance timeline, issuers, and certified names that no longer resolve | None |
| Published files | security.txt, robots.txt paths worth a look, favicon hash for Shodan pivots | None |
| ASN / BGP | IP to ASN, org, prefixes (RIPE, ARIN RDAP) | None |
| Port check | Top 20 TCP ports (active technique, off by default) | None |
| InternetDB | Open ports, CVEs, hostnames (Shodan InternetDB) | None |
| Shodan | Banners, org, geo | Your key |
| Wayback, redirects, tech fingerprint | History, archived paths worth a look, redirect chain, detected stack | None |
| At a glance | Rules-based brief of the run, no AI | None |
| Timeline | Every dated fact from the run in order: registration, first certificates, archive copies, upcoming expiries | None |
| AI summary | Attack-surface summary and next steps | Free tier, your key, or no key (copy the prompt) |

## Free tier and your own keys

Every non-AI source runs with no key, and every case gets a written "At a glance" brief that uses no AI at all. AI is opt-in per case: nothing is sent to a model until you press Analyze. Without your own key it runs on a shared Gemini key with a small daily allowance per visitor, and a cached answer or an identical re-run does not use a credit. Add your own key in Settings for unlimited AI (Claude or Gemini) and the Hunter and Shodan sources.

| | Free | With your key |
|---|---|---|
| OSINT and recon sources | All keyless sources | Same, plus Hunter and Shodan |
| AI analysis | 5 per day | Unlimited |
| Deep dive | 1 per day | Unlimited |
| AI provider | Gemini Flash | Claude or Gemini |

**No key at all:** press **Copy prompt** in the AI panel and paste it into Claude, ChatGPT, Gemini or any assistant you already use. Paste the reply back and CrawlR formats it as the same report. Nothing is sent to a model by CrawlR, and no credit is used.

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

Open http://localhost:8000. Free-tier, quota, cache, GitHub token, proxy and tool-concurrency settings are documented in [`.env.example`](.env.example).

Run the tests:

```bash
pip install pytest && pytest -q
for f in static/v2/js/*.js; do node --check "$f"; done
node tests/js/detect.test.mjs
node tests/js/contrast.test.mjs
node tests/js/brief.test.mjs
node tests/js/timeline.test.mjs
node tests/js/casefile.test.mjs
```

## How it is built

FastAPI on Python 3.11 serves a vanilla JavaScript frontend (no build step) and a JSON API. The browser runs sources in parallel and ranks the results. Fonts and the graph library are self-hosted, so the page makes no third-party requests when it loads. Hosted on Railway. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the code map, [static/v2/DESIGN.md](static/v2/DESIGN.md) for the design system and [docs/research.md](docs/research.md) for the comparison with other OSINT tools and the feature proposals.

## Privacy

- No accounts, no analytics, no tracking.
- Investigation history and notes stay in your browser. Exports (Markdown, HTML, print to PDF and a JSON case file) are built in the browser too.
- A case file opens on another machine from History. It is read in the browser and never uploaded.
- Each case has an optional purpose line that is saved with it and printed on every export.
- The server keeps no record of what you look up: targets are not written to its logs. Short-lived in-memory caches (AI answers, GitHub profiles) are lost on restart.
- Active techniques that connect to the target's own systems (the port scan, profile scraping for deep dive) are off by default and labeled.

## Responsible use

The full acceptable-use statement is in the app under Settings. For lawful purposes only: your own accounts, authorized assessments, research, journalism and missing-persons work. You accept these terms before first use. Results come from third parties and can be wrong. "Possible" findings are leads, not facts, and a confirmed account shows that a handle exists, not who owns it.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Roadmap

Ranked proposals with sources are in [docs/research.md](docs/research.md). Next candidates:

- Client-side correlation rules beyond the current brief
- Passphrase-encrypted case files
- Case mode for Trace Labs competitions

## License and author

MIT, see [LICENSE](LICENSE). Built by Eric Henderson, [github.com/Err0ric](https://github.com/Err0ric).
