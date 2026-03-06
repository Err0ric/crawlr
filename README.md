# Crawlr

AI-powered OSINT investigation platform for security researchers, investigators, and the infosec community. Built with FastAPI and Claude AI.

Crawlr combines automated reconnaissance modules with AI-driven analysis to surface identity connections, infrastructure weaknesses, and attack surface insights through a single dark-themed web interface.

## Modes

### INVESTIGATE

Lookup targets by username, email, full name, or phone number. Modules run automatically based on input type.

- **Sherlock** — username enumeration across 400+ social platforms
- **Holehe** — email-to-account detection (which services an email is registered on)
- **theHarvester** — email and subdomain discovery from public sources
- **GitHub API** — profile, repos, activity, and email scraping
- **HIBP** — Have I Been Pwned breach database lookup
- **Gravatar** — avatar and profile data from email hash
- **Profile Enricher** — scrapes bios, followers, and metadata from Reddit, TikTok, YouTube, Twitch, OnlyFans, Patreon, CashApp
- **Platform Check** — HTTP existence checks for Facebook, Instagram, Twitter/X, LinkedIn, Threads, OnlyFans
- **Name Search** — generates people-search engine links for full name targets
- **AI Analysis** — Claude-powered identity analysis with probable name inference, cross-platform correlation, and investigative leads

### RECON

Infrastructure analysis for domains, IP addresses, and ASN numbers. Auto-detects target type.

- **DNS Records** — A, AAAA, MX, NS, TXT, CNAME, SOA lookups
- **WHOIS** — registrar, registration dates, nameservers, org, country
- **SSL Certificate** — issuer, common name, SANs, expiry, chain details
- **HTTP Headers** — server identification and security header grading (A/B/C/F)
- **Subdomains** — DNS enumeration of 60+ common prefixes + certificate transparency log search via crt.sh
- **ASN / BGP** — IP-to-ASN mapping, org, prefixes, network info
- **ASN Detail** — full ASN analysis with RDAP queries, IPv4/IPv6 prefix enumeration, and peering data
- **Port Scan** — top 20 common ports (FTP, SSH, HTTP, HTTPS, SMB, RDP, databases, etc.)
- **AI Analysis** — Claude-powered attack surface summary, misconfiguration detection, and red team next steps

## Features

| Feature | Description |
|---------|-------------|
| BYOK | Bring Your Own Key — users provide their Anthropic API key, nothing stored server-side |
| AI Identity Analysis | Probable name inference, cross-platform correlation, investigative leads |
| AI Attack Surface | Misconfiguration detection, exposure assessment, red team recommendations |
| D3.js Topology Graph | Interactive hierarchical visualization for DNS records and ASN prefix maps |
| Active Techniques | Toggle (off by default) for techniques that may notify targets |
| Certificate Transparency | crt.sh log search reveals dev, staging, and internal subdomains |
| Auto-Routing | Domains/IPs/ASNs entered in INVESTIGATE auto-redirect to RECON mode |
| Markdown Export | Full report export for both INVESTIGATE and RECON results |
| Case Notes | Scratchpad for investigator notes, persisted in browser storage |
| Terms of Service | Acceptable use policy modal on first visit |

## Modules

| Module | Mode | Type | Description |
|--------|------|------|-------------|
| Sherlock | INVESTIGATE | Free | Username search across 400+ platforms |
| Holehe | INVESTIGATE | Free | Email-to-account detection |
| theHarvester | INVESTIGATE | Free | Email and subdomain discovery |
| GitHub API | INVESTIGATE | Free | Profile, repos, and activity data |
| HIBP | INVESTIGATE | Free | Breach database lookup |
| Gravatar | INVESTIGATE | Free | Avatar and profile from email |
| Profile Enricher | INVESTIGATE | Free | Bio/follower scraping (7 platforms) |
| Platform Check | INVESTIGATE | Free | Social platform existence checks |
| Name Search | INVESTIGATE | Free | People-search engine links |
| DNS Records | RECON | Free | A, MX, NS, TXT, CNAME, SOA |
| WHOIS | RECON | Free | Registration and ownership data |
| SSL Certificate | RECON | Free | Certificate details and expiry |
| HTTP Headers | RECON | Free | Server ID and security grading |
| Subdomains | RECON | Free | DNS enumeration + CT log search |
| ASN / BGP | RECON | Free | IP-to-ASN and network info |
| ASN Detail | RECON | Free | RDAP + prefix + peering analysis |
| Port Scan | RECON | Free | Top 20 TCP port scan |
| AI Analysis | Both | Key | Claude-powered analysis and recommendations |

## Setup

```bash
git clone https://github.com/Err0ric/crawlr.git
cd crawlr
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn anthropic httpx dnspython python-whois beautifulsoup4 sherlock-project holehe
```

## Run

```bash
uvicorn main:app --reload
```

Open [http://localhost:8000](http://localhost:8000) in your browser.

## API Key

The app uses a Claude API key for AI-powered analysis. Enter your Anthropic API key in the browser — it is stored in browser session memory only and sent directly to the Anthropic API. The Crawlr server never stores or logs API keys.

## Disclaimer

Crawlr is intended for authorized security research, penetration testing, investigative journalism, and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any target. See the in-app Terms of Service for the full acceptable use policy.
