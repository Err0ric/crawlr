# CRAWLR - Open Source OSINT Investigation Platform

Dual-mode OSINT platform for identity investigation and network reconnaissance. Built with FastAPI and Claude AI.

## Modes

### INVESTIGATE
People/identity OSINT: username enumeration, email breach detection, social platform mapping, AI-powered identity inference.

- **Sherlock** — username enumeration across 400+ social platforms with false positive filtering
- **Holehe** — email-to-account detection (which services an email is registered on)
- **theHarvester** — email and subdomain discovery from public sources
- **GitHub API** — profile, repos, activity, and email scraping
- **HIBP** — Have I Been Pwned breach database lookup
- **Gravatar** — avatar and profile data from email hash
- **Hunter.io** — domain email discovery and pattern detection
- **Shodan** — exposed services, ports, CVEs, and host intelligence
- **Profile Enricher** — scrapes bios, followers, and metadata from Reddit, TikTok, YouTube, Twitch, Patreon, CashApp
- **Platform Check** — HTTP existence checks for Facebook, Instagram, Twitter/X, LinkedIn, Threads
- **Name Search** — generates people-search engine links for full name targets
- **AI Analysis** — Claude-powered identity analysis with probable name inference, cross-platform correlation, and investigative leads
- **Deep Dive** — intelligence dossier mode: subject profile, confidence matrix, platform correlation, OPSEC assessment, and ready-to-use search queries

### RECON
Infrastructure OSINT: DNS records, WHOIS, SSL, HTTP headers, subdomain enumeration (DNS + certificate transparency logs), ASN/BGP, port scanning, attack surface analysis.

- **DNS Records** — A, AAAA, MX, NS, TXT, CNAME, SOA lookups with Cloudflare proxy detection
- **WHOIS** — registrar, registration dates, nameservers, org, country, privacy detection
- **SSL Certificate** — issuer, common name, SANs, expiry, chain details
- **HTTP Headers** — server identification and security header grading (A/B/C/F)
- **Subdomains** — DNS enumeration of 60+ common prefixes + certificate transparency log search via crt.sh
- **ASN / BGP** — IP-to-ASN mapping, org, prefixes, network info
- **ASN Detail** — full ASN analysis with RDAP queries, IPv4/IPv6 prefix enumeration, and peering data
- **Port Scan** — top 20 common ports (FTP, SSH, HTTP, HTTPS, SMB, RDP, databases, etc.)
- **AI Analysis** — Claude-powered attack surface summary, misconfiguration detection, and red team next steps

## Features

- **BYOK (Bring Your Own Key)** — Claude API key stored locally in browser, never sent to server
- **AI Analysis** — standard bullet-point analysis and Deep Dive intelligence dossier mode
- **Cross-target correlation** — bulk search with comma-separated targets, AI correlates identities across all results
- **D3.js topology graphs** — interactive hierarchical visualization for DNS records and ASN prefix maps
- **Certificate transparency** — crt.sh log integration reveals dev, staging, and internal subdomains
- **Cloudflare proxy detection** — identifies proxied IPs with amber CF badges in DNS topology
- **Active Techniques** — toggle for live profile scraping that may alert targets
- **5 themes** — Dark Purple (default), Midnight, Blood, Ghost, Flashbang (light)
- **Export to Markdown** — full report export for both INVESTIGATE and RECON results
- **History tab** — saved investigations with one-click reload
- **Settings tab** — API key management for Claude, Hunter.io, Shodan, HIBP, and module toggles
- **Terms of Service** — acceptable use policy gate on first launch

## Modules

| Module | Type | Requires |
|--------|------|----------|
| Sherlock | Username enumeration | Free |
| Holehe | Email account detection | Free |
| theHarvester | Domain/subdomain recon | Free |
| GitHub API | Profile and repo data | Free |
| Gravatar | Email profile lookup | Free |
| Platform Check | Social media existence | Free |
| Profile Enricher | Bio/metadata scraping | Free |
| Name Search | People-search links | Free |
| HIBP | Breach database | Free |
| Hunter.io | Email discovery | API Key |
| Shodan | Exposed services/CVEs | API Key |
| AI Analysis | Claude-powered inference | Claude API Key |
| Deep Dive | Intelligence dossier | Claude API Key |
| Correlation | Cross-target analysis | Claude API Key |

## Setup

```bash
git clone https://github.com/Err0ric/crawlr
cd crawlr
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000 and add your Claude API key in Settings.

## Legal

For authorized security research, penetration testing, investigative journalism, and missing persons investigations only. Users must agree to Terms of Service on first launch.

## Author

Eric Henderson | [github.com/Err0ric](https://github.com/Err0ric) | DC253 / BSides Seattle
