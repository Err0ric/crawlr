# CrawlR architecture

## Overview

One FastAPI process serves both the static frontend and a JSON API. The browser does the orchestration: it detects the target type, calls the relevant `/api/*` endpoints in parallel, ranks what comes back, and renders the case. The server is stateless apart from in-memory caches, rate-limit counters and AI quotas, which reset on restart.

```
Browser (static/v2, ES modules)
   |  fetch /api/...  (user AI key in X-Api-Key, provider in X-Ai-Provider)
   v
FastAPI (main.py)
   middleware: RequestContext -> SecurityHeaders -> SoftRateLimit
   routers/  ->  modules/  ->  public sources, CLI tools, AI providers
```

## Hosting and delivery

| Item | Value |
|---|---|
| Host | Railway, Nixpacks build (`railway.json`), deploys from `main` |
| Runtime | Python 3.11 (`runtime.txt`), one uvicorn worker |
| Start | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health check | `GET /api/health` |
| CI | GitHub Actions: compileall, pytest, `node --check` on v2 JS, JS detector test |
| Dependencies | Pinned in `requirements.txt`, Dependabot weekly |

## Routes

### Pages

| Route | Serves |
|---|---|
| `/` and `/v2` | `static/v2/index.html` (current UI) |
| `/classic` | `static/index.html` (legacy v1 UI) |
| `/static/*` | Static files |
| `/docs`, `/openapi.json` | FastAPI's generated API docs |

### API

| Prefix | Router | Endpoints | Notes |
|---|---|---|---|
| `/api/recon` | `routers/recon.py` | sherlock, maigret, holehe, harvester, hibp, gravatar, github, enrich, platform-check, hunter, shodan, internetdb, scrape-profiles | sherlock, maigret, holehe run as subprocesses under `core/subprocess_guard.py`. Hunter and Shodan need the user's key (`X-Hunter-Key`, `X-Shodan-Key`) |
| `/api/infra` | `routers/recon_infra.py` | dns, whois, ssl, headers, subdomains, asn, asn-detail, ip-asn, portscan, wayback, redirects, techfingerprint, summarize | Domain, IP and ASN recon. `summarize` is AI |
| `/api/analyze` | `routers/analyze.py` | summarize, deep-dive, deep, correlate, email-headers | All AI. Uses the user's key or the house key |
| `/api/hash` | `routers/hash_lookup.py` | hash | MalwareBazaar, CIRCL, OTX, ThreatFox |
| `/api/email` | `routers/email_headers.py` | analyze | Raw header parsing, SPF/DKIM/DMARC, hop analysis, IP geo |
| `/api/phone` | `routers/phone.py` | lookup | Optional `X-Numlookup-Key` |
| `/api/vehicles` | `routers/vehicles.py` | plate | Plate to VIN |
| `/api` | `main.py` | quota, health | Free-AI quota for the caller, liveness |

## Backend modules

| Area | Files |
|---|---|
| Identity | `sherlock.py`, `maigret_mod.py`, `holehe.py`, `github.py`, `gravatar.py`, `hibp.py`, `platform_check.py`, `profile_scraper.py`, `enricher.py`, `hunter.py` |
| Infrastructure | `dns_lookup.py`, `resolver.py`, `whois_lookup.py`, `ssl_check.py`, `headers_check.py`, `subdomain_enum.py`, `harvester.py`, `asn_lookup.py`, `asn_detail.py`, `port_scan.py`, `internetdb.py`, `shodan_lookup.py`, `wayback.py`, `redirect_chain.py`, `tech_fingerprint.py` |
| AI | `ai_provider.py`: Anthropic and Gemini calls, prompt cache |

`harvester.py` is a native, in-process aggregator (crt.sh, CertSpotter, HackerTarget, RapidDNS, urlscan, OTX, Anubis, Wayback). It does not use the theHarvester CLI.

## Core and middleware

| File | Role |
|---|---|
| `core/house_key.py` | Free AI tier: server-side Gemini key, per-IP daily quotas, global daily cap |
| `core/subprocess_guard.py` | Caps concurrent CLI tools (`MAX_CONCURRENT_TOOLS`), queue timeout, result logging |
| `core/logging.py` | Structured JSON logging |
| `middleware/observability.py` | Request ID, access log, security headers (CSP, HSTS, XFO, COOP, Permissions-Policy), client IP helper |
| `middleware/rate_limit.py` | Soft per-IP rate limiting on expensive endpoints |

## API keys

- AI, Hunter, Shodan and Numlookup keys are entered in Settings and kept in the browser's `localStorage`.
- They are sent with each request to the CrawlR server, which passes them to the matching provider. The server does not store them.
- The house Gemini key lives only in the server environment (`GEMINI_API_KEY`).

## Frontend (`static/v2/js`)

| File | Role |
|---|---|
| `app.js` | Entry point: mode navigation (`#investigate`, `#recon`, `#headers`, `#dorks`, `#decoders`), landing, settings, history drawer, AI pill, terms gate |
| `core.js` | Shared primitives: `h` tagged template (auto-escaping), `esc`, `safeUrl`, `link`, `store`, `post`/`postAi`, target `detect`, key handling |
| `ui.js` | Modal and drawer primitives (one overlay at a time, focus trap, Escape) |
| `investigate.js` | Investigate mode: run sources, build the ledger, AI, deep dive, history, notes, export |
| `recon.js` | Recon mode for a domain, IP or ASN; loads d3 from cdnjs for the topology tab |
| `graph.js` | D3 topology graph |
| `evidence.js` | Turns module responses into ranked evidence (`confirmed`, `flag`, `likely`, `unverified`) and extracted facts |
| `renderers.js` | Per-source cards for the "By source" section |
| `workbench.js` | Pieces shared by every mode: run log, tiered ledger, facts panel |
| `report.js` | Investigation report: dossier card plus one scrolling report |
| `ai.js` | AI response normalization and the markdown renderer used by every report |
| `tools.js` | Headers analyzer, dork builder, decoders (Base64, URL, hash, VIN, plate) |
| `md5.js` | MD5 for the hash decoder and Gravatar |

Design tokens and UI rules: `static/v2/DESIGN.md`.
