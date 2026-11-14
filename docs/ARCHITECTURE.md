# CrawlR architecture

## Overview

One FastAPI process serves both the static frontend and a JSON API. The browser does the orchestration: it detects the target type, calls the relevant `/api/*` endpoints in parallel, ranks what comes back, and renders the case. The server is stateless apart from in-memory caches, rate-limit counters and AI quotas, which reset on restart.

```
Browser (static/v2, ES modules)
   |  fetch /api/...  (user AI key in X-Api-Key, provider in X-Ai-Provider)
   v
FastAPI (main.py)
   middleware: RequestContext -> GZip -> SecurityHeaders -> BodyLimit -> RateLimit
   routers/  ->  core/validate  ->  modules/  ->  core/netguard  ->  public sources, CLI tools
   AI routers ->  core/ai_call  ->  modules/ai_provider  ->  Anthropic or Gemini
```

## Hosting and delivery

| Item | Value |
|---|---|
| Host | Railway, Nixpacks build (`railway.json`), deploys from `main` |
| Runtime | Python 3.11 (`runtime.txt`), one uvicorn worker |
| Start | `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| Health check | `GET /api/health` |
| CI | GitHub Actions: compileall (including `core/`), pytest, `node --check` on the JS, detector test, contrast test |
| Dependencies | Pinned in `requirements.txt`, Dependabot weekly |

## Routes

### Pages

| Route | Serves |
|---|---|
| `/` | `static/v2/index.html`, with asset URLs rewritten to `/assets/<fingerprint>/...`. `HEAD` is allowed |
| `/v2`, `/classic` | Permanent redirects to `/`. The v1 interface has been removed |
| `/assets/<fingerprint>/*` | `static/v2/*`, cached for a year. The fingerprint is a hash of every UI file, so any change gives every asset a new URL |
| `/static/*` | Static files at stable URLs, always revalidated |
| `/robots.txt`, `/sitemap.xml` | Generated from `SITE_URL` |
| `/docs`, `/openapi.json` | FastAPI's generated API docs |

### API

| Prefix | Router | Endpoints | Notes |
|---|---|---|---|
| `/api/recon` | `routers/recon.py` | sherlock, maigret, holehe, harvester, hibp, gravatar, github, enrich, platform-check, hunter, shodan, internetdb, scrape-profiles | sherlock, maigret, holehe run as subprocesses under `core/subprocess_guard.py`. Hunter and Shodan need the user's key (`X-Hunter-Key`, `X-Shodan-Key`) |
| `/api/infra` | `routers/recon_infra.py` | dns, whois, ssl, headers, subdomains, email-posture, dns-depth, takeover, lookalikes, wellknown, asn, asn-detail, ip-asn, portscan, wayback, redirects, techfingerprint, summarize, prompt | Domain, IP and ASN recon. `summarize` is AI; `prompt` returns the same prompt without calling a model |
| `/api/analyze` | `routers/analyze.py` | summarize, deep-dive, deep, correlate, email-headers, prompt, parse | All AI, through `core/ai_call.py`. Uses the user's key or the house key. Provider failures return `{detail, code}` with a matching status |
| `/api/hash` | `routers/hash_lookup.py` | hash | MalwareBazaar, CIRCL, OTX, ThreatFox |
| `/api/email` | `routers/email_headers.py` | analyze | Raw header parsing, SPF/DKIM/DMARC, hop analysis, IP geo |
| `/api/phone` | `routers/phone.py` | lookup | Optional `X-Numlookup-Key` |
| `/api/vehicles` | `routers/vehicles.py` | plate | Plate to VIN through an undocumented third-party endpoint. Flagged for a keep or remove decision |
| `/api` | `main.py` | quota, health | Free-AI quota for the caller, liveness |

## Backend modules

| Area | Files |
|---|---|
| Identity | `sherlock.py`, `maigret_mod.py`, `holehe.py`, `github.py`, `gravatar.py`, `hibp.py`, `platform_check.py`, `profile_scraper.py`, `enricher.py`, `hunter.py` |
| Infrastructure | `email_posture.py`, `dns_depth.py`, `takeover.py`, `lookalikes.py`, `wellknown.py`, `crtsh.py`, `dns_lookup.py`, `resolver.py`, `whois_lookup.py`, `ssl_check.py`, `headers_check.py`, `subdomain_enum.py`, `harvester.py`, `asn_lookup.py`, `asn_detail.py`, `port_scan.py`, `internetdb.py`, `shodan_lookup.py`, `wayback.py`, `redirect_chain.py`, `tech_fingerprint.py` |
| AI | `ai_provider.py`: async Anthropic and Gemini calls, typed `AIError`, response cache keyed per caller |

`harvester.py` is a native, in-process aggregator (crt.sh, CertSpotter, HackerTarget, RapidDNS, urlscan, OTX, Anubis, Wayback). It does not use the theHarvester CLI.

## Core and middleware

| File | Role |
|---|---|
| `core/netguard.py` | Outbound request guard. Resolves a host once, refuses anything that is not a public address, connects to the vetted address, and repeats the check on every redirect hop. Every module that fetches a user-supplied URL or opens a socket to a user-supplied host uses it |
| `core/validate.py` | Username, email, host and URL validation and normalization; registrable-domain comparison |
| `core/errors.py` | Maps upstream exceptions to `{error, error_code, error_detail}`: a short human message, a stable code, and the raw text for a details toggle |
| `core/ai_call.py` | The one path for AI endpoints: pick key, check cache, check and spend free quota, call, refund on failure |
| `core/ai_text.py` | Fence stripping and JSON extraction for model output |
| `core/dnspool.py` | One bounded thread pool for bulk DNS work, so a burst of lookups cannot starve the rest of a run |
| `core/house_key.py` | Free AI tier: server-side Gemini key, per-IP daily quotas, global daily cap |
| `core/subprocess_guard.py` | Caps concurrent CLI tools (`MAX_CONCURRENT_TOOLS`), queue timeout, result logging |
| `core/logging.py` | Structured JSON logging |
| `middleware/observability.py` | Request ID, access log, security headers (CSP with `script-src 'self'`, HSTS, XFO, COOP, Permissions-Policy), cache policy, body size limit, client IP helper (`TRUSTED_PROXY_HOPS`) |
| `middleware/rate_limit.py` | Per-IP sliding-window limits on every POST under `/api`. Over the limit returns 429 with `Retry-After` |

## Result states

Every source ends in one of three states, and they are kept apart from the module to the screen to the AI prompt:

| State | Module returns | UI | AI prompt |
|---|---|---|---|
| Found | data | ledger row, source card | listed as evidence |
| Not found | `found: false` with no error | "nothing found" in the run log, a neutral card | may be cited as a negative |
| Failed | `error`, `error_code`, `error_detail` (`found` is `null` where it applies) | red run-log row, a notice above the findings, a "failed" card | listed under "FAILED, treat as unknown" |

Account evidence has its own two levels. **Confirmed** means a profile signal verified the account: Maigret parsed profile data, GitHub's API returned the user, the enricher read a display name, or a registration check passed. **Possible** means a tool reported the handle and nothing verified it.

## AI without a key

Three ways to get a written report, none automatic:

1. **One click**: `POST /api/analyze/summarize` (or `/api/infra/summarize`) with the visitor's key or the house key.
2. **Copy prompt**: `POST /api/analyze/prompt` (or `/api/infra/prompt`) returns the exact prompt the endpoint above would send. The visitor pastes it into any assistant. No model is called and no quota is touched.
3. **Paste reply**: `POST /api/analyze/parse` formats the pasted reply with the same parser, so the report, dossier and pivot buttons render as usual.

`investigation_prompt()` and `recon_prompt()` build the prompt for both paths, so they cannot drift apart. Every case also gets the rules-based brief from `brief.js`, which needs no model.

## API keys

- AI, Hunter, Shodan and Numlookup keys are entered in Settings and kept in the browser's `localStorage`.
- They are sent with each request to the CrawlR server, which passes them to the matching provider. The server does not store them.
- The house Gemini key lives only in the server environment (`GEMINI_API_KEY`).
- `GITHUB_TOKEN` (optional, server-side) raises the GitHub API limit. No part of any key is logged.

## Frontend (`static/v2/js`)

| File | Role |
|---|---|
| `app.js` | Entry point: mode navigation (`#investigate`, `#recon`, `#headers`, `#dorks`, `#decoders`), landing, settings, history drawer, AI pill, theme, terms gate, focus management |
| `core.js` | Shared primitives: `h` tagged template (auto-escaping), `esc`, `safeUrl`, `link`, `store`, `post`/`postAi` (abortable, typed `ApiError`), `sourceOutcome`, target `detect`, key handling, `roving` keyboard helper |
| `ui.js` | Modal and drawer primitives: focus trap, inert background, Escape, focus return, `required` dialogs |
| `investigate.js` | Investigate mode: run and cancel sources, build the ledger, AI on request, deep dive, history, run diff, notes, export |
| `recon.js` | Recon mode for a domain, IP or ASN; loads the self-hosted d3 for the topology tab |
| `graph.js` | D3 topology graph. Nodes are focusable and emit `crawlr:node` when selected, which Recon turns into a pivot bar |
| `evidence.js` | Turns module responses into ranked evidence (`flag`, `confirmed`, `possible`, `noise`) and extracted facts. Confirmed needs a verified profile signal |
| `renderers.js` | Per-source cards for the "By source" section |
| `workbench.js` | Pieces shared by every mode: run log with progress, tiered ledger, facts panel, failed-source notice, run diff, result tabs, brief renderer, HTML export |
| `brief.js` | "At a glance": the rules-based written brief for Investigate and Recon. No model |
| `report.js` | Investigation report: dossier card plus one scrolling report |
| `ai.js` | AI response normalization, the markdown renderer used by every report, and the AI panel's start state (one-click analysis, copy prompt, paste reply) |
| `tools.js` | Headers analyzer, dork builder, decoders (Base64, URL, hash, VIN, plate) |
| `md5.js` | MD5 for the hash decoder and Gravatar |

Design tokens and UI rules: `static/v2/DESIGN.md`.
