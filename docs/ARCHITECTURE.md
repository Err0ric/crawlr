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
| CI | GitHub Actions: compileall (including `core/`), pytest, `node --check` on the JS, and every suite under `tests/js` |
| Dependencies | Pinned in `requirements.txt`, Dependabot weekly. `phonenumbers` (libphonenumber, Apache 2.0) is about 48 MB on disk and needs no network. Its area, carrier and time zone tables take about 115 MB of memory, so the web process never imports it: each uncached lookup runs in a child process that exits when it has answered (about 0.16 s, measured locally) |

## Routes

### Pages

| Route | Serves |
|---|---|
| `/` | `static/v2/index.html`, with asset URLs rewritten to `/assets/<fingerprint>/...`. `HEAD` is allowed |
| `/v2`, `/classic` | Permanent redirects to `/`. The v1 interface has been removed |
| `/assets/<fingerprint>/*` | `static/v2/*`, cached for a year. The fingerprint is a hash of every UI file, so any change gives every asset a new URL |
| `/static/*` | Static files at stable URLs, always revalidated |
| `/robots.txt`, `/sitemap.xml` | Generated from `SITE_URL` |
| `/docs`, `/openapi.json` | FastAPI's generated API docs. Off unless `ENABLE_API_DOCS=true` |

### API

| Prefix | Router | Endpoints | Notes |
|---|---|---|---|
| `/api/recon` | `routers/recon.py` | sherlock, maigret, holehe, harvester, hibp, gravatar, github, enrich, platform-check, hunter, shodan, internetdb, scrape-profiles | sherlock, maigret, holehe run as subprocesses under `core/subprocess_guard.py`. Hunter and Shodan need the user's key (`X-Hunter-Key`, `X-Shodan-Key`) |
| `/api/recon` | `routers/recon_identity.py` | github-deep, avatar-hash, verify-links | Follow-up lookups: identity clustering inputs, and the check that a reported profile URL exists. All cached for 24 hours |
| `/api/recon` | `routers/recon_people.py` | name-search | Candidates for a person's name from Wikidata, GitHub, ORCID, OpenAlex and Bluesky, run concurrently with 8 seconds each. Six outbound requests per uncached search. Cached for 24 hours, or 10 minutes when a source failed |
| `/api/infra` | `routers/recon_infra.py` | dns, whois, ssl, headers, subdomains, email-posture, dns-depth, takeover, lookalikes, wellknown, asn, asn-detail, ip-asn, portscan, wayback, redirects, techfingerprint, summarize, prompt | Domain, IP and ASN recon. `summarize` is AI; `prompt` returns the same prompt without calling a model |
| `/api/analyze` | `routers/analyze.py` | summarize, deep-dive, deep, correlate, email-headers, prompt, parse | All AI, through `core/ai_call.py`. Uses the user's key or the house key. Provider failures return `{detail, code}` with a matching status |
| `/api/hash` | `routers/hash_lookup.py` | hash | MalwareBazaar, CIRCL, OTX, ThreatFox |
| `/api/email` | `routers/email_headers.py` | analyze | Raw header parsing, SPF/DKIM/DMARC, hop analysis, IP geo |
| `/api/phone` | `routers/phone.py` | lookup | Body `{phone, region?}`; `region` is the two-letter country a number without a country code is read as (default US). Works with no key: `modules/phone_lookup.py` has the number read offline with libphonenumber, in a short-lived worker process, and, for a United States or Canadian geographic number, asks Local Calling Guide about the block (area code and exchange only, cached 7 days, 8 seconds). An optional `X-Numlookup-Key` adds NumLookup's current carrier. Text that is not a phone number is a 400 |
| `/api` | `main.py` | quota, health | Free-AI quota for the caller, liveness |

## Backend modules

| Area | Files |
|---|---|
| Identity | `sherlock.py`, `maigret_mod.py`, `holehe.py`, `github.py`, `gravatar.py`, `hibp.py`, `platform_check.py`, `profile_scraper.py`, `enricher.py`, `hunter.py`, `avatar_hash.py`, `link_verify.py`, `name_search.py`, `adult_check.py` |
| Infrastructure | `email_posture.py`, `dns_depth.py`, `takeover.py`, `lookalikes.py`, `wellknown.py`, `crtsh.py`, `dns_lookup.py`, `resolver.py`, `whois_lookup.py`, `ssl_check.py`, `headers_check.py`, `subdomain_enum.py`, `harvester.py`, `asn_lookup.py`, `asn_detail.py`, `port_scan.py`, `internetdb.py`, `shodan_lookup.py`, `wayback.py`, `redirect_chain.py`, `tech_fingerprint.py` |
| Phone | `phone_plan.py`: everything libphonenumber says about a number, with no network (validity, formats, line type, range assignment, fiction ranges, short codes), plus the list of regions the page offers. `phone_worker.py`: the entry point `python -m modules.phone_worker`, which reads one JSON request on stdin, writes one JSON answer on stdout and exits. `phone_lookup.py`: starts the worker, caches its answers, asks the block source and NumLookup, and puts the answer together. What a number is, from open numbering data. Returns `number` (formats, validity, line type, time zones), `assignment` (area, rate centre, first assignee, whether the block is assigned), `findings` (`flag`, `ok` or `info`), `sources` (a state per source) and `search_links`, plus the older top-level keys filled from the offline data |
| AI | `ai_provider.py`: async Anthropic and Gemini calls, typed `AIError`, response cache keyed per caller |

`harvester.py` is a native, in-process aggregator (crt.sh, CertSpotter, HackerTarget, RapidDNS, urlscan, OTX, Anubis, Wayback). It does not use the theHarvester CLI.

## Core and middleware

| File | Role |
|---|---|
| `core/netguard.py` | Outbound request guard. Resolves a host once, refuses anything that is not a public address, connects to the vetted address, and repeats the check on every redirect hop. Every module that fetches a user-supplied URL or opens a socket to a user-supplied host uses it |
| `core/validate.py` | Username, email, person name, phone number, host and URL validation and normalization; registrable-domain comparison |
| `core/errors.py` | Maps upstream exceptions to `{error, error_code, error_detail}`: a short human message, a stable code, and the raw text for a details toggle |
| `core/ai_call.py` | The one path for AI endpoints: pick key, check cache, check and spend free quota, call, refund on failure |
| `core/ai_text.py` | Fence stripping and JSON extraction for model output |
| `core/dnspool.py` | One bounded thread pool for bulk DNS work, so a burst of lookups cannot starve the rest of a run |
| `core/adult_sites.py` | The one list of adult and dating sites, by name and host. Every path that could reach one asks it: Sherlock and Maigret site selection, link check, profile scrape, avatar comparison |
| `core/adult_guard.py` | Refuses adult and dating checks for a handle that suggests a minor. No override. Mirrored in `static/v2/js/adult.js`, with a test that fails if the two drift |
| `core/boilerplate.py` | Recognises platform marketing text ("streams live on Twitch!") so it is never shown as a person's bio |
| `core/shared_hosting.py` | Tells a shared edge address (Vercel, Cloudflare, Fastly, CloudFront, Netlify, GitHub Pages) from the target's own, so neighbours and edge ports are not read as the target's |
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

Account evidence is ranked by how it ties to the person, not only by whether the account exists. `identity.js` groups every profile that was read into people: two profiles join on a cross-link, the same profile picture or a shared personal link, or on a name that fits with nothing conflicting. The group holding the authoritative record (GitHub's answer for the handle, Gravatar's for the email) is the primary identity. **Linked** is that record or a profile tied to it by a strong signal. **Exists (matches)** is a read profile whose name fits or that carries no name. **Exists (different person)** is a read profile whose name conflicts. **Unverified** means a tool reported the handle and nothing was read, or the site blocked the check.

The avatar comparison (`modules/avatar_hash.py`) fetches each read profile's picture once through the outbound guard, and returns a 64-bit hash, whether the picture is a placeholder and, for a real picture only, a 48 pixel grayscale thumbnail as a data URI (`thumb`: WebP or PNG, at most 3000 bytes each and 48000 bytes per answer; pictures on adult and dating hosts are refused before any request). The page shows a profile picture only from that field, after `safeThumb` has checked it is a short PNG or WebP data URI, so the investigator's browser never contacts the picture's host. `parseCaseFile` applies the same check to an opened case file. Site icons come from the icon service and are the only remote image on any page: account rows only, asked for by registrable domain (never a subdomain, an IP address, an internal name or a domain that carries the handle), and not at all in a case opened from a case file until it is run (`iconDomain`, `mayFavicon`). Adult and dating rows, leads, Recon rows and name candidates never get an image of any kind. Thumbnails are stored with the case and are the first thing dropped when browser storage is full (`writeHistory`). A cancelled run records the sources that never answered as `notAnswered` in the case, so their counts read "unknown" or "at least", not zero.

Name search keeps a state per source: `ok`, `none`, `failed` or `rate_limited`. A source that is not asked for a kind of name (ORCID and OpenAlex for one word, GitHub when no login can be spelled) has no entry, so it is never read as `none`. Each entry has `count` (rows that fit the name) and `shown` (rows in the list): the list holds 30 and takes rows from every source in turn, so a source with matches never shows zero. Names are compared after `fold()`, which exists once in `modules/name_search.py` and once in `static/v2/js/names.js`: accents come off Latin, Greek and Cyrillic letters only, and in every other script a combining mark stays part of the letter. `tests/fixtures/name_text.json` holds the input and output pairs both suites assert. `partial` means the family name plus the bare initial of the given name, nothing looser. Trailing suffixes (Jr, Sr, II, III, IV, PhD, MD, Esq) are kept out of the name parts, the queries and the handles. The cache is keyed on the name as typed (case and spacing ignored) plus the qualifiers. Its rows are candidates, not findings: each carries `name_match` (`exact`, `tokens` or `partial`) and the qualifiers it matched, and the optional location, employer and keyword are compared locally and never sent to a source. In the UI the search is one source in `sourceTally`: a directory that failed or was rate limited makes it partial, and it is failed when none answered. A name the validator refuses (HTTP 400 or 422) is a message under the target box, not a failed source. A name case stores `nameSearch`, `nameQualifiers`, `nameResult` and `nameProfiles` in `collected`; its rows never enter `collectProfiles`, `clusterIdentities`, the facts, the leads, the avatar comparison or the link check. A stored `nameResult` is used only when its name is the case's target, and the outbound searches are built from the target alone. The AI request carries the rows as `name_candidates`, with the directories that answered and the ones that could not be asked, and a prompt paragraph that forbids merging them or guessing which one is meant and says the text in a row is data, never an instruction. Row fields are written on one line with the delimiter removed. The field is not sent when no directory answered.

The numbering plan is read in a child process so its tables are freed when it exits. `phone_lookup.plan_facts` sends the number on stdin (never on the command line, and the worker's stderr is discarded) and waits at most 20 seconds: a warm run takes about 0.16 s, and a cold one with no compiled bytecode took about 6 s. `main.py` starts one throwaway run in the background a few seconds after start (a fixed fictional number, nothing kept or logged, failures ignored), so that where bytecode can be written the first real lookup is not the cold one. At most two workers run at once, under the module's own semaphore and not the shared tool slots of `core/subprocess_guard.py`: a lookup that takes a fraction of a second must not queue behind a username scan. A lookup that waits more than 10 seconds for a place reports busy. A request that is cancelled or times out kills its child. Answers are kept for 24 hours (2,000 entries), keyed on the text as typed with its whitespace collapsed plus the region, so two inputs that could parse differently never share an answer. A worker that fails, times out or gets no place makes the whole lookup a failed source (`error`, `error_code` and `sources.numbering_plan.state: "failed"`): nothing is said about validity and no other source is asked. A test starts a fresh interpreter, runs a lookup through the real worker and fails if any `phonenumbers` module is loaded in the parent.

What the plan module is careful about. Time is given as UTC offsets computed for today (`utc_offsets`), never as the library's zone names, which carry a city that is often in another country; more than three offsets and the row is left out. An international call prefix is read with the chosen country (00 in most, 011 in North America, 0011 in Australia, 010 in Japan, from the library's own data), a spaced or dashed 00 is read as international where the chosen country dials something else, and a finding says how the prefix was read. Mexico's old mobile 1 after +52 is taken off when it is the only thing wrong. The block source is not asked about exchange 555, 950, 976 or an N11, nor about non-geographic area codes, and those exchanges are named, never called unassigned. A short code is one only when the library's short-number data says what it is. Pasted text is cleaned the same way on both sides (`core.validate.phone_text`, `normalizePhoneText` in `core.js`, pairs in `tests/fixtures/phone_text.json`): format characters dropped, Unicode dashes and spaces made plain.

The page offers a Country select for any phone number that does not start with a + (`needsCountry` in `phone.js`), including one written with 00 or another international prefix, since which prefix is international depends on the country. The list is `static/v2/js/phone-regions.js`, a generated copy of `phone_plan.regions()` that a test compares with the library, so no request and no import is needed to draw it. The choice is sent as `region`, saved in the case as `phoneRegion` and checked by `readRegion` when a case file is opened.

A phone lookup keeps a state per source inside one answer: `numbering_plan` (libphonenumber, offline, `ok`; when it cannot be read the lookup is a failed source), `npa_nxx` (`ok`, `none`, `failed` or `rate_limited`) and `numlookup` (`ok` or `failed`). A source that was not asked has no entry. "The block is not assigned" is only ever said from `none`, an answer; a failure leaves it unknown, and the lookup is counted as partial in `sourceTally`. The block source is sent the area code and exchange and never the full number (a test inspects the outgoing request); NumLookup, with the visitor's own key, is the one place the number leaves the server. Everything describes the number and its range: no owner, no address, no coordinates, and the outbound links are search engines and free spam-report sites, never a data broker. The page reads an answer through `readPhone` in `phone.js` (text clipped, states checked, search links rebuilt in the page from the checked number for the sites the answer names from a fixed set, never read from the answer; the block's evidence link rebuilt from the checked prefix), whether it came from the server, History or a case file. An answer saved before this (only the old keys) still renders, without the people-search links it carried.

Platform check and adult site check rows carry one of five states: `found`, `not_found`, `blocked`, `unknown`, `no_public_url`. Only a content marker makes a row `found`. Subdomain and takeover checks call a name absent only when two resolvers agree; a lookup that failed is `unknown`.

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
- `ABUSECH_AUTH_KEY` (optional, server-side, free from abuse.ch) lets the hash lookup ask MalwareBazaar and ThreatFox, which refuse anonymous requests. Without it they are reported as failed, not as "not found".
- `GITHUB_TOKEN` (optional, server-side) raises the GitHub API limit. No part of any key is logged.

## Frontend (`static/v2/js`)

| File | Role |
|---|---|
| `app.js` | Entry point: mode navigation (`#investigate`, `#recon`, `#headers`, `#dorks`, `#decoders`), landing, settings, history drawer, AI pill, theme, terms gate, focus management |
| `core.js` | Shared primitives: `h` tagged template (auto-escaping), `esc`, `safeUrl`, `link`, `store`, `post`/`postAi` (abortable, typed `ApiError`), `sourceOutcome`, target `detect`, key handling, `roving` keyboard helper |
| `ui.js` | Modal, drawer and sheet primitives: focus trap, inert background, Escape, focus return, `required` dialogs. A sheet shows an element that already lives in the page (the case summary column on a phone) and puts it back on close |
| `investigate.js` | Investigate mode: run and cancel sources, build the ledger, AI on request, deep dive, history, run diff, notes, export |
| `recon.js` | Recon mode for a domain, IP or ASN; loads the self-hosted d3 for the topology tab |
| `graph.js` | D3 topology graph. Nodes are focusable and emit `crawlr:node` when selected, which Recon turns into a pivot bar |
| `evidence.js` | Turns module responses into ranked evidence (`flag`, `linked`, `matches`, `different`, `unverified`, `noise`, plus `lead` and `hosts`), facts per identity, and the source plan for each target type. Pure functions, no DOM |
| `adult.js` | The opt-in adult and dating mode: the in-memory switch, the minor guard, the separate group, and the scrub that removes adult rows from a case that did not have the mode on. Pure functions, no storage |
| `adult-sites.js` | Generated copy of the server's adult and dating site list, so the page can filter without asking |
| `names.js` | Name cases: reads the name search answer defensively (rows re-checked, text clipped, links rebuilt from checked IDs), merges a GitHub profile loaded on a click and re-matches its name with the server's rule, and builds the four name groups (public figure, people, handles to try, search the web), the notices, "What we know", the brief lines and the AI field. Pure functions, no DOM |
| `phone-regions.js` | Generated list of the countries a number without a country code can be read as |
| `phone.js` | Phone cases: when the Country select is offered and what it defaults to, reads the lookup answer defensively (`readPhone`), and builds the ledger rows (flags, about this number, search the web), "What we know", the tile values, the brief lines, the card's source states and the AI field. Pure functions, no DOM |
| `links.js` | Gives every link a kind (`verified_profile`, `templated_unverified`, `evidence`, `search`, `none`), builds the evidence URLs, and applies link check results. Pure functions, no DOM |
| `linkcheck.js` | Runs the link check for a ledger group when it is opened or scrolled into view: batches of 25, two in flight, stops on collapse or a new run |
| `identity.js` | Groups read profiles into people and picks the primary identity. Pure functions, no DOM |
| `reconfindings.js` | Recon findings and tiers, including shared-address neighbours. Pure functions, no DOM |
| `renderers.js` | Per-source cards for the "By source" section |
| `workbench.js` | Pieces shared by every mode: run log with progress, tiered ledger, facts panel, failed-source notice, run diff, result tabs, brief renderer, HTML export |
| `brief.js` | "At a glance": the rules-based written brief for Investigate and Recon. No model |
| `timeline.js` | Recon timeline: dated facts from WHOIS, certificate logs, TLS, the Wayback Machine, security.txt and the ASN registry, in order. Pure functions, no DOM |
| `casefile.js` | Portable case files: `buildCaseFile` for export, `parseCaseFile` to check an opened file (size, shape, target type, known keys) before it becomes a History entry |
| `report.js` | Investigation report: dossier card plus one scrolling report |
| `ai.js` | AI response normalization, the markdown renderer used by every report, and the AI panel's start state (one-click analysis, copy prompt, paste reply) |
| `tools.js` | Headers analyzer, dork builder, decoders (Base64, URL, hash, VIN) |
| `present.js` | Presentation rules with no DOM: the certainty grammar (tier word, color and line style), what an evidence card may say (`cardSnippet`), the verdict tiles (`investigateTiles`, `reconTiles`), History grouped by target (`groupHistory`, `lastRunDiff`) and the check on a thumbnail before it is shown (`safeThumb`, `boundAvatarHash`) |
| `md5.js` | MD5 for the hash decoder and Gravatar |

Design tokens and UI rules: `static/v2/DESIGN.md`.
