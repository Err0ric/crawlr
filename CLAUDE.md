# CrawlR

Browser-based OSINT investigation tool, live at https://crawlr.lol. Personal project of Eric Henderson. Public repo: https://github.com/Err0ric/crawlr.

Read `docs/ARCHITECTURE.md` for the code map and `static/v2/DESIGN.md` before touching the UI.

## Run it

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
cp .env.example .env            # optional: add GEMINI_API_KEY for the free AI tier
uvicorn main:app --reload --port 8000 --env-file .env
```

The app does not load `.env` on its own; `--env-file` does it (python-dotenv ships with `uvicorn[standard]`).

Open http://localhost:8000. Every non-AI module works with no keys.

## Test it

```bash
pytest -q
for f in static/v2/js/*.js; do node --check "$f"; done
node tests/js/detect.test.mjs
node tests/js/contrast.test.mjs
node tests/js/brief.test.mjs
node tests/js/timeline.test.mjs
node tests/js/casefile.test.mjs
node tests/js/phone.test.mjs
node tests/js/identity.test.mjs
node tests/js/evidence.test.mjs
node tests/js/links.test.mjs
node tests/js/adult.test.mjs
node tests/js/deep.test.mjs
node tests/js/minorscan.test.mjs
node tests/js/names.test.mjs
node tests/js/design.test.mjs
node tests/js/similar.test.mjs
node tests/js/modes.test.mjs
node tests/js/wildcard.test.mjs
node tests/js/casework.test.mjs
node tests/js/caserules.test.mjs
```

CI (`.github/workflows/ci.yml`) runs the same on Python 3.11. Use 3.11 locally to match `runtime.txt`.

## Layout

| Path | Holds |
|---|---|
| `main.py` | FastAPI app, middleware, router mounts, `/`, fingerprinted `/assets`, `robots.txt`, `sitemap.xml`, `/api/quota`, `/api/health` |
| `routers/` | HTTP endpoints, one file per area (recon, infra, analyze, hash, email, phone) |
| `modules/` | One data source or tool per file (sherlock, maigret, dns, whois, ssl, ...) |
| `core/` | Shared helpers: outbound request guard, input validation, error mapping, the AI call path, house AI key and quotas, logging, subprocess limits |
| `middleware/` | Request ID and access log, security headers, body size limit, rate limiting, client IP |
| `static/v2/` | The UI: vanilla ES modules, no build step. Self-hosted fonts in `fonts/`, d3 in `vendor/` |
| `tests/` | pytest suite plus `tests/js` for the target detector, the color contrast check, the brief rules, the recon timeline, case files and phone cases |

## Rules for working in this repo

- Work on a branch and open a PR. Never push to `main`, never merge, never deploy. Railway deploys `main` automatically.
- The repo is public. No secrets in code, commits, issues or PR text. Local keys go in `.env` (gitignored).
- Do not write details of unfixed vulnerabilities into tracked files, issues or PRs. Keep them in `local/` (gitignored) until the fix ships.
- No em dashes in code comments, copy, docs or commit messages.
- Frontend: every remote value goes through `h`, `esc` or `link` from `static/v2/js/core.js`. Never write source data with raw `innerHTML`. No inline scripts or event handlers: the CSP is `script-src 'self'`.
- Backend: any module that connects to a user-supplied host or URL goes through `core/netguard.py` (`safe_fetch` or `resolve_public_ip`). Usernames, emails and hosts go through `core/validate.py` before they reach a command line or an upstream URL. Failures are returned with `core.errors.error_fields`, never `str(exception)`.
- AI endpoints call `core.ai_call.run_ai`. AI never runs without an explicit click in the UI.
- A case file is outside data. It goes through `parseCaseFile` in `static/v2/js/casefile.js` before anything is shown or stored.
- A failed source is not a negative result. Keep "failed", "not found" and "found" as three separate states end to end. A site that blocks a check is "blocked", and a DNS lookup that errors is "unknown"; neither is "not found".
- An account that exists is not an account that belongs to the target. Profiles are grouped by person in `static/v2/js/identity.js`; facts and AI input come from the primary identity only.
- The primary identity is chosen by the rules or picked by the investigator (`collected.pick`, matched by members). After a pick, "primary" means the picked one, everywhere. A pick is a judgment, not a finding: label it as the investigator's on the page, in exports and in the AI payload, always with the automatic choice beside it. A pick never removes a row: another person's rows stay, filed as different, each with a check.
- Analysis and suggested next steps are rules (`static/v2/js/analysis.js`), never a model call. A suggestion is one hop on a click. Never suggest an adult or dating site, a people-search site or a data broker, and suggest nothing for a case the minor guard stopped.
- The pick, the pivot trail and parked steps are outside data when they come from History or a case file: read them with `readPick` and `readCasework`.
- Leads are followed one hop at a time and only on a click.
- Adult and dating sites are opt-in. The mode is off on every page load, held in memory only and never stored (not in localStorage, sessionStorage, a cookie, the URL, History or a case file). Once switched on it stays on for the page session, across cases, until it is switched off or the page is reloaded (`static/v2/js/modes.js`). A case records that a run had the mode on; that record never switches the mode on. With the mode off no path may query one: ask `core/adult_sites.py`. Results stay in their own group, text only, with no image of any kind. The minor guard has two stages and no override. The handle: `core.adult_guard.minor_indicated` refuses an age-specific token for 8 to 17 (`14yo`, `age16`, `16yrsold`) or one of three words, before the run, on every server path (a bare number never blocks, and bare years such as `16yrs` are only a soft signal). The profiles: the adult pass is its own request (`nsfw` with `adult_only`), made after the ordinary sources, and only when the scan of the profile text they found is clean: the page checks before it asks (`contentCheck` in `static/v2/js/evidence.js`), and `core.adult_guard.gate` checks again on the server from `core/profile_record.py` (kept per visitor under the `crawlr_run` session cookie, the only cookie the app sets) and wins. Unknown is not clean: without an answer from a source that reads profiles (Maigret or Platform check) there is no adult pass. Guard-only text on a row (`guard`) is read by the check and never stored, exported or sent to the AI. The rules live in one file, `static/v2/data/minor-rules.json`, applied by `core/minor_rules.py` and `static/v2/js/minorscan.js`: change a rule there, never in code, and keep `tests/test_minor_parity.py` passing (it needs node). Sherlock and Maigret run on the site lists that ship with the installed packages, so the queried set is known; regenerate `static/v2/js/adult-sites.js` when either package is upgraded.
- Every link gets a kind from `static/v2/js/links.js`. No finding links to a bare homepage, and no third-party URL carries a username or email in its query. `node tests/js/links.test.mjs` enforces both. The one exception is the "Search the web" group of a name case: link kind `search`, opened by the investigator, never evidence. A search the investigator should run on a value is offered as text to copy, not as a link. Archived copies are never offered for a profile address that carries a query.
- A name case holds candidates, not findings (`static/v2/js/names.js`). A candidate never becomes a fact, a cluster member or an avatar to compare, carries no picture, and nothing about it is fetched without a click. `node tests/js/names.test.mjs` enforces this.
- Tests never use the network. Recorded responses live in `tests/fixtures/` and `tests/js/fixtures/`; use invented names for private people.
- Do not log target values (usernames, emails, domains) on the server.
- Bulk DNS work (more than a handful of queries) goes through `core.dnspool.dns_thread`, not `asyncio.to_thread`.
- `phonenumbers` is imported only by `modules/phone_plan.py`, which runs in the short-lived worker (`python -m modules.phone_worker`). Never import it, or `phone_plan`, in the web process: its tables take about 115 MB.
- A phone lookup says what a number is (valid, country, line type, range assignment), never who uses it. No data brokers or paid people-search links. Only the area code and exchange go to the block source; the full number leaves the server only for NumLookup, with the visitor's own key.
- Recon checks return their own `findings` list (`level`: `flag`, `ok` or `info`). Only `flag` rows become ledger flags.
- Prompts are built by `investigation_prompt()` and `recon_prompt()` so the one-click and copy-prompt paths stay identical.
- Follow `static/v2/DESIGN.md` tokens and copy rules. Update it when a design decision changes.
- Line style carries certainty everywhere: solid means a source read or checked it, dashed means reported and unchecked. Purple is for the primary action, the brand, the active mode and focus rings only.
- A profile picture is shown only from the thumbnail the avatar comparison returns (`safeThumb` in `static/v2/js/present.js`). Never hotlink one, and never request a favicon or any image for an adult or dating row or a name candidate.
- New modules: add the module in `modules/`, the endpoint in a router (with a `RATE_LIMITS` entry if it is expensive), a test in `tests/`, and a row in the README module table.
- New colors or text styles: add them as tokens for both themes and keep `node tests/js/contrast.test.mjs` passing.
- Keep the responsible-use consent gate. Active techniques (anything that may notify the target) stay off by default and labeled. They are session modes like the adult one: never stored, off on every page load, each with its own switch and first-use confirmation ("Active techniques" in Investigate, "Port scan" in Recon), and one never switches on the other.
- Ask Eric before adding a paid service, a new third-party data source, or a heavy dependency.

## Open work

`local/fable-kickoff.md` (gitignored) holds the latest review findings and the improvement plan.
