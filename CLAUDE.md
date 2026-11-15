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
node tests/js/identity.test.mjs
node tests/js/evidence.test.mjs
node tests/js/links.test.mjs
node tests/js/adult.test.mjs
node tests/js/names.test.mjs
node tests/js/design.test.mjs
node tests/js/similar.test.mjs
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
| `tests/` | pytest suite plus `tests/js` for the target detector, the color contrast check, the brief rules, the recon timeline and case files |

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
- Leads are followed one hop at a time and only on a click.
- Adult and dating sites are opt-in per case and never remembered. With the mode off no path may query one: ask `core/adult_sites.py`. Results stay in their own group, text only, with no image of any kind. `core/adult_guard.py` runs before any such request and has no override. Sherlock and Maigret run on the site lists that ship with the installed packages, so the queried set is known; regenerate `static/v2/js/adult-sites.js` when either package is upgraded.
- Every link gets a kind from `static/v2/js/links.js`. No finding links to a bare homepage, and no third-party URL carries a username or email in its query. `node tests/js/links.test.mjs` enforces both. The one exception is the "Search the web" group of a name case: link kind `search`, opened by the investigator, never evidence.
- A name case holds candidates, not findings (`static/v2/js/names.js`). A candidate never becomes a fact, a cluster member or an avatar to compare, carries no picture, and nothing about it is fetched without a click. `node tests/js/names.test.mjs` enforces this.
- Tests never use the network. Recorded responses live in `tests/fixtures/` and `tests/js/fixtures/`; use invented names for private people.
- Do not log target values (usernames, emails, domains) on the server.
- Bulk DNS work (more than a handful of queries) goes through `core.dnspool.dns_thread`, not `asyncio.to_thread`.
- Recon checks return their own `findings` list (`level`: `flag`, `ok` or `info`). Only `flag` rows become ledger flags.
- Prompts are built by `investigation_prompt()` and `recon_prompt()` so the one-click and copy-prompt paths stay identical.
- Follow `static/v2/DESIGN.md` tokens and copy rules. Update it when a design decision changes.
- Line style carries certainty everywhere: solid means a source read or checked it, dashed means reported and unchecked. Purple is for the primary action, the brand, the active mode and focus rings only.
- A profile picture is shown only from the thumbnail the avatar comparison returns (`safeThumb` in `static/v2/js/present.js`). Never hotlink one, and never request a favicon or any image for an adult or dating row or a name candidate.
- New modules: add the module in `modules/`, the endpoint in a router (with a `RATE_LIMITS` entry if it is expensive), a test in `tests/`, and a row in the README module table.
- New colors or text styles: add them as tokens for both themes and keep `node tests/js/contrast.test.mjs` passing.
- Keep the responsible-use consent gate. Active techniques (anything that may notify the target) stay off by default and labeled.
- Ask Eric before adding a paid service, a new third-party data source, or a heavy dependency.

## Open work

`local/fable-kickoff.md` (gitignored) holds the latest review findings and the improvement plan.
