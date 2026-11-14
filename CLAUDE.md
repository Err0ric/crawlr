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
```

CI (`.github/workflows/ci.yml`) runs the same on Python 3.11. Use 3.11 locally to match `runtime.txt`.

## Layout

| Path | Holds |
|---|---|
| `main.py` | FastAPI app, middleware, router mounts, `/`, `/classic`, `/api/quota`, `/api/health` |
| `routers/` | HTTP endpoints, one file per area (recon, infra, analyze, hash, email, phone, vehicles) |
| `modules/` | One data source or tool per file (sherlock, maigret, dns, whois, ssl, ...) |
| `core/` | Shared helpers: logging, house AI key and quotas, subprocess limits |
| `middleware/` | Request ID and access log, security headers, soft rate limiting |
| `static/v2/` | Current UI: vanilla ES modules, no build step |
| `static/index.html`, `static/app.js`, `static/style.css` | Legacy v1 UI served at `/classic` |
| `tests/` | pytest suite plus `tests/js` for the frontend target detector |

## Rules for working in this repo

- Work on a branch and open a PR. Never push to `main`, never merge, never deploy. Railway deploys `main` automatically.
- The repo is public. No secrets in code, commits, issues or PR text. Local keys go in `.env` (gitignored).
- Do not write details of unfixed vulnerabilities into tracked files, issues or PRs. Keep them in `local/` (gitignored) until the fix ships.
- No em dashes in code comments, copy, docs or commit messages.
- Frontend: every remote value goes through `h`, `esc` or `link` from `static/v2/js/core.js`. Never write source data with raw `innerHTML`.
- Follow `static/v2/DESIGN.md` tokens and copy rules. Update it when a design decision changes.
- New modules: add the module in `modules/`, the endpoint in a router, a test in `tests/`, and a row in the README module table.
- Keep the responsible-use consent gate. Active techniques (anything that may notify the target) stay off by default and labeled.
- Ask Eric before adding a paid service, a new third-party data source, or a heavy dependency.

## Open work

`local/fable-kickoff.md` (gitignored) holds the latest review findings and the improvement plan.
