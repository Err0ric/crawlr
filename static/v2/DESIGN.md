# CrawlR v2 design notes

Concept: the case file. An investigation is a case; the UI is a workbench. The target is a dossier header, sources are things you choose to pull, results are evidence ranked by how much they tell you. One memorable element (the ranked ledger), everything else quiet.

## Tokens (static/v2/css/app.css, section 1)

| Token | Value | Use |
|---|---|---|
| `--bg` | #16151f | page |
| `--bg-raised` | #201f2b | cards, rails on mobile |
| `--bg-sunken` | #121119 | inputs, run log |
| `--bg-hover` | #262535 | hover rows, tags |
| `--line` | #2e2c3d | all borders |
| `--ink` / `--ink-2` / `--ink-3` / `--ink-4` | #ece9f5 / #c7c3d6 / #9b97ae / #8b87a3 | text, secondary, muted, dimmest (AA on bg at 12px+) |
| `--violet` / `--violet-2` | #a78bfa / #7c3aed | links, selected state / the one primary button |
| `--ok` / `--warn` / `--bad` | #34d399 / #f59e0b / #f87171 | confirmed only / flags and caution / errors |

Type: IBM Plex Sans for everything you read, IBM Plex Mono only for data (targets, hashes, emails, ports, run log). Scale 12/13/15/17/21/27/34, line-height 1.5. No all-caps labels, nothing under 12px.

Radius: 4 (tags) / 6 (buttons, inputs) / 10 (cards). Spacing on a 4px grid.

## Layout

Desktop: rail (272) | main | aside (300). Rail and aside are sticky and scroll on their own. Under 1180px the aside drops beneath the main column; under 760px the rail becomes a bottom sheet behind a "Target & sources" button.

## Rules

- Every remote value goes through `h`/`esc`/`link` in `core.js`. No raw `innerHTML` with source data.
- Green means confirmed, amber means caution, nothing else gets a state color.
- Motion only answers an action (toggle, collapse, toast). No entrance animations.
- Copy is sentence case, active voice, names the action: "Run investigation", "New case", "Clear all history".
- Empty states say what to do next, errors say what happened and how to fix it.
