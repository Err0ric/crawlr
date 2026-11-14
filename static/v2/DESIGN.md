# CrawlR v2 design notes

Concept: the case file. An investigation is a case; the UI is a workbench. The target is a dossier header, sources are things you choose to pull, results are evidence ranked by how much they tell you. One memorable element (the ranked ledger), everything else quiet.

The goal of every change is a faster, clearer investigator workflow. Decoration is not a reason.

## Tokens (static/v2/css/app.css, section 1)

Dark is the default. Light tokens apply when the system asks for light (`prefers-color-scheme`) or the user picks Light in Settings (`data-theme` on `<html>`). The two light blocks must stay identical; the contrast test checks that.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | #16151f | #f7f6fb | page |
| `--bg-raised` | #201f2b | #ffffff | cards, sheets, drawers |
| `--bg-sunken` | #121119 | #efedf6 | inputs, run log |
| `--bg-hover` | #262535 | #e8e5f2 | hover rows, tags |
| `--line` | #2e2c3d | #d6d2e4 | decorative borders |
| `--line-strong` | #7a7693 | #7d7896 | borders that must be seen: inputs, switches (3:1) |
| `--ink` / `--ink-2` | #ece9f5 / #c7c3d6 | #1b1928 / #35324a | text, secondary text |
| `--ink-3` / `--ink-4` | #a6a2ba / #9a96b0 | #555169 / #5f5b74 | muted text / placeholders and disabled |
| `--violet` | #a78bfa | #6d28d9 | links, selected state, focus ring |
| `--violet-2` / `--violet-3` | #7c3aed / #6d28d9 | same | the one primary button and its hover |
| `--ok` / `--warn` / `--bad` | #34d399 / #f59e0b / #f87171 | #03603f / #8a3f03 / #b91c1c | confirmed / caution / failed |

Every text token meets WCAG 2.2 AA (4.5:1) on every surface it sits on, in both themes, including the tinted chip backgrounds. `node tests/js/contrast.test.mjs` enforces this and runs in CI. Add a token there when you add one here.

Why `--ink-3` and `--ink-4` changed: the old `--ink-4` (#8b87a3) was 4.36:1 on `--bg-hover`. Both were lightened, and `--ink-4` is now reserved for placeholders, disabled controls and struck-through rows. Muted body text uses `--ink-3`.

## Type

IBM Plex Sans for everything you read, IBM Plex Mono only for data (targets, hashes, emails, ports, run log). Both are self-hosted in `static/v2/fonts` (OFL 1.1) with `font-display: swap`; nothing loads from a font CDN.

Scale, in rem so it follows the user's font size setting:

| Token | Size | Role |
|---|---|---|
| `--fs-0` | 12px | captions, tags, source labels |
| `--fs-1` | 13px | secondary text, ledger rows |
| `--fs-2` | 15px | body, card titles |
| `--fs-3` | 17px | lead text, dialog titles |
| `--fs-4` | 21px | case title |
| `--fs-5` | 27px | page title |
| `--fs-6` | 34px | landing headline |

Line-height 1.5. No all-caps labels. Nothing under 12px, with one exception: the five labels in the phone tab bar are 11px so they fit beside an icon.

Headings follow document order: one `h1` per view (the case target, or the empty-state title), `h2` for sections and ledger tiers, `h3` for cards.

Radius: 4 (tags) / 6 (buttons, inputs) / 10 (cards). Spacing on a 4px grid.

## Information architecture

One search box on the landing page takes any target and routes it by type. Two workbenches do the work:

- **Investigate**: people and handles (username, email, phone, hash, name).
- **Recon**: infrastructure (domain, IP, ASN).

Three **tools** need no target and are visually separated in the header: Headers, Dorks, Decoders. The landing page says where each kind of target goes.

## Layout

Results first. Each workbench is:

```
case bar   [ target ............ ] [ Run ] [ Sources 4 of 5 ]      sticky under the header
           detected type, or a choice of types
main       case title, run log strip, "At a glance", report        | summary column (300):
           tabs: Findings | By source | (Timeline, Topology)      | What we know, AI, Purpose, Notes
```

- The **case bar** replaced the left rail. The target and Run are always one glance away, and results get the width the rail used. Sources are a setting people change rarely, so they sit behind a button that shows how many are on. The panel is a plain disclosure: Escape and a click outside close it, and focus returns to the button.
- **Tabs** replaced the long page where source cards sat under the ledger. Tab labels carry counts.
- **Timeline** (Recon only) lists every dated fact a source returned, oldest first, with a Today row dividing what happened from what is due. Each row names its source and says how long ago or how soon. It shows only reported dates, and it is not built for person targets: a dated history of someone's accounts would be a profile.
- **Sources panel.** Every source carries one of three words for how it knows: `direct` (asks the system that holds the answer), `index` (a third party's copy, which can be out of date) or `heuristic` (inferred from how a site responds, so a hit is a lead). The legend sits at the top of the panel. Heuristic uses a dashed border so the difference is not carried by color.
- **Purpose** is one optional line above Notes: why the lookup is being done. It is saved with the case and printed on every export.
- Either workbench accepts any target. A domain typed in Investigate opens in Recon, and a username typed in Recon opens in Investigate, with a toast saying so. Choosing a type by hand ("search this domain as a username") turns the routing off for that run.
- Under 1180px the summary column drops beneath the results.
- Under 760px the mode links move to a fixed bottom tab bar, History and Settings become icon buttons, the case bar scrolls with the page, and the sources panel becomes a bottom sheet above the tab bar.

Checked at 375, 768, 1024 and 1440.

## Results

- Findings first. The run log is a one-line strip above them once a run completes. It stays open if a source failed.
- While running: "3 of 7 sources done", a bar, a clock, and a timer on each running source. Results appear as each source answers. The Run button becomes Cancel.
- States that are never merged: **read** (a profile or record was read), **unverified**, **blocked by site**, **not found**, **failed**. A failed source gets a red row in the log, a notice above the findings, and its own card state. Raw upstream error text is only ever behind a "details" toggle.
- Ledger tiers: Flags, Linked, Exists (matches), Exists (different person, collapsed), Unverified, Leads from profiles, Hosts on the email's domain (collapsed), Known noisy sites. Each row says why it sits where it does ("same name", "GitHub's own record for this handle", "Blocked by site").
- **What we know** shows one person at a time. A labelled select switches between the people who share the handle; the primary identity is first and the panel says why it is primary. Facts from different people are never mixed.
- **Links say what they are.** Every external link opens in a new tab with `rel="noopener noreferrer nofollow"` and an external-link icon. A URL that a source read is a solid link. A URL built from a site template that nothing checked has a dashed underline and the words "unverified URL" beside it (never a tooltip alone). A site with no public profile page, or a link that is only a homepage, is plain text with a "How to check" hint. Evidence links ("DNS lookup", "InternetDB record", "RDAP record", "Certificate logs") point at the public page where a claim can be checked, and never carry a username or email in the query. The outbound searches of a name case are a kind of their own (`search`): they carry the name on purpose and are never evidence.
- **Link check.** When a group is opened or scrolls into view, its unverified URLs are checked in place: "page checked", "page not found" (greyed, moved to the end, never removed), "Blocked by site" or "could not be checked". Rows do not change tier or height while this runs.
- **Adult and dating sites** are opt-in per case. The switch is off for every new case, on reload and when a case is opened, and is never stored. With it on, results sit in their own collapsed group after Unverified, with a count and one line: "Adult and dating sites are existence checks only. A match shows a handle is taken there, not who owns it." Rows are text: a badge with the site's initials, never a favicon, avatar, thumbnail or preview, in any view or export. They never enter the other tiers, What we know, identities, leads or the avatar comparison. Exports and the AI see them only when the case had the mode on, in a section labelled "Adult and dating sites (existence checks only)". A handle that suggests a minor disables the switch and says why.
- **Name cases.** A name is shared by many people, so a name search lists candidates, never findings. The results open with one line, always: "A name is shared by many people. Everything below is a candidate to look at, not a finding about one person." Groups, in order: Public figure (only when Wikidata has an exact match), People with this name (the directories' rows, best name fit first, each saying how the name fits and which typed details it matches), Handles to try (collapsed when there are candidates) and Search the web. The header and the tab count candidates, not findings. What we know says "No single person is selected" and shows no facts. Nothing is followed on its own: "Show profile" loads one GitHub profile, "Investigate this" starts one username case, and a search link opens on another site with the name in it, which its group says. Three optional boxes under the target (Location, Employer or school, Keyword) rank the rows and are never sent to a directory. A directory that failed or was rate limited is named as unknown, never as "nobody by this name". No picture or favicon is shown for a candidate in any view or export, and the adult mode switch and the link check are not offered.
- **Leads** are places to look next, not findings. A handle or address lead has "Investigate this", a domain has "Open in Recon". Nothing is followed without a click, and a lead never starts another lead.
- An email case does not run the username tools on the part before the @. That part is offered as a lead.
- One count, one function: the case header, the run log summary and the By source tab all read `sourceTally`. Every source that ran has a card, including ones that found nothing or failed.
- Search and tool inputs opt out of browser and password manager autofill. The key fields in Settings do not. Recon: Flags, Exposed services, Subdomains, Lookalike domains, Unrelated neighbours on a shared address (collapsed). A domain with no MX is "not graded" for email, with the null-mail records shown as a note.
- **At a glance** sits above the tabs once a run finishes: a few sentences built from rules, each tagged Check, Good or Note. It never appears mid-run, so it never describes half a picture. It states what sources returned and does not guess; where profiles under one handle carry different names it says they may be different people.
- In the topology graph a node is a button. Selecting one shows a bar with what can be done: run recon on it, or open it. One click is one run; nothing expands on its own.
- Re-running a target shows what is new and what is gone since the last local run. This is manual only; CrawlR does not watch targets.

## AI

AI never runs on its own. The AI panel shows a button and, under it, what pressing it costs ("Uses 1 of your 5 free analysis credits left today" or "Uses your Claude key"). An identical re-run reuses the last report and says so.

Pasting an API key into a website is a lot to ask, so the panel always offers a second path that needs none: **Copy prompt** puts the full prompt (instructions plus the findings) on the clipboard for any assistant the person already uses, and a box takes the reply back and formats it as the same report. If the browser blocks the clipboard, the prompt opens in a dialog to copy by hand.

## Rules

- Every remote value goes through `h`/`esc`/`link` in `core.js`. No raw `innerHTML` with source data. No inline scripts or event handlers (the CSP is `script-src 'self'`).
- Green means confirmed, amber means caution, red means failed. Nothing else gets a state color, and color is never the only signal: every state also has a word or an icon.
- Motion only answers an action (toggle, collapse, toast, progress). No entrance animations. `prefers-reduced-motion` turns all of it off.
- Copy is sentence case, active voice, names the action: "Run investigation", "New case", "Clear all history". No em dashes.
- Empty states say what to do next, errors say what happened and how to fix it.

## Accessibility (WCAG 2.2 AA)

- Every flow works from the keyboard. Focus is always visible (2px violet ring) and never hidden under the sticky header or the tab bar (`scroll-padding`).
- Dialogs (modal, drawer) move focus in, trap Tab, make the page behind inert, close on Escape and return focus to the opener. The consent gate is the one dialog that cannot be dismissed: it has no close button and ignores Escape and backdrop clicks.
- Tabs (Recon views) are a real tablist with `aria-controls`, one tab stop and arrow keys. Single-choice groups (target type, AI provider, theme) are radiogroups with the same keyboard model. Use `roving()` from `core.js` for new ones.
- Every input has a label. Switches are `role="switch"` named by their source.
- Pointer targets are at least 24 by 24 CSS pixels.
- Run progress is announced through a polite live region; `aria-busy` marks the results while a run is in flight.
- Links inside text are underlined, so they are not identified by color alone.

## Print and export

Purpose, notes and the collection time are mirrored into a `.print-only` block, because inputs print badly and are stripped from the HTML export. The timeline prints under its own heading.

The JSON export is a **case file**. "Open a case file" in History reads one back in the browser (never uploaded), checks it and adds it to History marked "from a case file". A file that is refused gets a dialog saying why, and History stays open.

"Print or PDF" uses a print stylesheet: light, no chrome, every tier expanded, link URLs printed after their text. The HTML export is the same markup in one self-contained file. Both carry a line saying findings can be wrong and possible items are leads.
