# CrawlR v2 design notes

Concept: the case file. An investigation is a case; the UI is a workbench. The target is a dossier header, sources are things you choose to pull, results are evidence filed by how sure each one is.

The goal of every change is a faster, clearer investigator workflow. Decoration is not a reason.

## The one idea: line style is certainty

Everything on a case page was either read by a source or only reported by one. That difference is drawn the same way everywhere:

- **Solid** means a source read or checked it.
- **Dashed** means it was reported and nothing checked it, or it could not be known.

Color then says which tier a row is in, and every tier also has a word, so neither line nor color is ever the only signal.

| Tier | Word on the pill | Color token | Line |
|---|---|---|---|
| Flags | Flag | `--flag` (amber) | solid |
| Linked | Linked | `--linked` (green) | solid |
| Exists (matches) | Matches | `--match` (teal) | solid |
| Exists (different person) | Different person | `--different` (muted) | solid |
| Unverified | Unverified | `--unverified` (gray) | dashed |

The grammar is defined once, in `CERTAINTY` in `static/v2/js/present.js`. It is used by the left edge of an evidence card, the certainty pill, the rail in a group heading, the verdict tiles, the identity header, the key on the landing page, and (since the link integrity work) the underline of a link: a URL a source read is solid, a templated URL nothing checked is dashed. A verdict tile whose count could not be known is dashed and says "unknown". A placeholder for a source that has not answered has a dashed outline and no tier color.

## Tokens (static/v2/css/app.css, section 1)

Dark is the default. Light tokens apply when the system asks for light (`prefers-color-scheme`) or the user picks Light in Settings (`data-theme` on `<html>`). The two light blocks must stay identical; the contrast test checks that.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | #16151f | #f7f6fb | the page |
| `--bg-raised` | #201f2b | #ffffff | a sheet: the case sheet, evidence cards, source cards, drawers |
| `--bg-sunken` | #121119 | #efedf6 | an inset: verdict tiles, inputs, the run log, site marks |
| `--bg-hover` | #262535 | #e8e5f2 | hover rows, tags, placeholder bars |
| `--line` | #2e2c3d | #d6d2e4 | decorative borders |
| `--line-strong` | #7a7693 | #7d7896 | borders that must be seen: inputs, switches, the ghost Cancel button (3:1) |
| `--ink` / `--ink-2` | #ece9f5 / #c7c3d6 | #1b1928 / #35324a | text, secondary text |
| `--ink-3` / `--ink-4` | #a6a2ba / #9a96b0 | #555169 / #5f5b74 | muted text / placeholders, disabled and struck-through rows |
| `--violet` | #a78bfa | #6d28d9 | the brand mark, the active mode, the focus ring |
| `--violet-2` / `--violet-3` | #7c3aed / #6d28d9 | same | the one primary button and its hover |
| `--flag` (= `--warn`) | #f5a623 | #8a3f03 | flags, caution |
| `--linked` (= `--ok`) | #4ade80 | #2a6a10 | linked, confirmed, good |
| `--match` | #22c7dc | #075985 | exists and matches |
| `--plate` | #ece9f5 | #ffffff | the light plate behind a site icon, so a dark icon shows on a dark page |
| `--different` | #a6a2ba | #555169 | exists, different person |
| `--unverified` | #9a96b0 | #5f5b74 | reported, nothing read (always with a dashed line) |
| `--bad` | #f87171 | #b91c1c | a failed source |
| `--switch-on` | #c7c3d6 | #35324a | a switch that is on |

`--flag-bg`, `--linked-bg` and `--match-bg` are the same colors at low alpha, for pills.

Linked and Matches sit side by side, so the contrast test also holds them at least 40 degrees of hue apart in both themes.

Every text token meets WCAG 2.2 AA (4.5:1) on every surface it sits on, in both themes, including muted text and the tinted pills; every card and tile edge meets 3:1 against the surface beside it. `node tests/js/contrast.test.mjs` enforces this and runs in CI. Add a token there when you add one here.

**Purple is reserved.** It appears on the primary action of a screen, the brand mark, the active mode in the nav, the skip link and focus rings. Nothing else is purple: links are ink with an underline, a selected tab is ink with a heavier weight, and a selected segment, pressed chip or switch is ink on the page color. This is what gives the one primary button its weight.

**Three surfaces.** The page, a sheet on it, and an inset inside a sheet. A case is one sheet at the top (header, verdict tiles, identity, "At a glance"), then the findings as groups that sit directly on the page with one card per row. Groups have no box of their own: a box around every group is what made every part of the page the same gray. No gradients, no shadows on cards (only on the things that float: the Sources panel and the phone drawer).

## Type

IBM Plex Sans for everything you read, IBM Plex Mono only for data (targets, handles, hashes, addresses, ports, counts on the verdict tiles, the run log). Both are self-hosted in `static/v2/fonts` (OFL 1.1) with `font-display: swap`; nothing loads from a font CDN.

Scale, in rem so it follows the user's font size setting:

| Token | Size | Role |
|---|---|---|
| `--fs-0` | 12px | captions, pills, chips, the "why here" line of a card |
| `--fs-1` | 13px | secondary text, facts on a card, compact rows |
| `--fs-2` | 15px | body, a card's site name |
| `--fs-3` | 17px | lead text, group headings, dialog titles, the name in the identity header |
| `--fs-4` | 21px | the case target on a phone |
| `--fs-5` | 27px | the case target, page titles, the number on a verdict tile |
| `--fs-6` | 34px | reserved; the landing headline scales from `--fs-5` to 44px |

Line-height 1.5. No all-caps labels. Nothing under 12px, with one exception: the five labels in the phone tab bar are 11px so they fit beside an icon.

Headings follow document order: one `h1` per view (the case target, or the empty-state title), `h2` for sections and ledger tiers, `h3` for cards.

Radius: 4 (tags, chips) / 6 (buttons, inputs, evidence cards, tiles) / 10 (sheets). Spacing on a 4px grid.

## One grid

Every page (landing, Investigate, Recon, Headers, Dorks, Decoders) sits in the same container: `--page-w` 1320px wide with a `--gutter` of 24px (16px under 760px). The top bar and the case bar are full-width bars whose content is held to the same container. 1320 leaves the findings column about 996px beside the 300px summary column, which keeps an evidence card on one or two lines without lines of text running past 110 characters.

The three tools share one layout: input on the left (5 parts), result on the right (6 parts), stacked under 960px. Decoders is four of those rows, one per conversion, each a sheet with its own input and result.

## Information architecture

One search box on the landing page takes any target and routes it by type. Two workbenches do the work:

- **Investigate**: people and handles (username, email, phone, hash, name).
- **Recon**: infrastructure (domain, IP, ASN).

Three **tools** need no target and are visually separated in the header: Headers, Dorks, Decoders. The landing page says where each kind of target goes.

## Layout

Results first. Each workbench is:

```
1440
[ brand | Investigate  Recon | Tools: Headers Dorks Decoders          AI  History  Settings ]
[ target ..................................... ] [ Run ] [ Sources 4 of 6 ]     case bar, sticky
  detected type, or a choice of types
+--------------------------------------------------------------+   What we know
| torvalds   Username, 47 findings, 7 sources    Export  New   |   (one identity at a time)
| [ 2 Linked ] [ 26 Exists ] [ 10 Unverified ] [ 3 Leads ]     |   AI analysis
| (pic) Linus Torvalds  (Primary identity)                     |   Purpose
|       why it is primary / member accounts / other people     |   Notes
| At a glance: Good ... Check ... Note ...                     |
+--------------------------------------------------------------+
  run log strip
  Findings (47) | By source (7)
  | Linked 2
  [x][pic] GitHub  torvalds  name | place | 12 repos | joined 2011     (Linked) Sherlock Maigret GitHub
           Why here  GitHub's own record for this handle
  : Unverified 10                                        (dashed rail, dashed card edge, dashed pill)
  [x][Ki ] Kick  torvalds  unverified URL                            (Unverified) Sherlock Maigret
           Reported by Sherlock, Maigret. Nothing was read.

390
[ brand                      AI  H  S ]
[ target                              ]
[ Run investigation ] [ Sources 4 of 6 ]
+------------------------------------+
| torvalds                           |
| Username, 47 findings ...          |
| [2 Linked][26 Exists][10 Unv][3 L] |
| [          Case details          ] |   opens What we know, AI, Purpose, Notes as a drawer
| (pic) Linus Torvalds ...           |
| At a glance ...                    |
+------------------------------------+
  Findings (47) | By source (7)
  cards stack: check, mark, text; pill and sources under the text
[ Investigate Recon Headers Dorks Decoders ]   tab bar
```

- The **case bar** replaced the left rail. The target and Run are always one glance away, and results get the width the rail used. Sources are a setting people change rarely, so they sit behind a button that shows how many are on. The panel is a plain disclosure: Escape and a click outside close it, and focus returns to the button.
- **Tabs** replaced the long page where source cards sat under the ledger. Tab labels carry counts.
- **Timeline** (Recon only) lists every dated fact a source returned, oldest first, with a Today row dividing what happened from what is due. Each row names its source and says how long ago or how soon. It shows only reported dates, and it is not built for person targets: a dated history of someone's accounts would be a profile.
- **Sources panel.** Every source carries one of three words for how it knows: `direct` (asks the system that holds the answer), `index` (a third party's copy, which can be out of date) or `heuristic` (inferred from how a site responds, so a hit is a lead). The legend sits at the top of the panel. Heuristic uses a dashed border so the difference is not carried by color.
- **Purpose** is one optional line above Notes: why the lookup is being done. It is saved with the case and printed on every export.
- Either workbench accepts any target. A domain typed in Investigate opens in Recon, and a username typed in Recon opens in Investigate, with a toast saying so. Choosing a type by hand ("search this domain as a username") turns the routing off for that run.
- With no case open the summary column is not shown: it has nothing to say, and the empty state gets the page.
- Under 1180px the summary column drops beneath the results.
- Under 760px the mode links move to a fixed bottom tab bar, History and Settings become icon buttons, the case bar scrolls with the page, and the sources panel becomes a bottom sheet above the tab bar.
- Long unbroken strings (a 60 character handle, name or address) wrap inside their box: the case header, tiles, identity header, brief, cards and History entries. Under 360px the tiles go two by two.
- Under 760px the summary column is a drawer. The case sheet shows the verdict tiles as a compact row of numbers with a **Case details** button under them, which opens What we know, AI analysis, Purpose and Notes from the top of the screen. It is a real dialog (`openSheet` in `ui.js`): the column itself is moved into the dialog and put back on close, so its fields and their state are the same ones. Focus moves in, Tab is trapped, Escape closes, the page behind is inert and does not scroll, and focus returns to the button. A dialog opened from inside the drawer (the prompt to copy by hand, a Deep Dive confirmation) sits over it: the drawer stays open and inert, and focus returns to the control inside it that opened the dialog.

Checked at 375, 390, 768, 1024 and 1440. Nothing scrolls sideways at any of them.

## The case sheet

One sheet at the top of a case, in this order.

**Case header.** The target in mono, then the type, the count and the source tally, then Export and New case.

**Verdict strip.** Up to four tiles, each a real count of the rows in a ledger group, built by `investigateTiles` and `reconTiles` in `present.js` from the same items the ledger draws. Each tile is a button that opens its group (or the By source tab) and moves focus there. The tiles wait for the run to finish, like the brief.

| Case | Tiles |
|---|---|
| Username | Linked, Exists, Unverified, Leads |
| Email | Linked, Breaches, Flags or Unverified, Leads. The third tile is Flags when the case has flags that are not breaches, otherwise Unverified |
| Hash | Verdict, Engines flagging it, Sources answered |
| Phone | Line type, Carrier, Flags |
| Name | Candidates, Directories answered, Handles to try, Public figure |
| Domain | Flags, Open ports, Subdomains, Expiring soon |
| IP address | Flags, Open ports, Expiring soon |

Three states are never merged on a tile. A count above zero is drawn in its tier color. **Zero** means every source the count depends on answered in full and found nothing: the number is muted and the tile is not a button to anywhere. **Unknown** means nothing was found and a source the count depends on did not fully answer: it failed, it answered only in part, or it was asked and had not answered when the run was cancelled. The tile is dashed, says "unknown" and opens By source. A count beside such a source is a lower bound: the tile shows "2+", reads "at least 2" to a screen reader and says why underneath. That caveat line is shown at every width; on a phone only the plain description lines are dropped. A tile whose source was not run says "not checked". The sources a cancelled run never heard from are saved with the case (`notAnswered`), so the tiles say the same when it is opened again. No tile is drawn while a run is in flight.

"At a glance" follows the same states: while any source did not fully answer, its count line starts "At least", names those sources and is tagged Note, never Good.

Why not Linked, Breaches, Flags, Leads on every case: breaches are only looked up for an email address and the Flags group of a person case holds nothing but breaches, so on a username case two of the four tiles could never be anything but empty. Each case type gets the four counts that can actually change.

**Identity header** (username and email cases). The mark (the server-made thumbnail, or initials), the name of the identity being shown, a pill ("Primary identity", "Different person", "Not tied to the target", "No name on these profiles", "No primary identity"), the sentence that says why, its member accounts as chips, and one button per person or profile group under the handle. A button and the select in What we know set the same view, and one person's facts never sit beside another's. With no primary identity the header says "Nobody is selected" and why.

**At a glance.** The rules-based brief, unchanged in what it says. Its tags are Check (amber), Good (green) and Note.

## Evidence cards

One component, `renderTiers` in `workbench.js`, for every ledger in Investigate and Recon.

```
[review box] [mark] Site name (the link)  handle   link state        [certainty pill] [source chips]
                    fact | fact | fact                               [row buttons]
                    "bio excerpt"
                    Why here  the reason this row is in this group
```

- **Mark.** The server-made thumbnail when the avatar comparison returned one, else the site's favicon, else the site's initials. The initials are always there underneath; an image covers them only once it has loaded.
- **Title.** The site name is the link, with the link rules unchanged (solid for a URL a source read, dashed plus the words "unverified URL" for a templated one, plain text plus "How to check" when there is no public page). The handle follows in mono.
- **Evidence line.** Only what a source returned for that profile: the name on it, the location, repo and follower counts, the year it was made, a bio excerpt. `cardSnippet` builds it and never fills anything in. When a profile carries none of these, the card says what kind of check found it ("Profile page read by Maigret. It carries no name, bio or dates." or "Reported by Sherlock. Nothing was read.").
- **Why here.** The reason the row sits in its group: "GitHub's own record for this handle", "same avatar image", "name does not conflict".
- **Pill and edge.** The tier word in the tier color, solid or dashed.
- **Handle taken.** Discord has no profile page; its sign-up check can only say that a handle is in use. That row stays in Unverified with the pill "Handle taken" and the dashed line (reported, nothing read), no link, the sentence "Discord's sign-up check says this handle is taken. Discord has no public profile page, so who holds it is unknown." and the how-to-check hint. It is never drawn as a read profile and counts nowhere but the Unverified tile. Reddit, which refuses servers, is an Unverified row that says "Blocked by site" with the reason, a dashed link to the profile and how to check it by hand.
- **After the link check.** A templated URL the link check looked at stays in Unverified, because nothing was read about who owns the page, but the row stops saying that nothing checked it (`rowCertainty` in `present.js`). *Page checked*: the pill reads "Page checked" with a solid neutral line and the card edge turns solid neutral, matching the link, which is now solid. *Page not found*: a greyed, struck pill "Page not found" and a muted solid edge; the row moves to the end of its group. *Blocked by site* and *could not be checked* stay dashed "Unverified", with the reason on the row. The Unverified tile says how many pages were checked ("reported, 3 pages checked").
- **Source chips.** One per source that named the site.

Account rows are cards. Leads, hosts on a domain, known noisy sites, name candidates and Recon's inventory rows stay compact rows: the same surface and edge, one line, no mark and no pill. Recon's flags carry the Flag pill.

**Pictures.** A profile picture is never loaded from the site that hosts it: that would send the investigator's address to that host. The avatar comparison already fetches each picture on the server, and now returns a 48 pixel grayscale thumbnail with it. Grayscale is deliberate: it is enough to recognise a picture, it reads as a photocopy in a file, and it is a third of the bytes. A placeholder picture gets no thumbnail. The AI report's header uses the same thumbnail. There is one place in the JS that writes an image element, `mark` in `core.js`, and a test fails if another appears; the HTML export removes any image that is not an embedded thumbnail.

**Site icons.** The only remote image is a site's icon from the icon service, and the rules for it are in `iconDomain` and `mayFavicon` in `present.js`:

- Only account rows get one. Leads, host inventory, Recon rows, name candidates and adult and dating rows never do: they show initials.
- The icon is asked for by the site's registrable domain, never a subdomain (some sites put the handle there) and never a domain that has the handle as a label.
- Never for an IP address, a single-label name or an internal name.
- A case opened from a case file asks for no icon at all until the investigator runs it: its hosts were chosen by whoever made the file.
- The icon sits on a light plate so a dark icon shows on the dark page, and the initials stay underneath until it has loaded.

**Storage.** Thumbnails are saved with the case in History and in an exported case file, at most 30 per case, each checked by `safeThumb`. When the browser's storage is full they are the first thing dropped: from older runs, then from the run being saved, and only then is the older half of History dropped (`writeHistory`). A case without its thumbnails shows initials.

**Placeholders.** While a run is in flight, the ledger ends with three placeholder rows under a line that names the sources still out, and By source holds one placeholder card per pending source. They have a dashed outline, no tier color, no review box and no numbers, so they cannot be read as results. They are hidden from screen readers, which get the run log's polite live region. They pulse gently, and not at all under `prefers-reduced-motion`.

## Empty states and examples

An empty page is centered: one sentence on what the page does, then example targets as buttons. An example fills the box and never runs anything.

- Investigate: a handle, an address, a file hash, a name. Recon: a domain, an IP address, an ASN.
- Headers: "Load a sample" fills the box with an invented header block built from documentation domains and address ranges.
- Landing: "Try one" is a single row that scrolls sideways inside its container when it does not fit. Each example is labelled with its type and opens the workbench it belongs to with the box filled, so the domain example opens Recon.
- The landing page opens with what CrawlR does in its own terms, and a key, "How to read a case", that shows the five tiers with their line styles.

## History

History shows one entry per target and workbench (`groupHistory`), newest first: the target, the workbench, how many runs, when the last one was, and what changed between the last two runs ("2 new, 0 gone since the run before", from the same finding keys the re-run notice uses). The entry opens the latest run. An entry with more than one run has "Show the N runs", which lists each run with its own open and delete buttons, under a "Delete all N runs" button that asks first. A single run is deleted from its entry. The workbench is named in sentence case (Investigate, Recon, Email headers). "From a case file" is marked on the entry and on the run. Grouping is how History is drawn: nothing stored is merged, migrated or removed.

## Results

- Findings first. The run log is a one-line strip above them once a run completes. It stays open if a source failed.
- While running: "3 of 7 sources done", a bar, a clock, and a timer on each running source. Results appear as each source answers. The Run button becomes **Cancel run**, a ghost button (transparent, a visible line, ink text) with a turning mark: stopping a run is not a second primary action, and the run log, `aria-busy` on the results and the placeholders say that a run is in flight.
- States that are never merged: **read** (a profile or record was read), **unverified**, **blocked by site**, **not found**, **failed**. A failed source gets a red row in the log, a notice above the findings, and its own card state. Raw upstream error text is only ever behind a "details" toggle.
- Ledger tiers: Flags, Linked, Exists (matches), Exists (different person, collapsed), Unverified, Leads from profiles, Similar handles (collapsed), Hosts on the email's domain (collapsed), Known noisy sites. Each row says why it sits where it does ("same name", "GitHub's own record for this handle", "Blocked by site").
- **What we know** shows one person at a time. A labelled select switches between the people who share the handle; the primary identity is first and the panel says why it is primary. Facts from different people are never mixed.
- **Links say what they are.** Every external link opens in a new tab with `rel="noopener noreferrer nofollow"` and an external-link icon. A URL that a source read is a solid link. A URL built from a site template that nothing checked has a dashed underline and the words "unverified URL" beside it (never a tooltip alone). A site with no public profile page, or a link that is only a homepage, is plain text with a "How to check" hint. Evidence links ("DNS lookup", "InternetDB record", "RDAP record", "Certificate logs") point at the public page where a claim can be checked, and never carry a username or email in the query. The outbound searches of a name case are a kind of their own (`search`): they carry the name on purpose and are never evidence.
- **Link check.** When a group is opened or scrolls into view, its unverified URLs are checked in place: "page checked", "page not found" (greyed, moved to the end, never removed), "Blocked by site" or "could not be checked". Rows do not change tier or height while this runs.
- **Adult and dating sites** are opt-in per case. The switch is off for every new case, on reload and when a case is opened, and is never stored. With it on, results sit in their own collapsed group after Unverified, with a count and one line: "Adult and dating sites are existence checks only. A match shows a handle is taken there, not who owns it." Rows are text: a badge with the site's initials, never a favicon, avatar, thumbnail or preview, in any view or export. They never enter the other tiers, What we know, identities, leads or the avatar comparison. Exports and the AI see them only when the case had the mode on, in a section labelled "Adult and dating sites (existence checks only)". A handle that suggests a minor disables the switch and says why.
- **Name cases.** A name is shared by many people, so a name search lists candidates, never findings. The results open with one line, always: "A name is shared by many people. Everything below is a candidate to look at, not a finding about one person." Groups, in order: Public figure (only when Wikidata has an exact match), People with this name (the directories' rows, best name fit first, each saying how the name fits and which typed details it matches), Handles to try (collapsed when there are candidates) and Search the web. The header and the tab count candidates, not findings. What we know says "No single person is selected" and shows no facts. Nothing is followed on its own: "Show profile" loads one GitHub profile (announced through a polite live region, with only that row redrawn and focus left where it is), "Investigate this" starts one username case, and a search link opens on another site with the name in it, which its group says. Three optional boxes under the target (Location, Employer or school, Keyword) rank the rows and are never sent to a directory. A directory that failed or was rate limited is named as unknown, never as "nobody by this name", and one that was not asked is not listed. When the list is capped a directory says "8 found, 6 shown". No picture or favicon is shown for a candidate in any view or export, and the adult mode switch and the link check are not offered.
- **Similar handles** are a group of their own after Leads from profiles, collapsed, in username and email cases: "Handles close to this one. Nothing has been checked. Check one to see whether its name or picture lines up with this case." A row is the handle in mono, the reason it was built in plain words, and two buttons: "Check" and "Investigate this" (a separate case). There is no "check all": one click, one handle. A checked row shows one sentence on what was found, then each profile that was read as a small evidence card on an inset (mark from the server's thumbnail or initials, never a site icon; site link; handle; the facts line; the line-up in words with the fact it rests on), then every source that read nothing grouped by state, so a blocked site is not read as absent. The card's pill is "Same picture" or "Links back" (Linked color), "Same name" (Matches color, with "A name alone is supporting, not proof."), "Name conflicts" (Different person color) or "Nothing to compare" (neutral), always solid because a profile was read. Only a profile that lines up has "Add to this case"; an added one says "Added" and has "Remove from this case", in the group and on its row in the ledger. An added row sits in the tier the identity rules give it and says "Added from the similar handle erroric: same picture as the GitHub profile." Loading and the outcome are announced through the polite live region with the handle in the message, only that row is redrawn while a handle is checked, and after adding or removing every group stays open or closed as it was and focus goes to the button that undoes the action. Similar handles are in no tile and no count, and the brief gets one line only after a check.
- **Leads** are places to look next, not findings. A handle or address lead has "Investigate this", a domain has "Open in Recon". Nothing is followed without a click, and a lead never starts another lead.
- An email case does not run the username tools on the part before the @. That part is offered as a lead.
- One count, one function: the case header, the run log summary and the By source tab all read `sourceTally`. Every source that ran has a card, including ones that found nothing or failed.
- Search and tool inputs opt out of browser and password manager autofill. The key fields in Settings do not. Recon: Flags, Exposed services, Subdomains, Lookalike domains, Unrelated neighbours on a shared address (collapsed). A domain with no MX is "not graded" for email, with the null-mail records shown as a note.
- **At a glance** sits above the tabs once a run finishes: a few sentences built from rules, each tagged Check, Good or Note. It never appears mid-run, so it never describes half a picture. It states what sources returned and does not guess; where profiles under one handle carry different names it says they may be different people.
- The topology graph is drawn in neutral ink tones from the tokens. Purple and amber mean the primary action and a flag on a case page, so the graph uses neither; a node says what it is in its own label (A, NS, the host or address), the legend names the kinds, and a Cloudflare address carries a CF badge.
- The AI report's account tiles and their legend use the ledger's grammar (`rowCertainty`): tier color on the tile's edge, dashed when nothing read the account, and the legend is the same pills.
- In the topology graph a node is a button. Selecting one shows a bar with what can be done: run recon on it, or open it. One click is one run; nothing expands on its own.
- Re-running a target shows what is new and what is gone since the last local run. This is manual only; CrawlR does not watch targets.

## AI

AI never runs on its own. The AI panel shows a button and, under it, what pressing it costs ("Uses 1 of your 5 free analysis credits left today" or "Uses your Claude key"). An identical re-run reuses the last report and says so.

Pasting an API key into a website is a lot to ask, so the panel always offers a second path that needs none: **Copy prompt** puts the full prompt (instructions plus the findings) on the clipboard for any assistant the person already uses, and a box takes the reply back and formats it as the same report. If the browser blocks the clipboard, the prompt opens in a dialog to copy by hand.

## Rules

- Every remote value goes through `h`/`esc`/`link` in `core.js`. No raw `innerHTML` with source data. No inline scripts or event handlers (the CSP is `script-src 'self'`).
- Green means linked or confirmed, teal means exists and matches, amber means a flag or caution, red means a failed source. Purple is never a state. Color is never the only signal: every state also has a word, and certainty also has a line style.
- Motion only answers an action (toggle, collapse, toast, progress). No entrance animations. `prefers-reduced-motion` turns all of it off.
- Copy is sentence case, active voice, names the action: "Run investigation", "New case", "Clear all history". No em dashes.
- Empty states say what to do next, errors say what happened and how to fix it.

## Accessibility (WCAG 2.2 AA)

- Every flow works from the keyboard. Focus is always visible (2px violet ring) and never hidden under the sticky header or the tab bar (`scroll-padding`). On a finished case the order is: target, Run, Sources, type, Export, New case, the verdict tiles, the people in the identity header, the run log, the result tabs, then each group heading followed by its rows (review box, then the row's link and buttons), then the summary column.
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
