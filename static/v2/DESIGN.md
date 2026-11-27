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
  detected type, or a choice of types    (o) Adult sites   (o) Active techniques [caution]
  | Adult sites on for this session.  Turn off                    only while a mode is on
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
  detected type
  (o) Adult sites  (o) Active techniques
  | Adult sites on for this session. Turn off
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
- **Session modes.** Two opt-ins sit in the case bar, on the row under the target beside the detected-type chips: "Adult sites" and "Active techniques" (with its amber "caution" tag). Each is the existing switch primitive with a label and a one-line description as visible text at every width; on a phone the two sit side by side under the chips. They are settings, not the action, so they are ink like every other switch and never purple. Recon's bar has one switch of its own, "Port scan" ("Connects to 20 common ports. May notify the target."), also with the "caution" tag. It is a separate mode from Investigate's "Active techniques", with its own state, confirmation and status line: switching one on never switches the other on, so a click in Investigate cannot arm a port scan in Recon. The same switches close the list in the Sources sheet (in Recon, the port scan's row is the Port scan switch), so the sheet stays complete: one state, drawn in two places, and the Sources count includes them.
  - **The session rule.** All three are off when the page loads. Once switched on, a mode stays on for every case in that page session, across another handle, "Investigate this" on a lead, a similar handle or a name candidate, New case, and a case opened from History or a case file, until it is switched off or the page is reloaded. It is held in memory only (`modes.js`): never in localStorage, sessionStorage, a cookie, the URL, History or a case file. A case records that a run had adult mode on, so its rows can be shown and exported; that record never switches the mode on. An old stored "active" or port scan preference is ignored and removed.
  - **The status line.** While a mode is on, a quiet line says so on every case: "Adult sites on for this session.", "Active techniques on for this session. May notify the target." or, in Recon, "Port scan on for this session. May notify the target.", each with a "Turn off" link-style button. It is ink text with a neutral left rule. It is a slim strip of its own between the case bar and the results, stuck under the top bar (and under the case bar where that is sticky), so it stays in view at every width: on a phone the case bar scrolls away, and the line must still be on screen at a lead's or a similar handle's button. It is always in the page and is drawn only when it has something to say (hidden by `:empty`, never by `hidden`), so it works as a polite live region. A mode is on for the session wherever the investigator is, so each workbench also names the other's modes: Investigate says "Port scan on (Recon)." and Recon says "Adult sites on (Investigate)." and "Active techniques on (Investigate).", each with its Turn off. The same lines are repeated at the top of the Case details drawer on a phone, where Deep Dive lives. While a run is in flight the line adds "A run is in progress: a change applies from the next run.": what a run does about the modes is decided when it starts. Turn off moves focus to the switch it stood for (in the drawer, to the drawer's close button).
  - **First use.** The first time each mode is switched on in a page session, a confirmation says what it does and that it stays on until switched off or the page is reloaded. Adult sites: asked after the ordinary sources, existence checks only, text only, not for a handle that states an age under 18 and not when a profile found for the handle suggests a minor, lawful purposes. Active techniques: CrawlR will fetch the target's own profile pages for a Deep Dive, which the target's services may log. Port scan: CrawlR will scan 20 common ports on the target host on every Recon run, which the target's services may log. Neither confirmation covers the other mode. Confirming turns the mode on; Cancel, Escape and the close button leave it off, and the switch goes back. It is not asked again in that session once accepted.
  - **Honest per case.** Whether a mode applies is said per case, in place of the description under the switch and in the status line. Adult sites applies to username cases only: for an email, hash, phone or name case it stays on and says "Not used for this kind of target." Active techniques says "Not used for this kind of target." for anything but a username case, and Port scan says it for an ASN.
  - **The minor guard: two stages, no override.** The rules (every pattern and threshold) are one file, `static/v2/data/minor-rules.json`, which the page fetches at startup and the server reads from disk; `minorscan.js` and `core/minor_rules.py` are the same small engine and hold no rule of their own. Without the file the adult mode cannot be switched on ("Adult sites cannot be switched on: the rules that keep them away from minors could not be loaded. Reload the page.") and the server refuses every adult pass. English only.
    1. **The handle, before the run (narrow).** Only an age-specific token for 8 to 17 blocks: digits then yo, y/o, y.o, y_o (`14yo`, `15y/o`, `15_y_o`), digits then years with "old" (`16yrsold`, `13yearsold`, `17_years_old`), or "age"/"aged" then digits at the start of the handle or after "my", "im" or a single letter (`age16`, `age14jay`, `my_age_14`, `x_age_16`). One of three words blocks too (underage, preteen, jailbait). A bare number never blocks anything: `gamer13`, `sk8r_15`, `10outof10` and `err0ric17` run. So do `7yo` and `3yo_dad` (under the floor), `stone_age_12` and `new_age_17` ("age" inside a phrase) and `mom_of_16yo` (an age about someone else). Years with no "old" (`16yrs`, `10yrs_exp`, `12years_sober`, `15yrsInfosec`) never block by themselves: for 8 to 17 they are a soft signal, like a birth year. The switch says "Not checked for this handle: it states an age under 18." and the status line "Adult and dating sites are not checked for this handle: the handle states an age under 18."
    2. **The profiles, after the ordinary sources (the main guard).** The adult pass is its own set of requests and waits for everything that returns profile text. The page then reads the display names, bios and further text fields that were found (Maigret, GitHub with its company and location, the platform check, profile enrichment; never an address, a handle or anything adult) for a stated age under 18 ("I'm 15", "15 y/o", "age 16", "fifteen years old", "just turned 16", "16 | she/her" at the start of a bio, "she/her 16"), a school level ("middle school", "junior in high school", "8th grade", "year 9", "Lincoln High '28", a class year with school context or five or more years ahead), a birth date under 18 ("born 2010", "bday 3/4/10", a cake emoji with a date, a birthday field) or "minor" as a self-description. Fancy digits and letters are folded to plain ones first. Adult framings do not count ("8th grade teacher", "mom of a 9th grader", "class of 2012", "Rex is 14 years old", "minors DNI"). Only a clean check starts the adult requests. Two soft signals in the handle do nothing alone and block together with a weaker sign in a profile ("freshman", "school", a near class year such as "class of 2029" with no school named): a year that makes the person under 18 today (6 to 17 years back, so 2009 on in 2026) and bare years (`16yrs`). A bare "student" or "teen" is not a sign at all: "CS student" runs, "high school student" blocks.
    - **Unknown is not clean.** The check needs something to read from: at least one source that reads profiles (Maigret or Platform check; the list is in the rules file and the server uses the same one) must have answered. Sherlock, GitHub or enrichment alone is not enough. A site that blocked the platform check is not a failure of that source, and a failed GitHub lookup does not stop the pass but is said. Otherwise there is no adult pass: "Adult and dating sites were not checked: no source that reads profiles answered for this handle, so there was nothing to check. Switch on Maigret or Platform check and run again." (or "... Run the case again." when they failed). Guard-only text a row carries for the check (the whole bio, other text fields, a birth date, an age) is read and then removed: it is never stored, exported or sent to the AI.
    - **The run log** has one row for it. While the ordinary sources run: "Adult sites: waiting on profile check". Then either "Adult sites: profile check clean (6 profiles read), checking" (with "; GitHub did not answer" when it did not; "profile check: no profile text was found for this handle" when a reader answered with nothing, never "clean (0 profiles read)"), followed by the three adult rows, or "Adult sites: not checked · (reason)". A cancelled run reads "Adult sites: not run (cancelled)". The polite live region says the outcome.
    - **The block notice** sits above the results and names what triggered it, so it can be checked: "Adult and dating sites were not checked: a profile found for this handle states an age under 18 (Instagram: "16 | junior in high school")." The source is a link to that profile, by its link kind, and the snippet is at most 60 characters of the profile's own text, escaped. A school signal reads "suggests a school-age person", a birth date "states a birth date under 18", and a weak sign with a soft signal in the handle "suggests a minor, and the handle carries a matching age or birth year" (the only sentence that mentions it, and it prints no digit of the handle). For the handle: "Adult and dating sites were not checked: the handle states an age under 18." No message mentions a number in the handle. The same sentence is in the status line, the run log, the brief, and in the adult group's place: the group is drawn open, counted "not checked", with one row that says why. The case records it (`collected.adultBlock`: kind, source, snippet, url), so History, exports and case files say the group was skipped and why; the AI is told only "adult sites not checked: minor indicator on (source)", never the quoted text.
    - **The server is the floor.** It keeps the profile text the ordinary sources returned for a handle for 30 minutes (in memory, never logged, added to and never overwritten, with a block sticky for that time), keyed on the handle and a random session ID in one cookie (`crawlr_run`: HttpOnly, SameSite=Strict, Path=/api, session-scoped, Secure over https), so one visitor's run says nothing to another. It refuses an adult request when no source that reads profiles is on record under that cookie, and runs the same scan before any adult site is asked. When the two disagree the server wins and the page shows the server's reason. When the server has no record of a run the page did make (the record lapsed, the cookie was lost, the server restarted) the notice, the status line and the run log row say exactly: "Adult sites need a fresh run. Re-run the case to enable them." That, too, is kept with the case.
    - **For the session.** A handle stopped by either stage stays suspended until the page is reloaded, the mode stays on, and it applies again on the next handle that passes. A case opened by a pivot (a lead, a similar handle, "Investigate this") from a stopped case inherits the block: "Adult and dating sites are not checked here: this case was opened from emma_15yo, whose handle states an age under 18." or "..., where a profile suggested a minor." A variant of a stopped handle typed by hand is not suspended: its own profiles are checked. The list is in memory only.
  - **A pivot never scans.** The port scan runs only on a Recon run the investigator starts by pressing Run recon (or Enter) in Recon's own box. A Recon run started any other way (a lead's "Open in Recon", a brief action, a topology node, the landing form, a domain typed in Investigate) runs the passive sources only, and says so above the findings and in the run log: "Port scan not run: this case was opened from a link. Press Run recon to scan this host." The status line stays, because the mode is still on. A Deep Dive checks Active techniques again at the moment it would fetch.
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
| Phone | Valid, Line type, Assigned in, Flags |
| Name | Candidates, Directories answered, Handles to try, Public figure |
| Domain | Flags, Open ports, Subdomains, Expiring soon |
| IP address | Flags, Open ports, Expiring soon |

A tile says "at least" or "unknown" only when a source it counts from failed, never answered, or answered in part in a way that can hide rows. Platform check or Adult site check with some sites blocked is not that: each blocked site is already a row, so the counts stay plain and the brief keeps its own line naming the sites (`partialGaps` in `core.js`).

Three states are never merged on a tile. A count above zero is drawn in its tier color. **Zero** means every source the count depends on answered in full and found nothing: the number is muted and the tile is not a button to anywhere. **Unknown** means nothing was found and a source the count depends on did not fully answer: it failed, it answered only in part, or it was asked and had not answered when the run was cancelled. The tile is dashed, says "unknown" and opens By source. A count beside such a source is a lower bound: the tile shows "2+", reads "at least 2" to a screen reader and says why underneath. That caveat line is shown at every width; on a phone only the plain description lines are dropped. A tile whose source was not run says "not checked". The sources a cancelled run never heard from are saved with the case (`notAnswered`), so the tiles say the same when it is opened again. No tile is drawn while a run is in flight.

**Phone tiles.** Valid, Line type and Assigned in are words read from the numbering plan, so they are solid, each with a line under it saying what the word means ("fits the numbering plan", "the plan cannot tell which", "the range, not the phone"). Valid is green; on a number reserved for fiction it is neutral and says "but reserved for fiction"; "Not valid" is amber with the reason. A value this number cannot have (the line type of digits that fit no range) and every tile of a lookup that failed are dashed "unknown" with the reason. Under 760px a case whose first tile is a word draws its tiles two by two, so the words are not broken, and the sublines that change what the word means keep the caveat style and stay visible at every width: "the range, not the phone", "the plan cannot tell which", "but reserved for fiction" and every reason for an unknown. Only plain descriptions ("fits the numbering plan", "by number range", "read these first") are dropped on a phone.

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
- **Handle taken.** Discord has no profile page; its sign-up check can only say that a handle is in use. That row stays in Unverified with the pill "Handle taken" and the dashed line (reported, nothing read), no link, the sentence "Discord's sign-up check says this handle is taken. Discord has no public profile page, so who holds it is unknown." and the how-to-check hint. It is never drawn as a read profile and counts nowhere but the Unverified tile: it is not a finding in the case header, and the platform check is not a source "with results" for it. The same holds for a Reddit row that only says the check was blocked. Reddit, which refuses servers, is an Unverified row that says "Blocked by site" with the reason, a dashed link to the profile and how to check it by hand.
- **After the link check.** A templated URL the link check looked at stays in Unverified, because nothing was read about who owns the page, but the row stops saying that nothing checked it (`rowCertainty` in `present.js`). *Page checked*: the pill reads "Page checked" with a solid neutral line and the card edge turns solid neutral, matching the link, which is now solid. *Page not found*: a greyed, struck pill "Page not found" and a muted solid edge; the row moves to the end of its group. *Blocked by site* and *could not be checked* stay dashed "Unverified", with the reason on the row. The Unverified tile says how many pages were checked ("reported, 3 pages checked").
- **Source chips.** One per source that named the site.
- **What was read.** A card for a profile a source read ends with a disclosure, "What was read", with the number of values behind it. Closed, the row is still one card. Open, it lists every value the source returned, on an inset, in two groups that say who wrote each value: **Written by the account holder** (name, bio, location, company, website, public email, links, accounts the profile lists) and **the site's own record** (join date, last active, counts, packages and organizations, and accounts a proof or a verified link confirms). Each group carries its provenance word in a small outlined label ("self-declared", "site record"), so the split is never color alone. A profile a tool parsed from a page (Maigret, the platform check, enrichment) is one group, "Read from the page by Maigret", labeled "tool report", because the tool cannot tell the two apart. A linked account says how it is known beside it: "proven on Keybase" with a Proof link, "verified link", or "listed on the profile". The builder is `profileDetail` in `deep.js` and the markup is `evDetail` in `workbench.js`; a redraw keeps an opened disclosure open. The same three words mark every value in the Markdown export and in what the AI is told.

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
- Result tabs: Findings, By source, and Timeline for a username or an email case.
- Ledger tiers: Flags, Linked, Exists (matches), Exists (different person, collapsed), Unverified, Leads from profiles, Similar handles (collapsed), Hosts on the email's domain (collapsed), Known noisy sites. Each row says why it sits where it does ("same name", "GitHub's own record for this handle", "Blocked by site").
- **What we know** shows one person at a time. A labelled select switches between the people who share the handle; the primary identity is first and the panel says why it is primary. Facts from different people are never mixed.
- **Links say what they are.** Every external link opens in a new tab with `rel="noopener noreferrer nofollow"` and an external-link icon. A URL that a source read is a solid link. A URL built from a site template that nothing checked has a dashed underline and the words "unverified URL" beside it (never a tooltip alone). A site with no public profile page, or a link that is only a homepage, is plain text with a "How to check" hint. Evidence links ("DNS lookup", "InternetDB record", "RDAP record", "Certificate logs") point at the public page where a claim can be checked, and never carry a username or email in the query. One exception, decided once: Hacker News serves a user's page only at `news.ycombinator.com/user?id=<handle>`. The rule exists so a target is never handed to a site that has no record of it (a search engine, a lookup page); this is the profile's own address on the site the profile is on. `ownProfileQuery` in `links.js` admits that exact shape (the host, the path, the single `id` parameter, a value that is a Hacker News name, https, no port, fragment or credentials) and nothing else, and `tests/js/links.test.mjs` holds both halves. Add a site there only when its profile page has no path form. The outbound searches of a name case and of a phone case are a kind of their own (`search`): they carry the name or the number on purpose and are never evidence.
- **Link check.** When a group is opened or scrolls into view, its unverified URLs are checked in place: "page checked", "page not found" (greyed, moved to the end, never removed), "Blocked by site" or "could not be checked". Rows do not change tier or height while this runs.
- **Adult and dating sites** are opt-in. The switch is a session mode (see Session modes under Layout): off when the page loads, never stored, and on for every case until it is switched off or the page is reloaded. With it on, results sit in their own collapsed group after Unverified, with a count and one line: "Adult and dating sites are existence checks only. A match shows a handle is taken there, not who owns it." Rows are text: a badge with the site's initials, never a favicon, avatar, thumbnail or preview, in any view or export. They never enter the other tiers, What we know, identities, leads or the avatar comparison. Exports and the AI see them only when the case had the mode on, in a section labelled "Adult and dating sites (existence checks only)". They are asked only after the ordinary sources, and only when the minor guard allows it (see Session modes): a handle that states an age under 18, or a profile found for the handle that suggests a minor, suspends the mode for that case and says why, with the source and a short quoted snippet; the switch itself stays as it is. The adult pass of Sherlock, the adult pass of Maigret and the adult site check are one source, "Adult site check", in every count.
- **Name cases.** A name is shared by many people, so a name search lists candidates, never findings. The results open with one line, always: "A name is shared by many people. Everything below is a candidate to look at, not a finding about one person." Groups, in order: Public figure (only when Wikidata has an exact match), People with this name (the directories' rows, best name fit first, each saying how the name fits and which typed details it matches), Handles to try (collapsed when there are candidates) and Search the web. The header and the tab count candidates, not findings. What we know says "No single person is selected" and shows no facts. Nothing is followed on its own: "Show profile" loads one GitHub profile (announced through a polite live region, with only that row redrawn and focus left where it is), "Investigate this" starts one username case, and a search link opens on another site with the name in it, which its group says. Three optional boxes under the target (Location, Employer or school, Keyword) rank the rows and are never sent to a directory. A directory that failed or was rate limited is named as unknown, never as "nobody by this name", and one that was not asked is not listed. When the list is capped a directory says "8 found, 6 shown". No picture or favicon is shown for a candidate in any view or export, the adult mode says it is not used for this kind of target, and the link check is not offered.
- **Country of a phone number.** A number typed without a country code has to be read as some country's. A "Country" select sits under the target while the Phone type is active and the text does not start with a + (a number written with 00 or 011 still needs it: which prefix is international depends on the country), with the hint "Used only when the number has no country code." It starts on the browser's region when the numbering data knows it, otherwise the United States, is a plain select of every region sorted by name, and is saved with the case and put back from History. The case then says which country was used ("No country code given, read as a United Kingdom number").
- **Phone cases.** A phone lookup says what a number is, never who uses it. Groups, in order: Flags (a premium-rate, VoIP or personal range, a range reserved for fiction, digits that are not a valid number, a block no carrier holds, an emergency number), About this number (the validity row, notes such as "No country code given, read as a United States number", and for a United States or Canadian number the block row with its "Block record" evidence link) and Search the web (search engines with the number in its written forms, and two free spam-report sites for +1 numbers, neither of which shows a location; the group says "The number goes to that site", the rows carry the `search` link kind and are not findings). Certainty: a fact read from the numbering plan is solid, because the plan is the authority on what a range is, and the wording carries the limit every time it is about a place or a carrier: "Range assigned in ... (the range, not the phone or the person using it)", "Range first assigned to ... (numbers are ported, so this may not be the current carrier)". Dashed is kept for what could not be known. Time is shown as "Time offset of the range" (UTC+2, or "UTC+10 to UTC+11" for a range that spans several), never as a time zone name: the numbering data names a zone by a city that is often in another country. What we know ends with "Who uses it: Not something open numbering data shows.", and the brief ends with the same sentence. NumLookup's answer, when the investigator has a key, sits beside the offline facts labelled as NumLookup's and never replaces them; when it or the block source fails the lookup is partial, the brief names the source as unknown, and "not assigned" is never inferred. The source list describes the lookup as it is and has no "links only" tag. No picture, favicon or map is shown.
- **Similar handles** are a group of their own after Leads from profiles, collapsed, in username and email cases: "Handles close to this one. Nothing has been checked. Check one to see whether its name or picture lines up with this case." A row is the handle in mono, the reason it was built in plain words, and two buttons: "Check" and "Investigate this" (a separate case). There is no "check all": one click, one handle. A checked row shows one sentence on what was found, then each profile that was read as a small evidence card on an inset (mark from the server's thumbnail or initials, never a site icon; site link; handle; the facts line; the line-up in words with the fact it rests on), then every source that read nothing grouped by state, so a blocked site is not read as absent. The card's pill names one of eight outcomes, always solid because a profile was read:

  | Pill | When | Add to this case | Tier when added |
  |---|---|---|---|
  | Same picture (Linked color) | the picture matches one on the primary identity | yes | Linked |
  | Same picture, name differs (Linked color) | the picture matches and the name conflicts; the card and the row say "Same picture, but the name on it differs (X, against Y)" | yes | Linked |
  | Links back (Linked color) | the cross-link or shared-link rule ties them | yes | Linked |
  | Same full name (Matches color) | both carry a full name of two words or more made of the same words, and the handle was not built from that name; always with "A name alone is supporting, not proof." | yes | Exists (matches) |
  | Same name, not enough to add (neutral) | a single word, or a name that fits but is not the same full name | no | |
  | Same name, proves nothing (neutral) | the same name under a handle that was built from that very name | no | |
  | Name conflicts (Different person color) | the name conflicts with the primary identity | no | |
  | Nothing to compare (neutral) | no name and no picture on one side, no primary identity, or a picture that could not be compared (said in those words) | no | |

  A card with no Add points at "Investigate this". An added profile says "Added" and has "Remove from this case", in the group and on its row in the ledger.

  **An added profile is a row, never part of the identity.** Adding one changes nothing but its own row: not the primary identity's label, picture, member list or facts, and not the tier or text of any other row. Clusters and standings are computed from the case's own profiles as if nothing had been added, and the added row is placed by its own line-up. Its row says "Added from the similar handle erroric: same picture as the GitHub profile." Its facts appear on its own card and in one block at the end of What we know, "From profiles you added (under a different handle)", each naming the site and the handle; the Markdown export has the same block and the AI is told the handle each such account is under. The brief's account counts leave added profiles out; they have their own line.

  A case opened from a case file keeps only similar handles the case would offer itself, keeps no profile as added, and shows what the file lists as "From the case file, not checked here." with a dashed card, dashed links and "Check here". Running a target again carries its checked and added similar handles into the new run and evaluates every line-up again. While a handle is being checked its row is busy and its button reads "Checking…" in every redraw. Loading and the outcome are announced through the polite live region with the handle in the message, only that row is redrawn while a handle is checked, and after adding or removing every group stays open or closed as it was and focus goes to the button that undoes the action. Similar handles are in no tile and no count, and the brief gets one line only after a check.
- **Profile sources** are one source in a username case, on by default, with its own switch: one request that reads the handle's public record on 16 sites with an open API (GitLab, Keybase, Hacker News, Mastodon, Docker Hub, npm, dev.to, Lichess, Chess.com, Codeberg, Bluesky, Wikipedia, Gravatar, Codeforces, Lobsters, Hugging Face). A record that was read is a read profile like any other: one row per site (merged with a username tool's row for the same site, the record's values and address kept), filed by the identity rules, with its picture already hashed by the server so the avatar comparison is not asked again. Each site keeps its own state. Only "profile read" and "not found" say whether an account is there; "blocked by site", "rate limited", "failed" and "could not tell" are unknown and are listed apart, on the card under By source, in the brief and in the export. A site whose handle rules the handle cannot fit is "not asked" and is not counted. When every site failed the source failed; when some did it is partial, and because a silent site has no row of its own, the tiles read "at least".
- **A proof is a strong tie; a listed account is not.** A Keybase proof and a link Mastodon marks as verified are confirmed from the other side, so each joins the two profiles by itself (the cross-link signal) and the row says which: "a Keybase proof ties the GitHub account to the Keybase profile". An account a profile only lists is an ordinary link: a lead, and at most a one-way link shown as support.
- **Accounts and keys** is a source in an email case: the GitHub account GitHub attributes commits with the address to, accounts whose public profile shows it, commits GitHub ties to no account, and OpenPGP keys on keys.openpgp.org. Wording is fixed in `deep.js` and is the same on the row, the card, the brief, the export and the AI prompt. An account with a commit attribution is Linked ("GitHub attributes commits that carry this address to this account, so the account has this address confirmed") with an Evidence commit link and "Investigate this". An account that only shows the address is Exists (matches); an organization is labeled as one and "unconfirmed". Commits tied to no account are one Unverified row that is not a finding. A key is Linked to the address (the key server verified the address by mail). Names, dates and UTC offsets written inside commits, and a key's names and creation date, are always labeled self-declared; names from a repository the account owns come first. None of these rows is a profile: they join no identity, and their facts in What we know are about the address and say "site record" or "self-declared" in the source. No handle is derived from the address: the login is a lead, followed on a click.
- **GitHub activity** runs with a username case when GitHub has the handle's account, like GitHub details. It is shown on the Timeline tab and as a card under By source: the window covered, then two strips of neutral ink bars on an inset (24 hours and 7 weekdays, UTC), each an image whose text alternative reads out every count, with the busiest hours also written under them, then the most active repositories and the kinds of event. Bars are ink, not a tier color: a count is not a verdict. The UTC offset estimate sits in a box with a dashed edge (inferred, not read) and the tag "a hint, not a fact", with its basis, its assumption and its caveat under it, and the sentence "A range of time offsets is not a place." It is never turned into a country, a city or a time zone, on the page or in the prompt. With no estimate the box says "none made" and why.
- **Timeline** is a third tab in a username or an email case (hidden for a hash, a phone number or a name). It lists every dated fact the sources returned, oldest first, with today marked: account created and last active from every read profile, the oldest and latest public GitHub event, the first and last commit seen for an address, a key's creation, breach dates. This reverses an earlier decision not to build a dated history of a person; the limits that make it acceptable are in `personTimeline` in `timeline.js`: only dates a source returned in this run, only accounts filed as Linked or Exists (matches) (a different person's account is left out, and a matching one says "not proven to be the same person"), never an adult or dating site, and every row says whether its date is a "site record", a "breach index record" or "self-declared". A self-declared date has a dashed dot and the word in italics.
- **Leads** are places to look next, not findings. Every lead says where it came from and, for an account a profile names, how it is known ("Keybase profile, proven on Keybase", "Mastodon profile, listed on the profile"). A handle or address lead has "Investigate this", a domain has "Open in Recon". Nothing is followed without a click, and a lead never starts another lead.
- An email case does not run the username tools on the part before the @. That part is offered as a lead.
- One count, one function: the case header, the run log summary and the By source tab all read `sourceTally`. Every source that ran has a card, including ones that found nothing or failed.
- Search and tool inputs opt out of browser and password manager autofill. The key fields in Settings do not. Recon: Flags, Exposed services, Subdomains, Lookalike domains, Unrelated neighbours on a shared address (collapsed). A domain with no MX is "not graded" for email, with the null-mail records shown as a note.
- **At a glance** sits above the tabs once a run finishes: a few sentences built from rules, each tagged Check, Good or Note. It never appears mid-run, so it never describes half a picture. It states what sources returned and does not guess; where profiles under one handle carry different names it says they may be different people.
- The topology graph is drawn in neutral ink tones from the tokens. Purple and amber mean the primary action and a flag on a case page, so the graph uses neither; a node says what it is in its own label (A, NS, the host or address), the legend names the kinds, and a Cloudflare address carries a CF badge.
- The AI report's account tiles and their legend use the ledger's grammar (`rowCertainty`): tier color on the tile's edge, dashed when nothing read the account, and the legend is the same pills.
- **Wildcard DNS is one finding, never a list.** When every name under a domain resolves, the Subdomains group opens with one row, `*.example.com`, that says what the wildcard resolves to, who runs the target when it is a third party (a registrar's parking host, a hosting platform), that a resolving name is therefore not proof a host exists, and how many guessed names were left out. It is a note, not a flag: a wildcard is a configuration fact. A name kept because a certificate, a DNS record or a passive source attests it says "resolves through the wildcard". The Subdomains tile counts names only and its line reads "wildcard DNS: 74 guesses left out"; the Subdomains card under By source carries the state as a tag ("wildcard DNS", "no wildcard DNS", "wildcard DNS not checked") and lists the names left out in a collapsed section, so nothing is hidden. When the test lookups failed the page says the check could not be made and leaves nothing out: unknown is never shown as "no wildcard".
- In the topology graph a wildcard is a single node, `*.example.com`, with a dashed outline (it is a rule, not a host), its CNAME target and its addresses beside it, and a Wildcard entry in the legend. There is never a node per guessed name. It is not a button: there is no host to run recon on. A name that resolves through the wildcard is drawn without addresses, because they are the wildcard's.
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
- Every input has a label. Switches are `role="switch"` named by their source. The two session mode switches are named by their visible label and described by the line under it; the first-use confirmation is an ordinary dialog (focus moves in, Escape cancels, focus returns to the switch).
- Pointer targets are at least 24 by 24 CSS pixels.
- Run progress is announced through a polite live region; `aria-busy` marks the results while a run is in flight.
- Links inside text are underlined, so they are not identified by color alone.

## Print and export

Purpose, notes and the collection time are mirrored into a `.print-only` block, because inputs print badly and are stripped from the HTML export. The timeline prints under its own heading.

The JSON export is a **case file**. "Open a case file" in History reads one back in the browser (never uploaded), checks it and adds it to History marked "from a case file". A file that is refused gets a dialog saying why, and History stays open.

"Print or PDF" uses a print stylesheet: light, no chrome, every tier expanded, link URLs printed after their text. The HTML export is the same markup in one self-contained file. Both carry a line saying findings can be wrong and possible items are leads.
