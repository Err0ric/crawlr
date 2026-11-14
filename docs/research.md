# OSINT tool landscape and responsible practice: research for CrawlR

Research date: 2026-11-13. Every link in this file was fetched and read during the research session. Pages that would not load are listed under "Could not verify" at the end and are not cited from memory. Vendor claims are reported as claims, not as tested facts. Most pages were read through a text extraction tool, so wording is paraphrased unless it sits in quotation marks.

## 1. Summary

- CrawlR already matches or beats the free tier of most tools reviewed on breadth for infrastructure recon. The gaps are in what happens after the results arrive: pivoting from the graph, comparing runs, telling strong evidence from weak, and handing a report to someone else.
- The highest-value work needs no new data source and no server state. Re-run diffing, a print-ready report, graph pivots, reliability labels and client-side correlation rules can all be built in the browser on top of data CrawlR already returns.
- WhatsMyName was archived on 2026-11-09 and is now read-only. Its README says the data "will get less accurate over time". It is still usable as a vendored snapshot (691 sites, CC BY-SA 4.0), but it is no longer a living source, and it counts as a new third-party source that the owner must approve.
- The best username tools decide "found" on status code and body string together, and they expose a third "unknown" state. CrawlR should show that state instead of folding it into found or not found.
- Paid people-search tools (Epieos, Predicta Search, OSINT Industries) sell three things CrawlR cannot copy cheaply: proprietary account-existence checks, "no false positives" claims, and PDF or DOC reports. The report format is the one part worth borrowing.
- SpiderFoot's correlation rules and Maltego's "right-click an entity, run a transform" are the two UX patterns most worth borrowing for the topology graph.
- Shareable read-only links conflict with CrawlR's strongest privacy property (no server-side storage of targets). An exportable file that another CrawlR user can import gives most of the value with none of the retention risk.
- The Berkeley Protocol, Bellingcat, SANS, Trace Labs and the ICO converge on the same checklist: a stated purpose, passive by default, collect only what the purpose needs, verify before relying on a finding, keep it only as long as needed, and say plainly what the tool must not be used for.

## 2. Tool notes

### OSINT Framework

What it does: a directory of free OSINT resources drawn as a clickable tree. Top-level branches seen on the live site include Username, Email Address, Domain Name, IP and MAC Address, Social Networks, People Search Engines, Telephone Numbers, Public Records, Archives, Dark Web and OpSec. Entries live in a single `arf.json` file. It runs nothing itself.

What its UX gets right: a four-letter legend tells the user what a link will cost them before they click: (T) local install, (D) Google dork, (R) registration required, (M) URL must be edited by hand. The current data model also records status (live, degraded, down, deprecated), pricing, expected input and output, and an OPSEC classification of passive or active with notes. The site has a "Report an issue" control for dead links and paywalls.

What CrawlR could borrow: the passive or active flag and the input to output description as visible metadata on every source card and every manual lookup link. A small "dead link" report path for the manual people-search and phone links.

Links: [osintframework.com](https://osintframework.com/), [README](https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/README.md)

### IntelTechniques search tools (Michael Bazzell)

What it does: a set of query-builder pages, grouped by target type (email addresses, usernames, names, telephone numbers, domains, IP addresses, images, documents, breaches and leaks, vehicles and more). The user types one value and the page opens the matching searches on third-party sites. It is a companion to the book OSINT Techniques, 11th edition. The page was last updated 2026-08-15.

What its UX gets right: the page states that queries run in the user's own browser and that the site does not "see, collect, or store the information you search". Broken tools are kept and marked, because the upstream service may return. A "Submit All" control opens every search for a value at once. The page closes with "Please be responsible."

What CrawlR could borrow: CrawlR's Name and Phone flows are already manual link lists. A "open all" control with a popup warning, and a visible "last checked" date on each link, would bring them to the same standard. The one-line privacy statement is a good model for CrawlR's own.

Link: [inteltechniques.com/tools](https://inteltechniques.com/tools/index.html)

### WhatsMyName (data project and web app)

What it does: a community-maintained JSON file of sites where a username can be checked by URL, plus a web app that runs the checks in the browser.

Status: the README states "As of November 9, 2026, WhatsMyName is no longer maintained. This repository is archived and read-only." It adds that accuracy will decline over time. The final file holds 691 sites.

License: the README states "This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License." The schema requires the same notice as a constant `license` array inside the data file. In practice that means credit is required, and a modified copy of the data must be shared under the same license. This is not legal advice. The raw LICENSE file path could not be fetched (see "Could not verify").

How `wmn-data.json` is meant to be consumed:

1. Top-level keys are `license`, `authors`, `categories` and `sites`. A schema file, `wmn-data-schema.json`, validates it.
2. Each site has required fields `name`, `uri_check`, `e_code`, `e_string`, `m_code`, `m_string`, `known` and `cat`. Optional fields are `uri_pretty`, `post_body`, `headers`, `strip_bad_char`, `valid` and `protection`.
3. Remove each character in `strip_bad_char` from the username, then substitute it for `{account}` in `uri_check` by plain string replacement.
4. Send a POST if `post_body` is present (the schema then requires `headers`), otherwise a GET.
5. "Found" requires both `e_code` and `e_string` to match. "Not found" requires both `m_code` and `m_string`. Anything else is "unknown". The README warns "never decide on the status code alone".
6. Skip entries with `valid: false`. The `protection` array marks sites behind Cloudflare, captcha or user-agent checks.
7. `known` lists usernames that exist on the site, which makes a self-test possible.
8. `uri_pretty` is the link to show a human.

What the web app gets right: multiple usernames in one search, category filters with NSFW excluded by default, a searchable results table with site, username, category and link, and Copy, CSV and PDF export. It also runs document and Google searches for the first username.

What CrawlR could borrow: the three-state result, the `known` self-test as a health check, NSFW off by default, and category filters. See proposal 7 for the source itself.

Links: [repository](https://github.com/WebBreacher/WhatsMyName), [README](https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/README.md), [schema](https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json), [whatsmyname.app](https://whatsmyname.app/)

### Epieos

What it does: reverse lookup of an email address or phone number to linked accounts. Maltego's listing describes coverage of more than 140 sites and a component based on an improved Holehe that checks over 120 sites.

What its UX gets right: three promises sit on the home page in plain words: "We do not log your queries", "We do not notify the target" and "We do not show false positives". These are vendor claims and were not tested. Pricing: not verified.

What CrawlR could borrow: the three promises are the right shape for a trust statement. CrawlR can make the first two honestly for passive modules, and should say where it cannot (active scan, Deep Dive, and Holehe-style checks, whose notification behaviour varies by site and should be described carefully).

Links: [epieos.com](https://epieos.com/), [Maltego Transform Hub listing](https://www.maltego.com/transform-hub/epieos/)

### Predicta Search

What it does: finds accounts and footprints from an email, phone, username or full name. The home page claims "1710+ platforms". It is run by Predicta Lab, an EU company based in France.

What its UX gets right: "Start with what you have" as the entry point. Queries are timestamped in the user's account as an audit trail and can be deleted. Higher plans add bulk search (a file of up to 50 identifiers), "cases" that merge several searches into one corroborated file, and report export. A separate graph product imports findings onto a canvas. The page restricts use to legitimate professional purposes, says the service does not access private accounts or scrape protected content, puts legal compliance on the user, and references GDPR and a code of ethics. Prices: none shown on the page, not verified.

What CrawlR could borrow: the idea of a case that merges several runs and shows which facts are corroborated by more than one search. A user-visible, deletable history, which CrawlR already has locally.

Link: [predictasearch.com](https://www.predictasearch.com/)

### OSINT Industries

What it does: account discovery from an email, phone, username, name or crypto wallet. The home page claims 1500+ sources.

What its UX gets right: results are shown three ways: a list of linked accounts, a map and a timeline. Export covers PDF, DOC, Excel and JSON. There is an API. The site says it does not store search results. The home page claims results are "100% accurate" with "Zero False Positives"; this is a vendor claim and was not tested. The pricing page listed monthly plans of 19, 49 and 99 GBP with 30, 100 and 300 credits, plus custom enterprise pricing, and free access request routes for law enforcement, government, journalists and non-profits. Part of that pricing page contained placeholder text, so treat the figures as indicative only.

What CrawlR could borrow: the timeline view. CrawlR already collects dated facts (certificate issue dates, Wayback snapshots, WHOIS creation, breach dates, profile creation dates), and a single timeline across sources would be new value with no new data.

Links: [osint.industries](https://www.osint.industries/), [pricing](https://www.osint.industries/pricing)

### Maltego

What it does: a link-analysis platform. The docs describe a desktop graph application for large-scale link analysis, a browser graph, a quick search product, a case store, a monitoring product, and access to "over 120 data providers", some with bring-your-own-key.

What its graph UX gets right: the unit of work is the entity on the canvas. Right-clicking an entity opens a list of transforms, and the list is filtered to those that accept that entity type (an email entity only offers email transforms). Results land on the same graph as new linked entities. A progress bar shows the combined progress of all running transforms, and one control cancels them all after a confirmation.

What CrawlR could borrow: node-level pivots on the D3 topology graph, with the action list filtered by node type, a visible progress state and a cancel control. See proposal 3.

Links: [What is Maltego](https://docs.maltego.com/en/support/solutions/articles/15000019166-what-is-maltego-), [Running a transform](https://docs.maltego.com/en/support/solutions/articles/15000056674-running-a-transform)

### SpiderFoot

What it does: open source (MIT) OSINT automation with over 200 modules, a web UI and a CLI. Target types cover IP, domain, hostname, subnet, ASN, email, phone, username, person name and Bitcoin address. Exports are CSV, JSON and GEXF.

What its correlation UX gets right: 37 YAML rules ship with the tool. A rule never collects anything. It queries what the scan already found, optionally groups it, filters the groups, and writes a headline with values filled in. Each rule carries a risk level of INFO, LOW, MEDIUM or HIGH. Analysis methods include a threshold and an outlier test. Shipped examples include a host reported malicious by multiple sources, a web server that differs from the rest of the set, an exposed database, an open cloud bucket and a possible DNS zone transfer.

What CrawlR could borrow: the rule shape (collect, aggregate, analyse, headline, risk) fits CrawlR's ledger well and can run in the browser over the JSON the server already returns. See proposal 6. "Reported by multiple sources" is also the simplest honest basis for a confidence signal (proposal 4).

Links: [repository](https://github.com/smicallef/spiderfoot), [correlation rules README](https://raw.githubusercontent.com/smicallef/spiderfoot/master/correlations/README.md)

### Shodan

What it does: a search engine for internet-connected devices, with an API, a monitoring product that alerts when unexpected devices appear in a network range, maps and image search. The site says it crawls the internet weekly. InternetDB is the keyless endpoint CrawlR already uses: it returns open ports, vulnerabilities, CPEs, hostnames and tags, with no banners, updated weekly.

Point to note: the InternetDB page says it is free for non-commercial use and that revenue-generating use needs an enterprise license. CrawlR is a personal project, so this fits today. It would need a second look if CrawlR ever charged for anything.

What CrawlR could borrow: show the data age ("InternetDB, updated weekly") next to results, so the user knows a port list is a snapshot and not a live scan.

Links: [shodan.io](https://www.shodan.io/), [internetdb.shodan.io](https://internetdb.shodan.io/)

### crt.sh

What it does: certificate transparency search run by Sectigo. The search page accepts an identity (domain name, organization name), a certificate fingerprint (SHA-1 or SHA-256) or a crt.sh ID, and has an advanced search page.

What CrawlR could borrow: CrawlR already queries crt.sh in two modules, so the value is not another query. It is using more of each response: issuer, validity dates and the full name list per certificate, and making one request serve both modules. See proposal 5. A direct connectivity check from the research machine returned HTTP 502 once, which supports caching and a fallback to CertSpotter.

Link: [crt.sh](https://crt.sh/)

### SecurityTrails

What it does: an API for IP, DNS, WHOIS and company data, authenticated with an API key. The API reference lists DNS history by record type, WHOIS history by domain, subdomain listing, associated domains, IP neighbors, IP WHOIS and domain search.

What it gets right: history as a first-class question. "What did this record say before" is something CrawlR can only partly answer today through OTX passive DNS and Wayback.

What CrawlR could borrow: nothing to build now. If the owner later wants deeper passive DNS history, this is the obvious bring-your-own-key source, in the same pattern as Shodan and Hunter.io. Pricing and free-tier limits: not verified.

Links: [API overview](https://docs.securitytrails.com/docs/overview), [API reference](https://docs.securitytrails.com/reference)

### urlscan.io

What it does: loads a submitted URL in a browser and records what happened, with APIs to submit, fetch results and search existing scans by domain, IP, ASN and hash. Unauthenticated callers get what the docs call "minor quotas".

What its UX gets right: visibility is an explicit choice on every scan. Public scans are searchable by anyone, unlisted scans are visible to vetted urlscan Pro customers, and private scans are visible only to the submitter. urlscan's own blog warns that people leak personal data by scanning URLs such as password reset links, invoices and unsubscribe links as public.

What CrawlR could borrow: CrawlR only uses the search API today, which is passive and correct. If a "scan this page" action is ever added, it must be labelled active, default to the most private visibility the key allows, and refuse URLs that contain an email address or a token-like query string.

Links: [API intro](https://docs.urlscan.io/pages/api-intro), [FAQ](https://docs.urlscan.io/pages/faq), [Scan visibility best practices](https://urlscan.io/blog/2022/07/27/scan-visibility-best-practices/)

### Trace Labs

What it does: runs Search Party CTFs in which volunteers gather open source intelligence on real missing-person cases for law enforcement, and publishes an OSINT VM and a field manual.

What its rules get right:

- Passive only. "This means you can view but not engage." Contacting the subject, family or friends, including tagging, friending or liking, means disqualification.
- No use of breached passwords, no password reset attempts, and not even visiting a reset page for an account tied to the case.
- Findings must be verifiable by a public link. Content behind a paywall scores nothing.
- Findings must be relevant, with a stated reason. Bulk-submitting every friend on a profile is rejected.
- No fabricated intelligence, no contact with law enforcement or media by contestants, and "We are not vigilantes."

The field manual adds that legal is not the same as right, that the investigator is responsible for how findings are used, that each finding should be validated against a starting source of truth and not taken from enumeration alone, and that an investigator should set red lines that end the work early.

The OSINT VM (Debian 13 based, GPL-3.0) ships Sherlock, Maigret, WhatsMyName, SpiderFoot, theHarvester and Shodan CLI among others, with Obsidian and Joplin report templates and a hardened Firefox. One scraping tool is opt-in because it has not cleared a terms-of-service review.

What CrawlR could borrow: "verifiable by a public link" and "state why it is relevant" map directly onto CrawlR's review checkboxes and per-case notes. The opt-in pattern for tools with unresolved terms questions is the same pattern CrawlR uses for active techniques.

Links: [Search Party rules](https://tracelabs.org/about/search-party-rules/), [OSINT VM README](https://raw.githubusercontent.com/tracelabs/tlosint-vm/main/README.md), [OSINT field manual](https://raw.githubusercontent.com/tracelabs/tofm/main/tofm.md)

## 3. Comparison table

Effort: S is under a day, M is a few days, L is a week or more. "Who has it" lists only what the fetched pages support.

| Feature | Who has it | CrawlR today | Effort (S/M/L) | Value (low/med/high) |
|---|---|---|---|---|
| Unified target detection | Predicta Search and OSINT Industries accept several identifier types in one box; SpiderFoot accepts ten target types | Yes. One box detects username, email, domain, IP, ASN, phone, hash, name and pasted headers | Done | High |
| Username enumeration breadth | WhatsMyName (691 sites), Predicta (claims 1710+ platforms), OSINT Industries (claims 1500+ sources) | Yes. Sherlock, Maigret, GitHub API, direct probes | M to add WhatsMyName | Med |
| Username false-positive handling | WhatsMyName (code plus string, three states, `known` self-test); Epieos and OSINT Industries claim no false positives | Partial. Depends on Sherlock and Maigret; no "unknown" state or self-test surfaced | S to M | High |
| Email-to-account discovery | Epieos, Predicta Search, OSINT Industries | Yes. Holehe, Gravatar, breach check, optional Hunter.io | Done | High |
| Cert transparency subdomains | crt.sh; SpiderFoot modules | Yes. crt.sh in two modules plus CertSpotter | S to dedup and add cert detail | Med |
| Passive DNS history | SecurityTrails (DNS and WHOIS history) | Partial. OTX passive DNS and Wayback only | M, needs a keyed source | Med |
| URL or page scanning | urlscan.io (submit, result, search) | Partial. urlscan search only, plus own redirect chain and tech fingerprint | M, active and needs a key | Low to med |
| Entity graph with pivots | Maltego (right-click entity, run transform); Predicta Graph | Partial. D3 topology graph, view only | M | High |
| Correlation rules | SpiderFoot (37 YAML rules with risk levels) | No. Ledger ranks findings but has no cross-source rules | M | High |
| Saved cases and notes | Maltego Cases; Predicta cases; Trace Labs VM note templates | Yes, local only. 50 cases, notes, review checkboxes | Done | High |
| Export: Markdown and JSON | SpiderFoot (CSV, JSON, GEXF); OSINT Industries (JSON) | Yes | Done | High |
| Export: PDF and HTML | OSINT Industries (PDF, DOC, Excel); WhatsMyName web (CSV, PDF) | No | S | High |
| Shareable read-only links | Not confirmed for any tool on the pages read; Maltego and Predicta offer account-based cases | No, by design. No server storage | L if server-side, S as a file | Low as a link, med as a file |
| Result diffing or monitoring over time | Shodan Monitor (network alerts); Maltego Monitor | No | S to M for manual diff | High |
| Per-source reliability or confidence scoring | SpiderFoot risk levels and the multiple-sources rule; OSINT Framework status field | No | S to M | High |
| API access | Shodan, SecurityTrails, urlscan, OSINT Industries, Predicta (by contact) | Internal JSON endpoints only, undocumented for outside use | M, and it changes the abuse profile | Low |
| Responsible-use controls | Trace Labs rules; OSINT Framework passive or active flag; Predicta permitted-use statement; IntelTechniques local-query statement | Yes. Consent modal, active techniques off and labelled | S to tighten wording | High |

## 4. Ranked feature proposals

Status (2026-11-14, after the recon tools and redesign PR):

- Built: 1 (re-run diff), 2 (print and HTML export), 3 (graph pivots, infrastructure nodes only, one click per run), 5 (certificate history and one shared crt.sh query), 8 (portable case files, opened from History and checked before use; not encrypted yet), 9 (timeline, for domain, IP and ASN cases only).
- Partly built: 4 (confirmed versus possible, failed as its own state, "reported by 2 tools", and every source labelled direct, index or heuristic in the Sources panel; the ledger is not reordered by it) and 6 (the "At a glance" brief applies a first set of rules, including the outlier-network and certificate-names-not-resolving rules proposed here; it also flags when profiles under one handle carry different names, as a caution against merging people, not as a link between them).
- Not built: 7 (WhatsMyName: a new third-party source, and the project was archived on 2026-11-09, so it is not planned).
- From the checklist in section 5: an optional purpose line per case that prints on exports, and the collection time on every export.
- Added beyond this list, all from DNS or sources already in use: email security posture, DNS hardening, subdomain takeover candidates, lookalike domains, published files (security.txt, robots.txt, favicon hash), archived path mining, and a keyless path for AI reports.

### 1. Re-run diff against the previous local case (build first)

What: when a target is run again and a history entry exists for it, show what is new, what is gone and what changed: subdomains, IPs, open ports, certificates, DNS records, found accounts. Compute it in the browser from the two stored result objects. Add the diff to the Markdown and JSON exports.

Why: change over time is where infrastructure findings come from, and it is what Shodan sells as [Monitor](https://www.shodan.io/). The data to do it is already in localStorage. SpiderFoot's [outlier and threshold analyses](https://raw.githubusercontent.com/smicallef/spiderfoot/master/correlations/README.md) show the same instinct: the interesting item is the one that differs.

Effort: S to M. Risk: low. The main trap is noise from sources that time out on one run, so a source that failed must be shown as "not compared" and never as "removed".

New third-party source or paid service: no.

Privacy: keep it manual. The [Berkeley Protocol](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf) (paragraph 28) notes that ongoing, persistent monitoring of individuals and long-term retention of personal data may need extra permissions in some jurisdictions. A scheduled or automatic re-run of a person-type target would be monitoring of an individual and should not be built. For username, email, phone and name targets, consider limiting the diff to an explicit user action with a short reminder of purpose. Diffing domains, IPs and ASNs raises no such concern.

### 2. Print-ready report and standalone HTML export (build first)

What: a print stylesheet so the browser's "Save as PDF" produces a clean report (case header, purpose and notes, reviewed findings first, sources with fetch time, the responsible-use line). Add a single-file HTML export built with the same escaping helpers the UI uses.

Why: PDF is the format the paid tools lead with ([OSINT Industries](https://www.osint.industries/) lists PDF, DOC, Excel and JSON; [WhatsMyName web](https://whatsmyname.app/) offers CSV and PDF). Trace Labs requires findings to be [verifiable by a public link](https://tracelabs.org/about/search-party-rules/), so every finding in the report should carry its source URL and retrieval time. The Berkeley Protocol's accuracy principle asks for results that acknowledge weaknesses in the underlying data, which argues for printing unreviewed findings in a clearly separate section.

Effort: S. Risk: low. The HTML export must escape every remote value, per the repo rule on `h`, `esc` and `link`.

New third-party source or paid service: no. No PDF library is needed.

Privacy: neutral to positive. A file the user controls is better than a hosted copy. Default the report to reviewed findings only, so an export does not spread unverified claims about a person.

### 3. Graph pivots: click a node to run it

What: on the topology graph, selecting a node offers the actions valid for its type (subdomain: recon; IP: InternetDB and ASN; ASN: owner and prefixes), runs the chosen one through existing endpoints and attaches the result to the graph. Show progress and a cancel control.

Why: this is the core of [Maltego's interaction model](https://docs.maltego.com/en/support/solutions/articles/15000056674-running-a-transform): actions filtered by entity type, results on the same canvas, a combined progress bar and a cancel-all control.

Effort: M. Risk: medium. One click must equal one run. No automatic recursion and no "expand all", or the user's quota and upstream rate limits will suffer. The active port scan must stay behind its existing toggle and never run from a pivot by default.

New third-party source or paid service: no.

Privacy: limit pivots to infrastructure nodes in the first version. If person-type nodes (usernames, emails found in results) are added to the graph later, a one-click pivot from one identity to the next makes it easy to build a profile of a private individual. That step should stay deliberate, with the consent reminder shown again, and is flagged here as a concern.

### 4. Per-source reliability labels and corroboration count

What: a small static table in the client that gives each source a reliability note (for example, authoritative record, third-party index, existence heuristic) and a data age where known. For each finding, show how many independent sources reported it. Use both to order the ledger.

Why: SpiderFoot's shipped rules include ["reported as malicious by multiple data sources"](https://raw.githubusercontent.com/smicallef/spiderfoot/master/correlations/README.md), which is corroboration as a signal. WhatsMyName's README says status codes alone are unreliable and that results are ["leads to verify"](https://github.com/WebBreacher/WhatsMyName). The Trace Labs field manual says to [validate against a source of truth and not rely on enumeration alone](https://raw.githubusercontent.com/tracelabs/tofm/main/tofm.md). OSINT Framework records a [status and OPSEC class per tool](https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/README.md).

Effort: S for labels and counts, M to feed ledger ranking. Risk: low to medium. A numeric score invites false precision. Use words (confirmed by 3 sources, single source, heuristic), not percentages.

New third-party source or paid service: no.

Privacy: positive. Marking a username hit as "heuristic, unverified" reduces the chance of a wrong person being tied to an account, which is the harm Bellingcat's [principles for data collection](https://www.bellingcat.com/app/uploads/2020/09/Principles-for-Data-Collection.pdf) ask about when information is erroneous or out of date.

### 5. Certificate detail and crt.sh dedup

What: fetch crt.sh once per run and share the result between the subdomain module and the passive harvester. Keep the fields already in the response (issuer, not-before, not-after, all names on the certificate) and show them: a certificate timeline, wildcard and expired flags, and names that appear only in certificates and no longer resolve.

Why: [crt.sh](https://crt.sh/) supports search by identity, fingerprint and ID, so each certificate can link back to its crt.sh record as the verifiable source. Two modules querying it separately doubles load on a free service that returned a 502 during this research.

Effort: S to M. Risk: low. Server-side change, but stateless (a per-request share, or a short in-memory cache keyed by domain).

New third-party source or paid service: no. It reduces calls to an existing source.

Privacy: certificates are public infrastructure records. Organization names in certificates can include sole traders, which is already public in CT logs. No new exposure.

### 6. Client-side correlation rules

What: a short list of declarative rules evaluated in the browser over the result JSON, each producing a headline, a level and links to the evidence. Starter set: subdomain resolves to an IP in a different ASN from the rest (outlier); name seen in certificates but no DNS record; open port reported by InternetDB and confirmed by the user's own scan; domain or hash flagged by two or more threat sources; expired or soon-to-expire certificate on a live host.

Why: this is SpiderFoot's model: [collect, aggregate, analyse, headline, with a risk level, and no new collection](https://raw.githubusercontent.com/smicallef/spiderfoot/master/correlations/README.md). It turns the "What we know" panel from a list of facts into findings.

Effort: M. Risk: medium. Rules that fire too often get ignored, so ship five good ones. Depends on proposal 4 for the corroboration count.

New third-party source or paid service: no.

Privacy: restrict rules to infrastructure and threat data. A rule that links identities (same avatar, same bio, same handle across sites) would be automated profiling of a person. It is not proposed, and should be discussed with the owner before anyone builds it.

### 7. WhatsMyName as a username source (needs owner approval)

What: vendor a pinned copy of `wmn-data.json`, run the checks server-side with the documented algorithm, show three states (found, not found, unknown), skip `valid: false`, skip or label `protection` entries, exclude NSFW by default, and credit the project with the license notice. Run the `known` usernames as an offline health check to disable entries that have gone stale.

Why: the format is simple and well specified ([README](https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/README.md), [schema](https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json)), and the Trace Labs VM ships it [alongside Sherlock and Maigret](https://raw.githubusercontent.com/tracelabs/tlosint-vm/main/README.md), which suggests practitioners see it as complementary.

Why it ranks low: the project was archived on 2026-11-09 and says accuracy will decay. Coverage overlaps with Sherlock and Maigret, which CrawlR already runs. It adds several hundred outbound requests per search from the server. CC BY-SA 4.0 means any edits CrawlR makes to the data file must be shared under the same license, which is easy in a public repo but should be a conscious choice next to the MIT-licensed code.

Effort: M. Risk: medium (stale data, false positives, rate limits, share-alike on the data).

New third-party source or paid service: yes, a new third-party data source. Free. Owner approval required before building.

Privacy: this widens the search for accounts belonging to a person. The checks are passive HTTP requests to public profile URLs and reveal only what those sites already expose, but the README's own warning applies: results are leads. Every hit must be presented as unverified until the user reviews it, and NSFW categories should stay off unless the user opts in, since a false match in those categories is the most harmful kind.

### 8. Portable case file in place of shareable links

What: export a case (results, notes, review state, purpose) as one JSON file and import it on another machine in a read-only view. Optionally encrypt the file with a passphrase using the browser's Web Crypto API.

Why: sharing is a real need. Predicta and Maltego solve it with [account-based cases](https://www.predictasearch.com/), which requires server storage. A hosted read-only link would put target data and findings about people on CrawlR's server, with all that follows: retention, access control, takedown requests, and for EU residents the duties that come with holding personal data not obtained from the person ([GDPR Article 14](https://gdpr-info.eu/art-14-gdpr/)). The Berkeley Protocol's [data minimization principle](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf) points the same way.

Effort: S for import and read-only view, M with encryption. Risk: low. The import path must validate the file and escape every value.

New third-party source or paid service: no.

Privacy: this is the privacy-preserving alternative. Server-hosted share links are not recommended. If the owner wants them later, they need a retention limit, unguessable URLs, a delete control and a decision on logging, and should be treated as a new risk review.

### 9. Unified timeline view

What: one chronological strip per case built from dated facts CrawlR already collects: WHOIS creation, certificate issue dates, first and last Wayback snapshot, passive DNS first seen, breach dates.

Why: [OSINT Industries](https://www.osint.industries/) presents a timeline as one of its three result views. For domains it answers "when did this infrastructure appear" at a glance.

Effort: M. Risk: low.

New third-party source or paid service: no.

Privacy: fine for infrastructure. For person-type targets, a timeline of account creation dates and breach dates is a step toward a profile of someone's online life. Start with domain, IP and ASN cases only, and flag the person-target version for an owner decision.

## 5. Responsible OSINT practice

### What the guidance says

- Berkeley Protocol (OHCHR and UC Berkeley Human Rights Center). Public availability does not remove privacy implications. Investigators must consider a person's reasonable expectation of privacy and the "mosaic effect", where separate public facts become identifying when combined (paragraph 28). Data minimization means collecting only what is "justified for an articulable purpose", necessary and proportional, and the principle "favours itemized, manual collection over bulk, automated collection" (paragraph 31). Over-collection by automated tools creates security and privacy risk. Accuracy requires acknowledging weaknesses in the data and not overstating conclusions (paragraph 30). Security should be the default (paragraph 33). The ethical principles include dignity, humility (correct errors), and transparency (no misrepresentation to obtain information). [Source](https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf)
- Bellingcat. Before using public material, ask whether it serves an investigative purpose and the public interest, whether anyone could be harmed, what happens if the information is wrong or out of date, and whether it can be verified. People not directly involved should not be exposed to harassment. Relatives and bystanders deserve protection even when showing them would make the method clearer, and sometimes the right call is to show less. [Principles for data collection](https://www.bellingcat.com/app/uploads/2020/09/Principles-for-Data-Collection.pdf), [Ethical dilemmas in open source research](https://bellingcat.com/resources/2023/09/18/notes-from-the-digital-field-ethical-dilemmas-in-open-source-research)
- SANS. Six principles: legal boundaries, avoiding harm, privacy, integrity and accuracy, purpose limitation, and transparency and accountability. "Passive means you do not engage with a target." Active research may count as undercover work in some organizations and needs clearance first. No vigilante action; report to the proper authorities. [Source](https://www.sans.org/blog/what-is-open-source-intelligence)
- Trace Labs. Passive only, no contact of any kind, no use of breached passwords, no password reset pages, findings must be verifiable and relevant, and "We are not vigilantes." The field manual adds that legal does not mean right and that the investigator owns the consequences. [Rules](https://tracelabs.org/about/search-party-rules/), [Field manual](https://raw.githubusercontent.com/tracelabs/tofm/main/tofm.md)
- GDPR legitimate interests (ICO guidance, UK GDPR). A three-part test: a legitimate purpose, necessity (no less intrusive way), and a balancing test against the person's interests. The basis fits uses people would reasonably expect with minimal privacy impact, and should be avoided for unexpected or potentially harmful uses. The assessment should be written down before processing. [Source](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/legitimate-interests/)
- GDPR Article 14. Whoever holds personal data that was not collected from the person owes them information about it, including the source and "whether it came from publicly accessible sources", normally within a month, with a narrow exemption for disproportionate effort. This is the main reason not to store results about people on CrawlR's server. [Source](https://gdpr-info.eu/art-14-gdpr/)
- urlscan.io. A reminder that a tool can leak the user's own sensitive data: URLs with tokens or email addresses submitted as public scans become searchable. [Source](https://urlscan.io/blog/2022/07/27/scan-visibility-best-practices/)

This section is a summary of published guidance, not legal advice.

### Checklist for CrawlR

Consent gate

- [ ] State the three things the user is agreeing to, in plain words: they have a lawful, legitimate purpose; they will not use CrawlR to harass, stalk, dox or locate a private individual; they are responsible for complying with the law where they are and where the target is.
- [ ] Suggested wording: "CrawlR gathers information that is already public. Public does not mean harmless. Use it only for a purpose you could explain to the person you are looking up: security work on systems you own or are authorized to test, research, journalism, or checking your own exposure. Do not use it to harass, stalk, or expose anyone. Results are leads, not proof. You are responsible for how you use them."
- [ ] Record acceptance locally with a version number, and show the gate again when the wording changes.
- [ ] Link the full acceptable-use statement from the gate and from the footer.

Active-technique labelling

- [ ] Keep port scan and Deep Dive off by default and labelled "active: the target may see this".
- [ ] Use the SANS and Trace Labs definition in the label help text: passive means no engagement with the target or its accounts.
- [ ] Say on the port scan that the user must own the host or be authorized to test it.
- [ ] Describe Holehe-style checks accurately. Epieos markets "do not notify the target" as a feature; CrawlR should only make that claim for modules where it has been checked.
- [ ] Never add: login attempts, password reset flows, use of breached credentials, or any interaction with a subject's account. These are bright lines in the Trace Labs rules.
- [ ] Reset active toggles to off for each new case.

Data minimization

- [ ] Keep history local-only, and say so next to the history panel, in the style of the IntelTechniques statement.
- [ ] Verify that server access logs and error logs do not record target values (path, query string or request body), and document the result. Prefer POST bodies over query strings for targets.
- [ ] State what leaves the browser: which third-party sources receive the target, and that AI reports send findings to the chosen model provider.
- [ ] Do not store AI report inputs or outputs server-side.
- [ ] Run only the modules that match the detected target type. Do not add "run everything" for person-type targets.
- [ ] Keep Deep Dive scraping limited to pages already found, and store extracted fields, not full page copies.

Retention

- [ ] Keep the 50-case cap and add a visible "delete this case" and "delete all history" control.
- [ ] Offer an optional auto-expiry for person-type cases (for example 30 days), on by default.
- [ ] Put the retrieval time on every finding and every export, so stale data is recognizable as stale.
- [ ] If any server cache is added (proposal 5), keep it in memory, short-lived, and limited to infrastructure targets.

Accuracy and verification

- [ ] Show found, not found and unknown as three states for username checks.
- [ ] Label single-source and heuristic findings as unverified until the user ticks the review box.
- [ ] Default exports to reviewed findings, with unreviewed ones in a separate, labelled section.
- [ ] Instruct the AI report prompt to state uncertainty and to avoid asserting that two accounts belong to the same person without evidence.

Acceptable-use statement

- [ ] Publish one short page: permitted uses, prohibited uses (harassment, stalking, doxxing, locating private individuals, unauthorized scanning, credential use), the passive-by-default policy, what is logged and what is not, how to report misuse, and a contact for removal or correction requests.
- [ ] Add "We are not a people-search service" in plain words, since Name and Phone lookups are manual links by design.
- [ ] Add an optional "purpose" field per case that prints on the report. The Berkeley Protocol's test is an articulable purpose, and writing it down is the cheapest way to meet it.

## 6. Sources

Pages fetched and read on 2026-11-13.

- OSINT Framework site: https://osintframework.com/
- OSINT Framework README: https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/README.md
- IntelTechniques search tools: https://inteltechniques.com/tools/index.html
- WhatsMyName repository: https://github.com/WebBreacher/WhatsMyName
- WhatsMyName README: https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/README.md
- WhatsMyName schema: https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data-schema.json
- WhatsMyName web app: https://whatsmyname.app/
- Epieos home page: https://epieos.com/
- Epieos listing on Maltego Transform Hub: https://www.maltego.com/transform-hub/epieos/
- Predicta Search: https://www.predictasearch.com/
- OSINT Industries: https://www.osint.industries/
- OSINT Industries pricing: https://www.osint.industries/pricing
- Maltego docs, What is Maltego: https://docs.maltego.com/en/support/solutions/articles/15000019166-what-is-maltego-
- Maltego docs, Running a transform: https://docs.maltego.com/en/support/solutions/articles/15000056674-running-a-transform
- SpiderFoot repository: https://github.com/smicallef/spiderfoot
- SpiderFoot correlation rules README: https://raw.githubusercontent.com/smicallef/spiderfoot/master/correlations/README.md
- Shodan: https://www.shodan.io/
- Shodan InternetDB: https://internetdb.shodan.io/
- crt.sh: https://crt.sh/
- SecurityTrails API overview: https://docs.securitytrails.com/docs/overview
- SecurityTrails API reference index: https://docs.securitytrails.com/reference
- urlscan API intro: https://docs.urlscan.io/pages/api-intro
- urlscan FAQ: https://docs.urlscan.io/pages/faq
- urlscan blog, Scan visibility best practices: https://urlscan.io/blog/2022/07/27/scan-visibility-best-practices/
- Trace Labs Search Party rules of engagement: https://tracelabs.org/about/search-party-rules/
- Trace Labs OSINT VM README: https://raw.githubusercontent.com/tracelabs/tlosint-vm/main/README.md
- Trace Labs OSINT field manual: https://raw.githubusercontent.com/tracelabs/tofm/main/tofm.md
- Berkeley Protocol on Digital Open Source Investigations (OHCHR PDF, chapter II read in full): https://www.ohchr.org/sites/default/files/2024-01/OHCHR_BerkeleyProtocol.pdf
- Bellingcat, Principles for data collection: https://www.bellingcat.com/app/uploads/2020/09/Principles-for-Data-Collection.pdf
- Bellingcat, Notes from the digital field: ethical dilemmas in open source research: https://bellingcat.com/resources/2023/09/18/notes-from-the-digital-field-ethical-dilemmas-in-open-source-research
- SANS, What is open source intelligence: https://www.sans.org/blog/what-is-open-source-intelligence
- ICO, Legitimate interests guide: https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/lawful-basis/a-guide-to-lawful-basis/legitimate-interests/
- GDPR Article 14: https://gdpr-info.eu/art-14-gdpr/

### Could not verify

- WhatsMyName LICENSE file at the raw path tried (HTTP 404). The license is confirmed from the README and the schema, not from a standalone license file. The full CC BY-SA 4.0 legal text was not read in this session.
- WhatsMyName archive date and site count come from the README as fetched. The contents of `wmn-data.json` itself were not downloaded or counted.
- SecurityTrails marketing pages (bot check, HTTP 403), pricing, free-tier limits, and the individual endpoint pages for DNS history (HTTP 404). Only the API overview and the reference index were read.
- Epieos pricing and module list. Only the home page and the Maltego listing were read.
- Predicta Search prices (none shown on the home page) and its code of ethics (referenced, not read).
- OSINT Industries ethics and compliance page (HTTP 404 at the URL tried). Its pricing page contained placeholder text, so the figures are indicative. Its accuracy claims were not tested.
- OSINT Curious ethics material. The dated article URL tried returned 404; only the ethics tag page loaded, and it lists one post about reporting illegal activity without its text. Nothing from OSINT Curious is relied on above.
- Trace Labs contestant guide PDF (connection refused) and the 2026 CTF preparation blog post (HTTP 403). Flag categories and point values are therefore not described.
- Maltego features beyond the two docs pages read: collections, graph views, export formats, sharing and pricing.
- Shodan pricing and Shodan Monitor details beyond the home page description.
- crt.sh JSON output format, rate limits and usage policy. The search page does not describe them, and the project's GitHub page did not load.
- urlscan API quota numbers, and a claim seen only in a search snippet that public submissions containing personal data are reclassified automatically. A dedicated scan visibility docs page returned 404; visibility is described from the FAQ and the blog post.
- UC Berkeley Human Rights Center page on the Protocol and a West Point Lieber Institute commentary (both failed DNS resolution). The Protocol itself was read from the OHCHR PDF.
- Whether any reviewed tool offers public read-only share links. None of the pages read confirmed it.
- IntelTechniques individual tool pages. Only the index page was read.
