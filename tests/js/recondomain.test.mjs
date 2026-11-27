// Ownership leads in a Recon domain case (static/v2/js/recondomain.js): the readers for the tracker
// and ad IDs and for document metadata, the comparison with saved cases, the ledger rows and the
// case file. Every domain and name here is invented. Nothing uses the network.
import "./rules.mjs";   // the content check over names needs its rules
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
const D = await import("../../static/v2/js/recondomain.js");
const { buildFindings, TIERS } = await import("../../static/v2/js/reconfindings.js");
const { buildCaseFile, parseCaseFile } = await import("../../static/v2/js/casefile.js");
const { sourceTally } = await import("../../static/v2/js/core.js");
const { reconTiles } = await import("../../static/v2/js/present.js");
const L = await import("../../static/v2/js/links.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const clone = (v) => JSON.parse(JSON.stringify(v));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---- answers, as the server gives them ---------------------------------------------------------------
const id = (kind, value, normalized, seen_in, extra = {}) => ({ kind, label: "x", value, normalized, key: `${kind}:${normalized}`, scope: "site", seen_in, search: `"${normalized}"`, meaning: "y", ...extra });
const TRACK = (domain, ids, extra = {}) => ({ domain, state: ids.length ? "ok" : "none", requests_target: true, url: `https://www.${domain}/`, final_host: `www.${domain}`, off_site: false, ids, count: ids.length, truncated: false, findings: [], note: "", cached: false, ...extra });
const A = TRACK("tidepool.example", [id("google_analytics_ua", "UA-48213907-3", "UA-48213907", ["inline_script"]), id("adsense", "ca-pub-4821730956127843", "pub-4821730956127843", ["script_src", "meta_tag"]), id("matomo", "stats.quillmoor-hosting.example/matomo", "stats.quillmoor-hosting.example/matomo", ["inline_script"], { site_id: "7" }), id("hotjar", "3948271", "3948271", ["inline_script"])]);
const B = TRACK("tidepool-shop.example", [id("google_analytics_ua", "UA-48213907-1", "UA-48213907", ["inline_script"]), id("google_analytics_4", "G-QX7L2M9KD4", "G-QX7L2M9KD4", ["script_src"])]);
const EMPTY = { title: "", author: "", last_modified_by: "", creator_software: "", producer: "", company: "", created: "", modified: "" };
const doc = (url, type, state, x = {}) => ({ url, type, state, size: null, last_archived: "2026-03-01T00:00:00Z", parsed: state === "ok" || state === "none", reason: "", reason_text: "", sources: [], ...EMPTY, ...x });
const DOCS = {
  domain: "tidepool.example", state: "ok", requests_target: true, source: "Internet Archive CDX index", listed: 11, listed_too_large: 1, listing_truncated: false,
  documents: [
    doc("https://www.tidepool.example/press/Launch.DOCX", "docx", "ok", { size: 1422, sources: ["core", "app"], title: "Spring price list", author: "Odalys Brandtmoor", last_modified_by: "Teodor Vashenko", creator_software: "Microsoft Office Word 16.0000", company: "Tidepool Supply Ltd", created: "2024-03-04T09:15:00Z", modified: "2025-11-20T16:42:10Z" }),
    doc("https://tidepool.example/files/annual-report-2021.pdf", "pdf", "ok", { size: 1004, sources: ["info"], title: "Annual report (2021)", author: "odalys brandtmoor", creator_software: "Quillwriter 7.2", producer: "Tidewater PDF Library 3.1", company: "Tidepool Supply Ltd", created: "2021-02-27T10:00:00+01:00", modified: "2021" }),
    doc("https://tidepool.example/files/rates.xlsx", "xlsx", "ok", { author: "kiosk-admin", sources: ["core"] }),
    doc("https://www.tidepool.example/old/brochure.pdf", "pdf", "unparsed", { size: 880, reason: "compressed", reason_text: "anything" }),
    doc("https://tidepool.example/files/blank.pdf", "pdf", "none"),
    doc("https://tidepool.example/files/handbook.pdf", "pdf", "rate_limited", { error: "The site was limiting requests, so this document was not asked for.", error_code: "rate_limited", error_detail: "" }),
  ],
  counts: { ok: 99 }, summary: { authors: [{ name: "Somebody Else", roles: ["author"], documents: 9, self_declared: true }], software: [], companies: [], note: "from the answer" },
  findings: [{ level: "flag", title: "from the answer", detail: "x" }], guard: { text: "Odalys Brandtmoor\nTidepool Supply Ltd\nSpring price list" }, note: "", cached: false,
};

// ---- tracker and ad IDs: the reader ---------------------------------------------------------------------
{
  const t = D.readTrackerIds(A);
  ok(t.state === "ok" && t.count === 4 && t.domain === "tidepool.example" && t.final_host === "tidepool.example", "an answer is read");
  ok(t.ids[0].label === "Google Analytics (Universal)" && t.ids[0].scope === "account" && /account/.test(t.ids[0].meaning) && t.ids[0].search === '"UA-48213907-"', "label, scope, meaning and search text are CrawlR's own for the kind, not the answer's");
  ok(t.ids[0].key === "google_analytics_ua:UA-48213907" && t.ids[2].site_id === "7" && t.ids[1].search === '"pub-4821730956127843"', "the key is rebuilt from the kind and the normalized ID");
  ok(t.findings.length === 4 && t.findings.every((f) => f.level === "info") && /Seen in an inline script\./.test(t.findings[0].detail), "every finding is info, and says where the ID was seen");
  ok(same(D.readTrackerIds(clone(t)), t) && D.readTrackerIds(t) === t, "the reader is idempotent");
  const none = D.readTrackerIds(TRACK("quiet-cove.example", []));
  ok(none.state === "none" && none.note === D.TRACKER_NONE && /not proof the site has none/.test(none.note), "none carries its caveat");
  const off = D.readTrackerIds(TRACK("parked-harbor.example", [id("adsense", "ca-pub-1", "pub-1", ["attribute"])], { url: "https://lot.sedge-parking.example/x", off_site: true, truncated: true }));
  ok(off.off_site && /redirects to another site \(lot\.sedge-parking\.example\)/.test(off.note) && /not necessarily parked-harbor\.example's/.test(off.note) && off.note.endsWith(D.TRACKER_CAPPED), "off site and truncated are said, with whose IDs these are");
  const blocked = D.readTrackerIds({ domain: "blocked-quay.example", state: "blocked", ids: [id("hotjar", "1", "1", [])], error: "The site refused the request, so its page could not be read.", error_code: "blocked", error_detail: "" });
  ok(blocked.state === "blocked" && blocked.error_code === "blocked" && blocked.ids.length === 0, "blocked stays blocked and holds no ID");
  const thrown = D.readTrackerIds({ error: "Too many requests. Try again in a minute.", error_code: "rate_limited", error_detail: "" });
  ok(thrown.state === "failed" && thrown.error_code === "rate_limited", "a request that failed is failed, never none");
  ok(D.readTrackerIds({ state: "ok" }).state === "none" && D.readTrackerIds({ state: "weird" }) === null && D.readTrackerIds(null) === null && D.readTrackerIds("x") === null, "an answer with no usable row is none; anything unreadable is dropped");
  // Hostile rows.
  const evil = D.readTrackerIds(TRACK("tidepool.example", [
    id("made_up_kind", "X-1", "X-1", ["inline_script"]), { ...id("hotjar", '12"><script>', "12", ["nowhere", "inline_script", "inline_script"]), label: "<img>", meaning: "Owned by Mallory.", search: "https://evil.example/?q=12", site_id: "7; drop" },
    id("google_tag_manager", "G".repeat(500), "N".repeat(500), ["script_src"]), id("hotjar", "", "", []), ...Array.from({ length: 200 }, (_, i) => id("yandex_metrica", String(10000 + i), String(10000 + i), ["inline_script"])),
  ], { url: "javascript:alert(1)", note: "Owned by Mallory.", findings: [{ level: "flag", title: "pwn", detail: "x" }] }));
  const s = JSON.stringify(evil);
  ok(evil.ids.length === 60 && evil.ids[0].kind === "hotjar" && evil.ids[0].value === "12script" && evil.ids[0].label === "Hotjar" && same(evil.ids[0].seen_in, ["inline_script"]) && !("site_id" in evil.ids[0]), "an unknown kind is dropped, text is cleaned, places are known ones, the list is capped at 60");
  ok(!/Mallory|evil\.example|javascript:|pwn|<img>/.test(s) && evil.url === "" && evil.ids[1].value.length === 120 && evil.findings.every((f) => f.level === "info"), "no sentence, address or flag from the answer survives");
}
// ---- the comparison with saved cases ----------------------------------------------------------------------------
{
  const hist = [
    { id: "c3", type: "RECON", target: "tidepool.example", timestamp: Date.UTC(2026, 10, 27), results: { tracker_ids: A } },
    { id: "c2", type: "RECON", target: "Tidepool-Shop.example", timestamp: Date.UTC(2026, 10, 20), results: { dns: {} } },                         // the latest run read no IDs
    { id: "c1", type: "RECON", target: "tidepool-shop.example", timestamp: Date.UTC(2026, 10, 12), results: { tracker_ids: B }, imported: 5 },
    { id: "c0", type: "RECON", target: "tidepool-shop.example", timestamp: Date.UTC(2026, 9, 1), results: { tracker_ids: B } },
    { id: "i1", type: "INVESTIGATE", target: "ua-48213907", timestamp: 1, results: { tracker_ids: B } },
    { id: "b1", type: "RECON", target: "blocked-quay.example", timestamp: 2, results: { tracker_ids: { state: "blocked", error: "x", error_code: "blocked" } } },
    { id: "p1", type: "RECON", target: "parked-harbor.example", timestamp: Date.UTC(2026, 10, 1), results: { tracker_ids: TRACK("parked-harbor.example", [id("adsense", "ca-pub-4821730956127843", "pub-4821730956127843", ["attribute"])], { off_site: true }) } },
    null, "x", { id: 5, type: "RECON", target: "n.example", results: { tracker_ids: B } },
  ];
  const sh = D.sharedTrackers(A, hist, "tidepool.example");
  ok(Object.keys(sh.byKey).length === 2 && sh.compared === 2, "two IDs are shared, across two other cases that read IDs");
  const ua = sh.byKey["google_analytics_ua:UA-48213907"];
  ok(ua.length === 1 && ua[0].id === "c1" && ua[0].target === "tidepool-shop.example" && ua[0].day === "2026-11-12" && ua[0].imported === true, "UA-48213907-3 and UA-48213907-1 are one account; one row per other target, its latest run that read IDs");
  ok(D.sharedText(ua[0]) === "Shared with tidepool-shop.example (case from 2026-11-12, opened from a case file)" && D.sharedText(sh.byKey["adsense:pub-4821730956127843"][0]) === "Shared with parked-harbor.example (case from 2026-11-01)", "the sentence names the domain and the day of the case");
  ok(sh.byKey["adsense:pub-4821730956127843"][0].off_site === true, "a case whose IDs were another site's says so");
  ok(same(D.sharedTrackers(B, hist, "tidepool-shop.example").byKey["google_analytics_ua:UA-48213907"].map((x) => x.id), ["c3"]), "the comparison never matches a case with itself");
  ok(same(D.sharedTrackers(null, hist, "x").byKey, {}) && same(D.sharedTrackers(A, null, "x"), { byKey: {}, compared: 0 }) && D.sharedTrackers({ state: "blocked", error: "x" }, hist, "x").compared === 0, "nothing to compare is an empty answer");
  ok(/A shared ID suggests one operator/.test(D.SHARED_CAVEAT) && /lead, not proof/.test(D.SHARED_CAVEAT), "the caveat words it as a lead");
  // The rows and the card.
  const { items } = buildFindings({ tracker_ids: A }, "tidepool.example", "domain", { shared: sh });
  const rows = items.filter((i) => i.tier === "ownership");
  ok(rows.length === 4 && items.every((i) => i.tier !== "flag") && rows.every((i) => i.link_kind === "none" && i.url === "" && i.source === "Tracker and ad IDs"), "each ID is a row of Ownership leads: never a flag, never a link");
  ok(/Shared with tidepool-shop\.example \(case from 2026-11-12/.test(rows[0].meta) && /A lead, not proof/.test(rows[0].meta) && !/Shared/.test(rows[3].meta), "a shared row says so, as a lead");
  ok(same(buildFindings({ tracker_ids: A }, "tidepool.example", "domain").items.map((i) => i.key), items.map((i) => i.key)), "the share changes what a row says, never its key");
  ok(buildFindings({ tracker_ids: A }, "203.0.113.10", "ip").items.length === 0, "only a domain case has these rows");
  ok(TIERS.some((t) => t.id === "ownership") && TIERS.findIndex((t) => t.id === "ownership") < TIERS.findIndex((t) => t.id === "inventory"), "the group sits before the subdomains");
  const card = D.trackerCard(A, sh);
  ok(/Shared with tidepool-shop\.example/.test(card.body) && /data-open-case="c1"/.test(card.body) && /data-copy="&quot;UA-48213907-&quot;"/.test(card.body) && /a bare number/.test(card.body) && /Nothing is sent anywhere/.test(card.body), "the card has the share, a button for that case, the search text to copy and the comparison's promise");
  const hrefs = [...card.body.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
  ok(hrefs.length === 1 && hrefs[0] === "https://www.tidepool.example/" && !/UA-48213907|pub-4821/.test(hrefs.join()), "its only link is the page that was read: no address carries an ID");
  const notice = D.sharedNotice(A, sh);
  ok(/Shared tracker IDs/.test(notice) && (notice.match(/data-open-case/g) || []).length === 2 && D.sharedNotice(A, { byKey: {} }) === "" && D.sharedNotice(B, { byKey: {} }) === "", "the notice lists each share with its button, and is absent without one");
  ok(/blocked by site/.test(D.trackerCard({ state: "blocked", error: "The site refused the request, so its page could not be read.", error_code: "blocked" }).badge) && /none found/.test(D.trackerCard(TRACK("q.example", [])).badge) && /failed/.test(D.trackerCard({ error: "x", error_code: "timeout" }).badge), "blocked, none and failed are three badges");
  const xss = D.trackerCard(TRACK("tidepool.example", [id("matomo", "a.example/<img src=x onerror=1>", "a.example/<img src=x onerror=1>", ["inline_script"])]), { byKey: { "matomo:a.example/img src=x onerror=1": [{ id: 'c"><script>', target: "<b>t</b>", day: "2026-01-01" }] }, compared: 1 });
  ok(!/<img|<script|<b>t/.test(xss.body), "values from a page and from History are escaped");
}
// ---- document metadata: the reader ------------------------------------------------------------------------------
{
  const d = D.readDocMeta(DOCS);
  ok(d.state === "ok" && d.documents.length === 6 && same(d.counts, { ok: 3, unparsed: 1, none: 1, rate_limited: 1 }), "an answer is read, and the counts are rebuilt from the rows");
  ok(!("guard" in d) && !JSON.stringify(d).includes("guard") && !d.names_held, "guard text is read and removed");
  ok(d.summary.authors.length === 3 && d.summary.authors[0].name === "Odalys Brandtmoor" && d.summary.authors[0].documents === 2 && d.summary.authors.every((a) => a.self_declared === true) && !JSON.stringify(d).includes("Somebody Else"), "names are tallied here from the rows, case-blind; the answer's own summary is not used");
  ok(d.summary.note === D.DOC_NAMES_NOTE && /Nothing verifies it/.test(d.summary.note) && d.findings.every((f) => f.level === "info") && d.findings.length === 3 && !JSON.stringify(d).includes("from the answer"), "the caveat is CrawlR's own and every finding is info");
  ok(d.documents[3].reason_text === D.DOC_REASONS.compressed && d.documents[1].modified === "2021" && d.documents[1].created === "2021-02-27T10:00:00+01:00", "a reason is CrawlR's own sentence; partial dates are kept");
  ok(same(D.readDocMeta(clone(d)), d), "the reader is idempotent");
  ok(D.countsText(d.counts) === "3 read, 1 read, declares nothing, 1 rate limited, 1 could not be parsed", "the counts name every state");
  // Each top-level state.
  const none = D.readDocMeta({ domain: "tidepool.example", state: "none", documents: [], note: "x" });
  ok(none.state === "none" && none.note === D.DOC_NO_LISTING && !none.error, "no listing is none, with its caveat");
  const limited = D.readDocMeta({ domain: "tidepool.example", state: "rate_limited", documents: [], error: "Rate limited by the source. Try again in a few minutes.", error_code: "rate_limited" });
  const failed = D.readDocMeta({ domain: "tidepool.example", state: "failed", documents: [], error: "The source took too long to answer.", error_code: "timeout", error_detail: "ReadTimeout" });
  ok(limited.state === "rate_limited" && failed.state === "failed" && failed.error_code === "timeout" && limited.error && failed.error, "an archive that could not be asked is rate limited or failed, with its error");
  const blocked = D.readDocMeta({ domain: "tidepool.example", state: "blocked", documents: [doc("https://tidepool.example/a.pdf", "pdf", "blocked", { error: "The site refused the request for this document.", error_code: "blocked" }), doc("https://tidepool.example/b.pdf", "pdf", "too_large", { size: 9301724 }), doc("https://tidepool.example/c.pdf", "pdf", "blocked")] });
  ok(blocked.state === "blocked" && blocked.error_code === "blocked" && /No document could be read: 2 blocked by site, 1 too large, not read\./.test(blocked.error) && blocked.documents[1].error_code === "too_large", "documents that were refused make the lookup blocked, with what happened to each");
  const allNone = D.readDocMeta({ domain: "tidepool.example", state: "none", documents: [doc("https://tidepool.example/a.pdf", "pdf", "none"), doc("https://tidepool.example/b.pdf", "pdf", "ok")] });
  ok(allNone.state === "none" && !allNone.error && allNone.documents[1].state === "none" && allNone.note === "", "files that declare nothing are none (an ok row with no field is that too)");
  const tie = D.readDocMeta({ domain: "t.example", state: "ok", documents: [doc("https://t.example/a.pdf", "pdf", "unparsed"), doc("https://t.example/b.pdf", "pdf", "failed", { error_code: "not_found" })] });
  ok(tie.state === "failed", "a tie between states goes to the earlier of blocked, rate limited, failed, too large, unparsed");
  const refused = D.readDocMeta({ domain: "veiled-lantern.example", state: "refused", documents: DOCS.documents, summary: DOCS.summary });
  ok(refused.state === "refused" && refused.note === D.DOC_REFUSED && refused.documents.length === 0 && refused.skipped === true, "refused keeps nothing but the refusal");
  ok(D.readDocMeta({ domain: "tidepool.example", state: "ok", documents: [] }).state === "failed" && D.readDocMeta({ state: "odd" }) === null && D.readDocMeta(null) === null, "an answer that says ok and holds no usable row is failed, not none");
  // The source tally: failed, blocked and refused are never "none".
  const names = { doc_metadata: "Document metadata", tracker_ids: "Tracker and ad IDs" };
  const st = (c) => sourceTally(c, names).rows.map((r) => r.state).join();
  ok(st({ doc_metadata: d }) === "results" && st({ doc_metadata: none }) === "none" && st({ doc_metadata: allNone }) === "none" && st({ doc_metadata: blocked }) === "failed" && st({ doc_metadata: failed }) === "failed" && st({ doc_metadata: limited }) === "failed" && st({ doc_metadata: refused }) === "skipped", "in the count of sources: read, none, failed and not asked stay apart");
  ok(st({ tracker_ids: D.readTrackerIds(A) }) === "results" && st({ tracker_ids: D.readTrackerIds(TRACK("q.example", [])) }) === "none" && st({ tracker_ids: D.readTrackerIds({ state: "blocked", error: "x", error_code: "blocked" }) }) === "failed", "the same for the tracker IDs");
  // A failed ownership source never makes the Flags tile uncertain.
  const c = { dns: { records: { A: ["203.0.113.10"] } }, tracker_ids: D.readTrackerIds({ state: "blocked", error: "x", error_code: "blocked" }), doc_metadata: blocked };
  const tiles = reconTiles({ items: [], collected: D.withoutOwnership(c), type: "domain", failedKeys: [] });
  ok(!("tracker_ids" in D.withoutOwnership(c)) && "dns" in D.withoutOwnership(c) && tiles[0].id === "flags" && !/unknown|at least/.test(JSON.stringify(tiles[0])), "the tiles are built without the two ownership sources");
  // Hostile rows.
  const evil = D.readDocMeta({ domain: "tidepool.example", state: "ok", listed: 1e12, documents: [
    doc("https://evil.example/a.pdf", "pdf", "ok", { author: "Off Site" }), doc("http://tidepool.example/a.pdf", "pdf", "ok", { author: "Plain Http" }), doc("https://nottidepool.example/a.pdf", "pdf", "ok", { author: "Suffix Trick" }),
    doc("https://user:pw@tidepool.example/a.pdf", "pdf", "ok", { author: "With Credentials" }), doc("javascript:alert(1)", "pdf", "ok", { author: "Script" }), doc("https://tidepool.example/", "pdf", "ok", { author: "Home Page" }),
    doc("https://sub.tidepool.example/x.pdf", "exe", "ok", { author: "A".repeat(900), title: "T\u0007itle", created: "yesterday", sources: ["info", "elsewhere"], reason_text: "Owned by Mallory." }),
    doc("https://tidepool.example/y.pdf", "pdf", "unparsed", { reason: "made_up", reason_text: "Owned by Mallory." }), doc("https://tidepool.example/z.pdf", "pdf", "exploded"),
    ...Array.from({ length: 40 }, (_, i) => doc(`https://tidepool.example/n${i}.pdf`, "pdf", "none")),
  ], note: "Owned by Mallory." });
  const s = JSON.stringify(evil);
  ok(evil.documents.length === 12 && evil.documents[0].url === "https://sub.tidepool.example/x.pdf" && !/Off Site|Plain Http|Suffix Trick|With Credentials|Script|Home Page|Mallory|javascript/.test(s), "a document must be an https address with a path on the case's own domain; the rest are dropped with their rows");
  ok(evil.documents[0].author.length === 300 && evil.documents[0].title === "T itle" && evil.documents[0].created === "" && evil.documents[0].type === "pdf" && same(evil.documents[0].sources, ["info"]) && evil.documents[1].reason === "" && evil.listed === 100000, "text is clipped and cleaned, a date must be a date, the type is a known one");
  // The content check over the free text.
  const minor = D.readDocMeta({ ...clone(DOCS), guard: { text: "Class newsletter\nI'm 15 and in 8th grade" } });
  const minor2 = D.readDocMeta({ ...clone(DOCS), guard: {}, documents: [doc("https://tidepool.example/a.pdf", "pdf", "ok", { author: "Mira Calloway", title: "I'm 14 years old: my year 9 project" })] });
  ok(minor.names_held === true && minor2.names_held === true && !JSON.stringify(minor).includes("8th grade"), "text that suggests a minor holds the names back, and the guard text itself is not kept");
  ok(D.nameLead("Odalys Brandtmoor", d) && !D.nameLead("kiosk-admin", d) && !D.nameLead("Odalys Brandtmoor", minor) && !D.nameLead("x".repeat(40) + " " + "y".repeat(50), d), "a name of two words or more can open a name case, unless the names are held");
  // Rows, markup, export.
  const { items } = buildFindings({ doc_metadata: d }, "tidepool.example", "domain");
  const rows = items.filter((i) => i.tier === "ownership");
  ok(rows.length === 5 && items.every((i) => i.tier !== "flag") && rows[0].what === "Name in a document: Odalys Brandtmoor" && /self-declared text inside the file, not verified/.test(rows[0].meta), "names, the company and the software are rows of Ownership leads, worded as text from a file");
  ok(same(rows[0].action, { label: "Open a name case", pivot: "investigate", value: "Odalys Brandtmoor", type: "name", via: "the name Odalys Brandtmoor", source: "a document published on tidepool.example" }) && !rows[2].action && !buildFindings({ doc_metadata: minor }, "tidepool.example", "domain").items.some((i) => i.action), "a name row carries one pivot, to a name case; a held name carries none");
  ok(buildFindings({ doc_metadata: blocked }, "tidepool.example", "domain").items.length === 0, "a lookup that read nothing adds no row");
  const body = D.docBody(d);
  ok(/Name in file \(author\)/.test(body) && /self-declared/.test(body) && /Nothing verifies it/.test(body) && /It is not an employee list/.test(body) && (body.match(/data-pivot="investigate" data-pivot-type="name"/g) || []).length === 2, "the result labels names as text in a file, with the caveat and one button per usable name");
  ok(/could not be parsed/.test(body) && /The file may still carry names/.test(body) && /read, declares nothing/.test(body) && /rate limited/.test(body) && /was not asked for/.test(body), "every state of a document has its own words");
  const links = [...body.matchAll(/<a href="([^"]*)"[^>]*data-link-kind="([^"]*)"/g)];
  ok(links.length === 6 && links.every((m) => m[2] === "evidence" && L.LINK_KINDS.includes(m[2]) && /^https:\/\/(www\.)?tidepool\.example\/.+/.test(m[1])), "each document is an evidence link to the file on the target's own site");
  ok(/No document's metadata could be read/.test(D.docBody(blocked)) && /8\.9 MB declared by the site/.test(D.docBody(blocked)) && /often comes on a second try/.test(D.docBody(failed)) && /received no request/.test(D.docBody(failed)) && /No request was made/.test(D.docBody(refused)) && /not proof the site publishes none/.test(D.docBody(none)), "blocked, a timeout, a refusal and no listing each say what happened");
  ok(/text in a file suggests a minor/.test(D.docBody(minor)) && !/data-pivot/.test(D.docBody(minor)), "held names say why and have no button");
  const ask = D.docLookup("tidepool.example", null, {});
  ok(/requests files from the target's site/.test(ask) && /requests up to 8 of them from tidepool\.example itself/.test(ask) && /The site&#39;s logs will show a visit from CrawlR&#39;s server/.test(ask) && /up to 90 seconds/.test(ask) && /Read document metadata/.test(ask), "before the click the section says what is requested and from whom");
  ok(/Try again/.test(D.docLookup("tidepool.example", failed, {})) && /Try again/.test(D.docLookup("tidepool.example", blocked, {})) && /Read again/.test(D.docLookup("tidepool.example", d, {})) && !/data-doc-meta/.test(D.docLookup("veiled-lantern.example", refused, {})), "a failure offers Try again; a refusal offers nothing");
  const busy = D.docLookup("tidepool.example", d, { busy: true, seconds: 23 });
  ok(/role="status"/.test(busy) && /data-doc-cancel/.test(busy) && /23 s/.test(busy) && !/data-doc-meta/.test(busy), "while it runs there is a status, a clock and Cancel");
  ok(/disabled/.test(D.docLookup("tidepool.example", null, { blocked: true })), "the button waits for a run in flight");
  const xss = D.docBody(D.readDocMeta({ domain: "tidepool.example", state: "ok", documents: [doc("https://tidepool.example/%3Cimg%20src=x%3E.pdf", "pdf", "ok", { author: "<script>alert(1)</script> Mallory", title: "<b>bold</b>", company: '"><img src=x>' })] }));
  ok(!/<script|<img|<b>bold/.test(xss), "text from inside a file and a file's name are escaped");
  const md = D.ownershipMarkdown({ tracker_ids: A, doc_metadata: d }, D.sharedTrackers(A, [{ id: "c1", type: "RECON", target: "tidepool-shop.example", timestamp: Date.UTC(2026, 10, 12), results: { tracker_ids: B } }], "tidepool.example")).join("\n");
  ok(/## Tracker and ad IDs/.test(md) && /Shared with tidepool-shop\.example \(case from 2026-11-12\)/.test(md) && /## Document metadata/.test(md) && /name in file \(author\): Odalys Brandtmoor/.test(md) && /Nothing verifies it/.test(md) && !md.includes(String.fromCharCode(0x2014)), "the Markdown export has both sections, with the share and the caveat");
}
// ---- History and case files -----------------------------------------------------------------------------------------
{
  const read = D.readOwnership({ dns: { records: {} }, tracker_ids: A, doc_metadata: DOCS, other: 1 });
  ok(read.tracker_ids.ids[0].label === "Google Analytics (Universal)" && !("guard" in read.doc_metadata) && read.dns && read.other === 1, "a stored case is read through the two readers and nothing else is touched");
  ok(!("tracker_ids" in D.readOwnership({ tracker_ids: "x" })) && !("doc_metadata" in D.readOwnership({ doc_metadata: { state: "odd" } })), "a value that cannot be read is dropped");
  const file = (collected, o = {}) => JSON.stringify({ ...buildCaseFile({ mode: "recon", target: "tidepool.example", type: "domain", ran: 1700000000000, collected }), ...o });
  const r = parseCaseFile(file({ dns: { records: { A: ["203.0.113.10"] } }, tracker_ids: A, doc_metadata: DOCS }));
  ok(r.ok && r.entry.results.tracker_ids.count === 4 && r.entry.results.doc_metadata.documents.length === 6 && !JSON.stringify(r.entry).includes('"guard"'), "a Recon case file keeps both, read and bounded, without guard text");
  const moved = parseCaseFile(file({ dns: { records: {} }, tracker_ids: A, doc_metadata: DOCS }, { target: "other-site.example" }));
  ok(moved.ok && moved.entry.results.doc_metadata.state === "failed" && moved.entry.results.doc_metadata.documents.length === 0 && !JSON.stringify(moved.entry.results.doc_metadata).includes("Odalys"), "documents of another domain than the file's target are dropped, and the lookup is not called empty");
  const evil = parseCaseFile(file({ dns: { records: {} }, tracker_ids: { ...A, ids: [{ ...A.ids[0], label: "<script>", meaning: "Owned by Mallory." }], note: "Mallory" }, doc_metadata: { ...DOCS, names_held: "no", summary: { authors: [{ name: "Mallory Planted" }] } } }));
  ok(evil.ok && !JSON.stringify(evil.entry).includes("Mallory") && evil.entry.results.tracker_ids.ids[0].label === "Google Analytics (Universal)", "a file cannot plant a sentence, a label or a name that no document row carries");
  const inv = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "samexample", type: "username", collected: { github: { found: true }, tracker_ids: A, doc_metadata: DOCS } })));
  const ip = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: "203.0.113.10", type: "ip", collected: { asn: { found: true }, tracker_ids: A, doc_metadata: DOCS } })));
  ok(inv.ok && !("tracker_ids" in inv.entry.results) && !("doc_metadata" in inv.entry.results) && ip.ok && !("tracker_ids" in ip.entry.results), "the two keys belong to a Recon domain case and are dropped anywhere else");
  ok(parseCaseFile(file({ tracker_ids: "x", doc_metadata: 5 })).ok === false, "a file with nothing readable in it is refused as before");
}
// ---- an ID is compared by what it shows, and a page address is the case's own ----------------------------------
{
  // The comparison key comes from the value on the row, by the kind's rule. A stored "normalized" is not read.
  const shown = (kind, value, normalized) => D.readTrackerIds(TRACK("harbor-lane.example", [id(kind, value, normalized, ["script_src"])])).ids[0];
  ok(shown("google_analytics_4", "G-QX7L2M9KD4", "G-ZZ99ZZ99ZZ").key === "google_analytics_4:G-QX7L2M9KD4" && shown("google_analytics_4", "G-QX7L2M9KD4", "G-ZZ99ZZ99ZZ").normalized === "G-QX7L2M9KD4" && shown("google_analytics_4", "G-QX7L2M9KD4", "G-ZZ99ZZ99ZZ").search === '"G-QX7L2M9KD4"', "the key, the normalized ID and the search text all follow the value the row shows");
  ok(shown("google_analytics_ua", "UA-48213907-3", "UA-11111111").key === "google_analytics_ua:UA-48213907" && shown("google_analytics_ua", "UA-48213907-3", "").search === '"UA-48213907-"' && shown("adsense", "ca-pub-4821730956127843", "pub-1").key === "adsense:pub-4821730956127843" && shown("bing_site_verification", "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "x").key === "bing_site_verification:0A1B2C3D4E5F60718293A4B5C6D7E8F9" && shown("bing_site_verification", "0a1b2c3d4e5f60718293a4b5c6d7e8f9", "x").search === '"0a1b2c3d4e5f60718293a4b5c6d7e8f9"' && shown("matomo", "Stats.Quillmoor-Hosting.example/Matomo", "y").key === "matomo:stats.quillmoor-hosting.example/Matomo" && shown("hotjar", "1234567", "7654321").key === "hotjar:1234567", "each kind's rule is the server's: the account part of a Universal ID, the publisher part of an AdSense ID, a Bing token in capitals, a Matomo host in small letters, anything else as it is");
  ok(same(D.readTrackerIds(A).ids.map((i) => i.key), A.ids.map((i) => i.key)) && same(D.readTrackerIds(B).ids.map((i) => i.key), B.ids.map((i) => i.key)), "a server answer reads to the same keys as before");
  const mine = TRACK("harbor-lane.example", [id("google_analytics_4", "G-QX7L2M9KD4", "G-QX7L2M9KD4", ["script_src"])]);
  const other = { id: "f1", type: "RECON", target: "far-quay.example", timestamp: Date.UTC(2026, 10, 3), imported: 1, results: { tracker_ids: TRACK("far-quay.example", [id("google_analytics_4", "G-AB12CD34EF", "G-QX7L2M9KD4", ["script_src"])]) } };
  ok(same(D.sharedTrackers(mine, [other], "harbor-lane.example").byKey, {}) && D.sharedTrackers(mine, [other], "harbor-lane.example").compared === 1, "a saved case is not reported as sharing an ID it does not show");
  // The page the IDs were read from is on the case's own domain, unless the answer says the home page redirected away.
  const at = (url, extra = {}) => D.readTrackerIds(TRACK("harbor-lane.example", mine.ids, { url, ...extra }));
  ok(at("https://www.harbor-lane.example/").url === "https://www.harbor-lane.example/" && at("https://harbor-lane.example/shop").final_host === "harbor-lane.example", "an address on the domain or a subdomain of it is kept");
  ok(at("https://elsewhere.example/").url === "" && at("https://elsewhere.example/").final_host === "" && at("https://notharbor-lane.example/").url === "" && at("https://harbor-lane.example.elsewhere.example/").url === "" && !/elsewhere/.test(D.ownershipMarkdown({ tracker_ids: at("https://elsewhere.example/") }).join("\n")), "an address on another site is not shown as the page that was read");
  ok(at("https://lot.sedge-parking.example/x", { off_site: true }).url === "https://lot.sedge-parking.example/x" && at("https://lot.sedge-parking.example/x", { off_site: true }).off_site === true, "unless the answer says the home page redirects to another site, which the page then says too");
  ok(D.readTrackerIds({ ...at("https://www.harbor-lane.example/"), domain: "" }).url === "", "and with no domain to hold it to, no address is kept");
}
// ---- names are offered only from an answer the content check has read --------------------------------------------
{
  const MS = await import("../../static/v2/js/minorscan.js");
  const { RULES } = await import("./rules.mjs");
  const raw = { ...clone(DOCS), guard: { text: "Class newsletter\nI'm 15 and in 8th grade" } };
  const plain = clone(DOCS);
  MS.setRules(null);
  ok(!MS.rulesReady(), "(the rules are not loaded for the next checks)");
  const early = D.readDocMeta(raw), earlyPlain = D.readDocMeta(plain);
  ok(early.names_unscanned === true && earlyPlain.names_unscanned === true && !("guard" in early) && !D.nameLead("Odalys Brandtmoor", earlyPlain), "an answer read before the content rules have loaded is marked as not scanned, and offers no name");
  MS.setRules(RULES);
  ok(MS.rulesReady() && D.readDocMeta(raw).names_held === true && !D.readDocMeta(raw).names_unscanned && !D.nameLead("Odalys Brandtmoor", D.readDocMeta(raw)), "the same answer read again once the rules are in is scanned, guard text included");
  ok(!D.readDocMeta(plain).names_unscanned && D.nameLead("Odalys Brandtmoor", D.readDocMeta(plain)), "and a clean one offers its names");
  // The copy that was made without the scan has lost the guard text, so it stays held however often it is read.
  ok(D.readDocMeta(early).names_unscanned === true && D.readDocMeta(clone(early)).names_unscanned === true && !D.nameLead("Odalys Brandtmoor", D.readDocMeta(clone(early))) && !D.nameLead("Odalys Brandtmoor", early), "a copy read without the scan never offers a name, also after it was stored and read again");
  const rows = D.ownershipItems({ doc_metadata: D.readDocMeta(clone(earlyPlain)) }, "tidepool.example"), body = D.docBody(D.readDocMeta(clone(earlyPlain)));
  ok(rows.some((r) => /^Name in a document/.test(r.what)) && rows.every((r) => !r.action) && !/Open a name case/.test(body) && /their text was not checked\. Use Read again\./.test(body) && /not checked/.test(D.DOC_UNSCANNED), "its rows carry no button to open a name case, and the card says why and what to do");
  ok(D.readDocMeta({ ...clone(DOCS), names_unscanned: "yes" }).names_unscanned === undefined && D.readDocMeta({ ...clone(DOCS), names_unscanned: true }).names_unscanned === true, "only the literal mark holds the names, and it can only hold them");
}
// ---- the page keeps its promises ------------------------------------------------------------------------------------------
{
  const src = (f) => fs.readFileSync(new URL(`../../static/v2/js/${f}`, import.meta.url), "utf8");
  const recon = src("recon.js"), mod = src("recondomain.js");
  ok(!/\bfetch\(|\bpost\(|\bdocument\.(querySelector|body|createElement|getElementById)|innerHTML|localStorage/.test(mod.replace(/\/\/.*$/gm, "")), "recondomain.js has no DOM, no network and no storage");
  ok(/if \(OWNERSHIP_READERS\[key\]\) d = OWNERSHIP_READERS\[key\]\(/.test(recon) && /state\.collected\[DOC_KEY\] = read;/.test(recon) && /collected: readOwnership\(e\.results \|\| \{\}\)/.test(recon), "a live answer and a case from History reach the page only through a reader");
  ok((recon.match(/\/api\/recon\/doc-metadata/g) || []).length === 1 && /async function runDocMeta\(\)[\s\S]{0,2500}\/api\/recon\/doc-metadata/.test(recon) && /if \(e\.target\.closest\("\[data-doc-meta\]"\)\) runDocMeta\(\);/.test(recon) && !/jobs\.push\([^\n]*doc-metadata/.test(recon), "document metadata is requested in one place, from a click, never by a run");
  ok(/id: "trackers",[^\n]*types: \["domain"\],\s*on: true/.test(recon) && /if \(type === "domain" && on\("trackers"\)\) jobs\.push\(source\(TRACKER_SOURCE, "\/api\/recon\/tracker-ids"/.test(recon), "tracker IDs are a source with a switch, on by default, for a domain only");
  const ai = recon.slice(recon.indexOf("const aiBody"), recon.indexOf("const hasData"));
  ok(!/tracker_ids|doc_metadata|TRACKER_KEY|DOC_KEY/.test(ai), "neither is sent to the AI");
  ok(!(mod + src("imagemeta.js") + src("exif.js") + src("geo.js")).includes(String.fromCharCode(0x2014)), "no em dash in the new modules");
}

console.log(bad ? `${bad} of ${n} ownership checks failed` : `all ${n} ownership checks pass`);
if (bad) process.exit(1);
