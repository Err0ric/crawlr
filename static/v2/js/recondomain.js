// Ownership leads for a domain in Recon:
//   Tracker and ad IDs   POST /api/recon/tracker-ids    account IDs in the home page's markup (with the run)
//   Document metadata    POST /api/recon/doc-metadata   names, software and dates inside public PDF and Office files (on a click)
// No DOM, no network. Like deep.js, every answer goes through a reader before anything is shown,
// stored or exported: a live answer, a case in History and a case file are all outside data. A
// reader returns a checked, bounded copy and is idempotent. The fixed sentences (what a kind of
// ID means, why a file could not be parsed, the caveats) are CrawlR's own and are written here,
// so a stored case or a case file cannot put other words in their place.
//
// Nothing here is a flag. A shared ID suggests one operator, and agencies, theme vendors and
// copied templates share IDs too. A name inside a file is text somebody's software saved there.
// Both are leads, worded as leads.

import { h, raw, esc, link, fmtNum, plural, looksLikeName } from "./core.js";
import { parseUrl, hostOf, isDomain } from "./links.js";
import { cleanText } from "./deep.js";
import { adultHost } from "./adult.js";
import { scanProfiles, rulesReady } from "./minorscan.js";

const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const lc = (s) => String(s ?? "").trim().toLowerCase().replace(/\.$/, "");
const line = (v, n) => (typeof v === "string" || typeof v === "number" ? Array.from(cleanText(v).replace(/\s+/g, " ").trim()).slice(0, n).join("") : "");
const count = (v, max = 100000) => (Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), max) : 0);
const memo = (fn) => { const seen = new WeakMap(); return (v) => { if (!isObj(v)) return null; if (!seen.has(v)) { const out = fn(v); seen.set(v, out); if (isObj(out)) seen.set(out, out); } return seen.get(v); }; };
const errorOf = (v, fallback) => ({ error: line(v.error, 300) || fallback, error_code: line(v.error_code, 40) || "request_failed", error_detail: line(v.error_detail, 300) });
const domainOf = (v) => { const d = lc(typeof v === "string" ? v : ""); return isDomain(d) ? d : ""; };
const dayOf = (ts) => (Number.isFinite(ts) && ts > 0 ? new Date(ts).toISOString().slice(0, 10) : "");

export const TRACKER_KEY = "tracker_ids", DOC_KEY = "doc_metadata";
export const OWNERSHIP_KEYS = [TRACKER_KEY, DOC_KEY];
export const TRACKER_SOURCE = "Tracker and ad IDs", DOC_SOURCE = "Document metadata";
export const OWNERSHIP_TIER = { id: "ownership", title: "Ownership leads", cls: "", collapseOver: 12, limit: 120, blurb: "Account IDs in the home page's markup and names saved inside public documents. A shared ID or a name is a lead to follow, not proof of who runs the site." };

// ---- tracker and ad IDs -----------------------------------------------------------------------------
// kind -> [label, scope, what a match means]. The same table as modules/tracker_ids.py.
export const TRACKER_KINDS = {
  google_analytics_ua: ["Google Analytics (Universal)", "account", "The number before the last dash is the account. Properties of one account share it."],
  google_analytics_4: ["Google Analytics 4", "site", "A measurement ID belongs to one data stream. The same ID on two sites means both report into one property."],
  google_tag_manager: ["Google Tag Manager", "site", "A container ID. The same container on two sites means one person manages the tags of both."],
  google_ads: ["Google Ads", "account", "A conversion ID of one Google Ads account."],
  adsense: ["Google AdSense", "account", "A publisher ID: one per AdSense account, which is the account that gets paid."],
  google_site_verification: ["Google site verification", "account", "A Search Console token. It is usually the same for every site one Google account verifies, but that is not guaranteed."],
  bing_site_verification: ["Bing site verification", "account", "A Bing Webmaster token. It is usually the same for every site one account verifies."],
  meta_pixel: ["Meta pixel", "site", "A pixel ID. One pixel can be placed on several sites of the same business."],
  hotjar: ["Hotjar", "site", "A Hotjar site ID."],
  yandex_metrica: ["Yandex Metrica", "site", "A counter number. One counter can be placed on several sites."],
  matomo: ["Matomo", "site", "The address of the Matomo server the page reports to. Sites that report to the same private server are usually run together."],
  cloudflare_insights: ["Cloudflare Web Analytics", "site", "A beacon token issued per site, so it is rarely shared."],
  microsoft_clarity: ["Microsoft Clarity", "site", "A Clarity project ID."],
  linkedin_insight: ["LinkedIn Insight", "account", "A partner ID of one LinkedIn ads account."],
};
const SEEN_IN = { script_src: "a script address", inline_script: "an inline script", meta_tag: "a meta tag", noscript_tag: "an image or frame address", attribute: "a tag attribute" };
// A bare number: the cross-case comparison is exact, the copied search text will match unrelated pages.
const BARE_NUMBER = new Set(["hotjar", "yandex_metrica", "meta_pixel", "linkedin_insight"]);
const SCOPE_WORD = { account: "one per account", site: "one per site or tag" };
export const TRACKER_STATES = ["ok", "none", "blocked", "failed"];
export const TRACKER_NONE = "No tracker or ad account ID was found in the home page's own markup. IDs loaded by an external script or through a tag manager are not visible here, so this is not proof the site has none.";
export const TRACKER_CAPPED = "Only the first 1.5 MB of the page was read.";
export const SHARED_CAVEAT = "A shared ID suggests one operator. Agencies, theme vendors and copied templates put one ID on unrelated sites too, so treat it as a lead, not proof.";
export const offSiteText = (d) => `The home page redirects to another site${d.final_host ? ` (${d.final_host})` : ""}. These IDs were read from that site's page, so they are that site's and not necessarily ${d.domain || "this domain"}'s.`;
const MAX_IDS = 60;
const seenText = (row) => (row.seen_in.length ? `Seen in ${row.seen_in.map((w) => SEEN_IN[w]).join(" and ")}.` : "");
const safeHttp = (u, max = 600) => { const s = typeof u === "string" ? u.trim() : ""; const x = s && s.length <= max ? parseUrl(s) : null; return x && !x.username && !x.password ? s : ""; };

function readId(v) {
  if (!isObj(v) || !Object.hasOwn(TRACKER_KINDS, v.kind)) return null;
  const value = line(v.value, 120).replace(/["<>]/g, "");
  if (!value) return null;
  const normalized = line(v.normalized, 120).replace(/["<>]/g, "") || value;
  const [label, scope, meaning] = TRACKER_KINDS[v.kind];
  const search = v.kind === "google_analytics_ua" ? `"${normalized}-"` : v.kind === "bing_site_verification" ? `"${value}"` : `"${normalized}"`;
  const out = { kind: v.kind, label, value, normalized, key: `${v.kind}:${normalized}`, scope, seen_in: (Array.isArray(v.seen_in) ? v.seen_in : []).filter((w, i, a) => Object.hasOwn(SEEN_IN, w) && a.indexOf(w) === i), search, meaning };
  const site = line(v.site_id, 12);
  if (/^\d{1,12}$/.test(site)) out.site_id = site;
  return out;
}
export const readTrackerIds = memo((v) => {
  const failed = !!(v.error || v.error_code);
  const state = TRACKER_STATES.includes(v.state) ? v.state : failed ? "failed" : "";
  if (!state) return null;
  const out = { domain: domainOf(v.domain), state, requests_target: true, url: "", final_host: "", off_site: false, ids: [], count: 0, truncated: false, findings: [], note: "", cached: v.cached === true };
  if (state === "blocked" || state === "failed") return { ...out, ...errorOf(v, state === "blocked" ? "The site refused the request, so its page could not be read." : "The home page could not be read.") };
  out.url = safeHttp(v.url);
  out.final_host = out.url ? hostOf(out.url) : "";
  out.off_site = v.off_site === true;
  out.truncated = v.truncated === true;
  const seen = new Set();
  for (const r of Array.isArray(v.ids) ? v.ids.slice(0, MAX_IDS * 2) : []) { const id = readId(r); if (id && !seen.has(`${id.kind}:${id.value}`) && out.ids.length < MAX_IDS) { seen.add(`${id.kind}:${id.value}`); out.ids.push(id); } }
  // A page that was read and gave no usable row is "none", whatever the answer called itself.
  out.state = out.ids.length ? "ok" : "none";
  out.count = out.ids.length;
  out.findings = out.ids.map((r) => ({ level: "info", title: `${r.label}: ${r.value}`, detail: [seenText(r), r.meaning].filter(Boolean).join(" ") }));
  out.note = [out.state === "none" ? TRACKER_NONE : "", out.off_site ? offSiteText(out) : "", out.truncated ? TRACKER_CAPPED : ""].filter(Boolean).join(" ");
  return out;
});

// Which of this case's IDs another Recon case saved in this browser also carries. `history` is
// the History list (newest first); one case per other target, its latest run that read IDs.
// Nothing is sent anywhere: this compares two things already in the browser.
//   { byKey: { "<kind:normalized>": [{ id, target, day, imported, off_site }] }, compared }
export function sharedTrackers(d, history, target = "") {
  const mine = readTrackerIds(d), out = { byKey: {}, compared: 0 };
  if (!mine || mine.state !== "ok") return out;
  const keys = new Set(mine.ids.map((i) => i.key)), done = new Set([lc(target)]);
  for (const e of Array.isArray(history) ? history : []) {
    if (!isObj(e) || e.type !== "RECON" || typeof e.target !== "string" || typeof e.id !== "string" || !isObj(e.results)) continue;
    const other = lc(e.target);
    if (!other || done.has(other)) continue;
    const o = readTrackerIds(e.results[TRACKER_KEY]);
    if (!o || o.state !== "ok") continue;
    done.add(other); out.compared++;
    for (const id of o.ids) if (keys.has(id.key)) {
      const list = (out.byKey[id.key] ||= []);
      if (list.length < 6) list.push({ id: line(e.id, 60), target: line(e.target, 253), day: dayOf(e.timestamp), imported: !!e.imported, off_site: o.off_site });
    }
  }
  return out;
}
export const sharedText = (s) => `Shared with ${s.target} (case from ${s.day || "an unknown date"}${s.imported ? ", opened from a case file" : ""})`;

// ---- document metadata --------------------------------------------------------------------------------
export const DOC_STATES = ["ok", "none", "rate_limited", "failed", "blocked", "too_large", "unparsed", "refused"];
const ROW_STATES = ["ok", "none", "blocked", "rate_limited", "failed", "too_large", "unparsed"];
const DOC_TYPES = ["pdf", "docx", "xlsx", "pptx"];
const DOC_ORIGINS = ["info", "xmp", "core", "app"];
// Why a file could not be parsed: the REASONS table of modules/doc_parse.py.
export const DOC_REASONS = {
  not_pdf: "The file does not start like a PDF.",
  encrypted: "The file is encrypted, so its metadata cannot be read.",
  truncated: "The file is cut short, so its metadata could not be found.",
  compressed: "The metadata sits in a compressed part of the file, which CrawlR does not unpack.",
  bad_pdf: "The file's metadata is damaged or written in a way CrawlR does not read.",
  bad_zip: "The file is not a readable Office archive.",
  zip_bomb: "The archive's metadata is larger than any real document's, so it was not unpacked.",
  xml_entities: "The metadata declares XML entities, so it was not parsed.",
  bad_xml: "The metadata inside the file is not readable XML.",
  legacy_office: "This is an older or password-protected Office file, which CrawlR does not read.",
  unknown_format: "The file is not a PDF or an Office document.",
};
// One word per state of a document. Only "metadata read" and "declares nothing" are answers.
export const DOC_STATE_WORD = { ok: "metadata read", none: "read, declares nothing", unparsed: "could not be parsed", too_large: "too large, not read", failed: "failed", blocked: "blocked by site", rate_limited: "rate limited" };
export const DOC_NAMES_NOTE = "Names, companies and software come from text saved inside each file. The author's software wrote it, or somebody typed over it. Nothing verifies it, and a file may have been made by someone outside the organization.";
export const DOC_NO_LISTING = "The Internet Archive lists no PDF or Office document under this domain. Documents it never captured are not seen here, so this is not proof the site publishes none.";
export const DOC_REFUSED = "CrawlR does not read documents from adult or dating sites.";
export const DOC_HELD = "Names from these files are not offered as new cases: text in a file suggests a minor.";
export const DOC_NO_RULES = "Names are not offered as new cases until the page's content rules have loaded. Reload the page.";
const DOC_SOURCE_NAME = "Internet Archive CDX index";
const MAX_DOCS = 12;
const DATE = /^\d{4}(?:-\d{2}(?:-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?)?)?$/;
const when = (v) => (typeof v === "string" && DATE.test(v.trim()) ? v.trim() : "");
const TEXT_FIELDS = ["title", "author", "last_modified_by", "creator_software", "producer", "company"];
const AUTHOR_ROLES = { author: "author", last_modified_by: "last modified by" }, SOFTWARE_ROLES = { creator_software: "made with", producer: "PDF written by" };

// A document's address: https, on the domain or a subdomain of it, with a path. Anything else is dropped with its row.
function docUrl(u, domain) {
  const s = safeHttp(u), x = s ? parseUrl(s) : null;
  if (!x || x.protocol !== "https:" || x.port || !domain) return "";
  const host = x.hostname.toLowerCase().replace(/\.$/, "");
  return (host === domain || host.endsWith(`.${domain}`)) && x.pathname.length > 1 && !adultHost(s) ? s : "";
}
function readDoc(v, domain) {
  if (!isObj(v) || !ROW_STATES.includes(v.state)) return null;
  const url = docUrl(v.url, domain);
  if (!url) return null;
  const typed = DOC_TYPES.includes(v.type) ? v.type : (/\.(pdf|docx|xlsx|pptx)$/i.exec(parseUrl(url).pathname) || [])[1]?.toLowerCase() || "";
  const out = { url, type: typed, state: v.state, size: Number.isFinite(v.size) && v.size >= 0 ? Math.floor(v.size) : null, last_archived: when(v.last_archived), parsed: v.parsed === true, reason: "", reason_text: "", sources: [] };
  for (const k of [...TEXT_FIELDS, "created", "modified"]) out[k] = "";
  if (v.state === "ok") {
    for (const k of TEXT_FIELDS) out[k] = line(v[k], 300);
    out.created = when(v.created); out.modified = when(v.modified);
    out.sources = (Array.isArray(v.sources) ? v.sources : []).filter((s, i, a) => DOC_ORIGINS.includes(s) && a.indexOf(s) === i);
    // "ok" means a field is set. A row that says ok and carries nothing is "declares nothing".
    if (![...TEXT_FIELDS, "created", "modified"].some((k) => out[k])) out.state = "none";
    out.parsed = true;
  } else if (v.state === "none") out.parsed = true;
  else if (v.state === "unparsed") { out.reason = Object.hasOwn(DOC_REASONS, v.reason) ? v.reason : ""; out.reason_text = DOC_REASONS[out.reason] || "The file's metadata could not be read."; out.parsed = false; }
  else { out.parsed = false; Object.assign(out, errorOf(v, v.state === "blocked" ? "The site refused the request for this document." : v.state === "too_large" ? "The file is larger than 8 MB, so it was not read." : v.state === "rate_limited" ? "The site was limiting requests, so this document was not asked for." : "The document could not be fetched.")); if (v.state !== "failed") out.error_code = v.state; }
  return out;
}
// Distinct names over the documents that were read, most documents first. Case does not make a
// different name. Built here from the checked rows, never taken from the answer.
function tally(rows) {
  const seen = new Map();
  for (const [name, role, i] of rows) {
    if (!name) continue;
    const k = name.toLowerCase();
    if (!seen.has(k)) seen.set(k, { name, roles: [], docs: new Set() });
    const e = seen.get(k);
    if (role && !e.roles.includes(role)) e.roles.push(role);
    e.docs.add(i);
  }
  return [...seen.values()].map((e) => ({ name: e.name, roles: e.roles, documents: e.docs.size })).sort((a, b) => b.documents - a.documents);
}
function summarize(docs) {
  const people = [], software = [], companies = [];
  docs.forEach((d, i) => {
    if (d.state !== "ok") return;
    people.push([d.author, "author", i], [d.last_modified_by, "last_modified_by", i]);
    software.push([d.creator_software, "creator_software", i], [d.producer, "producer", i]);
    companies.push([d.company, "", i]);
  });
  const authors = tally(people).map((a) => ({ ...a, self_declared: true }));
  const named = tally(companies).map((c) => ({ name: c.name, documents: c.documents, self_declared: true }));
  return { authors, software: tally(software), companies: named, note: authors.length || named.length ? DOC_NAMES_NOTE : "" };
}
// A document that did not answer this time and may answer later: refused, rate limited, or failed
// for a reason that can pass. "Not found", "redirects off site" and "not a document" are settled.
const SETTLED = ["not_found", "off_site", "not_document"];
export const unsettled = (docs) => (docs || []).filter((x) => x.state === "blocked" || x.state === "rate_limited" || (x.state === "failed" && !SETTLED.includes(x.error_code))).length;
const countsOf = (docs) => { const out = {}; for (const d of docs) out[d.state] = (out[d.state] || 0) + 1; return out; };
// "2 read, 1 could not be parsed, 1 blocked by site"
export const countsText = (counts) => ROW_STATES.filter((s) => counts[s]).map((s) => `${fmtNum(counts[s])} ${s === "ok" ? "read" : DOC_STATE_WORD[s]}`).join(", ");
const PRIORITY = ["blocked", "rate_limited", "failed", "too_large", "unparsed"];
function overall(docs) {
  const states = docs.map((d) => d.state);
  if (states.includes("ok")) return "ok";
  if (states.every((s) => s === "none")) return "none";
  const rest = states.filter((s) => s !== "none");
  return PRIORITY.reduce((best, s) => (rest.filter((x) => x === s).length > rest.filter((x) => x === best).length ? s : best), PRIORITY.find((s) => rest.includes(s)));
}
function docFindings(docs, summary) {
  const out = [], read = docs.filter((d) => d.state === "ok").length;
  const some = (rows, n) => rows.slice(0, n).map((r) => r.name).join(", ") + (rows.length > n ? ` and ${rows.length - n} more` : "");
  if (summary.authors.length) out.push({ level: "info", title: `${plural(summary.authors.length, "self-declared author name")} in ${plural(read, "public document")}`, detail: `${some(summary.authors, 6)}. Text from inside the files, not verified.` });
  if (summary.companies.length) out.push({ level: "info", title: "Company named in document metadata", detail: `${some(summary.companies, 6)}. Text from inside the files, not verified.` });
  if (summary.software.length) out.push({ level: "info", title: "Software that made the documents", detail: `${some(summary.software, 8)}.` });
  return out;
}
// The content check over the free text read from the files. `guard` is the answer's own guard
// text (every such value, one per line); it is read here and never kept.
function suggestsMinor(docs, guard = "") {
  const text = [guard, ...docs.flatMap((d) => [d.author, d.last_modified_by, d.company, d.title])].filter((x) => typeof x === "string" && x.trim()).join("\n").slice(0, 8000);
  if (!text) return false;
  // Without the rules the check cannot be made. That is not a signal, so it is not recorded; names
  // are simply not offered while the rules are missing (see nameLead).
  const r = scanProfiles([{ source: DOC_SOURCE, url: "", name: "", bio: "", text }], "", new Date());
  return r.blocked === true && r.kind !== "rules";
}
export const readDocMeta = memo((v) => {
  const domain = domainOf(v.domain);
  const empty = { domain, state: "none", requests_target: true, source: DOC_SOURCE_NAME, listed: 0, listed_too_large: 0, listing_truncated: false, documents: [], counts: {}, summary: { authors: [], software: [], companies: [], note: "" }, findings: [], note: "", cached: v.cached === true };
  // An adult or dating site: nothing is kept but the refusal, whatever the answer holds.
  if (v.state === "refused" || (domain && adultHost(domain))) return { ...empty, state: "refused", requests_target: false, reason: "adult_site", note: DOC_REFUSED, skipped: true, message: "Not read: adult or dating site" };
  const failed = !!(v.error || v.error_code);
  if (!DOC_STATES.includes(v.state) && !failed) return null;
  const docs = [];
  for (const r of Array.isArray(v.documents) ? v.documents.slice(0, MAX_DOCS * 2) : []) { const d = readDoc(r, domain); if (d && docs.length < MAX_DOCS && !docs.some((x) => x.url === d.url)) docs.push(d); }
  const out = { ...empty, listed: Math.max(count(v.listed), docs.length), listed_too_large: count(v.listed_too_large), listing_truncated: v.listing_truncated === true, documents: docs, counts: countsOf(docs) };
  if (!docs.length) {
    // No document row: the archive listed nothing (an answer), or it could not be asked (unknown).
    if (failed || v.state !== "none") return { ...out, state: v.state === "rate_limited" || v.error_code === "rate_limited" ? "rate_limited" : "failed", ...errorOf(v, v.state === "rate_limited" ? "Rate limited by the source. Try again in a few minutes." : "The list of documents could not be read.") };
    return { ...out, state: "none", note: DOC_NO_LISTING };
  }
  out.state = overall(docs);
  out.summary = summarize(docs);
  out.findings = docFindings(docs, out.summary);
  // Guard-only text is read once, for this, and dropped: it is never stored, exported or sent on.
  if (v.names_held === true || suggestsMinor(docs, isObj(v.guard) && typeof v.guard.text === "string" ? v.guard.text : "")) out.names_held = true;
  // No document was read and they are not all empty: the source did not answer. It is unknown,
  // never "none", so it carries error fields and counts as a source that failed.
  if (out.state !== "ok" && out.state !== "none") Object.assign(out, { error: `No document could be read: ${countsText(out.counts)}.`, error_code: out.state, error_detail: "" });
  return out;
});

export const OWNERSHIP_READERS = { [TRACKER_KEY]: readTrackerIds, [DOC_KEY]: readDocMeta };
// A case's collected results with the two ownership answers read (bounded, guard text removed).
// A value that cannot be read is dropped.
export function readOwnership(collected) {
  if (!isObj(collected)) return collected;
  const out = { ...collected };
  for (const [k, read] of Object.entries(OWNERSHIP_READERS)) if (k in out) { const v = read(out[k]); if (v) out[k] = v; else delete out[k]; }
  return out;
}
// The case without them, for the counts that can only be changed by a flag: neither source
// returns one, so a home page that could not be read never makes the Flags tile say "at least".
export const withoutOwnership = (collected) => { const out = { ...(isObj(collected) ? collected : {}) }; for (const k of OWNERSHIP_KEYS) delete out[k]; return out; };

// May this name open a name case? Two words or more, as a name case needs, and never when the
// files' text suggests a minor.
export const nameLead = (name, d) => !d?.names_held && rulesReady() && looksLikeName(name) && name.length <= 80;

// ---- ledger rows ---------------------------------------------------------------------------------------------
// Rows for the "Ownership leads" group. Never a flag. `shared` is sharedTrackers()'s answer.
export function ownershipItems(c, target, shared = { byKey: {} }) {
  const items = [], t = readTrackerIds(c?.[TRACKER_KEY]), d = readDocMeta(c?.[DOC_KEY]);
  if (t && t.state === "ok") for (const r of t.ids) {
    const also = shared.byKey?.[r.key] || [];
    items.push({ tier: "ownership", what: `${r.label}: ${r.value}`, url: "", source: TRACKER_SOURCE, key: `trk:${r.key}:${r.value}`,
      meta: [also.length ? `${also.map(sharedText).join("; ")}. A lead, not proof` : "", t.off_site ? `read from ${t.final_host || "another site"}, where the home page redirects` : "", SCOPE_WORD[r.scope], seenText(r).replace(/\.$/, "").replace(/^Seen/, "seen")].filter(Boolean).join(" · ") });
  }
  if (d && d.state === "ok") {
    const site = d.domain || lc(target);
    for (const a of d.summary.authors.slice(0, 40)) items.push({ tier: "ownership", what: `Name in a document: ${a.name}`, url: "", source: DOC_SOURCE, key: `docname:${a.name.toLowerCase()}`,
      meta: `${a.roles.map((r) => AUTHOR_ROLES[r]).filter(Boolean).join(" and ") || "named"} in ${plural(a.documents, "public file")} · self-declared text inside the file, not verified`,
      ...(nameLead(a.name, d) ? { action: { label: "Open a name case", pivot: "investigate", value: a.name, type: "name", via: `the name ${a.name}`, source: `a document published on ${site}` } } : {}) });
    for (const co of d.summary.companies.slice(0, 20)) items.push({ tier: "ownership", what: `Company in a document: ${co.name}`, url: "", source: DOC_SOURCE, key: `doccompany:${co.name.toLowerCase()}`, meta: `in ${plural(co.documents, "public file")} · self-declared text inside the file, not verified` });
    if (d.summary.software.length) items.push({ tier: "ownership", what: `Software that made the documents: ${d.summary.software.slice(0, 8).map((s) => s.name).join(", ")}`, url: "", source: DOC_SOURCE, key: "docsoftware", meta: "written into the files by the software itself" });
  }
  return items;
}

// ---- Markdown export ----------------------------------------------------------------------------------------
export function ownershipMarkdown(c, shared = { byKey: {} }) {
  const out = [], t = readTrackerIds(c?.[TRACKER_KEY]), d = readDocMeta(c?.[DOC_KEY]);
  if (t && (t.state === "ok" || t.state === "none")) {
    out.push(`## ${TRACKER_SOURCE}`, t.url ? `Read from ${t.url} (one request to the site).` : "", ...t.ids.map((r) => `- **${r.label}:** \`${r.value}\` · ${SCOPE_WORD[r.scope]} · search text \`${r.search}\`${(shared.byKey?.[r.key] || []).map((s) => ` · ${sharedText(s)}`).join("")}`),
      ...(Object.keys(shared.byKey || {}).length ? [`> ${SHARED_CAVEAT}`] : []), ...(t.note ? [`> ${t.note}`] : []), "");
  }
  if (d && d.documents.length) {
    out.push(`## ${DOC_SOURCE}`, `Files requested from the site itself, listed by the ${d.source}: ${countsText(d.counts)}.`, ...(d.summary.note ? [`> ${d.summary.note}`] : []),
      ...d.documents.map((x) => `- ${x.type ? `${x.type.toUpperCase()} · ` : ""}[${(x.title || fileName(x.url)).replace(/[[\]]/g, "")}](${x.url}) · ${DOC_STATE_WORD[x.state]}${[["name in file (author)", x.author], ["name in file (last modified by)", x.last_modified_by], ["company", x.company], ["made with", x.creator_software], ["PDF written by", x.producer], ["created", x.created], ["modified", x.modified]].filter(([, v]) => v).map(([k, v]) => ` · ${k}: ${v}`).join("")}${x.reason_text ? ` · ${x.reason_text}` : ""}${x.error ? ` · ${x.error}` : ""}`), "");
  } else if (d && d.state === "none") out.push(`## ${DOC_SOURCE}`, `> ${d.note}`, "");
  return out.filter((l, i, a) => l !== "" || a[i - 1] !== "");
}

// ---- markup ----------------------------------------------------------------------------------------------------
// Every value below is outside data and goes through h, esc or link.
const tag = (t, cls = "") => h`<span class="tag ${cls}">${t}</span>`;
const copyBtn = (text, what) => h`<button class="btn btn-sm" type="button" data-copy="${text}" aria-label="Copy ${what}">Copy</button>`;
const errDetail = (d) => (d.error_detail ? h`<details class="lg-detail"><summary>details</summary><code>${d.error_detail}</code></details>` : "");
export function fileName(u) {
  const p = parseUrl(u)?.pathname || "";
  let name = p.split("/").filter(Boolean).pop() || p;
  try { name = decodeURIComponent(name); } catch { /* shown as it is */ }
  return line(name, 80) || "document";
}
const fmtSize = (n) => (n === null ? "" : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`);

// The card under By source: { badge, body }. `has(id)`: is that case still in History?
export function trackerCard(v, shared = { byKey: {}, compared: 0 }, has = () => true) {
  const d = readTrackerIds(v);
  if (!d) return null;
  const asked = h`<p class="muted small">One request to the home page of ${d.domain || "the domain"}. Its logs will show a visit from CrawlR's server.</p>`;
  if (d.state === "blocked") return { badge: tag(d.error_code === "rate_limited" ? "rate limited by site" : "blocked by site", "warn"), body: h`<p class="muted">${d.error}</p><p class="muted small">The page was not read, so whether it carries an ID is unknown.</p>` + errDetail(d) };
  if (d.state === "failed") return { badge: tag(d.error_code === "rate_limited" ? "rate limited" : "failed", "bad"), body: h`<p class="muted">${d.error}</p><p class="muted small">The page was not read, so whether it carries an ID is unknown.</p>` + errDetail(d) };
  const read = d.url ? h`<p class="muted small">Read from ${raw(link(d.url, d.url, "", { kind: "evidence" }))}</p>` : "";
  const off = d.off_site ? h`<p class="own-note"><span class="tag warn">other site</span> ${offSiteText(d)}</p>` : "";
  if (d.state === "none") return { badge: tag("none found"), body: off + h`<p class="muted">${TRACKER_NONE}</p>${d.truncated ? raw(h`<p class="muted small">${TRACKER_CAPPED}</p>`) : ""}` + read + asked };
  const anyShared = d.ids.some((r) => shared.byKey?.[r.key]?.length);
  const rows = d.ids.map((r) => {
    const also = shared.byKey?.[r.key] || [];
    return h`<li class="own-id">
      <div class="own-head"><b>${r.label}</b><code class="mono">${r.value}</code>${raw(tag(SCOPE_WORD[r.scope]))}${r.site_id ? raw(tag(`site ${r.site_id} on that server`)) : ""}</div>
      <p class="own-what">${seenText(r)} ${r.meaning}</p>
      ${raw(also.map((s) => h`<p class="own-shared"><span class="tag">lead</span><span>${sharedText(s)}.${s.off_site ? " That case's IDs were read from the site its home page redirects to." : ""}</span>${has(s.id) ? raw(h`<button type="button" class="btn btn-sm" data-open-case="${s.id}">Open that case<span class="sr-only">: ${s.target}</span></button>`) : ""}</p>`).join(""))}
      <div class="own-search"><span class="dim">Search text</span><code>${r.search}</code>${raw(copyBtn(r.search, `search text for ${r.value}`))}${BARE_NUMBER.has(r.kind) ? raw('<span class="dim">a bare number: a search will also match unrelated pages</span>') : ""}</div>
    </li>`;
  }).join("");
  const compared = anyShared ? h`<p class="own-note">${SHARED_CAVEAT}</p>` : h`<p class="muted small">${shared.compared ? `No ID here is on ${shared.compared === 1 ? "the other Recon case" : `any of the ${fmtNum(shared.compared)} other Recon cases`} saved in this browser that read IDs.` : "No other Recon case saved in this browser has read IDs yet, so there is nothing to compare with."}</p>`;
  return { badge: tag(plural(d.count, "ID")) + (anyShared ? " " + tag("shared with a saved case") : ""),
    body: off + `<ul class="own-ids">${rows}</ul>` + compared
      + `<p class="muted small">The comparison is made in this browser against your saved Recon cases. Nothing is sent anywhere for it. The search text is for you to paste into a source-code or web search: CrawlR does not search for an ID.</p>`
      + (d.truncated ? h`<p class="muted small">${TRACKER_CAPPED}</p>` : "") + read + asked };
}
// A line above the findings when an ID is shared: the pivot should not wait behind a tab.
export function sharedNotice(v, shared, has = () => true) {
  const d = readTrackerIds(v);
  if (!d || d.state !== "ok") return "";
  const rows = d.ids.flatMap((r) => (shared.byKey?.[r.key] || []).map((s) => ({ r, s })));
  if (!rows.length) return "";
  return h`<div class="notice own-notice" role="note"><strong>Shared tracker ${rows.length === 1 ? "ID" : "IDs"}</strong><span>${SHARED_CAVEAT}</span><ul>${raw(rows.slice(0, 8).map(({ r, s }) => h`<li><span class="mono">${r.value}</span> (${r.label}): ${sharedText(s)}. ${has(s.id) ? raw(h`<button type="button" class="btn btn-sm" data-open-case="${s.id}">Open that case<span class="sr-only">: ${s.target}</span></button>`) : ""}</li>`).join(""))}</ul>${rows.length > 8 ? raw(h`<span>${rows.length - 8} more under By source.</span>`) : ""}</div>`;
}

const pivotBtn = (name, site) => h`<button type="button" class="btn btn-sm" data-pivot="investigate" data-pivot-type="name" data-value="${name}" data-via="the name ${name}" data-via-source="a document published on ${site}" data-confirm-run="1">Open a name case<span class="sr-only">: ${name}</span></button>`;
// What the document lookup found, in every state. Used by the section under the findings and by
// the card under By source.
export function docBody(v) {
  const d = readDocMeta(v);
  if (!d) return "";
  if (d.state === "refused") return h`<p class="own-note">${DOC_REFUSED} No request was made.</p>`;
  if (!d.documents.length) {
    if (d.state === "none") return h`<p class="muted">${DOC_NO_LISTING}</p><p class="muted small">Only the Internet Archive was asked. ${d.domain || "The site"} received no request.</p>`;
    const limited = d.state === "rate_limited";
    return h`<p class="own-note"><span class="tag ${limited ? "warn" : "bad"}">${limited ? "rate limited" : "failed"}</span> ${d.error}${d.error_code === "timeout" ? " The archive's list is slow for large sites and often comes on a second try." : ""}</p><p class="muted small">The list of documents could not be read, so whether the site publishes any is unknown. ${d.domain || "The site"} received no request.</p>` + errDetail(d);
  }
  const site = d.domain || "the site";
  const lead = h`<p class="card-lead">${d.listed > d.documents.length ? `The Internet Archive lists ${plural(d.listed, "document")} under this domain. The ${fmtNum(d.documents.length)} captured most recently were requested from ${site}: ` : `${plural(d.documents.length, "document")} requested from ${site}: `}${countsText(d.counts)}.</p>`
    + (d.state !== "ok" && d.state !== "none" ? h`<p class="own-note"><span class="tag warn">not read</span> No document's metadata could be read, so what the files say is unknown. That is not the same as files with no names in them.</p>` : "")
    + (d.state === "none" ? h`<p class="muted">Every document that was read declares nothing: no author, software or date.</p>` : "")
    + ((d.state === "ok" || d.state === "none") && unsettled(d.documents) ? h`<p class="own-note">${plural(unsettled(d.documents), "document")} did not answer this time, so the list of names may be incomplete. Try again in a few minutes.</p>` : "");
  const names = d.summary.authors.length ? h`<h4 class="own-h">Names in the files</h4><ul class="own-names">${raw(d.summary.authors.map((a) => h`<li><span class="own-name">${a.name}</span><span class="dim">${a.roles.map((r) => AUTHOR_ROLES[r]).filter(Boolean).join(" and ") || "named"} in ${plural(a.documents, "file")}</span><span class="src-how">self-declared</span>${nameLead(a.name, d) ? raw(pivotBtn(a.name, site)) : ""}</li>`).join(""))}</ul>` : "";
  const companies = d.summary.companies.length ? h`<h4 class="own-h">Companies in the files</h4><ul class="own-names">${raw(d.summary.companies.map((c) => h`<li><span class="own-name">${c.name}</span><span class="dim">in ${plural(c.documents, "file")}</span><span class="src-how">self-declared</span></li>`).join(""))}</ul>` : "";
  const software = d.summary.software.length ? h`<h4 class="own-h">Software</h4><ul class="own-names">${raw(d.summary.software.map((s) => h`<li><span class="own-name">${s.name}</span><span class="dim">${s.roles.map((r) => SOFTWARE_ROLES[r]).filter(Boolean).join(", ")} · ${plural(s.documents, "file")}</span></li>`).join(""))}</ul>` : "";
  const caveat = d.summary.note ? h`<p class="own-note">${DOC_NAMES_NOTE} A name here is a lead for a name case, one click at a time. It is not an employee list.</p>` : "";
  const held = d.summary.authors.length && (d.names_held || !rulesReady()) ? h`<p class="own-note">${d.names_held ? DOC_HELD : DOC_NO_RULES}</p>` : "";
  const docs = d.documents.map((x) => {
    const bad = x.state === "failed", unknown = x.state !== "ok" && x.state !== "none";
    const fields = [["Title", x.title], ["Name in file (author)", x.author], ["Name in file (last modified by)", x.last_modified_by], ["Company", x.company], ["Made with", x.creator_software], ["PDF written by", x.producer], ["Created", x.created], ["Modified", x.modified]].filter(([, val]) => val);
    return h`<li class="own-doc ${unknown ? "unknown" : ""}">
      <div class="own-head">${x.type ? raw(tag(x.type.toUpperCase())) : ""}<b>${raw(link(x.url, fileName(x.url), "", { kind: "evidence" }))}</b>${raw(tag(DOC_STATE_WORD[x.state], x.state === "ok" ? "ok" : bad ? "bad" : unknown ? "warn" : ""))}</div>
      ${fields.length ? raw(h`<dl class="kv">${raw(fields.map(([k, val]) => h`<dt>${k}</dt><dd>${val}</dd>`).join(""))}</dl>`) : ""}
      ${x.state === "none" ? raw('<p class="own-what">The file was read and declares no author, software or date.</p>') : ""}
      ${x.reason_text ? raw(h`<p class="own-what">${x.reason_text} The file may still carry names.</p>`) : ""}
      ${x.error ? raw(h`<p class="own-what">${x.error}</p>`) : ""}
      <p class="own-what dim">${[x.size !== null ? (x.state === "too_large" ? `${fmtSize(x.size)} declared by the site` : `${fmtSize(x.size)} read`) : "", x.last_archived ? `last seen by the archive ${x.last_archived.slice(0, 10)}` : "", x.sources.length ? `read from ${x.sources.map((s) => ({ info: "the PDF's Info block", xmp: "the PDF's XMP packet", core: "docProps/core.xml", app: "docProps/app.xml" })[s]).join(" and ")}` : ""].filter(Boolean).join(" · ")}</p>
    </li>`;
  }).join("");
  return lead + names + companies + software + caveat + held
    + `<h4 class="own-h">Documents</h4><ul class="own-docs">${docs}</ul>`
    + h`<p class="muted small">Dates are the clock of the machine that made the file. ${d.listing_truncated ? "The archive's list was cut at its maximum of 1,500 rows, so \"most recent\" is among those. " : ""}${d.listed_too_large ? `${plural(d.listed_too_large, "listed file")} over 8 MB ${d.listed_too_large === 1 ? "was" : "were"} left for last. ` : ""}Read: the Info block and XMP packet of a PDF, and docProps of an Office file. Not read: encrypted files, compressed metadata and old binary Office formats.</p>`;
}
export function docBadge(v) {
  const d = readDocMeta(v);
  if (!d) return "";
  if (d.state === "refused") return tag("not read");
  if (!d.documents.length) return d.state === "none" ? tag("none listed") : tag(d.state === "rate_limited" ? "rate limited" : "failed", d.state === "rate_limited" ? "warn" : "bad");
  const names = d.summary.authors.length;
  return tag(`${fmtNum(d.counts.ok || 0)} of ${fmtNum(d.documents.length)} read`, d.counts.ok ? "ok" : "warn") + (names ? " " + tag(plural(names, "name")) : "");
}
// What the lookup asks for and from whom, said before the click and kept beside the result.
export const docAsk = (domain) => `Asks the Internet Archive's index which PDF and Office files it has seen under ${domain}, then requests up to 8 of them from ${domain} itself and reads the title, author, software and dates saved inside. The site's logs will show a visit from CrawlR's server. These are public files and nothing else is sent to the site. It can take up to 90 seconds.`;
// The section under the findings of a domain case. ui: { busy, seconds, blocked }.
export function docLookup(domain, v, ui = {}) {
  const d = readDocMeta(v);
  const retry = d && (d.state === "failed" || d.state === "rate_limited" || (d.state !== "ok" && d.state !== "none" && d.state !== "refused"));
  const label = !d ? "Read document metadata" : retry ? "Try again" : "Read again";
  const act = ui.busy
    ? h`<div class="own-busy"><span class="own-bar" aria-hidden="true"><i></i></span><span role="status">Reading documents. The archive's list comes first and can take 40 seconds for a large site.</span><span class="mono" aria-hidden="true" data-doc-clock>${fmtNum(ui.seconds || 0)} s</span><button type="button" class="btn btn-sm btn-cancel" data-doc-cancel>Cancel</button></div>`
    : d?.state === "refused" ? ""
    : h`<div class="own-act"><button type="button" class="btn ${d ? "btn-sm" : ""}" data-doc-meta ${ui.blocked ? "disabled" : ""}>${label}</button>${ui.blocked ? raw('<span class="hint-inline">Available when the run finishes.</span>') : d?.cached ? raw('<span class="hint-inline">This answer came from CrawlR\'s memory of an earlier lookup: no request was made this time.</span>') : ""}</div>`;
  return h`<section class="own-lookup" aria-labelledby="rDocH">
    <div class="own-lhead"><h2 id="rDocH">Document metadata</h2><span class="tag">on a click</span><span class="tag">requests files from the target's site</span>${d ? raw(docBadge(d)) : ""}</div>
    <p class="own-ask">${docAsk(domain)}</p>
    ${raw(d && !ui.busy ? `<div class="own-result">${docBody(d)}</div>` : "")}
    ${raw(act)}
  </section>`;
}
