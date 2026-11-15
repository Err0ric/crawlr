// Phone cases. A phone lookup says what a number IS: whether it is valid, its country, its line
// type, and where and to whom its number range was assigned. It never says who uses the number
// or where that person is, and nothing here asks a source that would.
// Pure: no DOM, no network. The answer is read defensively (readPhone) whether it came from the
// server, from History or from a case file: text is clipped, states are checked, the evidence
// link is rebuilt from the checked prefix and a search link must point at the site it names.
//
// Three sources sit inside one answer, each with its own state (see modules/phone_lookup.py):
//   numbering_plan  libphonenumber, offline               ok (when it cannot be read the whole
//                                                         lookup is a failed source, never "not valid")
//   npa_nxx         Local Calling Guide, US and Canada     ok | none | failed | rate_limited
//   numlookup       only with the investigator's own key   ok | failed
// A source that was not asked has no entry, so it is never read as "none".
//
// Certainty: a fact read from the numbering plan is drawn solid, because the plan is the
// authority on what a number range is. It is a fact about the range, and the wording says so
// every time ("range assigned in", "first assigned to"). Dashed is kept for what could not be
// known: a failed lookup, or a tile with nothing to show.

import { classifyLink } from "./links.js";
import { PHONE_REGIONS } from "./phone-regions.js";

export const PHONE_SOURCE = "Phone lookup";
export const PHONE_SOURCE_DESC = "validity, country, line type and where the number range is assigned, from open numbering data; your NumLookup key adds the current carrier";
export const PLAN = "Numbering plan", BLOCKS = "Local Calling Guide", NUMLOOKUP = "NumLookup";
export const OWNER_NOTE = "Who uses this number is not something open numbering data shows.";
export const AREA_NOTE = "Where the number range is assigned. It is not where the phone or the person using it is.";
export const PORTED_NOTE = "Numbers are ported between carriers, so this may not be the current one.";
export const PHONE_NOT_USABLE = "That does not read as a phone number. Enter digits with an optional + and country code.";

export const PHONE_TIERS = [
  { id: "flag",      title: "Flags",             cls: "flag", open: true, blurb: "What stands out about this number: a premium-rate, VoIP or personal range, a range reserved for fiction, or digits that are not a valid number. Read these first." },
  { id: "info",      title: "About this number", cls: "",     open: true, blurb: "What open numbering data says about the number and the range it sits in. It describes the range, not the person using the number." },
  { id: "websearch", title: "Search the web",    cls: "",     open: true, blurb: "These open a search on another site. The number goes to that site." },
];

// ---- the country a number without a country code is read as -----------------------------------
// The page offers a Country select only while the Phone type is active and the text carries no
// country code (no leading + and no 00). Its value is sent as `region`, saved with the case as
// `phoneRegion`, and is one of the regions the server's numbering data knows.
const REGION_NAMES = new Map(PHONE_REGIONS);
export { PHONE_REGIONS };
export const readRegion = (v) => (typeof v === "string" && REGION_NAMES.has(v.trim().toUpperCase()) ? v.trim().toUpperCase() : "");
export const regionName = (code) => REGION_NAMES.get(readRegion(code)) || "";
export const needsCountry = (text) => { const t = String(text ?? "").trim(); return !!t && !/^\(?\s*(?:\+|00)/.test(t); };
// The browser's region when its language tag has one the list knows ("en-GB", "pt_BR"), otherwise the United States.
export function defaultRegion(lang) {
  const m = /^[A-Za-z]{2,3}(?:[-_][A-Za-z]{4})?[-_]([A-Za-z]{2})(?:$|[-_])/.exec(String(lang ?? "").trim());
  return readRegion(m ? m[1] : "") || "US";
}

// ---- reading an answer ------------------------------------------------------------------------
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const line = (v, n) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim().slice(0, n).trim() : "");
const bool = (v) => (v === true ? true : v === false ? false : null);
const LEVELS = new Set(["flag", "ok", "info"]);
const KINDS = new Set(["number", "short_code", "emergency"]);
const STATES = { numbering_plan: ["ok", "failed"], npa_nxx: ["ok", "none", "failed", "rate_limited"], numlookup: ["ok", "failed"] };
export const LINE_TYPES = { fixed_line: "Fixed line", mobile: "Mobile", fixed_line_or_mobile: "Fixed line or mobile", toll_free: "Toll free", premium_rate: "Premium rate", shared_cost: "Shared cost",
  voip: "VoIP", personal_number: "Personal number", pager: "Pager", uan: "Company number (UAN)", voicemail: "Voicemail access", unknown: "Unknown" };
// The only sites a search link may open, by the name the row shows.
const SEARCH_HOSTS = { Google: "www.google.com", Bing: "www.bing.com", DuckDuckGo: "duckduckgo.com", "800notes": "800notes.com", WhoCallsMe: "whocallsme.com" };
const MAX_FINDINGS = 20, MAX_LINKS = 12;
// The public page for a North American block. Only the area code and the exchange are in it.
export const blockPage = (prefix) => { const m = /^([2-9]\d\d)-([2-9]\d\d)$/.exec(String(prefix ?? "")); return m ? `https://localcallingguide.com/lca_prefix.php?npa=${m[1]}&nxx=${m[2]}` : ""; };

function readSource(key, v) {
  if (!isObj(v) || !STATES[key].includes(v.state)) return null;
  const out = { name: key === "numbering_plan" ? "libphonenumber" : key === "npa_nxx" ? BLOCKS : NUMLOOKUP, state: v.state };
  if (v.state === "failed" || v.state === "rate_limited") { out.error = line(v.error, 200) || "Failed"; out.error_code = line(v.error_code, 40); }
  if (key === "numbering_plan") out.version = line(v.version, 20);
  if (key === "npa_nxx") { out.asked = /^\d{3}-\d{3}$/.test(v.asked) ? v.asked : ""; if (v.cached === true) out.cached = true; }
  if (key === "numlookup" && v.state === "ok") { out.carrier = line(v.carrier, 80); out.line_type = line(v.line_type, 40); out.valid = bool(v.valid); }
  return out;
}

// The checked, bounded shape of a phone answer. null when it is not one. A failed lookup keeps
// its three error fields. An answer saved before open numbering data was read (only the old
// keys) comes back with legacy: true, without the people-search links it used to carry.
export function readPhone(v) {
  if (!isObj(v)) return null;
  if (v.error || v.error_code) return { error: line(String(v.message || v.error || ""), 300) || "Failed", error_code: line(v.error_code, 40) || "request_failed", error_detail: line(v.error_detail, 400) };
  const top = { input: line(v.input, 60), normalized: line(v.normalized, 20), valid: bool(v.valid), country: line(v.country, 80), country_code: line(v.country_code, 3), location: line(v.location, 80), carrier: line(v.carrier, 80), line_type: line(v.line_type, 40) };
  if (!isObj(v.number)) return { legacy: true, ...top, ...(line(v.api_error, 200) ? { api_error: line(v.api_error, 200) } : {}) };
  const n = v.number, a = isObj(v.assignment) ? v.assignment : null;
  const code = Object.hasOwn(LINE_TYPES, n.line_type) ? n.line_type : "unknown";
  const number = {
    e164: /^\+\d{4,15}$/.test(n.e164) ? n.e164 : "", international: line(n.international, 30), national: line(n.national, 30), short: /^\d{2,6}$/.test(n.short) ? n.short : "",
    extension: line(n.extension, 12), calling_code: Number.isInteger(n.calling_code) && n.calling_code > 0 && n.calling_code < 1000 ? n.calling_code : null,
    region: /^[A-Z]{2}$/.test(n.region) ? n.region : "", country: line(n.country, 80), possible: n.possible === true, possible_reason: line(n.possible_reason, 120), valid: n.valid === true,
    validity_text: line(n.validity_text, 240), line_type: code, line_type_text: LINE_TYPES[code], line_type_note: line(n.line_type_note, 240),
    region_assumed: n.region_assumed === true, assumed_text: line(n.assumed_text, 200),
    time_zones: (Array.isArray(n.time_zones) ? n.time_zones : []).filter((z) => typeof z === "string" && /^[A-Za-z0-9_+\/-]{1,40}$/.test(z)).slice(0, 3),
    vanity: n.vanity === true, fiction: n.fiction === true,
  };
  const sources = {};
  for (const k of Object.keys(STATES)) { const s = readSource(k, isObj(v.sources) ? v.sources[k] : null); if (s) sources[k] = s; }
  const prefix = a && /^[2-9]\d\d-[2-9]\d\d$/.test(a.prefix) ? a.prefix : "";
  const answered = sources.npa_nxx && (sources.npa_nxx.state === "ok" || sources.npa_nxx.state === "none");
  const assignment = a ? {
    area: line(a.area, 80), carrier: line(a.carrier, 80), prefix,
    rate_centre: answered ? line(a.rate_centre, 80) : "", region: answered ? line(a.region, 8) : "", company: answered ? line(a.company, 80) : "", ocn: answered ? line(a.ocn, 8) : "",
    // "Not assigned" only ever comes from a source that answered. Anything else is unknown.
    block_assigned: answered && prefix ? sources.npa_nxx.state === "ok" : null,
    evidence_url: answered ? blockPage(prefix) : "",
  } : null;
  const findings = (Array.isArray(v.findings) ? v.findings : []).filter((f) => isObj(f) && LEVELS.has(f.level) && line(f.title, 120)).slice(0, MAX_FINDINGS)
    .map((f) => ({ level: f.level, code: /^[a-z_]{1,40}$/.test(f.code) ? f.code : "note", title: line(f.title, 120), detail: line(f.detail, 400) }));
  const search_links = [];
  for (const l of Array.isArray(v.search_links) ? v.search_links.slice(0, 40) : []) {
    if (!isObj(l) || !Object.hasOwn(SEARCH_HOSTS, l.site) || typeof l.url !== "string" || l.url.length > 600 || search_links.length >= MAX_LINKS) continue;
    let u; try { u = new URL(l.url); } catch { continue; }
    if (u.protocol !== "https:" || u.hostname !== SEARCH_HOSTS[l.site] || u.username || u.password || u.port) continue;
    if (!search_links.some((x) => x.site === l.site)) search_links.push({ site: l.site, url: u.href, kind: "search", group: l.group === "spam reports" ? "spam reports" : "search engine", label: line(l.label, 80) });
  }
  return { ...top, parsed: v.parsed === true, kind: KINDS.has(v.kind) ? v.kind : "number", valid: number.valid, number, assignment, findings, sources, search_links };
}

// ---- one view for the screen ---------------------------------------------------------------------
// Everything the ledger, the facts, the tiles, the brief and the card show, old shape or new.
// null for no answer or a failed lookup: a failure contributes nothing and is reported as failed.
export function phoneView(raw) {
  const d = readPhone(raw);
  if (!d || d.error || d.error_code) return null;
  if (d.legacy) {
    return { legacy: true, kind: "number", written: d.normalized || d.input, valid: d.valid, validityText: d.valid === false ? "Reported invalid by NumLookup." : "", country: d.country || d.country_code, lineType: d.line_type, lineTypeNote: "",
      area: d.location, place: [d.location, d.country].filter(Boolean).join(", "), carrier: d.carrier, apiError: d.api_error || "", findings: [], sources: {}, links: [], zones: [] };
  }
  const n = d.number, a = d.assignment || {}, block = d.sources.npa_nxx || null, nl = d.sources.numlookup || null;
  const place = [a.rate_centre, a.region].filter(Boolean).join(", ") || a.area || (/^North America/.test(n.country) ? "North America" : n.country);
  return {
    legacy: false, kind: d.kind, parsed: d.parsed, written: (n.international || n.national || n.short || d.input) + (n.extension ? ` ext. ${n.extension}` : ""),
    e164: n.e164, national: n.national, international: n.international, extension: n.extension, callingCode: n.calling_code,
    valid: d.kind === "number" ? n.valid : false, possible: n.possible, validityText: n.validity_text, reason: n.possible_reason, assumedText: n.assumed_text,
    country: n.country, lineType: d.kind === "emergency" ? "Emergency number" : d.kind === "short_code" ? "Short code" : n.valid ? n.line_type_text : "", lineTypeNote: n.line_type_note,
    area: a.area || "", rateCentre: a.rate_centre || "", region: a.region || "", prefix: a.prefix || "", company: a.company || "", carrier: a.carrier || "",
    blockAssigned: a.block_assigned ?? null, evidenceUrl: a.evidence_url || "", place, zones: n.time_zones, fiction: n.fiction,
    findings: d.findings, sources: d.sources, block, nl, links: d.search_links, version: d.sources.numbering_plan?.version || "",
  };
}

const sourceOf = (code) => (code === "unassigned_block" ? BLOCKS : code === "numlookup_invalid" ? NUMLOOKUP : PLAN);
const blockEv = (v) => (v.evidenceUrl ? { url: v.evidenceUrl, label: "Block record" } : null);
const firstAssigned = (v) => v.company || v.carrier;
// A name that ends in a full stop ("INC.", "D.C.") does not get a second one.
const stop = (s) => `${String(s).replace(/\.+$/, "")}.`;

// ---- ledger rows -------------------------------------------------------------------------------
// Flags, then what the numbering data says, then the outbound searches. `ev` is the public page
// for the block, where one exists; evidence.js seals it as an evidence link.
export function phoneItems(view) {
  const v = view;
  if (!v) return [];
  const items = [];
  if (v.legacy) {
    // Runs saved before open numbering data: the two flags they could raise, from NumLookup.
    if (/voip/i.test(v.lineType || "")) items.push({ tier: "flag", what: "VoIP number", url: "", meta: "VoIP numbers are easy to get and discard.", source: NUMLOOKUP, key: "phone:voip" });
    if (v.valid === false) items.push({ tier: "flag", what: "Number reported invalid", url: "", meta: "", source: NUMLOOKUP, key: "phone:invalid" });
    return items;
  }
  const seen = new Set();
  for (const f of v.findings) {
    const key = `phone:${f.code}`;
    if (seen.has(key)) continue;
    seen.add(key);
    items.push({ tier: f.level === "flag" ? "flag" : "info", what: f.title, url: "", meta: f.detail, source: sourceOf(f.code), key, ...(f.code === "unassigned_block" && blockEv(v) ? { ev: blockEv(v) } : {}) });
  }
  if (v.rateCentre) {
    items.push({ tier: "info", what: `The ${v.prefix} block is assigned to ${[v.rateCentre, v.region].filter(Boolean).join(", ")}`, url: "",
      meta: ["The rate centre of the number range, not the place of the phone or the person using it.", v.company ? `First assigned to ${stop(v.company)} ${PORTED_NOTE}` : ""].filter(Boolean).join(" "),
      source: BLOCKS, key: "phone:block", ...(blockEv(v) ? { ev: blockEv(v) } : {}) });
  }
  if (v.nl?.state === "ok" && (v.nl.carrier || v.nl.line_type)) {
    items.push({ tier: "info", what: `NumLookup: ${[v.nl.carrier && `current carrier ${v.nl.carrier}`, v.nl.line_type && `line type ${v.nl.line_type}`].filter(Boolean).join(", ")}`, url: "",
      meta: "From NumLookup, asked with your key. A commercial index, which can be out of date.", source: NUMLOOKUP, key: "phone:numlookup" });
  }
  for (const l of v.links) {
    const k = classifyLink({ url: l.url, want: "search" });
    if (k.link_kind === "search") items.push({ tier: "websearch", what: l.site, url: k.url, link_kind: "search", meta: l.label, source: "opens on that site", key: `search:${l.site.toLowerCase()}` });
  }
  return items;
}

// ---- What we know ------------------------------------------------------------------------------
// { k, v, source, url? }. Every fact about a place or a carrier is worded as a fact about the range.
export function phoneFacts(view) {
  const v = view;
  if (!v) return [];
  const out = [], fact = (k, val, source, url = "") => { if (val) out.push({ k, v: String(val), source, url }); };
  if (v.legacy) {
    fact("Carrier", v.carrier, NUMLOOKUP); fact("Line type", v.lineType, NUMLOOKUP); fact("Location", v.place, NUMLOOKUP);
    return out;
  }
  if (v.kind !== "number") { fact("Kind of number", v.lineType, PLAN); fact("Country", v.country, PLAN); fact("Who uses it", "Nobody: it is a service, not a subscriber number.", PLAN); return out; }
  fact("Number", v.international && `${v.international}${v.extension ? ` ext. ${v.extension}` : ""}`, PLAN);
  fact("National format", v.national, PLAN);
  fact("E.164", v.e164, PLAN);
  fact("Validity", v.validityText, PLAN);
  fact("Country", v.country && `${v.country}${v.callingCode ? ` (+${v.callingCode})` : ""}`, PLAN);
  fact("Line type", v.lineType && `${v.lineType}${v.lineTypeNote ? " (the numbering plan cannot tell which)" : ""}`, PLAN);
  fact("Range assigned in", v.area && `${v.area} (the range, not the phone or the person using it)`, PLAN);
  fact("Rate centre", v.rateCentre && [v.rateCentre, v.region].filter(Boolean).join(", "), BLOCKS, v.evidenceUrl);
  fact("Range first assigned to", firstAssigned(v) && `${firstAssigned(v)} (numbers are ported, so this may not be the current carrier)`, v.company ? BLOCKS : PLAN);
  fact("Time zone of the range", v.zones.join(", "), PLAN);
  if (v.nl?.state === "ok") { fact("Current carrier", v.nl.carrier, NUMLOOKUP); fact("Line type from NumLookup", v.nl.line_type, NUMLOOKUP); }
  fact("Who uses it", "Not something open numbering data shows.", PLAN);
  return out;
}

// ---- verdict tiles --------------------------------------------------------------------------
// What investigateTiles needs for a phone case: Valid, Line type, Assigned in. The Flags tile is
// counted from the ledger rows.
export function phoneTileExtra(raw) {
  const v = phoneView(raw);
  if (!v) return { phone: { known: false } };
  const placed = !!v.place && (v.legacy || v.kind !== "number" || v.valid === true);
  const validWord = v.kind === "emergency" ? "Emergency number" : v.kind === "short_code" ? "Short code" : v.valid === true ? "Valid" : v.valid === false ? "Not valid" : "";
  return { phone: {
    known: true, legacy: !!v.legacy, valid: v.kind === "number" ? v.valid : false, validWord, fiction: !!v.fiction,
    validSub: v.kind !== "number" ? "not a subscriber number" : v.valid === true ? (v.fiction ? "but reserved for fiction" : v.legacy ? "" : "fits the numbering plan") : v.valid === false ? (v.reason || (v.legacy ? "" : "no range matches these digits")) : "this run did not check it",
    lineType: v.lineType || "", lineSub: v.lineType ? (v.legacy ? "" : v.lineTypeNote ? "the plan cannot tell which" : "by number range") : v.valid === false ? "not a valid number" : "",
    // A number that fits no range has no range to place. A service is placed by its country.
    place: placed ? v.place : "", placeSub: placed ? (v.legacy ? "" : v.kind === "number" ? "the range, not the phone" : "") : v.valid === false ? "not a valid number" : "",
    carrier: v.nl?.carrier || firstAssigned(v) || "",
  } };
}

// ---- At a glance -------------------------------------------------------------------------------
// Plain sentences: what the number is, what its flags mean, what could not be asked, and what
// cannot be known. { level, text, ev? }
export function phoneBrief(raw) {
  const v = phoneView(raw);
  const rows = [], add = (level, text, ev) => rows.push({ level, text, ev: ev || null });
  if (!v) return rows;
  if (v.legacy) {
    if (v.carrier || v.lineType) add(/voip/i.test(v.lineType || "") ? "flag" : "info", `${v.lineType || "Line"}${v.carrier ? ` on ${v.carrier}` : ""}${v.place ? `, ${v.place}` : ""}, according to NumLookup.${/voip/i.test(v.lineType || "") ? " VoIP numbers are easy to get and discard." : ""}`);
    add("info", "This case was saved before CrawlR read open numbering data. Run it again to see whether the number is valid, its line type and where its range is assigned.");
    add("info", OWNER_NOTE);
    return rows;
  }
  const flags = v.findings.filter((f) => f.level === "flag");
  if (v.kind !== "number") {
    for (const f of v.findings) add(f.level, `${f.title}. ${f.detail}`);
    return rows;
  }
  for (const f of flags) add("flag", `${f.title}. ${f.detail}`, f.code === "unassigned_block" ? blockEv(v) : null);
  if (v.valid) {
    const what = `${v.written} is a valid ${/^North America|^International/.test(v.country) ? "" : `${v.country} `}number`.replace(/\s+/g, " ");
    add(v.fiction || flags.length ? "info" : "ok", `${what}: ${/VoIP|UAN/.test(v.lineType) ? v.lineType : v.lineType.toLowerCase()}${v.lineTypeNote ? " (the numbering plan cannot tell which)" : ""}. Valid means the digits fit a number range. It does not show the number is in service.`);
  } else if (!flags.some((f) => f.code === "invalid" || f.code === "fiction")) add("flag", v.validityText || "Not a valid number.");
  if (v.assumedText) add("info", `${v.assumedText} Add the country code with a + if it belongs somewhere else.`);
  const where = [v.rateCentre, v.region].filter(Boolean).join(", ") || v.area;
  if (where || firstAssigned(v)) {
    add("info", [where ? `Its number range is assigned in ${stop(where)} That is where the range is assigned, not where the phone or the person using it is.` : "",
      firstAssigned(v) ? `The range was first assigned to ${stop(firstAssigned(v))} ${PORTED_NOTE}` : ""].filter(Boolean).join(" "), blockEv(v));
  }
  for (const f of v.findings.filter((x) => x.level === "info" && !["assumed_country", "assumed_plus"].includes(x.code))) add("info", `${f.title}. ${f.detail}`);
  if (v.nl?.state === "ok" && (v.nl.carrier || v.nl.line_type)) add("info", `NumLookup, asked with your key, reports ${[v.nl.carrier && `the current carrier as ${v.nl.carrier}`, v.nl.line_type && `the line type as ${v.nl.line_type}`].filter(Boolean).join(" and ")}.`);
  if (v.nl?.state === "failed") add("info", `NumLookup could not be asked (${v.nl.error.replace(/\.$/, "")}), so the current carrier is unknown. The open numbering data does not depend on it.`);
  if (v.block && (v.block.state === "failed" || v.block.state === "rate_limited")) add("info", `${BLOCKS} could not be asked about the ${v.prefix} block, so whether it is assigned is unknown, not "unassigned".`);
  add("info", OWNER_NOTE);
  return rows;
}

// ---- the AI field ----------------------------------------------------------------------------------
// The checked answer without the outbound links. A failed lookup is sent as its error, so the
// prompt lists the source as failed and says nothing else about the number.
export function phoneForAi(raw) {
  const d = readPhone(raw);
  if (!d) return null;
  if (d.error || d.error_code || d.legacy) return d;
  const { search_links, input, ...rest } = d;
  return rest;
}

// One line per source for the card: what it is, and how it answered.
export function phoneSourceRows(view) {
  const v = view;
  if (!v || v.legacy) return [];
  const rows = [["Numbering plan", `read offline from libphonenumber${v.version ? ` ${v.version}` : ""}. Nothing left the server.`]];
  if (v.block) rows.push([BLOCKS, v.block.state === "ok" ? `answered: the ${v.prefix} block is assigned` : v.block.state === "none" ? `answered: no carrier is listed for the ${v.prefix} block` : v.block.state === "rate_limited" ? "unknown: rate limited" : `unknown: ${v.block.error || "failed"}`]);
  else rows.push([BLOCKS, v.kind === "number" && v.valid ? "not asked: it lists United States and Canadian geographic blocks only" : "not asked"]);
  if (v.nl) rows.push([NUMLOOKUP, v.nl.state === "ok" ? (v.nl.carrier || v.nl.line_type ? "answered with your key" : "answered with your key, with no carrier or line type") : `unknown: ${v.nl.error || "failed"}`]);
  else rows.push([NUMLOOKUP, "not asked: no key in Settings. It is optional and adds the current carrier."]);
  return rows;
}
