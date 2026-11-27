// Portable case files. A case is exported as one JSON file and opened again on another
// machine from History. Nothing is uploaded: the file never leaves the browser.
// A case file is untrusted input, like any remote value. This module checks its shape and
// size; every value in it still reaches the page only through h, esc and link.
import { detect, reconType, INVESTIGATE_TYPES, RECON_TYPES } from "./core.js";
import { scrubNames } from "./names.js";
import { boundAvatarHash } from "./present.js";
import { readPhone, readRegion } from "./phone.js";
import { importSimilar } from "./evidence.js";
import { readBlock } from "./adult.js";
import { DEEP_READERS } from "./deep.js";
import { readCasework, CASEWORK_KEYS } from "./casework.js";

export const CASE_VERSION = 1;
export const MAX_CASE_BYTES = 3 * 1024 * 1024;   // browser storage holds about 5 MB for the whole history
const MAX_NOTES = 20000, MAX_PURPOSE = 300, MAX_SOURCES = 60;
const KEY_OK = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
const KEY_BAD = new Set(["constructor", "prototype"]);
const TEXT_KEYS = new Set(["nameSearch", "reverseImage", "phoneRegion"]);
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const clip = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
const fail = (error) => ({ ok: false, error });

// What Export writes. `mode` is the workbench, `type` the detected target type.
export function buildCaseFile({ mode, target, type, ran, collected, ai, deep, notes, purpose }) {
  return { crawlr_case: CASE_VERSION, app: "CrawlR", exported: new Date().toISOString(), mode, target, type, ran: ran || Date.now(), purpose: purpose || "", notes: notes || "", collected: collected || {}, ai: ai || null, deep: deep || null };
}

// An AI report keeps the fields the report view reads and drops everything else.
const SOURCES_OK = new Set(["house", "user", "pasted"]);
function report(v) {
  if (!isObj(v) || typeof v.summary !== "string" || !v.summary.trim()) return null;
  const out = { summary: v.summary.slice(0, 200000), short_summary: Array.isArray(v.short_summary) ? v.short_summary.filter((x) => typeof x === "string").slice(0, 12) : [], model: clip(v.model, 80) };
  if (SOURCES_OK.has(v.ai_source)) out.ai_source = v.ai_source;
  if (Number.isFinite(v.tokens)) out.tokens = v.tokens;
  if (Number.isFinite(v.elapsed)) out.elapsed = v.elapsed;
  if (isObj(v.profile) && JSON.stringify(v.profile).length <= 20000) out.profile = v.profile;
  return out;
}

// Returns { ok: true, entry } with a History entry, or { ok: false, error } with a sentence to show.
export function parseCaseFile(text) {
  if (typeof text !== "string" || !text.trim()) return fail("That file is empty.");
  if (text.length > MAX_CASE_BYTES) return fail("That file is too large to be a CrawlR case (limit 3 MB).");
  let j;
  try { j = JSON.parse(text); } catch { return fail("That file is not valid JSON."); }
  if (!isObj(j) || j.crawlr_case === undefined) return fail("That is not a CrawlR case file. Use the JSON option under Export to make one.");
  if (j.crawlr_case !== CASE_VERSION) return fail("That case file was made by a newer version of CrawlR.");
  const target = typeof j.target === "string" ? j.target.trim() : "";
  if (!target || target.length > 253 || /[\u0000-\u001f\u007f]/.test(target)) return fail("The case file has no usable target.");
  if (j.mode !== "recon" && j.mode !== "investigate") return fail("The case file does not say which workbench it belongs to.");
  let kind;
  if (j.mode === "recon") {
    // A Recon case says what its target is: a domain that was opened from a lead stays a domain
    // even when its last label is not on the detector's list. It must still have a domain's shape.
    kind = reconType(target, j.type);
    if (!RECON_TYPES.includes(kind)) return fail("The target in that file is not a domain, IP address or ASN.");
  } else {
    kind = INVESTIGATE_TYPES.includes(j.type) ? j.type : detect(target);
    if (!INVESTIGATE_TYPES.includes(kind)) return fail("The target in that file is not a username, email, hash, phone number or name.");
  }
  if (!isObj(j.collected)) return fail("The case file holds no results.");
  const results = {};
  for (const [k, v] of Object.entries(j.collected)) {
    if (!KEY_OK.test(k) || KEY_BAD.has(k)) continue;
    // The one flag among the results: this case had adult and dating sites switched on. Only the
    // literal true is kept. Without it the rows from those sites are never shown (see adult.js).
    if (k === "adultMode") { if (v === true) results.adultMode = true; continue; }
    // Why a case has no adult group: the minor guard stopped it. Kept in its checked, bounded
    // shape (a known kind, a short source name, a snippet of at most 60 characters, an http(s)
    // address). It can only hide the group: a file that carries one shows no adult row, and a
    // value that cannot be read still hides them. Leaving it out un-blocks nothing in this
    // session, which keeps its own list of suspended handles in memory.
    if (k === "adultBlock") { if (v !== null && v !== undefined) results.adultBlock = readBlock(v) || { kind: "server", source: "", snippet: "", url: "" }; continue; }
    // Sources return objects. Two client-side values are plain strings: the searched name and an image URL.
    if (v === null || typeof v === "object" || (TEXT_KEYS.has(k) && typeof v === "string" && v.length <= 2000)) results[k] = v;
  }
  // A name case's candidates, loaded profiles and qualifiers are re-checked like a fresh answer:
  // rows that do not fit a directory's shape are dropped, text is clipped and links are rebuilt.
  for (const k of ["nameResult", "nameProfiles", "nameQualifiers"]) delete results[k];
  // A result for another name than the file's target is dropped with them.
  Object.assign(results, scrubNames(Object.fromEntries(["nameResult", "nameProfiles", "nameQualifiers"].filter((k) => Object.hasOwn(j.collected, k)).map((k) => [k, j.collected[k]])), target));
  // A thumbnail in the avatar comparison may only be a small PNG or WebP data URI. Anything
  // else in that field is dropped, so a file cannot make the page load or show something else.
  if (results.avatarHash) results.avatarHash = boundAvatarHash(results.avatarHash);
  // A phone answer keeps only its checked, bounded fields: text is clipped, a search link must
  // point at the site it names, and the evidence link is rebuilt from the area code and exchange.
  // The country a number without a country code was read as: a known two-letter region, or nothing.
  if ("phoneRegion" in results) { const r = readRegion(results.phoneRegion); if (r) results.phoneRegion = r; else delete results.phoneRegion; }
  if ("phone" in results) { const ph = readPhone(results.phone); if (ph) results.phone = ph; else delete results.phone; }
  // Similar handles that were checked: every handle is held to the username pattern, every
  // address is rebuilt from the site and the handle, text is clipped, a thumbnail must pass the
  // same check as any other and a state must be a known one. "Added" is kept only for a profile
  // the file itself holds, and it still has to line up with the case when the case is drawn.
  // Whoever made the file chose what is in it. So only a handle this case would offer itself is
  // kept, no profile stays "added" (it can be checked and added again here), and what is kept
  // is marked as coming from the file until it is checked in this browser.
  if ("similar" in results) { const sm = importSimilar(results, target, kind); if (Object.keys(sm).length) results.similar = sm; else delete results.similar; }
  // The record sources (profile sources, the accounts and keys behind an address, GitHub
  // activity) are read like a fresh answer: a site is one of the 16 CrawlR asks and its profile
  // address must be on that site, every other address is held to http(s) and never an adult
  // site, a GitHub or key address is rebuilt from the login or the fingerprint, text is clipped,
  // a thumbnail passes the same check as any other and a state is a known one. Guard-only text
  // is dropped. A value that cannot be read is dropped; a recorded failure stays a failure.
  for (const [k, read] of Object.entries(DEEP_READERS)) if (k in results) { const v = read(results[k]); if (v) results[k] = v; else delete results[k]; }
  // The investigator's own work travels with the file and is read like everything else in it:
  // the pick of the person the case is about (member ids only, and marked as the file's pick, so
  // the page never says "you picked") and the pivot trail (text, clipped, each step marked as the
  // file's; its case ids mean nothing in this browser). Parked and followed steps are NOT kept: a
  // file must not be able to hide a suggestion from the person who opens it, so every step the
  // case supports is offered again. Archive answers are among the record sources above: each
  // snapshot address is rebuilt from its timestamp and the profile address.
  // A pick that names no cluster of this case simply does not apply: the automatic choice stands.
  { const cw = readCasework(results, { file: true }); for (const k of ["pick", "trail", "nextSteps"]) { if (k in cw) results[k] = cw[k]; else delete results[k]; } }
  // A Recon case keeps its trail beside the results (the History entry's `trail`), and has no
  // identity to pick. The file carries the trail among the results, like an Investigate case.
  const trail = j.mode === "recon" ? results.trail : null;
  if (j.mode === "recon") for (const k of ["pick", "trail", "nextSteps"]) delete results[k];
  if (Object.keys(results).length > MAX_SOURCES) return fail("The case file holds more sources than CrawlR has.");
  if (!Object.keys(results).filter((k) => k !== "adultMode" && k !== "adultBlock" && k !== "phoneRegion" && !CASEWORK_KEYS.includes(k)).length) return fail("The case file holds no results.");
  const ran = Number.isFinite(j.ran) && j.ran > 0 && j.ran <= Date.now() + 86400000 ? j.ran : Date.now();
  const ai = report(j.ai), deep = report(j.deep);
  const entry = {
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target, type: j.mode === "recon" ? "RECON" : "INVESTIGATE", kind, timestamp: ran,
    results, aiSummary: ai?.summary || null, ai, notes: clip(j.notes, MAX_NOTES), purpose: clip(j.purpose, MAX_PURPOSE).replace(/\s+/g, " ").trim(), v2: true, imported: Date.now(),
  };
  if (j.mode === "recon") { entry.deep = deep; if (trail?.length) entry.trail = trail; } else entry.deepDive = deep;
  return { ok: true, entry };
}
