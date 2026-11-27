// The investigator's own work on a case, kept with it: how the case was reached (the pivot
// trail) and what was done with each suggested next step (parked, or followed).
// Pure: no DOM, no network. Everything here is browser-only state. Nothing is sent to the server.
// A stored case and a case file are outside data, so each value is read through a reader that
// returns a checked, bounded copy or nothing.
//
// collected.trail      [{ target, type, id, at, via, source }]   the earlier cases, seed first.
//                      `via` says which lead led from that case to the next one, `source` where
//                      that lead came from. The case on screen is the end of the trail and is not
//                      in the list. A step that came with a case file carries `file: true`: it is
//                      what the file says, not something done in this browser, and the page never
//                      words it as "you".
// collected.nextSteps  { [step id]: { state: "parked" | "followed", title, at } }
//                      parked: "not now". It stays listed as parked and is not suggested again.
//                      followed: a case was opened from it. It is listed as followed.
// collected.selfAudit  { on: true, at }   the investigator's statement "This is me": the case is
//                      about themselves. It turns on the "Reduce your footprint" view (selfaudit.js)
//                      and nothing else: no finding, tier or identity changes. Only a username or
//                      an email case can carry it. Absent means off.
// (The pick of the person a case is about is collected.pick: see readPick in identity.js.)
//
// A case file brings its pick and its trail, each marked as the file's. It does not bring
// nextSteps: a file that could park or mark a step as followed could hide a suggestion from the
// person who opens it, so the steps are dropped on import (readCasework with file: true) and
// every suggestion the case supports is offered again. It does not bring selfAudit either: "this
// is me" is the statement of the person at this browser, and a file cannot make it for them.

import { readPick } from "./identity.js";
import { cleanText } from "./deep.js";

const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const line = (v, n) => (typeof v === "string" ? Array.from(cleanText(v).replace(/\s+/g, " ").trim()).slice(0, n).join("") : "");
const stamp = (v) => (Number.isFinite(v) && v > 0 && v <= Date.now() + 86400000 ? v : 0);

export const TRAIL_TYPES = ["username", "email", "hash", "phone", "name", "domain", "ip", "asn"];
export const TRAIL_MAX = 12;
const TYPE_WORD = { __proto__: null, username: "username", email: "email address", hash: "file hash", phone: "phone number", name: "name", domain: "domain", ip: "IP address", asn: "ASN" };

// opts.file: the trail is read from a case file, so every step is marked as the file's.
export function readTrail(v, { file = false } = {}) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const s of v.slice(-TRAIL_MAX)) {
    const target = isObj(s) ? line(s.target, 253) : "";
    if (!target || !TRAIL_TYPES.includes(s.type)) continue;
    out.push({ target, type: s.type, id: typeof s.id === "string" && /^[A-Za-z0-9_]{1,40}$/.test(s.id) ? s.id : "", at: stamp(s.at), via: line(s.via, 160), source: line(s.source, 80), ...(file || s.file === true ? { file: true } : {}) });
  }
  return out;
}
// Does any step of the trail come from a case file?
export const trailFromFile = (view) => (view || []).some((s) => s.file === true);
// The trail of a case opened from `from` (the case on screen when the button was pressed).
//   from  { target, type, id, at, trail }     via  { label, source }: the lead that was followed
// A case opened from itself adds nothing, and the list is bounded: the oldest steps go first.
export function extendTrail(from, via = {}) {
  const prev = readTrail(from?.trail);
  const step = readTrail([{ target: from?.target, type: from?.type, id: from?.id || "", at: from?.at || 0, via: via.label || "", source: via.source || "" }])[0];
  return step ? [...prev, step].slice(-TRAIL_MAX) : prev;
}
// The trail in words, one entry per earlier case, then the case on screen.
//   [{ target, type_word, via, id, at, here }]
export function trailView(trail, target, type) {
  const steps = readTrail(trail);
  if (!steps.length) return [];
  return [...steps.map((s) => ({ target: s.target, type_word: TYPE_WORD[s.type], via: [s.via, s.source && !s.via.includes(s.source) ? `from ${s.source}` : ""].filter(Boolean).join(", "), id: s.id, at: s.at, here: false, ...(s.file ? { file: true } : {}) })),
    { target: String(target ?? ""), type_word: TYPE_WORD[type] || "", via: "", id: "", at: 0, here: true }];
}
export const trailText = (view) => (trailFromFile(view) ? "As recorded in the case file this case was opened from: " : "") + view.map((s) => (s.here ? `${s.target} (this case)` : `${s.target} (${s.type_word})${s.via ? `, then ${s.via}` : ""}`)).join(" > ");
export const trailMarkdown = (view) => (view.length ? ["## How this case was reached", trailFromFile(view) ? "_As recorded in the case file this case was opened from: each step is a lead its author followed from the case before it._" : "_Each step was a click by the investigator on a lead of the case before it. Recorded in the browser only._", ...view.map((s, i) => `${i + 1}. ${s.here ? `**${s.target}** (this case)` : `**${s.target}** (${s.type_word})${s.via ? `: followed ${s.via}` : ""}`}`), ""] : []);

export const STEP_STATES = ["parked", "followed"];
const STEP_ID = /^[a-z]{2,12}:[^\u0000-\u001f]{1,200}$/;
export function readSteps(v) {
  const out = {};
  if (!isObj(v)) return out;
  for (const [id, s] of Object.entries(v).slice(0, 80)) if (STEP_ID.test(id) && isObj(s) && STEP_STATES.includes(s.state)) out[id] = { state: s.state, title: line(s.title, 160), at: stamp(s.at) };
  return out;
}
export function setStep(steps, id, state, title = "") {
  const out = readSteps(steps);
  if (!STEP_ID.test(String(id))) return out;
  if (!state) delete out[id];
  else if (STEP_STATES.includes(state)) out[id] = { state, title: line(title, 160), at: Date.now() };
  return out;
}

// ---- "This is me" -------------------------------------------------------------------------------
// The statement is read here every time it is used: only the literal `on: true` counts, and the
// time is a plausible one or 0.
export const readSelfAudit = (v) => (isObj(v) && v.on === true ? { on: true, at: stamp(v.at) } : null);
const PERSON_TYPES = ["username", "email"];
// Is the case marked "This is me"? type: when given, only a username or an email case can be.
export const selfAuditOn = (collected, type) => (type === undefined || PERSON_TYPES.includes(type)) && isObj(collected) && !!readSelfAudit(collected.selfAudit);
// The case with the statement set or taken back: a new object, the one passed in is not changed.
export function setSelfAudit(collected, on, now = Date.now()) {
  const { selfAudit: _was, ...rest } = isObj(collected) ? collected : {};
  return on === true ? { ...rest, selfAudit: { on: true, at: stamp(now) } } : rest;
}

// The keys this module and identity.js own, read like a fresh answer: for History and case files.
export function readCasework(results, { file = false } = {}) {
  if (!isObj(results)) return results;
  const out = { ...results };
  if ("pick" in out) { const p = readPick(out.pick); if (p) out.pick = file ? { ...p, file: true } : p; else delete out.pick; }
  if ("trail" in out) { const t = readTrail(out.trail, { file }); if (t.length) out.trail = t; else delete out.trail; }
  // A case file never parks or follows a step for the person who opens it.
  if ("nextSteps" in out) { const s = file ? {} : readSteps(out.nextSteps); if (Object.keys(s).length) out.nextSteps = s; else delete out.nextSteps; }
  // Nor does it say "this is me" for them.
  if ("selfAudit" in out) { const a = file ? null : readSelfAudit(out.selfAudit); if (a) out.selfAudit = a; else delete out.selfAudit; }
  return out;
}
// The investigator's own work on a case: what a new run of the same target carries over, and what
// alone does not make a case file hold results. The answers of the lookups made on a click
// (archived copies and their comparison, commit emails, post activity) are among them: each was
// asked by hand for one row, and each is read again through its reader in deep.js.
export const CASEWORK_KEYS = ["pick", "trail", "nextSteps", "archives", "selfAudit", "commitEmails", "postActivity", "archiveDiffs"];
