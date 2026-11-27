// The investigator's own work on a case, kept with it: how the case was reached (the pivot
// trail) and what was done with each suggested next step (parked, or followed).
// Pure: no DOM, no network. Everything here is browser-only state. Nothing is sent to the server.
// A stored case and a case file are outside data, so each value is read through a reader that
// returns a checked, bounded copy or nothing.
//
// collected.trail      [{ target, type, id, at, via, source }]   the earlier cases, seed first.
//                      `via` says which lead led from that case to the next one, `source` where
//                      that lead came from. The case on screen is the end of the trail and is not
//                      in the list.
// collected.nextSteps  { [step id]: { state: "parked" | "followed", title, at } }
//                      parked: "not now". It stays listed as parked and is not suggested again.
//                      followed: a case was opened from it. It is listed as followed.
// (The pick of the person a case is about is collected.pick: see readPick in identity.js.)

import { readPick } from "./identity.js";

const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const line = (v, n) => (typeof v === "string" ? Array.from(v.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim()).slice(0, n).join("") : "");
const stamp = (v) => (Number.isFinite(v) && v > 0 && v <= Date.now() + 86400000 ? v : 0);

export const TRAIL_TYPES = ["username", "email", "hash", "phone", "name", "domain", "ip", "asn"];
export const TRAIL_MAX = 12;
const TYPE_WORD = { username: "username", email: "email address", hash: "file hash", phone: "phone number", name: "name", domain: "domain", ip: "IP address", asn: "ASN" };

export function readTrail(v) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const s of v.slice(-TRAIL_MAX)) {
    const target = isObj(s) ? line(s.target, 253) : "";
    if (!target || !TRAIL_TYPES.includes(s.type)) continue;
    out.push({ target, type: s.type, id: typeof s.id === "string" && /^[A-Za-z0-9_]{1,40}$/.test(s.id) ? s.id : "", at: stamp(s.at), via: line(s.via, 160), source: line(s.source, 80) });
  }
  return out;
}
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
  return [...steps.map((s) => ({ target: s.target, type_word: TYPE_WORD[s.type], via: [s.via, s.source && !s.via.includes(s.source) ? `from ${s.source}` : ""].filter(Boolean).join(", "), id: s.id, at: s.at, here: false })),
    { target: String(target ?? ""), type_word: TYPE_WORD[type] || "", via: "", id: "", at: 0, here: true }];
}
export const trailText = (view) => view.map((s) => (s.here ? `${s.target} (this case)` : `${s.target} (${s.type_word})${s.via ? `, then ${s.via}` : ""}`)).join(" > ");
export const trailMarkdown = (view) => (view.length ? ["## How this case was reached", "_Each step was a click by the investigator on a lead of the case before it. Recorded in the browser only._", ...view.map((s, i) => `${i + 1}. ${s.here ? `**${s.target}** (this case)` : `**${s.target}** (${s.type_word})${s.via ? `: followed ${s.via}` : ""}`}`), ""] : []);

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

// The keys this module and identity.js own, read like a fresh answer: for History and case files.
export function readCasework(results, { file = false } = {}) {
  if (!isObj(results)) return results;
  const out = { ...results };
  if ("pick" in out) { const p = readPick(out.pick); if (p) out.pick = file ? { ...p, file: true } : p; else delete out.pick; }
  if ("trail" in out) { const t = readTrail(out.trail); if (t.length) out.trail = t; else delete out.trail; }
  if ("nextSteps" in out) { const s = readSteps(out.nextSteps); if (Object.keys(s).length) out.nextSteps = s; else delete out.nextSteps; }
  return out;
}
export const CASEWORK_KEYS = ["pick", "trail", "nextSteps", "archives"];
