// Session modes: "Adult sites" and "Active techniques" in Investigate, "Port scan" in Recon. Three
// separate opt-ins, each with its own state, switch, confirmation and status line: switching one
// on never switches another on. They are off whenever the page
// loads and, once switched on, stay on for every case of that page session until the investigator
// switches them off or reloads. No DOM, no network, no storage: the state is two booleans in this
// module's memory, so a fresh load of the module is a fresh session with all of them off.
//
// The rules this module holds, so they can be tested in one place:
//   - Off on load. Nothing here reads or writes localStorage, sessionStorage, a cookie, the URL,
//     History or a case file, and nothing a case holds can switch a mode on: the only way on is
//     request(id, true, ask), which is only ever called from a switch the investigator used.
//   - The first time a mode is switched on in a session, ask() is called and the mode goes on only
//     when the investigator accepts. After that it is not asked again in that session.
//   - A mode that is on is not switched off by a case: another handle, a new case, Clear, a pivot or
//     a case opened from History leave it alone. Whether it applies to the case on screen is a
//     separate question, answered per case by adultCase() and activeCase().
//   - The minor guard has no override. A handle that states an age under 18 suspends the adult
//     mode for that case before anything runs; a handle whose profiles suggest a minor suspends it
//     after the ordinary sources (the content check). Either way the mode stays on for the session,
//     the case says why, and the handle stays suspended until the page is reloaded. A case opened
//     by a pivot from a suspended case is suspended too. A variant of a suspended handle is not:
//     it gets its own check of its own profiles.
//   - Without the rules file (data/minor-rules.json) the adult mode cannot be switched on.
//   - What a run does about the modes is decided here, by startAdult(), portscanFor() and
//     deepDiveFor(). The workbenches call them once when a run starts and keep the answer, so a
//     switch moved mid-run applies from the next run.
import { h, raw } from "./core.js";
import { minorGuard, guardText, handleOf, blockClause, readBlock, RULES_UNAVAILABLE } from "./adult.js";
import { rulesReady } from "./minorscan.js";
import { similarBase } from "./similar.js";

export const MODE_IDS = ["adult", "active", "portscan"];
export const MODE = {
  adult: {
    label: "Adult sites",
    desc: "Existence checks on adult and dating sites.",
    sheet: "After the ordinary sources, Sherlock, Maigret and an adult site check ask adult and dating sites. Existence checks only, text only.",
    status: "Adult sites on for this session.",
    off: "Turn off adult sites",
    confirmTitle: "Switch on adult sites?",
    confirmYes: "Switch on adult sites",
    confirm: [
      "For every username case, once the ordinary sources have run and the profiles they found have been checked, Sherlock, Maigret and an adult site check will ask adult and dating sites.",
      "These are existence checks only, shown as text: a match shows a handle is taken there, not who owns it. No picture or post is ever loaded.",
      "They are not run for a handle that states an age under 18, and not when a profile found for the handle suggests a minor. There is no way around that. Use this only for lawful purposes.",
    ],
  },
  active: {
    label: "Active techniques",
    desc: "Profile scraping for Deep Dive. May notify the target.",
    sheet: "Profile scraping for Deep Dive. May notify the target.",
    status: "Active techniques on for this session. May notify the target.",
    off: "Turn off active techniques",
    confirmTitle: "Switch on active techniques?",
    confirmYes: "Switch on active techniques",
    confirm: [
      "CrawlR will fetch the target's own profile pages when you run a Deep Dive.",
      "That connects to the target's own services, which may log the visit. Each Deep Dive still asks before it runs.",
    ],
  },
  portscan: {
    label: "Port scan",
    desc: "Connects to 20 common ports. May notify the target.",
    sheet: "Connects to 20 common ports on the target. May notify the target. Only scan hosts you own or are authorized to test.",
    status: "Port scan on for this session. May notify the target.",
    off: "Turn off the port scan",
    confirmTitle: "Switch on the port scan?",
    confirmYes: "Switch on the port scan",
    confirm: [
      "CrawlR will scan 20 common ports on the target host on every Recon run of a domain or an IP address.",
      "That connects to the target's own systems, which the target's services may log. Only scan hosts you own or are authorized to test.",
    ],
  },
};
// The modes that connect to the target's own systems carry the amber "caution" tag.
export const CAUTIONED = ["active", "portscan"];
// Said in both first-use confirmations, the Sources sheets and the docs.
export const MODE_STAYS = "It stays on for every case until you switch it off or reload the page.";
export const MODE_RULE = "Adult sites, Active techniques and the Port scan are off when the page loads, stay on until you switch them off or reload, and are never saved.";
export const NOT_USED = "Not used for this kind of target.";
// The short line under the switch, by what stopped the case.
export const MINOR_SHORT = {
  handle: "Not checked for this handle: it states an age under 18.",
  word: "Not checked for this handle: it carries a word that marks it as a minor's.",
  content: "Not checked for this handle: a profile found for it suggests a minor.",
  server: "Not checked for this handle: the server refused it.",
  rules: "Not available: the minor rules could not be loaded.",
};
export const MINOR_TIED = "Not checked here: opened from a case the minor guard stopped.";
const shown = (handle) => String(handle ?? "").slice(0, 64);
// A case reached by a pivot (a lead, a similar handle, "Investigate this") from a suspended case.
// via: "content" (a profile of that case suggested a minor) or "handle" (its handle states an age).
export const pivotText = (origin, via = "handle") => `Adult and dating sites are not checked here: this case was opened from ${shown(origin)}, ${via === "content" ? "where a profile suggested a minor" : "whose handle states an age under 18"}.`;
// A handle whose own profiles stopped an earlier run in this session.
export const contentText = (block) => `Adult and dating sites are not checked for this handle: ${blockClause(block)}.`;
export const PORTSCAN_PIVOT_NOTE = "Port scan not run: this case was opened from a link. Press Run recon to scan this host.";
export const DEEP_DIVE_OFF = "Active techniques was switched off, so no profile page was fetched.";
export const RUN_IN_PROGRESS = "A run is in progress: a change applies from the next run.";
// Investigate: neither mode needs the run cancelled. Active techniques gates Deep Dive, which is
// asked when it would fetch; the adult pass can be added to the finished case on a click.
export const RUN_IN_PROGRESS_CASE = "A run is in progress, and there is no need to cancel it. Active techniques applies as soon as it is on. Adult sites switched on now can be added to this case when the run finishes.";

// ---- the session ------------------------------------------------------------------------------
export function makeSessionModes() {
  const on = { adult: false, active: false, portscan: false }, accepted = { adult: false, active: false, portscan: false };
  const subs = new Set();
  const known = (id) => MODE_IDS.includes(id);
  const tell = (id) => { for (const f of [...subs]) f(id); };
  const put = (id, v) => { if (on[id] !== v) { on[id] = v; tell(id); } };
  // What must hold before a mode may go on. The adult mode needs the minor rules loaded: without
  // them nothing could keep it away from a minor, so it stays off and the switch says why.
  const gate = { adult: rulesReady };
  return {
    on: (id) => known(id) && on[id] === true && (!gate[id] || gate[id]()),
    // false when a mode cannot be switched on at all right now, with the sentence to show.
    blocked: (id) => (known(id) && gate[id] && !gate[id]() ? RULES_UNAVAILABLE : ""),
    accepted: (id) => known(id) && accepted[id] === true,
    // want: the literal true switches on, anything else switches off. ask({ accept, cancel }) is
    // called only when the mode has not been accepted in this session yet. Returns "on", "off" or
    // "asked" (nothing changed: the answer decides).
    request(id, want, ask) {
      if (!known(id)) return "off";
      if (want !== true) { put(id, false); return "off"; }
      if (gate[id] && !gate[id]()) { put(id, false); tell(id); return "off"; }
      if (on[id]) return "on";
      if (accepted[id]) { put(id, true); return "on"; }
      if (typeof ask !== "function") return "off";
      let done = false;
      ask({
        accept: () => { if (done) return; done = true; accepted[id] = true; put(id, true); },
        // Cancelling leaves it off, and listeners are told so a switch that moved is put back.
        cancel: () => { if (done) return; done = true; tell(id); },
      });
      return on[id] ? "on" : "asked";
    },
    subscribe(fn) { subs.add(fn); return () => subs.delete(fn); },
  };
}
// One session per page load. Investigate reads "adult" and "active"; Recon reads "portscan" only.
export const session = makeSessionModes();

// ---- stored source preferences -----------------------------------------------------------------
// The per-source switches are remembered in localStorage; the modes never are. An older version
// kept "active" (and, before that, an adult sites choice under "maigret.nsfw") with them, and
// Recon kept "portscan". Those keys are ignored and removed, so nobody arrives with a mode on.
export const LEGACY_PREFS = ["active", "maigret.nsfw", "adult", "portscan"];
export function cleanPrefs(stored) {
  const src = stored && typeof stored === "object" && !Array.isArray(stored) ? stored : {};
  const prefs = {};
  let dirty = src !== stored && stored !== null && stored !== undefined;
  for (const [k, v] of Object.entries(src)) { if (LEGACY_PREFS.includes(k)) dirty = true; else prefs[k] = v; }
  return { prefs, dirty };
}
// A preference may be stored only for an ordinary source.
export const mayStore = (id) => typeof id === "string" && !LEGACY_PREFS.includes(id) && !MODE_IDS.includes(id);

// ---- the handles the adult mode is suspended for, this session -----------------------------------
// Matching ignores case, a leading "@" and the separators . _ - so that "Emma_2012" and "emma2012"
// are one handle here.
export const normHandle = (t) => handleOf(t).toLowerCase().replace(/[._-]+/g, "");
// The handle a case is about, as far as the guard is concerned: a username, or the part of an
// email before the @.
export const caseHandle = (type, target) => (type === "username" ? handleOf(target) : type === "email" ? similarBase(target, "email") || handleOf(String(target ?? "").split("@")[0]) : "");
// In memory only, bounded.
//   add(handle, { server, detail })   the server's guard refused this handle
//   add(handle, { block })            the check of this handle's profiles stopped a run
//   add(handle)                       the handle fails the handle check (it would again anyway)
//   tie(handle, origin, via)          a case for `handle` was opened by a pivot from `origin`
export function makeSuspended(max = 5000) {
  const m = new Map();
  // What a handle was stopped for stands, except that an entry of its own replaces a tie, and the
  // server's refusal replaces the page's reading.
  const put = (k, v) => { if (!k) return; const old = m.get(k); if (old && !((v.own && !old.own) || (v.server && !old.server))) return; if (!old && m.size >= max) m.delete(m.keys().next().value); m.set(k, v); };
  return {
    add(origin, { server = false, detail = "", block = null } = {}) {
      const o = handleOf(origin);
      put(normHandle(o), { origin: o, own: true, server: server === true, detail: String(detail || "").slice(0, 160), block: readBlock(block), via: block ? "content" : "handle" });
    },
    tie(handle, origin, via = "handle") {
      const k = normHandle(handle), o = handleOf(origin);
      if (k && o && k !== normHandle(o)) put(k, { origin: o, own: false, server: false, detail: "", block: null, via: via === "content" ? "content" : "handle" });
    },
    get: (target) => m.get(normHandle(target)) || null,
    get size() { return m.size; },
  };
}

// ---- does the mode apply to the case on screen? ------------------------------------------------
// state: "off" (the mode is off), "idle" (on, no target yet), "applies", "unused" (on, but this
// kind of target has nothing for it) or "suspended" (on, and the minor guard refuses this handle).
// note: the sentence to show whether the mode is on or off; reason: the full sentence for "suspended".
const view = (on, state, note = "", reason = "") => ({ on, applies: on && state === "applies", state: on ? state : "off", note, reason });
// Is this case one the adult mode must stay out of, whatever the switch says? null, or
// { kind, via, origin, reason, block }:
//   "guard"    the handle (or the email's local part) fails the handle check
//   "pivot"    opened from a suspended case: from is { minor } of the case the pivot button was on
//   "content"  this handle's own profiles stopped an earlier run in this session
//   "server"   the server's guard refused this handle
// via says what the suspension goes back to ("handle" or "content"), so a case opened from this
// one can say it. block is what the case records (collected.adultBlock). It does not depend on
// whether the mode is on.
const TOKEN_BLOCK = { age: "handle", word: "word", rules: "rules" };
export function minorFor({ type, target, from = null, suspended = null } = {}) {
  const hd = caseHandle(type, target);
  if (hd) { const g = minorGuard(hd); if (g.blocked) return { kind: "guard", via: "handle", token: g.kind, origin: hd, reason: guardText(g.reason), block: { kind: TOKEN_BLOCK[g.kind] || "server" } }; }
  const tied = (origin, via) => ({ kind: "pivot", via, origin: shown(origin), reason: pivotText(origin, via), block: { kind: "pivot", source: shown(origin), via } });
  if (from && from.minor && from.minor.origin) return tied(from.minor.origin, from.minor.via === "content" ? "content" : "handle");
  const e = hd && suspended ? suspended.get(hd) : null;
  if (!e) return null;
  if (e.own && e.server) return { kind: "server", via: "handle", origin: e.origin, reason: guardText(e.detail), block: e.block || { kind: "server" } };
  if (e.own && e.block) return { kind: "content", via: "content", origin: e.origin, reason: contentText(e.block), block: e.block };
  return tied(e.origin, e.via);
}
const shortNote = (minor) => (minor.kind === "pivot" ? MINOR_TIED : minor.kind === "content" ? MINOR_SHORT.content : minor.kind === "server" ? MINOR_SHORT.server : MINOR_SHORT[minor.token === "age" ? "handle" : minor.token] || MINOR_SHORT.server);
// What the adult mode does for one case. adult is true only when the mode is on, the target is a
// username and nothing suspends it. There is no argument that overrides a suspension.
export function adultFor({ on, type, target, from = null, suspended = null } = {}) {
  const isOn = on === true, minor = minorFor({ type, target, from, suspended });
  const v = !type ? view(isOn, "idle")
    : type !== "username" ? view(isOn, "unused", NOT_USED)
      : !normHandle(target) ? view(isOn, "idle")
        : minor ? view(isOn, "suspended", shortNote(minor), minor.reason)
          : view(isOn, "applies");
  return { adult: v.applies === true, minor, view: v };
}
// The same, when a case starts (a run, or a case opened from History): the decision, and a handle
// reached by a pivot from a suspended case is remembered, so that typing it by hand later in the
// session is judged the same way. This is the function investigate.js calls; it keeps the answer
// for the run. A clean answer here is stage 1 only: the run still has to pass the content check
// (contentCheck in evidence.js) before any adult request is made.
export function startAdult({ on, type, target, from = null, suspended = null } = {}) {
  const d = adultFor({ on, type, target, from, suspended });
  if (d.minor && suspended) {
    if (d.minor.kind === "guard") suspended.add(d.minor.origin);
    else if (d.minor.kind === "pivot") suspended.tie(caseHandle(type, target), d.minor.origin, d.minor.via);
  }
  return d;
}
// The run's content check stopped the case: the handle is suspended for the rest of the session,
// with what was found. Returns what the case keeps as state.minor.
export function suspendContent(suspended, target, block) {
  const b = readBlock(block);
  if (suspended && b) suspended.add(target, { block: b });
  return { kind: "content", via: "content", origin: handleOf(target), reason: contentText(b), block: b };
}
// The view alone, for the switch (kept for callers that only draw).
export const adultCase = (on, target, type, suspended = null, from = null) => adultFor({ on, type, target, from, suspended }).view;
// Active techniques (Investigate): profile scraping for Deep Dive, which reads the profile pages
// the username tools found. Port scan (Recon): a domain or an IP address.
const typed = (on, type, types) => { const isOn = on === true; return !type ? view(isOn, "idle") : types.includes(type) ? view(isOn, "applies") : view(isOn, "unused", NOT_USED); };
export const activeCase = (on, type) => typed(on, type, ["username"]);
export const portscanCase = (on, type) => typed(on, type, ["domain", "ip"]);
// Does this Recon run scan ports? Only when the mode is on, the target is a domain or an IP
// address, and the investigator started the run in Recon's own box (startedBy "run": the Run recon
// button, or Enter). A run started any other way (a lead, a brief action, a topology node, the
// landing form, another workbench) never scans, and says so. Anything but "run" is a pivot.
export function portscanFor({ on, type, startedBy } = {}) {
  if (on !== true || !["domain", "ip"].includes(type)) return { scan: false, note: "" };
  return startedBy === "run" ? { scan: true, note: "" } : { scan: false, note: PORTSCAN_PIVOT_NOTE };
}
// May a Deep Dive fetch the target's profile pages now? Asked again at the moment it would fetch.
export const deepDiveFor = ({ on } = {}) => (on === true ? { fetch: true, note: "" } : { fetch: false, note: DEEP_DIVE_OFF });

// ---- markup --------------------------------------------------------------------------------------
// Every control for a mode carries data-session-mode="<id>", in the case bar and in the Sources
// sheet: one state, drawn in two places, kept in step by syncSwitches().
export function syncSwitches(els, modes = session) {
  for (const el of els || []) { const id = el?.dataset?.sessionMode; if (MODE_IDS.includes(id)) el.checked = modes.on(id); }
}
const CAUTION = '<span class="tag warn">caution</span>';
// The compact switch in the case bar. p is the id prefix of the bench ("" or "r"); v is the case view.
export function barSwitchHtml(id, v, { prefix = "", desc = MODE[id].desc } = {}) {
  const m = MODE[id], base = `${prefix}mode-${id}`;
  return h`<div class="mode ${v.on ? "" : "off"}" data-mode-box="${id}">
      <label class="switch"><input type="checkbox" role="switch" id="${base}" data-session-mode="${id}" ${v.on ? "checked" : ""} aria-label="${m.label}" aria-labelledby="${base}-l" aria-describedby="${base}-d"><span></span></label>
      <div class="mode-text"><label class="mode-label" for="${base}" id="${base}-l">${m.label}${CAUTIONED.includes(id) ? raw(` ${CAUTION}`) : ""}</label><span class="mode-desc" id="${base}-d">${v.note || desc}</span></div>
    </div>`;
}
// The quiet line that stays in view while a mode is on: what is on, what that means for this case,
// and one click to switch it off. A row with `foreign` is a mode of the other workbench: it is on
// for the session, so it is said here too ("Port scan on (Recon)."). While a run is in flight the
// line says that a change applies from the next run.
export function statusHtml(rows, { running = false, wait = RUN_IN_PROGRESS } = {}) {
  const lines = rows.filter((r) => r.view.on).map((r) => h`<p class="mode-line" data-mode-line="${r.id}"><span>${r.foreign ? `${MODE[r.id].label} on (${r.foreign}).` : MODE[r.id].status}${r.foreign ? "" : r.view.state === "suspended" ? ` ${r.view.reason}` : r.view.state === "unused" ? ` ${NOT_USED}` : ""}</span> <button type="button" class="linklike" data-mode-off="${r.id}" aria-label="${MODE[r.id].off}">Turn off</button></p>`);
  return lines.join("") + (lines.length && running ? h`<p class="mode-line mode-wait">${wait}</p>` : "");
}
// The same control as a row of the Sources sheet.
export function sheetRowHtml(id, v, { prefix = "", name = MODE[id].label, desc = MODE[id].sheet, tag = CAUTIONED.includes(id) ? "caution" : "" } = {}) {
  const base = `${prefix}sheet-${id}`;
  return h`<div class="source mode-row ${v.on ? "" : "off"}" data-mode-row="${id}">
      <div>
        <div class="name" id="${base}-l">${name}${tag ? raw(h` <span class="tag warn">${tag}</span>`) : ""}</div>
        <div class="desc" id="${base}-d">${desc} ${MODE_STAYS}</div>
        ${v.note ? raw(h`<p class="adult-note" id="${base}-n">${v.reason || v.note}</p>`) : ""}
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-session-mode="${id}" ${v.on ? "checked" : ""} aria-label="${name}" aria-labelledby="${base}-l" aria-describedby="${base}-d${v.note ? ` ${base}-n` : ""}"><span></span></label>
    </div>`;
}
// The body of the first-use confirmation.
export const confirmHtml = (id) => MODE[id].confirm.map((p) => h`<p class="modal-p">${p}</p>`).join("") + h`<p class="modal-p">${MODE_STAYS} It is never saved: it is off again whenever the page loads.</p>`;
