// Session modes: "Adult sites" and "Active techniques". Two opt-ins that are off whenever the page
// loads and, once switched on, stay on for every case of that page session until the investigator
// switches them off or reloads. No DOM, no network, no storage: the state is two booleans in this
// module's memory, so a fresh load of the module is a fresh session with both off.
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
//   - The minor guard has no override: for a handle that suggests a minor the adult mode stays on
//     for the session and is suspended for that case, with the reason.
import { h, raw } from "./core.js";
import { minorGuard, guardText, handleOf } from "./adult.js";

export const MODE_IDS = ["adult", "active"];
export const MODE = {
  adult: {
    label: "Adult sites",
    desc: "Existence checks on adult and dating sites.",
    sheet: "Sherlock and Maigret add adult and dating sites, and an adult site check runs. Existence checks only, text only.",
    status: "Adult sites on for this session.",
    off: "Turn off adult sites",
    confirmTitle: "Switch on adult sites?",
    confirmYes: "Switch on adult sites",
    confirm: [
      "Sherlock and Maigret will add adult and dating sites, and an adult site check will run, for every username case.",
      "These are existence checks only, shown as text: a match shows a handle is taken there, not who owns it. No picture or post is ever loaded.",
      "They are never run for a handle that suggests a minor, and there is no way around that. Use this only for lawful purposes.",
    ],
  },
  active: {
    label: "Active techniques",
    desc: "Profile scraping for Deep Dive. May notify the target.",
    reconDesc: "Port scan of the target host. May notify the target.",
    sheet: "Profile scraping for Deep Dive. May notify the target. In Recon this is the port scan.",
    status: "Active techniques on for this session. May notify the target.",
    off: "Turn off active techniques",
    confirmTitle: "Switch on active techniques?",
    confirmYes: "Switch on active techniques",
    confirm: [
      "CrawlR will fetch the target's own profile pages when you run a Deep Dive in Investigate, and scan 20 common ports on the target host on every run in Recon.",
      "Both connect to the target's own systems, which the target's services may log. Only scan hosts you own or are authorized to test.",
    ],
  },
};
// Said in both first-use confirmations, the Sources sheets and the docs.
export const MODE_STAYS = "It stays on for every case until you switch it off or reload the page.";
export const MODE_RULE = "Adult sites and Active techniques are off when the page loads, stay on until you switch them off or reload, and are never saved.";
export const NOT_USED = "Not used for this kind of target.";
export const MINOR_SHORT = "Not checked for this handle: it suggests a minor.";

// ---- the session ------------------------------------------------------------------------------
export function makeSessionModes() {
  const on = { adult: false, active: false }, accepted = { adult: false, active: false };
  const subs = new Set();
  const known = (id) => MODE_IDS.includes(id);
  const tell = (id) => { for (const f of [...subs]) f(id); };
  const put = (id, v) => { if (on[id] !== v) { on[id] = v; tell(id); } };
  return {
    on: (id) => known(id) && on[id] === true,
    accepted: (id) => known(id) && accepted[id] === true,
    // want: the literal true switches on, anything else switches off. ask({ accept, cancel }) is
    // called only when the mode has not been accepted in this session yet. Returns "on", "off" or
    // "asked" (nothing changed: the answer decides).
    request(id, want, ask) {
      if (!known(id)) return "off";
      if (want !== true) { put(id, false); return "off"; }
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
// One session per page load, shared by Investigate and Recon.
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

// ---- does the mode apply to the case on screen? ------------------------------------------------
// state: "off" (the mode is off), "idle" (on, no target yet), "applies", "unused" (on, but this
// kind of target has nothing for it) or "suspended" (on, and the minor guard refuses this handle).
// note: the sentence to show whether the mode is on or off; reason: the full sentence for "suspended".
const view = (on, state, note = "", reason = "") => ({ on, applies: on && state === "applies", state: on ? state : "off", note, reason });
// refused: handle (lowercase, no @) -> the reason the server's own guard gave, for this session.
export function adultCase(on, target, type, refused = null) {
  const isOn = on === true;
  if (!type) return view(isOn, "idle");
  if (type !== "username") return view(isOn, "unused", NOT_USED);
  const key = handleOf(target).toLowerCase();
  if (!key) return view(isOn, "idle");
  const g = minorGuard(target);
  if (g.blocked) return view(isOn, "suspended", MINOR_SHORT, guardText(g.reason));
  if (refused && refused.has(key)) return view(isOn, "suspended", MINOR_SHORT, guardText(refused.get(key)));
  return view(isOn, "applies");
}
// bench: "investigate" (profile scraping for Deep Dive, which reads the profile pages the username
// tools found) or "recon" (the port scan: a domain or an IP address).
const ACTIVE_TYPES = { investigate: ["username"], recon: ["domain", "ip"] };
export function activeCase(on, type, bench = "investigate") {
  const isOn = on === true;
  if (!type) return view(isOn, "idle");
  return (ACTIVE_TYPES[bench] || []).includes(type) ? view(isOn, "applies") : view(isOn, "unused", NOT_USED);
}
// The handles the server's guard refused in this session. In memory only, bounded.
export function makeRefusals(max = 200) {
  const m = new Map();
  return {
    add(target, reason) { const k = handleOf(target).toLowerCase(); if (!k) return; if (m.size >= max && !m.has(k)) m.delete(m.keys().next().value); m.set(k, String(reason || "").slice(0, 160)); },
    has: (k) => m.has(k), get: (k) => m.get(k),
  };
}

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
      <label class="switch"><input type="checkbox" role="switch" id="${base}" data-session-mode="${id}" ${v.on ? "checked" : ""} aria-labelledby="${base}-l" aria-describedby="${base}-d"><span></span></label>
      <div class="mode-text"><label class="mode-label" for="${base}" id="${base}-l">${m.label}${id === "active" ? raw(` ${CAUTION}`) : ""}</label><span class="mode-desc" id="${base}-d">${v.note || desc}</span></div>
    </div>`;
}
// The quiet line under the switches while a mode is on: what is on, what that means for this case,
// and one click to switch it off.
export function statusHtml(rows) {
  return rows.filter((r) => r.view.on).map((r) => h`<p class="mode-line" data-mode-line="${r.id}"><span>${MODE[r.id].status}${r.view.state === "suspended" ? ` ${r.view.reason}` : r.view.state === "unused" ? ` ${NOT_USED}` : ""}</span> <button type="button" class="linklike" data-mode-off="${r.id}" aria-label="${MODE[r.id].off}">Turn off</button></p>`).join("");
}
// The same control as a row of the Sources sheet.
export function sheetRowHtml(id, v, { prefix = "", name = MODE[id].label, desc = MODE[id].sheet, tag = id === "active" ? "caution" : "" } = {}) {
  const base = `${prefix}sheet-${id}`;
  return h`<div class="source mode-row ${v.on ? "" : "off"}" data-mode-row="${id}">
      <div>
        <div class="name" id="${base}-l">${name}${tag ? raw(h` <span class="tag warn">${tag}</span>`) : ""}</div>
        <div class="desc" id="${base}-d">${desc} ${MODE_STAYS}</div>
        ${v.note ? raw(h`<p class="adult-note" id="${base}-n">${v.reason || v.note}</p>`) : ""}
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-session-mode="${id}" ${v.on ? "checked" : ""} aria-labelledby="${base}-l" aria-describedby="${base}-d${v.note ? ` ${base}-n` : ""}"><span></span></label>
    </div>`;
}
// The body of the first-use confirmation.
export const confirmHtml = (id) => MODE[id].confirm.map((p) => h`<p class="modal-p">${p}</p>`).join("") + h`<p class="modal-p">${MODE_STAYS} It is never saved: it is off again whenever the page loads.</p>`;
