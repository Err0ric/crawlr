// Pieces shared by every workbench mode: run log, tiered ledger, facts panel, run diff.
import { $$, h, raw, esc, link, linkOf, store, fmtNum, fmtAgo, plural, roving } from "./core.js";
import { checkText } from "./links.js";

// ---- run log ------------------------------------------------------------------
// One row per source. While a run is in flight the strip shows "3 of 7 sources" with a
// bar and a ticking clock; each row keeps its own timer until it settles. Row states:
//   run   in flight            done  returned data
//   none  ran, found nothing   err   failed (never the same thing as "none")
//   skip  not run / cancelled
// A polite live region announces each source as it settles, for screen readers.
let logSeq = 0;
export function makeLog(el) {
  const ICON = { run: "◌", done: "✓", none: "–", err: "✕", skip: "○" };
  const LABEL = { run: "running", done: "done", none: "nothing found", err: "failed", skip: "skipped" };
  const id = `runlog${++logSeq}`;
  const live = document.createElement("div");
  live.className = "sr-only"; live.setAttribute("role", "status"); live.setAttribute("aria-live", "polite");
  el.after(live);
  const secs = (t0) => `${((performance.now() - t0) / 1000).toFixed(1)}s`;
  let timer = null;
  const rows = () => [...el.querySelectorAll(".lg")];
  const counts = () => { const all = rows(); return { total: all.length, settled: all.filter((r) => !r.classList.contains("run")).length }; };
  function paint() {
    const { total, settled } = counts();
    const s = el.querySelector(".runlog-summary");
    if (!s || !log.running) return;
    s.querySelector(".st").textContent = total ? `Running · ${settled} of ${plural(total, "source")} done` : "Starting";
    s.querySelector(".t").textContent = secs(log.t0);
    s.querySelector(".bar i").style.width = `${total ? Math.round((settled / total) * 100) : 0}%`;
    for (const r of rows()) if (r.classList.contains("run")) r.querySelector(".t").textContent = secs(+r.dataset.t0);
  }
  const setOpen = (open) => { el.classList.toggle("collapsed", !open); el.querySelector(".runlog-summary")?.setAttribute("aria-expanded", open); };
  const log = {
    t0: 0, running: false,
    start() {
      el.hidden = false; this.running = true; this.t0 = performance.now();
      el.innerHTML = `<button type="button" class="runlog-summary" aria-expanded="true" aria-controls="${id}"><span class="st">Starting</span><span class="bar" aria-hidden="true"><i></i></span><span class="t"></span><span class="chev" aria-hidden="true">▾</span></button><div class="runlog-rows" id="${id}"></div>`;
      setOpen(true);
      clearInterval(timer); timer = setInterval(paint, 200);
      live.textContent = "Run started.";
    },
    add(text, status = "run") {
      const r = document.createElement("div");
      r.className = `lg ${status}`; r.dataset.t0 = performance.now();
      r.innerHTML = `<span class="ic" aria-hidden="true">${ICON[status]}</span><span class="m"></span><span class="t"></span>`;
      r.querySelector(".m").textContent = text;
      el.querySelector(".runlog-rows").appendChild(r);
      paint();
      return r;
    },
    // detail: raw technical text, tucked behind a "details" toggle on the row.
    set(r, text, status, detail = "") {
      r.className = `lg ${status}`;
      r.querySelector(".ic").textContent = ICON[status] || "";
      const m = r.querySelector(".m"); m.textContent = text;
      if (detail) {
        const d = document.createElement("details"); d.className = "lg-detail";
        d.innerHTML = `<summary>details</summary><code></code>`;
        d.querySelector("code").textContent = detail;
        m.append(" ", d);
      }
      r.querySelector(".t").textContent = secs(+r.dataset.t0);
      live.textContent = `${text}${status === "err" ? " (failed)" : ""}`;
      paint();
    },
    // failed comes from sourceTally, so the strip and the case header cannot disagree.
    finish(summary, failed = 0) {
      this.running = false; clearInterval(timer);
      const s = el.querySelector(".runlog-summary"); if (!s) return;
      for (const r of rows()) if (r.classList.contains("run")) { r.className = "lg skip"; r.querySelector(".ic").textContent = ICON.skip; }
      s.querySelector(".st").textContent = summary;
      s.classList.toggle("has-err", failed > 0);
      s.querySelector(".t").textContent = secs(this.t0);
      s.querySelector(".bar").hidden = true;
      // Collapse to one line when everything worked; stay open when something failed so it is seen.
      setOpen(failed > 0);
      live.textContent = `Run finished. ${summary}.`;
    },
    open() { setOpen(true); },
    // True once a run has drawn the strip. A case opened from History has no run log.
    get live() { return !el.hidden && !!el.querySelector(".runlog-rows"); },
    // A follow-up that settles after the run (the link check) updates the one-line summary.
    resummarize(summary, failed = 0) {
      const s = el.querySelector(".runlog-summary"); if (!s || this.running) return;
      s.querySelector(".st").textContent = summary; s.classList.toggle("has-err", failed > 0);
      if (failed > 0) setOpen(true);
    },
    statusOf: (r) => Object.keys(LABEL).find((k) => r.classList.contains(k)),
  };
  el.addEventListener("click", (e) => { if (e.target.closest(".runlog-summary")) setOpen(el.classList.contains("collapsed")); });
  return log;
}

// ---- tiered ledger ---------------------------------------------------------------
// tiers: [{ id, title, cls, open, blurb, limit?, collapseOver? }]
const PREVIEW = 15;
// The text side of one ledger row, as a string, so the link rules can be tested without a DOM.
// The name is the link when the row has a URL of its own. An evidence link is a labelled anchor
// after the text. A row with link_kind "none" is plain text, with a hint on how to check by hand.
const CHECK_CLS = { verified: "ok", not_found: "", blocked: "warn", unknown: "", no_public_url: "" };
export function evWhat(it) {
  const name = it.link_label ? esc(it.what) : linkOf(it);
  const labelled = it.link_label ? ` ${link(it.url, it.link_label, "ev-link", { kind: it.link_kind })}` : "";
  const more = it.more?.url ? ` ${link(it.more.url, it.more.label, "ev-link", { kind: "evidence" })}` : "";
  const state = checkText(it);
  return name + (it.isNew ? '<span class="tag violet">new</span>' : "") + labelled + more
    + (state ? h`<span class="lk-state ${CHECK_CLS[it.check] || ""}">${state}</span>` : "")
    + (it.meta ? h`<span class="meta">${it.meta}</span>` : "")
    + (it.hint ? h`<span class="ev-hint"><b>How to check</b> ${it.hint}</span>` : "");
}
// Replaces one row's text in place after its link was checked, and moves a row whose page was
// not found to the end of its group. Nothing else on the page moves.
// Focus stays with the keyboard user: if it was on this row's link it goes to the new link, or to
// the row's checkbox when the link became plain text; if it was on the checkbox it stays there
// through the move. Focus that is anywhere else is left alone.
export function patchRow(el, it, doc = globalThis.document) {
  const row = [...el.querySelectorAll(".ev[data-row]")].find((r) => r.dataset.row === it.key);
  if (!row) return false;
  const what = row.querySelector(".what"), box = row.querySelector("input[type=checkbox]");
  const active = doc?.activeElement;
  const was = active && active === box ? "box" : active && what.contains(active) ? "link" : "";
  what.innerHTML = evWhat(it);
  if (it.gone && !row.classList.contains("gone")) {
    row.classList.add("gone");
    const rows = row.parentElement.querySelectorAll(":scope > .ev");
    if (rows[rows.length - 1] !== row) rows[rows.length - 1].after(row);
  }
  if (was) ((was === "link" && what.querySelector("a.lk")) || box)?.focus({ preventScroll: true });
  return true;
}
// opts.check(tierId): how many of the group's links the link check could look at now. When it is
// more than none the group header carries a "Check these links" button (see linkcheck.js).
export function renderTiers(el, items, tiers, done, emptyHtml, opts = {}) {
  const byTier = Object.fromEntries(tiers.map((t) => [t.id, items.filter((i) => i.tier === t.id)]));
  const shown = tiers.filter((t) => byTier[t.id].length);
  el.innerHTML = shown.length ? shown.map((t) => {
    const rows = byTier[t.id];
    const limit = t.limit ?? 200;
    const open = t.collapseOver ? rows.length <= t.collapseOver : t.open;
    // Long tiers (a heavily breached email can have 200+ rows) show the first PREVIEW rows.
    const clip = Math.min(rows.length, limit) > PREVIEW + 5;
    const bodyId = `tier-${el.id}-${t.id}`;
    return h`
      <section class="tier ${t.cls} ${open ? "" : "collapsed"} ${clip ? "clipped" : ""}" data-tier="${t.id}">
        <h2 class="tier-h"><button type="button" class="tier-head" aria-expanded="${open}" aria-controls="${bodyId}">
          <span class="tier-rail" aria-hidden="true"></span><span class="tier-title">${t.title}</span><span class="count">${fmtNum(rows.length)}</span><span class="chev" aria-hidden="true">▾</span>
        </button>${((nCheck) => (nCheck > 0 ? raw(h`<button type="button" class="btn btn-sm tier-check" data-check-tier="${t.id}" data-count="${nCheck}">Check these links (${fmtNum(nCheck)})</button>`) : ""))(opts.check ? Number(opts.check(t.id)) || 0 : 0)}</h2>
        <div class="tier-body" id="${bodyId}">
          <div class="tier-blurb">${t.blurb}</div>
          ${t.note ? raw(h`<div class="tier-blurb">${t.note}</div>`) : ""}
          ${raw(rows.slice(0, limit).map((it, i) => h`
            <div class="ev ${done.has(it.key) ? "done" : ""} ${it.gone ? "gone" : ""} ${i >= PREVIEW ? "ev-extra" : ""}" data-row="${it.key}">
              <label class="ev-check"><input type="checkbox" data-key="${it.key}" ${done.has(it.key) ? "checked" : ""}><span class="sr-only">Mark ${it.what} reviewed</span></label>
              <div class="what">${raw(evWhat(it))}</div>
              <span class="src">${it.action ? raw(h`<button type="button" class="btn btn-sm ev-act" data-pivot="${it.action.pivot}" data-value="${it.action.value}" data-confirm-run="1" aria-label="${it.action.label}: ${it.action.value}">${it.action.label}</button>`) : ""}${it.source}</span>
            </div>`).join(""))}
          ${clip ? raw(h`<button type="button" class="btn btn-sm ev-toggle" data-show-all>Show all ${fmtNum(Math.min(rows.length, limit))}</button>`) : ""}
          ${rows.length > limit ? raw(h`<div class="ev-more">${fmtNum(rows.length - limit)} more not shown. Export for the full list.</div>`) : ""}
        </div>
      </section>`;
  }).join("") : emptyHtml;
}

// Wire collapse + review checkboxes once per ledger element.
export function bindLedger(el, storageKey) {
  el.addEventListener("click", (e) => {
    const more = e.target.closest("[data-show-all]");
    if (more) {
      more.dataset.label ||= more.textContent;
      const clipped = more.closest(".tier").classList.toggle("clipped");
      more.textContent = clipped ? more.dataset.label : "Show fewer";
      return;
    }
    const head = e.target.closest(".tier-head");
    if (!head) return;
    const sec = head.closest(".tier");
    sec.classList.toggle("collapsed");
    head.setAttribute("aria-expanded", !sec.classList.contains("collapsed"));
    // The link check starts when a group is opened and stops when it is closed.
    el.dispatchEvent(new CustomEvent("crawlr:tier", { detail: { tier: sec.dataset.tier, open: !sec.classList.contains("collapsed") } }));
  });
  el.addEventListener("change", (e) => {
    const k = e.target.dataset.key;
    if (!k) return;
    const key = storageKey();
    const s = new Set(store.get(key, []));
    e.target.checked ? s.add(k) : s.delete(k);
    store.set(key, [...s]);
    e.target.closest(".ev").classList.toggle("done", e.target.checked);
  });
}

// ---- failed sources ---------------------------------------------------------------
// Shown above the findings so a failure is never mistaken for an empty result.
export function failedNotice(failed) {
  if (!failed.length) return "";
  return h`<div class="notice err" role="note">
    <strong>${plural(failed.length, "source")} could not be checked.</strong>
    <span>Nothing below says anything about ${failed.length === 1 ? "it" : "them"}: a failed source is unknown, not "not found".</span>
    <ul>${raw(failed.map((f) => h`<li><b>${f.name}</b> ${f.text}${f.detail ? raw(h` <details class="lg-detail"><summary>details</summary><code>${f.detail}</code></details>`) : ""}</li>`).join(""))}</ul>
  </div>`;
}

// ---- changes since the last run of the same target ----------------------------------
// Compares finding keys with the previous saved case. Purely local and only on a manual
// re-run: CrawlR does not watch targets in the background.
export function diffRuns(prevKeys, items) {
  if (!prevKeys) return null;
  const before = new Set(prevKeys), now = new Set(items.map((i) => i.key));
  const added = items.filter((i) => !before.has(i.key));
  const removed = [...before].filter((k) => !now.has(k));
  return { added, removed, same: items.length - added.length };
}
const keyLabel = (k) => String(k).replace(/^[a-z]+:/, "");
export function diffNotice(diff, prevTs) {
  if (!diff) return "";
  const when = h`<span class="when" title="${new Date(prevTs).toLocaleString()}">compared with your run ${fmtAgo(prevTs)}</span>`;
  if (!diff.added.length && !diff.removed.length) return h`<div class="notice diff" role="note"><strong>No changes</strong> ${raw(when)}</div>`;
  const list = (title, arr) => arr.length ? h`<details><summary>${title} (${arr.length})</summary><ul>${raw(arr.slice(0, 60).map((x) => h`<li>${x}</li>`).join(""))}${arr.length > 60 ? raw(h`<li>and ${arr.length - 60} more</li>`) : ""}</ul></details>` : "";
  return h`<div class="notice diff" role="note">
    <strong>${diff.added.length} new, ${diff.removed.length} gone, ${diff.same} unchanged</strong> ${raw(when)}
    ${raw(list("New this run", diff.added.map((i) => i.what)))}${raw(list("No longer reported", diff.removed.map(keyLabel)))}
  </div>`;
}

// ---- facts panel -------------------------------------------------------------------
export function renderFacts(el, facts, emptyText = "No facts extracted yet.") {
  el.innerHTML = facts.length
    ? `<dl class="facts-list">${facts.map((f) => h`<div class="fact"><dt class="k">${f.k}</dt><dd class="v">${raw(linkOf(f, f.v))}<span class="src">${f.source}</span></dd></div>`).join("")}</dl>`
    : h`<p class="empty flat">${emptyText}</p>`;
}

// "What we know" for a person case: the facts of one identity cluster at a time, primary first.
// A labelled select switches to another cluster's facts. `pick` is the view id to show.
export function renderIdentityFacts(el, { views, primary, noPrimary }, factsOf, pick, emptyText) {
  const picked = views.find((v) => v.id === pick);
  const view = picked || views.find((v) => v.id === primary) || (noPrimary ? null : views[0]);
  const label = (v) => `${v.label}${v.primary ? " (primary)" : ""} · ${v.sites.slice(0, 3).join(", ")}${v.sites.length > 3 ? ` +${v.sites.length - 3}` : ""}`;
  const box = document.createElement("div");
  const select = (first) => h`<div class="who-pick"><label for="${el.id}Pick">Showing</label><select class="input" id="${el.id}Pick" data-cluster-pick>${raw(first)}${raw(views.map((v) => h`<option value="${v.id}" ${view && v.id === view.id ? "selected" : ""}>${label(v)}</option>`).join(""))}</select></div>`;
  // No anchor record and no strong signal: nobody is picked, and no one's facts are shown as the target's.
  const named = views.filter((v) => v.named).length;
  const none = noPrimary ? h`<p class="who-why">${named > 1 ? `${named} different names appear under this handle, and none is tied to the target.` : "Profiles were read, and nothing ties them to the target."} There is no record for the target itself and no strong signal between profiles, so no primary identity is chosen.</p>` : "";
  if (!view) {
    renderFacts(box, factsOf(null), "Pick a name above to see what its profiles say.");
    el.innerHTML = select(h`<option value="" selected>No primary identity</option>`) + none + box.innerHTML;
    return null;
  }
  renderFacts(box, factsOf(view.id), view.id === "unassigned" ? "These profiles carry no facts." : "No facts on these profiles.");
  const why = view.primary ? `Primary identity because ${view.why}.` : view.id === "unassigned" ? "Profiles that were read but carry no name, so nothing ties them to anyone." : noPrimary ? "One of the names under this handle. Nothing ties these profiles to the target." : "Not the primary identity: the name on these profiles conflicts with it, or nothing ties them to it.";
  const joined = view.signals.length ? ` Joined by: ${[...new Set(view.signals.map((s) => `${s.a} and ${s.b} (${s.detail})`))].slice(0, 4).join("; ")}.` : "";
  el.innerHTML = (views.length > 1 || noPrimary ? select(noPrimary ? h`<option value="">No primary identity</option>` : "") : h`<p class="who-one">${label(view)}</p>`)
    + none + h`<p class="who-why">${why}${joined}</p>` + box.innerHTML;
  return view.id;
}

// Fact collector with de-duplication on (label, value).
export function factCollector() {
  const facts = [];
  const add = (k, v, source, url) => {
    if (v === undefined || v === null || v === "" || (Array.isArray(v) && !v.length)) return;
    const val = Array.isArray(v) ? v.join(", ") : String(v);
    if (!facts.some((f) => f.k === k && f.v.toLowerCase() === val.toLowerCase())) facts.push({ k, v: val, source, url });
  };
  return { facts, add };
}

// Item collector with de-duplication on url or (source, text).
export function itemCollector() {
  const items = [];
  const seen = new Set();
  const add = (it) => {
    const id = it.url ? String(it.url).toLowerCase() : `${it.source}:${String(it.what).toLowerCase()}`;
    if (seen.has(id)) return;
    seen.add(id);
    items.push(it);
  };
  return { items, add };
}

// ---- print / standalone HTML export --------------------------------------------------
// The same markup as the screen, with every collapsed section opened, wrapped in a page
// that carries its own stylesheet. Nothing is uploaded: the file is built in the browser.
export async function standaloneHtml(title, mainEl, asideEl) {
  const cssUrl = document.querySelector('link[rel="stylesheet"]').href;
  let css = "";
  try { css = await (await fetch(cssUrl)).text(); } catch { /* unstyled is still readable */ }
  css = css.replace(/@font-face\s*{[^}]*}/g, "");   // fonts are not embedded; system fonts take over
  const clone = (el) => { const c = el.cloneNode(true); c.querySelectorAll(".panel").forEach((x) => (x.hidden = false)); c.querySelectorAll("[hidden], .btn, .ev-check, .runlog, .sr-only, [role=status], .lg-detail, .ai-pitch, .ai-cost, .lk-status, input, textarea, .tabs").forEach((x) => x.remove()); c.querySelectorAll(".collapsed, .clipped").forEach((x) => x.classList.remove("collapsed", "clipped")); c.querySelectorAll("details").forEach((d) => (d.open = true)); return c.innerHTML; };
  return `<!DOCTYPE html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>${css}\nbody{padding:24px;max-width:1000px;margin:0 auto}.print-only{display:block !important}.export-meta{color:var(--ink-3);font-size:13px;margin:0 0 20px}</style></head><body><p class="export-meta">Exported from CrawlR on ${esc(new Date().toLocaleString())}. Findings come from third-party public sources and can be wrong. "Unverified" items are leads, not facts, and a profile that exists is not proof of who owns it.</p><main class="main">${clone(mainEl)}</main>${asideEl ? `<aside class="aside">${clone(asideEl)}</aside>` : ""}</body></html>`;
}

// ---- tabs ---------------------------------------------------------------------------
// A tablist whose tabs name their panels with aria-controls. One tab stop, arrow keys,
// Home and End. Returns { set(name), get() }.
export function makeTabs(el, onChange) {
  const tabs = () => $$("[role=tab]", el);
  function set(name, { notify = true } = {}) {
    for (const t of tabs()) {
      const on = t.dataset.tab === name;
      t.setAttribute("aria-selected", on); t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.getAttribute("aria-controls"));
      if (panel) panel.hidden = !on;
    }
    if (notify) onChange?.(name);
  }
  el.addEventListener("click", (e) => { const b = e.target.closest("[role=tab]"); if (b) set(b.dataset.tab); });
  roving(el, "[role=tab]", (t) => set(t.dataset.tab));
  return { set, get: () => tabs().find((t) => t.getAttribute("aria-selected") === "true")?.dataset.tab };
}
export const setTabCount = (tabEl, label, n) => { tabEl.textContent = n ? `${label} (${fmtNum(n)})` : label; };

// ---- "At a glance" brief --------------------------------------------------------------
const BRIEF_WORD = { flag: "Check", ok: "Good", info: "Note" };
export function renderBrief(section, body, { rows, actions }) {
  section.hidden = !rows.length;
  if (!rows.length) { body.innerHTML = ""; return; }
  body.innerHTML = `<ul class="brief-list">${rows.map((r) => h`<li class="${r.level}"><span class="tag ${r.level === "flag" ? "warn" : r.level === "ok" ? "ok" : ""}">${BRIEF_WORD[r.level] || "Note"}</span><span>${r.text}${r.url && r.link_kind !== "none" ? raw(` ${link(r.url, r.link_label || "Source record", "ev-link", { kind: r.link_kind || "evidence" })}`) : ""}</span></li>`).join("")}</ul>`
    + (actions.length ? `<div class="brief-actions">${actions.map((a) => a.href ? link(a.href, a.label, "btn btn-sm") : a.tab ? h`<button type="button" class="btn btn-sm" data-brief-tab="${a.tab}">${a.label}</button>` : h`<button type="button" class="btn btn-sm" data-pivot="${a.pivot}" data-value="${a.value}">${a.label}</button>`).join("")}</div>` : "");
}

// ---- purpose and notes on paper ---------------------------------------------------------
// Inputs do not print well and are stripped from the HTML export, so the purpose and notes
// are mirrored into a block that only shows in print and in exported pages.
export function casePrint(el, { purpose, notes, ran }) {
  const p = String(purpose || "").trim(), n = String(notes || "").trim();
  el.innerHTML = (ran ? h`<p><b>Collected</b> ${new Date(ran).toLocaleString()}</p>` : "") + (p ? h`<p><b>Purpose</b> ${p}</p>` : "") + (n ? h`<p><b>Notes</b></p><p class="pre">${n}</p>` : "");
}
