// Pieces shared by every workbench mode: run log, tiered ledger, facts panel, run diff.
import { $$, h, raw, esc, link, safeUrl, store, fmtNum, fmtAgo, plural, roving } from "./core.js";

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
  const counts = () => { const all = rows(); return { total: all.length, settled: all.filter((r) => !r.classList.contains("run")).length, failed: all.filter((r) => r.classList.contains("err")).length }; };
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
    finish(summary) {
      this.running = false; clearInterval(timer);
      const s = el.querySelector(".runlog-summary"); if (!s) return;
      const { failed } = counts();
      for (const r of rows()) if (r.classList.contains("run")) { r.className = "lg skip"; r.querySelector(".ic").textContent = ICON.skip; }
      s.querySelector(".st").textContent = summary + (failed ? ` · ${failed} failed` : "");
      s.classList.toggle("has-err", failed > 0);
      s.querySelector(".t").textContent = secs(this.t0);
      s.querySelector(".bar").hidden = true;
      // Collapse to one line when everything worked; stay open when something failed so it is seen.
      setOpen(failed > 0);
      live.textContent = `Run finished. ${summary}${failed ? `, ${failed} failed` : ""}.`;
    },
    open() { setOpen(true); },
    statusOf: (r) => Object.keys(LABEL).find((k) => r.classList.contains(k)),
  };
  el.addEventListener("click", (e) => { if (e.target.closest(".runlog-summary")) setOpen(el.classList.contains("collapsed")); });
  return log;
}

// ---- tiered ledger ---------------------------------------------------------------
// tiers: [{ id, title, cls, open, blurb, limit?, collapseOver? }]
const PREVIEW = 15;
export function renderTiers(el, items, tiers, done, emptyHtml) {
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
        </button></h2>
        <div class="tier-body" id="${bodyId}">
          <div class="tier-blurb">${t.blurb}</div>
          ${raw(rows.slice(0, limit).map((it, i) => h`
            <div class="ev ${done.has(it.key) ? "done" : ""} ${i >= PREVIEW ? "ev-extra" : ""}">
              <label class="ev-check"><input type="checkbox" data-key="${it.key}" ${done.has(it.key) ? "checked" : ""}><span class="sr-only">Mark ${it.what} reviewed</span></label>
              <div class="what">${raw(it.url ? link(it.url, it.what) : esc(it.what))}${it.isNew ? raw('<span class="tag violet">new</span>') : ""}${it.meta ? raw(h`<span class="meta">${it.meta}</span>`) : ""}</div>
              <span class="src">${it.source}</span>
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
    ? `<dl class="facts-list">${facts.map((f) => h`<div class="fact"><dt class="k">${f.k}</dt><dd class="v">${raw(f.url ? link(f.url, f.v) : esc(f.v))}<span class="src">${f.source}</span></dd></div>`).join("")}</dl>`
    : h`<p class="empty flat">${emptyText}</p>`;
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
  const clone = (el) => { const c = el.cloneNode(true); c.querySelectorAll(".panel").forEach((x) => (x.hidden = false)); c.querySelectorAll("[hidden], .btn, .ev-check, .runlog, .sr-only, [role=status], .lg-detail, .ai-pitch, .ai-cost, input, textarea, .tabs").forEach((x) => x.remove()); c.querySelectorAll(".collapsed, .clipped").forEach((x) => x.classList.remove("collapsed", "clipped")); c.querySelectorAll("details").forEach((d) => (d.open = true)); return c.innerHTML; };
  return `<!DOCTYPE html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>${css}\nbody{padding:24px;max-width:1000px;margin:0 auto}.export-meta{color:var(--ink-3);font-size:13px;margin:0 0 20px}</style></head><body><p class="export-meta">Exported from CrawlR on ${esc(new Date().toLocaleString())}. Findings come from third-party public sources and can be wrong. "Possible" items are leads, not facts.</p><main class="main">${clone(mainEl)}</main>${asideEl ? `<aside class="aside">${clone(asideEl)}</aside>` : ""}</body></html>`;
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
  body.innerHTML = `<ul class="brief-list">${rows.map((r) => h`<li class="${r.level}"><span class="tag ${r.level === "flag" ? "warn" : r.level === "ok" ? "ok" : ""}">${BRIEF_WORD[r.level] || "Note"}</span><span>${r.text}</span></li>`).join("")}</ul>`
    + (actions.length ? `<div class="brief-actions">${actions.map((a) => a.href ? h`<a class="btn btn-sm" href="${safeUrl(a.href)}" target="_blank" rel="noopener noreferrer">${a.label}</a>` : a.tab ? h`<button type="button" class="btn btn-sm" data-brief-tab="${a.tab}">${a.label}</button>` : h`<button type="button" class="btn btn-sm" data-pivot="${a.pivot}" data-value="${a.value}">${a.label}</button>`).join("")}</div>` : "");
}
