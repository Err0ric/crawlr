// Pieces shared by every workbench mode: run log, tiered ledger, facts panel.
import { h, raw, esc, link, store, fmtNum } from "./core.js";

// ---- run log ------------------------------------------------------------------
export function makeLog(el) {
  const icon = (s) => (s === "run" ? "◌" : s === "done" ? "✓" : s === "err" ? "✕" : "…");
  const log = {
    t0: 0,
    start() {
      el.hidden = false; el.classList.remove("collapsed");
      el.innerHTML = `<div class="runlog-summary"><span>Running</span><span class="spacer"></span><span class="t"></span></div>`;
      this.t0 = performance.now();
    },
    add(text, status = "run") {
      const r = document.createElement("div");
      r.className = `lg ${status}`;
      r.innerHTML = `<span class="ic">${icon(status)}</span><span class="m"></span><span class="t"></span>`;
      r.querySelector(".m").textContent = text;
      el.appendChild(r);
      return r;
    },
    set(r, text, status) {
      r.className = `lg ${status}`;
      r.querySelector(".ic").textContent = icon(status);
      r.querySelector(".m").textContent = text;
      r.querySelector(".t").textContent = `${((performance.now() - this.t0) / 1000).toFixed(1)}s`;
    },
    finish(summary) {
      const s = el.querySelector(".runlog-summary");
      s.firstChild.textContent = summary;
      s.querySelector(".t").textContent = `${((performance.now() - this.t0) / 1000).toFixed(1)}s`;
      el.classList.add("collapsed");
    },
    open() { el.classList.remove("collapsed"); },
  };
  el.addEventListener("click", (e) => { if (e.target.closest(".runlog-summary")) el.classList.toggle("collapsed"); });
  return log;
}

// ---- tiered ledger ---------------------------------------------------------------
// tiers: [{ id, title, cls, open, blurb, limit?, collapseOver? }]
export function renderTiers(el, items, tiers, done, emptyHtml) {
  const byTier = Object.fromEntries(tiers.map((t) => [t.id, items.filter((i) => i.tier === t.id)]));
  const shown = tiers.filter((t) => byTier[t.id].length);
  el.innerHTML = shown.length ? shown.map((t) => {
    const rows = byTier[t.id];
    const limit = t.limit ?? 200;
    const open = t.collapseOver ? rows.length <= t.collapseOver : t.open;
    return h`
      <section class="tier ${t.cls} ${open ? "" : "collapsed"}" data-tier="${t.id}">
        <div class="tier-head" role="button" tabindex="0" aria-expanded="${open}">
          <span class="tier-rail"></span><h3>${t.title}</h3><span class="count">${fmtNum(rows.length)}</span><span class="chev">▾</span>
        </div>
        <div class="tier-body">
          <div class="tier-blurb">${t.blurb}</div>
          ${raw(rows.slice(0, limit).map((it) => h`
            <div class="ev ${done.has(it.key) ? "done" : ""}">
              <input type="checkbox" data-key="${it.key}" ${done.has(it.key) ? "checked" : ""} aria-label="Mark reviewed">
              <div class="what">${raw(it.url ? link(it.url, it.what) : esc(it.what))}${it.meta ? raw(h`<span class="meta">${it.meta}</span>`) : ""}</div>
              <span class="src">${it.source}</span>
            </div>`).join(""))}
          ${rows.length > limit ? raw(h`<div class="ev-more">${fmtNum(rows.length - limit)} more not shown. Export for the full list.</div>`) : ""}
        </div>
      </section>`;
  }).join("") : emptyHtml;
}

// Wire collapse + review checkboxes once per ledger element.
export function bindLedger(el, storageKey) {
  el.addEventListener("click", (e) => {
    const head = e.target.closest(".tier-head");
    if (!head) return;
    const sec = head.parentElement;
    sec.classList.toggle("collapsed");
    head.setAttribute("aria-expanded", !sec.classList.contains("collapsed"));
  });
  el.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target.classList.contains("tier-head")) { e.preventDefault(); e.target.click(); }
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

// ---- facts panel -------------------------------------------------------------------
export function renderFacts(el, facts, emptyText = "No facts extracted yet.") {
  el.innerHTML = facts.length
    ? facts.map((f) => h`<div class="fact"><span class="k">${f.k}</span><span class="v">${raw(f.url ? link(f.url, f.v) : esc(f.v))}<span class="src">${f.source}</span></span></div>`).join("")
    : h`<p class="empty" style="padding:0">${emptyText}</p>`;
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
