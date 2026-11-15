// Pieces shared by every workbench mode: run log, tiered ledger, facts panel, run diff.
import { $$, h, raw, esc, link, linkOf, mark, store, fmtNum, fmtAgo, plural, roving } from "./core.js";
import { rowCertainty, mayFavicon } from "./present.js";
import { checkText } from "./links.js";
import { ADULT_SECTION, adultHost } from "./adult.js";

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
// A similar handle: the handle and why it was built, then, once it was checked, what the check
// found. Every profile that was read is a small evidence card (mark, site, facts, how it lines up
// with the case), and every source that did not read one is named with its state, so a site that
// blocked the check is never read as absent. A thumbnail is the server-made one or nothing: these
// cards never ask for a site icon.
export function simWhat(it) {
  const s = it.sim;
  const head = h`<span class="ev-title"><span class="ev-name sim-handle">${it.what}</span><span class="meta">${s.reason}</span>${s.state === "new" ? raw('<span class="lk-state">not checked</span>') : ""}</span>`;
  if (s.state === "new") return head;
  const cards = s.profiles.map((p) => {
    const pill = p.pill || { word: "", tone: "" };
    const who = `${p.site} ${s.variant}`;
    return h`<li class="sim-card ${pill.tone ? `tone-${pill.tone}` : ""}">
      ${raw(mark(p.site, { thumb: p.thumb, favicon: false }))}
      <div class="sim-main">
        <span class="ev-title">${raw(link(p.url, p.site, "", { kind: "verified_profile" }))}<span class="ev-handle">${s.variant}</span></span>
        ${p.facts?.length ? raw(`<span class="ev-line">${p.facts.map((f) => h`<span class="ev-fact">${f}</span>`).join("")}</span>`) : ""}
        ${p.bio ? raw(h`<span class="ev-bio">${p.bio}</span>`) : ""}
        <span class="ev-why"><span>${p.lineup.text}${/[.!?]$/.test(p.lineup.text) ? "" : "."}${p.lineup.outcome === "name" ? " A name alone is supporting, not proof." : ""}${p.note === "suspended" ? " The site marks this account as suspended." : ""}</span></span>
      </div>
      <div class="sim-side">${pill.word ? raw(h`<span class="cp ${pill.tone ? `tone-${pill.tone}` : ""}">${pill.word}</span>`) : ""}${p.added ? raw(h`<span class="tag ok">Added</span><button type="button" class="btn btn-sm" data-sim-remove="${p.id}" data-variant="${s.variant}">Remove from this case<span class="sr-only">: ${who}</span></button>`)
        : p.lineup.canAdd ? raw(h`<button type="button" class="btn btn-sm" data-sim-add="${p.id}" data-variant="${s.variant}">Add to this case<span class="sr-only">: ${who}</span></button>`) : ""}</div>
    </li>`;
  }).join("");
  const states = s.sources.map((g) => h`<span class="sim-state"><b>${g.word}</b> ${g.sites.join(", ")}</span>`).join("");
  return head + h`<div class="sim-res"><p class="sim-sum">${s.summary}</p>${cards ? raw(h`<ul class="sim-cards" aria-label="Profiles read for the handle ${s.variant}">${raw(cards)}</ul>`) : ""}${states ? raw(`<p class="sim-states">${states}</p>`) : ""}</div>`;
}
export function evWhat(it) {
  if (it.sim) return simWhat(it);
  // An adult or dating site row carries the site's initials as its mark. Never an image.
  const name = (it.glyph ? h`<span class="site-glyph" aria-hidden="true">${it.glyph}</span>` : "") + (it.link_label ? esc(it.what) : linkOf(it));
  const labelled = it.link_label ? ` ${link(it.url, it.link_label, "ev-link", { kind: it.link_kind })}` : "";
  const more = it.more?.url ? ` ${link(it.more.url, it.more.label, "ev-link", { kind: "evidence" })}` : "";
  const state = checkText(it);
  const head = name + (it.card?.handle ? h`<span class="ev-handle">${it.card.handle}</span>` : "") + (it.isNew ? '<span class="tag violet">new</span>' : "") + labelled + more
    + (state ? h`<span class="lk-state ${CHECK_CLS[it.check] || ""}">${state}</span>` : "");
  const hint = it.hint ? h`<span class="ev-hint"><b>How to check</b> ${it.hint}</span>` : "";
  // An evidence card: the title line, then only what a source read (facts, a bio excerpt), or a
  // plain statement of what kind of check found the row, then why it sits in this group.
  if (it.card) {
    const c = it.card;
    return `<span class="ev-title">${head}</span>`
      + (c.facts?.length ? `<span class="ev-line">${c.facts.map((f) => h`<span class="ev-fact">${f}</span>`).join("")}</span>` : "")
      + (c.bio ? h`<span class="ev-bio">${c.bio}</span>` : "")
      + (c.basis || c.note || c.why ? `<span class="ev-why">${c.why ? h`<span><b>Why here</b>${c.why}</span>` : ""}${c.basis ? h`<span>${c.basis}</span>` : ""}${c.note ? h`<span>${c.note}</span>` : ""}</span>` : "")
      + hint;
  }
  return `<span class="ev-title">${head}${it.meta ? h`<span class="meta">${it.meta}</span>` : ""}</span>` + hint;
}
// The right side of a row: its buttons, then its sources as chips. The profile button's name is
// its visible text plus the login for screen readers, so the text can change to "Loading…" and be heard.
// A similar handle has "Check" until it was checked ("Try again" after a failed check). A profile
// that was added from one has "Remove from this case" on its row in the ledger.
const simAct = (it) => (it.sim && it.sim.state !== "checked" ? h`<button type="button" class="btn btn-sm ev-act" data-sim-check="${it.sim.variant}">${it.sim.state === "failed" ? "Try again" : "Check"}<span class="sr-only">: ${it.sim.variant}</span></button>` : "")
  + (it.similar ? h`<button type="button" class="btn btn-sm ev-act" data-sim-remove="${it.key}" data-variant="${it.similar.variant}">Remove from this case<span class="sr-only">: ${it.what} ${it.similar.variant}</span></button>` : "");
export const evSrc = (it) => simAct(it) + (it.fetch ? h`<button type="button" class="btn btn-sm ev-act" data-name-profile="${it.fetch.login}">${it.fetch.label}<span class="sr-only">: ${it.fetch.login}</span></button>` : "")
  + (it.action ? h`<button type="button" class="btn btn-sm ev-act" data-pivot="${it.action.pivot}" data-value="${it.action.value}" ${it.action.type ? raw(h`data-pivot-type="${it.action.type}"`) : ""} data-confirm-run="1" aria-label="${it.action.label}: ${it.action.value}">${it.action.label}</button>` : "")
  + String(it.source ?? "").split(", ").filter(Boolean).map((x) => h`<span class="chip">${x}</span>`).join("");
// The square mark of an evidence card: the server-made thumbnail, else the site's favicon, else
// initials. A row on an adult or dating host never asks for an image of any kind.
// opts.imported: the case came from a case file and has not been run here, so no icon is asked for.
// opts.handle: the searched handle, so a domain that carries it is never sent to the icon service.
export const rowMark = (it, opts = {}) => mark(it.what, { url: it.link_kind === "none" ? "" : it.url, thumb: it.thumb, handle: opts.handle || it.card?.handle || "", favicon: mayFavicon(it, opts) && !adultHost(it.url) });
const ROW_STATE = ["tone-flag", "tone-linked", "tone-match", "tone-different", "tone-unverified", "line-dashed", "is-checked", "is-gone"];
const rowState = (it) => { const c = rowCertainty(it); return [c.tone ? `tone-${c.tone}` : "", c.line === "dashed" ? "line-dashed" : "", c.checked ? "is-checked" : "", c.gone ? "is-gone" : ""].filter(Boolean); };
const rowClass = (it) => `${it.card ? "rich" : ""} ${rowState(it).join(" ")}`;
export const pillOf = (it) => { const c = rowCertainty(it); return c.word ? h`<span class="cp ${c.tone ? `tone-${c.tone}` : ""} ${c.line === "dashed" ? "line-dashed" : ""} ${c.checked ? "is-checked" : ""} ${c.gone ? "is-gone" : ""}">${c.word}</span>` : ""; };
// Placeholders for sources that are still out. They carry no result styling, and screen readers
// get the run log's live region instead.
export const skeletonRows = (pending) => (pending?.length ? h`<div class="sk-wrap"><p class="sk-cap">Waiting for ${pending.length === 1 ? pending[0] : `${pending.length} sources`}${pending.length > 1 ? `: ${pending.slice(0, 6).join(", ")}${pending.length > 6 ? " and more" : ""}` : ""}. Rows appear as each one answers.</p>${raw(['w60', 'w80', 'w40'].map((w) => `<div class="sk-row" aria-hidden="true"><span class="sk sq"></span><span class="sk-lines"><span class="sk ${w}"></span><span class="sk w40"></span></span><span class="sk"></span></div>`).join(""))}</div>` : "");
export const skeletonCards = (pending) => (pending || []).map((name) => h`<div class="sk-card"><span class="sk-name">${name}: waiting for an answer</span><span class="sk-lines" aria-hidden="true"><span class="sk w80"></span><span class="sk w60"></span><span class="sk w40"></span></span></div>`).join("");
// Replaces one row's text in place after its link was checked, and moves a row whose page was
// not found to the end of its group. Nothing else on the page moves.
// Focus stays with the keyboard user: if it was on this row's link it goes to the new link, or to
// the row's checkbox when the link became plain text; if it was on the checkbox it stays there
// through the move. Focus that is anywhere else is left alone.
// opts.actions: also redraw the row's buttons (a name case, after "Show profile"). Focus that was
// on one of them goes to the row's first button, or its link, or its checkbox.
export function patchRow(el, it, doc = globalThis.document, opts = {}) {
  const row = [...el.querySelectorAll(".ev[data-row]")].find((r) => r.dataset.row === it.key);
  if (!row) return false;
  const what = row.querySelector(".what"), box = row.querySelector("input[type=checkbox]");
  const src = opts.actions ? row.querySelector(".src") : null;
  const active = doc?.activeElement;
  const was = active && active === box ? "box" : active && what.contains(active) ? "link" : active && src && src.contains(active) ? "act" : "";
  what.innerHTML = evWhat(it);
  // The link check changes how the row is drawn: its edge and its pill follow (see rowCertainty).
  if (row.classList?.remove && row.querySelector) {
    row.classList.remove(...ROW_STATE); const st = rowState(it); if (st.length) row.classList.add(...st);
    const pill = row.querySelector(".ev-side > .cp"); if (pill) pill.outerHTML = pillOf(it);
  }
  if (src) {
    src.innerHTML = evSrc(it);
    const name = row.querySelector(".ev-check .sr-only");
    if (name) name.textContent = `Mark ${it.what} reviewed`;
  }
  if (it.gone && !row.classList.contains("gone")) {
    row.classList.add("gone");
    const rows = row.parentElement.querySelectorAll(":scope > .ev");
    if (rows[rows.length - 1] !== row) rows[rows.length - 1].after(row);
  }
  if (was) ((was === "act" && src.querySelector("button")) || (was !== "box" && what.querySelector("a.lk")) || box)?.focus({ preventScroll: true });
  return true;
}
// A row may carry two buttons: `action` (a pivot, with an optional target type so a handle such
// as "maria.co" is searched as a username) and `fetch` (a name case: load one GitHub profile).
// opts.check(tierId): how many of the group's links the link check could look at now. When it is
// more than none the group header carries a "Check these links" button (see linkcheck.js).
export function renderTiers(el, items, tiers, done, emptyHtml, opts = {}) {
  const byTier = Object.fromEntries(tiers.map((t) => [t.id, items.filter((i) => i.tier === t.id)]));
  const shown = tiers.filter((t) => byTier[t.id].length);
  // A group marked `aside` (similar handles) is offered beside the findings: when it is the only
  // one with rows, the page still says that nothing was found.
  const lead = shown.some((t) => !t.aside) ? "" : emptyHtml;
  el.innerHTML = shown.length ? lead + shown.map((t) => {
    const rows = byTier[t.id];
    const limit = t.limit ?? 200;
    // opts.open: which groups were open before a redraw that must not move the reader (Map of id to boolean).
    const open = opts.open?.has(t.id) ? opts.open.get(t.id) : t.collapseOver ? rows.length <= t.collapseOver : t.open;
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
            <div class="ev ${raw(rowClass(it))} ${done.has(it.key) ? "done" : ""} ${it.gone ? "gone" : ""} ${i >= PREVIEW ? "ev-extra" : ""}" data-row="${it.key}">
              <label class="ev-check"><input type="checkbox" data-key="${it.key}" ${done.has(it.key) ? "checked" : ""}><span class="sr-only">Mark ${it.what} reviewed</span></label>
              ${it.card ? raw(rowMark(it, opts)) : ""}
              <div class="what">${raw(evWhat(it))}</div>
              <div class="ev-side">${raw(pillOf(it))}<span class="src">${raw(evSrc(it))}</span></div>
            </div>`).join(""))}
          ${clip ? raw(h`<button type="button" class="btn btn-sm ev-toggle" data-show-all>Show all ${fmtNum(Math.min(rows.length, limit))}</button>`) : ""}
          ${rows.length > limit ? raw(h`<div class="ev-more">${fmtNum(rows.length - limit)} more not shown. Export for the full list.</div>`) : ""}
        </div>
      </section>`;
  }).join("") + skeletonRows(opts.pending) : emptyHtml + skeletonRows(opts.pending);
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

// Why an identity view stands where it does, in one or two sentences. Shared by "What we know"
// and the identity header, so the two can never disagree.
const noPrimaryText = (views) => { const named = views.filter((v) => v.named).length; return `${named > 1 ? `${named} different names appear under this handle, and none is tied to the target.` : "Profiles were read, and nothing ties them to the target."} There is no record for the target itself and no strong signal between profiles, so no primary identity is chosen.`; };
const viewWhy = (view, noPrimary) => (view.primary ? `Primary identity because ${view.why}.` : view.id === "unassigned" ? "Profiles that were read but carry no name, so nothing ties them to anyone." : noPrimary ? "One of the names under this handle. Nothing ties these profiles to the target." : "Not the primary identity: the name on these profiles conflicts with it, or nothing ties them to it.")
  + (view.signals.length ? ` Joined by: ${[...new Set(view.signals.map((s) => `${s.a} and ${s.b} (${s.detail})`))].slice(0, 4).join("; ")}.` : "");
const pickView = ({ views, primary, noPrimary }, pick) => views.find((v) => v.id === pick) || views.find((v) => v.id === primary) || (noPrimary ? null : views[0]) || null;

// "What we know" for a person case: the facts of one identity cluster at a time, primary first.
// A labelled select switches to another cluster's facts. `pick` is the view id to show.
export function renderIdentityFacts(el, { views, primary, noPrimary }, factsOf, pick, emptyText) {
  const view = pickView({ views, primary, noPrimary }, pick);
  const label = (v) => `${v.label}${v.primary ? " (primary)" : ""} · ${v.sites.slice(0, 3).join(", ")}${v.sites.length > 3 ? ` +${v.sites.length - 3}` : ""}`;
  const box = document.createElement("div");
  const select = (first) => h`<div class="who-pick"><label for="${el.id}Pick">Showing</label><select class="input" id="${el.id}Pick" data-cluster-pick>${raw(first)}${raw(views.map((v) => h`<option value="${v.id}" ${view && v.id === view.id ? "selected" : ""}>${label(v)}</option>`).join(""))}</select></div>`;
  // No anchor record and no strong signal: nobody is picked, and no one's facts are shown as the target's.
  const none = noPrimary ? h`<p class="who-why">${noPrimaryText(views)}</p>` : "";
  if (!view) {
    renderFacts(box, factsOf(null), "Pick a name above to see what its profiles say.");
    el.innerHTML = select(h`<option value="" selected>No primary identity</option>`) + none + box.innerHTML;
    return null;
  }
  renderFacts(box, factsOf(view.id), view.id === "unassigned" ? "These profiles carry no facts." : "No facts on these profiles.");
  el.innerHTML = (views.length > 1 || noPrimary ? select(noPrimary ? h`<option value="">No primary identity</option>` : "") : h`<p class="who-one">${label(view)}</p>`)
    + none + h`<p class="who-why">${viewWhy(view, noPrimary)}</p>` + box.innerHTML;
  return view.id;
}

// The identity cluster header of a username or email case: whose profiles these are, why that
// identity is primary (or that there is none), its member accounts, and one button per person
// who shares the handle. A button and the select in "What we know" set the same view.
export function identityHead({ views, primary, noPrimary }, pick) {
  if (!views.length) return "";
  const view = pickView({ views, primary, noPrimary }, pick);
  const pill = !view ? '<span class="cp tone-unverified line-dashed">No primary identity</span>'
    : view.primary ? '<span class="cp tone-linked">Primary identity</span>'
      : view.id === "unassigned" ? '<span class="cp tone-unverified line-dashed">No name on these profiles</span>'
        : noPrimary ? '<span class="cp tone-unverified line-dashed">Not tied to the target</span>' : '<span class="cp tone-different">Different person</span>';
  const who = view ? h`<span>${view.label}</span>` : "<span>Nobody is selected</span>";
  const members = view ? h`<div class="id-row"><span class="id-k">${plural(view.sites.length, "account")}</span>${raw(view.sites.slice(0, 12).map((x) => h`<span class="chip">${x}</span>`).join(""))}${view.sites.length > 12 ? raw(h`<span class="id-k">and ${view.sites.length - 12} more</span>`) : ""}</div>` : "";
  const people = views.length > 1 || noPrimary ? h`<div class="id-row who-switch" role="group" aria-label="People and profile groups under this handle"><span class="id-k">Show</span>${raw(views.map((v) => h`<button type="button" class="who-btn" data-cluster-btn="${v.id}" aria-pressed="${!!view && v.id === view.id}">${v.label}${v.primary ? " (primary)" : ""}<span class="sr-only">, ${plural(v.sites.length, "account")}</span></button>`).join(""))}</div>` : "";
  return mark(view ? view.label : "?", { thumb: view?.thumb || "", favicon: false, cls: "id-mark" })
    + h`<div><p class="id-name">${raw(who)}${raw(pill)}</p><p class="id-why">${view ? viewWhy(view, noPrimary) : noPrimaryText(views)}</p>${raw(members)}${raw(people)}</div>`;
}

// ---- verdict strip ----------------------------------------------------------------------------
// The tiles come from present.js (investigateTiles, reconTiles). Each is a button that opens its
// group or tab. A count of zero is quiet and not a button to anywhere; "unknown" opens By source,
// where the failure is.
export function verdictHtml(tiles) {
  return tiles.map((t) => {
    const caveat = t.caveat ? " caveat" : "";
    const jump = t.state === "zero" ? "disabled" : t.state === "unknown" || t.state === "off" || t.jump?.tab ? h`data-jump-tab="${t.jump?.tab || "sources"}"` : t.jump?.tier ? h`data-jump-tier="${t.jump.tier}"` : "disabled";
    return h`<button type="button" class="vt state-${t.state} ${t.tone ? `tone-${t.tone}` : ""} ${t.line === "dashed" ? "line-dashed" : ""}" ${raw(jump)}><span class="vt-n">${t.atLeast ? raw('<span class="sr-only">at least </span>') : ""}${typeof t.value === "number" ? fmtNum(t.value) : t.value}${t.atLeast ? raw('<span aria-hidden="true">+</span>') : ""}</span><span class="vt-l">${t.label}</span>${t.sub ? raw(h`<span class="vt-s${caveat}">${t.sub}</span>`) : ""}</button>`;
  }).join("");
}
export function renderVerdict(el, tiles) {
  el.className = `verdict-strip n${tiles.length}`;
  el.innerHTML = verdictHtml(tiles);
}
// One listener per strip. setTab(name) switches the result tabs; ledger is the findings element.
export function bindVerdict(el, { ledger, setTab, tabEl }) {
  el.addEventListener("click", (e) => {
    const b = e.target.closest(".vt"); if (!b || b.disabled) return;
    if (b.dataset.jumpTab) { setTab(b.dataset.jumpTab); const t = tabEl(b.dataset.jumpTab); t?.scrollIntoView({ block: "start" }); t?.focus({ preventScroll: true }); return; }
    setTab("findings");
    const sec = [...ledger.querySelectorAll(".tier")].find((x) => x.dataset.tier === b.dataset.jumpTier);
    const head = sec?.querySelector(".tier-head");
    if (!head) return;
    if (sec.classList.contains("collapsed")) head.click();
    sec.scrollIntoView({ block: "start" });
    head.focus({ preventScroll: true });
  });
}

// "What we know" for a name case: nobody is selected, so there are no facts to show.
export function renderNameKnown(el, { lead, lines }) {
  el.innerHTML = h`<p class="who-one">${lead}</p>${raw(lines.map((l) => h`<p class="who-why">${l}</p>`).join(""))}`;
}
// The notices above a name case: [{ level: "note" | "err", title?, text }].
export const nameNoticesHtml = (notices) => notices.map((n) => h`<div class="notice ${n.level === "err" ? "err" : ""}" role="note">${n.title ? raw(h`<strong>${n.title}</strong>`) : ""}<span>${n.text}</span></div>`).join("");

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

// What the HTML export removes from the page's markup. No image with a remote address survives:
// site icons go, and so would any other image that is not an embedded thumbnail.
export const EXPORT_STRIP = '[hidden], .btn, .ev-check, .runlog, .sr-only, [role=status], .lg-detail, .ai-pitch, .ai-cost, .lk-status, input, textarea, .tabs, .sk-wrap, .sk-card, .who-switch, .case-details, .mark img.mark-fav, img:not([src^="data:image/"])';

// ---- print / standalone HTML export --------------------------------------------------
// The same markup as the screen, with every collapsed section opened, wrapped in a page
// that carries its own stylesheet. Nothing is uploaded: the file is built in the browser.
export async function standaloneHtml(title, mainEl, asideEl) {
  const cssUrl = document.querySelector('link[rel="stylesheet"]').href;
  let css = "";
  try { css = await (await fetch(cssUrl)).text(); } catch { /* unstyled is still readable */ }
  css = css.replace(/@font-face\s*{[^}]*}/g, "");   // fonts are not embedded; system fonts take over
  const clone = (el) => { const c = el.cloneNode(true); c.querySelectorAll(".panel").forEach((x) => (x.hidden = false)); c.querySelectorAll(EXPORT_STRIP).forEach((x) => x.remove()); c.querySelectorAll(".collapsed, .clipped").forEach((x) => x.classList.remove("collapsed", "clipped")); c.querySelectorAll("details").forEach((d) => (d.open = true));
    // Adult and dating site rows go after every other finding, under a heading that says what they are.
    c.querySelectorAll('.tier[data-tier="adult"]').forEach((t) => { const title = t.querySelector(".tier-title"); if (title) title.textContent = ADULT_SECTION; t.parentElement?.append(t); });
    return c.innerHTML; };
  return `<!DOCTYPE html><html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>${css}\nbody{padding:24px;max-width:1000px;margin:0 auto}.print-only{display:block !important}.tier[data-tier="adult"] .tier-title::after{content:none !important}.export-meta{color:var(--ink-3);font-size:13px;margin:0 0 20px}.ev{grid-template-columns:minmax(0,1fr) auto}.ev.rich{grid-template-columns:32px minmax(0,1fr) auto}.mark img{opacity:1}</style></head><body><p class="export-meta">Exported from CrawlR on ${esc(new Date().toLocaleString())}. Findings come from third-party public sources and can be wrong. "Unverified" items are leads, not facts, and a profile that exists is not proof of who owns it.</p><main class="main">${clone(mainEl)}</main>${asideEl ? `<aside class="aside">${clone(asideEl)}</aside>` : ""}</body></html>`;
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
