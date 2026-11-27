// Pieces shared by every workbench mode: run log, tiered ledger, facts panel, run diff.
import { $$, h, raw, esc, link, linkOf, mark, store, fmtNum, fmtAgo, plural, roving } from "./core.js";
import { trailFromFile } from "./casework.js";
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
    const dashed = pill.dashed ? "line-dashed" : "";
    const who = `${p.site} ${s.variant}`;
    return h`<li class="${["sim-card", pill.tone ? `tone-${pill.tone}` : "", dashed].filter(Boolean).join(" ")}">
      ${raw(mark(p.site, { thumb: p.thumb, favicon: false }))}
      <div class="sim-main">
        <span class="ev-title">${raw(link(p.url, p.site, "", { kind: p.link_kind || "verified_profile" }))}<span class="ev-handle">${s.variant}</span></span>
        ${p.facts?.length ? raw(`<span class="ev-line">${p.facts.map((f) => h`<span class="ev-fact">${f}</span>`).join("")}</span>`) : ""}
        ${p.bio ? raw(h`<span class="ev-bio">${p.bio}</span>`) : ""}
        <span class="ev-why"><span>${p.lineup.text}${/[.!?]$/.test(p.lineup.text) ? "" : "."}${p.lineup.outcome === "name" ? " A name alone is supporting, not proof." : ""}${p.lineup.outcome === "name_weak" || p.lineup.outcome === "name_built" || p.lineup.outcome === "conflict" || p.lineup.outcome === "nothing" ? " Use Investigate this to look at the handle as a case of its own." : ""}${p.note === "suspended" ? " The site marks this account as suspended." : ""}</span></span>
      </div>
      <div class="sim-side">${pill.word ? raw(h`<span class="${["cp", pill.tone ? `tone-${pill.tone}` : "", dashed].filter(Boolean).join(" ")}">${pill.word}</span>`) : ""}${p.added ? raw(h`<span class="tag ok">Added</span><button type="button" class="btn btn-sm" data-sim-remove="${p.id}" data-variant="${s.variant}">Remove from this case<span class="sr-only">: ${who}</span></button>`)
        : p.lineup.canAdd ? raw(h`<button type="button" class="btn btn-sm" data-sim-add="${p.id}" data-variant="${s.variant}">Add to this case<span class="sr-only">: ${who}</span></button>`) : ""}</div>
    </li>`;
  }).join("");
  const states = s.sources.map((g) => h`<span class="sim-state"><b>${g.word}</b> ${g.sites.join(", ")}</span>`).join("");
  return head + h`<div class="sim-res"><p class="sim-sum">${s.summary}</p>${cards ? raw(h`<ul class="sim-cards" aria-label="Profiles read for the handle ${s.variant}">${raw(cards)}</ul>`) : ""}${states ? raw(`<p class="sim-states">${states}</p>`) : ""}</div>`;
}
// Archived copies of a read profile, once the investigator asked (archiveView in deep.js). The
// sentence says what the archive answered; each snapshot is a link opened by hand, and an
// archive that could not be asked is said to be unknown, never "no copies".
export function archHtml(it) {
  const v = it?.archive?.view;
  if (!v) return "";
  return h`<div class="ev-arch ${v.state === "ok" || v.state === "none" ? "" : "unknown"}"><b>Archived copies</b><span>${v.text}</span>${v.snapshots.length ? raw(h`<span class="ev-snaps"><span class="sr-only">Snapshots: </span>${raw(v.snapshots.map((x) => link(x.url, x.label, "ev-link", { kind: x.link_kind })).join(""))}</span>`) : ""}${raw(diffHtml(it))}</div>`;
}
// ---- two archived copies, compared on a click -------------------------------------------------
// Inside the Archived copies inset of a row whose archive listed two or more captures
// (row.archiveDiffPairs): two labelled selects, one button, and under them the last answer
// (archiveDiffView in deep.js). Removed and added are told apart by a word and a mark (a minus,
// a plus), never by color. A line of text from a capture is plain escaped text; a link goes
// through link() as an unverified URL, and an address the link rules do not pass is text.
// The captures a row can compare, oldest first: every time a pair names.
export const diffCaptures = (pairs) => [...new Set((pairs || []).flatMap((p) => [p.from, p.to]))].filter(Boolean).sort();
const capWord = (t, all) => (all.filter((x) => x.slice(0, 10) === t.slice(0, 10)).length > 1 ? `${t.slice(0, 10)} ${t.slice(11, 16)} UTC` : t.slice(0, 10));
// The pair the selects show: the one the investigator chose (it.diffPick), else the default pair.
export function diffChoice(it) {
  const pairs = it?.archiveDiffPairs || [], caps = diffCaptures(pairs), def = pairs.find((x) => x.default) || pairs[0] || { from: "", to: "" };
  const p = it?.diffPick;
  return p && caps.includes(p.from) && caps.includes(p.to) ? { from: p.from, to: p.to } : { from: def.from, to: def.to };
}
// What the line under the selects says about a chosen pair: { text, ok, warn }.
// ok: the pair can be sent. warn: the captures are not neighbours, so the answer will be noisier.
export const DIFF_HINT = "Neighbouring captures give the cleanest answer. One comparison per click: two requests to the Internet Archive, which can take a few seconds.";
export const DIFF_SAME = "Pick two different captures: these are the same one.";
export const DIFF_DISTANT = "These two captures are not neighbours. A site changes its layout over time, so the answer will also list differences that are not edits to the profile.";
export function diffHint(caps, from, to) {
  if (!from || !to || from === to) return { text: DIFF_SAME, ok: false, warn: true };
  const far = Math.abs(caps.indexOf(from) - caps.indexOf(to)) > 1;
  return { text: far ? DIFF_DISTANT : "", ok: true, warn: far };
}
const DIFF_SIDES = [["removed", "Removed", "−", "in the older capture, not in the newer"], ["added", "Added", "+", "in the newer capture, not in the older"]];
function diffPart(v, [k, word, sign, where]) {
  const d = v[k], rows = [
    ...d.text.map((t) => h`<li><span class="diff-mark" aria-hidden="true">${sign}</span><span class="sr-only">${word}: </span><span class="diff-text">${t}</span></li>`),
    ...d.links.map((l) => h`<li><span class="diff-mark" aria-hidden="true">${sign}</span><span class="sr-only">${word}: </span><span class="ed-prov">${l.link_kind === "none" ? "address" : "link"}</span>${raw(link(l.url, l.label, "", { kind: l.link_kind }))}</li>`)];
  return h`<div class="diff-part"><p class="diff-h"><span class="diff-mark" aria-hidden="true">${sign}</span><b>${word}</b><span class="diff-where">${where}</span></p>${rows.length ? raw(`<ul class="diff-list" aria-label="${word}">${rows.join("")}</ul>`) : raw(h`<p class="diff-none">Nothing ${word.toLowerCase()}.</p>`)}${d.more ? raw(h`<p class="diff-more">${d.more}</p>`) : ""}</div>`;
}
export function diffHtml(it) {
  const pairs = it?.archiveDiffPairs;
  if (!pairs?.length) return "";
  const caps = diffCaptures(pairs), pick = diffChoice(it), hint = diffHint(caps, pick.from, pick.to), v = it.archiveDiff, busy = !!it.diffBusy;
  const options = (sel) => caps.map((t) => h`<option value="${t}" ${t === sel ? raw("selected") : ""}>${capWord(t, caps)}</option>`).join("");
  const form = h`<div class="ev-diff" role="group" aria-label="Compare two captures of the ${it.what} profile" data-diff="${it.key}">
      <b class="diff-k">Compare two captures</b>
      <label class="diff-f"><span>Older capture</span><select class="input" data-diff-pick="from">${raw(options(pick.from))}</select></label>
      <label class="diff-f"><span>Newer capture</span><select class="input" data-diff-pick="to">${raw(options(pick.to))}</select></label>
      <button type="button" class="btn btn-sm" data-archive-diff="${it.key}" ${busy || !hint.ok ? raw('aria-disabled="true"') : ""}>${busy ? "Comparing…" : v?.retry ? "Try again" : "Compare"}<span class="sr-only">: two archived copies of the ${it.what} profile</span></button>
      <span class="diff-hint">${DIFF_HINT}</span>
      <span class="diff-warn" data-diff-warn role="status">${hint.text}</span>
    </div>`;
  if (!v) return form;
  const side = (s, word) => (s ? h`<span class="diff-cap"><span class="diff-capk">${word}</span>${raw(link(s.url, s.label || "capture", "ev-link", { kind: s.link_kind }))}${s.note ? raw(h`<span class="diff-capn">${s.note}</span>`) : ""}</span>` : "");
  const res = h`<div class="ev-diffres ${v.retry ? "unknown" : ""}" data-diff-result tabindex="-1">
      <p class="diff-sum"><b>What changed</b><span>${v.text}</span></p>
      ${v.from || v.to ? raw(h`<p class="diff-caps">${raw(side(v.from, "Older"))}${raw(side(v.to, "Newer"))}</p>`) : ""}
      ${v.state === "ok" ? raw(DIFF_SIDES.map((x) => diffPart(v, x)).join("")) : ""}
      ${v.caveats.length ? raw(h`<details class="diff-cav"><summary>How to read a comparison</summary><ul>${raw(v.caveats.map((c) => h`<li>${c}</li>`).join(""))}</ul></details>`) : ""}
    </div>`;
  return form + res;
}
// ---- commit emails of one forge account, read on a click ------------------------------------------
// commitEmailsView in deep.js. Each address is mono text (never a link), with how it is tied to
// the account as an outlined label and in words, the name written in the commits marked
// self-declared, how many commits carried it, the first and last date the commits state, and the
// repositories as evidence links. Unknown has a dashed rule and "Try again"; it is never "none".
export function commitHtml(it) {
  const v = it?.commitEmails;
  if (!v) return "";
  const known = v.state === "found" || v.state === "none" || v.state === "not_found" || v.state === "not_asked";
  const again = v.retry && it.canCommitEmails ? h`<button type="button" class="btn btn-sm" data-commit-emails="${it.key}" ${it.commitBusy ? raw('aria-disabled="true"') : ""}>${it.commitBusy ? "Asking…" : "Try again"}<span class="sr-only">: commit emails of ${it.what}</span></button>` : "";
  const row = (e) => h`<li class="ce-row">
      <span class="ce-main"><span class="ce-addr">${e.email}</span><span class="ed-prov">${e.strong ? "tied by the site" : "author line only"}</span></span>
      <span class="ce-how">${e.howText}</span>
      <span class="ce-meta">${e.name ? raw(h`<span>Name in the commits: <b>${e.name}</b> <span class="ed-prov">self-declared</span></span>`) : ""}<span>${plural(e.commits, "commit")} read</span>${e.first || e.last ? raw(h`<span>${e.first && e.last && e.first !== e.last ? `first ${e.first}, last ${e.last}` : `dated ${e.first || e.last}`} <span class="ed-prov">self-declared dates</span></span>`) : ""}</span>
      ${e.repos.length ? raw(h`<span class="ce-repos"><span class="ce-k">Seen in</span>${raw(e.repos.map((r) => link(r.url, r.name, "ev-link", { kind: r.link_kind })).join(""))}</span>`) : ""}
    </li>`;
  return h`<div class="ev-arch ev-ce ${known ? "" : "unknown"}" data-look="commit" tabindex="-1"><b>Commit emails</b>${v.partial ? raw('<span class="tag warn">partial</span>') : ""}<span>${v.text}</span>${raw(again)}${v.rows.length ? raw(h`<ul class="ce-list" aria-label="Addresses on the commits of the ${it.what} account">${raw(v.rows.map(row).join(""))}</ul><p class="ce-note">${v.note}</p>`) : ""}</div>`;
}
// ---- when one account posts, read on a click ------------------------------------------------------
// One line on the row (postActivityView in deep.js) and a control that opens the Timeline tab at
// the reading, where the hours are drawn. A site that could not be asked is unknown: dashed rule,
// "Try again", never "no posts".
export function postHtml(it) {
  const v = it?.postActivity;
  if (!v) return "";
  const again = v.retry && it.canPostActivity ? h`<button type="button" class="btn btn-sm" data-post-activity="${it.key}" ${it.postBusy ? raw('aria-disabled="true"') : ""}>${it.postBusy ? "Asking…" : "Try again"}<span class="sr-only">: post activity of ${it.what}</span></button>` : "";
  const open = v.state === "ok" || v.state === "none" ? h`<button type="button" class="btn btn-sm" data-open-reading="${it.key}">Show on the Timeline<span class="sr-only">: post activity of ${it.what}</span></button>` : "";
  const est = v.state === "ok" ? (v.estimate ? ` UTC offset estimate ${v.estimate.label}: a hint, not a fact, and never a place.` : " No UTC offset estimate was made.") : "";
  return h`<div class="ev-arch ev-pa ${v.retry ? "unknown" : ""}" data-look="post" tabindex="-1"><b>Post activity</b><span>${v.text}${est}</span>${raw(again)}${raw(open)}</div>`;
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
  const hint = (it.hint ? h`<span class="ev-hint"><b>How to check</b> ${it.hint}</span>` : "") + archHtml(it) + commitHtml(it) + postHtml(it);
  // An evidence card: the title line, then only what a source read (facts, a bio excerpt), or a
  // plain statement of what kind of check found the row, then why it sits in this group.
  if (it.card) {
    const c = it.card;
    return `<span class="ev-title">${head}</span>`
      + (c.facts?.length ? `<span class="ev-line">${c.facts.map((f) => h`<span class="ev-fact">${f}</span>`).join("")}</span>` : "")
      + (c.bio ? h`<span class="ev-bio">${c.bio}</span>` : "")
      + (c.basis || c.note || c.why ? `<span class="ev-why">${c.why ? h`<span><b>Why here</b>${c.why}</span>` : ""}${c.basis ? h`<span>${c.basis}</span>` : ""}${c.note ? h`<span>${c.note}</span>` : ""}</span>` : "")
      // Another person's account, or a name that could not be compared: the row stays, and asks.
      + (c.check ? h`<span class="ev-relate"><span class="tag warn">Check</span><span>${c.check}</span></span>` : "")
      + hint;
  }
  return `<span class="ev-title">${head}${it.meta ? h`<span class="meta">${it.meta}</span>` : ""}</span>` + hint;
}
// What a record carries beyond the card's one line, behind a disclosure on the row: every value a
// source read, grouped by how it is known (written by the account holder, or the site's own
// record; see profileDetail in deep.js). Closed by default, so a row stays one card.
// A value is escaped text; a link is evidence and goes through link() with its kind.
export function evDetail(it, open = false) {
  const d = it?.detail;
  if (!d?.groups?.length) return "";
  const row = (r) => h`<div class="ed-row"><dt>${r.k}</dt><dd>${raw(linkOf(r, r.v))}${r.how ? raw(h`<span class="ed-how">${r.how}</span>`) : ""}${r.more?.url ? raw(` ${link(r.more.url, r.more.label, "ev-link", { kind: "evidence" })}`) : ""}</dd></div>`;
  return h`<details class="ev-more" ${open ? raw("open") : ""}><summary>${it.pgp ? "Key details" : it.emailAccount || it.key === "commits:unattributed" ? "What GitHub and the commits say" : "What was read"}<span class="ev-more-n">${plural(d.count, "value")}</span></summary>${raw(d.groups.map((g) => h`<div class="ed-g"><p class="ed-h">${g.title}<span class="ed-prov">${g.prov}</span></p><dl class="ed">${raw(g.rows.map(row).join(""))}</dl></div>`).join(""))}</details>`;
}
// The right side of a row: its buttons, then its sources as chips. The profile button's name is
// its visible text plus the login for screen readers, so the text can change to "Loading…" and be heard.
// A similar handle has "Check" until it was checked ("Try again" after a failed check). A profile
// that was added from one has "Remove from this case" on its row in the ledger.
// While a handle is being checked (it.sim.busy) the button says so and is aria-disabled, in every redraw.
const simAct = (it) => (it.sim && it.sim.state !== "checked" ? h`<button type="button" class="btn btn-sm ev-act" data-sim-check="${it.sim.variant}" ${it.sim.busy ? raw('aria-disabled="true"') : ""}>${it.sim.busy ? "Checking…" : it.sim.state === "failed" ? "Try again" : it.sim.state === "file" ? "Check here" : "Check"}<span class="sr-only">: ${it.sim.variant}</span></button>` : "")
  + (it.similar ? h`<button type="button" class="btn btn-sm ev-act" data-sim-remove="${it.key}" data-variant="${it.similar.variant}">Remove from this case<span class="sr-only">: ${it.what} ${it.similar.variant}</span></button>` : "");
// "Archived copies" on a read profile: one lookup, on a click. Once the archive answered, the
// answer is on the row and the button is gone; an archive that could not be asked can be asked again.
const archAct = (it) => (it.archive && (!it.archive.view || it.archive.view.retry) ? h`<button type="button" class="btn btn-sm ev-act" data-archive="${it.key}" ${it.archive.busy ? raw('aria-disabled="true"') : ""}>${it.archive.busy ? "Asking…" : it.archive.view ? "Try again" : "Archived copies"}<span class="sr-only">: ${it.archive.view ? "archived copies of " : ""}${it.what}</span></button>` : "");
// "Commit emails" and "Post activity" on a read profile the lookup can be asked for: one request,
// on a click. Once the site answered, the answer is on the row and the button is gone; "Try again"
// for an answer that is unknown sits in the answer itself.
const lookBtn = (it, attr, label, busy) => h`<button type="button" class="btn btn-sm ev-act" ${raw(attr)}="${it.key}" ${busy ? raw('aria-disabled="true"') : ""}>${busy ? "Asking…" : label}<span class="sr-only">: ${it.what}</span></button>`;
const lookAct = (it) => (it.canCommitEmails && !it.commitEmails ? lookBtn(it, "data-commit-emails", "Commit emails", it.commitBusy) : "") + (it.canPostActivity && !it.postActivity ? lookBtn(it, "data-post-activity", "Post activity", it.postBusy) : "");
// A lead can be parked ("not now"): it stays listed, marked, and is not suggested again.
const stepAct = (it) => (it.tier === "lead" && it.action ? (it.step ? h`<span class="tag">${it.step}</span>` : "") + (it.step === "followed" ? "" : h`<button type="button" class="btn btn-sm btn-ghost ev-act" data-step-${it.step === "parked" ? "back" : "park"}="${it.key}" data-step-title="${it.action.label === "Open in Recon" ? `Open ${it.action.value} in Recon` : `Investigate ${it.action.value}`}">${it.step === "parked" ? "Bring back" : "Not now"}<span class="sr-only">: ${it.action.value}</span></button>`) : "");
const viaAttrs = (a, id) => raw([a.type ? h`data-pivot-type="${a.type}"` : "", a.via ? h`data-via="${a.via}"` : "", a.source ? h`data-via-source="${a.source}"` : "", id ? h`data-step="${id}"` : ""].filter(Boolean).join(" "));
export const evSrc = (it) => simAct(it) + archAct(it) + lookAct(it) + (it.fetch ? h`<button type="button" class="btn btn-sm ev-act" data-name-profile="${it.fetch.login}">${it.fetch.label}<span class="sr-only">: ${it.fetch.login}</span></button>` : "")
  + (it.action ? h`<button type="button" class="btn btn-sm ev-act" data-pivot="${it.action.pivot}" data-value="${it.action.value}" ${viaAttrs(it.action, it.tier === "lead" ? it.key : "")} data-confirm-run="1" aria-label="${it.action.label}: ${it.action.value}">${it.action.label}</button>` : "")
  + stepAct(it)
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
  what.innerHTML = evWhat(it) + evDetail(it, !!what.querySelector?.("details.ev-more[open]"));
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
  // A redraw keeps every opened "What was read" open: the reader is in the middle of it.
  const wasOpen = new Set([...(el.querySelectorAll?.(".ev details.ev-more[open]") || [])].map((d) => d.closest(".ev")?.dataset.row));
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
          <span class="tier-rail" aria-hidden="true"></span><span class="tier-title">${t.title}</span><span class="count">${t.count ?? fmtNum(rows.length)}</span><span class="chev" aria-hidden="true">▾</span>
        </button>${((nCheck) => (nCheck > 0 ? raw(h`<button type="button" class="btn btn-sm tier-check" data-check-tier="${t.id}" data-count="${nCheck}">Check these links (${fmtNum(nCheck)})</button>`) : ""))(opts.check ? Number(opts.check(t.id)) || 0 : 0)}</h2>
        <div class="tier-body" id="${bodyId}">
          <div class="tier-blurb">${t.blurb}</div>
          ${t.note ? raw(h`<div class="tier-blurb">${t.note}</div>`) : ""}
          ${raw(rows.slice(0, limit).map((it, i) => h`
            <div class="ev ${raw(rowClass(it))} ${done.has(it.key) ? "done" : ""} ${it.gone ? "gone" : ""} ${i >= PREVIEW ? "ev-extra" : ""}" data-row="${it.key}" ${it.sim?.busy ? raw('aria-busy="true"') : ""}>
              <label class="ev-check"><input type="checkbox" data-key="${it.key}" ${done.has(it.key) ? "checked" : ""}><span class="sr-only">Mark ${it.what} reviewed</span></label>
              ${it.card ? raw(rowMark(it, opts)) : ""}
              <div class="what">${raw(evWhat(it) + evDetail(it, wasOpen.has(it.key)))}</div>
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

// The facts of profiles the investigator added from a similar handle. They are shown apart, under
// their own heading at the end of "What we know", and each names the site and the handle it came
// from: an added profile is a row of the case, never part of an identity.
export const ADDED_FACTS = "From profiles you added (under a different handle)";
export function addedFactsHtml(added) {
  const facts = (added || []).flatMap((a) => a.facts);
  if (!facts.length) return "";
  const box = { innerHTML: "" };
  renderFacts(box, facts);
  return h`<h3 class="who-added">${ADDED_FACTS}</h3>` + box.innerHTML;
}

// ---- facts panel -------------------------------------------------------------------
export function renderFacts(el, facts, emptyText = "No facts extracted yet.") {
  el.innerHTML = facts.length
    ? `<dl class="facts-list">${facts.map((f) => h`<div class="fact"><dt class="k">${f.k}</dt><dd class="v">${raw(linkOf(f, f.v))}<span class="src">${f.source}</span>${f.how ? raw(h`<span class="how"><span class="ed-prov">${f.how.prov}</span>${f.how.text}</span>`) : ""}</dd></div>`).join("")}</dl>`
    : h`<p class="empty flat">${emptyText}</p>`;
}

// Why an identity view stands where it does, in one or two sentences. Shared by "What we know"
// and the identity header, so the two can never disagree. A picked identity is said to be the
// investigator's judgment, with what the rules would have chosen beside it.
const noPrimaryText = (views) => { const named = views.filter((v) => v.named).length; return `${named > 1 ? `${named} different names appear under this handle, and none is tied to the target.` : "Profiles were read, and nothing ties them to the target."} There is no record for the target itself and no strong signal between profiles, so no primary identity is chosen.`; };
export const pickText = (id) => `${id.pickFile ? "The case file you opened picked this person as the one the case is about. That is its author's judgment, not a finding." : "You picked this person as the one this case is about. That is your judgment, not a finding."} Every row is filed against this identity. ${id.autoLabel ? `The automatic choice would be ${id.autoLabel}, because ${id.autoWhy}.` : "Automatically nobody would be chosen: there is no record for the target itself and no strong signal between profiles."}`;
const viewWhy = (view, id) => (view.primary ? (view.picked ? pickText(id) : `Primary identity, chosen automatically because ${view.why}.`) : view.id === "unassigned" ? "Profiles that were read but carry no name, so nothing ties them to anyone." : id.noPrimary ? "One of the names under this handle. Nothing ties these profiles to the target." : "Not the primary identity: the name on these profiles conflicts with it, or nothing ties them to it.")
  + (view.signals.length ? ` Joined by: ${[...new Set(view.signals.map((s) => `${s.a} and ${s.b} (${s.detail})`))].slice(0, 4).join("; ")}.` : "");
const pickView = ({ views, primary, noPrimary }, pick) => views.find((v) => v.id === pick) || views.find((v) => v.id === primary) || (noPrimary ? null : views[0]) || null;

// "What we know" for a person case: the facts of one identity cluster at a time, primary first.
// A labelled select switches to another cluster's facts. `pick` is the view id to show. The select
// only changes what this panel shows: who the case is about is picked in the identity header.
export function renderIdentityFacts(el, id, factsOf, pick, emptyText) {
  const { views, noPrimary } = id;
  const view = pickView(id, pick);
  const label = (v) => `${v.label}${v.primary ? (v.picked ? (id.pickFile ? " (picked in the case file)" : " (your pick)") : " (primary)") : ""} · ${v.sites.slice(0, 3).join(", ")}${v.sites.length > 3 ? ` +${v.sites.length - 3}` : ""}`;
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
  // A pick is explained in the identity header and in the assessment's headline. This panel
  // names it in one short line and does not say the whole statement a third time.
  const why = view.primary && view.picked ? `${id.pickFile ? "Picked in the case file" : "Your pick"}: every row is filed against this identity. The header above says what the automatic choice would be.` : viewWhy(view, id);
  el.innerHTML = (views.length > 1 || noPrimary ? select(noPrimary ? h`<option value="">No primary identity</option>` : "") : h`<p class="who-one">${label(view)}</p>`)
    + none + h`<p class="who-why">${why}</p>` + box.innerHTML;
  return view.id;
}

// The identity cluster header of a username or email case: whose profiles these are, why that
// identity is primary (chosen automatically, picked by the investigator, or nobody), its member
// accounts, and one button per person who shares the handle.
// A button PICKS the person the case is about: the whole case is filed again around them (see
// rule 9 in identity.js), and one click goes back to the automatic choice. Each is a button with
// a pressed state. The group of profiles with no name is not a person and has no button; it can
// be shown with the select in "What we know", which changes that panel only.
export function identityHead(id, pick) {
  const { views, noPrimary } = id;
  if (!views.length) return "";
  const view = pickView(id, pick);
  const pill = !view ? '<span class="cp tone-unverified line-dashed">No primary identity</span>'
    : view.primary ? (view.picked ? (id.pickFile ? '<span class="cp">Picked in the case file</span>' : '<span class="cp">Your pick</span>') : '<span class="cp tone-linked">Primary identity</span>')
      : view.id === "unassigned" ? '<span class="cp tone-unverified line-dashed">No name on these profiles</span>'
        : noPrimary ? '<span class="cp tone-unverified line-dashed">Not tied to the target</span>' : '<span class="cp tone-different">Different person</span>';
  const who = view ? h`<span>${view.label}</span>` : "<span>Nobody is selected</span>";
  const members = view ? h`<div class="id-row"><span class="id-k">${plural(view.sites.length, "account")}</span>${raw(view.sites.slice(0, 12).map((x) => h`<span class="chip">${x}</span>`).join(""))}${view.sites.length > 12 ? raw(h`<span class="id-k">and ${view.sites.length - 12} more</span>`) : ""}</div>` : "";
  const can = views.filter((v) => v.pickable);
  const people = can.length > 1 || noPrimary || id.picked ? h`<div class="id-row who-switch" role="group" aria-label="The person this case is about">
      <span class="id-k">This case is about</span>${raw(can.map((v) => h`<button type="button" class="who-btn" data-pick="${v.id}" aria-pressed="${v.primary}">${v.label}${v.auto ? raw('<span class="who-tag">automatic choice</span>') : ""}<span class="sr-only">, ${plural(v.sites.length, "account")}</span></button>`).join(""))}
      ${id.picked ? raw(h`<button type="button" class="btn btn-sm btn-ghost who-auto" data-pick-auto>${id.autoLabel ? "Back to the automatic choice" : id.pickFile ? "Clear the pick" : "Clear my pick"}</button>`) : ""}
      <span class="who-hint">${id.picked ? "" : noPrimary ? "Pick a name to file the case around that person." : "Pick another name to file the whole case around that person. Nothing is removed."}</span>
    </div>` : "";
  return mark(view ? view.label : "?", { thumb: view?.thumb || "", favicon: false, cls: "id-mark" })
    + h`<div><p class="id-name">${raw(who)}${raw(pill)}</p><p class="id-why">${view ? viewWhy(view, id) : noPrimaryText(views)}</p>${raw(members)}${raw(people)}</div>`;
}

// ---- how the case was reached ---------------------------------------------------------------------
// The pivot trail: the earlier cases, seed first, then the case on screen (trailView in
// casework.js). An earlier case that is still in History is a button that opens it.
// has(id): is that case still in History?
export function trailHtml(view, has = () => false) {
  if (!view.length) return "";
  // A trail that came with a case file is its author's: it is never worded as "you".
  return h`<span class="trail-k">${trailFromFile(view) ? "How this case was reached, according to the case file" : "How you got here"}</span><ol class="trail-list">${raw(view.map((s) => (s.here
    ? h`<li aria-current="step"><span class="trail-t">${s.target}</span><span class="trail-via">this case</span></li>`
    : h`<li>${s.id && has(s.id) ? raw(h`<button type="button" class="trail-step" data-open-case="${s.id}">${s.target}<span class="sr-only">, ${s.type_word}: open this earlier case</span></button>`) : raw(h`<span class="trail-t">${s.target}</span>`)}<span class="trail-via">${s.type_word}${s.via ? `, then ${s.via}` : ""}</span></li>`)).join(""))}</ol>`;
}

// ---- what the evidence says, and what to do next --------------------------------------------------
// Both come from analysis.js. Rules only: no model wrote any of it.
const STRENGTH_TAG = { strong: "ok", moderate: "", thin: "warn", none: "warn" };
export function renderAnalysis(section, body, a) {
  const show = !!a?.headline;
  section.hidden = !show;
  if (!show) { body.innerHTML = ""; return; }
  const word = a.headline.split(". ")[0], rest = a.headline.slice(word.length + 2);
  body.innerHTML = h`<p class="an-head"><span class="an-k">How firmly the accounts are tied to one identity</span><span class="tag ${STRENGTH_TAG[a.strength] || ""}">${word}</span><span>${rest}</span></p>`
    + `<ul class="brief-list">${a.lines.map((r) => h`<li class="${r.level}"><span class="tag ${r.level === "flag" ? "warn" : r.level === "ok" ? "ok" : ""}">${BRIEF_WORD[r.level] || "Note"}</span><span>${r.text}</span></li>`).join("")}</ul>`;
}
// One suggestion: what to do, why, the one control that does it, and "Not now".
// busy: the ids of archive lookups in flight, so their buttons say so in every redraw.
// look: the other lookups in flight, as "commit:<row>", "post:<row>" and "diff:<row>".
function nextAct(x, busy, look = new Set()) {
  const a = x.action;
  if (!a) return "";
  const ask = (attr, id, extra = "") => h`<button type="button" class="btn btn-sm" ${raw(attr)}="${a.key}" ${raw(extra)} ${look.has(`${id}:${a.key}`) ? raw('aria-disabled="true"') : ""}>${look.has(`${id}:${a.key}`) ? (id === "diff" ? "Comparing…" : "Asking…") : a.label}<span class="sr-only">: ${x.title}</span></button>`;
  if (a.kind === "commit-emails") return ask("data-commit-emails", "commit");
  if (a.kind === "post-activity") return ask("data-post-activity", "post");
  if (a.kind === "archive-diff") return ask("data-archive-diff", "diff", h`data-from="${a.from}" data-to="${a.to}"`);
  if (a.kind === "pivot") return h`<button type="button" class="btn btn-sm" data-pivot="${a.pivot}" data-value="${a.value}" ${viaAttrs(a, x.id)} data-confirm-run="1">${a.label}<span class="sr-only">: ${a.value}</span></button>`;
  if (a.kind === "archive") return h`<button type="button" class="btn btn-sm" data-archive="${a.key}" ${busy.has(a.key) ? raw('aria-disabled="true"') : ""}>${busy.has(a.key) ? "Asking…" : a.label}<span class="sr-only">: ${x.title}</span></button>`;
  if (a.kind === "open") return link(a.url, a.label, "btn btn-sm", { kind: a.link_kind });
  if (a.kind === "copy") return h`<button type="button" class="btn btn-sm" data-next-copy="${a.text}">${a.label}</button>`;
  if (a.kind === "jump") return h`<button type="button" class="btn btn-sm" data-next-jump="${a.tier}">${a.label}</button>`;
  if (a.kind === "focus") return h`<button type="button" class="btn btn-sm" data-next-focus="${a.where}">${a.label}</button>`;
  if (a.kind === "rerun") return h`<button type="button" class="btn btn-sm" data-next-rerun>${a.label}</button>`;
  return "";
}
const nextItem = (x, busy, look) => h`<li class="next" data-next="${x.id}"><div class="next-main"><span class="next-t">${x.title}${x.tag ? raw(h`<span class="tag">${x.tag}</span>`) : ""}</span><span class="next-r">${x.reason}${x.action?.kind === "copy" ? raw(h` <code class="next-q">${x.action.text}</code>`) : ""}</span></div><div class="next-act">${raw(nextAct(x, busy, look))}<button type="button" class="btn btn-sm btn-ghost" data-step-park="${x.id}" data-step-title="${x.title}">Not now<span class="sr-only">: ${x.title}</span></button></div></li>`;
export function renderNext(section, body, s, { busy = new Set(), look = new Set(), open = false, held = false } = {}) {
  const any = !!s && (s.top.length || s.more.length || s.parked.length || s.followed.length || s.note);
  section.hidden = !any;
  if (!any) { body.innerHTML = ""; return; }
  const heldRows = [...s.followed.map((x) => ({ ...x, state: "followed" })), ...s.parked.map((x) => ({ ...x, state: "parked" }))];
  body.innerHTML = (s.note ? h`<p class="next-note">${s.note}</p>` : "")
    + (s.top.length ? `<ol class="next-list">${s.top.map((x) => nextItem(x, busy, look)).join("")}</ol>` : s.note ? "" : `<p class="next-note">Nothing more to suggest from what this case holds.</p>`)
    + (s.more.length ? h`<details class="next-more" ${open ? raw("open") : ""}><summary>${plural(s.more.length, "more suggestion")}</summary><ol class="next-list" start="${s.top.length + 1}">${raw(s.more.map((x) => nextItem(x, busy, look)).join(""))}</ol></details>` : "")
    + (heldRows.length ? h`<details class="next-more next-held" ${held ? raw("open") : ""}><summary>${[s.followed.length ? `${s.followed.length} followed` : "", s.parked.length ? `${s.parked.length} parked` : ""].filter(Boolean).join(", ")}</summary><ul class="next-list">${raw(heldRows.map((x) => h`<li class="next held"><div class="next-main"><span class="next-t">${x.title}<span class="tag">${x.state}</span></span><span class="next-r">${x.state === "parked" ? "Parked by you. It is not suggested while it is parked." : "A case was opened from this lead."}</span></div><div class="next-act">${x.state === "parked" ? raw(h`<button type="button" class="btn btn-sm btn-ghost" data-step-back="${x.id}">Bring back<span class="sr-only">: ${x.title}</span></button>`) : ""}</div></li>`).join(""))}</ul></details>` : "");
}

// ---- when the accounts are active (the Timeline tab) ---------------------------------------------
// One block per reading (activityReadings in evidence.js), the primary identity's first. A reading
// of an account that is not the person the case is about keeps its place, under a pill and a
// note that say whose it is. draw(view) is the one activity renderer (activityViewHtml).
// cmp: offsetComparison(ev). It is said above the readings, tagged as a hint like the estimates.
export const readingId = (key) => `act-${String(key).replace(/[^A-Za-z0-9_-]/g, "-")}`;
export function activityBlocks(readings, cmp, draw) {
  const all = [...(readings?.own || []), ...(readings?.other || [])];
  if (!all.length) return "";
  const head = (r) => (r.kind === "github" ? "When the GitHub account is active" : `When the ${r.label} account posts`);
  const fit = cmp && cmp.text ? h`<div class="act-fit ${cmp.verdict === "not_enough_data" ? "" : "est"}" id="actFit"><p><b>Do the offset estimates fit together</b>${cmp.verdict === "not_enough_data" ? "" : raw(' <span class="tag">a hint, not a fact</span>')}</p><p>${cmp.text}</p>${cmp.caution ? raw(h`<p class="muted small">${cmp.caution}</p>`) : ""}</div>` : "";
  return fit + all.map((r) => h`<section class="card act-card ${r.own ? "" : "other"}" id="${readingId(r.key)}" data-reading="${r.key}" tabindex="-1" aria-label="${r.heading}">
      <h3 class="act-h">${head(r)}${r.own ? "" : raw('<span class="cp tone-different">not the person this case is about</span>')}</h3>
      ${r.own || !r.note ? "" : raw(h`<p class="act-other" role="note">${r.note}</p>`)}
      ${raw(draw(r.view))}
    </section>`).join("");
}

// ---- "Reduce your footprint": the self-audit list of a case marked "This is me" --------------------
// selfAudit() in selfaudit.js made the list by rules; every string in it is plain text and is
// escaped here. A place is a link only when it carries a link kind of its own. No control in
// this view acts on another site: it is a list to read.
export function footprintHtml(result, { title, note, sum, statement }) {
  const where = (w) => h`<li>${raw(link(w.url || "", w.label, "", { kind: w.url ? w.link_kind || "" : "none" }))}${w.check ? raw('<span class="ed-prov">check that it is yours</span>') : ""}</li>`;
  const item = (it) => h`<li class="fp-item">
      <h3 class="fp-t">${it.title}<span class="ed-prov">${it.group}</span></h3>
      <dl class="fp-dl">
        <dt>Exposed</dt><dd>${it.exposed}</dd>
        ${it.where.length ? raw(h`<dt>Seen on</dt><dd><ul class="fp-where">${raw(it.where.map(where).join(""))}</ul></dd>`) : ""}
        <dt>Fix</dt><dd>${it.fix}</dd>
        ${it.why ? raw(h`<dt>Why</dt><dd>${it.why}</dd>`) : ""}
      </dl>
    </li>`;
  return h`<div class="fp-head"><h2 class="fp-h" id="footprintH" tabindex="-1">${title}</h2><span class="tag">rules, no AI</span></div>
    <p class="fp-note">${statement} ${note}</p>
    <p class="fp-sum">${sum}</p>
    ${result.items.length ? raw(h`<ol class="fp-list">${raw(result.items.map(item).join(""))}</ol>`) : ""}
    ${result.gaps.length ? raw(h`<h3 class="fp-gaps-h">What this list could not see</h3><ul class="fp-gaps">${raw(result.gaps.map((g) => h`<li>${g}</li>`).join(""))}</ul>`) : ""}`;
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
export const EXPORT_STRIP = '[hidden], .btn, .ev-check, .selfset, .ev-diff, .runlog, .sr-only, [role=status], .lg-detail, .ai-pitch, .ai-cost, .lk-status, input, textarea, .tabs, .sk-wrap, .sk-card, .who-switch, .case-details, .mode-echo, .mark img.mark-fav, img:not([src^="data:image/"])';

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
