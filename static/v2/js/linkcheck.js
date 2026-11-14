// Link check for the ledger: asks POST /api/recon/verify-links whether each templated profile
// URL really exists. It is a passive existence check of public pages, the same thing the
// username tools do, and it has its own switch in the Sources panel.
//
// When it starts:
//   a run started in this session   on its own, when an open group first scrolls into view, or
//                                   when a collapsed group is opened
//   a case from History or a file   never on its own. The group header shows "Check these links"
//                                   and nothing is fetched until that is clicked. For a case
//                                   file the caller confirms first (the links come from the file).
// Closing a group stops its check. Stop in the status bar stops everything.
//
// This module owns the timing, the status bar and the per-row "checking" marker. The queue, its
// pacing and what a result means for a row live in links.js; the caller stores the results.
import { post, plural } from "./core.js";
import { makeCheckQueue, isTransient, UNVERIFIED_TEXT } from "./links.js";

const MAX_PER_GROUP = 200;   // the ledger shows at most this many rows of a group

// opts:
//   ledger          the ledger element (rows carry data-row, groups carry data-tier)
//   allowed()       false while a run is in flight, when the switch is off, or for a non-username case
//   auto()          true only for a run started in this session
//   username()      the searched handle
//   rows(tier)      rows of that group still to check: [{ id, site, url }]
//   request(tier, n, go)       a click on "Check these links": call go() to start (after a confirm, if any)
//   onStart()                  a round is starting
//   onBatch(sent, results)     one batch answered
//   onFail(err)                a real failure. Nothing was changed; the user can try again
//   onRetry()                  the user asked to try again after a failure
//   onIdle({ stopped })        nothing is queued or in flight any more
export function makeLinkChecker({ ledger, allowed, auto, username, rows, request, onStart, onBatch, onFail, onRetry, onIdle }) {
  // The status bar sits after the ledger and sticks to the bottom of the window while the ledger
  // is on screen, so it never pushes a row.
  const bar = document.createElement("div");
  bar.className = "lk-status"; bar.hidden = true;
  bar.innerHTML = `<span class="lk-status-text" role="status" aria-live="polite"></span><button type="button" class="btn btn-sm" data-lk-stop hidden>Stop</button><button type="button" class="btn btn-sm" data-lk-retry hidden>Try again</button>`;
  ledger.after(bar);
  const text = bar.querySelector(".lk-status-text"), stopBtn = bar.querySelector("[data-lk-stop]"), retryBtn = bar.querySelector("[data-lk-retry]");

  let asked = new Set();         // row ids sent or queued in this case: never sent twice
  let busy = new Set();          // row ids queued or in flight, for the "checking" marker
  let failedTiers = new Set();   // groups to pick up again on "Try again"
  let halted = false;            // the user pressed Stop: nothing starts on its own after that
  let deferred = new Set();      // "not checked this time": open for a later check, by the button only
  let skipped = 0;
  let total = 0, done = 0, pause = null, tick = null, hideTimer = null, io = null;

  const rowEl = (id) => [...ledger.querySelectorAll(".ev[data-row]")].find((r) => r.dataset.row === id);
  function mark(id, on) {
    const flag = rowEl(id)?.querySelector(".lk-flag");
    if (!flag) return;
    flag.textContent = on ? "checking…" : UNVERIFIED_TEXT;
    flag.classList.toggle("busy", on);
  }
  const release = (list, forget = false) => { for (const r of list) { busy.delete(r.id); if (forget) asked.delete(r.id); mark(r.id, false); } };
  // byHand: a click may ask again for rows the checker put off; nothing does that on its own.
  const waitingIn = (tier, byHand = true) => (allowed() && !queue.failed ? rows(tier).filter((r) => !asked.has(r.id) && (byHand || !deferred.has(r.id))).slice(0, MAX_PER_GROUP) : []);
  // Group header buttons: shown while the group has links nobody has asked about.
  function paintButtons() {
    for (const b of ledger.querySelectorAll("[data-check-tier]")) {
      const n = waitingIn(b.dataset.checkTier).length;
      b.hidden = !n;
      if (n) b.textContent = `Check these links (${n.toLocaleString()})`;
    }
  }
  function show(msg, { stop = false, retry = false, fade = 0 } = {}) {
    clearTimeout(hideTimer);
    bar.hidden = !msg; text.textContent = msg; stopBtn.hidden = !stop; retryBtn.hidden = !retry;
    if (fade) hideTimer = setTimeout(() => { bar.hidden = true; text.textContent = ""; }, fade);
  }
  function status() {
    const progress = `${done.toLocaleString()} of ${plural(total, "link")} checked`;
    if (!pause) { show(`Checking links: ${progress}.`, { stop: true }); return; }
    const secs = Math.max(1, Math.ceil((pause.until - Date.now()) / 1000));
    show(pause.reason === "rate_limited" ? `Paused, the checker is rate limited. It continues in ${secs} s. ${progress}.` : `Checking links: ${progress}. Waiting ${secs} s to stay under the checker's limit.`, { stop: true });
  }
  const endPause = () => { pause = null; clearInterval(tick); tick = null; };

  const queue = makeCheckQueue({
    send: async (batch, signal) => (await post("/api/recon/verify-links", { username: username(), links: batch }, {}, signal))?.results,
    onBatch: (sent, results) => {
      release(sent); done += sent.length;
      // A site the checker was asked about too often answers "not checked this time". That is
      // not a result: the row stays as it is and can be checked again from the group's button.
      for (const r of results) if (isTransient(r) && sent.some((x) => x.id === r?.id)) { asked.delete(r.id); deferred.add(r.id); skipped++; }
      onBatch?.(sent, results); status();
    },
    // A batch cut short by Stop or by closing its group was never answered, so it may be sent again.
    onCancel: (sent) => { total -= sent.length; release(sent, true); paintButtons(); },
    onPause: (p) => { pause = p; clearInterval(tick); tick = setInterval(status, 1000); status(); },
    onResume: () => { endPause(); status(); },
    // A real failure is a failed source. It says nothing about any row: every row that was
    // waiting goes back to "unverified URL", and the user can try again.
    onFail: (err, dropped) => {
      endPause(); release(dropped, true);
      show(`Link check failed: ${err.detail || err.message} No row was changed.`, { retry: true });
      onFail?.(err);
    },
    onIdle: ({ stopped }) => {
      endPause();
      const put = skipped ? ` ${plural(skipped, "link")} ${skipped === 1 ? "was" : "were"} not checked this time, because the checker has asked that site a lot in the last minute. Use Check these links to try again.` : "";
      show((stopped ? `Link check stopped. ${done.toLocaleString()} of ${plural(Math.max(total, done), "link")} checked.` : `Link check finished. ${plural(done - skipped, "link")} checked.`) + put, { fade: skipped ? 15000 : 6000 });
      total = 0; done = 0; skipped = 0;
      paintButtons();
      onIdle?.({ stopped });
    },
  });

  function start(tier, byHand = false) {
    const todo = waitingIn(tier, byHand);
    for (const r of todo) deferred.delete(r.id);
    if (!todo.length) return;
    for (const r of todo) { asked.add(r.id); busy.add(r.id); mark(r.id, true); }
    failedTiers.add(tier);
    if (!queue.active) { total = 0; done = 0; onStart?.(); }
    total += todo.length;
    queue.add(tier, todo);
    paintButtons(); status();
  }
  // Closing a group stops its check. Rows that were waiting can be checked when it is opened again.
  function stop(tier) {
    const waiting = queue.stop(tier);
    total -= waiting.length;
    release(waiting, true);
    paintButtons();
  }
  // A new run, another case or the switch going off: drop everything.
  function reset() {
    queue.reset(); endPause(); io?.disconnect();
    asked = new Set(); busy = new Set(); failedTiers = new Set(); deferred = new Set(); halted = false; total = 0; done = 0; skipped = 0;
    show("");
  }
  // Call after every ledger render: re-marks rows in flight, paints the header buttons, and, for
  // a run started in this session only, watches the open groups.
  function watch() {
    io?.disconnect();
    for (const id of busy) mark(id, true);
    paintButtons();
    if (!allowed() || !auto() || halted || queue.failed) return;
    const open = [...ledger.querySelectorAll(".tier:not(.collapsed)")].filter((sec) => waitingIn(sec.dataset.tier, false).length);
    if (!open.length) return;
    if (typeof IntersectionObserver !== "function") { for (const sec of open) start(sec.dataset.tier); return; }
    io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) { io.unobserve(e.target); if (allowed() && auto() && !halted) start(e.target.dataset.tier); }
    });
    for (const sec of open) io.observe(sec);
  }
  ledger.addEventListener("crawlr:tier", (e) => { if (!e.detail.open) stop(e.detail.tier); else if (allowed() && auto() && !halted) start(e.detail.tier); });
  // "Check these links" is the one way a check starts for a case that was not run in this session.
  ledger.addEventListener("click", (e) => {
    const b = e.target.closest("[data-check-tier]");
    if (!b || !allowed()) return;
    const tier = b.dataset.checkTier, n = waitingIn(tier).length;
    if (!n) return;
    const go = () => {
      halted = false;
      const sec = b.closest(".tier");
      if (sec?.classList.contains("collapsed")) { sec.classList.remove("collapsed"); sec.querySelector(".tier-head")?.setAttribute("aria-expanded", "true"); }
      start(tier, true);
      (sec?.querySelector(".tier-head") || ledger).focus?.({ preventScroll: true });
    };
    if (request) request(tier, n, go); else go();
  });
  stopBtn.addEventListener("click", () => { halted = true; stop(undefined); });
  retryBtn.addEventListener("click", () => {
    const tiers = [...failedTiers];
    queue.clearFailure(); halted = false; show("");
    onRetry?.();
    for (const t of tiers) start(t, true);
    paintButtons();
  });
  return { watch, reset, start, stop, waiting: (tier) => waitingIn(tier).length, get active() { return queue.active; }, get failed() { return queue.failed; } };
}
