// Investigate mode: run sources, build the ledger, AI on request, deep dive, history, notes, export.
import { howTag, $, $$, h, raw, esc, link, store, toast, post, postAi, ApiError, getKey, aiAvailable, aiCost, freeLeft, userAiKey, providerName, detect, TYPE_LABEL, fmtNum, fmtAgo, plural, sourceOutcome, sourceHasResults, sourceCoverage, coverageText, statusForAi, sourceTally, tallyText, download, slug } from "./core.js";
import { buildEvidence, ledgerTiers, aiSignature, isFinding, factsFor, avatarImages, hashView, hashCoverage, sourcePlan, emailParts, isFreeMail, aiPayloadFor, caseMarkdown, deepDiveUrls } from "./evidence.js";
import { adultHost, adultOn, adultAllowed, usernameBody, withoutAdult, scrubResponse, scrubCollected, tallyView, reportForExport, isAdultRow, adultForAi, adultSummary, adultCheckText, guardText, ADULT_NOTICE, ADULT_SOURCE } from "./adult.js";
import { session, MODE, adultCase, activeCase, makeRefusals, cleanPrefs, mayStore, sheetRowHtml } from "./modes.js";
import { paintBar } from "./modeui.js";
import { sourceCards } from "./renderers.js";
import { normalizeAi, markdown, summaryBlock, aiStartHtml, copyPrompt, parseReply } from "./ai.js";
import { investigateBrief } from "./brief.js";
import { reportHtml } from "./report.js";
import { openModal, closeModal } from "./ui.js";
import { pendingChecks, mergeChecks, linkCheckSource, checkPolicy, checkConfirmText } from "./links.js";
import { makeLinkChecker } from "./linkcheck.js";
import { nameCase, nameNotices, nameKnown, nameTierView, profileStatus, directoryText, readNameResult, readProfile, readProfiles, readQualifiers, scrubNames, QUALIFIERS, NAME_SOURCE, NAME_SOURCE_DESC, NAME_NOT_USABLE } from "./names.js";
import { renderNameKnown, nameNoticesHtml, patchRow, makeLog, renderTiers, bindLedger, renderFacts, renderIdentityFacts, failedNotice, diffRuns, diffNotice, standaloneHtml, makeTabs, setTabCount, renderBrief, casePrint, renderVerdict, bindVerdict, identityHead, skeletonCards, addedFactsHtml } from "./workbench.js";
import { investigateTiles, writeHistory, boundAvatarHash } from "./present.js";
import { readPhone, phoneTileExtra, readRegion, needsCountry, defaultRegion, PHONE_REGIONS, PHONE_SOURCE, PHONE_SOURCE_DESC, PHONE_NOT_USABLE } from "./phone.js";
import { buildCaseFile } from "./casefile.js";
import { readSimilar, readProbe, similarBase, probeStatus, similarBlurb } from "./similar.js";

// ---- sources ---------------------------------------------------------------
// AI analysis is not in this list on purpose: it never runs on its own. The investigator
// asks for it from the AI panel once the sources are in, and sees what it will cost first.
export const SOURCES = [
  { id: "sherlock", how: "guess",  name: "Sherlock",        desc: "username across 400+ sites",            types: ["username"],          on: true },
  { id: "maigret", how: "guess",   name: "Maigret",         desc: "username across 500 top sites, reads profile data where it can", types: ["username"], on: true },
  { id: "github", how: "record",    name: "GitHub",          desc: "profile, organisations, repos, linked accounts and commit emails", types: ["username"], on: true },
  { id: "platform", how: "guess",  name: "Platform check",  desc: "reads the profile page on major platforms, asks Reddit and Discord directly, and says when a site blocks the check", types: ["username"], on: true },
  { id: "holehe", how: "guess",    name: "Holehe",          desc: "accounts registered to this email",     types: ["email"],             on: true },
  { id: "hibp", how: "index",      name: "Breaches",        desc: "known credential exposures",            types: ["email"],             on: true },
  { id: "gravatar", how: "record",  name: "Gravatar",        desc: "avatar profile for this email",         types: ["email"],             on: true },
  { id: "hunter", how: "index",    name: "Hunter.io",       desc: "addresses on the email's domain",       types: ["email"],             on: false, pro: "hunter" },
  { id: "harvester", how: "index", name: "Domain harvest",  desc: "hosts and other addresses on this email's domain, from 8 public sources. Skipped for mail providers such as gmail.com", types: ["email"], on: true },
  { id: "hash", how: "index",      name: "Hash lookup",     desc: "MalwareBazaar, CIRCL, OTX, ThreatFox",  types: ["hash"],              on: true },
  { id: "phone", how: "index",     name: PHONE_SOURCE,      desc: PHONE_SOURCE_DESC,                        types: ["phone"],             on: true, pro: "numlookup", proOptional: true },
  { id: "namesearch", how: "index", name: NAME_SOURCE,      desc: NAME_SOURCE_DESC,                         types: ["name"],              on: true },
  // Not part of the run: it starts when a ledger group with unchecked profile URLs is on screen.
  { id: "linkcheck", how: "guess", name: "Link check",      desc: "checks that each reported profile URL really exists, when you open a group", types: ["username"], on: true },
];
// "Active techniques" and "Adult sites" are not in this list: they are session modes (modes.js),
// off on every page load and never stored with these preferences.

// Stored switches for ordinary sources only. An older version kept "active" and an adult sites
// choice here; both are ignored and removed at once, so nobody arrives with a mode already on.
const { prefs: srcState, dirty: srcDirty } = cleanPrefs(store.get("crawlr_v2_sources", {}));
const saveSrc = () => store.set("crawlr_v2_sources", srcState);
if (srcDirty) saveSrc();
export const srcOn = (id) => (id in srcState ? !!srcState[id] : SOURCES.find((s) => s.id === id)?.on ?? false);
const setSrc = (id, v) => { if (!mayStore(id)) return; srcState[id] = v; saveSrc(); };

// ---- session modes: Adult sites and Active techniques ------------------------------------------
// Both live in modes.js, in memory only: off when the page loads, and on until the investigator
// switches them off or reloads. Nothing in this file switches one off for a new handle, a new
// case, Clear or a case opened from History, and nothing a case holds can switch one on.
// The handles the server's own minor guard refused in this session: suspended for that handle only.
const refusals = makeRefusals();
const adultView = (type, target = $("#targetInput").value) => adultCase(session.on("adult"), target, type, refusals);
const activeView = (type) => activeCase(session.on("active"), type);
// The two switches in the case bar, the status line under them, and the same two rows in the sheet.
function paintModes() {
  const rows = [{ id: "adult", view: adultView(sourcesType), desc: MODE.adult.desc }, { id: "active", view: activeView(sourcesType), desc: MODE.active.desc }];
  paintBar($("#modes"), $("#modeStatus"), rows);
  for (const r of rows) $(`#sources [data-mode-row="${r.id}"]`)?.classList.toggle("off", !r.view.on);
}

// ---- name qualifiers ---------------------------------------------------------------
// Three optional boxes under the target, shown for a name. They rank what comes back and are
// never sent to a directory. Saved with the case and put back when it is opened from History.
const QUAL_INPUT = { location: "#qLocation", employer: "#qEmployer", keyword: "#qKeyword" };
const qualifiers = () => readQualifiers(Object.fromEntries(Object.entries(QUAL_INPUT).map(([k, sel]) => [k, $(sel).value])));
const setQualifiers = (q) => { const r = readQualifiers(q); for (const [k, sel] of Object.entries(QUAL_INPUT)) $(sel).value = r[k]; };
// A string the server will not search as a name: said under the target box, in plain words.
function nameError(msg) { const el = $("#nameError"); el.textContent = msg || ""; el.hidden = !msg; }
$("#targetInput").addEventListener("input", () => nameError(""));
$("#nameQualifiers").addEventListener("keydown", (e) => { if (e.key === "Enter" && !state.running) $("#runBtn").click(); });

// ---- the country of a phone number typed without a country code --------------------------------
// One select under the target, shown while the Phone type is active and the text does not start
// with a +. It starts on the browser's region when the numbering data knows it, otherwise
// the United States. The choice goes with the lookup as `region` and is saved with the case.
const regionSelect = $("#phoneRegion");
regionSelect.innerHTML = PHONE_REGIONS.map(([code, name]) => h`<option value="${code}">${name}</option>`).join("");
regionSelect.value = defaultRegion(globalThis.navigator?.language);
const phoneRegion = (target) => (needsCountry(target) ? readRegion(regionSelect.value) || "US" : "");
const paintCountry = (type) => { $("#phoneCountry").hidden = !(type === "phone" && needsCountry($("#targetInput").value)); };

let sourcesType = "";   // the target type the panel was last drawn for
export function renderSources(type) {
  sourcesType = type || "";
  $("#nameQualifiers").hidden = type !== "name";
  paintCountry(type);
  const box = $("#sources");
  const rows = SOURCES.filter((s) => !type || s.types.includes(type));
  box.innerHTML = rows.map((s) => h`
    <div class="source ${srcOn(s.id) ? "" : "off"}" data-src="${s.id}">
      <div>
        <div class="name" id="src-${s.id}">${s.name}${s.warn ? raw(' <span class="tag warn">caution</span>') : ""}${s.pro && !s.proOptional ? raw(' <span class="tag violet">your key</span>') : ""}</div>
        <div class="desc" id="srcd-${s.id}">${raw(howTag(s.how))}${s.desc}</div>
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-label="${s.name}" aria-labelledby="src-${s.id}" aria-describedby="srcd-${s.id}"><span></span></label>
    </div>`).join("");
  if (!rows.length) box.innerHTML = h`<p class="empty flat">Type a target to see which sources apply.</p>`;
  // The two session modes close the list: the same switches as in the case bar, one state.
  box.insertAdjacentHTML("beforeend", sheetRowHtml("adult", adultView(sourcesType)) + sheetRowHtml("active", activeView(sourcesType)));
  paintModes();
  paintCount();
}
// The Sources button shows how many are switched on for this target type.
function paintCount() {
  const sw = $$("#sources [data-toggle], #sources [data-session-mode]"), on = sw.filter((el) => el.checked).length, all = sw.length;
  $("#sourcesCount").textContent = all ? `${on} of ${all}` : "";
}
$("#sources").addEventListener("change", (e) => {
  const t = e.target.dataset.toggle;
  if (t) {
    const s = SOURCES.find((q) => q.id === t);
    if (e.target.checked && s?.pro && !s.proOptional && !getKey(s.pro)) {
      e.target.checked = false;
      toast(`${s.name} needs your key. Add it in Settings.`);
      return;
    }
    setSrc(t, e.target.checked);
    e.target.closest(".source").classList.toggle("off", !e.target.checked);
    paintCount();
    if (t === "linkcheck") { if (e.target.checked) checker.watch(); else { checker.reset(); renderLedger(); } }
  }
});

// A mode changed: the bar and the sheet follow in place (no redraw, so focus stays on the switch),
// and Deep Dive in the AI panel becomes available or not.
session.subscribe((id) => { paintModes(); paintCount(); if (id === "active" && state.ai && !state.aiBusy) renderAiPanel(); });

// ---- run log + result tabs -----------------------------------------------------
const log = makeLog($("#runlog"));
const tabs = makeTabs($("#tabs"));

// ---- state -------------------------------------------------------------------
// prev: { keys, ts, ai, sig } from the last saved run of the same target, for the diff.
// view: which identity cluster "What we know" shows; "" means the primary one.
// live: this case was run in this session, so its header and run log follow the tally.
// pending: sources of the run in flight that have not answered yet (label by key), for the placeholders.
const pending = new Map();
// asked: the keys of every source this run started, so a cancelled run knows which never answered.
const asked = new Set();
export const state = { nameInvalid: "", target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, running: false, cancelled: false, controller: null, prev: null, aiBusy: false, ran: 0, view: "", live: false, imported: false, adultMode: false, adultBlocked: "" };
const checkKey = () => `crawlr_checked_${state.target}`;
const checked = () => new Set(store.get(checkKey(), []));

const SRC_NAME = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", holehe: "Holehe", hibp: "Breaches", gravatar: "Gravatar", hunter: "Hunter.io", harvester: "Domain harvest", hash: "Hash lookup", phone: PHONE_SOURCE, nameResult: NAME_SOURCE, enricher: "Profile enrichment", platformCheck: "Platform check", profileScrape: "Profile scrape", githubDeep: "GitHub details", avatarHash: "Avatar comparison", adultCheck: ADULT_SOURCE, linkCheck: "Link check" };
// Every count of sources on this page comes from this one tally. The link check is a source like
// any other: its row is built from the stored results, or from the error if the verifier failed.
// Counted over the adult-free view: Sherlock and Maigret are never "with results" for rows on
// adult sites. Those are tallied only as the separate adult site check, in a case with the mode on.
const tally = () => sourceTally({ ...tallyView(state.collected, state.target, state.type), linkCheck: linkCheckSource(state.collected) }, SRC_NAME);
const failedSources = () => tally().rows.filter((r) => r.state === "failed");
// Identical evidence means an identical AI answer, so a re-run can reuse the last one.
const adultItems = (items) => items.filter((i) => i.tier === "adult");
const hasAdult = () => adultAllowed(state.collected, state.target, state.type);
// Above the findings: what the adult and dating site rows are, or why they were not asked for.
function adultNotice() {
  if (state.adultBlocked) return h`<div class="notice" role="note">${state.adultBlocked} The other sources ran as usual.</div>`;
  if (!hasAdult()) return "";
  const mg = state.collected.maigret;
  return h`<div class="notice" role="note" id="adultNotice">${ADULT_NOTICE}${mg && mg.adult_error ? ` Maigret could not check adult and dating sites (${String(mg.adult_error).slice(0, 160)}), so that part is unknown, not "not found".` : ""}</div>`;
}

// ---- ledger + facts -------------------------------------------------------------
// Similar handles whose check is in flight (see simCheck).
const simBusy = new Set();
function evidence() {
  const ev = buildEvidence(state.collected, state.target, state.type);
  // Leads and host inventory are not findings, so they are not part of "what changed".
  // A name case has candidates and no findings, so there is nothing for "what changed" to compare.
  const diff = !state.running && state.prev && state.type !== "name" ? diffRuns(state.prev.keys, ev.items.filter(isFinding)) : null;
  if (diff) { const added = new Set(diff.added.map((i) => i.key)); for (const it of ev.items) it.isNew = added.has(it.key); }
  // Similar handles are offered once the run is in: they are built from the handle and from the
  // name on the primary profile, which is not known until the sources have answered.
  // A handle whose check is in flight says so in every redraw, not only on the button that was pressed.
  for (const it of ev.items) if (it.sim && simBusy.has(it.sim.variant)) it.sim.busy = true;
  return { ...ev, items: state.running ? ev.items.filter((i) => i.tier !== "similar") : ev.items, diff };
}
// opts.keep: a redraw after the investigator changed one row (added or removed a profile from a
// similar handle). Every group stays open or closed as it was.
function renderLedger(opts = {}) {
  const ev = evidence();
  const open = opts.keep ? new Map($$("#ledger .tier").map((t) => [t.dataset.tier, !t.classList.contains("collapsed")])) : null;
  const { items, facts, diff } = ev;
  $("#emptyState").hidden = true;
  // A name case opens with its caveat, always, then says how the search went.
  const isName = state.type === "name" && !state.nameInvalid;
  // When the search answered but its directories did not, the name notice already names each one.
  const failedShown = failedSources().filter((f) => !(isName && f.key === "nameResult" && nameCase(state.collected, state.target).result));
  $("#notices").innerHTML = (isName ? nameNoticesHtml(nameNotices(state.collected, state.target)) : "") + failedNotice(failedShown) + adultNotice() + (diff ? diffNotice(diff, state.prev.ts) : "");
  const nothing = state.running
    ? `<div class="empty"><h3>Collecting</h3><p>Findings appear here as each source answers.</p></div>`
    : state.nameInvalid ? h`<div class="empty"><h3>Not searched</h3><p>${state.nameInvalid} ${state.type === "phone" ? "Nothing was looked up." : "No directory was asked."}</p></div>`
    : failedSources().length
      ? `<div class="empty"><h3>No findings from the sources that answered</h3><p>Some sources failed, so this is not a clean negative. See the notice above and try again.</p></div>`
      : `<div class="empty"><h3>Nothing found</h3><p>Every source answered and none had a result for this target.</p></div>`;
  // The adult group says what its count is made of, under its heading.
  const tiers = nameTierView(ledgerTiers(state.target, state.type).map((t) => (t.id === "adult" ? { ...t, note: adultSummary(adultItems(items)) } : t.id === "similar" ? { ...t, blurb: similarBlurb(items) } : t)), items);
  renderTiers($("#ledger"), items, tiers, checked(), nothing, { check: (tier) => checker.waiting(tier), pending: state.running ? [...pending.values()] : [], imported: state.imported, handle: state.type === "username" ? state.target.replace(/^@/, "") : "", open });
  paintSummary(ev);
  checker.watch();
}
// What sits beside and above the rows: "What we know", the tab count and the brief. Drawn with the
// ledger, and on its own when a single row changes.
function paintSummary(ev) {
  const { items, facts } = ev;
  const isName = state.type === "name" && !state.nameInvalid;
  const emptyFacts = state.running ? "Collecting…" : "No facts extracted yet.";
  // A person case shows one identity at a time, so one person's name never sits beside another's.
  // state.view is only ever what the investigator picked; with no pick the primary cluster shows.
  // A name case selects nobody: no facts, no identity, only what is known about the search.
  if (isName && !state.running) renderNameKnown($("#facts"), nameKnown(state.collected, state.target));
  else if (ev.identity.views.length) renderIdentityFacts($("#facts"), ev.identity, (id) => factsFor(ev, id), state.view, emptyFacts);
  else renderFacts($("#facts"), facts, emptyFacts);
  // Facts of profiles added from a similar handle: apart from every identity, at the end.
  if (!isName && ev.added?.length) $("#facts").insertAdjacentHTML("beforeend", addedFactsHtml(ev.added));
  if (state.type === "name") setTabCount($("#tabFindings"), "Candidates", items.filter((i) => i.tier === "people").length);
  else setTabCount($("#tabFindings"), "Findings", items.filter(isFinding).length);
  // The identity header: whose profiles these are. Username and email cases only.
  const head = !isName && (state.type === "username" || state.type === "email") ? identityHead(ev.identity, state.view) : "";
  $("#identity").innerHTML = head; $("#identity").hidden = !head;
  // The verdict tiles wait for the run to finish, like the brief: a count mid-run is half a picture.
  $("#caseBar").hidden = !state.target;
  const rows = tally().rows, keysOf = (st) => rows.filter((r) => r.state === st).map((r) => r.key);
  // Sources that were asked and had not answered when the run was cancelled: unknown, never zero.
  const missing = (state.collected.notAnswered?.keys || []).filter((k) => typeof k === "string");
  renderVerdict($("#verdict"), !state.target || state.nameInvalid ? [] : investigateTiles({ items, collected: state.collected, type: state.type, running: state.running, failedKeys: keysOf("failed"), partialKeys: keysOf("partial"), missingKeys: missing, extra: tileExtra() }));
  // The written brief waits for the run to finish, so it never describes half a picture.
  renderBrief($("#brief"), $("#briefBody"), state.running || !state.target || state.nameInvalid ? { rows: [], actions: [] } : investigateBrief({ collected: state.collected, items, facts, identity: ev.identity, failed: failedSources(), incomplete: [...rows.filter((r) => r.state === "failed" || r.state === "partial").map((r) => r.name), ...missing.map((k) => SRC_NAME[k] || k)], type: state.type, target: state.target, similarLine: ev.similarLine }));
}
bindLedger($("#ledger"), checkKey);
// What the tiles of a hash, phone or name case show, from the same functions the cards use.
function tileExtra() {
  const c = state.collected;
  if (state.type === "hash") { const v = hashView(c.hash); if (!v) return {}; const cov = hashCoverage(c.hash); return { hash: { verdict: v.verdict, detection: v.detection || null, answered: cov.answered, asked: cov.answered + cov.failed.length } }; }
  if (state.type === "phone") return phoneTileExtra(c.phone);
  if (state.type === "name") { const cv = sourceCoverage(c.nameResult); return { name: cv ? { answered: cv.answered, asked: cv.total } : { answered: 0, asked: 0 } }; }
  return {};
}
bindVerdict($("#verdict"), { ledger: $("#ledger"), setTab: (t) => tabs.set(t), tabEl: (t) => $(`#tabs [data-tab="${t}"]`) });
// One identity at a time: the select in "What we know" and the buttons in the identity header
// set the same view. Focus stays on the control that was used.
function showIdentity(id, focusSel) {
  state.view = id || "";
  paintSummary(evidence());
  $(focusSel)?.focus({ preventScroll: true });
}
$("#facts").addEventListener("change", (e) => { if (e.target.matches("[data-cluster-pick]")) showIdentity(e.target.value, "#factsPick"); });
$("#identity").addEventListener("click", (e) => { const b = e.target.closest("[data-cluster-btn]"); if (b) showIdentity(b.dataset.clusterBtn, `#identity [data-cluster-btn="${CSS.escape(b.dataset.clusterBtn)}"]`); });

// ---- link check -----------------------------------------------------------------------
// Templated profile URLs are checked by the server (see linkcheck.js). For a run started in this
// session that begins when the group is on screen. A case from History or from a case file is
// never checked without a click: opening a file must not make anything fetch the links in it.
// Results are stored in the case, so history, exports and case files keep them.
const linkHandle = () => state.target.replace(/^@/, "");
const policy = () => checkPolicy({ on: srcOn("linkcheck"), running: state.running, type: state.type, handleOk: /^[A-Za-z0-9._-]{1,64}$/.test(linkHandle()) && !linkHandle().startsWith("-"), live: state.live, imported: state.imported });
let linkRow = null;
// The case header and the run log summary, from the one tally.
function summary() {
  const { items } = evidence();
  // A name case counts candidates. They are not findings, and are never called that.
  const t = tally(), isName = state.type === "name";
  const found = isName ? plural(items.filter((i) => i.tier === "people").length, "candidate") : plural(items.filter(isFinding).length, "finding");
  if (state.nameInvalid) return { items, t, log: `Not searched: that is not a usable ${state.type === "phone" ? "phone number" : "name"}`, head: `${TYPE_LABEL[state.type]} · not searched` };
  return { items, t, log: `${state.cancelled ? "Cancelled · partial results · " : ""}${tallyText(t)} · ${found}`, head: `${TYPE_LABEL[state.type]} · ${found} · ${tallyText(t)}${state.cancelled ? " · cancelled, partial" : ""}` };
}
function linkCheckDone(text, status, detail = "") {
  if (linkRow && log.live) log.set(linkRow, text, status, detail);
  if (state.live && !state.running) { const s = summary(); log.resummarize(s.log, s.t.failed); renderHead(s.head); }
  renderSourceCards();
  if (state.target) saveHistory();
}
const linkCounts = () => { const r = linkCheckSource({ linkChecks: state.collected.linkChecks })?.results || []; return `${fmtNum(r.filter((x) => x.state === "verified").length)} of ${plural(r.length, "page")} exist`; };
const checker = makeLinkChecker({
  ledger: $("#ledger"),
  allowed: () => policy().allowed,
  auto: () => policy().auto,
  username: linkHandle,
  // Account rows only, and never an address on an adult or dating host. The verifier's `adult`
  // field is never sent: no adult row goes to the link check.
  rows: (tier) => pendingChecks(buildEvidence(state.collected, state.target, state.type).items, tier).filter((r) => !adultHost(r.url)),
  // A case file's links were chosen by whoever made the file, so say so before fetching them.
  request: (tier, n, go) => {
    if (!policy().confirm) { go(); return; }
    openModal({ title: "Check the links in this case file?", body: h`<p class="modal-p">${checkConfirmText(n)}</p>`,
      actions: [{ label: "Cancel", onClick: closeModal }, { label: "Check these links", primary: true, onClick: () => { closeModal(); go(); } }] });
  },
  onStart: () => { if (log.live) { if (linkRow?.isConnected) log.set(linkRow, "Link check", "run"); else linkRow = log.add("Link check"); } },
  onBatch: (sent, results) => {
    state.collected.linkChecks = mergeChecks(state.collected.linkChecks, sent, results);
    const { items } = evidence();
    for (const r of sent) { const it = items.find((i) => i.key === r.id); if (it) patchRow($("#ledger"), it); }
    if (state.target) saveHistory();
  },
  onFail: (err) => {
    // Unknown, never "not found": no row changes, and the failure is shown like any failed source.
    state.collected.linkCheck = { error: err.detail || err.message, error_code: err.code || "request_failed", error_detail: err.raw || "" };
    renderLedger();
    linkCheckDone(`Link check: ${err.detail || err.message}`, "err", err.raw);
  },
  // "Try again" in the status bar: the failure is cleared and the same groups are asked again.
  onRetry: () => { delete state.collected.linkCheck; renderLedger(); },
  onIdle: ({ stopped }) => {
    if (state.collected.linkCheck) { delete state.collected.linkCheck; renderLedger(); }
    linkCheckDone(`Link check · ${linkCounts()}${stopped ? " · stopped" : ""}`, "done");
  },
});

function renderSourceCards() {
  // Drawn from the adult-free view: no card lists an adult row or a link to an adult site. The
  // adult site check has its own card, built from the ledger's adult group.
  const all = state.collected, c = withoutAdult(all);
  const cards = [];
  // Every source that ran gets a card: with results, "answered, nothing found", or failed.
  const push = (id, d, extra) => { if (d !== undefined && d !== null && !d.skipped && sourceCards[id]) { const html = sourceCards[id](d, extra); if (html) cards.push(html); } };
  push("hash", c.hash); push("phone", c.phone);
  push("hibp", c.hibp); push("holehe", c.holehe); push("github", c.github, c.githubDeep); push("githubDeep", c.githubDeep, c.github); push("gravatar", c.gravatar);
  push("sherlock", c.sherlock, c.linkChecks); push("maigret", c.maigret, c.linkChecks); push("platformCheck", c.platformCheck, c.linkChecks);
  // Its rows are the ledger's adult group, so the card and the group cannot disagree.
  if (hasAdult()) push("adultCheck", all.adultCheck, adultItems(buildEvidence(all, state.target, state.type).items));
  push("linkCheck", linkCheckSource(all));
  push("enricher", c.enricher); push("avatarHash", c.avatarHash); push("profileScrape", c.profileScrape); push("hunter", c.hunter); push("harvester", c.harvester);
  push("nameResult", c.nameResult);
  if (c.reverseImage) cards.push(sourceCards.reverseImage(c.reverseImage));
  // A source that has not answered yet holds its place with a placeholder card.
  const waiting = state.running ? skeletonCards([...pending.values()]) : "";
  $("#bySource").hidden = !cards.length && !waiting; $("#bySourceEmpty").hidden = !!cards.length || !!waiting;
  setTabCount($("#tabSources"), "By source", tally().ran);
  $("#sourceCards").innerHTML = cards.join("") + waiting;
}

function renderHead(meta) {
  $("#mainHead").hidden = false;
  $("#caseTarget").textContent = state.target;
  $("#caseMeta").textContent = meta || TYPE_LABEL[state.type] || "";
}

// ---- AI panel ---------------------------------------------------------------------
// Never an adult or dating site: Deep Dive reads the pages it is given (see deepDiveUrls).
const profileUrls = () => deepDiveUrls(state.collected);
const hasData = () => Object.entries(state.collected).some(([k, v]) => !["adultMode", "nameQualifiers", "nameProfiles", "notAnswered", "phoneRegion", "similar"].includes(k) && v && (typeof v === "object" ? sourceOutcome(v).state !== "error" : true));

// What the report will cover, said for the kind of target on screen.
const AI_PITCH = {
  username: "Get a written report: who this most likely is, what links the accounts, and what to check next.",
  email: "Get a written report: who this most likely is, what links the accounts, and what to check next.",
  hash: "Get a written report: what this file is, how sure the sources are, and what to do with it.",
  phone: "Get a written report: what kind of number this is, what its flags mean and what to check next. It never guesses who uses the number.",
  name: "Get a search plan: how to narrow people-search results for this name and what to check first.",
  nameFound: "Get a written comparison of the people found with this name and what would tell them apart.",
};
// The panel is redrawn whole. If focus was inside it (the button that was just pressed is gone),
// focus goes to the first control of the new content, or to the panel itself while it only says
// that it is working. Otherwise focus would drop to the page, and on a phone out of the drawer.
function keepPanelFocus(box, draw) {
  const had = box.contains(document.activeElement);
  draw();
  if (!had || (box.contains(document.activeElement) && document.activeElement !== box)) return;
  const next = box.querySelector("button:not([disabled]), a[href], textarea");
  if (!next) box.tabIndex = -1;
  (next || box).focus({ preventScroll: true });
}
function renderAiPanel() { keepPanelFocus($("#aiPanel"), drawAiPanel); }
function drawAiPanel() {
  const box = $("#aiPanel");
  const note = (t) => `<p class="empty flat">${esc(t)}</p>`;
  if (!state.ai) {
    if (state.aiBusy) { box.innerHTML = `<p class="empty flat" role="status">Asking ${esc(providerName())}…</p>`; return; }
    if (state.running) { box.innerHTML = note("Available when the sources finish. AI never runs on its own."); return; }
    if (!state.target || !hasData()) { box.innerHTML = note(state.target ? "Nothing to analyze yet." : "Run a target first. AI analysis is optional and only runs when you ask."); return; }
    // With candidates on screen the offer is a comparison of them; without, the older search plan.
    box.innerHTML = aiStartHtml("inv", state.type === "name" && nameCase(state.collected, state.target).people.length ? AI_PITCH.nameFound : AI_PITCH[state.type] || AI_PITCH.username);
    return;
  }
  const canDeep = session.on("active") && profileUrls().length && aiAvailable();
  const deepBtn = state.deepDive
    ? `<button class="btn btn-sm" type="button" data-open-report="deep">Deep Dive report</button>`
    : canDeep ? `<button class="btn btn-sm" type="button" id="deepDiveBtn">Deep Dive…</button>`
    : session.on("active") ? "" : `<span class="hint-inline">Deep Dive needs Active techniques on</span>`;
  box.innerHTML = summaryBlock(state.ai, { reportId: "summary", attr: "data-open-report", deepDive: deepBtn }).replace(">Full report<", ">Read report<");
  renderReport();
}

// The full investigation report lives in the main column, right under the case header.
function renderReport() {
  const sec = $("#reportSection");
  if (!state.ai?.summary) { sec.hidden = true; return; }
  sec.hidden = false;
  const { items, facts } = buildEvidence(state.collected, state.target, state.type);
  $("#reportBody").innerHTML = reportHtml({ ai: state.ai, target: state.target, items, facts, collected: state.collected, imported: state.imported, type: state.type });
  $("#reportMeta").textContent = [state.ai.model, state.ai.ai_source === "house" ? "free tier" : state.ai.ai_source === "pasted" ? "from your own assistant" : "", state.ai.reused ? "from your last run, no credit used" : state.ai.cached ? "cached, no credit used" : ""].filter(Boolean).join(" · ");
}
$("#reportToggle").addEventListener("click", (e) => {
  const body = $("#reportBody"), open = body.hidden;
  body.hidden = !open; e.currentTarget.textContent = open ? "Collapse" : "Expand"; e.currentTarget.setAttribute("aria-expanded", open);
});
$("#reportCopy").addEventListener("click", (e) => { const b = e.currentTarget; navigator.clipboard?.writeText(state.ai?.summary || "").then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1400); }); });
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-open-report]");
  if (b && b.dataset.openReport === "summary" && !$("#reportSection").hidden) { $("#reportBody").hidden = false; $("#reportSection").scrollIntoView({ behavior: "smooth", block: "start" }); $("#reportSection").focus({ preventScroll: true }); }
  else if (b) openReport(b.dataset.openReport);
  if (e.target.id === "deepDiveBtn") confirmDeepDive();
  if (e.target.id === "invAiRun") runAi();
  if (e.target.id === "invAiCopy") copyPrompt("/api/analyze/prompt", aiPayload());
  if (e.target.id === "invAiPasteGo") usePastedReply();
});
// A reply from the investigator's own assistant, formatted like any other report.
async function usePastedReply() {
  const ai = await parseReply($("#invAiPaste")?.value);
  if (!ai) return;
  state.ai = ai; saveHistory(); renderAiPanel();
  $("#reportSection").scrollIntoView({ behavior: "smooth", block: "start" });
}

function openReport(which) {
  const ai = which === "deep" ? state.deepDive : state.ai;
  if (!ai) return;
  openModal({
    title: which === "deep" ? "Deep Dive report" : "AI analysis",
    wide: true,
    // Sections about adult or dating sites are shown only for a case that has such rows, and never in a Deep Dive.
    body: `<div class="report">${markdown(reportForExport(ai.summary, which !== "deep" && adultItems(buildEvidence(state.collected, state.target, state.type).items).length > 0))}</div>`,
    actions: [{ label: "Copy markdown", onClick: () => navigator.clipboard?.writeText(ai.summary).then(() => toast("Copied")) }, { label: "Close", primary: true, onClick: closeModal }],
  });
}

// Everything the model is told about what ran and how it went.
function aiPayload(extra = {}) {
  const source_status = Object.fromEntries(tally().rows.filter((r) => r.state !== "skipped").map((r) => [r.name, statusForAi(r)]));
  // Built in evidence.js so it can be tested: adult and dating site rows travel only as their
  // own field, and only for a case that had the mode on.
  return { ...aiPayloadFor(state.collected, state.target, state.type, { source_status, active: session.on("active") }), ...extra };
}

// Runs only from the "Analyze with AI" button. One click, one credit, and the cost is on screen first.
async function runAi() {
  if (state.aiBusy || state.running || !aiAvailable() || !hasData()) return;
  state.aiBusy = true; renderAiPanel();
  const row = log.add(`AI analysis (${providerName()})`); log.open();
  try {
    const data = await postAi("/api/analyze/summarize", aiPayload());
    state.ai = normalizeAi(data);
    log.set(row, `AI analysis · ${data.model || providerName()}${data.cached ? " · cached, no credit used" : ""}`, "done");
    saveHistory();
  } catch (err) {
    log.set(row, `AI analysis: ${err.detail || err.message}`, "err", err.raw);
    toast(err.detail || err.message, 5000);
  }
  state.aiBusy = false;
  renderAiPanel();
}

function confirmDeepDive() {
  const urls = profileUrls();
  openModal({
    title: "Run a Deep Dive?",
    body: h`<p class="modal-p">CrawlR will open ${plural(urls.length, "profile page")} it found, read what's public, and ask ${providerName()} for a full dossier: likely identity, confidence matrix, OPSEC assessment and search leads.</p>
            <p class="modal-p warn">This fetches the target's pages. Some sites log visits.</p>
            <p class="modal-p muted">${aiCost("deepdive")}</p>`,
    actions: [{ label: "Cancel", onClick: closeModal }, { label: "Run Deep Dive", primary: true, onClick: () => { closeModal(); runDeepDive(urls); } }],
  });
}

async function runDeepDive(urls) {
  const row = log.add(`Scraping ${plural(urls.length, "profile")}`);
  log.open();
  try {
    const scraped = await post("/api/recon/scrape-profiles", { urls });
    state.collected.profileScrape = scraped;
    log.set(row, `Scraped ${plural((scraped.results || []).filter((r) => !r.error).length, "profile")}`, "done");
    renderLedger(); renderSourceCards();
    const row2 = log.add(`Deep Dive (${providerName()})`);
    try {
      const data = await postAi("/api/analyze/deep-dive", aiPayload({ shodan: null, name_search: null, profile_scrape: scraped, active_techniques: true, adult_sites: null }));
      state.deepDive = normalizeAi(data);
      log.set(row2, "Deep Dive complete", "done");
      saveHistory();
      renderAiPanel();
      openReport("deep");
    } catch (err) {
      log.set(row2, `Deep Dive: ${err.detail || err.message}`, "err", err.raw);
      toast(err.detail || err.message, 5000);
    }
  } catch (err) {
    log.set(row, `Profile scrape: ${err.detail || err.message}`, "err", err.raw);
    toast(err.detail || err.message, 5000);
  }
}

// ---- the run --------------------------------------------------------------------
function resultText(key, data) {
  if (key === "sherlock" || key === "maigret") {
    // Adult and dating site rows are counted apart, and only reach here when the mode is on.
    const ad = (data.results || []).filter(isAdultRow).length;
    const ok = (data.results || []).filter((r) => !isAdultRow(r) && r.confidence !== "false_positive");
    const v = ok.filter((r) => r.verified).length;
    return ok.length || ad ? [v && `${plural(v, "profile")} read`, ok.length ? `${ok.length - v} unverified` : "", ad && `${ad} on adult and dating sites, listed in their own group`].filter(Boolean).join(", ") : "";
  }
  if (key === "githubDeep") return "";
  // "Wikidata 1 · GitHub 8 · ORCID none · OpenAlex rate limited · Bluesky 1"
  if (key === "nameResult") return directoryText(data);
  if (key === "avatarHash") { const r = data?.results || [], n = r.filter((x) => x.hash && !x.error).length; return n === r.length ? `${plural(n, "image")} compared` : ""; }
  if (key === "adultCheck") return adultCheckText(data);
  if (key === "platformCheck" && (data?.results || []).some((r) => r.state)) { const r = data.results, n = (st) => r.filter((x) => x.state === st).length; 
    // Reddit and Discord are always asked, and are named with their state: neither can be read off a count.
    const WORD = { found: "read", taken: "handle taken", not_found: "not found", blocked: "blocked by site", unknown: "unclear" };
    const named = r.filter((x) => (x.platform === "Reddit" || x.platform === "Discord") && WORD[x.state]).map((x) => `${x.platform} ${WORD[x.state]}`).join(", ");
    return [n("found") && `${n("found")} read`, n("taken") && `${n("taken")} handle taken`, n("blocked") && `${n("blocked")} blocked by site`, n("unknown") && `${n("unknown")} unclear`].filter(Boolean).join(", ") + (named ? ` (${named})` : ""); }
  if (key === "harvester") return [data?.hosts?.length && plural(data.hosts.length, "host"), data?.emails?.length && plural(data.emails.length, "address", "addresses")].filter(Boolean).join(", ");
  const n = data?.total ?? data?.breaches?.length ?? data?.results?.filter?.((r) => r.found === true).length ?? (data?.found ? 1 : 0);
  return n ? `${fmtNum(n)} result${n === 1 ? "" : "s"}` : "";
}
// The server's own minor guard refused the adult part of a request. It wins over the client's
// copy: the mode is suspended for this handle (it stays on for the session), the reason is shown,
// and nothing adult is kept.
const GUARDED = Symbol("minor guard");
function adultRefused(reason) {
  const why = reason || "";
  if (!state.adultBlocked) toast(guardText(why), 6000);
  state.adultMode = false; state.adultBlocked = guardText(why);
  refusals.add(state.target, why);
  const clean = withoutAdult(state.collected);
  for (const k of Object.keys(state.collected)) delete state.collected[k];
  Object.assign(state.collected, clean);
  renderSources(state.type);
}
// opts.badInput(err): the server refused the input itself (400 or 422). That is a message for the
// person typing, not a source that failed, so nothing is stored for it.
async function runSource(label, url, body, headers, key, opts = {}) {
  const row = log.add(label);
  pending.set(row, label); asked.add(key);
  renderLedger(); renderSourceCards();
  try {
    // With the mode off any adult row in an answer is dropped here, before it is stored. With it
    // on, those rows keep their text fields and nothing else.
    const answer = await post(url, body, headers, state.controller?.signal);
    pending.delete(row);
    const data = scrubResponse(key, answer, state.adultMode);
    if (data === null) { log.set(row, `${label} · not kept`, "skip"); return null; }
    state.collected[key] = data;
    const o = sourceOutcome(data);
    const found = resultText(key, data);
    // A source whose every part was blocked or errored did not answer: that is a failure, not "nothing found".
    const cv = sourceCoverage(data);
    if (o.state === "error") log.set(row, `${label}: ${o.text}`, "err", o.detail);
    else if (o.state === "skipped") log.set(row, `${label} · skipped`, "skip");
    else if (cv && cv.total > 0 && cv.answered === 0) log.set(row, `${label} · ${cv.failedText}${key === "nameResult" && found ? ` (${found})` : ""}`, "err");
    else if (cv && cv.answered < cv.total) log.set(row, `${label} · ${[found, coverageText(cv)].filter(Boolean).join(" · ")}`, "done");
    else if (!sourceHasResults(key === "sherlock" || key === "maigret" ? withoutAdult({ [key]: data })[key] : data)) log.set(row, `${label} · nothing found${found ? ` (${found})` : ""}`, "none");
    else log.set(row, `${label} · ${found || "done"}`, "done");
    renderLedger(); renderSourceCards();
    return data;
  } catch (err) {
    pending.delete(row);
    if (err.code === "cancelled") { log.set(row, `${label} · cancelled`, "skip"); return null; }
    if (opts.badInput && (err.status === 400 || err.status === 422)) { log.set(row, `${label} · not run: that is not a usable ${opts.what || "name"}`, "skip"); opts.badInput(err); return null; }
    if (err.code === "minor_guard") { adultRefused(err.reason); log.set(row, `${label} · adult and dating sites not checked for this handle`, "skip"); renderLedger(); return GUARDED; }
    // Keep the failure with the results, so the screen and the AI both know this source is unknown.
    state.collected[key] = { error: err.detail || err.message, error_code: err.code || "request_failed", error_detail: err.raw || "" };
    log.set(row, `${label}: ${err.detail || err.message}`, "err", err.raw);
    renderLedger(); renderSourceCards();
    return null;
  }
}

function setRunning(on) {
  state.running = on;
  const b = $("#runBtn");
  b.textContent = on ? "Cancel run" : "Run investigation";
  // Cancel is a ghost button: the run is the thing in progress, not a second primary action.
  b.classList.toggle("btn-primary", !on); b.classList.toggle("btn-cancel", on);
  if (!on) pending.clear();
  $("#main").setAttribute("aria-busy", on);
}
export function cancel() {
  if (!state.running) return;
  state.cancelled = true;
  state.controller?.abort();
}

export async function run(targetRaw, typeOverride) {
  const target = String(targetRaw || "").trim();
  if (!target || state.running) return;
  const type = typeOverride || detect(target);
  if (type === "multi") { toast("One target at a time for now."); return; }
  if (!["username", "email", "hash", "phone", "name"].includes(type)) { toast(`That looks like a ${(TYPE_LABEL[type] || "domain").toLowerCase()}. Pick Username under the target to search it as a handle, or run it in Recon.`, 5000); return; }

  // The last saved run of this target, for "what changed" and to reuse its AI report.
  const last = getHistory().find((e) => e.type === "INVESTIGATE" && e.v2 && e.target.toLowerCase() === target.toLowerCase());
  let prev = null;
  if (last) { const ev = buildEvidence(last.results || {}, last.target, last.kind); prev = { keys: ev.items.filter(isFinding).map((i) => i.key), ts: last.timestamp, ai: last.ai || null, sig: aiSignature(scrubNames(last.results || {}, last.target), last.target, last.kind) }; }

  checker.reset(); linkRow = null; nameError(""); state.nameInvalid = ""; pending.clear(); asked.clear();
  // The session mode as it applies to this target: a username, and only if the handle passes the
  // minor guard. A pivot, a similar handle or a re-run reads the same session state, with no click.
  const av = adultView(type, target);
  const adult = adultOn(type, target, av.applies);
  // The similar handles checked in the last run of this target are the investigator's work: they
  // are carried into the new run, and every line-up is evaluated again against what it finds.
  const carried = last && last.kind === type ? readSimilar(last.results?.similar, similarBase(target, type)) : {};
  Object.assign(state, { target, type, collected: { ...(adult ? { adultMode: true } : {}), ...(Object.keys(carried).length ? { similar: carried } : {}) }, ai: null, deepDive: null, historyId: null, cancelled: false, controller: new AbortController(), prev, aiBusy: false, ran: Date.now(), view: "", live: true, imported: false, adultMode: adult, adultBlocked: av.state === "suspended" ? av.reason : "" });
  store.del(checkKey());
  setRunning(true);
  $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#emptyState").hidden = true; $("#bySource").hidden = true; $("#bySourceEmpty").hidden = false;
  $("#tabs").hidden = false; tabs.set("findings"); setTabCount($("#tabSources"), "By source", 0);
  renderHead(); loadNotes(); $("#reportSection").hidden = true;
  log.start();
  renderLedger(); renderAiPanel();

  // What runs for this kind of target is decided in one place (sourcePlan), then filtered by the switches.
  const plan = new Set(sourcePlan(type, target, { adult }));
  const on = (id) => plan.has(id) && srcOn(id);
  const c = state.collected;
  const isEmail = type === "email", isUser = type === "username";
  const domain = isEmail ? emailParts(target).domain : "";
  // An email's local part is not searched as a username: it is shown as a lead the investigator
  // can choose to follow. Username tools only ever run on a handle that was typed.
  const handle = target.replace(/^@/, "");
  const handleOk = isUser && /^[A-Za-z0-9._-]{1,64}$/.test(handle) && !handle.startsWith("-");

  if (type === "hash") {
    if (srcOn("hash")) await runSource("Hash lookup", "/api/hash/hash", { hash: target }, {}, "hash");
  } else if (type === "phone") {
    if (srcOn("phone")) {
      // One request. The open numbering data needs no key; a NumLookup key only adds to it, and a
      // rejected key is reported as that source failing while everything else stands.
      // A number with no country code is read as the country in the select, and the case keeps which.
      const k = getKey("numlookup"), region = phoneRegion(target);
      if (region) c.phoneRegion = region;
      await runSource(PHONE_SOURCE, "/api/phone/lookup", { phone: target, ...(region ? { region } : {}) }, k ? { "X-Numlookup-Key": k } : {}, "phone", { what: "phone number", badInput: (err) => {
        state.nameInvalid = err.status === 400 && err.detail ? err.detail : PHONE_NOT_USABLE;
        nameError(state.nameInvalid); delete c.phoneRegion;
      } });
      // Kept in the checked, bounded shape, so History and exports hold nothing else.
      if (c.phone && !c.phone.error && !c.phone.error_code) c.phone = readPhone(c.phone) || { error: "The answer could not be read.", error_code: "bad_response", error_detail: "" };
    }
  } else if (type === "name") {
    // One request to CrawlR, which asks the five directories. The qualifiers go with it only to
    // rank the answer. Nothing else is fetched: profiles and handles wait for a click.
    c.nameSearch = target;
    const q = qualifiers();
    if (QUALIFIERS.some((k) => q[k])) c.nameQualifiers = q;
    if (on("namesearch")) {
      await runSource(NAME_SOURCE, "/api/recon/name-search", { name: target, ...q }, {}, "nameResult", { badInput: (err) => {
        state.nameInvalid = err.status === 400 && err.detail ? err.detail : NAME_NOT_USABLE;
        nameError(state.nameInvalid); delete c.nameSearch; delete c.nameQualifiers;
      } });
      // Kept in the checked, bounded shape, so History and exports hold nothing else.
      if (c.nameResult && !c.nameResult.error && !c.nameResult.error_code) c.nameResult = readNameResult(c.nameResult) || { error: "The answer could not be read.", error_code: "bad_response", error_detail: "" };
    } else log.add(`${NAME_SOURCE} · switched off, so only the outbound searches are listed`, "skip");
  } else {
    const jobs = [];
    if (isUser && !handleOk && (on("sherlock") || on("maigret"))) log.add(`Username tools skipped: "${handle}" has characters they can't search`, "skip");
    // nsfw is true only while the mode is on. If the server's guard refuses, the tool runs again without it.
    const tool = async (label, url, key) => { const d = await runSource(label, url, usernameBody(handle, state.adultMode), {}, key); return d === GUARDED ? runSource(label, url, usernameBody(handle, false), {}, key) : d; };
    if (handleOk && on("sherlock")) jobs.push(tool("Sherlock", "/api/recon/sherlock", "sherlock"));
    if (handleOk && on("maigret")) jobs.push(tool("Maigret", "/api/recon/maigret", "maigret"));
    // The adult site check is its own source, and is only ever in the plan with the mode on.
    if (handleOk && plan.has("adult")) jobs.push(runSource(ADULT_SOURCE, "/api/recon/adult-check", { username: handle }, {}, "adultCheck"));
    if (handleOk && on("github")) jobs.push(runSource("GitHub", "/api/recon/github", { username: handle }, {}, "github"));
    if (on("holehe")) jobs.push(runSource("Holehe", "/api/recon/holehe", { email: target }, {}, "holehe"));
    if (on("hibp")) jobs.push(runSource("Breaches", "/api/recon/hibp", { email: target }, {}, "hibp"));
    if (on("gravatar")) jobs.push(runSource("Gravatar", "/api/recon/gravatar", { email: target }, {}, "gravatar"));
    if (on("harvester")) jobs.push(runSource("Domain harvest", "/api/recon/harvester", { domain }, {}, "harvester"));
    else if (isEmail && srcOn("harvester") && isFreeMail(domain)) {
      // A mail provider's hosts say nothing about one of its users.
      c.harvester = { skipped: true, message: `${domain} is a mail provider, so its hosts say nothing about this person.` };
      log.add(`Domain harvest · skipped: ${domain} is a mail provider`, "skip");
    }
    if (on("hunter") && getKey("hunter")) jobs.push(runSource("Hunter.io", "/api/recon/hunter", { domain }, { "X-Hunter-Key": getKey("hunter") }, "hunter"));
    await Promise.all(jobs);
    if (!state.cancelled && handleOk) {
      // Follow-up sources read profile pages, so they are never given an adult or dating site.
      const main = withoutAdult(c);
      const sites = [...(main.sherlock?.results || []), ...(main.maigret?.results || [])].filter((r) => r.confidence !== "false_positive").map((r) => r.site).slice(0, 1000);
      const after = [];
      if (sites.length) after.push(runSource("Profile enrichment", "/api/recon/enrich", { username: handle, sherlock_sites: sites }, {}, "enricher"));
      if (on("platform")) after.push(runSource("Platform check", "/api/recon/platform-check", { username: handle, sherlock_sites: sites }, {}, "platformCheck"));
      // One follow-up call when GitHub has the user: organisations, repos, linked accounts, commit emails.
      if (c.github?.found && sourceOutcome(c.github).state === "ok") after.push(runSource("GitHub details", "/api/recon/github-deep", { username: handle }, {}, "githubDeep"));
      await Promise.all(after);
    }
    // Compare profile pictures once every profile is in. A passive read of public CDN images;
    // it needs at least two to say anything. If it fails, clusters fall back to the other signals.
    const images = state.cancelled ? [] : avatarImages(c, target, type);
    // One picture is still fetched: it cannot be compared, but its thumbnail is shown on the card.
    if (images.length > 0) await runSource("Avatar comparison", "/api/recon/avatar-hash", { images }, {}, "avatarHash");
    const img = [target, ...(withoutAdult(c).maigret?.results || []).map((r) => r.profile?.image)].find((u) => /^https?:\/\/\S+\.(jpe?g|png|gif|webp)(\?|$)/i.test(String(u || "")));
    if (img) { c.reverseImage = img; renderSourceCards(); }
  }

  // A source that was asked and never answered (the run was cancelled) is recorded with the case,
  // so its counts read "unknown" or "at least" now and when the case is opened again.
  const silent = state.cancelled ? [...asked].filter((k) => !(k in c)) : [];
  if (silent.length) c.notAnswered = { keys: silent };
  setRunning(false);
  const { items, facts } = evidence();
  const sum = summary();
  log.finish(sum.log, sum.t.failed);
  renderHead(sum.head);
  // Same evidence as last time: show the report already paid for instead of asking again.
  if (!state.cancelled && prev?.ai && prev.sig === aiSignature(state.collected, state.target, state.type)) state.ai = { ...prev.ai, reused: true };
  renderLedger(); renderSourceCards(); renderAiPanel();
  if (Object.keys(c).length) saveHistory();
}

// ---- a name case: one GitHub profile, on a click -----------------------------------------
// GitHub's search gives a login and nothing else. "Show profile" asks GitHub's record for that
// one login, once, and keeps four text fields in the case (never the picture). The row then
// shows the name and bio and is re-matched against the searched name. A failure or a rate limit
// is kept as unknown, with "Try again" on the row. Nothing here runs without the click.
// Loading and its outcome are said through a polite live region, the row is marked busy, and
// only that row is redrawn: other rows that are loading keep their state, the groups stay as
// they are, and focus stays where the investigator is.
const profileBusy = new Set();
const profileLive = document.createElement("div");
profileLive.className = "sr-only"; profileLive.setAttribute("role", "status"); profileLive.setAttribute("aria-live", "polite");
$("#ledger").after(profileLive);
$("#ledger").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-name-profile]");
  if (!b) return;
  const login = b.dataset.nameProfile, target = state.target;
  if (state.type !== "name" || state.running || profileBusy.has(login)) return;
  // Only a login this case's GitHub rows carry, and only one that has not been read.
  if (!nameCase(state.collected, state.target).people.some((r) => r.source === "GitHub" && r.handle === login && (r.profile === "none" || r.profile === "unknown"))) return;
  profileBusy.add(login);
  // aria-disabled, not disabled: the button keeps focus while it loads.
  b.setAttribute("aria-disabled", "true"); b.innerHTML = h`Loading…<span class="sr-only">: ${login}</span>`;
  b.closest(".ev")?.setAttribute("aria-busy", "true");
  profileLive.textContent = profileStatus(login, "loading");
  let p;
  try { p = readProfile(await post("/api/recon/github", { username: login })); }
  catch (err) { p = { error: err.detail || err.message, error_code: err.status === 429 || err.code === "rate_limited" ? "rate_limited" : "request_failed" }; }
  profileBusy.delete(login);
  if (state.target !== target || state.type !== "name" || state.running) return;
  p ||= { error: "The answer could not be read.", error_code: "bad_response" };
  state.collected.nameProfiles = { ...readProfiles(state.collected.nameProfiles), [login]: p };
  saveHistory();
  const ev = evidence(), key = `cand:github:${login.toLowerCase()}`;
  const it = ev.items.find((x) => x.key === key);
  const row = $$("#ledger .ev[data-row]").find((r) => r.dataset.row === key);
  if (it && row && patchRow($("#ledger"), it, document, { actions: true })) row.setAttribute("aria-busy", "false");
  else renderLedger();
  paintSummary(ev);
  profileLive.textContent = profileStatus(login, "done", p);
});

// ---- similar handles: one handle, on a click ------------------------------------------------
// "Check" asks CrawlR about one handle close to this one (POST /api/recon/handle-probe: GitHub, the
// platform check and Bluesky, never Sherlock or Maigret). There is no "check all": one click is
// one handle. The answer is kept with the case, so opening the case again asks nothing. Whether a
// profile that was read lines up with this case is decided by the identity rules (similar.js),
// and adding one to the case is the investigator's click, per profile, and can be undone.
// Loading and the outcome are said through the polite live region, only that row is redrawn while
// a handle is checked, and focus stays where the investigator is.
const simRow = (variant) => evidence().items.find((i) => i.tier === "similar" && i.sim.variant === variant);
const simOk = () => (state.type === "username" || state.type === "email") && !state.running && !!similarBase(state.target, state.type);
async function simCheck(b) {
  const variant = b.dataset.simCheck, target = state.target;
  const it = simOk() ? simRow(variant) : null;
  // Only a handle this case offers, and only one that has not been checked.
  if (!it || it.sim.state === "checked" || simBusy.has(variant)) return;
  simBusy.add(variant);
  // aria-disabled, not disabled: the button keeps focus while it loads.
  b.setAttribute("aria-disabled", "true"); b.innerHTML = h`Checking…<span class="sr-only">: ${variant}</span>`;
  b.closest(".ev")?.setAttribute("aria-busy", "true");
  profileLive.textContent = probeStatus(variant, "loading");
  const entry = { variant, checked_at: Date.now(), added: [] };
  try {
    const probe = readProbe(await post("/api/recon/handle-probe", { username: variant }), variant);
    if (probe) entry.probe = probe; else entry.error = { error: "The answer could not be read.", error_code: "bad_response" };
  } catch (err) { entry.error = { error: err.detail || err.message, error_code: err.status === 429 || err.code === "rate_limited" ? "rate_limited" : "request_failed" }; }
  simBusy.delete(variant);
  if (state.target !== target || !simOk()) return;
  state.collected.similar = { ...readSimilar(state.collected.similar, similarBase(state.target, state.type)), [variant]: entry };
  saveHistory();
  const ev = evidence(), now = ev.items.find((i) => i.key === it.key);
  const row = $$("#ledger .ev[data-row]").find((r) => r.dataset.row === it.key);
  if (now && row && patchRow($("#ledger"), now, document, { actions: true })) row.setAttribute("aria-busy", "false");
  else renderLedger({ keep: true });
  paintSummary(ev);
  profileLive.textContent = now ? `Checked the handle ${variant}. ${now.sim.summary}` : probeStatus(variant, "done");
}
// Adds one read profile to the case, or takes it out again. The rules are asked again here: a
// profile that does not line up cannot be added, whatever the page shows.
function simToggle(b, on) {
  const id = on ? b.dataset.simAdd : b.dataset.simRemove, variant = b.dataset.variant;
  if (!simOk()) return;
  const all = readSimilar(state.collected.similar, similarBase(state.target, state.type)), e = all[variant];
  const p = simRow(variant)?.sim.profiles.find((x) => x.id === id);
  if (!e?.probe || !p || (on && !p.lineup.canAdd)) return;
  const added = new Set(e.added); if (on) added.add(id); else added.delete(id);
  state.collected.similar = { ...all, [variant]: { ...e, added: [...added] } };
  saveHistory();
  // Where the button was on screen, so the page does not jump under the reader when rows are added above it.
  const top = b.getBoundingClientRect().top;
  renderLedger({ keep: true });
  if (state.live) { const s = summary(); log.resummarize(s.log, s.t.failed); renderHead(s.head); }
  const sec = $$("#ledger .tier").find((t) => t.dataset.tier === "similar");
  if (sec?.classList.contains("collapsed")) sec.querySelector(".tier-head").click();
  const next = $$(`[data-sim-${on ? "remove" : "add"}]`, sec || $("#ledger")).find((x) => (on ? x.dataset.simRemove : x.dataset.simAdd) === id) || sec?.querySelector(".tier-head");
  if (next) { next.focus({ preventScroll: true }); window.scrollBy(0, next.getBoundingClientRect().top - top); }
  profileLive.textContent = `${p.site} ${variant}: ${probeStatus(variant, on ? "added" : "removed")}`;
}
$("#ledger").addEventListener("click", (e) => {
  const check = e.target.closest("[data-sim-check]"), add = e.target.closest("[data-sim-add]"), rm = e.target.closest("[data-sim-remove]");
  if (check) simCheck(check);
  else if (add || rm) simToggle(add || rm, !!add);
});

// ---- history ------------------------------------------------------------------------
const HISTORY_KEY = "crawlr_history", HISTORY_MAX = 50;
export const getHistory = () => store.get(HISTORY_KEY, []);
function saveHistory() {
  const list = getHistory();
  const entry = { id: state.historyId || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: state.target, type: "INVESTIGATE", kind: state.type, timestamp: Date.now(), results: state.collected, aiSummary: state.ai?.summary || null, ai: state.ai || null, deepDive: state.deepDive || null, notes: $("#notes").value, purpose: $("#purpose").value.trim(), v2: true };
  state.historyId = entry.id;
  const idx = list.findIndex((e) => e.id === entry.id);
  if (idx >= 0) { entry.timestamp = list[idx].timestamp; if (list[idx].imported) entry.imported = list[idx].imported; list[idx] = entry; } else list.unshift(entry);
  while (list.length > HISTORY_MAX) list.pop();
  // At most 30 checked thumbnails are stored with a case. When storage is full they are dropped
  // first, from older runs and then this one, before any run is dropped (see writeHistory).
  if (entry.results?.avatarHash) entry.results = { ...entry.results, avatarHash: boundAvatarHash(entry.results.avatarHash) };
  writeHistory(list, entry.id, (l) => store.set(HISTORY_KEY, l));
}
// Takes a saved case's id, or the entry itself (a case file that could not be stored).
export function loadHistory(idOrEntry) {
  const e = typeof idOrEntry === "string" ? getHistory().find((x) => x.id === idOrEntry) : idOrEntry;
  if (!e) return false;
  checker.reset(); linkRow = null;
  // Opening a case runs nothing and changes no session mode. The case shows adult and dating site
  // rows only if it recorded that the mode was on for that run; otherwise any such row is dropped
  // here. That record never switches the mode on.
  const kind = e.kind || detect(e.target);
  Object.assign(state, { live: false, imported: !!e.imported, target: e.target, type: kind, adultMode: false, adultBlocked: "", nameInvalid: "", collected: scrubNames(scrubCollected(e.results || {}, e.target, kind), e.target), ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deepDive: e.deepDive ? normalizeAi(e.deepDive) : null, historyId: e.id, running: false, prev: null, aiBusy: false, ran: e.timestamp, view: "" });
  $("#targetInput").value = e.target;
  // Opening a saved name case puts its qualifiers back and fetches nothing.
  nameError(""); setQualifiers(state.collected.nameQualifiers);
  // A saved phone case puts its country back, so a re-run reads the number the same way.
  if (readRegion(state.collected.phoneRegion)) regionSelect.value = readRegion(state.collected.phoneRegion);
  renderSources(state.type);
  $("#runlog").hidden = true; $("#tabs").hidden = false; tabs.set("findings");
  renderHead(`${TYPE_LABEL[state.type]} · ${e.imported ? "opened from a case file · collected" : "from history ·"} ${new Date(e.timestamp).toLocaleString()}`);
  $("#notes").value = e.notes || ""; $("#purpose").value = e.purpose || ""; updateNotesMeta();
  renderLedger(); renderSourceCards(); renderAiPanel();
  return true;
}
export function clearCase() {
  cancel(); checker.reset(); linkRow = null; nameError(""); setQualifiers(null);
  Object.assign(state, { nameInvalid: "", live: false, imported: false, adultMode: false, adultBlocked: "", target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, prev: null, aiBusy: false, view: "" });
  $("#targetInput").value = ""; $("#mainHead").hidden = true; $("#runlog").hidden = true; $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#bySource").hidden = true;
  $("#emptyState").hidden = false; $("#facts").innerHTML = `<p class="empty flat">Nothing yet.</p>`; $("#notes").value = ""; $("#purpose").value = ""; updateNotesMeta();
  renderSources(""); renderAiPanel(); $("#targetDetected").innerHTML = ""; $("#reportSection").hidden = true;
  $("#brief").hidden = true; $("#tabs").hidden = true; tabs.set("findings"); $("#bySourceEmpty").hidden = false;
  $("#caseBar").hidden = true; $("#verdict").innerHTML = ""; $("#identity").hidden = true; $("#identity").innerHTML = "";
}

// ---- notes --------------------------------------------------------------------------
let notesTimer;
function updateNotesMeta() {
  $("#notesCount").textContent = `${fmtNum($("#notes").value.length)} chars`;
  casePrint($("#casePrint"), { purpose: $("#purpose").value, notes: $("#notes").value, ran: state.target ? state.ran : 0 });
}
function loadNotes() { $("#notes").value = ""; $("#purpose").value = ""; updateNotesMeta(); }
const noteSave = () => {
  updateNotesMeta(); $("#notesStatus").textContent = "Saving…";
  clearTimeout(notesTimer);
  notesTimer = setTimeout(() => { if (state.target) saveHistory(); $("#notesStatus").textContent = "Saved"; }, 600);
};
$("#notes").addEventListener("input", noteSave);
$("#purpose").addEventListener("input", noteSave);

// ---- export ------------------------------------------------------------------------------
export function exportCase() {
  if (!state.target) return;
  const purpose = $("#purpose").value.trim();
  // Built in evidence.js so the export rules (the adult section included) can be tested.
  const md = caseMarkdown({ collected: state.collected, target: state.target, type: state.type, ran: state.ran, tallyLine: tallyText(tally()), failed: failedSources(), purpose, ai: state.ai, deep: state.deepDive, notes: $("#notes").value });
  const name = `crawlr-${slug(state.target)}`;
  const done = (fn) => () => { fn(); closeModal(); };
  openModal({
    title: "Export case",
    body: `<p class="modal-p">Everything is built in your browser. Nothing is uploaded.</p>
      <ul class="export-list"><li><b>Print or PDF</b> opens the print dialog with a clean, light layout. Choose "Save as PDF" there.</li><li><b>HTML</b> is one self-contained page you can send or archive.</li><li><b>Markdown</b> has the ledger, facts, AI reports and notes.</li><li><b>Case file</b> is the raw data from every source as JSON, with your notes. Open it in CrawlR on another machine from History.</li></ul>`,
    actions: [
      { label: "Case file", onClick: done(() => download(`${name}.json`, JSON.stringify(buildCaseFile({ mode: "investigate", target: state.target, type: state.type, ran: state.ran, collected: state.collected, ai: state.ai, deep: state.deepDive, notes: $("#notes").value, purpose }), null, 2), "application/json")) },
      { label: "Markdown", onClick: done(() => download(`${name}.md`, md, "text/markdown")) },
      { label: "HTML", onClick: async () => { const html = await standaloneHtml(`CrawlR case: ${state.target}`, $("#main"), $("#aside")); download(`${name}.html`, html, "text/html"); closeModal(); } },
      { label: "Print or PDF", primary: true, onClick: () => { closeModal(); setTimeout(() => window.print(), 50); } },
    ],
  });
}
