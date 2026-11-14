// Investigate mode: run sources, build the ledger, AI on request, deep dive, history, notes, export.
import { howTag, $, $$, h, raw, esc, link, store, toast, post, postAi, ApiError, getKey, aiAvailable, aiCost, freeLeft, userAiKey, providerName, detect, TYPE_LABEL, fmtNum, fmtAgo, plural, sourceOutcome, sourceHasResults, sourceCoverage, coverageText, statusForAi, sourceTally, tallyText, download, slug } from "./core.js";
import { buildEvidence, ledgerTiers, accountsFor, isFinding, factsFor, avatarImages, sourcePlan, emailParts, isFreeMail } from "./evidence.js";
import { sourceCards } from "./renderers.js";
import { normalizeAi, markdown, summaryBlock, aiStartHtml, copyPrompt, parseReply } from "./ai.js";
import { investigateBrief } from "./brief.js";
import { reportHtml } from "./report.js";
import { openModal, closeModal } from "./ui.js";
import { makeLog, renderTiers, bindLedger, renderFacts, renderIdentityFacts, failedNotice, diffRuns, diffNotice, standaloneHtml, makeTabs, setTabCount, renderBrief, casePrint } from "./workbench.js";
import { buildCaseFile } from "./casefile.js";

// ---- sources ---------------------------------------------------------------
// AI analysis is not in this list on purpose: it never runs on its own. The investigator
// asks for it from the AI panel once the sources are in, and sees what it will cost first.
export const SOURCES = [
  { id: "sherlock", how: "guess",  name: "Sherlock",        desc: "username across 400+ sites",            types: ["username"],          on: true },
  { id: "maigret", how: "guess",   name: "Maigret",         desc: "username across 500 top sites, reads profile data where it can", types: ["username"], on: true, extra: { id: "nsfw", label: "include adult and dating sites", on: false } },
  { id: "github", how: "record",    name: "GitHub",          desc: "profile, organisations, repos, linked accounts and commit emails", types: ["username"], on: true },
  { id: "platform", how: "guess",  name: "Platform check",  desc: "reads the profile page on major platforms, and says when a site blocks the check", types: ["username"], on: true },
  { id: "holehe", how: "guess",    name: "Holehe",          desc: "accounts registered to this email",     types: ["email"],             on: true },
  { id: "hibp", how: "index",      name: "Breaches",        desc: "known credential exposures",            types: ["email"],             on: true },
  { id: "gravatar", how: "record",  name: "Gravatar",        desc: "avatar profile for this email",         types: ["email"],             on: true },
  { id: "hunter", how: "index",    name: "Hunter.io",       desc: "addresses on the email's domain",       types: ["email"],             on: false, pro: "hunter" },
  { id: "harvester", how: "index", name: "Domain harvest",  desc: "hosts and other addresses on this email's domain, from 8 public sources. Skipped for mail providers such as gmail.com", types: ["email"], on: true },
  { id: "hash", how: "index",      name: "Hash lookup",     desc: "MalwareBazaar, CIRCL, OTX, ThreatFox",  types: ["hash"],              on: true },
  { id: "phone", how: "index",     name: "Phone lookup",    desc: "carrier and line type",                 types: ["phone"],             on: true, pro: "numlookup", proOptional: true },
  { id: "active", how: "record",    name: "Active techniques", desc: "profile scraping for Deep Dive. May notify the target.", types: ["username"], on: false, warn: true },
];

const srcState = store.get("crawlr_v2_sources", {});
export const srcOn = (id) => (id in srcState ? !!srcState[id] : SOURCES.find((s) => s.id === id)?.on ?? false);
const setSrc = (id, v) => { srcState[id] = v; store.set("crawlr_v2_sources", srcState); };
// Adult sites are opt-in: only an explicit "true" turns them on.
const nsfwOn = () => srcState["maigret.nsfw"] === true;

export function renderSources(type) {
  const box = $("#sources");
  const rows = SOURCES.filter((s) => !type || s.types.includes(type));
  box.innerHTML = rows.map((s) => h`
    <div class="source ${srcOn(s.id) ? "" : "off"}" data-src="${s.id}">
      <div>
        <div class="name" id="src-${s.id}">${s.name}${s.warn ? raw(' <span class="tag warn">caution</span>') : ""}${s.pro && !s.proOptional ? raw(' <span class="tag violet">your key</span>') : ""}</div>
        <div class="desc" id="srcd-${s.id}">${raw(howTag(s.how))}${s.desc}${s.pro && s.proOptional && !getKey(s.pro) ? raw(' <span class="tag">links only without a key</span>') : ""}</div>
        ${s.extra ? raw(h`<label class="source-extra"><input type="checkbox" data-extra="${s.extra.id}" ${nsfwOn() ? "checked" : ""}>${s.extra.label}</label>`) : ""}
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-label="${s.name}" aria-labelledby="src-${s.id}" aria-describedby="srcd-${s.id}"><span></span></label>
    </div>`).join("");
  if (!rows.length) box.innerHTML = h`<p class="empty flat">Type a target to see which sources apply.</p>`;
  paintCount();
}
// The Sources button shows how many are switched on for this target type.
function paintCount() {
  const on = $$("#sources [data-toggle]").filter((el) => el.checked).length, all = $$("#sources [data-toggle]").length;
  $("#sourcesCount").textContent = all ? `${on} of ${all}` : "";
}
$("#sources").addEventListener("change", (e) => {
  const t = e.target.dataset.toggle, x = e.target.dataset.extra;
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
  }
  if (x) setSrc(`maigret.${x}`, e.target.checked);
});

// ---- run log + result tabs -----------------------------------------------------
const log = makeLog($("#runlog"));
const tabs = makeTabs($("#tabs"));

// ---- state -------------------------------------------------------------------
// prev: { keys, ts, ai, sig } from the last saved run of the same target, for the diff.
// view: which identity cluster "What we know" shows; "" means the primary one.
export const state = { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, running: false, cancelled: false, controller: null, prev: null, aiBusy: false, ran: 0, view: "" };
const checkKey = () => `crawlr_checked_${state.target}`;
const checked = () => new Set(store.get(checkKey(), []));

const SRC_NAME = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", holehe: "Holehe", hibp: "Breaches", gravatar: "Gravatar", hunter: "Hunter.io", harvester: "Domain harvest", hash: "Hash lookup", phone: "Phone lookup", enricher: "Profile enrichment", platformCheck: "Platform check", profileScrape: "Profile scrape", githubDeep: "GitHub details", avatarHash: "Avatar comparison" };
// Every count of sources on this page comes from this one tally.
const tally = () => sourceTally(state.collected, SRC_NAME);
const failedSources = () => tally().rows.filter((r) => r.state === "failed");
// Identical evidence means an identical AI answer, so a re-run can reuse the last one.
const signature = (items, facts) => JSON.stringify([accountsFor(items), items.filter((i) => i.tier === "flag").map((i) => i.key), facts.map((f) => [f.k, f.v])]);

// ---- ledger + facts -------------------------------------------------------------
function evidence() {
  const ev = buildEvidence(state.collected, state.target, state.type);
  // Leads and host inventory are not findings, so they are not part of "what changed".
  const diff = !state.running && state.prev ? diffRuns(state.prev.keys, ev.items.filter(isFinding)) : null;
  if (diff) { const added = new Set(diff.added.map((i) => i.key)); for (const it of ev.items) it.isNew = added.has(it.key); }
  return { ...ev, diff };
}
function renderLedger() {
  const ev = evidence();
  const { items, facts, diff } = ev;
  $("#emptyState").hidden = true;
  $("#notices").innerHTML = failedNotice(failedSources()) + (diff ? diffNotice(diff, state.prev.ts) : "");
  const nothing = state.running
    ? `<div class="empty"><h3>Collecting</h3><p>Findings appear here as each source answers.</p></div>`
    : failedSources().length
      ? `<div class="empty"><h3>No findings from the sources that answered</h3><p>Some sources failed, so this is not a clean negative. See the notice above and try again.</p></div>`
      : `<div class="empty"><h3>Nothing found</h3><p>Every source answered and none had a result for this target.</p></div>`;
  renderTiers($("#ledger"), items, ledgerTiers(state.target, state.type), checked(), nothing);
  const emptyFacts = state.running ? "Collecting…" : "No facts extracted yet.";
  // A person case shows one identity at a time, so one person's name never sits beside another's.
  // state.view is only ever what the investigator picked; with no pick the primary cluster shows.
  if (ev.identity.views.length) renderIdentityFacts($("#facts"), ev.identity, (id) => factsFor(ev, id), state.view, emptyFacts);
  else renderFacts($("#facts"), facts, emptyFacts);
  setTabCount($("#tabFindings"), "Findings", items.filter(isFinding).length);
  // The written brief waits for the run to finish, so it never describes half a picture.
  renderBrief($("#brief"), $("#briefBody"), state.running || !state.target ? { rows: [], actions: [] } : investigateBrief({ collected: state.collected, items, facts, identity: ev.identity, failed: failedSources(), type: state.type, target: state.target }));
}
bindLedger($("#ledger"), checkKey);
$("#facts").addEventListener("change", (e) => { if (e.target.matches("[data-cluster-pick]")) { state.view = e.target.value; renderLedger(); $("#factsPick")?.focus(); } });

function renderSourceCards() {
  const c = state.collected;
  const cards = [];
  // Every source that ran gets a card: with results, "answered, nothing found", or failed.
  const push = (id, d, extra) => { if (d !== undefined && d !== null && !d.skipped && sourceCards[id]) { const html = sourceCards[id](d, extra); if (html) cards.push(html); } };
  push("hash", c.hash); push("phone", c.phone);
  push("hibp", c.hibp); push("holehe", c.holehe); push("github", c.github, c.githubDeep); push("githubDeep", c.githubDeep, c.github); push("gravatar", c.gravatar);
  push("sherlock", c.sherlock); push("maigret", c.maigret); push("platformCheck", c.platformCheck);
  push("enricher", c.enricher); push("avatarHash", c.avatarHash); push("profileScrape", c.profileScrape); push("hunter", c.hunter); push("harvester", c.harvester);
  if (c.nameSearch) cards.push(sourceCards.nameSearch(c.nameSearch));
  if (c.reverseImage) cards.push(sourceCards.reverseImage(c.reverseImage));
  $("#bySource").hidden = !cards.length; $("#bySourceEmpty").hidden = !!cards.length;
  setTabCount($("#tabSources"), "By source", tally().ran);
  $("#sourceCards").innerHTML = cards.join("");
}

function renderHead(meta) {
  $("#mainHead").hidden = false;
  $("#caseTarget").textContent = state.target;
  $("#caseMeta").textContent = meta || TYPE_LABEL[state.type] || "";
}

// ---- AI panel ---------------------------------------------------------------------
function profileUrls() {
  const urls = [];
  for (const k of ["sherlock", "maigret"]) for (const r of state.collected[k]?.results || []) if (r.url && r.confidence !== "false_positive") urls.push({ site: r.site, url: r.url });
  for (const r of state.collected.platformCheck?.results || []) if (r.found && r.url) urls.push({ site: r.platform, url: r.url });
  const seen = new Set(); return urls.filter((u) => /^https?:\/\//i.test(u.url) && !seen.has(u.url) && seen.add(u.url)).slice(0, 20);
}
const hasData = () => Object.values(state.collected).some((v) => v && (typeof v === "object" ? sourceOutcome(v).state !== "error" : true));

// What the report will cover, said for the kind of target on screen.
const AI_PITCH = {
  username: "Get a written report: who this most likely is, what links the accounts, and what to check next.",
  email: "Get a written report: who this most likely is, what links the accounts, and what to check next.",
  hash: "Get a written report: what this file is, how sure the sources are, and what to do with it.",
  phone: "Get a written report: what the line type and carrier suggest and what to check next.",
  name: "Get a search plan: how to narrow people-search results for this name and what to check first.",
};
function renderAiPanel() {
  const box = $("#aiPanel");
  const note = (t) => `<p class="empty flat">${esc(t)}</p>`;
  if (!state.ai) {
    if (state.aiBusy) { box.innerHTML = `<p class="empty flat" role="status">Asking ${esc(providerName())}…</p>`; return; }
    if (state.running) { box.innerHTML = note("Available when the sources finish. AI never runs on its own."); return; }
    if (!state.target || !hasData()) { box.innerHTML = note(state.target ? "Nothing to analyze yet." : "Run a target first. AI analysis is optional and only runs when you ask."); return; }
    box.innerHTML = aiStartHtml("inv", AI_PITCH[state.type] || AI_PITCH.username);
    return;
  }
  const canDeep = srcOn("active") && profileUrls().length && aiAvailable();
  const deepBtn = state.deepDive
    ? `<button class="btn btn-sm" type="button" data-open-report="deep">Deep Dive report</button>`
    : canDeep ? `<button class="btn btn-sm" type="button" id="deepDiveBtn">Deep Dive…</button>`
    : srcOn("active") ? "" : `<span class="hint-inline">Deep Dive needs Active techniques on</span>`;
  box.innerHTML = summaryBlock(state.ai, { reportId: "summary", attr: "data-open-report", deepDive: deepBtn }).replace(">Full report<", ">Read report<");
  renderReport();
}

// The full investigation report lives in the main column, right under the case header.
function renderReport() {
  const sec = $("#reportSection");
  if (!state.ai?.summary) { sec.hidden = true; return; }
  sec.hidden = false;
  const { items, facts } = buildEvidence(state.collected, state.target, state.type);
  $("#reportBody").innerHTML = reportHtml({ ai: state.ai, target: state.target, items, facts, collected: state.collected });
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
    body: `<div class="report">${markdown(ai.summary)}</div>`,
    actions: [{ label: "Copy markdown", onClick: () => navigator.clipboard?.writeText(ai.summary).then(() => toast("Copied")) }, { label: "Close", primary: true, onClick: closeModal }],
  });
}

// Everything the model is told about what ran and how it went.
function aiPayload(extra = {}) {
  const c = state.collected;
  const { items } = buildEvidence(c, state.target, state.type);
  const source_status = Object.fromEntries(tally().rows.filter((r) => r.state !== "skipped").map((r) => [r.name, statusForAi(r)]));
  return {
    target: state.target, target_type: state.type, accounts: accountsFor(items), source_status,
    hash: c.hash || null, phone: c.phone || null, github_deep: c.githubDeep || null,
    sherlock: c.sherlock || null, maigret: c.maigret || null, holehe: c.holehe || null, harvester: c.harvester || null, hibp: c.hibp || null,
    gravatar: c.gravatar || null, github: c.github || null, enricher: c.enricher || null, platform_check: c.platformCheck || null,
    hunter: c.hunter || null, name_search: c.nameSearch ? { name: c.nameSearch } : null, active_techniques: srcOn("active"), ...extra,
  };
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
      const data = await postAi("/api/analyze/deep-dive", aiPayload({ shodan: null, name_search: null, profile_scrape: scraped, active_techniques: true }));
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
    const ok = (data.results || []).filter((r) => r.confidence !== "false_positive");
    const v = ok.filter((r) => r.verified).length;
    return ok.length ? [v && `${plural(v, "profile")} read`, `${ok.length - v} unverified`].filter(Boolean).join(", ") : "";
  }
  if (key === "githubDeep") return "";
  if (key === "avatarHash") { const r = data?.results || [], n = r.filter((x) => x.hash && !x.error).length; return n === r.length ? `${plural(n, "image")} compared` : ""; }
  if (key === "platformCheck" && (data?.results || []).some((r) => r.state)) { const r = data.results, n = (st) => r.filter((x) => x.state === st).length; return [n("found") && `${n("found")} read`, n("blocked") && `${n("blocked")} blocked by site`, n("unknown") && `${n("unknown")} unclear`].filter(Boolean).join(", "); }
  if (key === "harvester") return [data?.hosts?.length && plural(data.hosts.length, "host"), data?.emails?.length && plural(data.emails.length, "address", "addresses")].filter(Boolean).join(", ");
  const n = data?.total ?? data?.breaches?.length ?? data?.results?.filter?.((r) => r.found === true).length ?? (data?.found ? 1 : 0);
  return n ? `${fmtNum(n)} result${n === 1 ? "" : "s"}` : "";
}
async function runSource(label, url, body, headers, key) {
  const row = log.add(label);
  try {
    const data = await post(url, body, headers, state.controller?.signal);
    state.collected[key] = data;
    const o = sourceOutcome(data);
    const found = resultText(key, data);
    // A source whose every part was blocked or errored did not answer: that is a failure, not "nothing found".
    const cv = sourceCoverage(data);
    if (o.state === "error") log.set(row, `${label}: ${o.text}`, "err", o.detail);
    else if (o.state === "skipped") log.set(row, `${label} · skipped`, "skip");
    else if (cv && cv.total > 0 && cv.answered === 0) log.set(row, `${label} · ${cv.failedText}`, "err");
    else if (cv && cv.answered < cv.total) log.set(row, `${label} · ${[found, coverageText(cv)].filter(Boolean).join(" · ")}`, "done");
    else if (!sourceHasResults(data)) log.set(row, `${label} · nothing found`, "none");
    else log.set(row, `${label} · ${found || "done"}`, "done");
    renderLedger(); renderSourceCards();
    return data;
  } catch (err) {
    if (err.code === "cancelled") { log.set(row, `${label} · cancelled`, "skip"); return null; }
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
  b.classList.toggle("btn-primary", !on); b.classList.toggle("btn-danger", on);
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
  if (last) { const ev = buildEvidence(last.results || {}, last.target, last.kind); prev = { keys: ev.items.filter(isFinding).map((i) => i.key), ts: last.timestamp, ai: last.ai || null, sig: signature(ev.items, ev.facts) }; }

  Object.assign(state, { target, type, collected: {}, ai: null, deepDive: null, historyId: null, cancelled: false, controller: new AbortController(), prev, aiBusy: false, ran: Date.now(), view: "" });
  store.del(checkKey());
  setRunning(true);
  $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#emptyState").hidden = true; $("#bySource").hidden = true; $("#bySourceEmpty").hidden = false;
  $("#tabs").hidden = false; tabs.set("findings"); setTabCount($("#tabSources"), "By source", 0);
  renderHead(); loadNotes(); $("#reportSection").hidden = true;
  log.start();
  renderLedger(); renderAiPanel();

  // What runs for this kind of target is decided in one place (sourcePlan), then filtered by the switches.
  const plan = new Set(sourcePlan(type, target));
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
      const k = getKey("numlookup");
      const d = await runSource("Phone lookup", "/api/phone/lookup", { phone: target }, k ? { "X-Numlookup-Key": k } : {}, "phone");
      if (!d && k && !state.cancelled) {
        // Saved key was rejected: still give the user the lookup links, and say why carrier data is missing.
        const d2 = await runSource("Phone lookup (links only)", "/api/phone/lookup", { phone: target }, {}, "phone");
        if (d2) { d2.api_error = "Your NumLookup key was rejected. Update or clear it in Settings."; renderSourceCards(); }
      }
    }
  } else if (type === "name") {
    c.nameSearch = target; renderSourceCards(); log.add("People search links ready", "done");
  } else {
    const jobs = [];
    if (isUser && !handleOk && (on("sherlock") || on("maigret"))) log.add(`Username tools skipped: "${handle}" has characters they can't search`, "skip");
    if (handleOk && on("sherlock")) jobs.push(runSource("Sherlock", "/api/recon/sherlock", { username: handle }, {}, "sherlock"));
    if (handleOk && on("maigret")) jobs.push(runSource("Maigret", "/api/recon/maigret", { username: handle, nsfw: nsfwOn() }, {}, "maigret"));
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
      const sites = [...(c.sherlock?.results || []), ...(c.maigret?.results || [])].filter((r) => r.confidence !== "false_positive").map((r) => r.site).slice(0, 1000);
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
    if (images.length > 1) await runSource("Avatar comparison", "/api/recon/avatar-hash", { images }, {}, "avatarHash");
    const img = [target, ...(c.maigret?.results || []).map((r) => r.profile?.image)].find((u) => /^https?:\/\/\S+\.(jpe?g|png|gif|webp)(\?|$)/i.test(String(u || "")));
    if (img) { c.reverseImage = img; renderSourceCards(); }
  }

  setRunning(false);
  const { items, facts } = evidence();
  const t = tally(), found = items.filter(isFinding).length;
  log.finish(`${state.cancelled ? "Cancelled · partial results · " : ""}${tallyText(t)} · ${plural(found, "finding")}`, t.failed);
  renderHead(`${TYPE_LABEL[type]} · ${plural(found, "finding")} · ${tallyText(t)}${state.cancelled ? " · cancelled, partial" : ""}`);
  // Same evidence as last time: show the report already paid for instead of asking again.
  if (!state.cancelled && prev?.ai && prev.sig === signature(items, facts)) state.ai = { ...prev.ai, reused: true };
  renderLedger(); renderSourceCards(); renderAiPanel();
  if (Object.keys(c).length) saveHistory();
}

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
  if (!store.set(HISTORY_KEY, list)) { list.splice(Math.floor(list.length / 2)); store.set(HISTORY_KEY, list); }
}
// Takes a saved case's id, or the entry itself (a case file that could not be stored).
export function loadHistory(idOrEntry) {
  const e = typeof idOrEntry === "string" ? getHistory().find((x) => x.id === idOrEntry) : idOrEntry;
  if (!e) return false;
  Object.assign(state, { target: e.target, type: e.kind || detect(e.target), collected: e.results || {}, ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deepDive: e.deepDive ? normalizeAi(e.deepDive) : null, historyId: e.id, running: false, prev: null, aiBusy: false, ran: e.timestamp, view: "" });
  $("#targetInput").value = e.target;
  renderSources(state.type);
  $("#runlog").hidden = true; $("#tabs").hidden = false; tabs.set("findings");
  renderHead(`${TYPE_LABEL[state.type]} · ${e.imported ? "opened from a case file · collected" : "from history ·"} ${new Date(e.timestamp).toLocaleString()}`);
  $("#notes").value = e.notes || ""; $("#purpose").value = e.purpose || ""; updateNotesMeta();
  renderLedger(); renderSourceCards(); renderAiPanel();
  return true;
}
export function clearCase() {
  cancel();
  Object.assign(state, { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, prev: null, aiBusy: false, view: "" });
  $("#targetInput").value = ""; $("#mainHead").hidden = true; $("#runlog").hidden = true; $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#bySource").hidden = true;
  $("#emptyState").hidden = false; $("#facts").innerHTML = `<p class="empty flat">Nothing yet.</p>`; $("#notes").value = ""; $("#purpose").value = ""; updateNotesMeta();
  renderSources(""); renderAiPanel(); $("#targetDetected").innerHTML = ""; $("#reportSection").hidden = true;
  $("#brief").hidden = true; $("#tabs").hidden = true; tabs.set("findings"); $("#bySourceEmpty").hidden = false;
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
  const ev = buildEvidence(state.collected, state.target, state.type);
  const { items, facts, identity } = ev;
  const failed = failedSources();
  const purpose = $("#purpose").value.trim();
  const main = identity.views.find((v) => v.primary);
  const others = identity.views.filter((v) => v.named && !v.primary);
  const md = [`# CrawlR case: ${state.target}`, `Generated ${new Date().toISOString()} · ${TYPE_LABEL[state.type]}${state.ran ? ` · collected ${new Date(state.ran).toISOString()}` : ""}`, tallyText(tally()), "", ...(purpose ? [`**Purpose:** ${purpose}`, ""] : []),
    "> Findings come from third-party public sources and can be wrong. Unverified items are leads, not facts. A profile that exists is not proof of who owns it, and leads are places to look, not findings.", "",
    ...(failed.length ? ["## Sources that failed", ...failed.map((f) => `- **${f.name}:** ${f.text} (unknown, not a negative result)`), ""] : []),
    `## What we know${main ? ` (primary identity: ${main.label}, from ${main.sites.join(", ")})` : ""}`, ...(facts.length ? facts.map((f) => `- **${f.k}:** ${f.v} _(${f.source})_`) : ["- Nothing extracted"]), "",
    ...(others.length ? ["## Other people using this handle", ...others.map((v) => `- **${v.label}:** ${v.sites.join(", ")}`), ""] : []),
    ...ledgerTiers(state.target, state.type).flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...rows.map((i) => `- ${i.url ? `[${i.what}](${i.url})` : i.what}${i.meta ? ` · ${i.meta}` : ""} _(${i.source})_`), ""] : []; }),
    ...(state.ai ? ["## AI analysis", state.ai.summary, ""] : []),
    ...(state.deepDive ? ["## Deep Dive", state.deepDive.summary, ""] : []),
    ...($("#notes").value.trim() ? ["## Notes", $("#notes").value.trim(), ""] : []),
  ].join("\n");
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
