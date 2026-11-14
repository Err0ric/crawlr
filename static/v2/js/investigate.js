// Investigate mode: run sources, build the ledger, AI on request, deep dive, history, notes, export.
import { $, $$, h, raw, esc, link, store, toast, post, postAi, ApiError, getKey, aiAvailable, aiCost, freeLeft, userAiKey, providerName, detect, TYPE_LABEL, fmtNum, fmtAgo, plural, sourceOutcome, download, slug } from "./core.js";
import { buildEvidence, TIERS, accountsFor } from "./evidence.js";
import { sourceCards } from "./renderers.js";
import { normalizeAi, markdown, summaryBlock } from "./ai.js";
import { reportHtml } from "./report.js";
import { openModal, closeModal } from "./ui.js";
import { makeLog, renderTiers, bindLedger, renderFacts, failedNotice, diffRuns, diffNotice, standaloneHtml } from "./workbench.js";

// ---- sources ---------------------------------------------------------------
// AI analysis is not in this list on purpose: it never runs on its own. The investigator
// asks for it from the AI panel once the sources are in, and sees what it will cost first.
export const SOURCES = [
  { id: "sherlock",  name: "Sherlock",        desc: "username across 400+ sites",            types: ["username", "email"], on: true },
  { id: "maigret",   name: "Maigret",         desc: "username across 500 top sites, reads profile data where it can", types: ["username", "email"], on: true, extra: { id: "nsfw", label: "include adult and dating sites", on: false } },
  { id: "github",    name: "GitHub",          desc: "profile, bio, linked email",            types: ["username"],          on: true },
  { id: "platform",  name: "Platform check",  desc: "profile URL probes on major platforms", types: ["username", "email"], on: true },
  { id: "holehe",    name: "Holehe",          desc: "accounts registered to this email",     types: ["email"],             on: true },
  { id: "hibp",      name: "Breaches",        desc: "known credential exposures",            types: ["email"],             on: true },
  { id: "gravatar",  name: "Gravatar",        desc: "avatar profile for this email",         types: ["email"],             on: true },
  { id: "hunter",    name: "Hunter.io",       desc: "addresses on the email's domain",       types: ["email"],             on: false, pro: "hunter" },
  { id: "harvester", name: "Domain harvest",  desc: "other addresses on this email's domain, from 8 public sources", types: ["email"], on: true },
  { id: "hash",      name: "Hash lookup",     desc: "MalwareBazaar, CIRCL, OTX, ThreatFox",  types: ["hash"],              on: true },
  { id: "phone",     name: "Phone lookup",    desc: "carrier and line type",                 types: ["phone"],             on: true, pro: "numlookup", proOptional: true },
  { id: "active",    name: "Active techniques", desc: "profile scraping for Deep Dive. May notify the target.", types: ["username", "email"], on: false, warn: true },
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
        <div class="desc" id="srcd-${s.id}">${s.desc}${s.pro && s.proOptional && !getKey(s.pro) ? raw(' <span class="tag">links only without a key</span>') : ""}</div>
        ${s.extra ? raw(h`<label class="source-extra"><input type="checkbox" data-extra="${s.extra.id}" ${nsfwOn() ? "checked" : ""}>${s.extra.label}</label>`) : ""}
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-labelledby="src-${s.id}" aria-describedby="srcd-${s.id}"><span></span></label>
    </div>`).join("");
  if (!rows.length) box.innerHTML = h`<p class="empty flat">Enter a target to see which sources apply.</p>`;
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
  }
  if (x) setSrc(`maigret.${x}`, e.target.checked);
});

// ---- run log -----------------------------------------------------------------
const log = makeLog($("#runlog"));

// ---- state -------------------------------------------------------------------
// prev: { keys, ts, ai, sig } from the last saved run of the same target, for the diff.
export const state = { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, running: false, cancelled: false, controller: null, prev: null, aiBusy: false };
const checkKey = () => `crawlr_checked_${state.target}`;
const checked = () => new Set(store.get(checkKey(), []));

const SRC_NAME = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", holehe: "Holehe", hibp: "Breaches", gravatar: "Gravatar", hunter: "Hunter.io", harvester: "Domain harvest", hash: "Hash lookup", phone: "Phone lookup", enricher: "Profile enrichment", platformCheck: "Platform check", profileScrape: "Profile scrape" };
const outcomes = () => Object.entries(state.collected).filter(([k, v]) => v && typeof v === "object" && SRC_NAME[k]).map(([k, v]) => ({ key: k, name: SRC_NAME[k], ...sourceOutcome(v) }));
const failedSources = () => outcomes().filter((o) => o.state === "error");
// Identical evidence means an identical AI answer, so a re-run can reuse the last one.
const signature = (items, facts) => JSON.stringify([accountsFor(items), items.filter((i) => i.tier === "flag").map((i) => i.key), facts.map((f) => [f.k, f.v])]);

// ---- ledger + facts -------------------------------------------------------------
function evidence() {
  const ev = buildEvidence(state.collected, state.target);
  const diff = !state.running && state.prev ? diffRuns(state.prev.keys, ev.items) : null;
  if (diff) { const added = new Set(diff.added.map((i) => i.key)); for (const it of ev.items) it.isNew = added.has(it.key); }
  return { ...ev, diff };
}
function renderLedger() {
  const { items, facts, diff } = evidence();
  $("#emptyState").hidden = true;
  $("#notices").innerHTML = failedNotice(failedSources()) + (diff ? diffNotice(diff, state.prev.ts) : "");
  const nothing = state.running
    ? `<div class="empty"><h3>Collecting</h3><p>Findings appear here as each source answers.</p></div>`
    : failedSources().length
      ? `<div class="empty"><h3>No findings from the sources that answered</h3><p>Some sources failed, so this is not a clean negative. See the notice above and try again.</p></div>`
      : `<div class="empty"><h3>Nothing found</h3><p>Every source answered and none had a result for this target.</p></div>`;
  renderTiers($("#ledger"), items, TIERS, checked(), nothing);
  renderFacts($("#facts"), facts, state.running ? "Collecting…" : "No facts extracted yet.");
}
bindLedger($("#ledger"), checkKey);

function renderSourceCards() {
  const c = state.collected;
  const cards = [];
  const push = (id, d) => { if (d !== undefined && d !== null && sourceCards[id]) { const html = sourceCards[id](d); if (html) cards.push(html); } };
  push("hash", c.hash); push("phone", c.phone);
  push("hibp", c.hibp); push("holehe", c.holehe); push("github", c.github); push("gravatar", c.gravatar);
  push("sherlock", c.sherlock); push("maigret", c.maigret); push("platformCheck", c.platformCheck);
  push("enricher", c.enricher); push("profileScrape", c.profileScrape); push("hunter", c.hunter); push("harvester", c.harvester);
  if (c.nameSearch) cards.push(sourceCards.nameSearch(c.nameSearch));
  if (c.reverseImage) cards.push(sourceCards.reverseImage(c.reverseImage));
  $("#bySource").hidden = !cards.length;
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

function renderAiPanel() {
  const box = $("#aiPanel");
  const note = (t) => `<p class="empty flat">${esc(t)}</p>`;
  if (!state.ai) {
    if (state.aiBusy) { box.innerHTML = `<p class="empty flat" role="status">Asking ${esc(providerName())}…</p>`; return; }
    if (state.running) { box.innerHTML = note("Available when the sources finish. AI never runs on its own."); return; }
    if (!state.target || !hasData()) { box.innerHTML = note(state.target ? "Nothing to analyze yet." : "Run a target first. AI analysis is optional and only runs when you ask."); return; }
    if (!aiAvailable()) { box.innerHTML = `${note("Add a Claude or Gemini key to turn on AI analysis.")}<button class="btn btn-sm" type="button" data-open-settings>Open settings</button>`; return; }
    const out = !userAiKey() && freeLeft() <= 0;
    box.innerHTML = h`<p class="ai-pitch">Get a written report: who this most likely is, what links the accounts, and what to check next.</p>
      <button class="btn btn-primary btn-block" type="button" id="aiRunBtn" ${out ? "disabled" : ""}>Analyze with AI</button>
      <p class="ai-cost">${aiCost()}</p>`;
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
  const { items, facts } = buildEvidence(state.collected, state.target);
  $("#reportBody").innerHTML = reportHtml({ ai: state.ai, target: state.target, items, facts, collected: state.collected });
  $("#reportMeta").textContent = [state.ai.model, state.ai.ai_source === "house" ? "free tier" : "", state.ai.reused ? "from your last run, no credit used" : state.ai.cached ? "cached, no credit used" : ""].filter(Boolean).join(" · ");
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
  if (e.target.id === "aiRunBtn") runAi();
});

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
  const { items } = buildEvidence(c, state.target);
  const source_status = Object.fromEntries(outcomes().map((o) => [o.name, o.state === "error" ? `failed: ${o.text}` : o.state === "none" ? "not found" : "ok"]));
  return {
    target: state.target, accounts: accountsFor(items), source_status,
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
    return ok.length ? [v && `${v} confirmed`, `${ok.length - v} possible`].filter(Boolean).join(", ") : "";
  }
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
    if (o.state === "error") log.set(row, `${label}: ${o.text}`, "err", o.detail);
    else if (o.state === "skipped") log.set(row, `${label} · skipped`, "skip");
    else if (o.state === "none" || !found) log.set(row, `${label} · nothing found`, "none");
    else log.set(row, `${label} · ${found}`, "done");
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
  if (last) { const ev = buildEvidence(last.results || {}, last.target); prev = { keys: ev.items.map((i) => i.key), ts: last.timestamp, ai: last.ai || null, sig: signature(ev.items, ev.facts) }; }

  Object.assign(state, { target, type, collected: {}, ai: null, deepDive: null, historyId: null, cancelled: false, controller: new AbortController(), prev, aiBusy: false });
  store.del(checkKey());
  setRunning(true);
  $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#emptyState").hidden = true; $("#bySource").hidden = true;
  renderHead(); loadNotes(); $("#reportSection").hidden = true;
  log.start();
  renderLedger(); renderAiPanel();

  const on = (id) => srcOn(id);
  const c = state.collected;
  const isEmail = type === "email", isUser = type === "username";
  const domain = isEmail ? target.split("@")[1] : "";
  // Username tools need a handle. For an email that is the part before the @ (without a +tag),
  // which is only a lead: it is searched, and every hit stays "possible" unless a profile is read.
  const handle = isEmail ? target.split("@")[0].replace(/\+.*$/, "") : target.replace(/^@/, "");
  const handleOk = /^[A-Za-z0-9._-]{1,64}$/.test(handle) && !handle.startsWith("-");
  const via = isEmail ? ` (handle ${handle})` : "";

  if (type === "hash") {
    if (on("hash")) await runSource("Hash lookup", "/api/hash/hash", { hash: target }, {}, "hash");
  } else if (type === "phone") {
    if (on("phone")) {
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
    if (!handleOk && (on("sherlock") || on("maigret"))) log.add(`Username tools skipped: "${handle}" has characters they can't search`, "skip");
    if (handleOk && on("sherlock")) jobs.push(runSource(`Sherlock${via}`, "/api/recon/sherlock", { username: handle }, {}, "sherlock"));
    if (handleOk && on("maigret")) jobs.push(runSource(`Maigret${via}`, "/api/recon/maigret", { username: handle, nsfw: nsfwOn() }, {}, "maigret"));
    if (isUser && handleOk && on("github")) jobs.push(runSource("GitHub", "/api/recon/github", { username: handle }, {}, "github"));
    if (isEmail && on("holehe")) jobs.push(runSource("Holehe", "/api/recon/holehe", { email: target }, {}, "holehe"));
    if (isEmail && on("hibp")) jobs.push(runSource("Breaches", "/api/recon/hibp", { email: target }, {}, "hibp"));
    if (isEmail && on("gravatar")) jobs.push(runSource("Gravatar", "/api/recon/gravatar", { email: target }, {}, "gravatar"));
    if (isEmail && on("harvester")) jobs.push(runSource("Domain harvest", "/api/recon/harvester", { domain }, {}, "harvester"));
    if (isEmail && on("hunter") && getKey("hunter")) jobs.push(runSource("Hunter.io", "/api/recon/hunter", { domain }, { "X-Hunter-Key": getKey("hunter") }, "hunter"));
    await Promise.all(jobs);
    if (!state.cancelled && handleOk) {
      const sites = [...(c.sherlock?.results || []), ...(c.maigret?.results || [])].filter((r) => r.confidence !== "false_positive").map((r) => r.site).slice(0, 1000);
      const after = [];
      if (sites.length) after.push(runSource("Profile enrichment", "/api/recon/enrich", { username: handle, sherlock_sites: sites }, {}, "enricher"));
      if (on("platform")) after.push(runSource("Platform check", "/api/recon/platform-check", { username: handle, sherlock_sites: sites }, {}, "platformCheck"));
      await Promise.all(after);
    }
    const img = [target, ...(c.maigret?.results || []).map((r) => r.profile?.image)].find((u) => /^https?:\/\/\S+\.(jpe?g|png|gif|webp)(\?|$)/i.test(String(u || "")));
    if (img) { c.reverseImage = img; renderSourceCards(); }
  }

  setRunning(false);
  const { items, facts } = evidence();
  const ran = outcomes().length || Object.keys(c).length;
  log.finish(`${state.cancelled ? "Cancelled · partial results · " : ""}${plural(ran, "source")} · ${plural(items.length, "finding")}`);
  renderHead(`${TYPE_LABEL[type]} · ${plural(items.length, "finding")}${state.cancelled ? " · cancelled, partial" : ""}`);
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
  const entry = { id: state.historyId || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: state.target, type: "INVESTIGATE", kind: state.type, timestamp: Date.now(), results: state.collected, aiSummary: state.ai?.summary || null, ai: state.ai || null, deepDive: state.deepDive || null, notes: $("#notes").value, v2: true };
  state.historyId = entry.id;
  const idx = list.findIndex((e) => e.id === entry.id);
  if (idx >= 0) { entry.timestamp = list[idx].timestamp; list[idx] = entry; } else list.unshift(entry);
  while (list.length > HISTORY_MAX) list.pop();
  if (!store.set(HISTORY_KEY, list)) { list.splice(Math.floor(list.length / 2)); store.set(HISTORY_KEY, list); }
}
export function loadHistory(id) {
  const e = getHistory().find((x) => x.id === id);
  if (!e) return false;
  Object.assign(state, { target: e.target, type: e.kind || detect(e.target), collected: e.results || {}, ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deepDive: e.deepDive ? normalizeAi(e.deepDive) : null, historyId: e.id, running: false, prev: null, aiBusy: false });
  $("#targetInput").value = e.target;
  renderSources(state.type);
  $("#runlog").hidden = true;
  renderHead(`${TYPE_LABEL[state.type]} · from history · ${new Date(e.timestamp).toLocaleString()}`);
  renderLedger(); renderSourceCards(); renderAiPanel();
  $("#notes").value = e.notes || ""; updateNotesMeta();
  return true;
}
export function clearCase() {
  cancel();
  Object.assign(state, { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, prev: null, aiBusy: false });
  $("#targetInput").value = ""; $("#mainHead").hidden = true; $("#runlog").hidden = true; $("#ledger").innerHTML = ""; $("#notices").innerHTML = ""; $("#bySource").hidden = true;
  $("#emptyState").hidden = false; $("#facts").innerHTML = `<p class="empty flat">Nothing yet.</p>`; $("#notes").value = ""; updateNotesMeta();
  renderSources(""); renderAiPanel(); $("#targetDetected").innerHTML = ""; $("#reportSection").hidden = true;
}

// ---- notes --------------------------------------------------------------------------
let notesTimer;
function updateNotesMeta() { $("#notesCount").textContent = `${fmtNum($("#notes").value.length)} chars`; }
function loadNotes() { $("#notes").value = ""; updateNotesMeta(); }
$("#notes").addEventListener("input", () => {
  updateNotesMeta(); $("#notesStatus").textContent = "Saving…";
  clearTimeout(notesTimer);
  notesTimer = setTimeout(() => { if (state.target) saveHistory(); $("#notesStatus").textContent = "Saved"; }, 600);
});

// ---- export ------------------------------------------------------------------------------
export function exportCase() {
  if (!state.target) return;
  const { items, facts } = buildEvidence(state.collected, state.target);
  const failed = failedSources();
  const md = [`# CrawlR case: ${state.target}`, `Generated ${new Date().toISOString()} · ${TYPE_LABEL[state.type]}`, "",
    "> Findings come from third-party public sources and can be wrong. Possible items are leads, not facts.", "",
    ...(failed.length ? ["## Sources that failed", ...failed.map((f) => `- **${f.name}:** ${f.text} (unknown, not a negative result)`), ""] : []),
    "## What we know", ...(facts.length ? facts.map((f) => `- **${f.k}:** ${f.v} _(${f.source})_`) : ["- Nothing extracted"]), "",
    ...TIERS.flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...rows.map((i) => `- ${i.url ? `[${i.what}](${i.url})` : i.what}${i.meta ? ` · ${i.meta}` : ""} _(${i.source})_`), ""] : []; }),
    ...(state.ai ? ["## AI analysis", state.ai.summary, ""] : []),
    ...(state.deepDive ? ["## Deep Dive", state.deepDive.summary, ""] : []),
    ...($("#notes").value.trim() ? ["## Notes", $("#notes").value.trim(), ""] : []),
  ].join("\n");
  const name = `crawlr-${slug(state.target)}`;
  const done = (fn) => () => { fn(); closeModal(); };
  openModal({
    title: "Export case",
    body: `<p class="modal-p">Everything is built in your browser. Nothing is uploaded.</p>
      <ul class="export-list"><li><b>Print or PDF</b> opens the print dialog with a clean, light layout. Choose "Save as PDF" there.</li><li><b>HTML</b> is one self-contained page you can send or archive.</li><li><b>Markdown</b> has the ledger, facts, AI reports and notes.</li><li><b>JSON</b> is the raw data from every source.</li></ul>`,
    actions: [
      { label: "JSON", onClick: done(() => download(`${name}.json`, JSON.stringify({ target: state.target, type: state.type, exported: new Date().toISOString(), collected: state.collected, ai: state.ai, deepDive: state.deepDive, notes: $("#notes").value }, null, 2), "application/json")) },
      { label: "Markdown", onClick: done(() => download(`${name}.md`, md, "text/markdown")) },
      { label: "HTML", onClick: async () => { const html = await standaloneHtml(`CrawlR case: ${state.target}`, $("#main"), $("#aside")); download(`${name}.html`, html, "text/html"); closeModal(); } },
      { label: "Print or PDF", primary: true, onClick: () => { closeModal(); setTimeout(() => window.print(), 50); } },
    ],
  });
}
