// Investigate mode: run sources, build the ledger, run AI, deep dive, history, notes, export.
import { $, $$, h, raw, esc, link, store, toast, post, postAi, ApiError, getKey, aiAvailable, providerName, detect, TYPE_LABEL, fmtNum, plural } from "./core.js";
import { buildEvidence, TIERS } from "./evidence.js";
import { sourceCards } from "./renderers.js";
import { normalizeAi, markdown, summaryBlock } from "./ai.js";
import { openModal, closeModal } from "./ui.js";
import { makeLog, renderTiers, bindLedger, renderFacts } from "./workbench.js";

// ---- sources ---------------------------------------------------------------
export const SOURCES = [
  { id: "sherlock",  name: "Sherlock",        desc: "username across 400+ sites",            types: ["username", "email"], on: true },
  { id: "maigret",   name: "Maigret",         desc: "username across 3,000+ sites",          types: ["username", "email"], on: true, extra: { id: "nsfw", label: "include adult sites", on: true } },
  { id: "github",    name: "GitHub",          desc: "profile, bio, linked email",            types: ["username"],          on: true },
  { id: "platform",  name: "Platform check",  desc: "registration probes on major platforms", types: ["username", "email"], on: true },
  { id: "holehe",    name: "Holehe",          desc: "accounts registered to this email",     types: ["email"],             on: true },
  { id: "hibp",      name: "Breaches",        desc: "known credential exposures",            types: ["email"],             on: true },
  { id: "gravatar",  name: "Gravatar",        desc: "avatar profile for this email",         types: ["email"],             on: true },
  { id: "hunter",    name: "Hunter.io",       desc: "addresses on the email's domain",       types: ["email"],             on: false, pro: "hunter" },
  { id: "harvester", name: "Domain harvest",  desc: "other addresses on this email's domain, from 8 public sources", types: ["email"], on: true },
  { id: "hash",      name: "Hash lookup",     desc: "MalwareBazaar, CIRCL, OTX, ThreatFox",  types: ["hash"],              on: true },
  { id: "phone",     name: "Phone lookup",    desc: "carrier and line type",                 types: ["phone"],             on: true, pro: "numlookup", proOptional: true },
  { id: "ai",        name: "AI analysis",     desc: "interpretation and next leads",         types: ["username", "email", "hash", "phone", "name"], on: true },
  { id: "active",    name: "Active techniques", desc: "profile scraping for Deep Dive. May notify the target.", types: ["username", "email"], on: false, warn: true },
];

const srcState = store.get("crawlr_v2_sources", {});
export const srcOn = (id) => (id in srcState ? !!srcState[id] : SOURCES.find((s) => s.id === id)?.on ?? false);
const setSrc = (id, v) => { srcState[id] = v; store.set("crawlr_v2_sources", srcState); };

export function renderSources(type) {
  const box = $("#sources");
  const rows = SOURCES.filter((s) => !type || s.types.includes(type));
  box.innerHTML = rows.map((s) => h`
    <div class="source ${srcOn(s.id) ? "" : "off"}" data-src="${s.id}">
      <div>
        <div class="name">${s.name}${s.warn ? raw(' <span class="tag warn">caution</span>') : ""}${s.pro && !s.proOptional ? raw(' <span class="tag violet">your key</span>') : ""}</div>
        <div class="desc">${s.desc}${s.note ? raw(h` <span class="tag">${s.note}</span>`) : ""}${s.pro && s.proOptional && !getKey(s.pro) ? raw(' <span class="tag">links only without a key</span>') : ""}</div>
        ${s.extra ? raw(h`<label style="display:flex;align-items:center;gap:8px;margin-top:6px;font-size:var(--fs-0);color:var(--ink-3)"><input type="checkbox" data-extra="${s.extra.id}" ${srcState[s.id + "." + s.extra.id] !== false ? "checked" : ""} style="accent-color:var(--violet-2)">${s.extra.label}</label>`) : ""}
      </div>
      <label class="switch"><input type="checkbox" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-label="${s.name}"><span></span></label>
    </div>`).join("");
  if (!rows.length) box.innerHTML = h`<p class="empty" style="padding:0">Enter a target to see which sources apply.</p>`;
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
export const state = { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, running: false };
const checkKey = () => `crawlr_checked_${state.target}`;
const checked = () => new Set(store.get(checkKey(), []));

// ---- ledger + facts -------------------------------------------------------------
function renderLedger() {
  const { items, facts } = buildEvidence(state.collected, state.target);
  $("#emptyState").hidden = true;
  renderTiers($("#ledger"), items, TIERS, checked(), `<div class="empty"><h3>Nothing found yet</h3><p>No source returned a result for this target.</p></div>`);
  renderFacts($("#facts"), facts);
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
  const seen = new Set(); return urls.filter((u) => !seen.has(u.url) && seen.add(u.url)).slice(0, 20);
}

function renderAiPanel() {
  const box = $("#aiPanel");
  if (!state.ai) { box.innerHTML = `<p class="empty" style="padding:0">${aiAvailable() ? "Runs automatically after the sources finish." : "Add a key in Settings to turn on AI analysis."}</p>`; return; }
  const canDeep = srcOn("active") && profileUrls().length && aiAvailable();
  const deepBtn = state.deepDive
    ? `<button class="btn btn-sm" type="button" data-open-report="deep">Deep Dive report</button>`
    : canDeep ? `<button class="btn btn-sm" type="button" id="deepDiveBtn">Deep Dive…</button>`
    : srcOn("active") ? "" : `<span style="color:var(--ink-4);font-size:var(--fs-0);align-self:center">Deep Dive needs Active techniques on</span>`;
  box.innerHTML = summaryBlock(state.ai, { reportId: "summary", attr: "data-open-report", deepDive: deepBtn });
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-open-report]");
  if (b) openReport(b.dataset.openReport);
  if (e.target.id === "deepDiveBtn") confirmDeepDive();
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

async function runAi() {
  if (!srcOn("ai") || !aiAvailable()) return;
  const c = state.collected;
  if (!Object.values(c).some((v) => v && typeof v === "object")) return;
  const row = log.add(`AI analysis (${providerName()})`);
  try {
    const sherlockMerged = { results: [...(c.sherlock?.results || []), ...(c.maigret?.results || []).filter((m) => !(c.sherlock?.results || []).some((s) => s.url === m.url))] };
    const data = await postAi("/api/analyze/summarize", {
      target: state.target, sherlock: sherlockMerged, holehe: c.holehe || null, harvester: c.harvester || null, hibp: c.hibp || null,
      gravatar: c.gravatar || null, github: c.github || null, enricher: c.enricher || null, platform_check: c.platformCheck || null,
      hunter: c.hunter || null, name_search: c.nameSearch ? { name: c.nameSearch } : null, active_techniques: srcOn("active"),
    });
    state.ai = normalizeAi(data);
    log.set(row, `AI analysis · ${data.model || providerName()}`, "done");
  } catch (err) {
    log.set(row, `AI analysis: ${err.detail || err.message}`, err.status === 429 ? "wait" : "err");
    if (err.status === 429) toast(err.detail, 5000);
  }
  renderAiPanel();
}

function confirmDeepDive() {
  const urls = profileUrls();
  openModal({
    title: "Run a Deep Dive?",
    body: h`<p style="font-size:var(--fs-1);color:var(--ink-2)">CrawlR will open ${plural(urls.length, "profile page")} it found, read what's public, and ask ${providerName()} for a full dossier: likely identity, confidence matrix, OPSEC assessment and search leads.</p>
            <p style="font-size:var(--fs-1);color:var(--warn);margin-top:10px">This fetches the target's pages. Some sites log visits.</p>`,
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
    const c = state.collected;
    const data = await postAi("/api/analyze/deep-dive", {
      target: state.target, sherlock: c.sherlock || null, holehe: c.holehe || null, harvester: c.harvester || null, hibp: c.hibp || null,
      gravatar: c.gravatar || null, github: c.github || null, enricher: c.enricher || null, platform_check: c.platformCheck || null,
      hunter: c.hunter || null, shodan: null, name_search: null, profile_scrape: scraped, active_techniques: true,
    });
    state.deepDive = normalizeAi(data);
    log.set(row2, "Deep Dive complete", "done");
    saveHistory();
    renderAiPanel();
    openReport("deep");
  } catch (err) {
    log.set(row, `Deep Dive: ${err.detail || err.message}`, "err");
    toast(err.detail || err.message, 5000);
  }
}

// ---- the run --------------------------------------------------------------------
async function runSource(label, url, body, headers, key) {
  const row = log.add(label);
  try {
    const data = await post(url, body, headers);
    state.collected[key] = data;
    const n = data?.total ?? data?.confirmed ?? data?.breaches?.length ?? data?.results?.filter?.((r) => r.found !== false).length ?? (data?.found ? 1 : 0);
    log.set(row, `${label} · ${data?.error ? data.error : fmtNum(n) + " result" + (n === 1 ? "" : "s")}`, data?.error ? "wait" : "done");
    renderLedger(); renderSourceCards();
    return data;
  } catch (err) {
    log.set(row, `${label}: ${err.detail || err.message}`, "err");
    return null;
  }
}

export async function run(targetRaw, typeOverride) {
  const target = String(targetRaw || "").trim();
  if (!target || state.running) return;
  const type = typeOverride || detect(target);
  if (type === "multi") { toast("One target at a time for now. Multi-target runs come back in a later build."); return; }
  if (!["username", "email", "hash", "phone", "name"].includes(type)) { toast(`${TYPE_LABEL[type] || "That"} targets run in Recon. Use the Recon tab.`); return; }

  Object.assign(state, { target, type, collected: {}, ai: null, deepDive: null, historyId: null, running: true });
  store.del(checkKey());
  $("#runBtn").disabled = true; $("#runBtn").textContent = "Running…";
  $("#ledger").innerHTML = ""; $("#emptyState").hidden = true; $("#bySource").hidden = true; $("#facts").innerHTML = `<p class="empty" style="padding:0">Collecting…</p>`;
  renderHead(); renderAiPanel(); loadNotes();
  log.start();

  const on = (id) => srcOn(id);
  const c = state.collected;
  const isEmail = type === "email", isUser = type === "username";
  const domain = isEmail ? target.split("@")[1] : "";

  if (type === "hash") {
    if (on("hash")) await runSource("Hash lookup", "/api/hash/hash", { hash: target }, {}, "hash");
  } else if (type === "phone") {
    if (on("phone")) {
      const k = getKey("numlookup");
      const d = await runSource("Phone lookup", "/api/phone/lookup", { phone: target }, k ? { "X-Numlookup-Key": k } : {}, "phone");
      if (!d && k) {
        // Saved key was rejected: still give the user the lookup links, and say why carrier data is missing.
        const d2 = await runSource("Phone lookup (links only)", "/api/phone/lookup", { phone: target }, {}, "phone");
        if (d2) { d2.api_error = "Your NumLookup key was rejected. Update or clear it in Settings."; renderSourceCards(); }
      }
    }
  } else if (type === "name") {
    c.nameSearch = target; renderSourceCards(); log.add("People search links ready", "done");
  } else {
    const jobs = [];
    if (on("sherlock")) jobs.push(runSource("Sherlock", "/api/recon/sherlock", { username: target }, {}, "sherlock"));
    if (on("maigret")) jobs.push(runSource("Maigret", "/api/recon/maigret", { username: target, nsfw: srcState["maigret.nsfw"] !== false }, {}, "maigret"));
    if (isUser && on("github")) jobs.push(runSource("GitHub", "/api/recon/github", { username: target }, {}, "github"));
    if (isEmail && on("holehe")) jobs.push(runSource("Holehe", "/api/recon/holehe", { email: target }, {}, "holehe"));
    if (isEmail && on("hibp")) jobs.push(runSource("Breaches", "/api/recon/hibp", { email: target }, {}, "hibp"));
    if (isEmail && on("gravatar")) jobs.push(runSource("Gravatar", "/api/recon/gravatar", { email: target }, {}, "gravatar"));
    if (isEmail && on("harvester")) jobs.push(runSource("Domain harvest", "/api/recon/harvester", { domain }, {}, "harvester"));
    if (isEmail && on("hunter") && getKey("hunter")) jobs.push(runSource("Hunter.io", "/api/recon/hunter", { domain }, { "X-Hunter-Key": getKey("hunter") }, "hunter"));
    await Promise.all(jobs);
    const sites = [...(c.sherlock?.results || []), ...(c.maigret?.results || [])].filter((r) => r.confidence !== "false_positive").map((r) => r.site);
    const after = [];
    if (sites.length) after.push(runSource("Profile enrichment", "/api/recon/enrich", { username: target, sherlock_sites: sites }, {}, "enricher"));
    if (on("platform")) after.push(runSource("Platform check", "/api/recon/platform-check", { username: target, sherlock_sites: sites }, {}, "platformCheck"));
    await Promise.all(after);
    const img = [target, ...[...(c.sherlock?.results || []), ...(c.maigret?.results || [])].map((r) => r.avatar_url || r.image)].find((u) => /\.(jpe?g|png|gif|webp)$/i.test(String(u || "")));
    if (img) { c.reverseImage = img; renderSourceCards(); }
  }

  await runAi();
  const { items } = buildEvidence(c, target);
  log.finish(`${plural(Object.keys(c).length, "source")} · ${plural(items.length, "finding")}`);
  renderHead(`${TYPE_LABEL[type]} · ${plural(items.length, "finding")}`);
  state.running = false;
  $("#runBtn").disabled = false; $("#runBtn").textContent = "Run investigation";
  saveHistory();
}

// ---- history (shares crawlr_history with the classic UI) -------------------------
const HISTORY_KEY = "crawlr_history", HISTORY_MAX = 50;
export const getHistory = () => store.get(HISTORY_KEY, []);
function saveHistory() {
  const list = getHistory();
  const entry = { id: state.historyId || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: state.target, type: "INVESTIGATE", timestamp: Date.now(), results: state.collected, aiSummary: state.ai?.summary || null, ai: state.ai || null, deepDive: state.deepDive || null, notes: $("#notes").value, v2: true };
  state.historyId = entry.id;
  const idx = list.findIndex((e) => e.id === entry.id);
  if (idx >= 0) list[idx] = entry; else list.unshift(entry);
  while (list.length > HISTORY_MAX) list.pop();
  if (!store.set(HISTORY_KEY, list)) { list.splice(Math.floor(list.length / 2)); store.set(HISTORY_KEY, list); }
}
export function loadHistory(id) {
  const e = getHistory().find((x) => x.id === id);
  if (!e) return false;
  Object.assign(state, { target: e.target, type: detect(e.target), collected: e.results || {}, ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deepDive: e.deepDive ? normalizeAi(e.deepDive) : null, historyId: e.id, running: false });
  $("#targetInput").value = e.target;
  renderSources(state.type);
  $("#runlog").hidden = true;
  renderHead(`${TYPE_LABEL[state.type]} · from history · ${new Date(e.timestamp).toLocaleString()}`);
  renderLedger(); renderSourceCards(); renderAiPanel();
  $("#notes").value = e.notes || ""; updateNotesMeta();
  return true;
}
export function clearCase() {
  Object.assign(state, { target: "", type: "", collected: {}, ai: null, deepDive: null, historyId: null, running: false });
  $("#targetInput").value = ""; $("#mainHead").hidden = true; $("#runlog").hidden = true; $("#ledger").innerHTML = ""; $("#bySource").hidden = true;
  $("#emptyState").hidden = false; $("#facts").innerHTML = `<p class="empty" style="padding:0">Nothing yet.</p>`; $("#notes").value = ""; updateNotesMeta();
  renderSources(""); renderAiPanel(); $("#targetDetected").innerHTML = "";
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
  const md = [`# CrawlR case: ${state.target}`, `Generated ${new Date().toISOString()} · ${TYPE_LABEL[state.type]}`, "",
    "## What we know", ...(facts.length ? facts.map((f) => `- **${f.k}:** ${f.v} _(${f.source})_`) : ["- Nothing extracted"]), "",
    ...TIERS.flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...rows.map((i) => `- ${i.url ? `[${i.what}](${i.url})` : i.what}${i.meta ? ` — ${i.meta}` : ""} _(${i.source})_`), ""] : []; }),
    ...(state.ai ? ["## AI analysis", state.ai.summary, ""] : []),
    ...(state.deepDive ? ["## Deep Dive", state.deepDive.summary, ""] : []),
    ...($("#notes").value.trim() ? ["## Notes", $("#notes").value.trim(), ""] : []),
  ].join("\n");
  openModal({
    title: "Export case",
    body: `<p style="font-size:var(--fs-1);color:var(--ink-2)">Markdown includes the ledger, facts, AI reports and notes. JSON is the raw data from every source.</p>`,
    actions: [
      { label: "Download JSON", onClick: () => download(`crawlr-${slug(state.target)}.json`, JSON.stringify({ target: state.target, type: state.type, collected: state.collected, ai: state.ai, deepDive: state.deepDive, notes: $("#notes").value }, null, 2), "application/json") },
      { label: "Download Markdown", primary: true, onClick: () => download(`crawlr-${slug(state.target)}.md`, md, "text/markdown") },
    ],
  });
}
const slug = (s) => s.replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 60) || "case";
function download(name, content, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000); closeModal();
}
