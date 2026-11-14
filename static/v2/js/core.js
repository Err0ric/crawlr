// Shared primitives. Everything that touches the DOM with remote data goes
// through esc() or h(). Nothing else may call innerHTML with raw strings.

export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Only http(s) URLs are allowed to become links.
export const safeUrl = (u) => {
  try {
    const url = new URL(String(u), location.origin);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : "";
  } catch { return ""; }
};

export const link = (url, text, cls = "") => {
  const u = safeUrl(url);
  const t = esc(text ?? url);
  return u ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer"${cls ? ` class="${cls}"` : ""}>${t}</a>` : t;
};

// Tagged template: interpolations are escaped unless wrapped in raw().
class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
export const raw = (s) => new Raw(s);
export const h = (strings, ...vals) =>
  strings.reduce((out, str, i) => {
    const v = vals[i - 1];
    const piece = v instanceof Raw ? v.s : Array.isArray(v) ? v.map((x) => (x instanceof Raw ? x.s : esc(x))).join("") : esc(v);
    return out + piece + str;
  });

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const fmtNum = (n) => Number(n ?? 0).toLocaleString();
export const fmtSecs = (s) => `${Number(s).toFixed(1)}s`;
export const plural = (n, one, many = one + "s") => `${fmtNum(n)} ${n === 1 ? one : many}`;

// ---- storage (namespaced, JSON, tolerant) ----------------------------------
export const store = {
  get(key, fallback = null) {
    try { const v = localStorage.getItem(key); return v === null ? fallback : JSON.parse(v); }
    catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
  },
  del(key) { try { localStorage.removeItem(key); } catch {} },
  str(key, fallback = "") { try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; } },
  setStr(key, value) { try { value ? localStorage.setItem(key, value) : localStorage.removeItem(key); } catch {} },
};

// ---- toast ------------------------------------------------------------------
let toastTimer;
export function toast(msg, ms = 2800) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), ms);
}

// ---- keys + AI availability ---------------------------------------------------
export const KEYS = [
  { id: "claude",    label: "Claude",     store: "crawlr_anthropic_key", placeholder: "sk-ant-api03-…", help: "console.anthropic.com", url: "https://console.anthropic.com/settings/keys" },
  { id: "gemini",    label: "Gemini",     store: "crawlr_gemini_key",    placeholder: "AQ.… or AIza…",  help: "aistudio.google.com",    url: "https://aistudio.google.com/apikey" },
  { id: "shodan",    label: "Shodan",     store: "cs_shodan_key",        placeholder: "Shodan API key", help: "account.shodan.io",      url: "https://account.shodan.io/" },
  { id: "hunter",    label: "Hunter.io",  store: "cs_hunter_key",        placeholder: "Hunter API key", help: "hunter.io/api-keys",     url: "https://hunter.io/api-keys" },
  { id: "numlookup", label: "NumLookup",  store: "cs_numlookup_key",     placeholder: "NumLookup key",  help: "numlookupapi.com",       url: "https://www.numlookupapi.com/" },
];
export const getKey = (id) => store.str(KEYS.find((k) => k.id === id)?.store || "");
export const setKey = (id, v) => store.setStr(KEYS.find((k) => k.id === id)?.store || "", v.trim());
export const getProvider = () => store.str("crawlr_ai_provider", "anthropic");
export const setProvider = (p) => store.setStr("crawlr_ai_provider", p);
export const providerName = () => (getProvider() === "gemini" ? "Gemini" : "Claude");
export const userAiKey = () => (getProvider() === "gemini" ? getKey("gemini") : getKey("claude") || store.str("crawlr_api_key"));

export const quota = { state: { house_ai: false }, listeners: new Set() };
export async function refreshQuota() {
  try {
    const r = await fetch("/api/quota");
    if (r.ok) quota.state = await r.json();
  } catch { /* offline: keep last state */ }
  quota.listeners.forEach((fn) => fn(quota.state));
  return quota.state;
}
export const aiAvailable = () => !!userAiKey() || !!quota.state.house_ai;
export const freeLeft = (bucket = "analysis") => quota.state.remaining?.[bucket] ?? 0;
// short: what fits in the top bar at any width. long: the accessible name and tooltip.
export const aiLabel = () => {
  if (userAiKey()) return { text: providerName(), long: `AI analysis uses your ${providerName()} key. Open settings.`, cls: "ok" };
  if (quota.state.house_ai) {
    const left = freeLeft();
    return { text: `Free AI · ${left}`, long: `Free AI: ${left} of ${quota.state.limits?.analysis ?? left} analyses left today. Open settings.`, cls: left > 0 ? "violet" : "warn" };
  }
  return { text: "AI off", long: "AI off. Add a key in settings to turn on AI analysis.", cls: "" };
};
// What one AI call will cost the user, said before they spend it.
export const aiCost = (bucket = "analysis") => {
  if (userAiKey()) return `Uses your ${providerName()} key.`;
  if (!quota.state.house_ai) return "";
  const left = freeLeft(bucket), what = bucket === "deepdive" ? "Deep Dive" : "analysis";
  return left > 0 ? `Uses 1 of your ${left} free ${what} ${left === 1 ? "credit" : "credits"} left today.` : `No free ${what} credits left today. Add your own key in Settings.`;
};

// ---- API ---------------------------------------------------------------------
// detail: a short message that is safe to show. raw: technical text for a "details" toggle.
export class ApiError extends Error {
  constructor(status, detail, { code = "", raw = "" } = {}) { super(detail || `HTTP ${status}`); this.status = status; this.detail = detail; this.code = code; this.raw = raw; }
}

export async function post(url, body, headers = {}, signal) {
  let r;
  try {
    r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(body),
      signal,
    });
  } catch (e) {
    if (e.name === "AbortError") throw new ApiError(0, "Cancelled", { code: "cancelled" });
    throw new ApiError(0, "Could not reach CrawlR. Check your connection and try again.", { code: "network", raw: String(e.message || e) });
  }
  if (!r.ok) {
    let j = null;
    try { j = await r.json(); } catch {}
    const d = j?.detail;
    // FastAPI validation errors arrive as a list; never show that to a person.
    if (r.status === 422 || Array.isArray(d)) throw new ApiError(r.status, "That input isn't valid for this source.", { code: "bad_input", raw: JSON.stringify(d ?? "").slice(0, 400) });
    if (typeof d === "string" && r.status < 500) throw new ApiError(r.status, d, { code: j.code || "" });
    if (typeof d === "string" && j.code) throw new ApiError(r.status, d, { code: j.code });
    throw new ApiError(r.status, "CrawlR hit an error running this. Try again in a moment.", { code: "server", raw: `HTTP ${r.status} ${typeof d === "string" ? d : r.statusText}`.trim() });
  }
  return r.json();
}

// Outcome of one source, used by the run log, the source cards and the AI prompt.
// "error" and "not found" are different things and must never be merged.
export function sourceOutcome(d) {
  if (!d) return { state: "error", text: "No response" };
  if (d.error || d.error_code) return { state: "error", text: String(d.message || d.error || "Failed"), detail: String(d.error_detail || ""), code: d.error_code || "" };
  if (d.skipped) return { state: "skipped", text: String(d.message || "Skipped") };
  if (d.found === false) return { state: "none", text: "Not found" };
  return { state: "ok", text: "" };
}

// ---- one count of what ran ---------------------------------------------------------------
// Did a source that answered actually return something? Used for the run log row and the tally,
// so "nothing found" means the same thing everywhere.
export function sourceHasResults(d) {
  if (!d || typeof d !== "object" || d.error || d.error_code || d.skipped || d.found === false) return false;
  if (d.found === true) return true;
  if (typeof d.total === "number") return d.total > 0;
  for (const k of ["results", "breaches", "emails", "hosts", "profiles", "subdomains", "candidates", "ports", "findings", "hops"]) {
    if (Array.isArray(d[k]) && d[k].some((r) => !r || typeof r !== "object" || (r.found !== false && r.open !== false && r.found !== null && !r.error))) return true;
  }
  if (d.records && typeof d.records === "object" && Object.values(d.records).some((v) => [].concat(v ?? []).length)) return true;
  if (d.verdict) return String(d.verdict).toUpperCase() !== "UNKNOWN";
  return !!(d.carrier || d.line_type || d.lookup_links || d.asn || d.grade);
}
// Some sources are several lookups in one answer: platform check asks each site, the avatar
// comparison fetches each image, the hash lookup asks four services, GitHub details has sections.
// When none of them answered, the source failed even though the request succeeded. When only
// some did, it is partial. Returns null for a source that has no parts.
//   { answered, total, unit, failedText }
export function sourceCoverage(d) {
  if (!d || typeof d !== "object" || d.error || d.error_code || d.skipped) return null;
  const rows = Array.isArray(d.results) ? d.results.filter((r) => r && typeof r === "object") : [];
  if (rows.some((r) => typeof r.state === "string")) {
    const asked = rows.filter((r) => r.state !== "manual");
    return { answered: asked.filter((r) => r.state === "found" || r.state === "not_found").length, total: asked.length, unit: "sites", failedText: "blocked by every site checked" };
  }
  if (rows.length && rows.every((r) => typeof r.id === "string" && ("hash" in r || "error" in r || "error_code" in r))) {
    return { answered: rows.filter((r) => r.hash && !r.error && !r.error_code).length, total: rows.length, unit: "images", failedText: "no image could be read" };
  }
  if (Array.isArray(d.failed_sources) && d.failed_sources.length) {
    const answered = ["malware_bazaar", "circl", "alienvault", "threatfox"].filter((k) => d[k] && typeof d[k] === "object" && (d[k].found === true || d[k].found === false) && !d[k].error && !d[k].error_code).length;
    return { answered, total: answered + d.failed_sources.length, unit: "sources", failedText: `no source could be asked (${d.failed_sources.join(", ")})` };
  }
  if (d.sections && typeof d.sections === "object" && Object.keys(d.sections).length) {
    const v = Object.values(d.sections);
    return { answered: v.filter((x) => x === "ok").length, total: v.length, unit: "sections", failedText: "no section could be read" };
  }
  return null;
}
export const coverageText = (cv) => `partial: ${cv.answered} of ${cv.total} ${cv.unit} ${cv.unit === "images" || cv.unit === "sections" ? "read" : "answered"}`;

// The one place that counts sources, for the case header, the run log summary and the
// "By source" tab in both modes. `names` maps a key in `collected` to the source's name.
//   ran          sources that were asked and came back, with an answer or a failure
//   answered     ran and did not fail            withResults  answered and returned something
//   partial      answered, but some of its parts did not (counted inside answered)
//   failed       ran and failed, or none of its parts answered (unknown, never "not found")
//   skipped      deliberately not run (not part of ran)
// Row states: "results", "none" (answered in full, nothing found), "partial" (answered in part,
// with or without results; never read as "nothing found"), "failed", "skipped".
// Follow-up lookups (GitHub details, Avatar comparison, Profile enrichment) are sources like any
// other: each is a request that can fail, has its own run log row and its own card. Values the
// browser makes itself (search links, the IP to ASN map for the graph) are not sources.
// A registry answering "no such record" (error_code not_found) is an answer, not a failure.
export function sourceTally(collected, names) {
  const rows = [];
  for (const [key, name] of Object.entries(names || {})) {
    const d = collected?.[key];
    if (!d || typeof d !== "object") continue;
    const o = sourceOutcome(d);
    const cv = sourceCoverage(d);
    const has = sourceHasResults(d);
    let state = d.skipped ? "skipped" : o.state === "error" && d.error_code !== "not_found" ? "failed" : has ? "results" : "none";
    let text = o.text;
    if (cv && state !== "skipped" && state !== "failed") {
      if (cv.total > 0 && cv.answered === 0) { state = "failed"; text = cv.failedText; }
      else if (cv.answered < cv.total) { state = "partial"; text = coverageText(cv); }
    }
    rows.push({ key, name, state, hasResults: state !== "failed" && state !== "skipped" && has, text, detail: o.detail || "", code: o.code || "" });
  }
  const n = (s) => rows.filter((r) => r.state === s).length;
  const failed = n("failed"), skipped = n("skipped"), partial = n("partial");
  const ran = rows.length - skipped;
  return { ran, answered: ran - failed, withResults: rows.filter((r) => r.hasResults).length, partial, failed, skipped, rows };
}
export const tallyText = (t) => [`${plural(t.ran, "source")} ran`, t.ran ? `${fmtNum(t.withResults)} with results` : "", t.partial ? `${fmtNum(t.partial)} partial` : "", t.failed ? `${fmtNum(t.failed)} failed` : "", t.skipped ? `${fmtNum(t.skipped)} skipped` : ""].filter(Boolean).join(" · ");
// What the AI is told about one source: never "not found" for a source that did not answer.
export const statusForAi = (r) => (r.state === "failed" ? (/^blocked/.test(r.text) ? `blocked: ${r.text}` : `failed: ${r.text}`) : r.state === "partial" ? r.text : r.state === "none" ? "not found" : "ok");

export function aiHeaders() {
  const hdr = { "X-Ai-Provider": getProvider() };
  const k = userAiKey();
  if (k) hdr["X-Api-Key"] = k;
  return hdr;
}
export async function postAi(url, body, signal) {
  try {
    return await post(url, body, aiHeaders(), signal);
  } finally {
    if (!userAiKey()) refreshQuota();
  }
}

// ---- target detection (single source of truth) --------------------------------
const RE = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  domain: /^[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$/i,
  ip: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/,
  asn: /^AS\d+$/i,
  hash: /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i,
  phone: /^\+?\d[\d\s\-().]{7,}$/,
  name: /^[A-Za-z]{2,}\s+[A-Za-z]{2,}/,
};
export const looksLikeHeaders = (t) =>
  [/^Received:/mi, /^From:/mi, /^To:/mi, /^Subject:/mi, /^Message-ID:/mi, /^MIME-Version:/mi, /^Authentication-Results:/mi, /^Return-Path:/mi, /^DKIM-Signature:/mi]
    .filter((re) => re.test(t)).length >= 3;

// A dotted string is only a domain if it ends in a real TLD; "word.word" is a username.
// Ported from the classic UI's list, plus common newer/ccTLDs.
const TLDS = new Set(("com org net edu gov mil int io co dev app ai me us uk ca au de fr it es nl br ru cn jp kr in za mx ar cl se no fi dk pl cz at ch be pt ie nz sg hk tw ph th id my vn ae sa il tr gr ro hu bg hr sk si lt lv ee is lu mt cy eu ua by kz pk bd ng ke eg ma " +
  "info biz name pro museum coop aero cat jobs mobi tel travel asia post xxx xyz online site store tech space fun icu top wang club vip shop work ltd group live cloud digital world center network systems " +
  "solutions agency media design studio email zone guru ninja rocks lol wtf gg tv cc ly fm to sh so gl ws la page blog news tools security link run host website tk ml ga cf gq su").split(" "));
const isDomain = (t) => RE.domain.test(t) && TLDS.has(t.split(".").pop().toLowerCase());

export function detect(input) {
  const t = String(input ?? "").trim();
  if (!t) return "";
  if (looksLikeHeaders(t)) return "headers";
  if (t.includes(",")) return "multi";
  if (RE.email.test(t)) return "email";
  if (RE.asn.test(t)) return "asn";
  if (RE.ip.test(t)) return "ip";
  if (RE.hash.test(t)) return "hash";
  if (RE.phone.test(t) && t.replace(/\D/g, "").length >= 7 && t.replace(/\D/g, "").length <= 15) return "phone";
  if (isDomain(t)) return "domain";
  if (RE.name.test(t)) return "name";
  return "username";
}
export const TYPE_LABEL = { email: "Email", username: "Username", domain: "Domain", ip: "IP address", asn: "ASN", hash: "Hash", phone: "Phone", name: "Name", headers: "Email headers", multi: "Multiple targets" };
export const INVESTIGATE_TYPES = ["username", "email", "hash", "phone", "name"];
export const RECON_TYPES = ["domain", "ip", "asn"];

// ---- keyboard helpers -------------------------------------------------------------
// Roving tabindex for a group of tabs or radios: one tab stop, arrows move, Home/End jump.
// `select(el)` is called when the user lands on an item.
export function roving(container, itemSel, select) {
  const items = () => $$(itemSel, container).filter((el) => !el.disabled);
  const sync = () => { const all = items(); const cur = all.find((el) => el.getAttribute("aria-selected") === "true" || el.getAttribute("aria-checked") === "true") || all[0]; all.forEach((el) => (el.tabIndex = el === cur ? 0 : -1)); };
  container.addEventListener("keydown", (e) => {
    const all = items(); const i = all.indexOf(e.target.closest(itemSel)); if (i < 0) return;
    const next = { ArrowRight: i + 1, ArrowDown: i + 1, ArrowLeft: i - 1, ArrowUp: i - 1, Home: 0, End: all.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const el = all[(next + all.length) % all.length];
    select(el); sync(); (container.contains(el) ? el : items().find((x) => x.tabIndex === 0))?.focus();
  });
  sync();
  return sync;
}
export const fmtAgo = (ts) => { const s = Math.max(0, (Date.now() - ts) / 1000); return s < 90 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`; };
export function download(name, content, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
export const slug = (s) => String(s).replace(/[^a-z0-9]+/gi, "-").replace(/^-|-$/g, "").slice(0, 60) || "case";

// ---- how a source knows ---------------------------------------------------------------
// Three plain words, shown beside every source, so a hit can be weighed by where it came from.
export const HOW = {
  record: { word: "direct", means: "asks the system that holds the answer" },
  index: { word: "index", means: "a third party's copy, which can be out of date" },
  guess: { word: "heuristic", means: "inferred from how a site responds, so a hit is a lead to check" },
};
export const howTag = (k) => (HOW[k] ? `<span class="src-how ${k}">${esc(HOW[k].word)}</span>` : "");
export const HOW_LEGEND = Object.values(HOW).map((v) => `<b>${esc(v.word)}</b> ${esc(v.means)}`).join(". ") + ".";
