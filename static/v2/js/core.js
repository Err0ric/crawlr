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
  { id: "gemini",    label: "Gemini",     store: "crawlr_gemini_key",    placeholder: "AIza…",          help: "aistudio.google.com",    url: "https://aistudio.google.com/apikey" },
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
export const aiLabel = () => {
  if (userAiKey()) return { text: providerName(), cls: "ok" };
  if (quota.state.house_ai) {
    const left = quota.state.remaining?.analysis ?? 0;
    return { text: `Free AI · ${left} left today`, cls: left > 0 ? "violet" : "warn" };
  }
  return { text: "AI off", cls: "" };
};

// ---- API ---------------------------------------------------------------------
export class ApiError extends Error {
  constructor(status, detail) { super(detail || `HTTP ${status}`); this.status = status; this.detail = detail; }
}

export async function post(url, body, headers = {}) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch {}
    throw new ApiError(r.status, detail);
  }
  return r.json();
}

export function aiHeaders() {
  const hdr = { "X-Ai-Provider": getProvider() };
  const k = userAiKey();
  if (k) hdr["X-Api-Key"] = k;
  return hdr;
}
export async function postAi(url, body) {
  try {
    return await post(url, body, aiHeaders());
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
  if (RE.domain.test(t)) return "domain";
  if (RE.name.test(t)) return "name";
  return "username";
}
export const TYPE_LABEL = { email: "Email", username: "Username", domain: "Domain", ip: "IP address", asn: "ASN", hash: "Hash", phone: "Phone", name: "Name", headers: "Email headers", multi: "Multiple targets" };
export const INVESTIGATE_TYPES = ["username", "email", "hash", "phone", "name"];
export const RECON_TYPES = ["domain", "ip", "asn"];
