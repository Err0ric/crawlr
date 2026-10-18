// Headers analyzer, dork builder, decoders.
import { $, $$, h, raw, esc, link, store, toast, post, postAi, aiAvailable, providerName, looksLikeHeaders, fmtNum } from "./core.js";
import { md5 } from "./md5.js";

const copy = (text, btn) => navigator.clipboard?.writeText(text).then(() => { if (btn) { const t = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = t), 1400); } else toast("Copied"); });

// =====================================================================================
// Email headers
// =====================================================================================
const VERDICT = {
  SPOOFED:     { cls: "bad",  text: "Authentication failed and the sender identity doesn't line up. Treat as spoofed." },
  SUSPICIOUS:  { cls: "warn", text: "Something in the authentication or routing is off. Read the flags before trusting it." },
  LEGITIMATE:  { cls: "ok",   text: "Authentication passed and the routing looks normal." },
};
let lastHeaders = null;

function authChip(name, v) {
  const s = String(v || "missing").toLowerCase();
  const cls = s === "pass" ? "ok" : s === "fail" ? "bad" : s === "softfail" || s === "neutral" ? "warn" : "";
  return h`<span class="pill ${cls}"><span class="dot"></span>${name} ${s}</span>`;
}
const fmtDelay = (s) => { const n = Number(s); if (!Number.isFinite(n)) return ""; const a = Math.abs(n); return a >= 3600 ? `${(n / 3600).toFixed(1)}h` : a >= 60 ? `${Math.round(n / 60)}m` : `${n}s`; };
const delayCls = (s) => { const n = Number(s); return n > 300 || n < -60 ? "bad" : n > 30 ? "warn" : "ok"; };

function renderHeaders(d) {
  const v = String(d.verdict || "UNKNOWN").toUpperCase();
  const meta = VERDICT[v] || { cls: "", text: "Not enough information for a verdict." };
  const a = d.authentication || {};
  const kh = d.key_headers || {};
  const geo = d.ip_geolocation || {};
  const sender = d.sender_ip ? geo[d.sender_ip] : null;
  const anomalies = d.anomalies || [];
  const hops = d.hops || [];
  const sevOrder = { high: 0, medium: 1, low: 2 };
  return h`
    <div class="verdict ${meta.cls}">
      <div class="v">${v.replace("_", " ").toLowerCase()}</div>
      <p>${meta.text}</p>
      <div class="chips">${raw(authChip("SPF", a.spf) + authChip("DKIM", a.dkim) + authChip("DMARC", a.dmarc))}</div>
    </div>
    <div id="hdrAi">${raw(aiAvailable() ? `<button class="btn btn-sm" type="button" id="hdrAiBtn">Ask ${esc(providerName())} for a verdict</button>` : "")}</div>
    ${anomalies.length ? raw(h`
      <article class="card"><div class="card-head"><h3>Flags</h3><span class="tag warn">${anomalies.length}</span></div>
      <div class="card-body flags">${raw([...anomalies].sort((x, y) => (sevOrder[x.severity] ?? 3) - (sevOrder[y.severity] ?? 3)).map((f) => h`<div class="flag ${f.severity}"><span class="sev">${f.severity}</span><span>${f.detail}</span></div>`).join(""))}</div></article>`) : ""}
    <div class="sources-grid">
      <article class="card"><div class="card-head"><h3>Message</h3></div><div class="card-body"><dl class="kv">${raw(["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID", "X-Mailer", "User-Agent"].filter((k) => kh[k]).map((k) => h`<dt>${k}</dt><dd class="${/ID|Path/.test(k) ? "mono" : ""}">${kh[k]}</dd>`).join(""))}</dl></div></article>
      <article class="card"><div class="card-head"><h3>Sender origin</h3></div><div class="card-body">${raw(d.sender_ip ? h`<dl class="kv"><dt>IP</dt><dd class="mono">${d.sender_ip}</dd>${raw(sender ? h`<dt>Location</dt><dd>${[sender.city, sender.region, sender.country].filter(Boolean).join(", ")}</dd><dt>Network</dt><dd>${[sender.isp, sender.org, sender.asn].filter(Boolean).join(" · ")}</dd>` : "")}</dl>` : `<p style="color:var(--ink-3);font-size:var(--fs-1)">No originating IP in the headers.</p>`)}
        ${raw(Object.keys(geo).filter((ip) => ip !== d.sender_ip).length ? h`<details style="margin-top:8px;font-size:var(--fs-0)"><summary style="cursor:pointer;color:var(--ink-3)">Other IPs in the chain</summary>${raw(Object.entries(geo).filter(([ip]) => ip !== d.sender_ip).map(([ip, g]) => h`<div><span class="mono">${ip}</span> <span style="color:var(--ink-3)">${[g.city, g.country, g.org].filter(Boolean).join(", ")}</span></div>`).join(""))}</details>` : "")}
      </div></article>
    </div>
    ${hops.length ? raw(h`
      <article class="card"><div class="card-head"><h3>Route</h3><span class="tag">${hops.length} hops${d.total_delay_seconds != null ? ` · ${fmtDelay(d.total_delay_seconds)} total` : ""}</span></div>
      <div class="card-body flush"><ol class="hops">${raw(hops.map((x) => h`
        <li><div class="hop-main"><span class="mono">${x.from || "?"}</span> <span style="color:var(--ink-4)">to</span> <span class="mono">${x.by || "?"}</span></div>
        <div class="hop-meta">${[...(x.ips || [])].join(", ")}${x.geo ? ` · ${[x.geo.city, x.geo.country].filter(Boolean).join(", ")}` : ""}${raw(x.delay_seconds != null ? h` <span class="tag ${delayCls(x.delay_seconds)}">${fmtDelay(x.delay_seconds)}</span>` : "")}</div></li>`).join(""))}</ol></div></article>`) : ""}`;
}

async function runHeaders() {
  const text = $("#hdrInput").value.trim();
  if (!text) { toast("Paste the raw headers first."); return; }
  const btn = $("#hdrRun"); btn.disabled = true; btn.textContent = "Analyzing…";
  try {
    lastHeaders = await post("/api/email/analyze", { headers: text });
    $("#hdrOut").innerHTML = renderHeaders(lastHeaders);
    saveHeaderHistory(text);
  } catch (err) {
    $("#hdrOut").innerHTML = h`<div class="empty"><h3>Couldn't analyze those headers</h3><p>${err.detail || err.message}</p></div>`;
  } finally { btn.disabled = false; btn.textContent = "Analyze headers"; }
}
async function runHeaderAi() {
  const box = $("#hdrAi");
  box.innerHTML = `<p style="color:var(--ink-3);font-size:var(--fs-1)">Asking ${esc(providerName())}…</p>`;
  try {
    const d = await postAi("/api/analyze/email-headers", { header_analysis: lastHeaders });
    const v = String(d.verdict || "").toUpperCase();
    const cls = v === "LEGITIMATE" ? "ok" : /PHISH|BEC|SPOOF/.test(v) ? "bad" : "warn";
    box.innerHTML = h`<article class="card"><div class="card-head"><h3>AI verdict</h3><span class="pill ${cls}"><span class="dot"></span>${v.toLowerCase()}</span></div>
      <div class="card-body report">${d.summary ? raw(h`<p>${d.summary}</p>`) : ""}
        ${raw((d.reasons || []).length ? h`<h3>Why</h3><ul>${raw(d.reasons.map((r) => h`<li>${r}</li>`).join(""))}</ul>` : "")}
        ${raw((d.next_steps || []).length ? h`<h3>Next steps</h3><ul>${raw(d.next_steps.map((r) => h`<li>${r}</li>`).join(""))}</ul>` : "")}
        <div class="ai-meta">${[d.model, d.tokens ? `${fmtNum(d.tokens)} tokens` : "", d.ai_source === "house" ? "free tier" : ""].filter(Boolean).join(" · ")}</div></div></article>`;
  } catch (err) {
    box.innerHTML = h`<p style="color:var(--warn);font-size:var(--fs-1)">${err.detail || err.message}</p>`;
  }
}
function saveHeaderHistory(text) {
  const list = store.get("crawlr_history", []);
  const subj = lastHeaders?.key_headers?.Subject || lastHeaders?.key_headers?.From || "Email headers";
  list.unshift({ id: `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: String(subj).slice(0, 120), type: "email_headers", timestamp: Date.now(), results: lastHeaders, raw: text.slice(0, 20000), v2: true });
  while (list.length > 50) list.pop();
  if (!store.set("crawlr_history", list)) { list.splice(Math.floor(list.length / 2)); store.set("crawlr_history", list); }
}
export function loadHeaderHistory(e) {
  $("#hdrInput").value = e.raw || "";
  if (e.results) { lastHeaders = e.results; $("#hdrOut").innerHTML = renderHeaders(e.results); }
  else if (e.raw) runHeaders();
  else $("#hdrOut").innerHTML = `<div class="empty"><h3>Saved by the classic interface</h3><p>That entry only kept rendered HTML. Paste the headers again to re-run.</p></div>`;
}
export function prefillHeaders(text) { $("#hdrInput").value = text; runHeaders(); }

$("#hdrRun").addEventListener("click", runHeaders);
$("#hdrInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) runHeaders(); });
$("#hdrClear").addEventListener("click", () => { $("#hdrInput").value = ""; lastHeaders = null; $("#hdrOut").innerHTML = $("#hdrEmptyTpl").innerHTML; $("#hdrInput").focus(); });
$("#hdrOut").addEventListener("click", (e) => { if (e.target.id === "hdrAiBtn") runHeaderAi(); });

// =====================================================================================
// Dork builder
// =====================================================================================
const PLATFORMS = [
  { cat: "Social", items: [["Instagram", "instagram.com"], ["Facebook", "facebook.com"], ["X / Twitter", "twitter.com"], ["TikTok", "tiktok.com"], ["Reddit", "reddit.com"], ["Snapchat", "snapchat.com"], ["Pinterest", "pinterest.com"]] },
  { cat: "Professional", items: [["LinkedIn", "linkedin.com"], ["GitHub", "github.com"], ["Indeed", "indeed.com"]] },
  { cat: "Video", items: [["YouTube", "youtube.com"], ["Twitch", "twitch.tv"], ["Vimeo", "vimeo.com"]] },
  { cat: "Forums", items: [["Quora", "quora.com"], ["Medium", "medium.com"], ["Pastebin", "pastebin.com"], ["Discord", "discord.com"]] },
  { cat: "Marketplaces", items: [["Craigslist", "craigslist.org"], ["eBay", "ebay.com"], ["OfferUp", "offerup.com"], ["Poshmark", "poshmark.com"]] },
  { cat: "Gaming", items: [["Steam", "steamcommunity.com"], ["Xbox", "xbox.com"], ["PlayStation", "psnprofiles.com"]] },
  { cat: "Documents", items: [["Scribd", "scribd.com"], ["SlideShare", "slideshare.net"], ["PDF files", "filetype:pdf"]] },
];
const chosen = new Set(store.get("crawlr_v2_dork_sites", []));
$("#dkPlatforms").innerHTML = PLATFORMS.map((g) => h`
  <fieldset class="plat"><legend>${g.cat}</legend>${raw(g.items.map(([label, site]) => h`<button type="button" class="chip-btn" data-site="${site}" aria-pressed="${chosen.has(site)}">${label}</button>`).join(""))}</fieldset>`).join("");
const q = (s) => `"${s.replace(/"/g, "")}"`;
function buildDork() {
  const v = (id) => $(id).value.trim();
  const [name, user, email, loc, emp, kw] = ["#dkName", "#dkUser", "#dkEmail", "#dkLoc", "#dkEmp", "#dkKw"].map(v);
  const parts = [];
  if (name && user) parts.push(`(${q(user)} OR ${q(name)})`); else if (name) parts.push(q(name)); else if (user) parts.push(user);
  for (const x of [loc, emp, email]) if (x) parts.push(q(x));
  const kws = kw.split(",").map((s) => s.trim()).filter(Boolean);
  if (kws.length === 1) parts.push(q(kws[0])); else if (kws.length > 1) parts.push(`(${kws.map(q).join(" OR ")})`);
  const sites = [...chosen].map((s) => (s.startsWith("filetype:") ? s : `site:${s}`));
  if (sites.length === 1) parts.push(sites[0]); else if (sites.length > 1) parts.push(`(${sites.join(" OR ")})`);
  const query = parts.join(" ");
  $("#dkQuery").textContent = query || "Fill in any field to build a query.";
  $("#dkQuery").classList.toggle("placeholder", !query);
  $$("#dkSearch, #dkCopy, #dkBing, #dkDdg").forEach((b) => (b.disabled = !query));
  return query;
}
$("#dorks").addEventListener("input", buildDork);
$("#dkPlatforms").addEventListener("click", (e) => {
  const b = e.target.closest("[data-site]"); if (!b) return;
  const s = b.dataset.site; chosen.has(s) ? chosen.delete(s) : chosen.add(s);
  b.setAttribute("aria-pressed", chosen.has(s)); store.set("crawlr_v2_dork_sites", [...chosen]); buildDork();
});
const openSearch = (base) => { const query = buildDork(); if (query) window.open(base + encodeURIComponent(query), "_blank", "noopener"); };
$("#dkSearch").addEventListener("click", () => openSearch("https://www.google.com/search?q="));
$("#dkBing").addEventListener("click", () => openSearch("https://www.bing.com/search?q="));
$("#dkDdg").addEventListener("click", () => openSearch("https://duckduckgo.com/?q="));
$("#dkCopy").addEventListener("click", (e) => copy(buildDork(), e.currentTarget));
$("#dkClear").addEventListener("click", () => { $$("#dorks input").forEach((i) => (i.value = "")); chosen.clear(); store.set("crawlr_v2_dork_sites", []); $$("[data-site]").forEach((b) => b.setAttribute("aria-pressed", "false")); buildDork(); });
buildDork();

// =====================================================================================
// Decoders
// =====================================================================================
const out = (id, html) => ($(id).innerHTML = html);
const result = (text, cls = "") => h`<div class="dec-out ${cls}"><code>${text}</code><button class="btn btn-sm" type="button" data-copy="${text}">Copy</button></div>`;
const err = (text) => h`<p class="dec-err">${text}</p>`;

// base64 (UTF-8 safe both ways)
$("#b64Enc").addEventListener("click", () => { try { out("#b64Out", result(btoa(String.fromCharCode(...new TextEncoder().encode($("#b64In").value))))); } catch (e) { out("#b64Out", err(e.message)); } });
$("#b64Dec").addEventListener("click", () => {
  try {
    const clean = $("#b64In").value.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
    const bytes = Uint8Array.from(atob(clean + "===".slice((clean.length + 3) % 4)), (c) => c.charCodeAt(0));
    out("#b64Out", result(new TextDecoder("utf-8", { fatal: false }).decode(bytes)));
  } catch { out("#b64Out", err("That isn't valid Base64.")); }
});
// URL
$("#urlEnc").addEventListener("click", () => out("#urlOut", result(encodeURIComponent($("#urlIn").value))));
$("#urlDec").addEventListener("click", () => { try { out("#urlOut", result(decodeURIComponent($("#urlIn").value.replace(/\+/g, " ")))); } catch { out("#urlOut", err("That contains a malformed % sequence.")); } });
// hashes
$("#hashGo").addEventListener("click", async () => {
  const s = $("#hashIn").value;
  const bytes = new TextEncoder().encode(s);
  const hex = async (alg) => [...new Uint8Array(await crypto.subtle.digest(alg, bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const rows = [["MD5", md5(s)], ["SHA-1", await hex("SHA-1")], ["SHA-256", await hex("SHA-256")], ["SHA-512", await hex("SHA-512")]];
  out("#hashOut", rows.map(([k, v]) => h`<div class="dec-row"><span class="k">${k}</span>${raw(result(v))}</div>`).join(""));
});
// VIN (NHTSA, straight from the browser)
const VIN_RE = /^[A-HJ-NPR-Z0-9]{17}$/i;
$("#vinGo").addEventListener("click", async () => {
  const vin = $("#vinIn").value.trim().toUpperCase();
  if (!VIN_RE.test(vin)) { out("#vinOut", err("A VIN is 17 characters, letters and digits, never I, O or Q.")); return; }
  out("#vinOut", `<p class="dec-wait">Decoding…</p>`);
  try {
    const r = await fetch(`https://vpic.nhtsa.dot.gov/api/vehicles/decodevin/${encodeURIComponent(vin)}?format=json`);
    const j = await r.json();
    const get = (id) => (j.Results || []).find((x) => x.VariableId === id)?.Value || "";
    const rows = [["Year", get(29)], ["Make", get(26)], ["Model", get(28)], ["Trim", get(38)], ["Body", get(5)], ["Engine", [get(13) && `${get(13)} L`, get(9) && `${get(9)} cyl`].filter(Boolean).join(", ")], ["Plant", [get(31), get(75)].filter(Boolean).join(", ")]].filter(([, v]) => v);
    out("#vinOut", rows.length ? `<dl class="kv">${rows.map(([k, v]) => h`<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>` : err("NHTSA has no record for that VIN."));
  } catch { out("#vinOut", err("Couldn't reach NHTSA. Try again in a moment.")); }
});
// plate
$("#plateGo").addEventListener("click", async () => {
  const plate = $("#plateIn").value.trim().toUpperCase(), state = $("#plateState").value;
  if (!plate || !state) { out("#plateOut", err("Enter a plate and pick a state.")); return; }
  out("#plateOut", `<p class="dec-wait">Looking up…</p>`);
  try {
    const d = await post("/api/vehicles/plate", { plate, state });
    if (d.error) { out("#plateOut", err(d.error)); return; }
    const rows = [["Year", d.year], ["Make", d.make], ["Model", d.model], ["Trim", d.trim], ["Engine", d.engine], ["VIN", d.vin]].filter(([, v]) => v);
    out("#plateOut", rows.length ? `<dl class="kv">${rows.map(([k, v]) => h`<dt>${k}</dt><dd class="${k === "VIN" ? "mono" : ""}">${v}</dd>`).join("")}</dl>${d.vin ? `<button class="btn btn-sm" type="button" id="plateToVin" style="margin-top:8px">Decode this VIN</button>` : ""}` : err("No vehicle found for that plate."));
    if (d.vin) $("#plateToVin").addEventListener("click", () => { $("#vinIn").value = d.vin; $("#vinGo").click(); $("#vinIn").scrollIntoView({ behavior: "smooth", block: "center" }); });
  } catch (e) { out("#plateOut", err(e.detail || e.message)); }
});
// Enter submits each decoder
[["#b64In", null], ["#urlIn", null], ["#hashIn", "#hashGo"], ["#vinIn", "#vinGo"], ["#plateIn", "#plateGo"]].forEach(([i, b]) => b && $(i).addEventListener("keydown", (e) => { if (e.key === "Enter") $(b).click(); }));

// paste-detect on the decoders input is not needed; headers paste-detect lives in app.js
export { looksLikeHeaders };
