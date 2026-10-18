// Recon mode: infrastructure for a domain, IP or ASN.
import { $, $$, h, raw, esc, link, store, toast, post, postAi, getKey, aiAvailable, providerName, detect, TYPE_LABEL, RECON_TYPES, fmtNum, plural } from "./core.js";
import { normalizeAi, markdown, summaryBlock } from "./ai.js";
import { openModal, closeModal } from "./ui.js";
import { makeLog, renderTiers, bindLedger, renderFacts, factCollector, itemCollector } from "./workbench.js";
import { harvestCard } from "./renderers.js";

// ---- sources -----------------------------------------------------------------
export const SOURCES = [
  { id: "dns",        name: "DNS records",      desc: "A, MX, NS, TXT, CNAME, SOA",                     types: ["domain"],        on: true },
  { id: "whois",      name: "WHOIS",            desc: "registrar, dates, privacy",                      types: ["domain"],        on: true },
  { id: "ssl",        name: "TLS certificate",  desc: "issuer, names covered, expiry",                  types: ["domain", "ip"],  on: true },
  { id: "headers",    name: "HTTP headers",     desc: "server and security header grade",               types: ["domain", "ip"],  on: true },
  { id: "subdomains", name: "Subdomains",       desc: "DNS checks and certificate transparency logs",   types: ["domain"],        on: true },
  { id: "harvest",    name: "Passive discovery", desc: "hosts and addresses from 8 public sources (CT, passive DNS, URLScan, Wayback)", types: ["domain"], on: true },
  { id: "asn",        name: "Network owner",    desc: "ASN, organization, announced prefixes",          types: ["domain", "ip"],  on: true },
  { id: "exposure",   name: "Exposure",         desc: "open ports and CVEs (InternetDB, or Shodan with your key)", types: ["domain", "ip"], on: true },
  { id: "portscan",   name: "Port scan",        desc: "connects to 20 common ports on the target",      types: ["domain", "ip"],  on: true, warn: "active" },
  { id: "redirects",  name: "Redirect chain",   desc: "every hop to the final URL",                     types: ["domain", "ip"],  on: true },
  { id: "techfp",     name: "Tech fingerprint", desc: "CMS, server, frameworks, CDN",                   types: ["domain"],        on: true },
  { id: "wayback",    name: "Wayback Machine",  desc: "archived snapshots",                             types: ["domain"],        on: true },
  { id: "asndetail",  name: "ASN detail",       desc: "organization, prefixes, peers",                  types: ["asn"],           on: true },
  { id: "ai",         name: "AI analysis",      desc: "attack surface summary and next steps",          types: ["domain", "ip", "asn"], on: true },
];
const srcState = store.get("crawlr_v2_recon_sources", {});
const srcOn = (id) => (id in srcState ? !!srcState[id] : SOURCES.find((s) => s.id === id)?.on ?? false);

export function renderSources(type) {
  const rows = SOURCES.filter((s) => !type || s.types.includes(type));
  $("#rSources").innerHTML = rows.length ? rows.map((s) => h`
    <div class="source ${srcOn(s.id) ? "" : "off"}">
      <div>
        <div class="name">${s.name}${s.warn ? raw(h` <span class="tag warn">${s.warn}</span>`) : ""}${s.id === "exposure" && getKey("shodan") ? raw(' <span class="tag violet">Shodan</span>') : ""}</div>
        <div class="desc">${s.desc}</div>
      </div>
      <label class="switch"><input type="checkbox" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-label="${s.name}"><span></span></label>
    </div>`).join("") : `<p class="empty" style="padding:0">Enter a domain, IP or ASN.</p>`;
}
$("#rSources").addEventListener("change", (e) => {
  const t = e.target.dataset.toggle; if (!t) return;
  srcState[t] = e.target.checked; store.set("crawlr_v2_recon_sources", srcState);
  e.target.closest(".source").classList.toggle("off", !e.target.checked);
});

// ---- state ---------------------------------------------------------------------
export const state = { target: "", type: "", collected: {}, ai: null, deep: null, historyId: null, running: false, tab: "findings" };
const checkKey = () => `crawlr_checked_${state.target}`;
const log = makeLog($("#rRunlog"));
bindLedger($("#rLedger"), checkKey);

// ---- findings -------------------------------------------------------------------
const RISKY = { 21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB" };
const daysUntil = (d) => { const t = Date.parse(d); return Number.isFinite(t) ? Math.round((t - Date.now()) / 86400000) : null; };
const flat = (v) => [].concat(v ?? []).flat().filter(Boolean);

export const TIERS = [
  { id: "flag",      title: "Flags",            cls: "flag",    open: true, blurb: "Known CVEs, risky open services, weak headers, expiring certificates or domains." },
  { id: "surface",   title: "Exposed services", cls: "surface", open: true, blurb: "What answers from the internet." },
  { id: "inventory", title: "Subdomains",       cls: "",        collapseOver: 15, limit: 300, blurb: "From DNS checks, certificate transparency and passive sources. Each opens in a new tab." },
];

export function buildFindings(c, target) {
  const { items, add } = itemCollector();
  const { facts, add: fact } = factCollector();
  const exp = c.shodan;
  const expSrc = exp?.source === "internetdb" ? "InternetDB" : "Shodan";

  // flags
  for (const cve of (exp?.vulns || []).slice(0, 30)) add({ tier: "flag", what: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}`, meta: exp.ip ? `on ${exp.ip}` : "", source: expSrc, key: `cve:${cve}` });
  const openPorts = new Map();
  for (const r of c.portscan?.results || []) if (r.open) openPorts.set(Number(r.port), { svc: r.service, src: "Port scan" });
  for (const p of exp?.ports || []) if (!openPorts.has(Number(p))) openPorts.set(Number(p), { svc: "", src: expSrc });
  for (const [p, { svc, src }] of [...openPorts].sort((a, b) => a[0] - b[0])) {
    if (RISKY[p]) add({ tier: "flag", what: `${RISKY[p]} open on ${p}`, url: "", meta: "should rarely face the internet", source: src, key: `port:${p}` });
    else add({ tier: "surface", what: `${p}/tcp${svc ? ` ${svc}` : ""}`, url: "", meta: "", source: src, key: `port:${p}` });
  }
  const hd = c.headers;
  if (hd?.found && ["C", "D", "F"].includes(String(hd.grade).toUpperCase())) add({ tier: "flag", what: `Security headers grade ${hd.grade}`, url: "", meta: `${hd.present ?? 0} of ${hd.total ?? 0} present`, source: "HTTP headers", key: "hdr:grade" });
  const ssl = c.ssl;
  if (ssl && (ssl.error || ssl.found === false) && state.type === "domain") add({ tier: "flag", what: "No valid TLS certificate", url: "", meta: ssl.error || "", source: "TLS", key: "tls:none" });
  if (ssl?.found && ssl.days_left != null && ssl.days_left < 30) add({ tier: "flag", what: ssl.days_left < 0 ? "TLS certificate expired" : `TLS certificate expires in ${ssl.days_left} days`, url: "", meta: ssl.not_after || "", source: "TLS", key: "tls:expiry" });
  const wh = c.whois;
  const whDays = daysUntil(wh?.expiration_date);
  if (whDays != null && whDays < 60) add({ tier: "flag", what: whDays < 0 ? "Domain registration expired" : `Domain expires in ${whDays} days`, url: "", meta: String(wh.expiration_date).slice(0, 10), source: "WHOIS", key: "whois:expiry" });
  if (c.redirects?.found && c.redirects.is_clean === false) add({ tier: "flag", what: "Redirect chain leaves the domain or downgrades", url: c.redirects.final_url, meta: `${c.redirects.hop_count ?? 0} hops`, source: "Redirect chain", key: "redir:dirty" });

  // surface
  if (c.redirects?.final_url) add({ tier: "surface", what: c.redirects.final_url, url: c.redirects.final_url, meta: "final URL", source: "Redirect chain", key: "redir:final" });
  for (const hn of (exp?.hostnames || []).slice(0, 20)) add({ tier: "surface", what: hn, url: `https://${hn}`, meta: "hostname on this IP", source: expSrc, key: `host:${hn}` });

  // inventory
  for (const s of c.subdomains?.subdomains || []) add({ tier: "inventory", what: s.subdomain, url: `https://${s.subdomain}`, meta: [flat(s.ips).join(", "), s.source].filter(Boolean).join(" · "), source: "Subdomains", key: `sub:${s.subdomain}` });

  const hv = c.harvest;
  if (hv && !hv.error && !hv.skipped) {
    for (const e of hv.emails || []) add({ tier: "surface", what: e, url: "", meta: "address on this domain", source: "Passive discovery", key: `email:${e}` });
    for (const hn of hv.hosts || []) add({ tier: "inventory", what: hn, url: `https://${hn}`, meta: (hv.host_sources?.[hn] || []).join(", "), source: "Passive discovery", key: `sub:${hn}` });
  }

  // facts
  if (wh?.found !== false) {
    fact("Registrar", wh?.registrar, "WHOIS");
    fact("Registered", String(wh?.creation_date || "").slice(0, 10), "WHOIS");
    fact("Expires", String(wh?.expiration_date || "").slice(0, 10), "WHOIS");
    fact("Registrant", wh?.privacy_protected ? "Privacy protected" : [wh?.org, wh?.country].filter(Boolean).join(", "), "WHOIS");
    fact("Name servers", flat(wh?.name_servers).slice(0, 4).map((x) => String(x).toLowerCase()), "WHOIS");
  }
  const ip = c.asn?.ip || c.portscan?.ip || exp?.ip;
  fact("IP", ip, c.asn?.ip ? "Network owner" : expSrc);
  if (c.asn?.found !== false && c.asn?.asn) fact("Network", `${c.asn.asn}${c.asn.org ? ` · ${c.asn.org}` : ""}`, "Network owner");
  if (c.dns?.cloudflare_proxied) fact("Hosting", "Behind Cloudflare proxy", "DNS");
  fact("Server", hd?.server, "HTTP headers");
  if (ssl?.found) { fact("TLS issuer", ssl.issuer, "TLS"); fact("TLS valid until", String(ssl.not_after || "").slice(0, 10), "TLS"); }
  const tech = c.techfp?.detected_tech || {};
  fact("CMS", flat(tech.cms), "Tech fingerprint");
  fact("Frameworks", flat(tech.frameworks), "Tech fingerprint");
  fact("CDN", flat(tech.cdn), "Tech fingerprint");
  if (exp?.org) fact("Org", exp.org, expSrc);
  if (exp?.country) fact("Location", [exp.city, exp.country].filter(Boolean).join(", "), expSrc);
  if (c.wayback?.found) fact("Archived", `${fmtNum(c.wayback.total_snapshots)} snapshots`, "Wayback", c.wayback.most_recent_snapshot?.url);
  const ad = c.asn_detail;
  if (ad?.found) {
    fact("Organization", ad.org || ad.name, "ASN detail");
    fact("Country", ad.country, "ASN detail");
    fact("Registry", ad.rir, "ASN detail");
    fact("Registered", ad.date_registered, "ASN detail");
    fact("Prefixes", ad.total_prefixes, "ASN detail");
    fact("Peers", ad.total_peers, "ASN detail");
  }
  const order = { flag: 0, surface: 1, inventory: 2 };
  items.sort((a, b) => order[a.tier] - order[b.tier]);
  return { items, facts };
}

// ---- cards -------------------------------------------------------------------------
const card = (title, badge, body) => `<article class="card"><div class="card-head"><h3>${esc(title)}</h3>${badge}</div><div class="card-body">${body}</div></article>`;
const tag = (t, cls = "") => h`<span class="tag ${cls}">${t}</span>`;
const kv = (pairs) => `<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => h`<dt>${k}</dt><dd>${raw(v)}</dd>`).join("")}</dl>`;
const mono = (s) => h`<span class="mono">${s}</span>`;
const muted = (s) => h`<p style="color:var(--ink-3);font-size:var(--fs-1)">${s}</p>`;
const errCard = (title, d) => card(title, tag("error", "warn"), muted(d.error));

const CARDS = {
  harvest: (d) => harvestCard(d),
  dns: (d) => {
    const rec = d.records || {};
    const rows = Object.entries(rec).filter(([, v]) => flat(v).length).map(([t, v]) => [t, flat(v).map((x) => mono(typeof x === "object" ? JSON.stringify(x) : x)).join("<br>")]);
    return card("DNS records", tag(`${fmtNum(d.total ?? rows.length)} records`) + (d.cloudflare_proxied ? " " + tag("Cloudflare", "warn") : ""), rows.length ? kv(rows) : muted("No records returned."));
  },
  whois: (d) => d.error ? errCard("WHOIS", d) : card("WHOIS", d.privacy_protected ? tag("privacy") : "", kv([["Registrar", esc(d.registrar)], ["Created", esc(String(d.creation_date || "").slice(0, 10))], ["Updated", esc(String(d.updated_date || "").slice(0, 10))], ["Expires", esc(String(d.expiration_date || "").slice(0, 10))], ["Org", esc(d.org)], ["Country", esc(d.country)], ["Name servers", flat(d.name_servers).map((x) => mono(String(x).toLowerCase())).join("<br>")]])),
  ssl: (d) => d.error || d.found === false ? card("TLS certificate", tag("none", "warn"), muted(d.error || "No certificate presented.")) : card("TLS certificate", tag(d.days_left < 30 ? `${d.days_left} days left` : "valid", d.days_left < 30 ? "warn" : "ok"), kv([["Common name", mono(d.common_name)], ["Issuer", esc(d.issuer)], ["Valid from", esc(String(d.not_before || "").slice(0, 10))], ["Valid until", esc(String(d.not_after || "").slice(0, 10))], ["Also covers", flat(d.sans).slice(0, 12).map(mono).join("<br>") + (flat(d.sans).length > 12 ? h`<br>+${flat(d.sans).length - 12} more` : "")]])),
  headers: (d) => {
    if (d.error || d.found === false) return errCard("HTTP headers", { error: d.error || "No response" });
    const g = String(d.grade || "?").toUpperCase();
    const rows = Object.entries(d.security_headers || {}).map(([k, v]) => [k, v?.present ? h`<span style="color:var(--ok)">present</span>${v.value ? raw(h` <span class="mono" style="color:var(--ink-3)">${String(v.value).slice(0, 80)}</span>`) : ""}` : `<span style="color:var(--warn)">missing</span>`]);
    return card("HTTP headers", tag(`grade ${g}`, g === "A" ? "ok" : g === "B" ? "" : "warn"), kv([["Server", esc(d.server)], ...rows]));
  },
  subdomains: (d) => {
    const subs = d.subdomains || [];
    const ct = d.ct_entries || [];
    return card("Subdomains", tag(`${fmtNum(subs.length)} found`) + (d.ct_found ? " " + tag(`${fmtNum(d.ct_found)} from CT`) : ""),
      (subs.length ? `<div style="font-size:var(--fs-1)">${subs.slice(0, 25).map((s) => h`<div>${raw(link(`https://${s.subdomain}`, s.subdomain))} <span style="color:var(--ink-4)" class="mono">${flat(s.ips).join(", ")}</span></div>`).join("")}${subs.length > 25 ? h`<div style="color:var(--ink-4)">+${subs.length - 25} more in the ledger</div>` : ""}</div>` : muted("None found."))
      + (ct.length ? h`<details style="margin-top:10px;font-size:var(--fs-0)"><summary style="cursor:pointer;color:var(--ink-3)">Recent certificate log entries (${ct.length})</summary>${raw(ct.slice(0, 30).map((e) => h`<div class="mono" style="color:var(--ink-2)">${String(e.date || "").slice(0, 10)}  ${e.subdomain}  <span style="color:var(--ink-4)">${e.issuer}</span></div>`).join(""))}</details>` : ""));
  },
  asn: (d) => d.error || d.found === false ? errCard("Network owner", { error: d.error || "Not found" }) : card("Network owner", tag(d.asn || ""), kv([["IP", mono(d.ip)], ["ASN", link(`https://bgp.he.net/${d.asn}`, d.asn)], ["Org", esc(d.org)], ["Prefixes", flat(d.prefixes).slice(0, 8).map(mono).join("<br>")]])),
  portscan: (d) => {
    if (d.error) return errCard("Port scan", d);
    const open = (d.results || []).filter((r) => r.open);
    return card("Port scan", tag(`${open.length} of ${d.total_scanned ?? (d.results || []).length} open`, open.some((r) => RISKY[r.port]) ? "warn" : ""), open.length ? `<div style="font-size:var(--fs-1)">${open.map((r) => h`<div><span class="mono">${r.port}/tcp</span> ${r.service}${RISKY[r.port] ? raw(' <span class="tag warn">risky</span>') : ""}</div>`).join("")}</div>` : muted("No common ports answered."));
  },
  shodan: (d) => {
    const isIdb = d.source === "internetdb";
    const title = isIdb ? "Exposure (InternetDB)" : "Exposure (Shodan)";
    if (!d.found) return card(title, tag(d.error ? "error" : "not indexed", d.error ? "warn" : ""), muted(d.error || "This IP is not in the index."));
    const vulns = d.vulns || [];
    const svc = (d.services || []).slice(0, 8).map((s) => h`<div><span class="mono">${s.port}/${s.transport}</span> ${[s.product, s.version].filter(Boolean).join(" ")}</div>`).join("");
    return card(title, tag(`${(d.ports || []).length} ports`) + (vulns.length ? " " + tag(`${d.vuln_count || vulns.length} CVEs`, "warn") : ""),
      kv([["IP", mono(d.ip)], ["Org", esc(d.org)], ["ISP", esc(d.isp)], ["OS", esc(d.os)], ["Location", esc([d.city, d.country].filter(Boolean).join(", "))], ["Ports", mono((d.ports || []).join(", "))], ["Hostnames", flat(d.hostnames).slice(0, 8).map(mono).join("<br>")], ["Tags", esc(flat(d.tags).join(", "))], ["Software", flat(d.cpes).slice(0, 6).map((x) => mono(String(x).replace(/^cpe:\/a:/, ""))).join("<br>")], ["CVEs", vulns.slice(0, 12).map((v) => link(`https://nvd.nist.gov/vuln/detail/${v}`, v)).join(", ") + (vulns.length > 12 ? h` +${vulns.length - 12}` : "")]])
      + (svc ? `<div style="margin-top:8px;font-size:var(--fs-1)">${svc}</div>` : "")
      + (isIdb ? muted("Free keyless source. Add a Shodan key in Settings for banners, org and location.").replace("<p ", '<p style="margin-top:8px" ') : ""));
  },
  wayback: (d) => !d.found ? card("Wayback Machine", tag("none"), muted("No snapshots archived.")) : card("Wayback Machine", tag(`${fmtNum(d.total_snapshots)} snapshots`), kv([["Latest", link(d.most_recent_snapshot?.url, String(d.most_recent_snapshot?.timestamp || "open"))], ["History", (d.snapshot_history || []).slice(0, 8).map((s) => link(s.url, s.date)).join("<br>")]])),
  redirects: (d) => !d.found ? card("Redirect chain", tag("none"), muted("No response.")) : card("Redirect chain", tag(d.is_clean ? "clean" : "check", d.is_clean ? "ok" : "warn"), `<div style="font-size:var(--fs-1)">${(d.hops || []).map((x) => h`<div><span class="mono" style="color:var(--ink-3)">${x.status_code}</span> ${raw(link(x.url, x.url))}${x.server ? raw(h` <span style="color:var(--ink-4)">${x.server}</span>`) : ""}</div>`).join("")}</div>`),
  techfp: (d) => {
    if (!d.found) return card("Tech fingerprint", tag("none"), muted("Nothing identified."));
    const t = d.detected_tech || {};
    return card("Tech fingerprint", "", kv([["CMS", esc(flat(t.cms).join(", "))], ["Server", esc(flat(t.server).join(", "))], ["Language", esc(flat(t.language).join(", "))], ["Frameworks", esc(flat(t.frameworks).join(", "))], ["CDN", esc(flat(t.cdn).join(", "))], ["Analytics", esc(flat(t.analytics).join(", "))], ["Missing headers", esc(flat(d.security_headers?.missing).join(", "))]]));
  },
  asn_detail: (d) => {
    if (!d.found) return card("ASN detail", tag("not found", "warn"), muted("The registry has no record for this ASN."));
    const v4 = flat(d.prefixes_v4), v6 = flat(d.prefixes_v6), peers = d.peers || [];
    return card("ASN detail", tag(d.asn), kv([["Name", esc(d.name)], ["Org", esc(d.org)], ["Handle", esc(d.handle)], ["Country", esc(d.country)], ["Registry", esc(d.rir)], ["Registered", esc(d.date_registered)], ["Lookup", link(`https://bgp.he.net/${d.asn}`, "bgp.he.net")]]))
      + card("Announced prefixes", tag(`${v4.length} v4 · ${v6.length} v6`), `<div class="mono" style="font-size:var(--fs-0);columns:2 160px">${[...v4.slice(0, 40), ...v6.slice(0, 20)].map(esc).join("<br>")}</div>`)
      + (peers.length ? card("Peers", tag(`${fmtNum(d.total_peers ?? peers.length)}`), `<div style="font-size:var(--fs-1)">${peers.slice(0, 25).map((p) => h`<div>${raw(link(`https://bgp.he.net/AS${String(p.asn).replace(/^AS/i, "")}`, `AS${String(p.asn).replace(/^AS/i, "")}`))} ${p.name}</div>`).join("")}</div>`) : "");
  },
};
const CARD_ORDER = ["shodan", "portscan", "headers", "ssl", "dns", "whois", "subdomains", "harvest", "asn", "asn_detail", "redirects", "techfp", "wayback"];

function renderCards() {
  const html = CARD_ORDER.filter((k) => state.collected[k]).map((k) => { try { return CARDS[k](state.collected[k]); } catch (e) { return card(k, tag("render error", "warn"), muted(e.message)); } }).join("");
  $("#rBySource").hidden = !html;
  $("#rSourceCards").innerHTML = html;
}

function renderAll() {
  const { items, facts } = buildFindings(state.collected, state.target);
  $("#rEmpty").hidden = true;
  renderTiers($("#rLedger"), items, TIERS, new Set(store.get(checkKey(), [])), `<div class="empty"><h3>No findings</h3><p>Nothing risky or exposed was found. Details from each source are below.</p></div>`);
  renderFacts($("#rFacts"), facts);
  renderCards();
  if (state.tab === "topology") drawGraph();
  return items;
}

// ---- tabs + topology --------------------------------------------------------------------
$("#rTabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) setTab(b.dataset.tab); });
function setTab(tab) {
  state.tab = tab;
  $$("#rTabs [data-tab]").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
  $("#rFindings").hidden = tab !== "findings";
  $("#rTopology").hidden = tab !== "topology";
  if (tab === "topology") drawGraph();
}
let d3Loading;
function loadD3() {
  if (window.d3) return Promise.resolve();
  d3Loading ??= new Promise((res, rej) => {
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js";
    s.onload = res; s.onerror = () => rej(new Error("Could not load the graph library."));
    document.head.appendChild(s);
  });
  return d3Loading;
}
async function drawGraph() {
  const el = $("#rGraph");
  if (!state.target) { el.innerHTML = `<div class="empty">Run a target first.</div>`; return; }
  try {
    await loadD3();
    const { renderGraph } = await import("./graph.js");
    requestAnimationFrame(() => renderGraph(el, state.collected, state.target));
  } catch (err) {
    el.innerHTML = h`<div class="empty">${err.message}</div>`;
  }
}

// ---- AI ------------------------------------------------------------------------------------
const aiBody = () => {
  const c = state.collected;
  return { target: state.target, dns: c.dns || null, whois: c.whois || null, ssl: c.ssl || null, headers: c.headers || null, subdomains: c.subdomains || null, asn: c.asn || null, portscan: c.portscan || null, asn_detail: c.asn_detail || null, shodan: c.shodan || null };
};
function renderAi() {
  const box = $("#rAiPanel");
  if (!state.ai) { box.innerHTML = `<p class="empty" style="padding:0">${aiAvailable() ? "Runs automatically after the sources finish." : "Add a key in Settings to turn on AI analysis."}</p>`; return; }
  const deep = state.deep ? `<button class="btn btn-sm" type="button" data-open-rreport="deep">Deep analysis</button>` : aiAvailable() ? `<button class="btn btn-sm" type="button" id="rDeepBtn">Deep analysis…</button>` : "";
  box.innerHTML = summaryBlock(state.ai, { reportId: "summary", attr: "data-open-rreport", deepDive: deep });
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-open-rreport]");
  if (b) openReport(b.dataset.openRreport);
  if (e.target.id === "rDeepBtn") confirmDeep();
});
function openReport(which) {
  const ai = which === "deep" ? state.deep : state.ai;
  if (!ai) return;
  openModal({ title: which === "deep" ? "Deep analysis" : "AI analysis", wide: true, body: `<div class="report">${markdown(ai.summary)}</div>`,
    actions: [{ label: "Copy markdown", onClick: () => navigator.clipboard?.writeText(ai.summary).then(() => toast("Copied")) }, { label: "Close", primary: true, onClick: closeModal }] });
}
async function runAi() {
  if (!srcOn("ai") || !aiAvailable()) return;
  const row = log.add(`AI analysis (${providerName()})`);
  try {
    state.ai = normalizeAi(await postAi("/api/infra/summarize", aiBody()));
    log.set(row, `AI analysis · ${state.ai.model || providerName()}`, "done");
  } catch (err) {
    log.set(row, `AI analysis: ${err.detail || err.message}`, err.status === 429 ? "wait" : "err");
    if (err.status === 429) toast(err.detail, 5000);
  }
  renderAi();
}
function confirmDeep() {
  openModal({ title: "Run a deep analysis?", body: h`<p style="font-size:var(--fs-1);color:var(--ink-2)">${providerName()} gets everything collected for ${state.target} and writes a full attack surface assessment: exposure, likely entry points, misconfigurations and prioritized next steps. This counts as a Deep Dive on the free tier.</p>`,
    actions: [{ label: "Cancel", onClick: closeModal }, { label: "Run deep analysis", primary: true, onClick: async () => {
      closeModal();
      const row = log.add("Deep analysis"); log.open();
      try { state.deep = normalizeAi(await postAi("/api/analyze/deep", aiBody())); log.set(row, "Deep analysis complete", "done"); saveHistory(); renderAi(); openReport("deep"); }
      catch (err) { log.set(row, `Deep analysis: ${err.detail || err.message}`, "err"); toast(err.detail || err.message, 5000); }
    } }] });
}

// ---- run ---------------------------------------------------------------------------------------
async function source(label, url, body, key, headers = {}) {
  const row = log.add(label);
  try {
    const d = await post(url, body, headers);
    state.collected[key] = d;
    const note = d?.error ? d.error : d?.found === false ? "nothing found" : "done";
    log.set(row, `${label} · ${note}`, d?.error ? "wait" : "done");
    renderAll();
    return d;
  } catch (err) {
    log.set(row, `${label}: ${err.detail || err.message}`, "err");
    return null;
  }
}

export async function run(raw0) {
  const target = String(raw0 || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  if (!target || state.running) return;
  const type = detect(target);
  if (!RECON_TYPES.includes(type)) { toast(`${TYPE_LABEL[type] || "That"} targets run in Investigate.`); return; }
  Object.assign(state, { target, type, collected: {}, ai: null, deep: null, historyId: null, running: true });
  store.del(checkKey());
  $("#rTargetInput").value = target; renderSources(type);
  $("#rRunBtn").disabled = true; $("#rRunBtn").textContent = "Running…";
  $("#rLedger").innerHTML = ""; $("#rEmpty").hidden = true; $("#rBySource").hidden = true; $("#rFacts").innerHTML = `<p class="empty" style="padding:0">Collecting…</p>`;
  $("#rNotes").value = ""; notesMeta();
  head(); renderAi(); log.start();

  const on = srcOn;
  const T = { domain: target };
  if (type === "asn") {
    if (on("asndetail")) await source("ASN detail", "/api/infra/asn-detail", { asn_number: parseInt(target.replace(/^AS/i, ""), 10) }, "asn_detail");
  } else {
    const jobs = [];
    if (type === "domain" && on("dns")) jobs.push(source("DNS records", "/api/infra/dns", T, "dns"));
    if (type === "domain" && on("whois")) jobs.push(source("WHOIS", "/api/infra/whois", T, "whois"));
    if (on("ssl")) jobs.push(source("TLS certificate", "/api/infra/ssl", T, "ssl"));
    if (on("headers")) jobs.push(source("HTTP headers", "/api/infra/headers", T, "headers"));
    if (type === "domain" && on("subdomains")) jobs.push(source("Subdomains", "/api/infra/subdomains", T, "subdomains"));
    if (type === "domain" && on("harvest")) jobs.push(source("Passive discovery", "/api/recon/harvester", T, "harvest"));
    if (on("asn")) jobs.push(source("Network owner", "/api/infra/asn", T, "asn"));
    if (on("exposure")) jobs.push(getKey("shodan") ? source("Exposure (Shodan)", "/api/recon/shodan", { target }, "shodan", { "X-Shodan-Key": getKey("shodan") }) : source("Exposure (InternetDB)", "/api/recon/internetdb", { target }, "shodan"));
    if (on("redirects")) jobs.push(source("Redirect chain", "/api/infra/redirects", { target }, "redirects"));
    if (type === "domain" && on("techfp")) jobs.push(source("Tech fingerprint", "/api/infra/techfingerprint", T, "techfp"));
    if (type === "domain" && on("wayback")) jobs.push(source("Wayback Machine", "/api/infra/wayback", T, "wayback"));
    await Promise.all(jobs);
    if (on("portscan")) await source("Port scan", "/api/infra/portscan", T, "portscan");
    // IP → ASN map for the topology graph
    const c = state.collected;
    const ips = [...new Set([...(c.subdomains?.subdomains || []).flatMap((s) => flat(s.ips)), ...flat(c.dns?.records?.A)].filter((x) => /^\d+\.\d+\.\d+\.\d+$/.test(String(x))))].slice(0, 100);
    if (ips.length) { try { c.ipAsn = (await post("/api/infra/ip-asn", { ips })).results || {}; } catch { /* graph falls back to the main ASN */ } }
  }

  await runAi();
  const items = renderAll();
  const flags = items.filter((i) => i.tier === "flag").length;
  log.finish(`${plural(Object.keys(state.collected).filter((k) => k !== "ipAsn").length, "source")} · ${plural(flags, "flag")}`);
  head(`${TYPE_LABEL[type]} · ${plural(flags, "flag")} · ${plural(items.length - flags, "other finding")}`);
  state.running = false;
  $("#rRunBtn").disabled = false; $("#rRunBtn").textContent = "Run recon";
  saveHistory();
}

function head(meta) {
  $("#rMainHead").hidden = false;
  $("#rCaseTarget").textContent = state.target;
  $("#rCaseMeta").textContent = meta || TYPE_LABEL[state.type] || "";
}

// ---- history (classic-compatible RECON entries) ---------------------------------------------------
const HISTORY_KEY = "crawlr_history";
function saveHistory() {
  const list = store.get(HISTORY_KEY, []);
  const entry = { id: state.historyId || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: state.target, type: "RECON", timestamp: Date.now(), results: state.collected, aiSummary: state.ai?.summary || null, ai: state.ai, deep: state.deep, notes: $("#rNotes").value, v2: true };
  state.historyId = entry.id;
  const i = list.findIndex((e) => e.id === entry.id);
  if (i >= 0) list[i] = entry; else list.unshift(entry);
  while (list.length > 50) list.pop();
  if (!store.set(HISTORY_KEY, list)) { list.splice(Math.floor(list.length / 2)); store.set(HISTORY_KEY, list); }
}
export function loadHistory(e) {
  Object.assign(state, { target: e.target, type: detect(e.target), collected: e.results || {}, ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deep: e.deep ? normalizeAi(e.deep) : null, historyId: e.id, running: false });
  $("#rTargetInput").value = e.target; renderSources(state.type); $("#rRunlog").hidden = true;
  head(`${TYPE_LABEL[state.type]} · from history · ${new Date(e.timestamp).toLocaleString()}`);
  renderAll(); renderAi();
  $("#rNotes").value = e.notes || ""; notesMeta();
}
export function clearCase() {
  Object.assign(state, { target: "", type: "", collected: {}, ai: null, deep: null, historyId: null, running: false });
  $("#rTargetInput").value = ""; $("#rMainHead").hidden = true; $("#rRunlog").hidden = true; $("#rLedger").innerHTML = ""; $("#rBySource").hidden = true;
  $("#rEmpty").hidden = false; $("#rFacts").innerHTML = `<p class="empty" style="padding:0">Nothing yet.</p>`; $("#rNotes").value = ""; notesMeta();
  renderSources(""); renderAi(); setTab("findings");
}

// ---- notes + export ----------------------------------------------------------------------------------
let notesTimer;
function notesMeta() { $("#rNotesCount").textContent = `${fmtNum($("#rNotes").value.length)} chars`; }
$("#rNotes").addEventListener("input", () => {
  notesMeta(); $("#rNotesStatus").textContent = "Saving…"; clearTimeout(notesTimer);
  notesTimer = setTimeout(() => { if (state.target) saveHistory(); $("#rNotesStatus").textContent = "Saved"; }, 600);
});

export function exportCase() {
  if (!state.target) return;
  const { items, facts } = buildFindings(state.collected, state.target);
  const md = [`# CrawlR recon: ${state.target}`, `Generated ${new Date().toISOString()} · ${TYPE_LABEL[state.type]}`, "",
    "## What we know", ...(facts.length ? facts.map((f) => `- **${f.k}:** ${f.v} _(${f.source})_`) : ["- Nothing extracted"]), "",
    ...TIERS.flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...rows.map((i) => `- ${i.url ? `[${i.what}](${i.url})` : i.what}${i.meta ? ` — ${i.meta}` : ""} _(${i.source})_`), ""] : []; }),
    ...(state.ai ? ["## AI analysis", state.ai.summary, ""] : []), ...(state.deep ? ["## Deep analysis", state.deep.summary, ""] : []),
    ...($("#rNotes").value.trim() ? ["## Notes", $("#rNotes").value.trim(), ""] : [])].join("\n");
  const slug = state.target.replace(/[^a-z0-9]+/gi, "-").slice(0, 60);
  const dl = (name, content, type) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000); closeModal(); };
  openModal({ title: "Export recon", body: `<p style="font-size:var(--fs-1);color:var(--ink-2)">Markdown includes findings, facts, AI reports and notes. JSON is the raw data from every source.</p>`,
    actions: [{ label: "Download JSON", onClick: () => dl(`crawlr-recon-${slug}.json`, JSON.stringify({ target: state.target, type: state.type, collected: state.collected, ai: state.ai, deep: state.deep, notes: $("#rNotes").value }, null, 2), "application/json") },
              { label: "Download Markdown", primary: true, onClick: () => dl(`crawlr-recon-${slug}.md`, md, "text/markdown") }] });
}

// ---- rail wiring -----------------------------------------------------------------------------------------
$("#rTargetInput").addEventListener("input", () => { const t = detect($("#rTargetInput").value); renderSources(RECON_TYPES.includes(t) ? t : ""); $("#rTargetDetected").innerHTML = $("#rTargetInput").value.trim() ? h`<span>Detected</span> <span class="pill ${RECON_TYPES.includes(t) ? "violet" : ""}">${TYPE_LABEL[t] || ""}</span>${RECON_TYPES.includes(t) ? "" : raw(' <span>runs in <a href="#investigate" data-goto="investigate">Investigate</a></span>')}` : ""; });
$("#rTargetInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#rRunBtn").click(); });
$("#rRunBtn").addEventListener("click", () => { $("#rRail").classList.remove("open"); run($("#rTargetInput").value); });
$("#rClearBtn").addEventListener("click", clearCase);
$("#rExportBtn").addEventListener("click", exportCase);
renderSources("");
