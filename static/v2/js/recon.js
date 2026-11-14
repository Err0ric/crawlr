// Recon mode: infrastructure for a domain, IP or ASN.
import { howTag, $, $$, h, raw, esc, link, store, toast, post, postAi, getKey, aiAvailable, aiCost, freeLeft, userAiKey, providerName, detect, TYPE_LABEL, RECON_TYPES, fmtNum, plural, sourceOutcome, roving, download, slug } from "./core.js";
import { normalizeAi, markdown, summaryBlock, aiStartHtml, copyPrompt, parseReply } from "./ai.js";
import { reconBrief } from "./brief.js";
import { reconTimeline } from "./timeline.js";
import { openModal, closeModal } from "./ui.js";
import { makeLog, renderTiers, bindLedger, renderFacts, factCollector, itemCollector, failedNotice, diffRuns, diffNotice, standaloneHtml, makeTabs, setTabCount, renderBrief, casePrint } from "./workbench.js";
import { buildCaseFile } from "./casefile.js";
import { harvestCard, errorCard } from "./renderers.js";

// ---- sources -----------------------------------------------------------------
export const SOURCES = [
  { id: "dns", how: "record",        name: "DNS records",      desc: "A, MX, NS, TXT, CNAME, SOA",                     types: ["domain"],        on: true },
  { id: "whois", how: "record",      name: "WHOIS",            desc: "registrar, dates, privacy",                      types: ["domain"],        on: true },
  { id: "ssl", how: "record",        name: "TLS certificate",  desc: "issuer, names covered, expiry",                  types: ["domain", "ip"],  on: true },
  { id: "headers", how: "record",    name: "HTTP headers",     desc: "server and security header grade",               types: ["domain", "ip"],  on: true },
  { id: "subdomains", how: "index", name: "Subdomains",       desc: "DNS checks and certificate transparency logs",   types: ["domain"],        on: true },
  { id: "harvest", how: "index",    name: "Passive discovery", desc: "hosts and addresses from 8 public sources (CT, passive DNS, URLScan, Wayback)", types: ["domain"], on: true },
  { id: "emailsec", how: "record",   name: "Email security",   desc: "SPF, DMARC, DKIM, MTA-STS: can this domain be spoofed?", types: ["domain"],     on: true },
  { id: "dnsdepth", how: "record",   name: "DNS hardening",    desc: "CAA, DNSSEC, wildcard DNS, reverse DNS",         types: ["domain"],        on: true },
  { id: "takeover", how: "guess",   name: "Takeover candidates", desc: "subdomains pointing at claimable cloud services (DNS only)", types: ["domain"], on: true },
  { id: "lookalikes", how: "record", name: "Lookalike domains", desc: "registered typo and lookalike variants (DNS only)", types: ["domain"],     on: true },
  { id: "wellknown", how: "record",  name: "Published files",  desc: "security.txt, robots.txt, favicon hash",         types: ["domain"],        on: true },
  { id: "asn", how: "index",        name: "Network owner",    desc: "ASN, organization, announced prefixes",          types: ["domain", "ip"],  on: true },
  { id: "exposure", how: "index",   name: "Exposure",         desc: "open ports and CVEs (InternetDB, or Shodan with your key)", types: ["domain", "ip"], on: true },
  { id: "portscan", how: "record",   name: "Port scan",        desc: "connects to 20 common ports on the target. Only scan hosts you own or are authorized to test.", types: ["domain", "ip"], on: false, warn: "active" },
  { id: "redirects", how: "record",  name: "Redirect chain",   desc: "every hop to the final URL",                     types: ["domain", "ip"],  on: true },
  { id: "techfp", how: "guess",     name: "Tech fingerprint", desc: "CMS, server, frameworks, CDN",                   types: ["domain"],        on: true },
  { id: "wayback", how: "index",    name: "Wayback Machine",  desc: "archived snapshots",                             types: ["domain"],        on: true },
  { id: "asndetail", how: "index",  name: "ASN detail",       desc: "organization, prefixes, peers",                  types: ["asn"],           on: true },
];
const srcState = store.get("crawlr_v2_recon_sources", {});
const srcOn = (id) => (id in srcState ? !!srcState[id] : SOURCES.find((s) => s.id === id)?.on ?? false);

export function renderSources(type) {
  const rows = SOURCES.filter((s) => !type || s.types.includes(type));
  $("#rSources").innerHTML = rows.length ? rows.map((s) => h`
    <div class="source ${srcOn(s.id) ? "" : "off"}">
      <div>
        <div class="name" id="rsrc-${s.id}">${s.name}${s.warn ? raw(h` <span class="tag warn">${s.warn}</span>`) : ""}${s.id === "exposure" && getKey("shodan") ? raw(' <span class="tag violet">Shodan</span>') : ""}</div>
        <div class="desc" id="rsrcd-${s.id}">${raw(howTag(s.how))}${s.desc}</div>
      </div>
      <label class="switch"><input type="checkbox" role="switch" data-toggle="${s.id}" ${srcOn(s.id) ? "checked" : ""} aria-label="${s.name}" aria-labelledby="rsrc-${s.id}" aria-describedby="rsrcd-${s.id}"><span></span></label>
    </div>`).join("") : `<p class="empty flat">Type a domain, IP or ASN to see which sources apply.</p>`;
  paintCount();
}
function paintCount() {
  const on = $$("#rSources [data-toggle]").filter((el) => el.checked).length, all = $$("#rSources [data-toggle]").length;
  $("#rSourcesCount").textContent = all ? `${on} of ${all}` : "";
}
$("#rSources").addEventListener("change", (e) => {
  const t = e.target.dataset.toggle; if (!t) return;
  srcState[t] = e.target.checked; store.set("crawlr_v2_recon_sources", srcState);
  e.target.closest(".source").classList.toggle("off", !e.target.checked);
  paintCount();
});

// ---- state ---------------------------------------------------------------------
export const state = { target: "", type: "", collected: {}, ai: null, deep: null, historyId: null, running: false, cancelled: false, controller: null, prev: null, aiBusy: false, tab: "findings", ran: 0 };
const SRC_NAME = { email_posture: "Email security", dns_depth: "DNS hardening", takeover: "Takeover candidates", lookalikes: "Lookalike domains", wellknown: "Published files", dns: "DNS records", whois: "WHOIS", ssl: "TLS certificate", headers: "HTTP headers", subdomains: "Subdomains", harvest: "Passive discovery", asn: "Network owner", shodan: "Exposure", portscan: "Port scan", redirects: "Redirect chain", techfp: "Tech fingerprint", wayback: "Wayback Machine", asn_detail: "ASN detail" };
// A source that failed is unknown. "No certificate" or "not indexed" are answers; a timeout is not.
const isFailed = (d) => !!(d && typeof d === "object" && (d.error_code || d.error) && d.error_code !== "not_found");
const failedSources = () => Object.entries(state.collected).filter(([k, v]) => SRC_NAME[k] && isFailed(v)).map(([k, v]) => ({ name: SRC_NAME[k], ...sourceOutcome(v) }));
const checkKey = () => `crawlr_checked_${state.target}`;
const log = makeLog($("#rRunlog"));
bindLedger($("#rLedger"), checkKey);

// ---- findings -------------------------------------------------------------------
const RISKY = { 21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB" };
const daysUntil = (d) => { const t = Date.parse(d); return Number.isFinite(t) ? Math.round((t - Date.now()) / 86400000) : null; };
const flat = (v) => [].concat(v ?? []).flat().filter(Boolean);
// Certificate dates arrive as "Sep 26 22:10:00 2026 GMT"; show them as 2026-09-26.
const day = (d) => { const t = Date.parse(d); return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : String(d || "").slice(0, 10); };

export const TIERS = [
  { id: "flag",      title: "Flags",            cls: "flag",    open: true, blurb: "Known CVEs, risky open services, weak headers, expiring certificates or domains." },
  { id: "surface",   title: "Exposed services", cls: "surface", open: true, blurb: "What answers from the internet." },
  { id: "inventory", title: "Subdomains",       cls: "",        collapseOver: 15, limit: 300, blurb: "From DNS checks, certificate transparency and passive sources. Each opens in a new tab." },
  { id: "lookalike", title: "Lookalike domains", cls: "",       collapseOver: 8,  limit: 120, blurb: "Registered names that resemble this one. Registered is not the same as malicious: brands register their own typos. The ones that can receive mail are listed first." },
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
  // Only a TLS-level failure says something about the certificate. A timeout or DNS error does not.
  if (ssl && ssl.error_code === "tls" && state.type === "domain") add({ tier: "flag", what: "No valid TLS certificate", url: "", meta: ssl.error || "", source: "TLS", key: "tls:none" });
  if (ssl?.found && ssl.days_left != null && ssl.days_left < 30) add({ tier: "flag", what: ssl.days_left < 0 ? "TLS certificate expired" : `TLS certificate expires in ${ssl.days_left} days`, url: "", meta: day(ssl.not_after), source: "TLS", key: "tls:expiry" });
  const wh = c.whois;
  const whDays = daysUntil(wh?.expiration_date);
  if (whDays != null && whDays < 60) add({ tier: "flag", what: whDays < 0 ? "Domain registration expired" : `Domain expires in ${whDays} days`, url: "", meta: String(wh.expiration_date).slice(0, 10), source: "WHOIS", key: "whois:expiry" });
  if (c.redirects?.found && c.redirects.is_clean === false) add({ tier: "flag", what: "Redirect chain leaves the domain or downgrades", url: c.redirects.final_url, meta: `${c.redirects.hop_count ?? 0} hops`, source: "Redirect chain", key: "redir:dirty" });

  // email, DNS, takeover: each module returns its own findings; only real problems become flags
  const ep = c.email_posture;
  if (ep && !ep.error) {
    for (const f of ep.findings || []) if (f.level === "flag") add({ tier: "flag", what: f.title, url: "", meta: f.detail, source: "Email security", key: `mail:${f.title}` });
  }
  const dd = c.dns_depth;
  if (dd && !dd.error) for (const f of dd.findings || []) if (f.level === "flag") add({ tier: "flag", what: f.title, url: "", meta: f.detail, source: "DNS hardening", key: `dnsx:${f.title}` });
  const tk = c.takeover;
  if (tk && !tk.error) for (const x of tk.candidates || []) {
    if (x.status === "dangling") add({ tier: "flag", what: `Possible subdomain takeover: ${x.host}`, url: "", meta: `CNAME to ${x.cname} (${x.service}), which no longer resolves. Verify by hand.`, source: "Takeover candidates", key: `tko:${x.host}` });
    else add({ tier: "surface", what: x.host, url: `https://${x.host}`, meta: `hosted on ${x.service} (${x.cname})`, source: "Takeover candidates", key: `tko:${x.host}` });
  }
  const wkn = c.wellknown;
  if (wkn && !wkn.error) for (const pth of (wkn.robots?.interesting || []).slice(0, 12)) add({ tier: "surface", what: `${target}${pth}`, url: "", meta: "path listed in robots.txt", source: "Published files", key: `robots:${pth}` });
  const la = c.lookalikes;
  if (la && !la.error) for (const r of la.results || []) add({ tier: "lookalike", what: r.domain, url: "", meta: [r.technique, r.mail ? "can receive mail" : "", flat(r.ips).join(", ")].filter(Boolean).join(" · "), source: "Lookalike domains", key: `look:${r.domain}` });

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
  if (ssl?.found) { fact("TLS issuer", ssl.issuer, "TLS"); fact("TLS valid until", day(ssl.not_after), "TLS"); }
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
  if (ep && !ep.error && ep.grade) fact("Email security", `Grade ${ep.grade} · ${ep.spoofable === "yes" ? "can be spoofed" : ep.spoofable === "no" ? "spoofing rejected" : "mostly protected"}`, "Email security");
  if (dd && !dd.error) fact("DNSSEC", dd.dnssec?.signed && dd.dnssec?.ds ? "Enabled" : "Not enabled", "DNS hardening");
  const cs = c.subdomains?.ct_summary;
  if (cs) fact("Certificates", `${fmtNum(cs.total)} logged since ${cs.first_issued || "?"} · ${fmtNum(cs.active)} still valid`, "Certificate logs");
  if (wkn?.favicon) fact("Favicon hash", String(wkn.favicon.hash), "Published files", `https://www.shodan.io/search?query=${encodeURIComponent(wkn.favicon.shodan_query)}`);
  if (wkn && !wkn.error && wkn.found) fact("security.txt", wkn.security_txt ? (wkn.security_txt.contact || []).slice(0, 2).join(", ") || "Published" : "Not published", "Published files");
  const order = { flag: 0, surface: 1, inventory: 2, lookalike: 3 };
  items.sort((a, b) => order[a.tier] - order[b.tier]);
  return { items, facts };
}

// ---- cards -------------------------------------------------------------------------
const card = (title, badge, body) => `<article class="card"><div class="card-head"><h3 class="card-title">${esc(title)}</h3>${badge}</div><div class="card-body">${body}</div></article>`;
const tag = (t, cls = "") => h`<span class="tag ${cls}">${t}</span>`;
const kv = (pairs) => `<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => h`<dt>${k}</dt><dd>${raw(v)}</dd>`).join("")}</dl>`;
const mono = (s) => h`<span class="mono">${s}</span>`;
const muted = (s) => h`<p style="color:var(--ink-3);font-size:var(--fs-1)">${s}</p>`;
const errCard = (title, d) => errorCard(title, d);

const LEVEL = { flag: "warn", ok: "ok", info: "" };
const findingList = (rows) => `<ul class="finds">${rows.map((f) => h`<li class="find ${f.level}"><span class="tag ${LEVEL[f.level] || ""}">${f.level === "flag" ? "issue" : f.level === "ok" ? "good" : "note"}</span><div><b>${f.title}</b><span>${f.detail}</span></div></li>`).join("")}</ul>`;
const details = (summary, inner) => `<details class="more"><summary>${esc(summary)}</summary>${inner}</details>`;
const bars = (rows) => { const max = Math.max(1, ...rows.map((r) => r.count)); return `<div class="bars" role="img" aria-label="${esc(rows.map((r) => `${r.year}: ${r.count}`).join(", "))}">${rows.map((r) => h`<div class="bar-col"><span class="bar-n">${r.count}</span><i style="height:${Math.max(4, Math.round((r.count / max) * 56))}px"></i><span class="bar-l">${r.year}</span></div>`).join("")}</div>`; };

const CARDS = {
  email_posture: (d) => {
    if (d.error) return errCard("Email security", d);
    const g = String(d.grade || "?");
    const rec = [["SPF", d.spf?.record], ["DMARC", d.dmarc?.record], ["MX", flat(d.mx).join(", ")], ["DKIM selectors", (d.dkim || []).map((x) => x.selector).join(", ")], ["MTA-STS", d.mta_sts], ["TLS-RPT", d.tls_rpt], ["BIMI", d.bimi]];
    return card("Email security", tag(`grade ${g}`, g <= "B" ? "ok" : g === "C" ? "" : "warn") + " " + tag(d.spoofable === "yes" ? "can be spoofed" : d.spoofable === "no" ? "spoofing rejected" : "mostly protected", d.spoofable === "yes" ? "warn" : "ok"),
      h`<p class="card-lead">${d.summary}</p>` + findingList(d.findings || []) + details("Records", kv(rec.map(([k, v]) => [k, v ? mono(v) : ""]))) + muted(`DKIM selectors cannot be listed from DNS. ${d.dkim_selectors_checked ?? 0} common ones were tried.`).replace("<p ", '<p class="muted small" '));
  },
  dns_depth: (d) => {
    if (d.error) return errCard("DNS hardening", d);
    return card("DNS hardening", tag(d.dnssec?.signed && d.dnssec?.ds ? "DNSSEC on" : "DNSSEC off", d.dnssec?.signed && d.dnssec?.ds ? "ok" : "") + (d.wildcard?.present ? " " + tag("wildcard DNS", "warn") : ""),
      findingList(d.findings || []) + kv([["CAA issuers", esc(flat(d.caa?.issue).join(", "))], ["Name servers", flat(d.nameservers).map(mono).join("<br>")], ["Reverse DNS", (d.reverse_dns || []).map((r) => h`<span class="mono">${r.ip}</span> ${r.ptr || "no PTR"}`).join("<br>")]]));
  },
  takeover: (d) => {
    if (d.error) return errCard("Takeover candidates", d);
    const rows = d.candidates || [];
    return card("Takeover candidates", tag(`${d.dangling || 0} dangling`, d.dangling ? "warn" : "ok") + " " + tag(`${fmtNum(d.checked || 0)} checked`),
      (rows.length ? `<div class="rows">${rows.slice(0, 30).map((x) => h`<div><span class="tag ${x.status === "dangling" ? "warn" : ""}">${x.status}</span> <span class="mono">${x.host}</span> <span class="dim">to ${x.cname} (${x.service})</span></div>`).join("")}</div>` : muted("No subdomain points at a claimable cloud service."))
      + muted("From DNS only. A dangling record is a candidate, not a confirmed takeover: check the service's own error page by hand, and only on hosts you are authorized to test.").replace("<p ", '<p class="muted small" '));
  },
  lookalikes: (d) => {
    if (d.error) return errCard("Lookalike domains", d);
    const rows = d.results || [];
    return card("Lookalike domains", tag(`${fmtNum(d.registered || 0)} registered`, d.registered ? "warn" : "ok") + (d.with_mail ? " " + tag(`${d.with_mail} with mail`, "warn") : ""),
      (rows.length ? `<div class="rows">${rows.slice(0, 12).map((r) => h`<div><span class="mono">${r.domain}</span> <span class="dim">${r.technique}${r.mail ? " · can receive mail" : ""}</span></div>`).join("")}${rows.length > 12 ? h`<div class="dim">+${rows.length - 12} more in the ledger</div>` : ""}</div>` : muted("None of the generated variants are registered."))
      + muted(`${fmtNum(d.checked || 0)} variants checked in DNS. The sites were not contacted. Registered does not mean malicious.`).replace("<p ", '<p class="muted small" '));
  },
  wellknown: (d) => {
    if (d.error) return errCard("Published files", d);
    if (!d.found) return card("Published files", tag("none"), muted("No security.txt, robots.txt or favicon was served."));
    const st = d.security_txt, rb = d.robots, fv = d.favicon;
    return card("Published files", tag(st ? "security.txt" : "no security.txt", st ? "ok" : ""),
      kv([["Security contact", st ? flat(st.contact).map((x) => (/^https?:/.test(x) ? link(x, x) : esc(x))).join("<br>") : "Not published"], ["Expires", esc(flat(st?.expires)[0] || "")], ["Policy", st?.policy?.[0] ? link(st.policy[0], st.policy[0]) : ""],
        ["robots.txt", rb ? esc(`${rb.disallow_count} disallowed paths`) : "Not served"], ["Sitemaps", flat(rb?.sitemaps).slice(0, 3).map((x) => link(x, x)).join("<br>")],
        ["Favicon hash", fv ? h`<span class="mono">${fv.hash}</span> ${raw(link(`https://www.shodan.io/search?query=${encodeURIComponent(fv.shodan_query)}`, "find hosts with this icon in Shodan"))}` : ""]])
      + (rb?.interesting?.length ? details(`Paths in robots.txt worth a look (${rb.interesting.length})`, `<div class="mono rows">${rb.interesting.map((x) => h`<div>${x}</div>`).join("")}</div>`) : ""));
  },
  certs: (d) => {
    const s = d.ct_summary; if (!s) return "";
    return card("Certificate history", tag(`${fmtNum(s.total)} logged`) + " " + tag(`${fmtNum(s.active)} valid`, "ok"),
      kv([["First issued", esc(s.first_issued)], ["Latest", esc(s.last_issued)], ["Wildcards", esc(s.wildcards)], ["Issuers", (s.issuers || []).slice(0, 5).map((i) => h`${i.name} <span class="dim">${i.count}</span>`).join("<br>")]])
      + (s.by_year?.length > 1 ? `<p class="muted small">Certificates issued per year</p>${bars(s.by_year.slice(-12))}` : "")
      + (s.not_resolving?.length ? details(`Certified names that no longer resolve (${s.not_resolving.length})`, `<p class="muted small">Often retired, internal or renamed hosts. Worth a look in archives.</p><div class="mono rows">${s.not_resolving.map((x) => h`<div>${x}</div>`).join("")}</div>`) : ""));
  },
  harvest: (d) => harvestCard(d),
  dns: (d) => {
    const rec = d.records || {};
    const rows = Object.entries(rec).filter(([, v]) => flat(v).length).map(([t, v]) => [t, flat(v).map((x) => mono(typeof x === "object" ? JSON.stringify(x) : x)).join("<br>")]);
    return card("DNS records", tag(`${fmtNum(d.total ?? rows.length)} records`) + (d.cloudflare_proxied ? " " + tag("Cloudflare", "warn") : ""), rows.length ? kv(rows) : muted("No records returned."));
  },
  whois: (d) => d.error ? errCard("WHOIS", d) : card("WHOIS", d.privacy_protected ? tag("privacy") : "", kv([["Registrar", esc(d.registrar)], ["Created", esc(String(d.creation_date || "").slice(0, 10))], ["Updated", esc(String(d.updated_date || "").slice(0, 10))], ["Expires", esc(String(d.expiration_date || "").slice(0, 10))], ["Org", esc(d.org)], ["Country", esc(d.country)], ["Name servers", flat(d.name_servers).map((x) => mono(String(x).toLowerCase())).join("<br>")]])),
  ssl: (d) => d.error_code === "tls" || (d.found === false && !d.error) ? card("TLS certificate", tag("none", "warn"), muted(d.error || "No certificate presented.")) : d.error ? errCard("TLS certificate", d) : card("TLS certificate", tag(d.days_left < 30 ? `${d.days_left} days left` : "valid", d.days_left < 30 ? "warn" : "ok"), kv([["Common name", mono(d.common_name)], ["Issuer", esc(d.issuer)], ["Valid from", esc(day(d.not_before))], ["Valid until", esc(day(d.not_after))], ["Also covers", flat(d.sans).slice(0, 12).map(mono).join("<br>") + (flat(d.sans).length > 12 ? h`<br>+${flat(d.sans).length - 12} more` : "")]])),
  headers: (d) => {
    if (d.error || d.found === false) return errCard("HTTP headers", d.error ? d : { error: "No response" });
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
  asn: (d) => d.error ? errCard("Network owner", d) : d.found === false ? card("Network owner", tag("not found"), muted("No network owner on record for this address.")) : card("Network owner", tag(d.asn || ""), kv([["IP", mono(d.ip)], ["ASN", link(`https://bgp.he.net/${d.asn}`, d.asn)], ["Org", esc(d.org)], ["Prefixes", flat(d.prefixes).slice(0, 8).map(mono).join("<br>")]])),
  portscan: (d) => {
    if (d.error) return errCard("Port scan", d);
    const open = (d.results || []).filter((r) => r.open);
    return card("Port scan", tag(`${open.length} of ${d.total_scanned ?? (d.results || []).length} open`, open.some((r) => RISKY[r.port]) ? "warn" : ""), open.length ? `<div style="font-size:var(--fs-1)">${open.map((r) => h`<div><span class="mono">${r.port}/tcp</span> ${r.service}${RISKY[r.port] ? raw(' <span class="tag warn">risky</span>') : ""}</div>`).join("")}</div>` : muted("No common ports answered."));
  },
  shodan: (d) => {
    const isIdb = d.source === "internetdb";
    const title = isIdb ? "Exposure (InternetDB)" : "Exposure (Shodan)";
    if (d.error) return errCard(title, d);
    if (!d.found) return card(title, tag("not indexed"), muted("This IP is not in the index."));
    const vulns = d.vulns || [];
    const svc = (d.services || []).slice(0, 8).map((s) => h`<div><span class="mono">${s.port}/${s.transport}</span> ${[s.product, s.version].filter(Boolean).join(" ")}</div>`).join("");
    return card(title, tag(`${(d.ports || []).length} ports`) + (vulns.length ? " " + tag(`${d.vuln_count || vulns.length} CVEs`, "warn") : ""),
      kv([["IP", mono(d.ip)], ["Org", esc(d.org)], ["ISP", esc(d.isp)], ["OS", esc(d.os)], ["Location", esc([d.city, d.country].filter(Boolean).join(", "))], ["Ports", mono((d.ports || []).join(", "))], ["Hostnames", flat(d.hostnames).slice(0, 8).map(mono).join("<br>")], ["Tags", esc(flat(d.tags).join(", "))], ["Software", flat(d.cpes).slice(0, 6).map((x) => mono(String(x).replace(/^cpe:\/a:/, ""))).join("<br>")], ["CVEs", vulns.slice(0, 12).map((v) => link(`https://nvd.nist.gov/vuln/detail/${v}`, v)).join(", ") + (vulns.length > 12 ? h` +${vulns.length - 12}` : "")]])
      + (svc ? `<div style="margin-top:8px;font-size:var(--fs-1)">${svc}</div>` : "")
      + (isIdb ? muted("Free keyless source. Add a Shodan key in Settings for banners, org and location.").replace("<p ", '<p style="margin-top:8px" ') : ""));
  },
  wayback: (d) => {
    if (!d.found) return card("Wayback Machine", tag("none"), muted("No snapshots archived."));
    const groups = Object.entries(d.interesting_paths || {});
    const n = groups.reduce((a, [, v]) => a + v.length, 0);
    return card("Wayback Machine", tag(`${fmtNum(d.total_snapshots)} snapshots`) + (n ? " " + tag(`${n} paths worth a look`, "warn") : ""),
      kv([["Latest", link(d.most_recent_snapshot?.url, String(d.most_recent_snapshot?.timestamp || "open"))], ["History", (d.snapshot_history || []).slice(0, 8).map((s) => link(s.url, s.date)).join("<br>")]])
      + groups.map(([g, paths]) => details(`${g} (${paths.length})`, `<div class="rows mono">${paths.map((u) => h`<div>${raw(link(`https://web.archive.org/web/*/${u}`, u))}</div>`).join("")}</div>`)).join("")
      + (n ? muted("These are archived URLs, not proof the paths still exist. Opening one loads the archive, not the target.").replace("<p ", '<p class="muted small" ') : ""));
  },
  redirects: (d) => d.error ? errCard("Redirect chain", d) : !d.found ? card("Redirect chain", tag("none"), muted("No response.")) : card("Redirect chain", tag(d.is_clean ? "clean" : "check", d.is_clean ? "ok" : "warn"), `<div style="font-size:var(--fs-1)">${(d.hops || []).map((x) => h`<div><span class="mono" style="color:var(--ink-3)">${x.status_code}</span> ${raw(link(x.url, x.url))}${x.server ? raw(h` <span style="color:var(--ink-4)">${x.server}</span>`) : ""}</div>`).join("")}</div>`),
  techfp: (d) => {
    if (d.error) return errCard("Tech fingerprint", d);
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
const CARD_ORDER = ["shodan", "portscan", "email_posture", "takeover", "headers", "ssl", "dns_depth", "dns", "whois", "subdomains", "certs", "harvest", "lookalikes", "wellknown", "asn", "asn_detail", "redirects", "techfp", "wayback"];
const cardData = (k) => (k === "certs" ? state.collected.subdomains : state.collected[k]);

function renderCards() {
  const html = CARD_ORDER.filter((k) => cardData(k)).map((k) => { try { return CARDS[k](cardData(k)); } catch (e) { return card(k, tag("render error", "warn"), muted(e.message)); } }).join("");
  $("#rBySource").hidden = !html; $("#rBySourceEmpty").hidden = !!html;
  setTabCount($("#rTabSources"), "By source", (html.match(/<article class="card/g) || []).length);
  $("#rSourceCards").innerHTML = html;
}

// ---- timeline ------------------------------------------------------------------------
// Dated facts the sources already returned, oldest first, with today marked.
function renderTimeline() {
  const { events, today } = reconTimeline(state.collected, state.target);
  setTabCount($("#rTabTimeline"), "Timeline", events.length);
  const box = $("#rTimelineBody");
  if (!events.length) { box.innerHTML = `<p class="empty flat">${state.running ? "Collecting…" : "No dated facts yet. WHOIS, certificate logs, the TLS certificate and the Wayback Machine supply them."}</p>`; return; }
  const row = (e, i, all) => h`<li class="tl-ev ${e.future ? "future" : ""}">
      <span class="tl-year">${i === 0 || all[i - 1].date.slice(0, 4) !== e.date.slice(0, 4) ? e.date.slice(0, 4) : ""}</span>
      <time datetime="${e.date}">${e.date}</time>
      <div class="tl-what"><b>${e.url ? raw(link(e.url, e.title)) : e.title}</b>${e.detail ? raw(h`<span>${e.detail}</span>`) : ""}</div>
      <span class="tl-meta"><span class="tl-when">${e.when}</span><span class="tl-src">${e.source}</span></span>
    </li>`;
  const past = events.filter((e) => !e.future), future = events.filter((e) => e.future);
  box.innerHTML = `<p class="tl-note">Every date below was reported by a source in this run. Nothing is inferred, and a source that failed leaves a gap, not a clean record.</p>
    <ol class="tl">${past.map(row).join("")}<li class="tl-now"><span class="tl-year"></span><time datetime="${esc(today)}">${esc(today)}</time><b>Today</b></li>${future.map((e, i, all) => row(e, i, all)).join("")}</ol>`;
}

function renderAll() {
  const { items, facts } = buildFindings(state.collected, state.target);
  const diff = !state.running && state.prev ? diffRuns(state.prev.keys, items) : null;
  if (diff) { const added = new Set(diff.added.map((i) => i.key)); for (const it of items) it.isNew = added.has(it.key); }
  const failed = failedSources();
  $("#rEmpty").hidden = true;
  $("#rNotices").innerHTML = failedNotice(failed) + (diff ? diffNotice(diff, state.prev.ts) : "");
  const nothing = state.running ? `<div class="empty"><h3>Collecting</h3><p>Findings appear here as each source answers.</p></div>`
    : failed.length ? `<div class="empty"><h3>No findings from the sources that answered</h3><p>Some sources failed, so this is not a clean bill of health. See the notice above.</p></div>`
    : `<div class="empty"><h3>No findings</h3><p>Nothing risky or exposed was found. Details from each source are below.</p></div>`;
  renderTiers($("#rLedger"), items, TIERS, new Set(store.get(checkKey(), [])), nothing);
  renderFacts($("#rFacts"), facts, state.running ? "Collecting…" : "No facts extracted yet.");
  setTabCount($("#rTabFindings"), "Findings", items.length);
  renderBrief($("#rBrief"), $("#rBriefBody"), state.running || !state.target ? { rows: [], actions: [] } : reconBrief({ collected: state.collected, items, failed, type: state.type, target: state.target }));
  renderCards();
  renderTimeline();
  if (state.tab === "topology") drawGraph();
  return items;
}

// ---- tabs + topology --------------------------------------------------------------------
// Findings, By source and Topology are a real tablist (see makeTabs in workbench.js).
const tabs = makeTabs($("#rTabs"), (tab) => { state.tab = tab; if (tab === "topology") drawGraph(); });
function setTab(tab) { tabs.set(tab); }

// ---- graph pivots --------------------------------------------------------------------
// Selecting a node offers to run it. One click is one run: nothing expands on its own,
// and the port scan stays behind its own switch.
function hidePivot() { $("#rPivot").hidden = true; $("#rPivot").innerHTML = ""; }
$("#rGraph").addEventListener("crawlr:node", (e) => {
  const { type, label } = e.detail;
  const asn = (String(label).match(/AS\d+/i) || [])[0];
  const value = type === "asn" || type === "cf_asn" ? asn : String(label).trim();
  if (!value) return;
  const kind = { subdomain: "Subdomain", ip: "IP address", asn: "Network", cf_asn: "Network", domain: "Domain" }[type] || "Host";
  const same = value.toLowerCase() === state.target.toLowerCase();
  const openUrl = type === "ip" ? `https://www.shodan.io/host/${value}` : asn ? `https://bgp.he.net/${asn}` : `https://${value}`;
  const box = $("#rPivot");
  box.hidden = false;
  box.innerHTML = h`<span class="pv-k">${kind}</span><span class="pv-v mono">${value}</span>
    <span class="pv-acts">${raw(same ? '<span class="dim">this is the current target</span>' : h`<button type="button" class="btn btn-sm btn-primary" data-run-node="${value}">Run recon on it</button>`)}
    ${raw(link(openUrl, type === "ip" ? "Open in Shodan" : asn ? "Open in bgp.he.net" : "Open site", "btn btn-sm"))}
    <button type="button" class="btn btn-sm btn-ghost" data-hide-pivot>Dismiss</button></span>`;
  box.querySelector("button, a")?.focus();
});
$("#rPivot").addEventListener("click", (e) => {
  if (e.target.closest("[data-hide-pivot]")) { hidePivot(); return; }
  const b = e.target.closest("[data-run-node]"); if (!b) return;
  if (state.running) { toast("A run is in progress. Cancel it or wait for it to finish."); return; }
  // The current case is already saved in History; this starts a new one for the selected node.
  toast(`New case: ${b.dataset.runNode}. The previous one is in History.`, 4000);
  run(b.dataset.runNode);
});
let d3Loading;
function loadD3() {
  if (window.d3) return Promise.resolve();
  d3Loading ??= new Promise((res, rej) => {
    const s = document.createElement("script");
    // Self-hosted (static/v2/vendor): no third-party script host, and the CSP stays script-src 'self'.
    s.src = new URL("../vendor/d3.min.js", import.meta.url).href;
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
  return { target: state.target, dns: c.dns || null, whois: c.whois || null, ssl: c.ssl || null, headers: c.headers || null, subdomains: c.subdomains || null, asn: c.asn || null, portscan: c.portscan || null, asn_detail: c.asn_detail || null, shodan: c.shodan || null, email_posture: c.email_posture || null, dns_depth: c.dns_depth || null, takeover: c.takeover || null, lookalikes: c.lookalikes || null, wellknown: c.wellknown || null };
};
const hasData = () => Object.entries(state.collected).some(([k, v]) => SRC_NAME[k] && v && !isFailed(v));
function renderAi() {
  const box = $("#rAiPanel");
  const note = (t) => `<p class="empty flat">${esc(t)}</p>`;
  if (!state.ai) {
    if (state.aiBusy) { box.innerHTML = `<p class="empty flat" role="status">Asking ${esc(providerName())}…</p>`; return; }
    if (state.running) { box.innerHTML = note("Available when the sources finish. AI never runs on its own."); return; }
    if (!state.target || !hasData()) { box.innerHTML = note(state.target ? "Nothing to analyze yet." : "Run a target first. AI analysis is optional and only runs when you ask."); return; }
    box.innerHTML = aiStartHtml("rec", "Get an attack surface summary: what is exposed, what looks misconfigured, and what to check next.");
    return;
  }
  const deep = state.deep ? `<button class="btn btn-sm" type="button" data-open-rreport="deep">Deep analysis</button>` : aiAvailable() ? `<button class="btn btn-sm" type="button" id="rDeepBtn">Deep analysis…</button>` : "";
  box.innerHTML = summaryBlock(state.ai, { reportId: "summary", attr: "data-open-rreport", deepDive: deep });
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-open-rreport]");
  if (b) openReport(b.dataset.openRreport);
  if (e.target.id === "rDeepBtn") confirmDeep();
  if (e.target.id === "recAiRun") runAi();
  if (e.target.id === "recAiCopy") copyPrompt("/api/infra/prompt", aiBody());
  if (e.target.id === "recAiPasteGo") parseReply($("#recAiPaste")?.value).then((ai) => { if (ai) { state.ai = ai; saveHistory(); renderAi(); openReport("summary"); } });
  const bt = e.target.closest("[data-brief-tab]"); if (bt) { setTab(bt.dataset.briefTab); $("#rTabs").scrollIntoView({ behavior: "smooth", block: "start" }); }
});
function openReport(which) {
  const ai = which === "deep" ? state.deep : state.ai;
  if (!ai) return;
  openModal({ title: which === "deep" ? "Deep analysis" : "AI analysis", wide: true, body: `<div class="report">${markdown(ai.summary)}</div>`,
    actions: [{ label: "Copy markdown", onClick: () => navigator.clipboard?.writeText(ai.summary).then(() => toast("Copied")) }, { label: "Close", primary: true, onClick: closeModal }] });
}
// Runs only from the "Analyze with AI" button, after the cost has been shown.
async function runAi() {
  if (state.aiBusy || state.running || !aiAvailable() || !hasData()) return;
  state.aiBusy = true; renderAi();
  const row = log.add(`AI analysis (${providerName()})`); log.open();
  try {
    state.ai = normalizeAi(await postAi("/api/infra/summarize", aiBody()));
    log.set(row, `AI analysis · ${state.ai.model || providerName()}${state.ai.cached ? " · cached, no credit used" : ""}`, "done");
    saveHistory();
  } catch (err) {
    log.set(row, `AI analysis: ${err.detail || err.message}`, "err", err.raw);
    toast(err.detail || err.message, 5000);
  }
  state.aiBusy = false;
  renderAi();
}
function confirmDeep() {
  openModal({ title: "Run a deep analysis?", body: h`<p class="modal-p">${providerName()} gets everything collected for ${state.target} and writes a full attack surface assessment: exposure, likely entry points, misconfigurations and prioritized next steps.</p><p class="modal-p muted">${aiCost("deepdive")}</p>`,
    actions: [{ label: "Cancel", onClick: closeModal }, { label: "Run deep analysis", primary: true, onClick: async () => {
      closeModal();
      const row = log.add("Deep analysis"); log.open();
      try { state.deep = normalizeAi(await postAi("/api/analyze/deep", aiBody())); log.set(row, "Deep analysis complete", "done"); saveHistory(); renderAi(); openReport("deep"); }
      catch (err) { log.set(row, `Deep analysis: ${err.detail || err.message}`, "err", err.raw); toast(err.detail || err.message, 5000); }
    } }] });
}

// ---- run ---------------------------------------------------------------------------------------
async function source(label, url, body, key, headers = {}) {
  const row = log.add(label);
  try {
    const d = await post(url, body, headers, state.controller?.signal);
    state.collected[key] = d;
    if (isFailed(d)) { const o = sourceOutcome(d); log.set(row, `${label}: ${o.text}`, "err", o.detail); }
    else if (d?.skipped) log.set(row, `${label} · skipped`, "skip");
    else if (d?.found === false || d?.error) log.set(row, `${label} · nothing found`, "none");
    else log.set(row, `${label} · done`, "done");
    renderAll();
    return d;
  } catch (err) {
    if (err.code === "cancelled") { log.set(row, `${label} · cancelled`, "skip"); return null; }
    state.collected[key] = { error: err.detail || err.message, error_code: err.code || "request_failed", error_detail: err.raw || "" };
    log.set(row, `${label}: ${err.detail || err.message}`, "err", err.raw);
    renderAll();
    return null;
  }
}

function setRunning(on) {
  state.running = on;
  const b = $("#rRunBtn");
  b.textContent = on ? "Cancel run" : "Run recon";
  b.classList.toggle("btn-primary", !on); b.classList.toggle("btn-danger", on);
  $("#rMain").setAttribute("aria-busy", on);
}
export function cancel() {
  if (!state.running) return;
  state.cancelled = true;
  state.controller?.abort();
}

export async function run(raw0) {
  const target = String(raw0 || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  if (!target || state.running) return;
  const type = detect(target);
  if (!RECON_TYPES.includes(type)) { toast(`${TYPE_LABEL[type] || "That"} targets run in Investigate.`); return; }
  const last = store.get(HISTORY_KEY, []).find((e) => e.type === "RECON" && e.v2 && e.target.toLowerCase() === target.toLowerCase());
  const prev = last ? { keys: buildFindings(last.results || {}, last.target).items.map((i) => i.key), ts: last.timestamp } : null;
  Object.assign(state, { target, type, collected: {}, ai: null, deep: null, historyId: null, cancelled: false, controller: new AbortController(), prev, aiBusy: false, ran: Date.now() });
  store.del(checkKey());
  $("#rTargetInput").value = target; renderSources(type);
  setRunning(true);
  $("#rLedger").innerHTML = ""; $("#rNotices").innerHTML = ""; $("#rEmpty").hidden = true; $("#rBySource").hidden = true; $("#rBySourceEmpty").hidden = false;
  $("#rTabs").hidden = false; setTab("findings"); hidePivot();
  $("#rNotes").value = ""; $("#rPurpose").value = ""; notesMeta();
  head(); log.start(); renderAll(); renderAi();

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
    if (type === "domain" && on("emailsec")) jobs.push(source("Email security", "/api/infra/email-posture", T, "email_posture"));
    if (type === "domain" && on("dnsdepth")) jobs.push(source("DNS hardening", "/api/infra/dns-depth", T, "dns_depth"));
    if (type === "domain" && on("wellknown")) jobs.push(source("Published files", "/api/infra/wellknown", T, "wellknown"));
    if (on("asn")) jobs.push(source("Network owner", "/api/infra/asn", T, "asn"));
    if (on("exposure")) jobs.push(getKey("shodan") ? source("Exposure (Shodan)", "/api/recon/shodan", { target }, "shodan", { "X-Shodan-Key": getKey("shodan") }) : source("Exposure (InternetDB)", "/api/recon/internetdb", { target }, "shodan"));
    if (on("redirects")) jobs.push(source("Redirect chain", "/api/infra/redirects", { target }, "redirects"));
    if (on("techfp")) jobs.push(source("Tech fingerprint", "/api/infra/techfingerprint", T, "techfp"));
    if (type === "domain" && on("wayback")) jobs.push(source("Wayback Machine", "/api/infra/wayback", T, "wayback"));
    await Promise.all(jobs);
    // Takeover candidates need the subdomain list, so they run once discovery is in.
    const hosts = [...new Set([...(state.collected.subdomains?.subdomains || []).map((x) => x.subdomain), ...(state.collected.harvest?.hosts || [])])].slice(0, 200);
    const late = [];
    if (type === "domain" && on("takeover") && hosts.length && !state.cancelled) late.push(source("Takeover candidates", "/api/infra/takeover", { domain: target, hosts }, "takeover"));
    if (on("portscan") && !state.cancelled) late.push(source("Port scan", "/api/infra/portscan", T, "portscan"));
    // A few hundred DNS queries: kept out of the first wave so it does not slow the core checks.
    if (type === "domain" && on("lookalikes") && !state.cancelled) late.push(source("Lookalike domains", "/api/infra/lookalikes", T, "lookalikes"));
    await Promise.all(late);
    // IP to ASN map for the topology graph
    const c = state.collected;
    const ips = [...new Set([...(c.subdomains?.subdomains || []).flatMap((s) => flat(s.ips)), ...flat(c.dns?.records?.A)].filter((x) => /^\d+\.\d+\.\d+\.\d+$/.test(String(x))))].slice(0, 100);
    if (ips.length && !state.cancelled) { try { c.ipAsn = (await post("/api/infra/ip-asn", { ips }, {}, state.controller.signal)).results || {}; } catch { /* graph falls back to the main ASN */ } }
  }

  setRunning(false);
  const items = renderAll();
  renderAi();
  const flags = items.filter((i) => i.tier === "flag").length;
  log.finish(`${state.cancelled ? "Cancelled · partial results · " : ""}${plural(Object.keys(state.collected).filter((k) => k !== "ipAsn").length, "source")} · ${plural(flags, "flag")}`);
  head(`${TYPE_LABEL[type]} · ${plural(flags, "flag")} · ${plural(items.length - flags, "other finding")}${state.cancelled ? " · cancelled, partial" : ""}`);
  if (Object.keys(state.collected).length) saveHistory();
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
  const entry = { id: state.historyId || `${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, target: state.target, type: "RECON", timestamp: Date.now(), results: state.collected, aiSummary: state.ai?.summary || null, ai: state.ai, deep: state.deep, notes: $("#rNotes").value, purpose: $("#rPurpose").value.trim(), v2: true };
  state.historyId = entry.id;
  const i = list.findIndex((e) => e.id === entry.id);
  if (i >= 0) { entry.timestamp = list[i].timestamp; if (list[i].imported) entry.imported = list[i].imported; list[i] = entry; } else list.unshift(entry);
  while (list.length > 50) list.pop();
  if (!store.set(HISTORY_KEY, list)) { list.splice(Math.floor(list.length / 2)); store.set(HISTORY_KEY, list); }
}
export function loadHistory(e) {
  Object.assign(state, { target: e.target, type: detect(e.target), collected: e.results || {}, ai: e.ai || (e.aiSummary ? normalizeAi({ summary: e.aiSummary }) : null), deep: e.deep ? normalizeAi(e.deep) : null, historyId: e.id, running: false, prev: null, aiBusy: false, ran: e.timestamp });
  $("#rTargetInput").value = e.target; renderSources(state.type); $("#rRunlog").hidden = true; $("#rTabs").hidden = false; setTab("findings"); hidePivot();
  head(`${TYPE_LABEL[state.type]} · ${e.imported ? "opened from a case file · collected" : "from history ·"} ${new Date(e.timestamp).toLocaleString()}`);
  $("#rNotes").value = e.notes || ""; $("#rPurpose").value = e.purpose || ""; notesMeta();
  renderAll(); renderAi();
}
export function clearCase() {
  cancel();
  Object.assign(state, { target: "", type: "", collected: {}, ai: null, deep: null, historyId: null, prev: null, aiBusy: false });
  $("#rTargetInput").value = ""; $("#rMainHead").hidden = true; $("#rRunlog").hidden = true; $("#rLedger").innerHTML = ""; $("#rNotices").innerHTML = ""; $("#rBySource").hidden = true;
  $("#rEmpty").hidden = false; $("#rFacts").innerHTML = `<p class="empty flat">Nothing yet.</p>`; $("#rNotes").value = ""; $("#rPurpose").value = ""; notesMeta();
  renderSources(""); renderAi(); setTab("findings"); hidePivot();
  $("#rBrief").hidden = true; $("#rTabs").hidden = true; $("#rBySourceEmpty").hidden = false; $("#rTimelineBody").innerHTML = ""; setTabCount($("#rTabTimeline"), "Timeline", 0);
}

// ---- notes + export ----------------------------------------------------------------------------------
let notesTimer;
function notesMeta() {
  $("#rNotesCount").textContent = `${fmtNum($("#rNotes").value.length)} chars`;
  casePrint($("#rCasePrint"), { purpose: $("#rPurpose").value, notes: $("#rNotes").value, ran: state.target ? state.ran : 0 });
}
const noteSave = () => {
  notesMeta(); $("#rNotesStatus").textContent = "Saving…"; clearTimeout(notesTimer);
  notesTimer = setTimeout(() => { if (state.target) saveHistory(); $("#rNotesStatus").textContent = "Saved"; }, 600);
};
$("#rNotes").addEventListener("input", noteSave);
$("#rPurpose").addEventListener("input", noteSave);

export function exportCase() {
  if (!state.target) return;
  const { items, facts } = buildFindings(state.collected, state.target);
  const failed = failedSources();
  const purpose = $("#rPurpose").value.trim();
  const md = [`# CrawlR recon: ${state.target}`, `Generated ${new Date().toISOString()} · ${TYPE_LABEL[state.type]}${state.ran ? ` · collected ${new Date(state.ran).toISOString()}` : ""}`, "", ...(purpose ? [`**Purpose:** ${purpose}`, ""] : []),
    ...(failed.length ? ["## Sources that failed", ...failed.map((f) => `- **${f.name}:** ${f.text} (unknown, not a clean result)`), ""] : []),
    "## What we know", ...(facts.length ? facts.map((f) => `- **${f.k}:** ${f.v} _(${f.source})_`) : ["- Nothing extracted"]), "",
    ...TIERS.flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...rows.map((i) => `- ${i.url ? `[${i.what}](${i.url})` : i.what}${i.meta ? ` · ${i.meta}` : ""} _(${i.source})_`), ""] : []; }),
    ...((tl) => (tl.length ? ["## Timeline", ...tl.map((e) => `- ${e.date} · ${e.title}${e.detail ? ` · ${e.detail}` : ""} _(${e.source})_`), ""] : []))(reconTimeline(state.collected, state.target).events),
    ...(state.ai ? ["## AI analysis", state.ai.summary, ""] : []), ...(state.deep ? ["## Deep analysis", state.deep.summary, ""] : []),
    ...($("#rNotes").value.trim() ? ["## Notes", $("#rNotes").value.trim(), ""] : [])].join("\n");
  const name = `crawlr-recon-${slug(state.target)}`;
  const done = (fn) => () => { fn(); closeModal(); };
  openModal({ title: "Export recon",
    body: `<p class="modal-p">Everything is built in your browser. Nothing is uploaded.</p>
      <ul class="export-list"><li><b>Print or PDF</b> opens the print dialog with a clean, light layout. Choose "Save as PDF" there.</li><li><b>HTML</b> is one self-contained page you can send or archive.</li><li><b>Markdown</b> has findings, facts, AI reports and notes.</li><li><b>Case file</b> is the raw data from every source as JSON, with your notes. Open it in CrawlR on another machine from History.</li></ul>`,
    actions: [
      { label: "Case file", onClick: done(() => download(`${name}.json`, JSON.stringify(buildCaseFile({ mode: "recon", target: state.target, type: state.type, ran: state.ran, collected: state.collected, ai: state.ai, deep: state.deep, notes: $("#rNotes").value, purpose }), null, 2), "application/json")) },
      { label: "Markdown", onClick: done(() => download(`${name}.md`, md, "text/markdown")) },
      { label: "HTML", onClick: async () => { setTab("findings"); const html = await standaloneHtml(`CrawlR recon: ${state.target}`, $("#rMain"), $("#rAside")); download(`${name}.html`, html, "text/html"); closeModal(); } },
      { label: "Print or PDF", primary: true, onClick: () => { closeModal(); setTab("findings"); setTimeout(() => window.print(), 50); } },
    ] });
}

// ---- rail wiring -----------------------------------------------------------------------------------------
$("#rTargetInput").addEventListener("input", () => { const t = detect($("#rTargetInput").value); renderSources(RECON_TYPES.includes(t) ? t : ""); $("#rTargetDetected").innerHTML = $("#rTargetInput").value.trim() ? h`<span>Detected</span> <span class="pill ${RECON_TYPES.includes(t) ? "violet" : ""}">${TYPE_LABEL[t] || ""}</span>${RECON_TYPES.includes(t) ? "" : raw(' <span>runs in <a href="#investigate" data-goto="investigate">Investigate</a></span>')}` : ""; });
$("#rTargetInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !state.running) $("#rRunBtn").click(); });
$("#rRunBtn").addEventListener("click", () => { if (state.running) { cancel(); return; } document.dispatchEvent(new CustomEvent("crawlr:close-rail")); run($("#rTargetInput").value); });
$("#rClearBtn").addEventListener("click", clearCase);
$("#rExportBtn").addEventListener("click", exportCase);
renderSources("");
