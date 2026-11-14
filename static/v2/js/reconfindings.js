// Recon findings: turns the collected module responses into ranked ledger rows and facts.
// Pure (no DOM, no network), so the rules can be tested with plain node.
import { fmtNum, plural } from "./core.js";
import { factCollector, itemCollector } from "./workbench.js";
import { resolvedHosts, mailState, noMailOpen } from "./brief.js";

// ---- findings -------------------------------------------------------------------
export const RISKY = { 21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB" };
const daysUntil = (d) => { const t = Date.parse(d); return Number.isFinite(t) ? Math.round((t - Date.now()) / 86400000) : null; };
export const flat = (v) => [].concat(v ?? []).flat().filter(Boolean);
// Certificate dates arrive as "Sep 26 22:10:00 2026 GMT"; show them as 2026-09-26.
export const day = (d) => { const t = Date.parse(d); return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : String(d || "").slice(0, 10); };

export const TIERS = [
  { id: "flag",      title: "Flags",            cls: "flag",    open: true, blurb: "Known CVEs, risky open services, weak headers, expiring certificates or domains." },
  { id: "surface",   title: "Exposed services", cls: "surface", open: true, blurb: "What answers from the internet." },
  { id: "inventory", title: "Subdomains",       cls: "",        collapseOver: 15, limit: 300, blurb: "From DNS checks, certificate transparency and passive sources. Each opens in a new tab." },
  { id: "lookalike", title: "Lookalike domains", cls: "",       collapseOver: 8,  limit: 120, blurb: "Registered names that resemble this one. Registered is not the same as malicious: brands register their own typos. The ones that can receive mail are listed first." },
  { id: "neighbor",  title: "Unrelated neighbours on the shared address", cls: "", open: false, limit: 200, blurb: "Other sites that answer on the same shared hosting address. They belong to other customers of the provider and say nothing about this target." },
];
export const lc = (s) => String(s ?? "").trim().toLowerCase().replace(/\.$/, "");

// type: "domain" | "ip" | "asn". Pure: the same code ranks a live run, a saved one and a case file.
export function buildFindings(c, target, type = "domain") {
  const { items, add } = itemCollector();
  const { facts, add: fact } = factCollector();
  const exp = c.shodan;
  const expSrc = exp?.source === "internetdb" ? "InternetDB" : "Shodan";

  // flags
  for (const cve of (exp?.vulns || []).slice(0, 30)) add({ tier: "flag", what: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}`, meta: exp.ip ? `on ${exp.ip}` : "", source: expSrc, key: `cve:${cve}` });
  const openPorts = new Map();
  for (const r of c.portscan?.results || []) if (r.open) openPorts.set(Number(r.port), { svc: r.service, src: "Port scan" });
  for (const p of exp?.ports || []) if (!openPorts.has(Number(p))) openPorts.set(Number(p), { svc: "", src: expSrc });
  // On a shared hosting edge the indexed ports are the provider's. The note says so on each row.
  const shared = exp && !exp.error && exp.shared_host ? exp.shared_host : null;
  const portsNote = shared ? String(exp.ports_note || `seen on a shared ${shared.provider || "hosting"} address, not necessarily this site's own`) : "";
  for (const [p, { svc, src }] of [...openPorts].sort((a, b) => a[0] - b[0])) {
    const note = src === expSrc ? portsNote : "";
    if (RISKY[p]) add({ tier: "flag", what: `${RISKY[p]} open on ${p}`, url: "", meta: ["should rarely face the internet", note].filter(Boolean).join(" · "), source: src, key: `port:${p}` });
    else add({ tier: "surface", what: `${p}/tcp${svc ? ` ${svc}` : ""}`, url: "", meta: note, source: src, key: `port:${p}` });
  }
  const hd = c.headers;
  if (hd?.found && ["C", "D", "F"].includes(String(hd.grade).toUpperCase())) add({ tier: "flag", what: `Security headers grade ${hd.grade}`, url: "", meta: `${hd.present ?? 0} of ${hd.total ?? 0} present`, source: "HTTP headers", key: "hdr:grade" });
  const ssl = c.ssl;
  // Only a TLS-level failure says something about the certificate. A timeout or DNS error does not.
  if (ssl && ssl.error_code === "tls" && type === "domain") add({ tier: "flag", what: "No valid TLS certificate", url: "", meta: ssl.error || "", source: "TLS", key: "tls:none" });
  if (ssl?.found && ssl.days_left != null && ssl.days_left < 30) add({ tier: "flag", what: ssl.days_left < 0 ? "TLS certificate expired" : `TLS certificate expires in ${ssl.days_left} days`, url: "", meta: day(ssl.not_after), source: "TLS", key: "tls:expiry" });
  const wh = c.whois;
  const whDays = daysUntil(wh?.expiration_date);
  if (whDays != null && whDays < 60) add({ tier: "flag", what: whDays < 0 ? "Domain registration expired" : `Domain expires in ${whDays} days`, url: "", meta: String(wh.expiration_date).slice(0, 10), source: "WHOIS", key: "whois:expiry" });
  if (c.redirects?.found && c.redirects.is_clean === false) add({ tier: "flag", what: "Redirect chain leaves the domain or downgrades", url: c.redirects.final_url, meta: `${c.redirects.hop_count ?? 0} hops`, source: "Redirect chain", key: "redir:dirty" });

  // email, DNS, takeover: each module returns its own findings; only real problems become flags
  const ep = c.email_posture;
  const noMail = mailState(ep) === "none";
  if (ep && !ep.error) {
    // A domain that takes no mail is not flagged for missing SPF or DMARC (old saved runs did).
    for (const f of ep.findings || []) if (f.level === "flag" && !(noMail && /^No (SPF|DMARC) record/.test(f.title || ""))) add({ tier: "flag", what: f.title, url: "", meta: f.detail, source: "Email security", key: `mail:${f.title}` });
  }
  const dd = c.dns_depth;
  if (dd && !dd.error) for (const f of dd.findings || []) if (f.level === "flag") add({ tier: "flag", what: f.title, url: "", meta: f.detail, source: "DNS hardening", key: `dnsx:${f.title}` });
  const tk = c.takeover;
  const live = resolvedHosts(c, target);
  if (tk && !tk.error) for (const x of tk.candidates || []) {
    // A takeover flag needs "dangling" from the backend, and is withheld when this same run resolved the host.
    if (x.status === "dangling" && live.has(lc(x.host))) add({ tier: "surface", what: x.host, url: `https://${x.host}`, meta: `the takeover check called its CNAME to ${x.cname} (${x.service}) dangling, but this run resolved the host, so it is not listed as a candidate. Check by hand.`, source: "Takeover candidates", key: `tko:${x.host}` });
    else if (x.status === "dangling") add({ tier: "flag", what: `Possible subdomain takeover: ${x.host}`, url: "", meta: `CNAME to ${x.cname} (${x.service}), which no longer resolves. Verify by hand.`, source: "Takeover candidates", key: `tko:${x.host}` });
    else if (x.status === "unknown") add({ tier: "surface", what: x.host, url: `https://${x.host}`, meta: `takeover check could not be completed${x.cname ? `: the lookup of ${x.cname}${x.service ? ` (${x.service})` : ""} failed` : ""}. Unknown, not safe.`, source: "Takeover candidates", key: `tko:${x.host}` });
    else add({ tier: "surface", what: x.host, url: `https://${x.host}`, meta: `hosted on ${x.service} (${x.cname})`, source: "Takeover candidates", key: `tko:${x.host}` });
  }
  const wkn = c.wellknown;
  if (wkn && !wkn.error) for (const pth of (wkn.robots?.interesting || []).slice(0, 12)) add({ tier: "surface", what: `${target}${pth}`, url: "", meta: "path listed in robots.txt", source: "Published files", key: `robots:${pth}` });
  const la = c.lookalikes;
  if (la && !la.error) for (const r of la.results || []) add({ tier: "lookalike", what: r.domain, url: "", meta: [r.technique, r.mail ? "can receive mail" : "", flat(r.ips).join(", ")].filter(Boolean).join(" · "), source: "Lookalike domains", key: `look:${r.domain}` });

  // surface
  if (c.redirects?.final_url) add({ tier: "surface", what: c.redirects.final_url, url: c.redirects.final_url, meta: "final URL", source: "Redirect chain", key: "redir:final" });
  // On a shared address the other hostnames are other customers. They get one line and their own
  // collapsed group, never a row each under exposed services.
  const neighbors = shared ? (exp.neighbors || []).map(String) : [];
  const nb = new Set(neighbors.map(lc));
  for (const hn of (exp?.hostnames || []).filter((x) => !nb.has(lc(x))).slice(0, 20)) add({ tier: "surface", what: hn, url: `https://${hn}`, meta: "hostname on this IP", source: expSrc, key: `host:${hn}` });
  if (shared) add({ tier: "surface", what: `Shared ${shared.provider || "hosting"} address: ${plural(neighbors.length, "other site")} answer${neighbors.length === 1 ? "s" : ""} on this IP`, url: "", meta: neighbors.length ? "listed at the end under unrelated neighbours" : "", source: expSrc, key: "host:shared" });
  for (const hn of neighbors.slice(0, 200)) add({ tier: "neighbor", what: hn, url: "", meta: `unrelated site on the same ${shared.provider || "shared"} address`, source: expSrc, key: `nbr:${hn}` });

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
  if (ep && !ep.error && noMail) fact("Email security", noMailOpen(ep) ? "No mail: no MX records, not graded" : "No mail, and locked against spoofing", "Email security");
  else if (ep && !ep.error && ep.grade && ep.grade !== "N/A") fact("Email security", `Grade ${ep.grade} · ${ep.spoofable === "yes" ? "can be spoofed" : ep.spoofable === "no" ? "spoofing rejected" : "mostly protected"}`, "Email security");
  if (dd && !dd.error) fact("DNSSEC", dd.dnssec?.signed && dd.dnssec?.ds ? "Enabled" : "Not enabled", "DNS hardening");
  const cs = c.subdomains?.ct_summary;
  if (cs) fact("Certificates", `${fmtNum(cs.total)} logged since ${cs.first_issued || "?"} · ${fmtNum(cs.active)} still valid`, "Certificate logs");
  if (wkn?.favicon) fact("Favicon hash", String(wkn.favicon.hash), "Published files", `https://www.shodan.io/search?query=${encodeURIComponent(wkn.favicon.shodan_query)}`);
  if (wkn && !wkn.error && wkn.found) fact("security.txt", wkn.security_txt ? (wkn.security_txt.contact || []).slice(0, 2).join(", ") || "Published" : "Not published", "Published files");
  const order = { flag: 0, surface: 1, inventory: 2, lookalike: 3, neighbor: 4 };
  items.sort((a, b) => order[a.tier] - order[b.tier]);
  return { items, facts };
}

// What the AI is sent about takeover candidates: exactly what the screen shows. A candidate the
// backend called dangling is withheld when this same run resolved the host, here as in the ledger.
export function takeoverForAi(c, target) {
  const tk = c?.takeover;
  if (!tk || tk.error || !Array.isArray(tk.candidates)) return tk || null;
  const live = resolvedHosts(c, target);
  const candidates = tk.candidates.filter((x) => !(x.status === "dangling" && live.has(lc(x.host))));
  return { ...tk, candidates, dangling: candidates.filter((x) => x.status === "dangling").length, withheld_resolved_in_this_run: tk.candidates.length - candidates.length };
}
