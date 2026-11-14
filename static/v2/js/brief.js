// "At a glance": a short written brief built from rules, with no model involved.
// It reads the same evidence the ledger shows and says what stands out, what is
// uncertain, and what to do next. Every line is a plain statement of what a source
// returned; nothing here guesses.
//
// A row: { level: "flag" | "ok" | "info", text }   An action: { label, pivot, value } | { label, tab }

import { reconTimeline, domainAgeDays } from "./timeline.js";

const norm = (s) => String(s ?? "").trim().toLowerCase().replace(/\s+/g, " ");
const list = (arr, n = 4) => arr.slice(0, n).join(", ") + (arr.length > n ? ` and ${arr.length - n} more` : "");
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

export function investigateBrief({ collected: c, items, facts, failed, type, target }) {
  const rows = [], actions = [];
  const add = (level, text) => rows.push({ level, text });
  const accounts = items.filter((i) => i.key?.startsWith("acct:"));
  const confirmed = accounts.filter((i) => i.tier === "confirmed"), possible = accounts.filter((i) => i.tier === "possible");

  if (type === "hash") {
    const v = String(c.hash?.verdict || "").toUpperCase();
    if (c.hash && !c.hash.error) add(v === "MALICIOUS" ? "flag" : v === "CLEAN" ? "ok" : "info", v === "MALICIOUS" ? `Known malware${c.hash.malware_families?.length ? ` (${list(c.hash.malware_families, 3)})` : ""}. Do not run this file.` : v === "CLEAN" ? "A known, benign file according to CIRCL." : "No source has seen this hash. That is not a clean bill of health: new or rare files are often unknown.");
  } else if (type === "phone") {
    const p = c.phone || {};
    if (p.carrier || p.line_type) add(/voip/i.test(p.line_type || "") ? "flag" : "info", `${p.line_type || "Line"}${p.carrier ? ` on ${p.carrier}` : ""}${p.location || p.country ? `, ${[p.location, p.country].filter(Boolean).join(", ")}` : ""}.${/voip/i.test(p.line_type || "") ? " VOIP numbers are easy to get and discard." : ""}`);
    else add("info", "No carrier data without a NumLookup key. The lookup links under By source open in a new tab.");
  } else if (type === "name") {
    add("info", "CrawlR does not query people-search sites. The links under By source open them for you to search by hand.");
  } else {
    if (confirmed.length || possible.length) add(confirmed.length ? "ok" : "info", `${plural(confirmed.length, "confirmed account")} and ${plural(possible.length, "possible account")}. Confirmed means the account exists; it does not say who owns it.`);
    // Names read from profiles. Showing that they differ is the point: one handle, several people.
    const names = new Map();
    const seeName = (name, where) => { const k = norm(name); if (!k || k === norm(target) || k.length < 3) return; if (!names.has(k)) names.set(k, { name: String(name).trim(), where: [] }); if (!names.get(k).where.includes(where)) names.get(k).where.push(where); };
    if (c.github?.found && !c.github.error) seeName(c.github.name, "GitHub");
    if (c.gravatar?.found && !c.gravatar.error) seeName(c.gravatar.name || c.gravatar.display_name, "Gravatar");
    for (const r of c.maigret?.results || []) if (r.verified) seeName(r.profile?.name, r.site);
    for (const p of c.enricher?.profiles || []) seeName(p.display_name, p.platform);
    const ns = [...names.values()];
    if (ns.length > 1) add("flag", `Profiles under this handle show ${ns.length} different names (${list(ns.map((n) => `${n.name} on ${n.where[0]}`), 4)}). They may belong to different people. Do not treat the accounts as one person without more evidence.`);
    else if (ns.length === 1 && ns[0].where.length > 1) add("ok", `The name "${ns[0].name}" appears on ${ns[0].where.length} profiles (${list(ns[0].where)}), which supports them being the same person.`);
    else if (ns.length === 1) add("info", `One profile carries a name: "${ns[0].name}" on ${ns[0].where[0]}.`);

    const breaches = c.hibp && !c.hibp.error ? c.hibp.breaches || [] : [];
    if (breaches.length) add("flag", `This address is in ${plural(breaches.length, "known breach", "known breaches")} (${list(breaches, 5)}). Passwords used on those sites should be considered exposed.`);
    else if (c.hibp && !c.hibp.error) add("ok", "Not in any breach known to the breach source.");
    const holehe = c.holehe && !c.holehe.error ? c.holehe.results || [] : [];
    if (holehe.length) add("info", `Registered on ${plural(holehe.length, "service")} according to Holehe (${list(holehe.map((r) => r.site || r.domain), 6)}).`);
    if (c.sherlock || c.maigret) {
      const two = possible.filter((i) => (i.sources || []).length > 1).length;
      if (two) add("info", `${plural(two, "possible account")} ${two === 1 ? "was" : "were"} reported by two tools. That is worth more than one, but still not verification.`);
    }
    if (!accounts.length && !breaches.length && !holehe.length && !failed.length && (c.sherlock || c.maigret || c.holehe)) add("info", "No source found anything for this target. Check the spelling, or try a variant of the handle.");

    // next steps: only things CrawlR can do or the investigator can check directly
    const email = facts.find((f) => f.k === "Email")?.v;
    if (email && norm(email) !== norm(target)) actions.push({ label: `Investigate ${email}`, pivot: "investigate", value: email });
    const site = facts.find((f) => f.k === "Website")?.v;
    try { const host = site ? new URL(/^https?:/.test(site) ? site : `https://${site}`).hostname.replace(/^www\./, "") : ""; if (host && !/(github|twitter|x|linkedin|instagram|facebook|youtube|medium|linktr)\./.test(host + ".")) actions.push({ label: `Recon ${host}`, pivot: "recon", value: host }); } catch { /* not a URL */ }
    if (type === "email") { const d = target.split("@")[1]; if (d && !c.harvester?.skipped) actions.push({ label: `Recon ${d}`, pivot: "recon", value: d }); }
    if (possible.length) add("info", "Next: open the possible accounts that matter and tick them off as you check them. The review boxes are saved with the case.");
  }
  if (failed.length) add("flag", `${plural(failed.length, "source")} failed (${list(failed.map((f) => f.name))}), so this picture has gaps. Re-run to fill them.`);
  return { rows, actions };
}

export function reconBrief({ collected: c, items, failed, type, target, today }) {
  const rows = [], actions = [];
  const add = (level, text) => rows.push({ level, text });
  const flags = items.filter((i) => i.tier === "flag");
  const ok = (d) => d && !d.error;

  if (type === "asn") {
    const a = c.asn_detail;
    if (a?.found) add("info", `${a.asn}${a.org || a.name ? ` is ${a.org || a.name}` : ""}${a.country ? ` (${a.country})` : ""}, announcing ${a.total_prefixes ?? "?"} prefixes with ${a.total_peers ?? "?"} peers.`);
  } else {
    if (flags.length) add("flag", `${plural(flags.length, "flag")}: ${list(flags.map((f) => f.what), 3)}.`);
    else if (!failed.length) add("ok", "No flags: nothing risky or misconfigured showed up in the checks that ran.");

    if (c.dns?.cloudflare_proxied) add("info", "Behind Cloudflare. Open ports, the TLS certificate and HTTP headers describe Cloudflare's edge, not the origin server.");
    const ep = c.email_posture;
    if (ok(ep) && ep.grade) add(ep.spoofable === "yes" ? "flag" : "ok", ep.spoofable === "yes" ? "Mail from this domain can be spoofed: there is no enforced DMARC policy. Phishing that uses the real domain in the From line would be delivered." : `Email spoofing is ${ep.spoofable === "no" ? "rejected" : "mostly caught"} (grade ${ep.grade}).`);
    const age = domainAgeDays(c, today);
    if (age != null && age < 90) add("flag", `Registered ${age === 0 ? "today" : `${age} day${age === 1 ? "" : "s"} ago`}. A very new domain is common for phishing and throwaway infrastructure, and for any project that has just started. Weigh it with the other findings.`);
    const tk = c.takeover;
    if (ok(tk) && tk.dangling) add("flag", `${plural(tk.dangling, "subdomain")} point${tk.dangling === 1 ? "s" : ""} at a cloud resource that no longer exists (${list((tk.candidates || []).filter((x) => x.status === "dangling").map((x) => x.host), 3)}). Verify by hand before reporting a takeover.`);

    // hosts outside the main network
    const subs = c.subdomains?.subdomains || [], map = c.ipAsn || {};
    const byAsn = new Map();
    for (const s of subs) for (const ip of [].concat(s.ips || [])) { const a = map[ip]?.asn; if (a) { if (!byAsn.has(a)) byAsn.set(a, { org: map[ip].org, hosts: new Set() }); byAsn.get(a).hosts.add(s.subdomain); } }
    if (byAsn.size > 1) {
      const sorted = [...byAsn.entries()].sort((x, y) => y[1].hosts.size - x[1].hosts.size);
      const [mainAsn, main] = sorted[0];
      const outliers = sorted.slice(1).filter(([, v]) => v.hosts.size <= 2);
      if (outliers.length && main.hosts.size >= 3) add("info", `Most hosts sit in ${mainAsn}${main.org ? ` (${main.org})` : ""}. ${((n) => `${plural(n, "host")} ${n === 1 ? "sits" : "sit"}`)(outliers.reduce((n, [, v]) => n + v.hosts.size, 0))} elsewhere (${list(outliers.map(([a, v]) => `${[...v.hosts][0]} in ${a}`), 3)}), which often means a third-party service or a forgotten server.`);
    }
    const cs = c.subdomains?.ct_summary;
    if (cs?.not_resolving?.length) add("info", `${plural(cs.not_resolving.length, "name")} in certificate logs no longer resolve${cs.not_resolving.length === 1 ? "s" : ""}${cs.not_resolving.length <= 3 ? ` (${cs.not_resolving.join(", ")})` : ""}. Retired hosts are worth a look in the Wayback Machine.`);
    const la = c.lookalikes;
    if (ok(la) && la.registered) add(la.with_mail ? "flag" : "info", `${plural(la.registered, "lookalike domain")} ${la.registered === 1 ? "is" : "are"} registered${la.with_mail ? `, ${la.with_mail} of them able to receive mail` : ""}. Registered does not mean malicious; check who owns the mail-capable ones first.`);
    const wk = c.wellknown;
    if (ok(wk) && wk.found && !wk.security_txt) add("info", "No security.txt, so there is no published contact for reporting a vulnerability.");
    const paths = Object.values(c.wayback?.interesting_paths || {}).reduce((n, v) => n + v.length, 0);
    if (paths) add("info", `${plural(paths, "archived path")} look sensitive (admin pages, backups, config files). They are in the Wayback card under By source.`);
    const sslDays = c.ssl?.found ? c.ssl.days_left : null;
    if (sslDays != null && sslDays >= 30) add("ok", `TLS certificate is valid for another ${sslDays} days.`);
    if (!c.portscan && c.shodan?.found && (c.shodan.ports || []).length) add("info", "Open ports come from a passive index, not a live scan. Turn on the port scan under Sources for a live check of hosts you are authorized to test.");
    if (wk?.favicon) actions.push({ label: "Find this favicon in Shodan", href: `https://www.shodan.io/search?query=${encodeURIComponent(wk.favicon.shodan_query)}` });
    if (subs.length) actions.push({ label: "Open the topology", tab: "topology" });
    if (reconTimeline(c, target, today).events.length > 2) actions.push({ label: "Open the timeline", tab: "timeline" });
  }
  if (failed.length) add("flag", `${plural(failed.length, "check")} failed (${list(failed.map((f) => f.name))}), so this is not a complete picture. Re-run to fill the gaps.`);
  return { rows, actions };
}
