// "At a glance": a short written brief built from rules, with no model involved.
// It reads the same evidence the ledger shows and says what stands out, what is
// uncertain, and what to do next. Every line is a plain statement of what a source
// returned; nothing here guesses.
//
// A row: { level: "flag" | "ok" | "info", text, url, link_kind, link_label? }
//   url is the page where the statement can be checked, when one exists (see links.js).
// An action: { label, pivot, value } | { label, tab } | { label, href }

import { reconTimeline, domainAgeDays } from "./timeline.js";
import { breachList, hashView, hashCoverage, TEST_FILE_TEXT, isFreeMail, emailParts } from "./evidence.js";
import { adultBriefText } from "./adult.js";
import { nameBrief } from "./names.js";
import { sealLink, evidenceUrl, exposureEvidence, dnsEvidence, certEvidence, rdapEvidence, waybackEvidence, isDomain } from "./links.js";

const norm = (s) => String(s ?? "").trim().toLowerCase().replace(/\s+/g, " ");
const list = (arr, n = 4) => arr.slice(0, n).join(", ") + (arr.length > n ? ` and ${arr.length - n} more` : "");
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

// identity: the clusters from buildEvidence ({ views, primary }). Without it the brief says
// nothing about names, so it can never merge people on its own.
// incomplete: names of sources that failed, answered only in part, or never answered. While there
// are any, a count is a lower bound: the brief says "at least" and never calls a zero good.
export function investigateBrief({ collected: c, items, facts, identity, failed, incomplete = [], type, target }) {
  const rows = [], actions = [];
  const add = (level, text, ev) => rows.push(sealLink({ level, text, ev }, { subjects: [target] }));
  const accounts = items.filter((i) => i.key?.startsWith("acct:"));
  const tier = (t) => accounts.filter((i) => i.tier === t);
  const linked = tier("linked"), matches = tier("matches"), different = tier("different"), unverified = tier("unverified");

  if (type === "hash") {
    const v = hashView(c.hash);
    const vt = ((u) => (u ? { url: u, label: "VirusTotal" } : null))(evidenceUrl.virustotal(c.hash?.hash));
    if (v) {
      if (v.verdict === "TEST_FILE") add("ok", `${v.testFile.name}: ${TEST_FILE_TEXT}. It is not malware.`, vt);
      else if (v.verdict === "MALICIOUS") add("flag", `Known malware${v.family ? ` (${v.family})` : ""}. Do not run this file.`, vt);
      else if (v.verdict === "CLEAN") add("ok", "A known, benign file according to CIRCL.", vt);
      else {
        // Only the sources that answered can be said not to have seen it.
        const cov = hashCoverage(c.hash);
        add("info", !cov.failed.length ? "No source has seen this hash. That is not a clean bill of health: new or rare files are often unknown."
          : cov.answered ? `None of the ${cov.answered} ${cov.answered === 1 ? "source" : "sources"} that answered has seen this hash. That is not a clean bill of health: new or rare files are often unknown.`
            : "No source could be asked about this hash, so nothing is known about it. Run it again.");
      }
      if (v.verdict === "MALICIOUS" && !v.detection) add("info", "There is no detection ratio from keyless sources, so the verdict rests on the sources named in the Hash lookup card.");
      const down = c.hash.failed_sources || [];
      if (down.length) add("info", `${list(down.map(String))} could not be asked, so ${down.length === 1 ? "it is" : "they are"} unknown, not "not found".`);
    }
  } else if (type === "phone") {
    const p = c.phone || {};
    if (p.carrier || p.line_type) add(/voip/i.test(p.line_type || "") ? "flag" : "info", `${p.line_type || "Line"}${p.carrier ? ` on ${p.carrier}` : ""}${p.location || p.country ? `, ${[p.location, p.country].filter(Boolean).join(", ")}` : ""}.${/voip/i.test(p.line_type || "") ? " VOIP numbers are easy to get and discard." : ""}`);
    else add("info", "No carrier data without a NumLookup key. The lookup links under By source open in a new tab.");
  } else if (type === "name") {
    // Candidates, never findings: how many, where from, what could not be asked, one next step.
    for (const r of nameBrief(c, target)) add(r.level, r.text, r.ev);
  } else {
    const read = linked.length + matches.length + different.length;
    const noPrimary = !!identity?.noPrimary;
    if (accounts.length && noPrimary) add("info", `${plural(matches.length, "profile")} ${matches.length === 1 ? "was" : "were"} read and ${unverified.length} ${unverified.length === 1 ? "account is" : "accounts are"} unverified. Each read profile exists, and nothing ties it to the target.`);
    else if (accounts.length && incomplete.length) add("info", `At least ${[linked.length && plural(linked.length, "linked account"), matches.length && `${matches.length} that exist and match`, different.length && `${different.length} that belong to a different person`, unverified.length && `${unverified.length} unverified`].filter(Boolean).join(", ")}. ${list(incomplete)} did not fully answer, so these are lower bounds and any count not listed is unknown, not zero.`);
    else if (accounts.length) add(linked.length ? "ok" : "info", `${plural(linked.length, "linked account")}, ${matches.length} that exist and match, ${different.length} that belong to a different person, and ${unverified.length} unverified. A profile that exists shows the handle is taken there; only a linked one is tied to this identity.`);
    // People, not names: "Eric" and "Eric Henderson" are one person, two unrelated names are two.
    const views = identity?.views || [];
    const people = views.filter((v) => v.named);
    const main = views.find((v) => v.primary);
    const who = (v) => `${v.label} on ${list(v.sites, 3)}`;
    if (noPrimary && people.length > 1) add("flag", `${plural(people.length, "different name")} appear under this handle (${list(people.map(who), 4)}), and none is tied to the target. There is no record for the target itself and no strong signal between the profiles, so no one is treated as the target.`);
    else if (noPrimary && people.length === 1) add("info", `One name appears under this handle (${who(people[0])}). Nothing ties it to the target: there is no record for the target itself and no strong signal.`);
    else if (main?.named && main.sites.length > 1) add("ok", `${main.sites.length} profiles carry the name "${main.label}" or are tied to it (${list(main.sites)}), which supports them being one person.`);
    else if (main?.named) add("info", `The primary identity is "${main.label}", from ${main.sites[0]}.`);
    // Only clusters whose name conflicts with the primary identity are other people. A name that
    // does not conflict ("L. Torvalds", a nickname) is not counted as someone else.
    const others = people.filter((v) => !v.primary && (v.different || !main?.named));
    if (main?.named && others.length) add("flag", `${plural(others.length + 1, "different person", "different people")} use this handle: ${list([main, ...others].map(who), 4)}. Only the first is treated as the target. Do not read the others' accounts as the same person.`);
    else if (main && !main.named && others.length) add("info", `The ${main.sites[0]} record carries no name. ${others.length === 1 ? `One name appears on other profiles (${who(others[0])})` : `${others.length} unrelated names appear on other profiles (${list(others.map(who), 4)})`}, and nothing ties ${others.length === 1 ? "it" : "any of them"} to that record yet.`);
    const blocked = unverified.filter((i) => /^Blocked by site/.test(i.meta || ""));
    if (blocked.length) add("info", `${list(blocked.map((i) => i.what))} blocked the check, so ${blocked.length === 1 ? "that account is" : "those accounts are"} unknown, not absent.`);

    // Adult and dating sites get one neutral line. They are in none of the counts above.
    const adult = items.filter((i) => i.tier === "adult");
    if (adult.length) add("info", adultBriefText(adult));

    const breaches = c.hibp && !c.hibp.error ? breachList(c.hibp) : [];
    if (breaches.length) add("flag", `This address is in ${plural(breaches.length, "known breach", "known breaches")} (${list(breaches.map((b) => (b.year ? `${b.name} ${b.year}` : b.name)), 5)}). Passwords used on those sites should be considered exposed.`);
    else if (c.hibp && !c.hibp.error) add("ok", "Not in any breach known to the breach source.");
    const holehe = c.holehe && !c.holehe.error ? c.holehe.results || [] : [];
    if (holehe.length) add("info", `Registered on ${plural(holehe.length, "service")} according to Holehe (${list(holehe.map((r) => r.site || r.domain), 6)}).`);
    if (c.sherlock || c.maigret) {
      const two = unverified.filter((i) => (i.sources || []).length > 1).length;
      if (two) add("info", `${plural(two, "unverified account")} ${two === 1 ? "was" : "were"} reported by two tools. That is worth more than one, but still not verification.`);
    }
    if (!accounts.length && !breaches.length && !holehe.length && !failed.length && (c.sherlock || c.maigret || c.holehe)) add("info", "No source found anything for this target. Check the spelling, or try a variant of the handle.");

    // next steps: only things CrawlR can do or the investigator can check directly
    const email = facts.find((f) => f.k === "Email")?.v;
    if (email && norm(email) !== norm(target)) actions.push({ label: `Investigate ${email}`, pivot: "investigate", value: email });
    const site = facts.find((f) => f.k === "Website")?.v;
    try { const host = site ? new URL(/^https?:/.test(site) ? site : `https://${site}`).hostname.replace(/^www\./, "") : ""; if (host && !/(github|twitter|x|linkedin|instagram|facebook|youtube|medium|linktr)\./.test(host + ".")) actions.push({ label: `Recon ${host}`, pivot: "recon", value: host }); } catch { /* not a URL */ }
    if (type === "email") {
      const { handle, domain } = emailParts(target);
      if (domain && !c.harvester?.skipped && !isFreeMail(domain)) actions.push({ label: `Recon ${domain}`, pivot: "recon", value: domain });
      const hosts = c.harvester && !c.harvester.error && !c.harvester.skipped ? (c.harvester.hosts || []).length : 0;
      if (hosts) add("info", `${plural(hosts, "host")} on ${domain} ${hosts === 1 ? "is" : "are"} listed at the end of the findings. They describe the organisation, not this person.`);
      if (handle) add("info", `Username tools were not run on "${handle}", the part before the @: it is a guess at a handle, not a finding. It is listed under Leads from profiles if you want to follow it.`);
    }
    const leads = items.filter((i) => i.tier === "lead").length;
    if (leads && type !== "email") add("info", `${plural(leads, "lead")} from profiles (handles, addresses, domains, links) ${leads === 1 ? "is" : "are"} listed under the findings. Nothing is followed until you click.`);
    if (unverified.length || read > linked.length) add("info", "Next: open the accounts that matter and tick them off as you check them. The review boxes are saved with the case.");
  }
  if (failed.length) add("flag", `${plural(failed.length, "source")} failed (${list(failed.map((f) => f.name))}), so this picture has gaps. Re-run to fill them.`);
  return { rows, actions };
}

const lc = (s) => String(s ?? "").trim().toLowerCase().replace(/\.$/, "");
const arr = (v) => [].concat(v ?? []).flat().filter(Boolean);
// Hosts this run saw answering: an address in DNS, a live HTTP response, a TLS handshake.
export function resolvedHosts(c, target) {
  const live = new Set();
  const t = lc(target);
  const rec = c?.dns && !c.dns.error ? c.dns.records || {} : {};
  if (t && (arr(rec.A).length || arr(rec.AAAA).length || arr(rec.CNAME).length || (c?.headers?.found && !c.headers.error) || (c?.ssl?.found && !c.ssl.error) || (c?.redirects?.found && !c.redirects.error))) live.add(t);
  for (const s of c?.subdomains?.subdomains || []) if (arr(s.ips).length) live.add(lc(s.subdomain));
  return live;
}
// "none": the domain has no MX and takes no mail. "unknown": the MX lookup failed. Old saved
// runs have no mail_enabled field, so an answered, empty MX list is read the same way.
export function mailState(ep) {
  if (!ep || ep.error) return "unknown";
  if (ep.mail_enabled === false) return "none";
  if (ep.mail_enabled === true) return "yes";
  if (ep.mail_enabled === null) return "unknown";
  return Array.isArray(ep.mx) && ep.mx.length === 0 && !ep.spf && !ep.dmarc ? "none" : "yes";
}
// A no-mail domain is still open to forged From lines unless it publishes the null records.
// Open: the backend says spoofable, or suggests records to add. Otherwise it is already locked.
export const noMailOpen = (ep) => ep?.spoofable === "yes" || (Array.isArray(ep?.suggested_records) && ep.suggested_records.length > 0);
export const NULL_RECORDS = ["v=spf1 -all", "v=DMARC1; p=reject;", "0 ."];
export const nullRecords = (ep) => { const r = (ep?.suggested_records || []).map((x) => (typeof x === "string" ? x : x?.value || x?.record || "")).filter(Boolean); return r.length ? r : NULL_RECORDS.slice(0, 2); };

export function reconBrief({ collected: c, items, failed, type, target, today }) {
  const rows = [], actions = [];
  const add = (level, text, ev) => rows.push(sealLink({ level, text, ev }, { subjects: [target] }));
  const domain = type === "domain" && isDomain(target) ? lc(target) : "";
  const flags = items.filter((i) => i.tier === "flag");
  const ok = (d) => d && !d.error;

  if (type === "asn") {
    const a = c.asn_detail;
    if (a?.found) add("info", `${a.asn}${a.org || a.name ? ` is ${a.org || a.name}` : ""}${a.country ? ` (${a.country})` : ""}, announcing ${a.total_prefixes ?? "?"} prefixes with ${a.total_peers ?? "?"} peers.`);
  } else {
    if (flags.length) add("flag", `${plural(flags.length, "flag")}: ${list(flags.map((f) => f.what), 3)}.`);
    else if (!failed.length) add("ok", "No flags: nothing risky or misconfigured showed up in the checks that ran.");

    if (c.dns?.cloudflare_proxied) add("info", "Behind Cloudflare. Open ports, the TLS certificate and HTTP headers describe Cloudflare's edge, not the origin server.", dnsEvidence(domain, "A"));
    const ep = c.email_posture;
    const mail = mailState(ep);
    if (ok(ep) && mail === "none" && noMailOpen(ep)) add("info", `This domain has no MX records, so it does not receive mail, and it is not graded for spoofing. It publishes no policy that stops others using it in a From line: ${nullRecords(ep).slice(0, 2).join(" and ")} would close that.`, dnsEvidence(domain, "MX"));
    else if (ok(ep) && mail === "none") add("ok", "This domain has no MX records, so it does not receive mail, and its SPF and DMARC records tell receivers to reject mail that claims to come from it. It is locked against spoofing.", dnsEvidence(domain ? `_dmarc.${domain}` : "", "TXT"));
    else if (ok(ep) && ep.grade && ep.grade !== "N/A") add(ep.spoofable === "yes" ? "flag" : "ok", ep.spoofable === "yes" ? "Mail from this domain can be spoofed: there is no enforced DMARC policy. Phishing that uses the real domain in the From line would be delivered." : `Email spoofing is ${ep.spoofable === "no" ? "rejected" : "mostly caught"} (grade ${ep.grade}).`, dnsEvidence(domain ? `_dmarc.${domain}` : "", "TXT"));
    const age = domainAgeDays(c, today);
    if (age != null && age < 90) add("flag", `Registered ${age === 0 ? "today" : `${age} day${age === 1 ? "" : "s"} ago`}. A very new domain is common for phishing and throwaway infrastructure, and for any project that has just started. Weigh it with the other findings.`, rdapEvidence(domain));
    const tk = c.takeover;
    const live = resolvedHosts(c, target);
    // A takeover row needs "dangling" from the backend, and is dropped if this run resolved the host.
    const dangling = ok(tk) ? (tk.candidates || []).filter((x) => x.status === "dangling" && !live.has(lc(x.host))) : [];
    if (dangling.length) add("flag", `${plural(dangling.length, "subdomain")} point${dangling.length === 1 ? "s" : ""} at a cloud resource that no longer exists (${list(dangling.map((x) => x.host), 3)}). Verify by hand before reporting a takeover.`);
    const tkUnknown = ok(tk) ? Number(tk.unknown || 0) + (Array.isArray(tk.unchecked) ? tk.unchecked.length : Number(tk.unchecked || 0)) : 0;
    if (tkUnknown) add("info", `${plural(tkUnknown, "host")} could not be checked for takeover because a DNS lookup failed. That is unknown, not safe.`);
    const exp = c.shodan;
    if (ok(exp) && exp.shared_host) add("info", `The address is shared ${exp.shared_host.provider || "hosting"}: ${plural((exp.neighbors || []).length, "other site")} answer${(exp.neighbors || []).length === 1 ? "s" : ""} on it, and the open ports are the provider's, not this site's.`, exposureEvidence(exp));

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
    // Never say "no longer resolves" about a name this same run resolved.
    const gone = (cs?.not_resolving || []).filter((x) => !live.has(lc(x)));
    if (gone.length) add("info", `${plural(gone.length, "name")} in certificate logs no longer resolve${gone.length === 1 ? "s" : ""}${gone.length <= 3 ? ` (${gone.join(", ")})` : ""}. Retired hosts are worth a look in the Wayback Machine.`, certEvidence(domain));
    const unsure = (cs?.resolution_unknown || []).filter((x) => !live.has(lc(x)));
    if (unsure.length) add("info", `${plural(unsure.length, "name")} in certificate logs could not be checked${unsure.length <= 3 ? ` (${unsure.join(", ")})` : ""}: the DNS lookup failed, so whether ${unsure.length === 1 ? "it resolves" : "they resolve"} is unknown.`);
    const la = c.lookalikes;
    if (ok(la) && la.registered) add(la.with_mail ? "flag" : "info", `${plural(la.registered, "lookalike domain")} ${la.registered === 1 ? "is" : "are"} registered${la.with_mail ? `, ${la.with_mail} of them able to receive mail` : ""}. Registered does not mean malicious; check who owns the mail-capable ones first.`);
    const wk = c.wellknown;
    if (ok(wk) && wk.found && !wk.security_txt) add("info", "No security.txt, so there is no published contact for reporting a vulnerability.");
    const paths = Object.values(c.wayback?.interesting_paths || {}).reduce((n, v) => n + v.length, 0);
    if (paths) add("info", `${plural(paths, "archived path")} look sensitive (admin pages, backups, config files). They are in the Wayback card under By source.`, waybackEvidence(domain));
    const sslDays = c.ssl?.found ? c.ssl.days_left : null;
    if (sslDays != null && sslDays >= 30) add("ok", `TLS certificate is valid for another ${sslDays} days.`, certEvidence(domain));
    if (!c.portscan && c.shodan?.found && (c.shodan.ports || []).length) add("info", "Open ports come from a passive index, not a live scan. Turn on the port scan under Sources for a live check of hosts you are authorized to test.", exposureEvidence(c.shodan));
    if (wk?.favicon) actions.push({ label: "Find this favicon in Shodan", href: `https://www.shodan.io/search?query=${encodeURIComponent(wk.favicon.shodan_query)}` });
    if (subs.length) actions.push({ label: "Open the topology", tab: "topology" });
    if (reconTimeline(c, target, today).events.length > 2) actions.push({ label: "Open the timeline", tab: "timeline" });
  }
  if (failed.length) add("flag", `${plural(failed.length, "check")} failed (${list(failed.map((f) => f.name))}), so this is not a complete picture. Re-run to fill the gaps.`);
  return { rows, actions };
}
