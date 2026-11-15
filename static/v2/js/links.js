// Link integrity. Every ledger row, fact, lead, recon finding and source-card link carries a
// link_kind, decided here, so a link never claims more than the source knew.
// Pure: no DOM, no network. Old saved cases and case files go through the same code.
//
//   verified_profile      the URL came from a source that read that page or record (GitHub's API,
//                         Gravatar, a Maigret row with a profile read, the enricher, a platform
//                         check that found a marker), or the link check confirmed the page exists
//   templated_unverified  a site template plus the handle, which nothing has checked (Sherlock,
//                         Maigret without a profile read, a platform check that was blocked)
//   evidence              where the claim can be checked: a public lookup page for that exact
//                         record, or the thing the row is about (a host, a link found on a profile)
//   search                an outbound search the investigator chooses to open (a name case, see
//                         names.js, and a phone case, see phone.js). It carries the name or the
//                         number on purpose, proves nothing, and is never used for a finding, a
//                         fact or a lead.
//   none                  no usable public URL. Rendered as plain text, never as an anchor.
//
// An item's link: { url, link_kind, hint?, link_label?, more? }
//   link_label  the link is shown as its own labelled anchor after the text ("InternetDB record")
//               instead of wrapping it, because it points at evidence and not at the thing itself
//   more        one further evidence link: { url, label, link_kind: "evidence" }
//   hint        how to check by hand, for a row that has no public URL

export const LINK_KINDS = ["verified_profile", "templated_unverified", "evidence", "search", "none"];
export const UNVERIFIED_TEXT = "unverified URL";

const lc = (s) => String(s ?? "").trim().toLowerCase();
const enc = encodeURIComponent;

// Only absolute http(s) URLs can become links.
export function parseUrl(u) {
  try { const x = new URL(String(u ?? "").trim()); return x.protocol === "http:" || x.protocol === "https:" ? x : null; } catch { return null; }
}
const decode = (s) => { try { return decodeURIComponent(s); } catch { return s; } };
export const hostOf = (u) => parseUrl(/^https?:\/\//i.test(String(u ?? "")) ? u : `https://${u}`)?.hostname.toLowerCase().replace(/^www\./, "") || "";

// A homepage says nothing about the subject: no path, and nothing in the host, the query or the
// fragment that names it. "https://discord.com" is one; "https://handle.itch.io/" and a row whose
// subject is the host itself are not.
export function isBareHome(u, subjects = []) {
  const x = parseUrl(u);
  if (!x) return false;
  if (x.pathname.replace(/\/+$/, "")) return false;
  const subs = [].concat(subjects).map(lc).filter(Boolean);
  const host = x.hostname.toLowerCase().replace(/^www\./, "");
  const labels = host.split(".");
  // A handle counts only as a subdomain label, so the user "github" does not make github.com a profile.
  if (subs.some((s) => (s.includes(".") ? host === s || host.endsWith(`.${s}`) : labels.slice(0, -2).includes(s)))) return false;
  const tail = decode(x.search + x.hash).toLowerCase();
  if (tail.length > 1) return subs.length ? !subs.some((s) => tail.includes(s)) : false;
  return true;
}

// ---- platforms with no public username URL ---------------------------------------------
// Shown before any verification. The link check returns its own hint for other sites.
export const siteId = (s) => lc(s).replace(/\(.*?\)/g, "").replace(/[^a-z0-9]/g, "");
// The wording matches the hints the link check returns, so a row reads the same before and after.
const NO_PUBLIC = {
  discord: "Discord has no public profile page. Search the handle inside the app or ask for the numeric user ID.",
  whatsapp: "WhatsApp accounts are phone numbers, not handles. There is no public page to open.",
  signal: "Signal has no public profiles. A handle can only be looked up inside the app by someone who knows it exactly.",
  skype: "Skype has no public profile page. Search the name in the Skype or Teams directory while signed in.",
  cashapp: "Cash App shows a page only at cash.app/$cashtag. Look the cashtag up inside the app to see the name on it.",
};
// Reddit refuses requests from servers, so its row is usually "Blocked by site" with a link to open by hand.
export const REDDIT_HINT = "Open the link in a browser. A missing account shows 'nobody on Reddit goes by that name'.";
// A sign-up check said the handle is in use and nothing was read. CrawlR's own sentence per site:
// the text is never taken from a stored case or a case file.
export const TAKEN_TEXT = { discord: "Discord's sign-up check says this handle is taken. Discord has no public profile page, so who holds it is unknown." };
export const TAKEN_GENERIC = "The site's sign-up check says this handle is taken. Nothing was read, so who holds it is unknown.";
export const TAKEN_NOTE = "handle taken, owner unknown";
// Reddit's API answers "not found" for an account it hides, so that answer is never the last word on a tool's report.
export const REDDIT_HIDDEN = "Reddit's API has no visible account with this name (a hidden or shadow-banned account looks the same)";
export const GENERIC_HINT = "This link is the site's homepage. Search the handle on the site itself.";
export const REGISTERED_HINT = "Found through the site's sign-up or reset form. There is no public page for an email address.";
export const BREACH_HINT = "No reference page for this breach. Search the address at xposedornot.com to check it.";
export const howToCheck = (site) => NO_PUBLIC[siteId(site)] || "";
const isCashtag = (x) => /(^|\.)cash\.app$/i.test(x.hostname) && /^\/\$[\w-]+\/?$/.test(decode(x.pathname));

// The one decision. `want` is what the source supports; this can only lower it to "none".
//   subjects  what the row is about (the handle, a host), for the homepage rule
//   secrets   an email or username that must never sit in a third-party query string
export function classifyLink({ url, want = "evidence", site = "", subjects = [], secrets = [] } = {}) {
  const profile = want === "verified_profile" || want === "templated_unverified";
  const none = (hint = "") => ({ url: "", link_kind: "none", ...(hint ? { hint } : {}) });
  const x = parseUrl(url);
  const id = siteId(site);
  // A URL with credentials in it is never shown or sent anywhere.
  if (x && (x.username || x.password)) return none(profile ? howToCheck(site) || GENERIC_HINT : "");
  const cash = id === "cashapp" && x && isCashtag(x);
  if (want === "templated_unverified" && Object.hasOwn(NO_PUBLIC, id) && !cash) return none(NO_PUBLIC[id]);
  // A cashtag page cannot be checked from a server, so its row keeps the hint beside the link.
  if (want === "templated_unverified" && cash) return { url: String(url).trim(), link_kind: want, hint: NO_PUBLIC.cashapp };
  if (!x) return none(profile ? howToCheck(site) || GENERIC_HINT : "");
  if (isBareHome(x.href, subjects)) return none(profile ? howToCheck(site) || GENERIC_HINT : "");
  if (want === "evidence") {
    const q = decode(x.search).toLowerCase();
    if (q && [].concat(secrets).map(lc).filter(Boolean).some((s) => q.includes(s))) return none();
  }
  return { url: String(url).trim(), link_kind: LINK_KINDS.includes(want) ? want : "evidence" };
}

// Gives an item its link fields. `ev` is an evidence link ({ url, label }) set by the builder:
// it becomes the item's labelled link, or its second link when the item has one of its own.
export function sealLink(it, { subjects = [], secrets = [] } = {}) {
  const subs = [...[].concat(subjects), it.what, hostOf(it.what)];
  const ev = it.ev; delete it.ev;
  if (!it.link_kind) {
    const own = it.url ? classifyLink({ url: it.url, want: "evidence", subjects: subs, secrets }) : { url: "", link_kind: "none" };
    it.url = own.url; it.link_kind = own.link_kind;
  }
  if (ev?.url) {
    const e = classifyLink({ url: ev.url, want: "evidence", subjects: subs, secrets });
    if (e.link_kind === "evidence" && it.link_kind === "none") { it.url = e.url; it.link_kind = "evidence"; it.link_label = String(ev.label || "Source record"); }
    else if (e.link_kind === "evidence" && e.url !== it.url) it.more = { url: e.url, label: String(ev.label || "Source record"), link_kind: "evidence" };
  }
  return it;
}
// The same for a fact: { k, v, source, url } gains link_kind. The value's own host is a subject,
// so a "Website" fact may link to the site it names.
export function sealFact(f, { subjects = [], secrets = [] } = {}) {
  if (f.link_kind) return f;
  const l = f.url ? classifyLink({ url: f.url, want: "evidence", subjects: [...[].concat(subjects), f.v, hostOf(f.v)], secrets }) : { url: "", link_kind: "none" };
  f.url = l.url; f.link_kind = l.link_kind;
  return f;
}

// ---- evidence URLs -----------------------------------------------------------------------
// Built only from values already in the result. Each opens the public page where the claim can
// be checked. Only a domain, an IP or a hash ever goes into one, never a username or an email.
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/i;
const IP4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const IP6 = /^(?=.*:)[0-9a-f:]{2,39}$/i;
const HASH = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i;
const DNS_TYPES = new Set(["A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA", "DS", "DNSKEY", "SOA", "PTR"]);
export const isDomain = (d) => DOMAIN.test(String(d ?? "").trim().replace(/\.$/, ""));
const isIp = (ip) => IP4.test(String(ip ?? "").trim()) || IP6.test(String(ip ?? "").trim());
const dom = (d) => lc(d).replace(/\.$/, "");
export const evidenceUrl = {
  internetdb: (ip) => (isIp(ip) ? `https://internetdb.shodan.io/${enc(String(ip).trim())}` : ""),
  shodanHost: (ip) => (isIp(ip) ? `https://www.shodan.io/host/${enc(String(ip).trim())}` : ""),
  dns: (name, type) => (isDomain(name) && DNS_TYPES.has(type) ? `https://dns.google/query?name=${enc(dom(name))}&type=${enc(type)}` : ""),
  crtsh: (domain) => (isDomain(domain) ? `https://crt.sh/?q=${enc(dom(domain))}` : ""),
  rdap: (domain) => (isDomain(domain) ? `https://rdap.org/domain/${enc(dom(domain))}` : ""),
  wayback: (domain) => (isDomain(domain) ? `https://web.archive.org/web/*/${enc(dom(domain))}` : ""),
  virustotal: (hash) => (HASH.test(String(hash ?? "").trim()) ? `https://www.virustotal.com/gui/file/${lc(hash)}` : ""),
  otx: (hash) => (HASH.test(String(hash ?? "").trim()) ? `https://otx.alienvault.com/indicator/file/${lc(hash)}` : ""),
  asn: (asn) => (/^(AS)?\d{1,10}$/i.test(String(asn ?? "").trim()) ? `https://bgp.he.net/AS${String(asn).trim().replace(/^AS/i, "")}` : ""),
};
const ev = (url, label) => (url ? { url, label } : null);
// Exposure rows: the index that reported the port or the CVE, for that exact address.
export const exposureEvidence = (exp) => (!exp || exp.error ? null : exp.source === "internetdb" ? ev(evidenceUrl.internetdb(exp.ip), "InternetDB record") : ev(evidenceUrl.shodanHost(exp.ip), "Shodan record"));
export const dnsEvidence = (name, type) => ev(evidenceUrl.dns(name, type), "DNS lookup");
export const certEvidence = (domain) => ev(evidenceUrl.crtsh(domain), "Certificate logs");
export const rdapEvidence = (domain) => ev(evidenceUrl.rdap(domain), "RDAP record");
export const waybackEvidence = (domain) => ev(evidenceUrl.wayback(domain), "Wayback Machine");
// An email or DNS hardening finding names the record it is about in its title. The lookup is
// for that exact record. A finding with no single record behind it (a wildcard, a suggestion)
// gets no link.
export function dnsFindingEvidence(title, domain, data = {}) {
  const t = lc(title);
  if (!isDomain(domain) || /suggested records|wildcard|reverse dns/.test(t)) return null;
  if (/dmarc|subdomains are not protected/.test(t)) return dnsEvidence(`_dmarc.${dom(domain)}`, "TXT");
  if (/\bspf\b/.test(t)) return dnsEvidence(domain, "TXT");
  if (/dkim/.test(t)) {
    const sel = (String(title).match(/\(([a-z0-9._-]+)/i) || [])[1] || (Array.isArray(data.dkim) ? data.dkim[0]?.selector : "");
    return /no dkim key/.test(t) || !sel ? null : dnsEvidence(`${sel}._domainkey.${dom(domain)}`, "TXT");
  }
  if (/mta-sts/.test(t)) return dnsEvidence(`_mta-sts.${dom(domain)}`, "TXT");
  if (/tls reporting/.test(t)) return dnsEvidence(`_smtp._tls.${dom(domain)}`, "TXT");
  if (/bimi/.test(t)) return dnsEvidence(`default._bimi.${dom(domain)}`, "TXT");
  if (/\bmx\b/.test(t)) return dnsEvidence(domain, "MX");
  if (/\bcaa\b/.test(t)) return dnsEvidence(domain, "CAA");
  if (/dnssec keys with no ds/.test(t)) return dnsEvidence(domain, "DS");
  if (/dnssec/.test(t)) return dnsEvidence(domain, "DNSKEY");
  return null;
}
// The findings a module returned, each with the lookup for its record: { ...finding, url, link_kind, link_label }.
export const findingsWithEvidence = (d, domain) => (d?.findings || []).map((f) => {
  const e = dnsFindingEvidence(f?.title, domain, d);
  return { ...f, url: e?.url || "", link_kind: e ? "evidence" : "none", ...(e ? { link_label: e.label } : {}) };
});

// ---- link check ----------------------------------------------------------------------------
// POST /api/recon/verify-links answers one of these per link. Results are kept in the case as
// collected.linkChecks, keyed by row id, so history, exports and case files keep them.
export const CHECK_STATES = ["verified", "not_found", "blocked", "unknown", "no_public_url"];
export const CHECK_TEXT = { verified: "page checked", not_found: "page not found", blocked: "Blocked by site", unknown: "could not be checked", no_public_url: "no public page" };
export const CHECK_BATCH = 25, CHECK_PARALLEL = 2;
// The server allows 12 calls a minute. The client stays under it, across every group.
export const CHECK_PER_MINUTE = 10, CHECK_WINDOW_MS = 60000, CHECK_RATE_WAITS = 6;
// What the verifier accepts for one link. A longer value is never sent, and never cut to fit.
export const MAX_CHECK_URL = 600, MAX_CHECK_ID = 80;
export const TOO_LONG = "address too long", HAS_PORT = "address names a port";
// The verifier refuses a whole batch over one address with an explicit port (":443" included),
// so those are never sent. The URL parser hides a default port, so the raw text is read.
export const hasPort = (u) => /:\d*$/.test(((String(u ?? "").trim().match(/^https?:\/\/([^/?#]*)/i) || [])[1] || "").replace(/^[^@]*@/, ""));
export const NO_PAGE_HINT = "This site has no public page for a handle. Search the handle on the site itself.";
// The verifier's own fixed sentences: the EVIDENCE dict in modules/link_verify.py, in its order
// (tests/js/links.test.mjs fails if the two drift). A stored case or a case file is
// outside data: a reason that is not one of these is dropped, and the row shows the plain state.
export const KNOWN_EVIDENCE = [
  "The page loaded and its title names this handle.",
  "The page loaded and the site's own profile data names this handle.",
  "The site answered 404: there is no page at this address.",
  "The site answered 410: the page has been removed.",
  "The site shows its own no-such-user page for this handle.",
  "The link redirects to a sign-in page.",
  "The site asks visitors to sign in or accept a prompt before it shows this page.",
  "The site refused the request.",
  "The site answered with a bot check instead of the page.",
  "The site shows what looks like a no-such-user page, but CrawlR has not confirmed that rule.",
  "The link redirects to the site's homepage, which can mean no such user or a members-only page.",
  "The link redirects to an error page, which does not say whether the profile exists.",
  "The link redirects to a search page, not to a profile.",
  "The site answers the same way for a missing profile and a refused request.",
  "This site rarely shows profiles to anonymous visitors, and nothing on the page names this handle.",
  "The page loaded but nothing on it names this handle.",
  "The link redirects to a page that is not a profile for this handle.",
  "The link redirects to a different site.",
  "The site answered with an error.",
  "The site sent a response CrawlR could not read.",
  "The link redirects too many times.",
  "The site took too long to answer.",
  "Could not connect to the site.",
  "The site's name could not be looked up.",
  "The secure connection to the site failed.",
  "CrawlR only connects to public internet hosts.",
  "The check could not be completed.",
  "CrawlR only checks links on sites its tools know.",
  "This link does not name this handle, so it was not checked.",
  "This link is not a plain http or https address, so it was not checked.",
  "CrawlR has checked this site many times in the last minute, so this link was not checked this time.",
  "Adult and dating sites are checked only when that mode is on, and never for a handle that suggests a minor.",
  "This site has no public profile page to check.",
  "This link points at the site's homepage, not at a profile.",
];
const EVIDENCE_OK = new Set(KNOWN_EVIDENCE);
// "Not checked this time" is not a result: the row stays open for a later check and is not stored.
export const THROTTLED_EVIDENCE = "CrawlR has checked this site many times in the last minute, so this link was not checked this time.";
export const isTransient = (r) => !!r && r.state === "unknown" && r.evidence === THROTTLED_EVIDENCE;
const KNOWN_HINTS = new Set([...Object.values(NO_PUBLIC), GENERIC_HINT, NO_PAGE_HINT, REDDIT_HINT]);
// Results that came from the verifier in this session. Membership cannot be saved or imported,
// so anything read back from History or a case file is treated as stored.
const FRESH = new WeakSet();
const clip = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
// One result, read defensively. Text from a stored result is kept only when it is a sentence
// CrawlR itself would have written; the live answer is shown as the server gave it (escaped).
export function readCheck(v) {
  if (!v || typeof v !== "object" || !CHECK_STATES.includes(v.state)) return null;
  if (FRESH.has(v)) return v;
  const evidence = clip(v.evidence, 200), hint = clip(v.hint, 300);
  return { state: v.state, url: clip(v.url, MAX_CHECK_URL), final_url: clip(v.final_url, MAX_CHECK_URL), evidence: EVIDENCE_OK.has(evidence) || evidence === TOO_LONG || evidence === HAS_PORT ? evidence : "", hint: KNOWN_HINTS.has(hint) ? hint : "", cached: v.cached === true };
}
export function readChecks(map) {
  const out = {};
  if (map && typeof map === "object" && !Array.isArray(map)) for (const [k, v] of Object.entries(map)) { const c = /^acct:/.test(k) && k.length <= MAX_CHECK_ID ? readCheck(v) : null; if (c) out[k] = c; }
  return out;
}
// The registrable part of a host, near enough without a suffix list: the last two labels, or
// three under a two-letter country suffix with a generic second level (example.co.uk).
export function regHost(u) {
  const labels = (parseUrl(u)?.hostname.toLowerCase().replace(/\.$/, "") || "").split(".").filter(Boolean);
  if (labels.length < 2) return labels.join(".");
  const n = labels.length > 2 && labels[labels.length - 1].length === 2 && /^(co|com|org|net|ac|gov|edu)$/.test(labels[labels.length - 2]) ? 3 : 2;
  return labels.slice(-n).join(".");
}
const SITE_ALIAS = { "twitter.com": "x.com", "threads.net": "threads.com" };
const sameSite = (a, b) => { const x = regHost(a), y = regHost(b); return !!x && (SITE_ALIAS[x] || x) === (SITE_ALIAS[y] || y); };
// Where a verified link may point after redirects: a profile address on the same site as the
// URL that was checked. Anything else (another host, a homepage, credentials) is ignored.
export function safeFinalUrl(finalUrl, rowUrl, subjects = []) {
  const x = parseUrl(finalUrl);
  return x && !x.username && !x.password && sameSite(finalUrl, rowUrl) && !isBareHome(finalUrl, subjects) ? String(finalUrl).trim() : "";
}
// Applies a result to an account row. It only ever acts on the URL that was checked, and never
// on a row a source already read: a stale check cannot take a read profile's link away.
export function applyCheck(row, check, { subjects = [] } = {}) {
  const c = readCheck(check);
  if (!c || !row) return row;
  if (c.state === "no_public_url") {
    if (row.link_kind === "verified_profile" || (c.url && row.url && c.url !== row.url)) return row;
    // A hint from the verifier is shown as given. From a stored case it is one of CrawlR's own.
    Object.assign(row, { url: "", link_kind: "none", check: c.state, hint: row.hint || c.hint || howToCheck(row.what) || NO_PAGE_HINT });
    return row;
  }
  if (row.link_kind !== "templated_unverified" || c.url !== row.url) return row;
  row.check = c.state;
  if (c.evidence) row.check_evidence = c.evidence;
  if (c.state === "verified") {
    Object.assign(row, { link_kind: "verified_profile", url: safeFinalUrl(c.final_url, row.url, subjects) || row.url });
  } else if (c.state === "not_found") {
    // The page is gone or never existed. The row stays, without a link, at the end of its group.
    Object.assign(row, { checked_url: row.url, url: "", link_kind: "none", gone: true });
  } else if (c.hint && !row.hint) row.hint = c.hint;
  return row;
}
// A templated row whose address the verifier would refuse is never sent. It says so, instead of
// sitting unchecked with no reason.
export function markUnsendable(row) {
  if (!row || row.link_kind !== "templated_unverified" || row.check) return row;
  if (String(row.url).length > MAX_CHECK_URL || String(row.key).length > MAX_CHECK_ID) Object.assign(row, { check: "unknown", check_evidence: TOO_LONG });
  else if (hasPort(row.url)) Object.assign(row, { check: "unknown", check_evidence: HAS_PORT });
  return row;
}
// What the row says about its check, for the screen and for exports.
export const checkText = (it) => (it?.check && CHECK_TEXT[it.check] ? CHECK_TEXT[it.check] + (it.check_evidence && it.check !== "verified" ? ` (${String(it.check_evidence).replace(/\.$/, "")})` : "") : "");
// Rows the link check has not looked at yet: templated account links only, sent whole.
export const pendingChecks = (items, tier) => (items || []).filter((i) => i && i.link_kind === "templated_unverified" && !i.check && !i.no_check && /^acct:/.test(i.key || "") && (!tier || i.tier === tier)
  && String(i.url).length <= MAX_CHECK_URL && String(i.key).length <= MAX_CHECK_ID && !hasPort(i.url) && ((x) => x && !x.username && !x.password)(parseUrl(i.url)))
  .map((i) => ({ id: i.key, site: String(i.what).slice(0, 120), url: String(i.url) }));
export const batches = (rows, size = CHECK_BATCH) => { const out = []; for (let i = 0; i < rows.length; i += size) out.push(rows.slice(i, i + size)); return out; };
// Merges one live answer into the stored results. Only ids that were sent are accepted.
export function mergeChecks(prev, sent, results) {
  const out = { ...readChecks(prev) };
  const asked = new Map((sent || []).map((r) => [r.id, r.url]));
  for (const r of Array.isArray(results) ? results : []) {
    if (!r || !asked.has(r.id) || !CHECK_STATES.includes(r.state) || isTransient(r)) continue;
    const c = { state: r.state, url: asked.get(r.id), final_url: clip(r.final_url, MAX_CHECK_URL), evidence: clip(r.evidence, 200), hint: clip(r.hint, 300), cached: r.cached === true };
    FRESH.add(c); out[r.id] = c;
  }
  return out;
}
// The link check as a source, for sourceTally and its card. A request that failed is a failed
// source (collected.linkCheck holds the error). It never turns a row into "not found".
export function linkCheckSource(collected) {
  const fail = collected?.linkCheck;
  if (fail && typeof fail === "object" && (fail.error || fail.error_code)) return fail;
  const checks = readChecks(collected?.linkChecks);
  const ids = Object.keys(checks);
  if (!ids.length) return null;
  return { link_check: true, total: ids.filter((k) => checks[k].state === "verified").length, results: ids.map((k) => ({ id: k, state: checks[k].state })) };
}

// When the link check may run. It makes the server fetch every URL in the group, so it starts on
// its own only for a run the user started in this session. A case from History or from a case
// file waits for a click on "Check these links", and a case file's links are named as such first:
// whoever wrote the file chose those addresses.
export function checkPolicy({ on = true, running = false, type = "username", handleOk = true, live = false, imported = false } = {}) {
  const allowed = !!on && !running && type === "username" && !!handleOk;
  return { allowed, auto: allowed && !!live && !imported, confirm: allowed && !!imported };
}
export const checkConfirmText = (n) => `CrawlR will request ${n} ${n === 1 ? "address" : "addresses"} once each to see whether the page exists. These links come from the case file you opened, not from a run on this machine, so whoever made the file chose them and the sites behind them will see a request from CrawlR.`;

// The queue behind the link check: batches go out a few at a time and never faster than the
// rate limit allows, across every group. A 429 is "wait and continue", not a failure. No DOM, no
// network: `send(rows, signal)` does the request, `sleep(ms)` waits, `now()` tells the time.
//   onBatch(rows, results)   onCancel(rows)   onFail(err, droppedRows)
//   onPause({ until, reason: "pace" | "rate_limited" })   onResume()   onIdle({ stopped })
export function makeCheckQueue({ send, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), perMinute = CHECK_PER_MINUTE, windowMs = CHECK_WINDOW_MS, parallel = CHECK_PARALLEL, size = CHECK_BATCH, onBatch, onCancel, onFail, onPause, onResume, onIdle } = {}) {
  let queue = [], calls = [], flying = new Map();
  let gen = 0, hold = 0, pausedUntil = 0, rateWaits = 0, active = false, failed = false, waiting = false, cut = false;
  function settle() {
    if (!active || failed || flying.size || queue.length) return;
    active = false; const stopped = cut; cut = false;
    onIdle?.({ stopped });
  }
  function pump() {
    if (failed || waiting) return;
    while (flying.size < parallel && queue.length) {
      const t = now();
      calls = calls.filter((c) => t - c < windowMs);
      const wait = Math.max(pausedUntil - t, calls.length >= perMinute ? calls[0] + windowMs - t : 0);
      if (wait > 0) {
        waiting = true;
        const g = gen, h = ++hold;
        onPause?.({ until: t + wait, reason: pausedUntil > t ? "rate_limited" : "pace" });
        sleep(wait).then(() => { if (g !== gen || h !== hold) return; waiting = false; onResume?.(); pump(); });
        return;
      }
      launch(queue.shift());
    }
    settle();
  }
  function fail(err, batch) {
    failed = true; active = false;
    const dropped = [...batch.rows, ...queue.flatMap((b) => b.rows)]; queue = [];
    for (const [b, ctl] of flying) { dropped.push(...b.rows); ctl.abort(); }
    flying = new Map(); gen++; waiting = false;
    onFail?.(err, dropped);
  }
  function launch(batch) {
    const g = gen, ctl = new AbortController();
    calls.push(now()); flying.set(batch, ctl);
    Promise.resolve().then(() => send(batch.rows, ctl.signal)).then((results) => {
      if (g !== gen) return;
      flying.delete(batch); rateWaits = 0;
      onBatch?.(batch.rows, Array.isArray(results) ? results : []);
      pump();
    }, (err) => {
      if (g !== gen) return;
      flying.delete(batch);
      if (err?.code === "cancelled") onCancel?.(batch.rows);
      else if (err?.status === 429 && ++rateWaits <= CHECK_RATE_WAITS) {
        // Rate limited: put the batch back and wait. Retry-After if the server sent one,
        // otherwise until the oldest call leaves the minute window.
        queue.unshift(batch);
        const t = now(), ra = Number(err.retryAfter);
        pausedUntil = t + (ra > 0 ? Math.min(ra, 300) * 1000 : calls.length ? Math.max(1000, calls[0] + windowMs - t) : windowMs);
      } else { fail(err, batch); return; }
      pump();
    });
  }
  return {
    add(tier, rows) { if (failed || !rows.length) return; for (const b of batches(rows, size)) queue.push({ tier, rows: b }); active = true; pump(); },
    // reset() drops the work but keeps the rate limit bookkeeping: the limit is per visitor, not per case.
    // Stops one group, or everything. Returns the rows that were still waiting to be sent.
    stop(tier) {
      const mine = (b) => tier === undefined || b.tier === tier;
      const waitingRows = queue.filter(mine).flatMap((b) => b.rows);
      queue = queue.filter((b) => !mine(b));
      for (const [b, ctl] of flying) if (mine(b)) ctl.abort();
      if (active) cut = true;
      if (!queue.length && waiting) { hold++; waiting = false; }
      Promise.resolve().then(() => Promise.resolve()).then(settle);
      return waitingRows;
    },
    reset() { gen++; hold++; for (const ctl of flying.values()) ctl.abort(); queue = []; flying = new Map(); rateWaits = 0; active = false; failed = false; waiting = false; cut = false; },
    // After a failure the user can ask again. The rate limit bookkeeping is kept.
    clearFailure() { failed = false; rateWaits = 0; },
    get failed() { return failed; }, get active() { return active; }, get paused() { return waiting; },
  };
}

// ---- exports ---------------------------------------------------------------------------------
// One ledger row or fact as Markdown: an unverified URL says so, a row with no URL has no link.
export function mdLink(it, text = it.what) {
  const t = String(text ?? "");
  const more = it.more?.url ? ` · [${it.more.label}](${it.more.url})` : "";
  if (!it.url || it.link_kind === "none" || !parseUrl(it.url)) return t + more;
  if (it.link_label) return `${t} · [${it.link_label}](${it.url})${more}`;
  return `[${t}](${it.url})${it.link_kind === "templated_unverified" ? ` (${UNVERIFIED_TEXT})` : ""}${more}`;
}
export const mdNote = (it) => [it.meta, checkText(it), it.hint ? `how to check: ${it.hint}` : ""].filter(Boolean).join(" · ");
