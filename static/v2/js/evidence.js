// Turns raw module responses into ranked evidence, identity clusters, leads and facts.
// Pure: no DOM, no network. Old saved runs and case files go through the same code.
//
// An evidence item: { tier, what, url, link_kind, meta, source, key, action?, hint?, check? }
//   link_kind says what the URL is worth (see links.js): a profile a source read, a templated URL
//   nothing checked, a page where the claim can be checked, or "none" (plain text, with a hint).
//   tier:
//     flag        something that changes the risk picture (breach, malware verdict, a VoIP,
//                 premium-rate, fiction or invalid number)
//     info        the answer to a lookup that is not about accounts (a hash verdict, what the
//                 numbering data says about a phone number)
//     linked      tied to the primary identity by a strong signal (a cross-link, the same avatar,
//                 a shared personal site), or the authoritative record for the target itself:
//                 GitHub's API answer for the searched handle, a registration check for the
//                 searched email
//     matches     a profile was read and its name fits the primary identity, or it carries no
//                 name that conflicts. Consistent, not proven.
//     different   a profile was read and the name on it conflicts with the primary identity:
//                 another person who uses the same handle
//     unverified  a tool reported the handle and nothing was read. Many sites answer "yes" to
//                 any name, so these are leads to check, not facts.
//     lead        a handle, address, domain or link found on a profile. Somewhere to look next,
//                 never a finding about the target.
//     hosts       hostnames on an email's domain. Inventory, not a finding about the person.
//     adult       an adult or dating site, only in a case that had that mode on (see adult.js).
//                 Existence and text only. These rows are built apart from every other account:
//                 they are never linked, matched, clustered, turned into facts or leads, or counted.
//     similar     a handle close to the searched one (see similar.js). Nothing is checked until
//                 the investigator clicks "Check" on one. Never a finding, a lead or a count.
//                 A profile read for a similar handle becomes an account row of the case only
//                 when the investigator adds it AND it still lines up. AN ADDED PROFILE IS A ROW,
//                 NEVER PART OF THE IDENTITY: clusters, the primary's label, its facts and picture
//                 and every other row's tier are computed from the case's own profiles alone.
//                 when the investigator adds it AND the identity rules say it lines up.
//     noise       sites known to answer yes to everything, collapsed by default
//     notable, people, handles, websearch
//                 a name case (see names.js): the public figure with that name, the candidates
//                 the directories returned, handles built from the name, and outbound searches.
//                 A phone case has the outbound searches too (see phone.js). None of them is a
//                 finding, a fact, a profile or a cluster member.
//   The link check never moves a row to another tier: it changes what the link is worth.
//   A source that FAILED contributes nothing here; failures are reported separately so an
//   error is never read as "not found".
//   key: stable id used for the checkbox state and the run diff, e.g. "acct:github"
//
// A fact: { k, v, source, url?, link_kind }  (name, location, employer…), shown in "What we know".
// Facts belong to an identity cluster, so one person's name is never shown beside another's.

import { cardSnippet, safeThumb } from "./present.js";
import { classifyLink, sealLink, sealFact, readChecks, applyCheck, markUnsendable, evidenceUrl, REGISTERED_HINT, BREACH_HINT, REDDIT_HINT, REDDIT_HIDDEN, TAKEN_TEXT, TAKEN_GENERIC, TAKEN_NOTE, mdLink, mdNote } from "./links.js";
import { evaluateSimilar, addedProfiles, similarItems, similarBrief, similarBase, similarHandles, fromFile, SIMILAR_GROUP, SIMILAR_BLURB, SIMILAR_SOURCE } from "./similar.js";
import { TYPE_LABEL } from "./core.js";
import { clusterIdentities, standing, meaningfulName, looksBoilerplate, linkParts, urlsIn } from "./identity.js";
import { NAME_TIERS, isNameTier, nameItems, nameForAi, nameMarkdownHead } from "./names.js";
import { PHONE_TIERS, phoneView, phoneItems, phoneFacts, phoneForAi } from "./phone.js";
import { withoutAdult, adultRows, adultOn, adultAllowed, adultForAi, adultFound, adultMarkdown, blockForAi, reportForExport, adultHost, handleOf, ADULT_GROUP, ADULT_NOTICE, ADULT_SOURCE } from "./adult.js";
import { scanProfiles } from "./minorscan.js";

const norm = (s) => String(s ?? "").trim().toLowerCase();

// Different tools name the same site differently ("Twitter" vs "X", "Steam Community" vs "Steam").
// Accounts are merged on the canonical name so one site is one row, with every source that saw it.
const SITE_ALIAS = {
  "twitter": "x", "x (twitter)": "x", "x / twitter": "x", "x/twitter": "x", "twitter.com": "x", "x.com": "x",
  "steam community": "steam", "steamcommunity": "steam", "threads.net": "threads", "instagram.com": "instagram",
  "facebook.com": "facebook", "youtube channel": "youtube", "reddit.com": "reddit", "github.com": "github",
  "tiktok.com": "tiktok", "twitch.tv": "twitch", "bsky": "bluesky", "bsky.app": "bluesky", "hugging face": "huggingface",
};
const SITE_DISPLAY = { x: "X (Twitter)", steam: "Steam", huggingface: "Hugging Face", threads: "Threads", gravatar: "Gravatar" };
export const canonSite = (s) => { const n = norm(s).replace(/\s*\((?!twitter).*\)$/, ""); return SITE_ALIAS[n] || n; };
const failed = (d) => !!(d && (d.error || d.error_code));
const fmtNum = (n) => Number(n ?? 0).toLocaleString("en-US");

export const TIER_ORDER = ["flag", "info", "notable", "people", "handles", "websearch", "linked", "matches", "different", "unverified", "adult", "lead", "similar", "hosts", "noise"];
const TIER_RANK = Object.fromEntries(TIER_ORDER.map((t, i) => [t, i]));
// Leads and host inventory are not findings about the target, so no count includes them. Adult
// and dating site rows are existence checks kept apart from the findings, with their own count.
// A name case has candidates, suggestions and outbound searches, and none of them is a finding.
// Similar handles are suggestions: unchecked, or checked and not part of the case.
// nofind: a row that says a site could not be checked (Reddit blocked the platform check and no
// tool reported the handle) or that a sign-up check called the handle taken. Neither found
// anything, so neither is a finding; they still sit in Unverified and on its tile.
export const isFinding = (it) => it.tier !== "lead" && it.tier !== "similar" && it.tier !== "hosts" && it.tier !== "adult" && !isNameTier(it.tier) && !it.nofind;
const ACCOUNT_TIERS = ["linked", "matches", "different", "unverified"];
// Sites the platform check asks directly, where its answer stands in for a username tool's.
const PC_OWN = new Set(["reddit", "discord"]);

// ---- email ---------------------------------------------------------------------------
// A mail provider's own hosts say nothing about one of its users, so the domain harvest is
// skipped for these.
const FREE_MAIL = /^(gmail\.com|googlemail\.com|outlook\.com|hotmail\.com|yahoo\.com|icloud\.com|proton\.me|protonmail\.com|aol\.com|live\.com|me\.com|mail\.com|gmx\.[a-z.]+|yandex\.[a-z.]+)$/i;
export const isFreeMail = (domain) => FREE_MAIL.test(String(domain ?? "").trim());
export function emailParts(email) {
  const [local = "", domain = ""] = String(email ?? "").trim().split("@");
  return { local, handle: local.replace(/\+.*$/, ""), domain: domain.toLowerCase() };
}
const HANDLE_OK = /^[A-Za-z0-9._-]{1,64}$/;

// Which sources run for a target type, in order. Investigate uses this list to run them,
// so the test of the email flow and the app cannot drift apart.
// opts.adult: the case-level switch. The adult pass is planned only for a username whose handle
// passes the first stage of the minor guard; with the switch off it is never part of a run.
// "adult" is always last: it starts after the other sources, and only if the check of the
// profiles they found comes back clean (contentCheck below, adultRequests in adult.js).
export function sourcePlan(type, target, { adult = false } = {}) {
  if (type === "hash") return ["hash"];
  if (type === "phone") return ["phone"];
  if (type === "name") return ["namesearch"];
  if (type === "email") {
    const { domain } = emailParts(target);
    // No Sherlock, Maigret or Platform check: the part before the @ is only a lead.
    return ["holehe", "hibp", "gravatar", ...(isFreeMail(domain) ? [] : ["harvester"]), "hunter"];
  }
  return ["sherlock", "maigret", "github", "platform", ...(adultOn(type, target, adult) ? ["adult"] : [])];
}

// ---- the profile text the minor guard reads -----------------------------------------------------
// Every display name and bio a source returned for this handle in the ordinary run, with the
// site it was read on. The same fields the server keeps for its own copy of the check
// (core/profile_record.py), in the same order: Maigret, GitHub, the platform check (Reddit's
// record included), profile enrichment, then Gravatar and a profile scrape when the case has
// them. Sites known to answer for any name are left out, and nothing adult is ever read: the
// case goes through withoutAdult first. Profiles the identity grouping calls a different person
// are included on purpose: an adult-site account under this handle could be theirs, and the
// message names the source so the investigator can judge. Addresses and handles are not scanned,
// and a similar handle's probe is not part of this case.
const BIRTH_KEYS = ["birthday", "birth_date", "birthdate", "born", "dob", "date_of_birth", "age"];
export function profileTexts(collected) {
  const c = withoutAdult(collected), out = [];
  const text = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
  const put = (source, url, name, bio, extra) => {
    const e = { source: text(String(source ?? ""), 80), url: text(url, 600), name: text(name, 200), bio: text(bio, 600) };
    if (adultHost(e.url)) return;
    for (const k of BIRTH_KEYS) { const v = extra?.[k]; if (typeof v === "string" || typeof v === "number") { const t = String(v).slice(0, 40); if (t) e[k] = t; } }
    if (Object.entries(e).some(([k, v]) => k !== "source" && k !== "url" && v)) out.push(e);
  };
  const rows = (d, list = "results") => (d && !failed(d) && Array.isArray(d[list]) ? d[list].filter((r) => r && typeof r === "object") : []);
  for (const r of rows(c.maigret)) if (r.confidence !== "false_positive" && r.profile && typeof r.profile === "object") put(r.site || r.name, r.url, r.profile.name, r.profile.bio, r.profile);
  if (c.github?.found && !failed(c.github)) put("GitHub", c.github.profile_url, c.github.name, c.github.bio);
  for (const r of rows(c.platformCheck)) if (r.state === "found") put(r.platform, r.url, r.display_name, r.bio, r);
  for (const e of rows(c.enricher, "profiles")) put(e.platform, e.url, e.display_name, e.bio, e);
  if (c.gravatar?.found && !failed(c.gravatar)) put("Gravatar", c.gravatar.profile_url, c.gravatar.name || c.gravatar.display_name, c.gravatar.about || c.gravatar.bio);
  for (const r of rows(c.profileScrape)) if (!r.error) put(r.site || "Profile", r.url, r.display_name, r.bio, r);
  return out;
}
// Stage 2 of the minor guard, for a case whose ordinary sources are in:
// { blocked, kind, signal: { strength, kind, source, snippet, url } | null, signals, soft, read }.
// today is a parameter so the tests can pin it.
export const contentCheck = (collected, target, type = "username", today = new Date()) => scanProfiles(type === "username" ? profileTexts(collected) : [], handleOf(target), today);

// ---- breaches ------------------------------------------------------------------------
// Accepts the old shape (a list of names) and the new one (objects with a date and data classes).
export function breachList(hibp) {
  const rows = (hibp?.breaches || []).map((b) => (typeof b === "string" ? { name: b } : b && typeof b === "object" ? b : null)).filter((b) => b && b.name).map((b, i) => {
    const date = /^\d{4}(-\d{2}(-\d{2})?)?$/.test(String(b.date || "")) ? String(b.date) : "";
    const year = Number.isInteger(b.year) ? b.year : date ? Number(date.slice(0, 4)) : null;
    return { name: String(b.name), date, year, data_classes: Array.isArray(b.data_classes) ? b.data_classes.map(String) : [], records: Number.isFinite(b.records) ? b.records : null, verified: b.verified ?? null, sensitive: b.sensitive ?? null, domain: String(b.domain || ""), url: String(b.url || ""), _i: i };
  });
  // Newest first, undated last, otherwise the order the source gave.
  rows.sort((a, b) => (b.date || (b.year ? String(b.year) : "")).localeCompare(a.date || (a.year ? String(a.year) : "")) || a._i - b._i);
  // One row per breach name, so the ledger, the card and the brief always count the same.
  const seen = new Set();
  return rows.filter((b) => !seen.has(norm(b.name)) && seen.add(norm(b.name))).map(({ _i, ...b }) => b);
}
export function breachMeta(b) {
  const classes = b.data_classes.slice(0, 4).join(", ") + (b.data_classes.length > 4 ? ` and ${b.data_classes.length - 4} more` : "");
  return [b.year ? String(b.year) : "", classes].filter(Boolean).join(" · ") || "credential exposure";
}

// ---- hash ----------------------------------------------------------------------------
// The EICAR test file. New responses mark it themselves (verdict TEST_FILE); this list is only
// for runs saved before that, which called it malware.
const EICAR = new Set(["44d88612fea8a8f36de82e1278abb02f", "3395856ce81f2b7382dee72602f798b642f14140", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"]);
export const TEST_FILE_TEXT = "harmless by design, every scanner flags it";
// One reading of a hash response, old shape or new.
export function hashView(hs) {
  if (!hs || failed(hs)) return null;
  const legacy = !("family" in hs) && !("community_tags" in hs) && !("known_test_file" in hs);
  const test = hs.known_test_file || (String(hs.verdict || "").toUpperCase() === "TEST_FILE" || EICAR.has(norm(hs.hash)) ? { name: "EICAR antivirus test file", note: "" } : null);
  const raw = String(hs.verdict || "UNKNOWN").toUpperCase();
  const det = hs.detection && Number.isFinite(hs.detection.positives) && Number.isFinite(hs.detection.total) ? hs.detection : null;
  return {
    verdict: test ? "TEST_FILE" : ["MALICIOUS", "CLEAN"].includes(raw) ? raw : "UNKNOWN",
    testFile: test ? { name: String(test.name || "EICAR antivirus test file"), note: String(test.note || "") } : null,
    // Only a family a structured source names goes in a headline. Old responses mixed in free text.
    family: legacy ? "" : String(hs.family || ""), familySources: (hs.family_sources || []).map(String),
    tags: (legacy ? hs.malware_families || [] : hs.community_tags || []).map(String),
    families: legacy ? [] : (hs.malware_families || []).map(String),
    detection: det, fileType: String(hs.file_type || hs.malware_bazaar?.file_type || ""), fileName: String(hs.file_name || hs.malware_bazaar?.file_name || hs.circl?.file_name || ""),
    fileSize: hs.file_size ?? hs.circl?.file_size ?? null, firstSeen: String(hs.first_seen || hs.malware_bazaar?.first_seen || ""), lastSeen: String(hs.last_seen || ""), legacy,
  };
}
// Which of the four hash sources answered, and which could not be asked.
export function hashCoverage(hs) {
  const failedList = (hs?.failed_sources || []).map(String);
  const answered = ["malware_bazaar", "circl", "alienvault", "threatfox"].filter((k) => hs?.[k] && typeof hs[k] === "object" && (hs[k].found === true || hs[k].found === false) && !hs[k].error && !hs[k].error_code).length;
  return { answered, failed: failedList, total: answered + failedList.length };
}
export const detectionText = (v) => (v.detection ? `${fmtNum(v.detection.positives)} of ${fmtNum(v.detection.total)} engines${v.detection.source ? ` (${v.detection.source})` : ""}` : "no detection ratio from keyless sources");

// ---- profiles ------------------------------------------------------------------------
// Every profile a source actually read, one per site, with the facts and leads found on it.
// Rows from adult and dating sites are removed first: they are never profiles.
// The case's own profiles only. A profile added from a similar handle is never one of them.
export function collectProfiles(collected, target, type = inferType(collected, target)) {
  const c = withoutAdult(collected);
  const searched = type === "email" ? "" : String(target ?? "").trim().replace(/^@/, "");
  const map = new Map();
  const put = (site, source, p) => {
    const id = `acct:${canonSite(site)}`;
    if (id === "acct:") return null;
    let cur = map.get(id);
    if (!cur) { cur = { id, site: SITE_DISPLAY[canonSite(site)] || String(site), url: "", handle: searched, name: "", location: "", bio: "", image: "", links: [], websites: [], anchor: "", sources: [], facts: [], leads: [], evidence: "", created: "", note: "", repos: null, followers: null, karma: null, thumb: "" }; map.set(id, cur); }
    if (!cur.sources.includes(source)) cur.sources.push(source);
    for (const k of ["url", "location", "bio", "image", "anchor", "evidence", "created", "note"]) if (!cur[k] && p[k]) cur[k] = String(p[k]);
    // Counts a source returned for this profile. Shown on the card as they came, never estimated.
    for (const k of ["repos", "followers", "karma"]) if (cur[k] === null && Number.isFinite(p[k]) && p[k] >= 0) cur[k] = p[k];
    if (p.handle) cur.handle = String(p.handle);
    // Keep the first name that says something; a handle echoed back is not a name.
    if (p.name && (!cur.name || (!meaningfulName(cur.name, [cur.handle, searched]) && meaningfulName(p.name, [cur.handle, searched])))) cur.name = String(p.name).trim();
    for (const l of p.links || []) if (l && !cur.links.includes(String(l))) cur.links.push(String(l));
    for (const l of p.websites || []) if (l && !cur.websites.includes(String(l))) cur.websites.push(String(l));
    return cur;
  };
  // A fact links to the page it was read from: evidence, never a claim about who owns the page.
  const secrets = [type === "email" ? target : "", searched].filter((x) => String(x || "").length > 2);
  const fact = (p, k, v, source, url) => { if (p && v !== undefined && v !== null && String(v).trim()) p.facts.push(sealFact({ k, v: String(v), source, url }, { subjects: [searched], secrets })); };
  const lead = (p, kind, value, from) => { if (p && value && String(value).trim()) p.leads.push({ kind, value: String(value).trim(), from }); };
  const nameFact = (p, label, name, source, url) => { if (meaningfulName(name, [p?.handle, searched])) fact(p, label, name, source, url); };
  const cleanBio = (bio, flagged) => (flagged || !bio || looksBoilerplate(bio) ? "" : String(bio));

  // GitHub's API answer for the searched handle: the anchor for a username case.
  const gh = c.github;
  if (gh?.found && !failed(gh)) {
    const tw = String(gh.twitter_username || "").replace(/^@/, "");
    const p = put("GitHub", "GitHub", { url: gh.profile_url, name: gh.name, location: gh.location, bio: gh.bio, image: gh.avatar_url, created: gh.created_at, repos: gh.public_repos, followers: gh.followers, anchor: type === "email" ? "" : "github", links: [tw && `https://x.com/${tw}`].filter(Boolean), websites: [gh.blog].filter(Boolean) });
    nameFact(p, "Name", gh.name, "GitHub", gh.profile_url);
    fact(p, "Location", gh.location, "GitHub", gh.profile_url);
    fact(p, "Employer", gh.company, "GitHub", gh.profile_url);
    fact(p, "Email", gh.email, "GitHub", gh.profile_url);
    fact(p, "Website", gh.blog, "GitHub", gh.blog);
    fact(p, "Bio", gh.bio, "GitHub", gh.profile_url);
    fact(p, "Active since", gh.created_at ? String(gh.created_at).slice(0, 10) : "", "GitHub", gh.profile_url);
    lead(p, "url", gh.blog, "GitHub website field");
    lead(p, "handle", tw, "GitHub Twitter field");
    lead(p, "email", gh.email, "GitHub public email");
    const dp = c.githubDeep;
    if (dp && !failed(dp) && dp.found !== false) {
      const ok = (k) => !dp.sections || !dp.sections[k] || dp.sections[k] === "ok";
      if (ok("orgs")) fact(p, "Organisations", (dp.orgs || []).map((o) => o.login).filter(Boolean).slice(0, 12).join(", "), "GitHub details", gh.profile_url);
      // The top_repos section also covers languages.
      if (ok("top_repos")) fact(p, "Languages", (dp.languages || []).slice(0, 8).join(", "), "GitHub details", gh.profile_url);
      for (const e of ok("commit_emails") ? (dp.commit_emails || []).slice(0, 5) : []) { fact(p, "Commit email", e.email, "GitHub details", gh.profile_url); lead(p, "email", e.email, `GitHub commit${e.repo ? ` in ${e.repo}` : ""}`); }
      for (const k of dp.keys?.gpg || []) for (const e of k.emails || []) lead(p, "email", e, "GitHub GPG key");
      for (const s of dp.social_accounts || []) if (s?.url) { p.links.push(String(s.url)); lead(p, "url", s.url, "GitHub social accounts"); }
      // README links are leads only. A README links to documentation, projects and other people,
      // so it must never tie another profile to this one.
      for (const u of dp.readme_links || []) lead(p, "url", u, "GitHub profile README");
    }
  }

  // Gravatar's record for the searched email: the anchor for an email case.
  const gr = c.gravatar;
  if (gr?.found && !failed(gr)) {
    const slug = String(gr.profile_url || "").replace(/\/+$/, "").split("/").pop() || "";
    // Gravatar's display name is often the account's username, which is a handle and not a name.
    const display = norm(gr.display_name) === norm(slug) ? "" : gr.display_name;
    const p = put("Gravatar", "Gravatar", { url: gr.profile_url, handle: slug, name: gr.name || display, location: gr.location, image: gr.avatar_url, anchor: type === "email" ? "gravatar" : "" });
    nameFact(p, "Name", gr.name || display, "Gravatar", gr.profile_url);
    fact(p, "Location", gr.location, "Gravatar", gr.profile_url);
    if (slug && norm(slug) !== norm(searched)) lead(p, "handle", slug, "Gravatar username");
  }

  // Maigret parsed a real profile. Sites known to answer for any name are left out.
  for (const r of c.maigret && !failed(c.maigret) ? c.maigret.results || [] : []) {
    if (!r.verified || r.confidence === "false_positive") continue;
    const pr = r.profile || {};
    const bio = cleanBio(pr.bio, pr.bio_boilerplate || r.bio_boilerplate);
    const p = put(r.site || r.name || "", "Maigret", { url: r.url, name: pr.name, location: pr.location, bio, image: pr.image, created: pr.created_at, followers: typeof pr.followers === "number" ? pr.followers : null, links: pr.links || [] });
    nameFact(p, "Name", pr.name, r.site, r.url);
    fact(p, "Location", pr.location, r.site, r.url);
    fact(p, "Bio", bio.slice(0, 160), r.site, r.url);
    for (const u of urlsIn(bio)) lead(p, "url", u, `${r.site} bio`);
    for (const u of pr.links || []) lead(p, "url", u, `${r.site} profile`);
  }

  // The enricher read a display name or a bio from the page.
  for (const e of c.enricher && !failed(c.enricher) ? c.enricher.profiles || [] : []) {
    if (!e.platform || !(e.display_name || e.bio || e.bio_boilerplate)) continue;
    const bio = cleanBio(e.bio, e.bio_boilerplate);
    const p = put(e.platform, "Profile enrichment", { url: e.url, name: e.display_name, bio });
    nameFact(p, "Name", e.display_name, e.platform, e.url);
    fact(p, "Bio", bio.slice(0, 160), e.platform, e.url);
    for (const u of urlsIn(bio)) lead(p, "url", u, `${e.platform} bio`);
  }

  // Deep Dive scraped the page (active, on request).
  for (const s of c.profileScrape && !failed(c.profileScrape) ? (c.profileScrape.results || []).filter((r) => !r.error) : []) {
    const bio = cleanBio(s.bio, s.bio_boilerplate);
    const p = put(s.site || "", "Profile scrape", { url: s.url, name: s.display_name, location: s.location, bio, links: s.links || [] });
    nameFact(p, "Name", s.display_name, s.site || "Profile", s.url);
    fact(p, "Location", s.location, s.site || "Profile", s.url);
    for (const e of s.emails || []) { fact(p, "Email", e, s.site || "Profile", s.url); lead(p, "email", e, `${s.site || "profile"} page`); }
    for (const u of s.links || []) lead(p, "url", u, `${s.site || "profile"} page`);
  }

  // Platform check, new shape: "found" means a marker on the page matched, so a profile was read.
  for (const r of c.platformCheck && !failed(c.platformCheck) ? c.platformCheck.results || [] : []) {
    if (r.state !== "found") continue;
    // Reddit's record carries more than a name: a bio, the day the account was made, karma and a picture.
    const bio = cleanBio(r.bio, false);
    const p = put(r.platform, "Platform check", { url: r.url, name: r.display_name, evidence: r.evidence, bio, created: r.created, karma: r.karma, image: r.avatar_url, note: r.note === "suspended" ? "suspended" : "" });
    nameFact(p, "Name", r.display_name, r.platform, r.url);
    fact(p, "Bio", bio.slice(0, 160), r.platform, r.url);
    fact(p, "Active since", /^\d{4}-\d{2}-\d{2}/.test(String(r.created || "")) ? String(r.created).slice(0, 10) : "", r.platform, r.url);
    for (const u of urlsIn(bio)) lead(p, "url", u, `${r.platform} bio`);
  }

  // Avatar hashes, when the comparison ran.
  const av = c.avatarHash;
  if (av && !failed(av)) for (const r of av.results || []) { const p = map.get(r.id); if (p && r.hash && !r.error) { p.avatarHash = String(r.hash); p.avatarDefault = !!r.default; if (!r.default) p.thumb = safeThumb(r.thumb); } }
  return [...map.values()];
}
// The facts of a profile added from a similar handle. The source names the handle it is under.
function withSimilarFacts(added, searched, secrets) {
  for (const p of added) {
    const src = `${p.site} (${p.handle})`;
    const fact = (k, v) => { if (v && String(v).trim()) p.facts.push(sealFact({ k, v: String(v), source: src, url: p.url }, { subjects: [searched, p.handle], secrets })); };
    if (meaningfulName(p.name, [p.handle, searched])) fact("Name", p.name);
    fact("Location", p.location);
    fact("Bio", looksBoilerplate(p.bio) ? "" : String(p.bio || "").slice(0, 160));
  }
  return added;
}

// Images to compare, one per read profile. Sent once to /api/recon/avatar-hash.
export function avatarImages(c, target, type) {
  return collectProfiles(c, target, type).filter((p) => /^https:\/\//i.test(p.image)).map((p) => ({ id: p.id, url: p.image.slice(0, 600) })).slice(0, 30);
}

const inferType = (c, target) => (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(target ?? "").trim()) ? "email" : c?.hash ? "hash" : c?.phone ? "phone" : c?.nameSearch || c?.nameResult ? "name" : "username");
const dedupeFacts = (facts) => { const out = []; for (const f of facts) if (!out.some((x) => x.k === f.k && norm(x.v) === norm(f.v))) out.push(f); return out; };

// ---- leads ---------------------------------------------------------------------------
// Handles, addresses, domains and links found on profiles. One hop, started by a click.
function buildLeads(c, target, type, profiles, rel, accountUrls) {
  const out = new Map();
  const searched = norm(type === "email" ? emailParts(target).handle : String(target ?? "").replace(/^@/, ""));
  const add = (kind, value, from, source, tied = true) => {
    const k = `lead:${kind}:${norm(value)}`;
    const prev = out.get(k);
    if (prev) { if (!prev.from.includes(from)) prev.from.push(from); if (!prev.sources.includes(source)) prev.sources.push(source); prev.tied ||= tied; return; }
    out.set(k, { kind, value, from: [from], sources: [source], tied, key: k });
  };
  for (const p of profiles) {
    const r = rel.get(p.id);
    if (!r || r.tier === "different") continue;
    const tied = r.tier === "linked" || r.inPrimary;
    for (const l of p.leads) {
      if (l.kind === "handle") { const hv = l.value.replace(/^@/, ""); if (HANDLE_OK.test(hv) && norm(hv) !== searched) add("handle", hv, l.from, p.site, tied); }
      else if (l.kind === "email") { if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(l.value) && norm(l.value) !== norm(target)) add("email", l.value.toLowerCase(), l.from, p.site, tied); }
      else {
        const parts = linkParts(l.value);
        if (!parts || accountUrls.has(parts.key)) continue;
        if (!parts.platform) add("domain", parts.host, l.from, p.site, tied);
        if (parts.platform || parts.path) add("url", /^https?:/i.test(l.value) ? l.value : `https://${l.value}`, l.from, p.site, tied);
      }
    }
  }
  if (type === "email") {
    const { handle, domain } = emailParts(target);
    if (HANDLE_OK.test(handle) && !handle.startsWith("-")) add("handle", handle, "the part before the @", "Target");
    if (domain && !isFreeMail(domain)) add("domain", domain, "the email's domain", "Target");
  }
  const WORD = { handle: "handle", email: "email address", domain: "domain", url: "link" };
  const ORDER = { handle: 0, email: 1, domain: 2, url: 3 };
  return [...out.values()].sort((a, b) => ORDER[a.kind] - ORDER[b.kind] || a.value.localeCompare(b.value)).map((l) => ({
    tier: "lead", what: l.kind === "url" ? l.value.replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "") : l.value,
    url: l.kind === "url" ? l.value : l.kind === "domain" ? `https://${l.value}` : "",
    meta: `${WORD[l.kind]} · ${l.from.join(", ")}${l.tied ? "" : " · on a profile not tied to the target"}`,
    source: l.sources.join(", "), key: l.key, lead: { kind: l.kind, value: l.value },
    action: l.kind === "handle" || l.kind === "email" ? { label: "Investigate this", pivot: "investigate", value: l.value } : l.kind === "domain" ? { label: "Open in Recon", pivot: "recon", value: l.value } : null,
  // A lead's link is the lead itself: the domain, or the link as it was found on the profile.
  })).map((l) => sealLink(l, { subjects: [l.lead.value], secrets: [type === "email" ? target : "", searched].filter((x) => String(x || "").length > 2) }));
}

// ---- the ledger ----------------------------------------------------------------------
export function buildEvidence(collected, target, typeArg) {
  // Everything below reads the case without its adult and dating site rows. Those are built
  // on their own (adultRows) and only for a case that had the mode on.
  const c = withoutAdult(collected);
  const type = typeArg || inferType(c, target);
  const person = type === "username" || type === "email";
  const items = [];
  const general = [];                     // facts about the target that belong to no person
  const seen = new Set();
  const add = (it) => {
    const dedupe = it.url ? norm(it.url) : `${it.source}:${norm(it.what)}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);
    items.push(it);
  };
  const searchedHandle = type === "email" ? "" : String(target ?? "").trim().replace(/^@/, "");
  // An email or a username never goes into a third-party query string.
  const secrets = person ? [type === "email" ? target : "", searchedHandle].filter((x) => String(x || "").length > 2) : [];
  const fact = (k, v, source, url) => { if (v) general.push(sealFact({ k, v: String(v), source, url }, { secrets })); };

  // One row per site across every source that names it.
  const accounts = new Map();
  const addAccount = (site, { source, url = "", kind, meta = "" }) => {
    const cs = canonSite(site);
    if (!cs) return;
    let row = accounts.get(cs);
    if (!row) { row = { what: SITE_DISPLAY[cs] || String(site), url: "", key: `acct:${cs}`, sources: [], kinds: new Set(), notes: [] }; accounts.set(cs, row); items.push(row); }
    if (!row.sources.includes(source)) row.sources.push(source);
    if (!row.url && url) row.url = url;
    // The URL a source actually read. A templated URL from another tool never replaces it.
    if (kind === "read" && !row.readUrl && url) row.readUrl = url;
    row.kinds.add(kind);
    if (meta && !row.notes.some((n) => n.kind === kind && n.meta === meta)) row.notes.push({ kind, meta });
  };

  // Reddit and Discord: the platform check asks each site directly, so its state replaces a
  // username tool's unread report of the same site, and the tool's homepage URL is dropped.
  // The tool is still named on the row, unless the platform check found the handle is not there.
  const pcRows = c.platformCheck && !failed(c.platformCheck) ? (c.platformCheck.results || []).filter((r) => r && typeof r.state === "string") : [];
  const pcOwn = new Map(pcRows.filter((r) => PC_OWN.has(canonSite(r.platform))).map((r) => [canonSite(r.platform), r.state]));
  const pcSoft = new Map(pcRows.filter((r) => PC_OWN.has(canonSite(r.platform)) && r.state === "not_found" && r.hidden_possible === true).map((r) => [canonSite(r.platform), String(r.url || "")]));
  const cited = [];
  // --- username enumeration: sherlock + maigret ---------------------------------------
  for (const [src, d] of [["Sherlock", c.sherlock], ["Maigret", c.maigret]]) {
    if (!d || failed(d)) continue;
    for (const r of d.results || []) {
      const noisy = r.confidence === "false_positive";
      const cs0 = canonSite(r.site || r.name || "");
      // Reddit's API answers "not found" for a hidden or shadow-banned account too, so a tool's
      // report of Reddit is kept, unverified, with that said.
      if (pcOwn.get(cs0) === "not_found" && pcSoft.has(cs0) && !r.verified) { addAccount(r.site || r.name || "", { source: src, url: pcSoft.get(cs0), kind: "reported", meta: REDDIT_HIDDEN }); cited.push([cs0, src]); continue; }
      if (pcOwn.has(cs0) && !r.verified) { if (pcOwn.get(cs0) !== "not_found") cited.push([cs0, src]); continue; }
      addAccount(r.site || r.name || "", { source: src, url: r.url, kind: noisy ? "noise" : r.verified ? "read" : "reported", meta: noisy || r.verified ? "" : r.category || "" });
    }
  }
  // --- registration checks for the searched email --------------------------------------
  for (const r of c.holehe && !failed(c.holehe) ? c.holehe.results || [] : []) {
    addAccount(r.site || r.domain, { source: "Holehe", url: r.domain ? `https://${r.domain}` : "", kind: "registered" });
  }
  // --- platform check: only "found" read a profile -------------------------------------
  for (const r of c.platformCheck && !failed(c.platformCheck) ? c.platformCheck.results || [] : []) {
    const why = r.evidence ? ` (${String(r.evidence).replace(/\.$/, "")})` : "";
    if (r.state === "found") addAccount(r.platform, { source: "Platform check", url: r.url, kind: "read" });
    // A sign-up check said the handle is in use. Nothing was read and there is no page to open.
    else if (r.state === "taken") addAccount(r.platform, { source: "Platform check", url: "", kind: "taken" });
    else if (r.state === "blocked") addAccount(r.platform, { source: "Platform check", url: r.url, kind: "reported", meta: `Blocked by site${why}` });
    else if (r.state === "unknown") addAccount(r.platform, { source: "Platform check", url: r.url, kind: "reported", meta: `Could not tell${why}` });
    // Old shape: a bare 200 on the profile URL, which these sites often give for any name.
    else if (r.state === undefined && r.found === true) addAccount(r.platform, { source: "Platform check", url: r.url, kind: "reported", meta: "profile URL answered, check by hand" });
    // not_found adds nothing.
  }
  for (const [cs, src] of cited) { const row = accounts.get(cs); if (row) { row.pcOwn = pcOwn.get(cs); if (!row.sources.includes(src)) row.sources.push(src); } }
  for (const [cs, st] of pcOwn) { const row = accounts.get(cs); if (row) row.pcOwn = st; }
  const gh = c.github;
  if (gh?.found && !failed(gh)) addAccount("GitHub", { source: "GitHub", url: gh.profile_url, kind: "read" });
  const gr = c.gravatar;
  if (gr?.found && !failed(gr)) addAccount("Gravatar", { source: "Gravatar", url: gr.profile_url, kind: "read" });
  for (const p of c.enricher && !failed(c.enricher) ? c.enricher.profiles || [] : []) if (p.platform && (p.display_name || p.bio || p.bio_boilerplate)) addAccount(p.platform, { source: "Profile enrichment", url: p.url, kind: "read" });

  // --- identity: cluster the read profiles, then rank each account against the primary --
  const searched = type === "email" ? "" : String(target ?? "").replace(/^@/, "");
  const ownProfiles = person ? collectProfiles(c, target, type, { similar: false }).filter((p) => !(accounts.get(p.id.slice(5))?.kinds.has("noise") && !accounts.get(p.id.slice(5)).kinds.has("read"))) : [];
  // The identity is built from the case's own profiles and nothing else.
  const profiles = ownProfiles;
  const result = clusterIdentities(profiles, { handle: searched });
  const primary = result.clusters.find((x) => x.primary) || null;
  const byId = new Map(profiles.map((p) => [p.id, p]));
  const clusterOf = (id) => result.clusters.find((x) => x.id === result.byProfile[id]) || null;
  const rel = new Map();
  for (const p of profiles) { const s = standing(p, result, { handle: searched }); rel.set(p.id, { ...s, inPrimary: !!primary && result.byProfile[p.id] === primary.id }); }
  // --- similar handles: what was checked, and the profiles the investigator added ----------
  // A profile is part of the case only when it was added and still lines up with the case's own
  // profiles, evaluated here from the data: "added" in a stored case is never taken on trust.
  // It is then a row and nothing more. It joins no cluster, changes no label, fact, picture or
  // tier, and is placed by its own line-up: Linked for a picture or a link, Exists (matches) for
  // a full name. Its facts are kept apart (see `added` in the result).
  const simBase = similarBase(target, type);
  const primaryName = primary?.named ? primary.label : "";
  const evaluated = person && simBase ? evaluateSimilar(c.similar, ownProfiles, { handle: searched, own: simBase, name: primaryName }) : {};
  const addedList = withSimilarFacts(addedProfiles(evaluated), searched, secrets);
  for (const p of addedList) {
    const row = { what: p.site, url: p.url, key: p.id, sources: [SIMILAR_SOURCE], kinds: new Set(["read"]), notes: [], readUrl: p.url, similar: p.similar };
    accounts.set(p.id.slice(5), row); items.push(row);
    byId.set(p.id, p); rel.set(p.id, { tier: p.similar.tier, why: "", inPrimary: false });
  }

  const checks = readChecks(c.linkChecks);
  for (const row of accounts.values()) {
    const p = byId.get(row.key), r = rel.get(row.key);
    const reported = row.notes.filter((n) => n.kind === "reported").map((n) => n.meta);
    if (row.kinds.has("registered")) {
      row.tier = "linked";
      row.meta = ["registered with this email", p?.anchor === "gravatar" ? "Gravatar's record for this email" : ""].filter(Boolean).join(" · ");
    } else if (p && r && row.kinds.has("read")) {
      row.tier = r.tier;
      const named = meaningfulName(p.name, [p.handle, searched]);
      const cl = clusterOf(p.id);
      if (p.anchor === "github") row.meta = ["GitHub's own record for this handle", named ? `name on profile: ${p.name}` : "", `${fmtNum(gh.public_repos)} repos`, `${fmtNum(gh.followers)} followers`].filter(Boolean).join(" · ");
      else if (p.anchor === "gravatar") row.meta = ["Gravatar's record for this email", named ? `name on profile: ${p.name}` : "", p.location].filter(Boolean).join(" · ");
      else row.meta = [row.similar ? `under the handle ${row.similar.variant}, added from a similar handle check (${row.similar.reason})` : "", "profile read", named ? `name on profile: ${p.name}` : r.tier === "matches" ? "no name on profile" : "", p.location, r.tier !== "different" && r.why && r.why !== "no name on the profile" ? r.why : "", p.evidence].filter(Boolean).join(" · ");
      if (r.tier === "different") row.person = cl?.label || p.name;
    } else if (row.kinds.has("taken")) {
      // In use according to the site's sign-up check. Unverified: nothing was read, nobody is named.
      row.tier = "unverified"; row.taken = true;
      row.meta = TAKEN_TEXT[row.key.slice(5)] || TAKEN_GENERIC;
    } else if (row.kinds.has("read") || row.kinds.has("reported")) {
      // "read" with no profile left means the only reader was a noisy site's extractor.
      row.tier = "unverified";
      row.meta = [...new Set(reported)].join(" · ");
    } else {
      row.tier = "noise"; row.meta = "";
    }
    // What the link is worth. A read profile's URL came from the source that read it; anything
    // else is a site template plus the handle. A homepage is never a profile link.
    row.srcUrl = row.url;
    const lk = row.kinds.has("registered") && !row.readUrl ? { url: "", link_kind: "none", hint: REGISTERED_HINT }
      : row.readUrl ? classifyLink({ url: row.readUrl, want: "verified_profile", site: row.what, subjects: [searchedHandle, p?.handle] })
        : classifyLink({ url: row.url, want: "templated_unverified", site: row.what, subjects: [searchedHandle] });
    row.url = lk.url; row.link_kind = lk.link_kind;
    if (lk.hint) row.hint = lk.hint;
    // Reddit refuses servers, so its unread row says how to check by hand, beside the link.
    if (row.key === "acct:reddit" && row.tier === "unverified" && (row.pcOwn === "blocked" || row.pcOwn === "unknown") && !row.hint) row.hint = REDDIT_HINT;
    // The link check's answer for this row, when it has one (see links.js).
    applyCheck(row, checks[row.key], { subjects: [searchedHandle] });
    // What the evidence card shows: the handle, the facts a source read on this profile, and why
    // the row sits in its tier. `meta` keeps the same statements as one line for exports and the AI.
    if (row.tier !== "noise") {
      const named = p && meaningfulName(p.name, [p.handle, searched]) ? p.name : "";
      const snip = cardSnippet(row, p && row.kinds.has("read") ? { ...p, shownName: named } : null);
      const read = p && r && row.kinds.has("read");
      const why = row.kinds.has("registered") ? "registered with this email"
        : read ? (p.anchor === "github" ? "GitHub's own record for this handle" : p.anchor === "gravatar" ? "Gravatar's record for this email"
          : r.tier === "different" ? "the name on it conflicts with the primary identity" : r.why && r.why !== "no name on the profile" ? r.why : named ? "" : "no name on the profile")
          : "";
      // What a tool said about a row nothing read: why the check stopped, or the site's category.
      const said = read ? [] : [...new Set(reported)].filter(Boolean);
      const OWN_WORDS = /^(Blocked by site|Could not tell|profile URL answered|Reddit's API)/;
      const note = [...said.filter((x) => OWN_WORDS.test(x)).map((x) => (/^Reddit's API/.test(x) ? `${x}.` : x)), ...said.filter((x) => !OWN_WORDS.test(x)).map((x) => `Listed under ${x}.`)].join(" ");
      row.card = { handle: String(p?.handle || searchedHandle || ""), ...snip, why: snip.basis && why === "no name on the profile" ? "" : why, note };
      // The platform check asked the site itself and read nothing: it did not "report" the handle.
      if (!read && row.pcOwn && row.card.basis) { const tools = row.sources.filter((x) => x !== "Platform check"); row.card.basis = tools.length ? `Reported by ${tools.join(", ")}. Nothing was read.` : "Nothing was read."; }
      // A taken handle: the card says what the sign-up check said, and nothing about a profile.
      if (row.taken) row.card = { handle: String(searchedHandle || ""), facts: [], bio: "", basis: row.meta, why: "", note: "" };
      if (read && p.note === "suspended") row.card.note = "The site marks this account as suspended.";
      if (row.similar) row.card.why = "";
      if (read && row.similar) row.card.note = [`Added from the similar handle ${row.similar.variant}: ${row.similar.reason}.`, row.card.note].filter(Boolean).join(" ");
      if (p?.thumb) row.thumb = p.thumb;
    }
    // The tools that reported the row. For Reddit and Discord the platform check asked the site
    // itself, so it is not one of them.
    row.tools = row.sources.filter((x) => !(row.pcOwn && x === "Platform check")).length;
    if (row.taken || (row.pcOwn && row.tier === "unverified" && !row.tools)) row.nofind = true;
    markUnsendable(row);
    delete row.kinds; delete row.notes; delete row.readUrl;
  }

  // --- similar handles: one row per variant, after the leads ------------------------------
  if (person && simBase) {
    const snippet = (sp) => { const sn = cardSnippet({ sources: [SIMILAR_SOURCE], kinds: ["read"] }, { ...sp, shownName: meaningfulName(sp.name, [sp.profile.handle, searched]) ? sp.name : "", repos: null }); return { facts: sn.facts, bio: sn.bio }; };
    for (const r of similarItems({ handle: simBase, name: primaryName, evaluated, snippet })) items.push(r);
  }

  // --- breaches -----------------------------------------------------------------------
  for (const b of c.hibp && !failed(c.hibp) ? breachList(c.hibp) : []) {
    // Two breaches can share one reference URL, so these are told apart by name, never by link.
    const key = `breach:${norm(b.name)}`;
    if (!items.some((i) => i.key === key)) items.push({ tier: "flag", what: `Breach: ${b.name}`, url: b.url, meta: breachMeta(b), source: c.hibp.source || "Breaches", key, ...(b.url ? {} : { hint: BREACH_HINT }) });
  }

  // --- hunter -------------------------------------------------------------------------
  const hu = c.hunter;
  if (hu && !hu.error) {
    if (hu.pattern) fact("Email pattern", hu.pattern, "Hunter.io");
    for (const e of (hu.emails || []).slice(0, 25)) {
      add({ tier: "unverified", what: e.email, url: "", meta: ["address on the same domain", [e.first_name, e.last_name].filter(Boolean).join(" "), e.position, e.confidence != null ? `Hunter confidence ${e.confidence}%` : ""].filter(Boolean).join(" · "), source: "Hunter.io", key: `email:${norm(e.email)}` });
    }
  }

  // --- domain harvest: addresses are leads about people, hostnames are inventory ----------
  const hv = c.harvester;
  if (hv && !hv.error && !hv.skipped) {
    for (const e of hv.emails || []) if (norm(e) !== norm(target)) add({ tier: "unverified", what: e, url: "", meta: "same domain, seen in public archives", source: "Domain harvest", key: `email:${norm(e)}` });
    for (const hn of hv.hosts || []) add({ tier: "hosts", what: hn, url: `https://${hn}`, meta: (hv.host_sources?.[hn] || []).join(", "), source: "Domain harvest", key: `host:${norm(hn)}` });
  }

  // --- hash ---------------------------------------------------------------------------
  const hs = c.hash, hv2 = hashView(hs);
  if (hv2) {
    const kind = hs.hash_type || "hash";
    // Where the verdict can be checked: the VirusTotal page for this hash, and OTX when it answered.
    const vt = evidenceUrl.virustotal(hs.hash) || hs.virustotal_url || "";
    const otx = hs.alienvault && typeof hs.alienvault === "object" && !hs.alienvault.error && !hs.alienvault.error_code ? evidenceUrl.otx(hs.hash) : "";
    const verdict = (it) => { add(it); const row = items.find((i) => i.key === "hash:verdict"); if (row && !row.link_kind) { row.link_label = "VirusTotal"; if (otx) row.ev = { url: otx, label: "OTX" }; } };
    if (hv2.verdict === "TEST_FILE") verdict({ tier: "info", what: `${hv2.testFile.name}: ${TEST_FILE_TEXT}`, url: vt, meta: "not malware", source: "Hash lookup", key: "hash:verdict" });
    else if (hv2.verdict === "MALICIOUS") verdict({ tier: "flag", what: `Malicious ${kind}${hv2.family ? `: ${hv2.family}` : ""}`, url: vt, meta: ["known malware", hv2.family && hv2.familySources.length ? `family named by ${hv2.familySources.join(", ")}` : "", hv2.detection ? detectionText(hv2) : ""].filter(Boolean).join(" · "), source: "Hash lookup", key: "hash:verdict" });
    else if (hv2.verdict === "CLEAN") verdict({ tier: "info", what: `Known clean ${kind}`, url: vt, meta: String(hs.verdict_basis || "CIRCL hashlookup"), source: "Hash lookup", key: "hash:verdict" });
    else {
      // Say how many sources actually answered. A source that could not be asked did not say "not seen".
      const cov = hashCoverage(hs), name = hs.hash_type || "Hash";
      const what = !cov.failed.length ? `${name} not seen by any source`
        : cov.answered ? `${name} not seen by the ${cov.answered} ${cov.answered === 1 ? "source" : "sources"} that answered; ${cov.failed.length} could not be asked (${cov.failed.join(", ")})`
          : `${name} could not be checked: no source could be asked (${cov.failed.join(", ")})`;
      verdict({ tier: "info", what, url: vt, meta: String(hs.verdict_basis || "unknown is not the same as clean"), source: "Hash lookup", key: "hash:verdict" });
    }
    fact("File name", hv2.fileName, "Hash lookup");
    fact("File type", hv2.fileType, "Hash lookup");
    fact("File size", hv2.fileSize != null && hv2.fileSize !== "" ? `${fmtNum(hv2.fileSize)} bytes` : "", "Hash lookup");
    fact("First seen", hv2.firstSeen.slice(0, 10), "Hash lookup");
    fact("Last seen", hv2.lastSeen.slice(0, 10), "Hash lookup");
    fact("Family", hv2.family, hv2.familySources.join(", ") || "Hash lookup", vt);
    fact("Detection", detectionText(hv2), "Hash lookup", vt);
    if (hs.malware_bazaar?.signature) fact("Signature", hs.malware_bazaar.signature, "MalwareBazaar");
  }

  // --- phone --------------------------------------------------------------------------
  // What the number is, never who uses it (see phone.js). A failed lookup gives no view, so it
  // contributes nothing here. An answer saved before open numbering data was read still renders.
  const pv = phoneView(c.phone);
  if (pv) {
    for (const f of phoneFacts(pv)) fact(f.k, f.v, f.source, f.url);
    for (const r of phoneItems(pv)) items.push(r);
  }

  // --- a name case: candidates, suggested handles and outbound searches -------------------
  // Built on their own and only for a name. They never reach the profiles, clusters, facts or
  // leads above, so a person who shares the name is never written up as the target.
  if (type === "name") for (const r of nameItems(c, target)) items.push(r);

  // --- adult and dating sites: their own group, from the unfiltered case -----------------
  for (const r of adultRows(collected, target, type)) items.push(r);

  // --- leads --------------------------------------------------------------------------
  if (person) {
    const urls = new Set([...accounts.values()].map((a) => linkParts(a.srcUrl || a.url)?.key).filter(Boolean));
    for (const l of buildLeads(c, target, type, profiles, rel, urls)) items.push(l);
  }

  for (const it of items) if (it.sources) {
    it.source = it.sources.join(", ");
    // Two tools agreeing is worth saying, but it is still not verification.
    // Not for a row the platform check asked itself: it did not "report" the handle.
    if (it.tier === "unverified" && !it.taken && (it.tools ?? it.sources.length) > 1 && it.key?.startsWith("acct:")) it.meta = [it.meta, `reported by ${it.tools ?? it.sources.length} tools`].filter(Boolean).join(" · ");
  }
  for (const it of items) { delete it.srcUrl; sealLink(it, { subjects: [searchedHandle], secrets }); }
  // A row whose page was not found stays in its group, at the end.
  items.sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || (a.gone ? 1 : 0) - (b.gone ? 1 : 0) || (!a.key?.startsWith("acct:") || !b.key?.startsWith("acct:") ? 0 : (b.sources?.length || 1) - (a.sources?.length || 1) || a.what.localeCompare(b.what)));

  // --- identity views: whose facts "What we know" can show ------------------------------
  // A profile added from a similar handle is named with that handle, so it is never read as the target's.
  const siteName = (p) => (p?.similar ? `${p.site} (${p.handle})` : p?.site);
  const sitesOf = (ids) => ids.map((id) => siteName(byId.get(id))).filter(Boolean);
  const views = result.clusters.map((cl) => ({
    // different: at least one of its profiles carries a name that conflicts with the primary identity.
    id: cl.id, label: cl.label, named: cl.named, primary: cl.primary, different: cl.members.some((id) => rel.get(id)?.tier === "different"), why: cl.why || "", sites: sitesOf(cl.members), names: cl.names, locations: cl.locations, thumb: cl.members.map((id) => byId.get(id)?.thumb).find(Boolean) || "",
    signals: cl.links.flatMap((l) => l.signals.map((s) => ({ ...s, a: siteName(byId.get(l.a)), b: siteName(byId.get(l.b)) }))),
    facts: dedupeFacts(cl.members.flatMap((id) => byId.get(id)?.facts || [])),
  }));
  if (result.unassigned.length) views.push({ id: "unassigned", label: "Profiles with no name", named: false, primary: false, why: "", sites: sitesOf(result.unassigned), names: [], locations: [], thumb: "", signals: [], facts: dedupeFacts(result.unassigned.flatMap((id) => byId.get(id)?.facts || [])) });
  // noPrimary: profiles were read, but there is no anchor and no strong signal, so nobody is picked.
  const identity = { views, primary: primary ? primary.id : null, people: views.filter((v) => v.named).length, noPrimary: !primary && views.length > 0 };
  // Without a primary identity no person's facts are shown as the target's.
  const facts = dedupeFacts([...(views.find((v) => v.primary)?.facts || []), ...general]);
  // added: the facts of the profiles added from a similar handle, kept apart from every identity.
  const addedFacts = addedList.map((p) => ({ id: p.id, label: `${p.site} (${p.handle})`, facts: p.facts })).filter((a) => a.facts.length);
  return { items, facts, general: dedupeFacts(general), identity, type, similarLine: similarBrief(evaluated), added: addedFacts };
}

// Facts for one identity view, plus the facts that belong to the target and to no person.
export function factsFor(ev, viewId) {
  const v = ev.identity.views.find((x) => x.id === viewId);
  return v ? dedupeFacts([...v.facts, ...ev.general]) : ev.facts;
}

export const ADDED_HEADING = "From profiles you added (under a different handle)";
// The similar handles of a case that came from a case file: only handles this case would offer
// itself are kept, nothing stays "added", and each answer is marked as coming from the file.
export function importSimilar(results, target, type) {
  const base = similarBase(target, type);
  if (!base || !results || typeof results !== "object" || !("similar" in results)) return {};
  const { similar, ...rest } = results;
  const ev = buildEvidence(rest, target, type);
  const main = ev.identity.views.find((v) => v.primary);
  return fromFile(similar, base, similarHandles(base, { name: main?.named ? main.label : "" }).map((x) => x.value));
}

export const TIERS = [
  { id: "flag",       title: "Flags",                     cls: "flag",      open: true,  blurb: "Breaches, malware, disposable numbers. Read these first." },
  { id: "info",       title: "Lookup result",             cls: "",          open: true,  blurb: "What the sources returned for this target." },
  { id: "linked",     title: "Linked",                    cls: "confirmed", open: true,  blurb: "Tied to the primary identity by a strong signal (a cross-link, the same avatar, a shared personal site), or the authoritative record for the target itself. Each row says which." },
  { id: "matches",    title: "Exists (matches)",          cls: "possible",  open: true,  blurb: "A profile was read. Its name fits the primary identity, or it carries no name that conflicts. Consistent is not proven: open the ones that matter." },
  { id: "different",  title: "Exists (different person)", cls: "",          open: false, blurb: "A profile was read, and the name on it conflicts with the primary identity. These are other people who use the same handle." },
  { id: "unverified", title: "Unverified",                cls: "",          open: true,  blurb: "A tool reported the handle and nothing was read, or the site blocked the check. Many sites answer yes to any name. Open and check before relying on one." },
  { id: "adult",      title: ADULT_GROUP,                 cls: "",          open: false, blurb: `${ADULT_NOTICE} Each row says how it is known. Nothing here is tied to the target, and no picture or post is ever loaded.` },
  { id: "lead",       title: "Leads from profiles",       cls: "",          open: true,  blurb: "Handles, addresses, domains and links found on the profiles above. Each says where it came from. They are places to look next, not findings about this target, and nothing is followed until you click." },
  // aside: a group that is offered beside the findings. It does not stand in for "nothing found".
  { id: "similar",    title: SIMILAR_GROUP,               cls: "",          open: false, aside: true, blurb: SIMILAR_BLURB },
  { id: "hosts",      title: "Hosts on this domain",      cls: "",          open: false, limit: 300, blurb: "Hostnames on the email's domain, from public sources. This is the organisation's inventory. It says nothing about the person." },
  { id: "noise",      title: "Known noisy sites",         cls: "",          open: false, limit: 40, blurb: "Sites that answer yes to any username. Kept for completeness." },
];
// The same tiers with the host group named after the email's domain. A name case has groups of its own and none of the others (see names.js).
export const ledgerTiers = (target, type) => type === "name" ? NAME_TIERS.map((t) => ({ ...t })) : type === "phone" ? PHONE_TIERS.map((t) => ({ ...t })) : TIERS.map((t) => (t.id === "hosts" && type === "email" && emailParts(target).domain ? { ...t, title: `Hosts on ${emailParts(target).domain}` } : t));

// The account rows the AI prompt and the report use, so they match the screen exactly.
// status is the tier id: linked, matches, different or unverified.
export const accountsFor = (items) => items.filter((i) => i.key?.startsWith("acct:") && ACCOUNT_TIERS.includes(i.tier))
  .map((i) => ({ site: String(i.what).slice(0, 120), url: i.link_kind === "none" ? "" : String(i.url || "").slice(0, 600), link_kind: i.link_kind || "none", ...(i.check ? { link_check: i.check } : {}), status: i.tier, sources: (i.sources || [i.source]).slice(0, 8).map(String),
    // A taken handle is told as that: no profile was read and the owner is unknown.
    note: i.taken ? TAKEN_NOTE : i.tier === "unverified" ? "" : String(i.meta || "").slice(0, 200),
    // A profile added from a similar handle is under another handle than the target's.
    ...(i.similar ? { handle: String(i.similar.variant).slice(0, 64) } : {}) }));
export const tierCounts = (items) => Object.fromEntries(ACCOUNT_TIERS.map((t) => [t, items.filter((i) => i.key?.startsWith("acct:") && i.tier === t).length]));

// Everything the model is told about a case. Sources are sent without their adult and dating
// site rows. Those travel only as `adult_sites` (site, category, state and link kind: no names,
// no bios, no URLs), only for a case that had the mode on, and never inside `accounts`.
export function aiPayloadFor(collected, target, type, { source_status = {}, active = false } = {}) {
  const c = withoutAdult(collected);
  const { items } = buildEvidence(collected, target, type);
  const adult = adultAllowed(collected, target, type);
  return {
    target, target_type: type, accounts: accountsFor(items),
    source_status: adult ? source_status : Object.fromEntries(Object.entries(source_status).filter(([k]) => k !== ADULT_SOURCE)),
    hash: c.hash || null, phone: phoneForAi(c.phone), github_deep: c.githubDeep || null,
    sherlock: c.sherlock || null, maigret: c.maigret || null, holehe: c.holehe || null, harvester: c.harvester || null, hibp: c.hibp || null,
    gravatar: c.gravatar || null, github: c.github || null, enricher: c.enricher || null, platform_check: c.platformCheck || null,
    hunter: c.hunter || null, name_search: c.nameSearch ? { name: c.nameSearch } : null, active_techniques: !!active,
    // A name case: the candidates as the screen shows them. Absent for every other case.
    ...(type === "name" && nameForAi(c, target) ? { name_candidates: nameForAi(c, target) } : {}),
    ...(adult ? { adult_sites: adultForAi(items.filter((i) => i.tier === "adult")) } : {}),
    // A case the minor guard stopped: the model is told that the group was skipped and on which
    // site the sign was. The quoted text is never sent.
    ...(type === "username" && blockForAi(collected) ? { adult_block: blockForAi(collected) } : {}),
  };
}

// What an AI report was written from. Two runs with the same signature get the same report, so a
// re-run can reuse the last one. Computed from the case it is given, never from the one on screen.
export function aiSignature(collected, target, type) {
  const { items, facts } = buildEvidence(collected, target, type);
  return JSON.stringify([accountsFor(items), items.filter((i) => i.tier === "flag").map((i) => i.key), facts.map((f) => [f.k, f.v]),
    adultForAi(items.filter((i) => i.tier === "adult")), type === "name" ? nameForAi(withoutAdult(collected), target) : null, ...(type === "username" && blockForAi(collected) ? [blockForAi(collected)] : [])]);
}

// The profile pages a Deep Dive may read. Built from the adult-free view, and a URL whose host is
// on the adult and dating list is left out whatever row it sits on: the scraper refuses those.
export function deepDiveUrls(collected) {
  const c = withoutAdult(collected), urls = [];
  for (const k of ["sherlock", "maigret"]) for (const r of c[k]?.results || []) if (r && r.url && r.confidence !== "false_positive") urls.push({ site: r.site, url: r.url });
  for (const r of c.platformCheck?.results || []) if (r && r.found && r.url) urls.push({ site: r.platform, url: r.url });
  const seen = new Set();
  return urls.filter((u) => /^https?:\/\//i.test(u.url) && !adultHost(u.url) && !seen.has(u.url) && seen.add(u.url)).slice(0, 20);
}

// The Markdown export of a case. Adult and dating site rows come after every other finding,
// under their own heading, and only exist for a case that had the mode on.
export function caseMarkdown({ collected, target, type, ran = 0, tallyLine = "", failed = [], purpose = "", ai = null, deep = null, notes = "", now = new Date() }) {
  const { items, facts, identity, added = [] } = buildEvidence(collected, target, type);
  const main = identity.views.find((v) => v.primary);
  const others = identity.views.filter((v) => v.named && !v.primary);
  const adult = items.filter((i) => i.tier === "adult");
  return [`# CrawlR case: ${target}`, `Generated ${now.toISOString()} · ${TYPE_LABEL[type]}${ran ? ` · collected ${new Date(ran).toISOString()}` : ""}`, tallyLine, "", ...(purpose ? [`**Purpose:** ${purpose}`, ""] : []),
    "> Findings come from third-party public sources and can be wrong. Unverified items are leads, not facts. A link marked (unverified URL) is a site address built from the handle that nothing has checked. A profile that exists is not proof of who owns it, and leads are places to look, not findings.", "",
    ...(failed.length ? ["## Sources that failed", ...failed.map((f) => `- **${f.name}:** ${f.text} (unknown, not a negative result)`), ""] : []),
    // A name case selects no one: the caveat line, then what is known about the search itself.
    ...(type === "name" ? nameMarkdownHead(collected, target) : [`## What we know${main ? ` (primary identity: ${main.label}, from ${main.sites.join(", ")})` : ""}`, ...(facts.length ? facts.map((f) => `- **${f.k}:** ${mdLink(f, f.v)} _(${f.source})_`) : ["- Nothing extracted"]), ""]),
    ...(added.length ? [`## ${ADDED_HEADING}`, ...added.flatMap((a) => a.facts.map((f) => `- **${f.k}:** ${mdLink(f, f.v)} _(${f.source})_`)), ""] : []),
    ...(others.length ? ["## Other people using this handle", ...others.map((v) => `- **${v.label}:** ${v.sites.join(", ")}`), ""] : []),
    ...ledgerTiers(target, type).filter((t) => t.id !== "adult").flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...(isNameTier(t.id) ? [`_${t.blurb}_`] : []), ...rows.map((i) => `- ${mdLink(i)}${mdNote(i) ? ` · ${mdNote(i)}` : ""} _(${i.source})_`), ""] : []; }),
    ...adultMarkdown(adult),
    // A report's own sections about adult or dating sites are exported only for a case that has such rows.
    ...(ai ? ["## AI analysis", reportForExport(ai.summary, adultFound(adult).length > 0), ""] : []),
    ...(deep ? ["## Deep Dive", reportForExport(deep.summary, false), ""] : []),
    ...(String(notes).trim() ? ["## Notes", String(notes).trim(), ""] : []),
  ].join("\n");
}
