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
// A fact: { k, v, source, url?, link_kind, how? }  (name, location, employer…), shown in "What we know".
// Facts belong to an identity cluster, so one person's name is never shown beside another's.
//   how: how the fact is known (factHow in analysis.js): the site's own record, self-declared by
//   the account holder or a tool report, and how many of the identity's profiles say the same.
//
// The primary identity is chosen by the rules, or picked by the investigator (collected.pick:
// the member ids of the cluster they chose; see rule 9 in identity.js). Everything below is
// computed against whichever it is: the tier of every account row, the facts, the leads. Nothing
// is removed by a pick. A row that belongs to another person stays, filed as "different", and
// carries a check: whether that person is connected to the one the case is about.

import { cardSnippet, safeThumb } from "./present.js";
import { classifyLink, sealLink, sealFact, readChecks, applyCheck, markUnsendable, evidenceUrl, REGISTERED_HINT, BREACH_HINT, REDDIT_HINT, REDDIT_HIDDEN, TAKEN_TEXT, TAKEN_GENERIC, TAKEN_NOTE, mdLink, mdNote } from "./links.js";
import { evaluateSimilar, addedProfiles, similarItems, similarBrief, similarBase, similarHandles, fromFile, SIMILAR_GROUP, SIMILAR_BLURB, SIMILAR_SOURCE } from "./similar.js";
import { TYPE_LABEL } from "./core.js";
import { clusterIdentities, standing, meaningfulName, nameTokens, looksBoilerplate, linkParts, urlsIn, readPick } from "./identity.js";
import { NAME_TIERS, isNameTier, nameItems, nameForAi, nameMarkdownHead } from "./names.js";
import { PHONE_TIERS, phoneView, phoneItems, phoneFacts, phoneForAi } from "./phone.js";
import { withoutAdult, adultRows, adultOn, adultAllowed, adultForAi, adultFound, adultMarkdown, blockForAi, reportForExport, adultHost, handleOf, isAdultRow, readiness, adultRequests, readBlock, stripGuard, blockText, blockFromScan, blockFromRefusal, usernameBody, ADULT_GROUP, ADULT_NOTICE, ADULT_SOURCE, ADULT_LOG, CANCELLED_TEXT } from "./adult.js";
import { scanProfiles, sourceRoles } from "./minorscan.js";
import { readProfileSources, readEmailAccounts, readActivity, readDeep, profileDetail, detailMarkdown, profileCoverage, emailAccountItems, emailAccountFacts, emailAccountLeads, emailAccountsForAi, emailLookupsDown, activityView, activityForAi, activityMarkdown, proofStrong, readArchives, archiveView, archivable, archiveMarkdown, PROOF_TEXT, PROFILE_SOURCE, PROFILE_STATE_WORD, EMAIL_ACCOUNTS_SOURCE, ACTIVITY_SOURCE, ARCHIVE_SOURCE,
  MASTODON_INSTANCES, unclaimedProfile, profileNoteText, NOT_ACTIVE_NOTE,
  readCommitEmails, commitEmailsFor, commitEmailsView, commitEmailLeads, commitEmailsMarkdown, commitEmailsForAi, COMMIT_EMAILS_SOURCE,
  readPostActivities, postActivityFor, postActivityView, postActivityLabel, postActivityMarkdown, postActivityForAi, compareOffsets, POST_ACTIVITY_SOURCE,
  readArchiveDiffs, archiveDiffPairs, archiveDiffView, archiveDiffLeads, archiveDiffMarkdown, archiveDiffTexts } from "./deep.js";
import { assessCase, suggestNext, factHow, analysisMarkdown, analysisForAi } from "./analysis.js";
import { trailView, trailText, trailMarkdown, selfAuditOn } from "./casework.js";
import { selfAudit, selfAuditMarkdown } from "./selfaudit.js";

const norm = (s) => String(s ?? "").trim().toLowerCase();

// Different tools name the same site differently ("Twitter" vs "X", "Steam Community" vs "Steam").
// Accounts are merged on the canonical name so one site is one row, with every source that saw it.
const SITE_ALIAS = {
  "twitter": "x", "x (twitter)": "x", "x / twitter": "x", "x/twitter": "x", "twitter.com": "x", "x.com": "x",
  "steam community": "steam", "steamcommunity": "steam", "threads.net": "threads", "instagram.com": "instagram",
  "facebook.com": "facebook", "youtube channel": "youtube", "reddit.com": "reddit", "github.com": "github",
  "tiktok.com": "tiktok", "twitch.tv": "twitch", "bsky": "bluesky", "bsky.app": "bluesky", "hugging face": "huggingface",
  // The profile sources name a site the way the site does; the username tools have their own
  // spellings. The canonical name is the one older cases already use as the row's key.
  "hacker news": "hackernews", "dev.to": "dev community", "chess.com": "chess", "mastodon": "mastodon.social", "codeberg.org": "codeberg", "codeforces.com": "codeforces", "dockerhub": "docker hub", "lobste.rs": "lobsters",
  // Sherlock and Maigret call the Gitea.com check "Gitea" and the fosstodon.org one "Fosstodon";
  // the other Mastodon instances they know go by their host, which is the canonical name here.
  "gitea.com": "gitea", "launchpad.net": "launchpad", "fosstodon": "fosstodon.org",
};
const SITE_DISPLAY = { x: "X (Twitter)", steam: "Steam", huggingface: "Hugging Face", threads: "Threads", gravatar: "Gravatar", hackernews: "Hacker News", "dev community": "dev.to", chess: "Chess.com", "mastodon.social": "Mastodon", "docker hub": "Docker Hub", gitea: "Gitea.com", launchpad: "Launchpad",
  // One row per Mastodon instance: the same handle on two instances is two accounts.
  ...Object.fromEntries(MASTODON_INSTANCES.slice(1).map((host) => [host, `Mastodon (${host})`])) };
// "Mastodon (fosstodon.org)" is the account on that instance, and its canonical name is the host.
// mastodon.social keeps the name older cases use as its row key. Any other trailing parenthesis
// is a tool's remark about the site and is dropped.
const MASTODON_AT = /^mastodon\s*\(([a-z0-9-]+(?:\.[a-z0-9-]+)+)\)$/;
export const canonSite = (s) => { const raw = norm(s), m = raw.match(MASTODON_AT); if (m) return m[1]; const n = raw.replace(/\s*\((?!twitter).*\)$/, ""); return Object.hasOwn(SITE_ALIAS, n) ? SITE_ALIAS[n] : n; };
const siteDisplay = (cs) => (Object.hasOwn(SITE_DISPLAY, cs) ? SITE_DISPLAY[cs] : "");
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
    // "emailaccounts" asks GitHub and the key server about the address itself. No handle is derived.
    return ["holehe", "hibp", "gravatar", "emailaccounts", ...(isFreeMail(domain) ? [] : ["harvester"]), "hunter"];
  }
  // "profiles" reads the handle's record on sites with an open API. It runs beside the username
  // tools. GitHub activity is a follow-up of "github", like GitHub details, and has no entry here.
  return ["sherlock", "maigret", "github", "platform", "profiles", ...(adultOn(type, target, adult) ? ["adult"] : [])];
}

// ---- the profile text the minor guard reads -----------------------------------------------------
// Every display name, bio and further text field a source returned for this handle in the
// ordinary run, with the site it was read on: the same fields, in the same order, with the same
// bounds as the server keeps for its own copy of the check (entries_of in core/profile_record.py;
// tests/test_minor_parity.py feeds one case through both and compares). The order is the rules
// file's `sources.text_order`: Maigret, GitHub, the platform check (Reddit's record included),
// profile enrichment, then the profile sources (collected.profiles: the name, the bio and
// `guard.bio`, with the company and the location as further text), then the names on commits
// (collected.commitEmails, one entry per found answer with rows, in the order the answers are
// kept: the site name, the profile address, the profile's display name as the name, and the other
// author names of at most 10 rows as the bio, one per line, each once and at most 100 characters;
// guard_profile in modules/commit_emails.py builds the same row for the server's record. A
// commit address is never scanned), then what two archived copies of a profile said
// (collected.archiveDiffs: the page titles and the removed and added lines, as the server records
// them under "Internet Archive"). Then, on the page only, Gravatar and a profile scrape when
// the case has them.
// A row may carry guard-only text under `guard` (the whole bio, other text fields, a birth date,
// an age): it is read here and removed before the case is kept (stripGuard in adult.js).
// Sites known to answer for any name are left out, and nothing adult is ever read. Profiles the
// identity grouping calls a different person are included on purpose: an adult-site account
// under this handle could be theirs, and the message names the source so the investigator can
// judge. Addresses and handles are not scanned, and a similar handle's probe is not part of it.
const BIRTH_KEYS = ["birthday", "birth_date", "birthdate", "born", "dob", "date_of_birth", "age"];
const clipText = (v, n) => (typeof v === "string" || typeof v === "number" ? Array.from(String(v)).slice(0, n).join("") : "");
const textLines = (...parts) => parts.filter((x) => typeof x === "string" && x.trim()).map((x) => x.trim()).join("\n");
export function profileTexts(collected) {
  const c = collected && typeof collected === "object" ? collected : {}, out = [];
  const guardOf = (r) => (r && r.guard && typeof r.guard === "object" && !Array.isArray(r.guard) ? r.guard : {});
  const put = (source, url, name, bio, text, extra) => {
    const e = { source: clipText(source, 80), url: clipText(url, 600), name: clipText(name, 200), bio: clipText(bio, 2000), text: clipText(text, 1000) };
    if (adultHost(e.url) || isAdultRow({ site: e.source, url: e.url })) return;
    for (const k of BIRTH_KEYS) { const t = clipText(extra?.[k], 40); if (t) e[k] = t; }
    if (Object.entries(e).some(([k, v]) => k !== "source" && k !== "url" && v)) out.push(e);
  };
  const rows = (d, list = "results") => (d && !failed(d) && Array.isArray(d[list]) ? d[list].filter((r) => r && typeof r === "object") : []);
  const read = {
    maigret: (d) => { for (const r of rows(d)) { if (r.adult || r.confidence === "false_positive") continue; const p = r.profile && typeof r.profile === "object" ? r.profile : {}, g = guardOf(p); put(r.site || r.name, r.url, p.name, g.bio || p.bio, textLines(p.location, g.text), g); } },
    github: (d) => { if (d?.found && !failed(d)) put("GitHub", d.profile_url, d.name, d.bio, textLines(d.company, d.location)); },
    platformCheck: (d) => { for (const r of rows(d)) if (r.state === "found") put(r.platform, r.url, r.display_name, r.bio, "", guardOf(r)); },
    enricher: (d) => { for (const e of rows(d, "profiles")) put(e.platform, e.url, e.display_name, e.bio, "", guardOf(e)); },
  };
  for (const [, key] of sourceRoles().textOrder) read[key]?.(c[key]);
  // The profile sources, after the sources the rules file orders (the server appends them the
  // same way: `texts` in core/profile_record.py). The rows are read as they came, not through
  // readProfileSources, so the page scans exactly what the server scans.
  for (const p of rows(c.profiles, "profiles")) if (p.state === "found") { const g = guardOf(p); put(p.site, p.url, p.display_name, g.bio || p.bio, textLines(p.company, p.location), g); }
  // The names on commits (POST /api/recon/commit-emails), as the server records them. A stored
  // answer keeps these names as they came (readCommitEmails in deep.js), so there is no guard-only text.
  for (const a of Object.values(c.commitEmails && typeof c.commitEmails === "object" && !Array.isArray(c.commitEmails) ? c.commitEmails : {})) {
    if (!a || typeof a !== "object" || a.state !== "found" || !Array.isArray(a.emails)) continue;
    const mails = a.emails.filter((r) => r && typeof r === "object" && !Array.isArray(r)).slice(0, 10);
    if (!mails.length) continue;
    const text = (v) => (typeof v === "string" ? clipText(v, 100) : ""), shown = text(a.display_name), names = [];
    for (const r of mails) { const n = text(r.name); if (n && n !== shown && !names.includes(n)) names.push(n); }
    put(a.site_name, a.profile_url, shown, names.join("\n"), "");
  }
  // What two archived copies said (POST /api/recon/archive-diff), as the server records it under
  // "Internet Archive": the page titles and the removed and added lines, in pieces of at most 2000
  // characters, with the address of the older capture (archiveDiffTexts in deep.js). In the order
  // the answers are kept.
  for (const a of Object.values(c.archiveDiffs && typeof c.archiveDiffs === "object" && !Array.isArray(c.archiveDiffs) ? c.archiveDiffs : {})) for (const e of archiveDiffTexts(a)) put(e.source, e.url, "", e.bio, "");
  if (c.gravatar?.found && !failed(c.gravatar)) put("Gravatar", c.gravatar.profile_url, c.gravatar.name || c.gravatar.display_name, c.gravatar.about || c.gravatar.bio, "");
  for (const r of rows(c.profileScrape)) if (!r.error) put(r.site || "Profile", r.url, r.display_name, r.bio, "");
  return out;
}
// Stage 2 of the minor guard, for a case whose ordinary sources are in:
// { blocked, kind, signal: { strength, kind, source, snippet, url } | null, signals, soft, soft_years, read }.
// today is a parameter so the tests can pin it.
export const contentCheck = (collected, target, type = "username", today = new Date()) => scanProfiles(type === "username" ? profileTexts(collected) : [], handleOf(target), today);

// ---- a username run: what is asked, and when ----------------------------------------------------
// investigate.js builds its requests with these three functions and does what they say, so the
// order of a run is tested here and not by reading the page's code.
// The ordinary run's own Sherlock and Maigret requests: nsfw false whatever the mode.
export const ordinaryRequests = (handle, { sherlock = true, maigret = true } = {}) => [
  ...(sherlock ? [{ key: "sherlock", label: "Sherlock", url: "/api/recon/sherlock", body: usernameBody(handle, false) }] : []),
  ...(maigret ? [{ key: "maigret", label: "Maigret", url: "/api/recon/maigret", body: usernameBody(handle, false) }] : []),
];
// The adult pass, decided once everything that returns profile text has answered.
//   planned    the mode applies to this case (the last entry of sourcePlan is "adult")
//   switched   { sherlock, maigret, platformCheck }: the Sources panel's switches
// state: "none" (not planned), "cancelled", "unread" (no source that reads profiles answered:
// unknown is not clean), "blocked" (the profile check found a sign of a minor) or "clean".
// Only "clean" has requests. block is what the case records; log is the run log row.
export function adultPassPlan({ planned, cancelled = false, collected, target, type = "username", switched = {}, today = new Date() } = {}) {
  const none = { state: "none", requests: [], log: "", notice: "", block: null, scan: null, silent: [] };
  if (planned !== true || type !== "username") return none;
  if (cancelled) return { ...none, state: "cancelled", log: ADULT_LOG.cancelled, notice: CANCELLED_TEXT };
  const ready = readiness(collected, switched);
  if (!ready.ok) { const block = readBlock({ kind: "unread", via: ready.via }); return { ...none, state: "unread", log: ADULT_LOG.blocked(block), notice: blockText(block), block }; }
  const scan = contentCheck(collected, target, type, today);
  if (scan.blocked) { const block = blockFromScan(scan); return { ...none, state: "blocked", log: ADULT_LOG.blocked(block), notice: blockText(block), block, scan }; }
  return { ...none, state: "clean", scan, silent: ready.silent, log: ADULT_LOG.clean(scan.read, ready.silent), requests: adultRequests(handleOf(target), scan, { sherlock: switched.sherlock !== false, maigret: switched.maigret !== false }) };
}
// The server refused an adult request. 400 minor_guard: its own check blocked (or the handle).
// 409 mainstream_first: it has no record of this run (expired, lost cookie, restart).
// Returns what the case records and the run log row, or null for any other error.
export function adultRefusal(err) {
  if (err?.code === "minor_guard") { const block = blockFromRefusal(err); return { state: "refused", block, log: ADULT_LOG.blocked(block), notice: blockText(block), minor: ["age", "school", "birth", "soft"].includes(block.kind) ? "content" : "server" }; }
  if (err?.code === "mainstream_first") { const block = readBlock({ kind: "fresh" }); return { state: "fresh", block, log: ADULT_LOG.blocked(block), notice: blockText(block), minor: "" }; }
  return null;
}

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
    if (!cur) { cur = { id, site: siteDisplay(canonSite(site)) || String(site), url: "", handle: searched, name: "", location: "", bio: "", image: "", links: [], websites: [], anchor: "", sources: [], facts: [], leads: [], evidence: "", created: "", note: "", repos: null, followers: null, karma: null, thumb: "",
      // What a record carries beyond the card's one line (see profileDetail in deep.js). api: a
      // site's own API answered, so its dates and counts are the site's record. proven: links the
      // other side has confirmed (a Keybase proof, a verified link), for the identity rules.
      company: "", lastActive: "", siteNote: "", emails: [], accounts: [], items: [], stats: {}, proven: [], api: false, avatarState: "" }; map.set(id, cur); }
    if (!cur.sources.includes(source)) cur.sources.push(source);
    for (const k of ["url", "location", "bio", "image", "anchor", "evidence", "created", "note", "company", "lastActive", "siteNote"]) if (!cur[k] && p[k]) cur[k] = String(p[k]);
    if (p.api) cur.api = true;
    for (const e of p.emails || []) if (e && !cur.emails.includes(String(e).toLowerCase())) cur.emails.push(String(e).toLowerCase());
    for (const a of p.accounts || []) if (a?.url && !cur.accounts.some((x) => norm(x.url) === norm(a.url))) cur.accounts.push(a);
    for (const a of p.proven || []) if (a?.url && !cur.proven.some((x) => norm(x.url) === norm(a.url))) cur.proven.push(a);
    for (const i of p.items || []) if (i?.url && !cur.items.some((x) => norm(x.url) === norm(i.url))) cur.items.push(i);
    for (const [k, v] of Object.entries(p.stats || {})) if (!Object.hasOwn(cur.stats, k) && Number.isFinite(v) && v >= 0) cur.stats[k] = v;
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
  // basis: how the value is known. A site's API says who wrote what: a join date and a list of
  // organisations are the site's record, a name or a bio was written by the account holder. A
  // value a tool parsed from a page is a tool report, because the tool cannot tell the two apart.
  const RECORD_KEYS = new Set(["Active since", "Organisations", "Languages"]);
  const fact = (p, k, v, source, url, api = false) => { if (p && v !== undefined && v !== null && String(v).trim()) p.facts.push(sealFact({ k, v: String(v), source, url, pid: p.id, basis: api ? (RECORD_KEYS.has(k) ? "record" : "self") : "tool" }, { subjects: [searched], secrets })); };
  const afact = (p, k, v, source, url) => fact(p, k, v, source, url, true);
  const lead = (p, kind, value, from) => { if (p && value && String(value).trim()) p.leads.push({ kind, value: String(value).trim(), from }); };
  const nameFact = (p, label, name, source, url, api = false) => { if (meaningfulName(name, [p?.handle, searched])) fact(p, label, name, source, url, api); };
  const cleanBio = (bio, flagged) => (flagged || !bio || looksBoilerplate(bio) ? "" : String(bio));

  // GitHub's API answer for the searched handle: the anchor for a username case.
  const gh = c.github;
  if (gh?.found && !failed(gh)) {
    const tw = String(gh.twitter_username || "").replace(/^@/, "");
    const p = put("GitHub", "GitHub", { url: gh.profile_url, name: gh.name, location: gh.location, bio: gh.bio, image: gh.avatar_url, created: gh.created_at, repos: gh.public_repos, followers: gh.followers, company: gh.company, emails: [gh.email].filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || ""))), api: true, anchor: type === "email" ? "" : "github", links: [tw && `https://x.com/${tw}`].filter(Boolean), websites: [gh.blog].filter(Boolean) });
    nameFact(p, "Name", gh.name, "GitHub", gh.profile_url, true);
    afact(p, "Location", gh.location, "GitHub", gh.profile_url);
    afact(p, "Employer", gh.company, "GitHub", gh.profile_url);
    afact(p, "Email", gh.email, "GitHub", gh.profile_url);
    afact(p, "Website", gh.blog, "GitHub", gh.blog);
    afact(p, "Bio", gh.bio, "GitHub", gh.profile_url);
    afact(p, "Active since", gh.created_at ? String(gh.created_at).slice(0, 10) : "", "GitHub", gh.profile_url);
    lead(p, "url", gh.blog, "GitHub website field");
    lead(p, "handle", tw, "GitHub Twitter field");
    lead(p, "email", gh.email, "GitHub public email");
    const dp = c.githubDeep;
    if (dp && !failed(dp) && dp.found !== false) {
      const ok = (k) => !dp.sections || !dp.sections[k] || dp.sections[k] === "ok";
      if (ok("orgs")) afact(p, "Organisations", (dp.orgs || []).map((o) => o.login).filter(Boolean).slice(0, 12).join(", "), "GitHub details", gh.profile_url);
      // The top_repos section also covers languages.
      if (ok("top_repos")) afact(p, "Languages", (dp.languages || []).slice(0, 8).join(", "), "GitHub details", gh.profile_url);
      for (const e of ok("commit_emails") ? (dp.commit_emails || []).slice(0, 5) : []) { afact(p, "Commit email", e.email, "GitHub details", gh.profile_url); lead(p, "email", e.email, `GitHub commit${e.repo ? ` in ${e.repo}` : ""}`); }
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
    const p = put("Gravatar", "Gravatar", { url: gr.profile_url, handle: slug, name: gr.name || display, location: gr.location, image: gr.avatar_url, api: true, anchor: type === "email" ? "gravatar" : "" });
    nameFact(p, "Name", gr.name || display, "Gravatar", gr.profile_url, true);
    afact(p, "Location", gr.location, "Gravatar", gr.profile_url);
    if (slug && norm(slug) !== norm(searched)) lead(p, "handle", slug, "Gravatar username");
  }

  // The profile sources: a site's own record for the handle (deep.js). They come before the
  // username tools, so for a site both know, the record's values are the ones kept. A picture is
  // already hashed by the server, so these profiles are never sent to the avatar comparison.
  const ps = readProfileSources(c.profiles);
  // A record Launchpad made by itself is not a claimed account: it is no profile, whoever read it.
  const unclaimed = new Set();
  for (const r of ps && !failed(ps) ? ps.profiles : []) {
    if (unclaimedProfile(r)) { unclaimed.add(`acct:${canonSite(r.site)}`); continue; }
    const bio = cleanBio(r.bio, false);
    const p = put(r.site, PROFILE_SOURCE, {
      url: r.url, handle: r.handle, name: r.name, location: r.location, bio, created: r.created, lastActive: r.last_active, company: r.company, siteNote: r.note,
      followers: r.followers, karma: r.stats.karma ?? null, repos: r.stats.repos ?? r.stats.public_repos ?? null,
      // An account the profile names is a link like any other. Only a proof or a verified link is
      // more: the other side has confirmed it (`proven`, see identity.js).
      links: [...r.links, ...r.accounts.map((a) => a.url)], websites: [r.website].filter(Boolean),
      emails: r.emails, accounts: r.accounts, items: r.items, stats: r.stats, proven: r.accounts.filter((a) => proofStrong(a.proof)).map((a) => ({ url: a.url, proof: a.proof })), api: true,
    });
    if (!p) continue;
    nameFact(p, "Name", r.name, r.site, r.url, true);
    afact(p, "Location", r.location, r.site, r.url);
    afact(p, "Employer", r.company, r.site, r.url);
    for (const e of r.emails) { afact(p, "Email", e, r.site, r.url); lead(p, "email", e, `${r.site} public email`); }
    afact(p, "Website", r.website, r.site, r.website);
    afact(p, "Bio", bio.slice(0, 160), r.site, r.url);
    afact(p, "Active since", r.created.slice(0, 10), r.site, r.url);
    lead(p, "url", r.website, `${r.site} website field`);
    const named = new Set([r.website, ...r.accounts.map((a) => a.url)].map(norm));
    for (const u of r.links) if (!named.has(norm(u))) lead(p, "url", u, `${r.site} profile`);
    for (const a of r.accounts) {
      const how = `${r.site} profile, ${PROOF_TEXT[a.proof]}`;
      lead(p, "url", a.url, how);
      if (a.handle) lead(p, "handle", a.handle, `${a.site} account, ${how}`);
    }
    if (r.avatar_hash) { p.avatarHash = r.avatar_hash; p.avatarDefault = r.avatar_default; if (!r.avatar_default) p.thumb = r.thumb; }
    p.avatarState = r.avatar_state; p.hashed = true;
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
  if (av && !failed(av)) for (const r of av.results || []) { const p = map.get(r.id); if (p && !p.hashed && r.hash && !r.error) { p.avatarHash = String(r.hash); p.avatarDefault = !!r.default; if (!r.default) p.thumb = safeThumb(r.thumb); } }
  for (const id of unclaimed) map.delete(id);
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
  return collectProfiles(c, target, type).filter((p) => !p.hashed && /^https:\/\//i.test(p.image)).map((p) => ({ id: p.id, url: p.image.slice(0, 600) })).slice(0, 30);
}

const inferType = (c, target) => (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(target ?? "").trim()) ? "email" : c?.hash ? "hash" : c?.phone ? "phone" : c?.nameSearch || c?.nameResult ? "name" : "username");
const dedupeFacts = (facts) => { const out = []; for (const f of facts) if (!out.some((x) => x.k === f.k && norm(x.v) === norm(f.v))) out.push(f); return out; };
// One fact per value, with how it is known: which kinds of knowledge it rests on, and on how many
// of the identity's profiles the same value stands. Two spellings of one name are one name.
function mergeFacts(facts, { weak = new Set() } = {}) {
  const out = [], idx = new Map();
  for (const f of facts) {
    const key = `${f.k}|${f.k === "Name" ? nameTokens(f.v).sort().join(" ") : norm(f.v)}`;
    let cur = idx.get(key);
    if (!cur) { cur = { f, src: [], basis: new Set(), pids: new Set() }; idx.set(key, cur); out.push(cur); }
    for (const x of String(f.source ?? "").split(", ")) if (x && !cur.src.includes(x)) cur.src.push(x);
    if (f.basis) cur.basis.add(f.basis);
    if (f.pid) cur.pids.add(f.pid);
  }
  return out.map(({ f, src, basis, pids }) => {
    const { pid, basis: _b, ...rest } = f;
    const how = factHow({ kinds: [...basis], sites: pids.size || 1, sources: src, weak: pids.size > 0 && [...pids].every((id) => weak.has(id)), commit: f.k === "Commit email" });
    return how ? { ...rest, how } : rest;
  });
}

// ---- leads ---------------------------------------------------------------------------
// Handles, addresses, domains and links found on profiles. One hop, started by a click.
// extra: leads that come from the address itself and not from a profile (emailAccountLeads), and
// the leads of a lookup made on a click for one row: an address on its commits, a link removed
// between two archived copies. Each of those carries `tied` from the standing of its row.
function buildLeads(c, target, type, profiles, rel, accountUrls, extra = []) {
  const out = new Map();
  const searched = norm(type === "email" ? emailParts(target).handle : String(target ?? "").replace(/^@/, ""));
  const add = (kind, value, from, source, tied = true) => {
    const k = `lead:${kind}:${norm(value)}`;
    const prev = out.get(k);
    if (prev) { if (!prev.from.includes(from)) prev.from.push(from); if (!prev.sources.includes(source)) prev.sources.push(source); prev.tied ||= tied; return; }
    out.set(k, { kind, value, from: [from], sources: [source], tied, key: k });
  };
  // A link: a page is a link lead, and a site that is not a platform is a domain lead as well. A
  // bare personal domain is a domain lead only; a platform's own front page is nowhere to look.
  const link = (value, from, source, tied) => {
    const parts = linkParts(value);
    if (!parts || accountUrls.has(parts.key)) return;
    if (!parts.platform) add("domain", parts.host, from, source, tied);
    if (parts.path) add("url", /^https?:/i.test(value) ? value : `https://${value}`, from, source, tied);
  };
  for (const p of profiles) {
    const r = rel.get(p.id);
    if (!r || r.tier === "different") continue;
    const tied = r.tier === "linked" || r.inPrimary;
    for (const l of p.leads) {
      if (l.kind === "handle") { const hv = l.value.replace(/^@/, ""); if (HANDLE_OK.test(hv) && norm(hv) !== searched) add("handle", hv, l.from, p.site, tied); }
      else if (l.kind === "email") { if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(l.value) && norm(l.value) !== norm(target)) add("email", l.value.toLowerCase(), l.from, p.site, tied); }
      else link(l.value, l.from, p.site, tied);
    }
  }
  for (const l of extra) {
    // A link found on an archived page: never one on an adult or dating site.
    if (l.kind === "url") { if (!adultHost(l.value)) link(l.value, l.from, l.source, l.tied); continue; }
    if (l.kind === "handle" && HANDLE_OK.test(l.value) && !l.value.startsWith("-") && (type === "email" || norm(l.value) !== searched)) add("handle", l.value, l.from, l.source, l.tied);
    else if (l.kind === "email" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(l.value) && norm(l.value) !== norm(target)) add("email", l.value.toLowerCase(), l.from, l.source, l.tied);
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
    source: l.sources.join(", "), key: l.key, lead: { kind: l.kind, value: l.value }, from: l.from, tied: l.tied,
    // via, source: what the pivot trail of the case this opens will say about the hop.
    action: l.kind === "handle" || l.kind === "email" ? { label: "Investigate this", pivot: "investigate", value: l.value, ...(l.kind === "handle" ? { type: "username" } : {}), via: `the ${WORD[l.kind]} ${l.value}`, source: l.from.join(", ") } : l.kind === "domain" ? { label: "Open in Recon", pivot: "recon", value: l.value, type: "domain", via: `the domain ${l.value}`, source: l.from.join(", ") } : null,
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
    if (!row) { row = { what: siteDisplay(cs) || String(site), url: "", key: `acct:${cs}`, sources: [], kinds: new Set(), notes: [] }; accounts.set(cs, row); items.push(row); }
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
  // --- profile sources: the site's own record was read -----------------------------------
  // First, so the record's address and the site's own name are the ones the row keeps.
  const ps = person ? readProfileSources(c.profiles) : null;
  for (const r of ps && !failed(ps) ? ps.profiles : []) addAccount(r.site, { source: PROFILE_SOURCE, url: r.url, kind: "read" });
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
  // The investigator's pick, when the case has one and it still names exactly one cluster.
  const pick = person ? readPick(c.pick) : null;
  const result = clusterIdentities(profiles, { handle: searched, pick: pick?.members, pickFile: pick?.file === true });
  const primary = result.clusters.find((x) => x.primary) || null;
  const archives = person ? readArchives(c.archives || {}) : {};
  // The three lookups made on a click for one read profile, each kept by row (deep.js).
  const commitEmails = person ? readCommitEmails(c.commitEmails || {}) || {} : {};
  const postActivity = person ? readPostActivities(c.postActivity || {}) || {} : {};
  const archiveDiffs = person ? readArchiveDiffs(c.archiveDiffs || {}) || {} : {};
  // rowLeads: what those lookups found to look at next. readings: the post activity that was
  // read, by row. aiCommits: the commit addresses the model is told (primary identity only).
  const rowLeads = [], readings = [], aiCommits = [];
  // A record Launchpad made by itself (see unclaimedProfile in deep.js): shown, and never an account of anybody's.
  const unclaimed = new Set((ps && !failed(ps) ? ps.profiles : []).filter(unclaimedProfile).map((r) => canonSite(r.site)));
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
  const evaluated = person && simBase ? evaluateSimilar(c.similar, ownProfiles, { handle: searched, own: simBase, name: primaryName, pick: pick?.members }) : {};
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
    } else if (unclaimed.has(row.key.slice(5))) {
      // Launchpad's record was read, and it is not an account anybody claimed. Unverified, with
      // its own words; no profile, so nothing below treats it as one.
      row.tier = "unverified"; row.unclaimed = true;
      row.meta = UNCLAIMED_META;
    } else if (p && r && row.kinds.has("read")) {
      row.tier = r.tier;
      const named = meaningfulName(p.name, [p.handle, searched]);
      const cl = clusterOf(p.id);
      if (p.anchor === "github") row.meta = ["GitHub's own record for this handle", named ? `name on profile: ${p.name}` : "", `${fmtNum(gh.public_repos)} repos`, `${fmtNum(gh.followers)} followers`].filter(Boolean).join(" · ");
      else if (p.anchor === "gravatar") row.meta = ["Gravatar's record for this email", named ? `name on profile: ${p.name}` : "", p.location].filter(Boolean).join(" · ");
      else row.meta = [row.similar ? `under the handle ${row.similar.variant}, added from a similar handle check (${row.similar.reason})` : "", "profile read", named ? `name on profile: ${p.name}` : r.tier === "matches" ? "no name on profile" : "", p.location, r.tier !== "different" && r.why && r.why !== "no name on the profile" ? r.why : "", p.evidence].filter(Boolean).join(" · ");
      // Another person's account: it stays in the ledger, with a check for the investigator and
      // why it is thought to be someone else. Never a claim that the two are unrelated.
      if (r.tier === "different") {
        row.person = cl?.label || p.name;
        const against = (r.against?.length ? r.against : [primary.label]).map((n) => `"${n}"`).join(" and ");
        row.relate = r.via
          ? `Check whether this account is connected to ${primary.label}. It is grouped with ${r.via}${r.tie ? ` (${r.tie})` : ""}, a name that conflicts with ${against}, and no link, picture or proof ties it to ${primary.label}.`
          : `Check whether this account is connected to ${primary.label}. The name on it, "${p.name}", conflicts with ${against}, and no link, picture or proof ties it to that identity.`;
        if (r.via) row.via = r.via;
        row.meta = [row.meta, `filed as a different person: check whether this account is connected to ${primary.label}`].filter(Boolean).join(" · ");
      } else if (r.unsettled && !row.similar) {
        const q = (l) => (l || []).map((n) => `"${n}"`).join(" and ");
        row.unsettled = { name: p.name, against: r.against || [], ...(r.mixed ? { mixed: true, fits: r.fits || [] } : {}) };
        // mixed: a one-word name of the identity fits this name and its full name conflicts with it.
        row.relate = r.mixed
          ? `Check whether this is the person you mean. The name on it, "${p.name}", fits the one-word name ${q(r.fits)} on a profile of the primary identity and conflicts with its full name ${q(r.against)}. Neither settles it, so it is not filed as a different person.`
          : `Check whether this is the person you mean. The name on it, "${p.name}", could not be compared: the primary identity carries only the one-word name ${q(r.against)}.`;
        row.meta = [row.meta, r.mixed ? "name not settled: it fits a one-word name of the primary identity and conflicts with its full name" : "name not compared: the primary identity has only a one-word name"].filter(Boolean).join(" · ");
      }
    } else if (row.kinds.has("taken")) {
      // In use according to the site's sign-up check. Unverified: nothing was read, nobody is named.
      row.tier = "unverified"; row.taken = true;
      row.meta = Object.hasOwn(TAKEN_TEXT, row.key.slice(5)) ? TAKEN_TEXT[row.key.slice(5)] : TAKEN_GENERIC;
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
        : read ? (r.tier === "different" ? [p.anchor === "github" ? "GitHub's own record for this handle" : p.anchor === "gravatar" ? "Gravatar's record for this email" : "", r.via ? `grouped with ${r.via}, whose name conflicts with ${primary?.label || "the primary identity"}` : `the name on it conflicts with ${primary?.label || "the primary identity"}`].filter(Boolean).join(", and ")
          : p.anchor === "github" ? "GitHub's own record for this handle" : p.anchor === "gravatar" ? "Gravatar's record for this email"
            : r.why && r.why !== "no name on the profile" ? r.why : named ? "" : "no name on the profile")
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
      // A record nobody claimed: the card says what Launchpad's record is, and shows nothing from it.
      if (row.unclaimed) row.card = { handle: String(searchedHandle || ""), facts: [], bio: "", basis: UNCLAIMED_TEXT, why: "", note: "" };
      if (read && p.note === "suspended") row.card.note = "The site marks this account as suspended.";
      // The site's record came back in part ("bio not read"). What was not read is unknown: the
      // card says so, and never words it as a profile with no bio.
      // A note the page knows (moved, a team, an organization, suspended, automated) is said in the
      // page's own sentence, and the row carries the note's code as `siteNote`.
      if (read && p.siteNote && !row.similar) {
        const known = profileNoteText(p.siteNote);
        if (known) row.siteNote = p.siteNote;
        row.card.note = [row.card.note, known ? (p.siteNote === "suspended" && p.note === "suspended" ? "" : known) : /not read$/.test(p.siteNote) ? `${p.site} answered in part: ${p.siteNote}. That part is unknown, not empty.` : `${p.site} notes: ${p.siteNote}${/[.!?]$/.test(p.siteNote) ? "" : "."}`].filter(Boolean).join(" ");
        if (/carries no name, bio or dates/.test(row.card.basis || "")) row.card.basis = `Profile record read by ${row.sources.join(", ")}.`;
      }
      if (row.similar) row.card.why = "";
      if (read && row.relate && !row.similar) row.card.check = row.relate;
      // What the record carries beyond the one line: opened on the row, with how each value is known.
      if (read && !row.similar) { const d = profileDetail({ ...p, fullName: named, fullBio: p.bio }, { secrets }); if (d) row.detail = d; }
      if (read && row.similar) row.card.note = [`Added from the similar handle ${row.similar.variant}: ${row.similar.reason}.`, row.card.note].filter(Boolean).join(" ");
      if (p?.thumb) row.thumb = p.thumb;
      // Archived copies can be asked for a profile a source read, on a click, one profile at a
      // time. Never for an address with a query (the snapshot address would carry it) and never
      // for an adult or dating site: archivable() in deep.js. An answer is shown on the row.
      if (read && !row.similar && row.link_kind === "verified_profile" && archivable(row.url)) { const a = archives[row.key]; row.archive = { url: row.url, ...(a && a.url === row.url ? { view: archiveView(a) } : {}) }; }
      // Three more lookups on a click, each for one read profile and never for an adult or dating
      // site. can*: what the page sends when the button is pressed (the row is on a site the
      // lookup reads). An answer is shown on the row when it is about this row's account. What an
      // answer leads to is tied to the person only as far as the row is, and a row filed as a
      // different person gives no lead and no fact.
      if (read && !row.similar && row.link_kind === "verified_profile" && !adultHost(row.url)) {
        const who = { url: row.url, handle: p.handle, siteNote: p.siteNote };
        const tied = r.tier === "linked" || r.inPrimary, other = r.tier === "different";
        const sameName = (a, b, exact = false) => (exact ? String(a) === String(b) : norm(a) === norm(b));
        const ce = commitEmailsFor(who), ca = ce ? commitEmails[row.key] : null;
        if (ce) row.canCommitEmails = ce;
        if (ca && ca.site === ce.site && sameName(ca.username, ce.username) && (!ca.profile_url || linkParts(ca.profile_url)?.key === linkParts(row.url)?.key)) {
          row.commitEmails = commitEmailsView(ca);
          if (!other) for (const l of commitEmailLeads(ca)) rowLeads.push({ kind: "email", value: l.value, from: `${l.from}${/self-declared/.test(l.from) ? "" : ", self-declared"}`, source: COMMIT_EMAILS_SOURCE, tied });
          // A fact only for a profile of the primary identity, and marked as what it is: typed
          // into a commit by its author. The weaker tie says so in its source. It links to a
          // repository the address was seen in, where the commits can be read.
          if (tied) {
            for (const e of row.commitEmails.rows.slice(0, 5)) p.facts.push(sealFact({ k: "Commit email", v: e.email, source: `${ca.site_name} commits${e.strong ? "" : " (author line only)"}`, url: e.repos[0]?.url || "", pid: p.id, basis: "self" }, { subjects: [searchedHandle], secrets }));
            const ai = commitEmailsForAi(ca);
            if (ai) aiCommits.push(ai);
          }
        }
        const pa = postActivityFor(who), pv = pa ? postActivity[row.key] : null;
        if (pa) row.canPostActivity = pa;
        // Hacker News names are case sensitive, so there the answer must be about the exact name.
        if (pv && pv.site === pa.site && (pv.instance || "") === (pa.instance || "") && sameName(pv.username, pa.username, pa.site === "hackernews")) {
          row.postActivity = postActivityView(pv);
          readings.push({ key: row.key, kind: "post", label: postActivityLabel(pv), answer: pv, view: row.postActivity, tied, tier: r.tier, person: row.person || "" });
        }
        // Two archived copies can be compared once the archive listed two or more captures.
        // The server needs a handle with every comparison (its minor guard files the text under
        // it): the case's own in a username case, the row's own in an email case. A row with no
        // handle the server would take is not offered the comparison.
        const pairs = row.archive?.view?.state === "ok" ? archiveDiffPairs(archives[row.key]) : [];
        const diffUser = [type === "email" ? p.handle : searchedHandle].map((x) => String(x || "").trim().replace(/^@/, "")).find((x) => /^[A-Za-z0-9._-]{1,64}$/.test(x) && !x.startsWith("-")) || "";
        if (pairs.length && diffUser) {
          row.archiveDiffPairs = pairs;
          row.archiveDiffUser = diffUser;
          const d = archiveDiffs[row.key];
          if (d && d.url === row.url) {
            row.archiveDiff = archiveDiffView(d, { subjects: [searchedHandle, p.handle].filter(Boolean), secrets });
            if (!other) for (const l of archiveDiffLeads(d, { site: row.what })) rowLeads.push({ kind: "url", value: l.value, from: l.from, source: ARCHIVE_SOURCE, tied });
          }
        }
      }
    }
    // The tools that reported the row. For Reddit and Discord the platform check asked the site
    // itself, so it is not one of them.
    if (r?.inPrimary) row.inPrimary = true;
    row.tools = row.sources.filter((x) => !(row.pcOwn && x === "Platform check")).length;
    if (row.taken || row.unclaimed || (row.pcOwn && row.tier === "unverified" && !row.tools)) row.nofind = true;
    markUnsendable(row);
    delete row.kinds; delete row.notes; delete row.readUrl; delete row.relate;
  }

  // --- similar handles: one row per variant, after the leads ------------------------------
  if (person && simBase) {
    const snippet = (sp) => { const sn = cardSnippet({ sources: [SIMILAR_SOURCE], kinds: ["read"] }, { ...sp, shownName: meaningfulName(sp.name, [sp.profile.handle, searched]) ? sp.name : "", repos: null }); return { facts: sn.facts, bio: sn.bio }; };
    for (const r of similarItems({ handle: simBase, name: primaryName, evaluated, snippet })) items.push(r);
  }

  // --- an email case: the accounts and keys behind the address (deep.js) -----------------
  // Built on their own: an account GitHub ties to the address is a row and a lead, never a
  // profile, so it joins no cluster and names nobody. Its facts are about the address.
  if (type === "email") {
    for (const r of emailAccountItems(c.emailAccounts)) items.push(r);
    for (const f of emailAccountFacts(c.emailAccounts)) fact(f.k, f.v, f.source, f.url);
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
    for (const l of buildLeads(c, target, type, profiles, rel, urls, [...(type === "email" ? emailAccountLeads(c.emailAccounts, target) : []), ...rowLeads])) items.push(l);
  }

  for (const it of items) if (it.sources) {
    it.source = it.sources.join(", ");
    // Two tools agreeing is worth saying, but it is still not verification.
    // Not for a row the platform check asked itself: it did not "report" the handle.
    if (it.tier === "unverified" && !it.taken && !it.unclaimed && (it.tools ?? it.sources.length) > 1 && it.key?.startsWith("acct:")) it.meta = [it.meta, `reported by ${it.tools ?? it.sources.length} tools`].filter(Boolean).join(" · ");
  }
  for (const it of items) { delete it.srcUrl; sealLink(it, { subjects: [searchedHandle], secrets }); }
  // A row whose page was not found stays in its group, at the end.
  items.sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || (a.gone ? 1 : 0) - (b.gone ? 1 : 0) || (!a.key?.startsWith("acct:") || !b.key?.startsWith("acct:") ? 0 : (b.sources?.length || 1) - (a.sources?.length || 1) || a.what.localeCompare(b.what)));

  // --- identity views: whose facts "What we know" can show ------------------------------
  // A profile added from a similar handle is named with that handle, so it is never read as the target's.
  const siteName = (p) => (p?.similar ? `${p.site} (${p.handle})` : p?.site);
  const sitesOf = (ids) => ids.map((id) => siteName(byId.get(id))).filter(Boolean);
  // The facts of one identity, each with how it is known. A profile joined to the identity by its
  // name only is weaker ground than one tied by a link, a picture or a proof, and a fact that
  // rests on such profiles alone says so.
  const viewFacts = (cl, ids) => mergeFacts(ids.flatMap((id) => byId.get(id)?.facts || []), { weak: cl && cl.members.length > 1 ? new Set(cl.members.filter((id) => id !== cl.anchorId && !cl.strongIds.includes(id))) : new Set() });
  const autoCl = result.clusters.find((cl) => cl.id === result.auto) || null;
  const views = result.clusters.map((cl) => ({
    // different: at least one of its profiles carries a name that conflicts with the primary identity.
    // picked: the investigator chose this identity. auto: the rules would choose it. members: the
    // ids a pick of this identity stores.
    id: cl.id, label: cl.label, named: cl.named, primary: cl.primary, picked: !!cl.picked, auto: cl.id === result.auto, pickable: true, anchor: cl.anchor || "", members: cl.members,
    different: cl.members.some((id) => rel.get(id)?.tier === "different"), why: cl.why || "", sites: sitesOf(cl.members), names: cl.names, locations: cl.locations, thumb: cl.members.map((id) => byId.get(id)?.thumb).find(Boolean) || "",
    signals: cl.links.flatMap((l) => l.signals.map((s) => ({ ...s, a: siteName(byId.get(l.a)), b: siteName(byId.get(l.b)) }))),
    facts: viewFacts(cl, cl.members),
  }));
  // Profiles with no name are a set of unrelated accounts, not a person: they can be shown, and
  // they cannot be picked as the person the case is about.
  if (result.unassigned.length) views.push({ id: "unassigned", label: "Profiles with no name", named: false, primary: false, picked: false, auto: false, pickable: false, anchor: "", members: result.unassigned, why: "", sites: sitesOf(result.unassigned), names: [], locations: [], thumb: "", signals: [], facts: viewFacts(null, result.unassigned) });
  // noPrimary: profiles were read, but there is no anchor and no strong signal, and nobody was picked.
  // picked: the primary identity is the investigator's choice. auto, autoLabel, autoWhy: what the
  // rules would choose, so the page can always say which of the two it is showing.
  const identity = { views, primary: primary ? primary.id : null, people: views.filter((v) => v.named).length, noPrimary: !primary && views.length > 0,
    picked: !!result.picked, pickFile: !!(result.picked && pick?.file), auto: result.auto, autoLabel: autoCl ? autoCl.label : "", autoWhy: result.autoWhy || "" };
  // Without a primary identity no person's facts are shown as the target's.
  const facts = dedupeFacts([...(views.find((v) => v.primary)?.facts || []), ...general]);
  // added: the facts of the profiles added from a similar handle, kept apart from every identity.
  const addedFacts = addedList.map((p) => ({ id: p.id, label: `${p.site} (${p.handle})`, facts: p.facts })).filter((a) => a.facts.length);
  // --- when the accounts are active: every reading the case holds, and whose each one is -----
  // own: the readings of the primary identity (GitHub's while that account is the case's own, and
  // post activity for a row that is Linked or part of the primary identity). other: the rest,
  // each with the sentence that says whose activity it is. Only `own` is compared, written into
  // the assessment or sent to the model.
  const who = primary ? primary.label : "the person this case is about";
  const reading = (x, own, note) => ({ key: x.key, kind: x.kind, label: x.label, heading: `${x.kind === "github" ? "GitHub activity" : `${x.label} post activity`}${own ? "" : " (not the person this case is about)"}`, own, note: own ? "" : note, standing: { own, text: own ? "" : note }, state: x.view.state, view: x.view, answer: x.answer });
  const all = [];
  const ghAct = type === "username" ? readActivity(c.githubActivity) : null, ghView = ghAct ? activityView(ghAct) : null;
  if (ghView) { const st = githubStanding({ items, identity }); all.push(reading({ key: "acct:github", kind: "github", label: "GitHub", answer: ghAct, view: ghView }, st.own, st.text)); }
  for (const x of readings.sort((a, b) => a.label.localeCompare(b.label))) all.push(reading(x, x.tied, x.tier === "different"
    ? `This is the post activity of the ${x.label} account, which the findings file as a different person${x.person ? ` (${x.person})` : ""}. It is that account's, not ${who}'s.`
    : `This is the post activity of the ${x.label} account. Nothing ties that account to ${who}, so it is not read as theirs.`));
  const activity = { own: all.filter((x) => x.own), other: all.filter((x) => !x.own) };
  const offsets = compareOffsets(activity.own.map((x) => ({ label: x.label, answer: x.answer })));
  return { items, facts, general: dedupeFacts(general), identity, type, similarLine: similarBrief(evaluated), added: addedFacts, activity, offsets, commitsForAi: aiCommits };
}

// What the row and the card of a Launchpad record nobody claimed say (the pill word is in present.js).
export const UNCLAIMED_META = "not a claimed account: Launchpad made this record by itself";
export const UNCLAIMED_TEXT = profileNoteText(NOT_ACTIVE_NOTE).replace(/^Not a claimed account\.\s*/, "");
export const UNCLAIMED_NOTE = "not a claimed account, made by the site itself";

// ---- when the accounts are active --------------------------------------------------------------
// The activity readings of a case, as buildEvidence filed them:
//   { own: [reading], other: [reading] }
//   reading: { key, kind: "github" | "post", label, heading, own, note, standing: { own, text },
//              state, view, answer }
//     view     what one renderer draws for GitHub's reading and a post site's (activityView and
//              postActivityView in deep.js return the same keys)
//     heading  the title above it; note: whose activity it is, for a reading that is not the
//              primary identity's ("" when it is)
//     answer   the checked reading, for the exports
// own holds the readings of the primary identity; they are the only ones compared.
const NO_READINGS = { own: [], other: [] };
export const activityReadings = (ev) => ev?.activity || NO_READINGS;
// Do the UTC offset ranges of the primary identity's readings fit together? compareOffsets in
// deep.js: { verdict: "agree" | "disagree" | "not_enough_data", compared, shared, label, labels,
// text, caution }. A hint either way, never a place, and it moves no profile between identities.
export const offsetComparison = (ev) => ev?.offsets || compareOffsets([]);

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
  { id: "different",  title: "Exists (different person)", cls: "",          open: false, blurb: "A profile was read, and the name on it conflicts with the primary identity. These are other people who use the same handle. Nothing is removed: each row asks you to check whether that person is connected to the one this case is about." },
  { id: "unverified", title: "Unverified",                cls: "",          open: true,  blurb: "A tool reported the handle and nothing was read, or the site blocked the check. Many sites answer yes to any name. Open and check before relying on one." },
  { id: "adult",      title: ADULT_GROUP,                 cls: "",          open: false, blurb: `${ADULT_NOTICE} Each row says how it is known. Nothing here is tied to the target, and no picture or post is ever loaded.` },
  { id: "lead",       title: "Leads from profiles",       cls: "",          open: true,  blurb: "Handles, addresses, domains and links found on the profiles above. Each says where it came from. They are places to look next, not findings about this target, and nothing is followed until you click." },
  // aside: a group that is offered beside the findings. It does not stand in for "nothing found".
  { id: "similar",    title: SIMILAR_GROUP,               cls: "",          open: false, aside: true, blurb: SIMILAR_BLURB },
  { id: "hosts",      title: "Hosts on this domain",      cls: "",          open: false, limit: 300, blurb: "Hostnames on the email's domain, from public sources. This is the organisation's inventory. It says nothing about the person." },
  { id: "noise",      title: "Known noisy sites",         cls: "",          open: false, limit: 40, blurb: "Sites that answer yes to any username. Kept for completeness." },
];
// The same tiers with the host group named after the email's domain. A name case has groups of its own and none of the others (see names.js).
// An email case words two groups for what they hold there: a record ties an account or a key to
// the ADDRESS (not to a person), and a search match that nothing read is unverified.
const EMAIL_BLURB = {
  linked: "Tied to this address by a record: an account GitHub attributes commits with the address to, a key the key server verified for it by mail, a site whose sign-up check answered for it, or Gravatar's record for it. A profile tied to that identity by a strong signal is here too. Each row says which.",
  unverified: "Reported, and nothing was read: an account GitHub's search matched to this address without its profile being read, commits GitHub ties to no account, and other addresses on the same domain. Open and check before relying on one.",
};
export const ledgerTiers = (target, type) => type === "name" ? NAME_TIERS.map((t) => ({ ...t })) : type === "phone" ? PHONE_TIERS.map((t) => ({ ...t })) : TIERS.map((t) => (t.id === "hosts" && type === "email" && emailParts(target).domain ? { ...t, title: `Hosts on ${emailParts(target).domain}` } : type === "email" && Object.hasOwn(EMAIL_BLURB, t.id) ? { ...t, blurb: EMAIL_BLURB[t.id] } : t));

// The account rows the AI prompt and the report use, so they match the screen exactly.
// status is the tier id: linked, matches, different or unverified.
export const accountsFor = (items) => items.filter((i) => i.key?.startsWith("acct:") && ACCOUNT_TIERS.includes(i.tier))
  .map((i) => ({ site: String(i.what).slice(0, 120), url: i.link_kind === "none" ? "" : String(i.url || "").slice(0, 600), link_kind: i.link_kind || "none", ...(i.check ? { link_check: i.check } : {}), status: i.tier, sources: (i.sources || [i.source]).slice(0, 8).map(String),
    // A taken handle is told as that: no profile was read and the owner is unknown.
    // A record Launchpad made by itself is told as that: it is nobody's claimed account.
    note: i.taken ? TAKEN_NOTE : i.unclaimed ? UNCLAIMED_NOTE : i.tier === "unverified" ? "" : String(i.meta || "").slice(0, 200),
    // A profile added from a similar handle is under another handle than the target's.
    ...(i.similar ? { handle: String(i.similar.variant).slice(0, 64) } : {}) }));
export const tierCounts = (items) => Object.fromEntries(ACCOUNT_TIERS.map((t) => [t, items.filter((i) => i.key?.startsWith("acct:") && i.tier === t).length]));

// ---- whose GitHub account is it --------------------------------------------------------------------
// GitHub's record, its details and its activity describe one account. They are the case's own only
// while that account is the person the case is about: its row is Linked, or it sits in the primary
// identity. After a pick of somebody else the same data is another person's. It can still be
// seen, labelled as that; it is never written into the brief, the timeline or the AI's input as
// the target's. One function, so every reader of the GitHub data asks the same question.
//   { own, tier, text }   text: the sentence the page and the exports put above the data when
//                         the account is not the case's ("" when it is)
export function githubStanding(ev) {
  const row = (ev?.items || []).find((i) => i.key === "acct:github") || null;
  const main = (ev?.identity?.views || []).find((v) => v.primary) || null;
  const own = !!row && (row.tier === "linked" || row.inPrimary === true);
  const who = main ? main.label : "the person this case is about";
  const text = own ? "" : !row ? "This case holds no GitHub profile record, so nothing ties this account to the person the case is about."
    : row.tier === "different" ? `This is the activity of the GitHub account, which the findings file as a different person${row.person ? ` (${row.person})` : ""}. It is that account's, not ${who}'s.`
      : `This is the activity of the GitHub account. Nothing ties that account to ${who}, so it is not read as theirs.`;
  return { own, tier: row ? row.tier : "", text };
}

// What is kept of a case in History, whoever asks and whenever: guard-only text is removed and the
// record sources are in their checked, bounded shape. A save in the middle of a run (a step is
// parked, a note is typed) stores the same cleaned form as the save at the end.
export const storedCase = (collected) => readDeep(stripGuard(collected));

// Everything the model is told about a case. Sources are sent without their adult and dating
// site rows. Those travel only as `adult_sites` (site, category, state and link kind: no names,
// no bios, no URLs), only for a case that had the mode on, and never inside `accounts`.
// The assessment, the suggestions and the trail of one case, from the same evidence the ledger
// shows. One function, so the page, the exports and the AI payload cannot drift apart.
//   failed: the names of the sources that failed (from the source tally)
export function caseAnalysis(ev, { collected, target, type, failed = [] } = {}) {
  const c = withoutAdult(collected);
  return { assessment: assessCase(ev, { collected: c, type, failed }), // The guard's block is read from the case as it is: the adult-free view does not carry it.
    suggestions: suggestNext(ev, { collected: collected?.adultBlock != null ? { ...c, adultBlock: collected.adultBlock } : c, target, type, failed }), trail: trailView(c.trail, target, type) };
}

//   failed         the names of the sources the page's tally calls failed. The page passes them, so
//                  the assessment the model reads is built from the same list as the one on screen
//                  (a source "blocked by every site" is failed too). Without it they are read
//                  from source_status: every value that starts "failed" or "blocked".
//   profileScrape  a Deep Dive's page reads, sent as profile_scrape
// Per-site data travels beside `accounts` (a name, a bio, a location, as each source returned
// them). It is sent only for an account the ledger does not file as a different person: another
// person's name and bio are not the model's to read as the target's. GitHub's record, details and
// activity are sent only while that account is the case's own (githubStanding); otherwise the
// model is told the account is not the target's, in `github_not_target`, and gets none of it.
export function aiPayloadFor(collected, target, type, { source_status = {}, active = false, failed: failedNames = null, profileScrape = null } = {}) {
  const c = withoutAdult(collected);
  const ev = buildEvidence(collected, target, type), { items } = ev;
  const adult = adultAllowed(collected, target, type);
  // The rule-based assessment, the identity choice and how the case was reached, so the model
  // starts from what the page already worked out. A pick is named as the investigator's judgment.
  const down = Array.isArray(failedNames) ? failedNames.map(String) : Object.entries(source_status).filter(([, v]) => /^(failed|blocked)/.test(String(v))).map(([k]) => k);
  const analysis = caseAnalysis(ev, { collected, target, type, failed: down });
  const forAi = analysisForAi(analysis.assessment, ev.identity, trailText(analysis.trail));
  const person = type === "username" || type === "email";
  const tierOf = (site) => (person ? items.find((i) => i.key === `acct:${canonSite(site)}`)?.tier || "" : "");
  const other = (site) => tierOf(site) === "different";
  const rowsOf = (d, key) => (d && typeof d === "object" && Array.isArray(d[key]) ? d[key].filter((r) => r && typeof r === "object") : null);
  const gh = githubStanding(ev), ghData = !!(c.github || c.githubDeep || c.githubActivity), ghOwn = !person || !ghData || gh.own;
  // Rows that belong to another person keep the site and the state, and lose what was read on them.
  const enricher = rowsOf(c.enricher, "profiles") ? { ...c.enricher, profiles: rowsOf(c.enricher, "profiles").filter((p) => !other(p.platform)) } : c.enricher || null;
  const platform = rowsOf(c.platformCheck, "results") ? { ...c.platformCheck, results: rowsOf(c.platformCheck, "results").map((r) => (other(r.platform) ? { platform: r.platform, url: r.url, state: r.state } : r)) } : c.platformCheck || null;
  const maigret = rowsOf(c.maigret, "results") ? { ...c.maigret, results: rowsOf(c.maigret, "results").map((r) => { if (!other(r.site || r.name)) return r; const { profile, ...rest } = r; return rest; }) } : c.maigret || null;
  const scrape = rowsOf(profileScrape, "results") ? { ...profileScrape, results: rowsOf(profileScrape, "results").filter((r) => !other(r.site)) } : null;
  return {
    target, target_type: type, accounts: accountsFor(items),
    source_status: adult ? source_status : Object.fromEntries(Object.entries(source_status).filter(([k]) => k !== ADULT_SOURCE)),
    hash: c.hash || null, phone: phoneForAi(c.phone), github_deep: ghOwn ? c.githubDeep || null : null,
    sherlock: c.sherlock || null, maigret, holehe: c.holehe || null, harvester: c.harvester || null, hibp: c.hibp || null,
    gravatar: other("Gravatar") ? null : c.gravatar || null, github: ghOwn ? c.github || null : null, enricher, platform_check: platform,
    ...(ghOwn ? {} : { github_not_target: gh.tier === "different" ? "different" : gh.tier === "matches" ? "matches" : "unread" }),
    ...(scrape ? { profile_scrape: scrape } : {}),
    hunter: c.hunter || null, name_search: c.nameSearch ? { name: c.nameSearch } : null, active_techniques: !!active,
    // The three record sources, each value marked by how it is known (see deepForAi).
    ...deepForAi(c, items, type, ev),
    ...(forAi && (type === "username" || type === "email") ? { case_analysis: forAi } : {}),
    // A name case: the candidates as the screen shows them. Absent for every other case.
    ...(type === "name" && nameForAi(c, target) ? { name_candidates: nameForAi(c, target) } : {}),
    ...(adult ? { adult_sites: adultForAi(items.filter((i) => i.tier === "adult")) } : {}),
    // A case the minor guard stopped: the model is told that the group was skipped and on which
    // site the sign was. The quoted text is never sent.
    ...(type === "username" && blockForAi(collected) ? { adult_block: blockForAi(collected) } : {}),
  };
}

// The profile sources, the accounts and keys behind an address, and GitHub activity, as the model
// is told them. Absent when the source did not run or failed (a failure is in source_status).
//   profile_sources   one entry per record read, with the standing its ledger row has, the values
//                     the account holder wrote, the values the site recorded, and every site that
//                     did not answer (unknown, never "not found"). A record the ledger files as
//                     a different person is sent as its site and that status, and nothing else:
//                     another person's name, bio, location, addresses and accounts stay here.
//   email_accounts    emailAccountsForAi: self-declared values carry that in the field name
//   github_activity   activityForAi: counts by UTC hour, and an offset range that is never a place.
//                     Only while the GitHub account is the case's own (see githubStanding).
// And, from `ev` (the result of buildEvidence), what the lookups made on a click found, for the
// rows of the primary identity only (Linked, or part of it):
//   post_activity     at most 3 readings (postActivityForAi): the site, counts by UTC hour, the
//                     page's own sentences, and an offset range that is never a place
//   offset_comparison whether those ranges and GitHub's fit together: the verdict, the accounts
//                     compared, the shared range and the page's sentence and caution. Absent
//                     when fewer than two readings carry a range.
//   commit_emails     at most 4 accounts (commitEmailsForAi): at most 5 addresses each, every one
//                     with its tie and `self_declared: true`
// A Launchpad record nobody claimed is not sent as a profile: it is one line among the notes.
// Archive diff text and the self-audit are never sent.
export function deepForAi(c, items, type, ev = null) {
  const out = {};
  const ps = type === "username" ? readProfileSources(c.profiles) : null;
  if (ps && !failed(ps)) {
    const cov = profileCoverage(ps);
    out.profile_sources = {
      profiles: ps.profiles.filter((r) => !unclaimedProfile(r)).map((r) => ({ r, status: items.find((i) => i.key === `acct:${canonSite(r.site)}`)?.tier || "unverified" })).map(({ r, status }) => (status === "different" ? { site: r.site, status } : {
        site: r.site, url: r.url, handle: r.handle, status,
        self_declared: Object.fromEntries(Object.entries({ name: r.name, bio: r.bio, location: r.location, company: r.company, website: r.website, public_emails: r.emails.join(", "), listed_accounts: r.accounts.filter((a) => !proofStrong(a.proof)).map((a) => `${a.site} ${a.handle} ${a.url}`.replace(/\s+/g, " ")).join("; ") }).filter(([, v]) => v)),
        site_record: Object.fromEntries(Object.entries({ joined: r.created.slice(0, 10), last_active: r.last_active.slice(0, 10), ...r.stats, proven_accounts: r.accounts.filter((a) => proofStrong(a.proof)).map((a) => `${a.site} ${a.handle} ${a.url} (${PROOF_TEXT[a.proof]})`.replace(/\s+/g, " ")).join("; "), items: r.items.slice(0, 12).map((i) => `${i.kind} ${i.name}`).join(", ") }).filter(([, v]) => v !== "" && v !== null && v !== undefined)),
      })),
      not_found: cov.by.not_found || [],
      not_answered: cov.down.map((x) => `${x.site}: ${PROFILE_STATE_WORD[x.state]}`),
      notes: [...ps.profiles.filter(unclaimedProfile).map((r) => `${r.site}: a record exists under this handle that is not a claimed account. The site made it by itself, so it is not the target's account and says nothing about who holds the name`), ...cov.notes.map((x) => `${x.site}: ${x.note}`)],
    };
  }
  const ea = type === "email" ? emailAccountsForAi(c.emailAccounts) : null;
  if (ea) out.email_accounts = ea;
  const ghRow = items.find((i) => i.key === "acct:github");
  const act = type === "username" && ghRow && (ghRow.tier === "linked" || ghRow.inPrimary === true) ? activityForAi(c.githubActivity) : null;
  if (act) out.github_activity = act;
  if (ev && (type === "username" || type === "email")) {
    const posts = activityReadings(ev).own.filter((x) => x.kind === "post").slice(0, 3).map((x) => postActivityForAi(x.answer)).filter(Boolean);
    if (posts.length) out.post_activity = posts;
    const cmp = offsetComparison(ev);
    if (cmp.verdict !== "not_enough_data") out.offset_comparison = { verdict: cmp.verdict, accounts: cmp.labels.slice(0, 6), shared_range: cmp.label, text: cmp.text, caution: cmp.caution };
    const commits = (ev.commitsForAi || []).slice(0, 4);
    if (commits.length) out.commit_emails = commits;
  }
  return out;
}

// What an AI report was written from. Two runs with the same signature get the same report, so a
// re-run can reuse the last one. Computed from the case it is given, never from the one on screen.
export function aiSignature(collected, target, type) {
  const ev = buildEvidence(collected, target, type), { items, facts, identity } = ev;
  // A picked identity is part of what the report was written from. Only then, so an older case
  // keeps the signature it had.
  return JSON.stringify([...(identity.picked ? [["picked", identity.primary]] : []), accountsFor(items), items.filter((i) => i.tier === "flag").map((i) => i.key), facts.map((f) => [f.k, f.v]),
    adultForAi(items.filter((i) => i.tier === "adult")), type === "name" ? nameForAi(withoutAdult(collected), target) : null, ...(type === "username" && blockForAi(collected) ? [blockForAi(collected)] : []),
    // Only when the case has one of the record sources, so an older case keeps the signature it had.
    ...((d) => (Object.keys(d).length ? [d] : []))(deepForAi(withoutAdult(collected), items, type, ev))]);
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

// "Reduce your footprint": the self-audit of a case the investigator marked "This is me"
// (collected.selfAudit, see casework.js), built by rules in selfaudit.js. Only then, and only for
// a username or an email case. The section says whose statement that is.
export const FOOTPRINT_HEADING = "Reduce your footprint";
export const FOOTPRINT_NOTE = "The investigator marked this case as being about themselves (\"This is me\"). That is their own statement, not a finding of the tool.";
function footprintMarkdown(ev, collected, target, type) {
  if (!selfAuditOn(collected, type)) return [];
  const made = selfAuditMarkdown(selfAudit(ev, collected, { target, type }));
  const lines = (Array.isArray(made) ? made : String(made ?? "").split("\n")).map(String);
  // The builder may bring a heading of its own: the section then starts there.
  const body = /^##\s/.test(lines[0] || "") ? lines.slice(1) : lines;
  while (body.length && !body[0].trim()) body.shift();
  while (body.length && !body.at(-1).trim()) body.pop();
  return [`## ${FOOTPRINT_HEADING}`, `_${FOOTPRINT_NOTE}_`, ...(body.length ? body : ["- Nothing in this case calls for a step."]), ""];
}

// The Markdown export of a case. Adult and dating site rows come after every other finding,
// under their own heading, and only exist for a case that had the mode on.
// timeline: the events of personTimeline (timeline.js), passed in by the page. Each line says
// whether its date is a record or self-declared.
export function caseMarkdown({ collected, target, type, ran = 0, tallyLine = "", failed = [], purpose = "", ai = null, deep = null, notes = "", now = new Date(), timeline = [] }) {
  const ev = buildEvidence(collected, target, type), { items, facts, identity, added = [] } = ev;
  const c0 = withoutAdult(collected);
  const analysis = caseAnalysis(ev, { collected, target, type, failed: failed.map((f) => f.name) });
  const factLine = (f) => `- **${f.k}:** ${mdLink(f, f.v)} _(${f.source}${f.how ? ` · ${f.how.prov} · ${f.how.text}` : ""})_`;
  const choice = identity.picked ? `_The primary identity was picked by the investigator${identity.pickFile ? " (in the case file)" : ""}. That is a judgment, not a finding. ${identity.autoLabel ? `The automatic choice would be ${identity.autoLabel}, because ${identity.autoWhy}.` : "Automatically nobody would be chosen."}_` : identity.primary ? `_The primary identity was chosen automatically because ${identity.autoWhy}._` : "";
  // A site or a lookup that did not answer is listed, so the export never reads as a clean negative.
  const downSites = type === "username" ? profileCoverage(c0.profiles).down : [];
  const downLookups = type === "email" ? emailLookupsDown(c0.emailAccounts) : [];
  const main = identity.views.find((v) => v.primary);
  const others = identity.views.filter((v) => v.named && !v.primary);
  const adult = items.filter((i) => i.tier === "adult");
  return [`# CrawlR case: ${target}`, `Generated ${now.toISOString()} · ${TYPE_LABEL[type]}${ran ? ` · collected ${new Date(ran).toISOString()}` : ""}`, tallyLine, "", ...(purpose ? [`**Purpose:** ${purpose}`, ""] : []),
    "> Findings come from third-party public sources and can be wrong. Unverified items are leads, not facts. A link marked (unverified URL) is a site address built from the handle that nothing has checked. A profile that exists is not proof of who owns it, and leads are places to look, not findings.", "",
    ...trailMarkdown(analysis.trail),
    ...(failed.length ? ["## Sources that failed", ...failed.map((f) => `- **${f.name}:** ${f.text} (unknown, not a negative result)`), ""] : []),
    ...(downSites.length || downLookups.length ? ["## Lookups that did not answer", ...downSites.map((x) => `- **${x.site}** (${PROFILE_SOURCE}): ${PROFILE_STATE_WORD[x.state]} (unknown, not a negative result)`), ...downLookups.map((x) => `- **${x.name}** (${EMAIL_ACCOUNTS_SOURCE}): ${x.state === "rate_limited" ? "rate limited" : "failed"} (unknown, not a negative result)`), ""] : []),
    // A name case selects no one: the caveat line, then what is known about the search itself.
    ...(type === "name" ? nameMarkdownHead(collected, target) : [`## What we know${main ? ` (primary identity: ${main.label}, from ${main.sites.join(", ")})` : ""}`, ...(choice ? [choice] : []), ...(facts.length ? facts.map(factLine) : ["- Nothing extracted"]), "", ...analysisMarkdown(analysis.assessment, analysis.suggestions)]),
    ...(added.length ? [`## ${ADDED_HEADING}`, ...added.flatMap((a) => a.facts.map((f) => `- **${f.k}:** ${mdLink(f, f.v)} _(${f.source})_`)), ""] : []),
    ...(others.length ? ["## Other people using this handle", "_Not removed from the case. Check whether each is connected to the primary identity before leaving them out._", ...others.map((v) => `- **${v.label}:** ${v.sites.join(", ")}`), ""] : []),
    ...ledgerTiers(target, type).filter((t) => t.id !== "adult").flatMap((t) => { const rows = items.filter((i) => i.tier === t.id); return rows.length ? [`## ${t.title} (${rows.length})`, ...(isNameTier(t.id) ? [`_${t.blurb}_`] : []), ...rows.flatMap((i) => [`- ${mdLink(i)}${mdNote(i) ? ` · ${mdNote(i)}` : ""} _(${i.source})_`, ...detailMarkdown(i.detail), ...archiveMarkdown(i.archive?.view), ...archiveDiffMarkdown(i.archiveDiff), ...commitEmailsMarkdown(i.commitEmails)]), ""] : []; }),
    ...(timeline.length ? ["## Timeline", "_Every date was reported by a source in this run. A date marked self-declared was written by the account holder or inside a commit or a key, and can be false._", ...timeline.map((e) => `- ${e.date} · ${mdLink(e, e.title)}${e.detail ? ` · ${e.detail}` : ""} _(${e.source} · ${e.basis_text})_`), ""] : []),
    // GitHub activity is the case's own only while the GitHub account is. Otherwise it is
    // exported under a heading that says whose it is, never as the target's.
    ...(type === "username" ? activityMarkdown(c0.githubActivity, githubStanding(ev)) : []),
    // Post activity, one section per reading, each under a heading that says whose it is. Then
    // whether the offset ranges of the primary identity's readings fit together.
    ...[...activityReadings(ev).own, ...activityReadings(ev).other].filter((x) => x.kind === "post").flatMap((x) => postActivityMarkdown(x.answer, x.standing)),
    ...(offsetComparison(ev).verdict !== "not_enough_data" ? ["## Do the activity readings fit together", `- ${offsetComparison(ev).text} ${offsetComparison(ev).caution}`, ""] : []),
    ...footprintMarkdown(ev, c0, target, type),
    ...adultMarkdown(adult),
    // A report's own sections about adult or dating sites are exported only for a case that has such rows.
    ...(ai ? ["## AI analysis", reportForExport(ai.summary, adultFound(adult).length > 0), ""] : []),
    ...(deep ? ["## Deep Dive", reportForExport(deep.summary, false), ""] : []),
    ...(String(notes).trim() ? ["## Notes", String(notes).trim(), ""] : []),
  ].join("\n");
}
