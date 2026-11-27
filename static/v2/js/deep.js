// The three sources that read a record instead of guessing that one exists:
//   Profile sources     POST /api/recon/profiles          a handle's public record on 25 sites
//   Accounts and keys   POST /api/recon/email-accounts    the GitHub account and OpenPGP keys behind an address
//   GitHub activity     POST /api/recon/github-activity   when an account's public events happen
// and four lookups that run only on a click, each for one read profile:
//   Profile archive     POST /api/recon/profile-archive   which copies of a profile page the Internet Archive holds
//   Archive diff        POST /api/recon/archive-diff      what text and links two of those copies do not share
//   Commit emails       POST /api/recon/commit-emails     the addresses on an account's own commits (GitLab, Codeberg, Gitea.com)
//   Post activity       POST /api/recon/post-activity     when an account posts (Hacker News, Mastodon, Lobsters)
// and one comparison made here, with no request: whether the UTC offset ranges of two or more
// activity readings fit together (compareOffsets).
// Pure: no DOM, no network. Every answer is read through one of the readers below before
// anything is shown, stored or exported. A reader takes outside data (a live answer, a case in
// History, a case file) and returns a checked, bounded copy: text is clipped, an address is
// rebuilt or held to the site it must be on, a thumbnail passes safeThumb, and a state is one
// of the known ones. A reader is idempotent, so reading its own output changes nothing.
//
// How a value is known is carried with it, in three words used by the page, the exports and the AI:
//   site record     the site wrote it: a join date, a count, an attribution, a proof it checked
//   self-declared   the account holder wrote it: a name, a bio, a location, a link, and every
//                   name, date and time zone written inside a commit or a key
//   tool report     a tool parsed it from a page (Maigret, the platform check, enrichment)

import { safeThumb } from "./present.js";
import { parseUrl, classifyLink, foundLink, hostOf, isBareHome, ownProfileQuery } from "./links.js";
import { adultHost } from "./adult.js";

const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
// Text from outside: control characters and the characters that reorder or hide text (bidi
// overrides and isolates, the zero-width no-break space) are removed, so a name or a handle
// cannot be made to read as something else. The server does the same for its own answers
// (modules/profiles/base.py); a case file does not pass through the server.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
export const cleanText = (v) => String(v).replace(UNSAFE, " ");
const line = (v, n) => (typeof v === "string" || typeof v === "number" ? Array.from(cleanText(v).replace(/\s+/g, " ").trim()).slice(0, n).join("") : "");
const int = (v) => (Number.isFinite(v) && v >= 0 ? Math.floor(v) : null);
// A count is held to a ceiling: no source here returns more, and a case file may claim anything.
const COUNT_MAX = 1e9;
const capped = (v, max = COUNT_MAX) => { const n = int(v); return n === null ? null : Math.min(n, max); };
const num = (v, max = COUNT_MAX) => capped(v, max) ?? 0;
const list = (v, n) => (Array.isArray(v) ? v.slice(0, n) : []);
const HEX16 = /^[0-9a-f]{16}$/i;
const EMAIL = /^[^\s@<>"']{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,24}$/;
const ISO = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;
const when = (v) => (typeof v === "string" && ISO.test(v.trim()) ? v.trim() : "");
export const dayOf = (v) => when(v).slice(0, 10);
// An address that may be shown as a link: http(s), no credentials, bounded, never an adult or dating site.
const safeLink = (u) => { const s = typeof u === "string" ? u.trim() : ""; const x = s && s.length <= 300 ? parseUrl(s) : null; return x && !x.username && !x.password && !adultHost(s) ? s : ""; };
const email = (v) => (typeof v === "string" && v.length <= 254 && EMAIL.test(v.trim()) ? v.trim().toLowerCase() : "");
const errorOf = (raw) => ({ error: line(raw.error, 300) || "The source failed.", error_code: line(raw.error_code, 40) || "request_failed", error_detail: line(raw.error_detail, 300) });
const failed = (d) => !!(d && (d.error || d.error_code));
// A reader's answer for one raw object is computed once: the ledger is rebuilt often.
const memo = (fn) => { const seen = new WeakMap(); return (raw) => { if (!isObj(raw)) return null; if (!seen.has(raw)) { const out = fn(raw); seen.set(raw, out); if (isObj(out)) seen.set(out, out); } return seen.get(raw); }; };

// ---- answers kept by row -------------------------------------------------------------------------
// collected.archives, .commitEmails, .postActivity and .archiveDiffs are each { [row key]: answer }.
// A key is an account row's; at most 40 are kept.
const ROW_KEY = /^acct:[^\u0000-\u001f]{1,76}$/;
const byRow = (read) => memo((raw) => {
  const out = {};
  for (const [k, v] of Object.entries(raw).slice(0, 40)) { const a = ROW_KEY.test(k) && isObj(v) ? read(v) : null; if (a) out[k] = a; }
  return out;
});
const askedAt = (raw) => (Number.isFinite(raw.asked_at) && raw.asked_at > 0 ? raw.asked_at : 0);
const retryAfter = (raw) => (int(raw.retry_after) ? { retry_after: Math.min(int(raw.retry_after), 86400) } : {});
const waitText = (s) => (s ? ` Try again in ${s < 90 ? "a minute" : `${Math.ceil(s / 60)} minutes`}.` : " Try again in a few minutes.");
const andList = (xs) => (xs.length < 2 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`);

export const PROVENANCE = { record: "site record", self: "self-declared", tool: "tool report" };

// ---- profile sources -----------------------------------------------------------------------------
export const PROFILE_SOURCE = "Profile sources";
export const PROFILE_SOURCE_DESC = "reads the public record for this handle on 25 sites with an open API: name, bio, links, dates and linked accounts";
// id -> [site name, the host a profile address must be on]. The names and hosts are CrawlR's own:
// a stored case or a case file cannot rename a site or point a profile somewhere else.
// Mastodon: one source per instance, and the same handle on two instances is two accounts. The
// list is the server's (INSTANCES in modules/profiles/mastodon.py), in its order. The id is
// "mastodon" for mastodon.social and "mastodon_" plus the host with underscores for the rest.
export const MASTODON_INSTANCES = ["mastodon.social", "mastodon.online", "mstdn.social", "fosstodon.org", "hachyderm.io", "infosec.exchange", "mas.to", "mastodon.world"];
const MASTODON_IDS = Object.fromEntries(MASTODON_INSTANCES.map((host, i) => [i ? `mastodon_${host.replace(/\./g, "_")}` : "mastodon", host]));
// The instance a source id, a host or a profile address names: one of the known hosts, or "".
export function mastodonInstance(v) {
  const s = typeof v === "string" ? v.trim() : "";
  if (Object.hasOwn(MASTODON_IDS, s)) return MASTODON_IDS[s];
  if (MASTODON_INSTANCES.includes(s.toLowerCase())) return s.toLowerCase();
  const x = s.length <= 300 ? parseUrl(s) : null;
  const host = x && x.protocol === "https:" && !x.port && !x.username && !x.password ? x.hostname.toLowerCase() : "";
  return MASTODON_INSTANCES.includes(host) ? host : "";
}
export const PROFILE_SITES = {
  gitlab: ["GitLab", "gitlab.com"], keybase: ["Keybase", "keybase.io"], hackernews: ["Hacker News", "news.ycombinator.com"],
  ...Object.fromEntries(Object.entries(MASTODON_IDS).map(([id, host]) => [id, [id === "mastodon" ? "Mastodon" : `Mastodon (${host})`, host]])),
  dockerhub: ["Docker Hub", "hub.docker.com"], npm: ["npm", "npmjs.com"], devto: ["dev.to", "dev.to"], lichess: ["Lichess", "lichess.org"], chesscom: ["Chess.com", "chess.com"],
  codeberg: ["Codeberg", "codeberg.org"], bluesky: ["Bluesky", "bsky.app"], wikipedia: ["Wikipedia", "en.wikipedia.org"], gravatar: ["Gravatar", "gravatar.com"],
  codeforces: ["Codeforces", "codeforces.com"], lobsters: ["Lobsters", "lobste.rs"], huggingface: ["Hugging Face", "huggingface.co"],
  launchpad: ["Launchpad", "launchpad.net"], gitea: ["Gitea.com", "gitea.com"],
};
export const PROFILE_STATES = ["found", "not_found", "blocked", "rate_limited", "unknown", "failed", "not_asked"];
// Only "found" and "not_found" say whether the account is there. The rest are unknown.
export const PROFILE_STATE_WORD = { found: "profile read", not_found: "not found", blocked: "blocked by site", rate_limited: "rate limited", unknown: "could not tell", failed: "failed", not_asked: "not asked" };
export const PROOFS = ["keybase", "verified_link", "listed"];
export const PROOF_TEXT = { keybase: "proven on Keybase", verified_link: "verified link", listed: "listed on the profile" };
export const proofStrong = (proof) => proof === "keybase" || proof === "verified_link";
const ITEM_KINDS = { package: "Packages", organization: "Organizations" };
const AVATAR_STATES = ["ok", "none", "default", "failed"];
// What a site's own `note` on a record means, in the page's words. A note outside this table is
// shown as the site gave it (a part that was not read, say), never as one of these.
export const NOT_ACTIVE_NOTE = "not an active account";
export const PROFILE_NOTE_TEXT = {
  [NOT_ACTIVE_NOTE]: "Not a claimed account. Launchpad makes such a record by itself for a person named in an imported bug, translation or package, so the person did not necessarily make it and it says nothing about who holds the name.",
  team: "A team on Launchpad, not a person.",
  moved: "The account says it moved to another instance. This row is the old account.",
  suspended: "The site has suspended this account.",
  bot: "The account is marked as automated.",
  organization: "An organization, not a person.",
  admin: "The site lists this account as an administrator.",
  moderator: "The site lists this account as a moderator.",
};
export const profileNoteText = (note) => (typeof note === "string" && Object.hasOwn(PROFILE_NOTE_TEXT, note) ? PROFILE_NOTE_TEXT[note] : "");
const SITE_BY_NAME = Object.fromEntries(Object.entries(PROFILE_SITES).map(([id, [name]]) => [name.toLowerCase(), id]));
const SITE_BY_HOST = Object.fromEntries(Object.entries(PROFILE_SITES).map(([id, [, host]]) => [host, id]));
const onHost = (u, host) => { const x = parseUrl(u); const hn = x ? x.hostname.toLowerCase().replace(/^www\./, "") : ""; return !!x && x.protocol === "https:" && hn === host && x.pathname.replace(/\/+$/, "").length > 0; };
// Which of the 25 sources a record, a profile or a ledger row is about: its `source` id, else the
// host of its address, else its site name. "" when it is none of them. This says which site, not
// that the row was read: the caller offers a lookup only on a row a source read.
export function profileSourceId(p) {
  if (typeof p === "string") return Object.hasOwn(PROFILE_SITES, p) ? p : "";
  if (!isObj(p)) return "";
  if (typeof p.source === "string" && Object.hasOwn(PROFILE_SITES, p.source)) return p.source;
  const url = safeLink(p.url), host = url ? hostOf(url) : "";
  if (host && Object.hasOwn(SITE_BY_HOST, host) && onHost(url, host)) return SITE_BY_HOST[host];
  const name = [p.site, p.what].find((x) => typeof x === "string" && Object.hasOwn(SITE_BY_NAME, x.trim().toLowerCase()));
  return !url && name ? SITE_BY_NAME[name.trim().toLowerCase()] : "";
}
// A Launchpad record the site made by itself. It is shown, and it is not a claimed account: no
// identity, fact, lead, timeline entry or AI input is taken from it.
export const unclaimedProfile = (p) => isObj(p) && profileSourceId(p) === "launchpad" && (p.note ?? p.siteNote) === NOT_ACTIVE_NOTE;
// The handle a lookup is asked about: the row's own spelling, else the one its address carries.
const HANDLE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;
function handleOf(p) {
  const own = [p.handle, p.username].map((x) => (typeof x === "string" ? x.trim().replace(/^@/, "") : "")).find((x) => HANDLE.test(x));
  if (own) return own;
  const url = safeLink(p.url), x = url ? parseUrl(url) : null;
  const seg = x ? ownProfileQuery(url) || (x.search || x.hash ? "" : x.pathname.split("/").filter(Boolean).at(-1) || "").replace(/^[@~]/, "") : "";
  return HANDLE.test(seg) ? seg : "";
}
// A row a lookup may be asked for: one of `sites`, read ("found" when it says), never on an adult site.
function askable(p, ok) {
  const id = profileSourceId(p);
  if (!id || !ok(id)) return null;
  if (typeof p === "string") return { id, username: "" };
  if (("state" in p && p.state !== "found") || unclaimedProfile(p) || (p.url && !safeLink(p.url))) return null;
  const username = handleOf(p);
  return username ? { id, username } : null;
}

function readProfile(p) {
  if (!isObj(p) || p.state !== "found" || !Object.hasOwn(PROFILE_SITES, p.source)) return null;
  const [site, host] = PROFILE_SITES[p.source];
  const url = safeLink(p.url);
  if (!url || !onHost(url, host)) return null;
  const hash = typeof p.avatar_hash === "string" && HEX16.test(p.avatar_hash) ? p.avatar_hash.toLowerCase() : "";
  const dflt = hash ? p.avatar_default === true : false;
  const stats = {};
  if (isObj(p.stats)) for (const [k, v] of Object.entries(p.stats).slice(0, 12)) if (/^[a-z][a-z0-9_]{0,29}$/.test(k) && capped(v) !== null) stats[k] = capped(v);
  const seen = new Set();
  const accounts = list(p.accounts, 20).map((a) => {
    const u = isObj(a) ? safeLink(a.url) : "";
    if (!u || seen.has(u.toLowerCase()) || !line(a.site, 60)) return null;
    seen.add(u.toLowerCase());
    const proof = PROOFS.includes(a.proof) ? a.proof : "listed";
    const pu = proof === "keybase" ? safeLink(a.proof_url) : "";
    return { site: line(a.site, 60), handle: line(a.handle, 64), url: u, proof, ...(pu ? { proof_url: pu } : {}) };
  }).filter(Boolean);
  const name = line(p.display_name ?? p.name, 200);
  return {
    site, source: p.source, handle: line(p.handle, 80), url, state: "found", display_name: name, name,
    bio: line(p.bio, 300), location: line(p.location, 100), company: line(p.company, 100), website: safeLink(p.website),
    links: [...new Set(list(p.links, 12).map(safeLink).filter(Boolean))], emails: [...new Set(list(p.emails, 6).map(email).filter(Boolean))],
    created: when(p.created), last_active: when(p.last_active), accounts, stats, followers: stats.followers ?? null,
    items: list(p.items, 20).map((i) => (isObj(i) && Object.hasOwn(ITEM_KINDS, i.kind) && line(i.name, 80) && safeLink(i.url) ? { name: line(i.name, 80), url: safeLink(i.url), kind: i.kind } : null)).filter(Boolean),
    note: line(p.note, 200), avatar_hash: hash, avatar_default: dflt, thumb: hash && !dflt ? safeThumb(p.thumb) : "",
    avatar_state: hash ? (dflt ? "default" : "ok") : AVATAR_STATES.includes(p.avatar_state) && p.avatar_state !== "ok" ? p.avatar_state : "none",
  };
}
// The whole answer: { username, cached, profiles, sources } or a failure ({ error, error_code,
// error_detail }), or null for something that is not an answer at all. `guard` never survives.
export const readProfileSources = memo((raw) => {
  if (failed(raw)) return errorOf(raw);
  if (!Array.isArray(raw.profiles) || !isObj(raw.sources)) return null;
  const profiles = [], seen = new Set();
  for (const p of raw.profiles.slice(0, 40)) { const r = readProfile(p); if (r && !seen.has(r.source)) { seen.add(r.source); profiles.push(r); } }
  const sources = {};
  for (const id of Object.keys(PROFILE_SITES)) {
    const s = raw.sources[id];
    if (!isObj(s) || !PROFILE_STATES.includes(s.state)) continue;
    // A source that says "found" with no readable profile behind it showed nothing.
    const state = s.state === "found" && !seen.has(id) ? "unknown" : s.state;
    sources[id] = { site: PROFILE_SITES[id][0], state, ...(line(s.note, 200) ? { note: line(s.note, 200) } : {}), ...(state === "failed" || state === "rate_limited" ? { error: line(s.error, 200), error_code: line(s.error_code, 40), error_detail: line(s.error_detail, 200) } : {}), ...(state === "rate_limited" && int(s.retry_after) ? { retry_after: Math.min(int(s.retry_after), 86400) } : {}) };
  }
  for (const id of seen) if (!sources[id]) sources[id] = { site: PROFILE_SITES[id][0], state: "found" };
  // asked: the sites this call asked. The rest came from the server's cache of an earlier call.
  return { username: line(raw.username, 64), cached: raw.cached === true, profiles, sources, ...(Array.isArray(raw.asked) ? { asked: [...new Set(raw.asked.filter((x) => Object.hasOwn(PROFILE_SITES, x)))] } : {}) };
});
// A site that answered whether the account is there. npm cannot see an account without packages:
// it answers, and says so in a note, which is still an answer from the site.
const answeredState = (s) => s.state === "found" || s.state === "not_found" || (s.state === "unknown" && !!s.note && !s.error_code);
// { read, asked, answered, by: { state: [site] }, down: [{ site, state, note }], unclaimed: [site] }
// down: the sites that were asked and did not say. Unknown, never "not found".
// unclaimed: sites whose record is not a claimed account (unclaimedProfile). The site answered
// "found", so it is in `read` and `by.found`; a caller that counts profiles takes these out.
export function profileCoverage(d) {
  const r = readProfileSources(d);
  const out = { read: 0, asked: 0, answered: 0, by: {}, down: [], notes: [], unclaimed: [] };
  if (!r || failed(r)) return out;
  out.unclaimed = r.profiles.filter(unclaimedProfile).map((p) => p.site);
  for (const s of Object.values(r.sources)) {
    (out.by[s.state] ||= []).push(s.site);
    if (s.state === "not_asked") continue;
    out.asked++;
    if (s.state === "found") out.read++;
    if (answeredState(s)) out.answered++; else out.down.push({ site: s.site, state: s.state });
    if (s.note) out.notes.push({ site: s.site, note: s.note });
  }
  return out;
}
// "5 profiles read · 3 did not answer (Lichess rate limited, Lobsters blocked by site)" for the run log.
export function profileSourcesText(d) {
  const c = profileCoverage(d);
  if (!c.asked) return "";
  const down = c.down.map((x) => `${x.site} ${PROFILE_STATE_WORD[x.state]}`);
  // A record a site made by itself is not a profile that was read: it is said apart.
  const read = c.read - c.unclaimed.length;
  return [`${read} ${read === 1 ? "profile" : "profiles"} read on ${c.asked} sites`, c.unclaimed.length ? `${c.unclaimed.length} ${c.unclaimed.length === 1 ? "record" : "records"} nobody claimed (${c.unclaimed.join(", ")})` : "", down.length ? `${down.length} did not answer (${down.slice(0, 4).join(", ")}${down.length > 4 ? ` and ${down.length - 4} more` : ""})` : ""].filter(Boolean).join(", ");
}

// ---- what a read profile shows when its row is opened -----------------------------------------
const STAT_LABEL = { followers: "Followers", following: "Following", posts: "Posts", karma: "Karma", repos: "Repositories", public_repos: "Repositories", packages: "Packages", games: "Games", stars: "Stars", edits: "Edits", rating: "Rating", max_rating: "Highest rating", contributions: "Contributions", friends: "Friends", models: "Models", datasets: "Datasets", spaces: "Spaces", submissions: "Submissions", comments: "Comments", articles: "Articles", starred: "Starred" };
const statLabel = (k) => (Object.hasOwn(STAT_LABEL, k) ? STAT_LABEL[k] : (k.charAt(0).toUpperCase() + k.slice(1)).replace(/_/g, " "));
const fmt = (n) => Number(n).toLocaleString("en-US");
const bareUrl = (u) => String(u).replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "");
// One row of a detail: { k, v, url, link_kind, how? }. A link is evidence: where the value can be
// seen, never a claim about who owns the page. `subjects` and `secrets` are the link rules' own.
// own: the link is itself the value (a website, a link the profile carries), so its host is what
// the row is about and a bare site may be linked. For every other row (an account, a package, an
// organization) a bare homepage shows nothing about the value, and is not linked.
function drow(k, v, url, { subjects = [], secrets = [], how = "", own = false } = {}) {
  const l = url ? classifyLink({ url, want: "evidence", subjects: [...subjects, v, ...(own ? [hostOf(url)] : [])], secrets }) : { url: "", link_kind: "none" };
  return { k, v: String(v), url: l.url, link_kind: l.link_kind, ...(how ? { how } : {}) };
}
// p: a profile from collectProfiles. Returns { groups: [{ id, title, prov, rows }], count }.
// A profile read from a site's own API is split by who wrote each value. A profile a tool parsed
// from a page is one group, because the tool cannot tell the two apart.
export function profileDetail(p, { secrets = [] } = {}) {
  if (!p) return null;
  const o = { subjects: [p.handle], secrets };
  const self = [], rec = [];
  if (p.fullName) self.push(drow("Name", p.fullName));
  if (p.fullBio) self.push(drow("Bio", p.fullBio));
  if (p.location) self.push(drow("Location", p.location));
  if (p.company) self.push(drow("Company", p.company));
  for (const w of p.websites || []) self.push(drow("Website", bareUrl(w), /^https?:/i.test(w) ? w : `https://${w}`, { ...o, own: true }));
  for (const e of p.emails || []) self.push(drow("Public email", e));
  for (const a of (p.accounts || []).filter((x) => !proofStrong(x.proof))) self.push(drow("Listed account", `${a.site}${a.handle ? ` ${a.handle}` : ""}`, a.url, { ...o, subjects: [p.handle, a.handle], how: PROOF_TEXT.listed }));
  const shown = new Set([...(p.websites || []), ...(p.accounts || []).map((a) => a.url)].map((u) => String(u).toLowerCase().replace(/\/$/, "")));
  for (const u of (p.links || []).filter((x) => !shown.has(String(x).toLowerCase().replace(/\/$/, ""))).slice(0, 8)) self.push(drow("Link", bareUrl(u), u, { ...o, own: true }));
  for (const a of (p.accounts || []).filter((x) => proofStrong(x.proof))) {
    const r = drow(a.proof === "keybase" ? "Proven account" : "Verified link", `${a.site}${a.handle ? ` ${a.handle}` : ""}`, a.url, { ...o, subjects: [p.handle, a.handle], how: PROOF_TEXT[a.proof] });
    if (a.proof_url) { const pl = classifyLink({ url: a.proof_url, want: "evidence", subjects: [p.handle, a.handle], secrets }); if (pl.link_kind === "evidence") r.more = { url: pl.url, label: "Proof", link_kind: "evidence" }; }
    rec.push(r);
  }
  if (dayOf(p.created) || /^\d{4}-\d{2}-\d{2}/.test(String(p.created || ""))) rec.push(drow("Joined", String(p.created).slice(0, 10)));
  if (dayOf(p.lastActive)) rec.push(drow("Last active", dayOf(p.lastActive)));
  const stats = { ...(p.stats || {}) };
  for (const [k, v] of [["repos", p.repos], ["followers", p.followers], ["karma", p.karma]]) if (Number.isFinite(v) && v >= 0 && !Object.hasOwn(stats, k) && !(k === "repos" && Object.hasOwn(stats, "public_repos"))) stats[k] = v;
  for (const [k, v] of Object.entries(stats)) rec.push(drow(statLabel(k), fmt(v)));
  for (const kind of Object.keys(ITEM_KINDS)) { const it = (p.items || []).filter((i) => i.kind === kind); for (const i of it.slice(0, 10)) rec.push(drow(ITEM_KINDS[kind].replace(/s$/, ""), i.name, i.url, { ...o, subjects: [p.handle, i.name] })); if (it.length > 10) rec.push(drow(ITEM_KINDS[kind], `and ${it.length - 10} more`)); }
  if (p.avatarState === "failed") rec.push(drow("Picture", "could not be read, so it was not compared"));
  // The site answered in part ("bio not read"): that part is unknown, and is never shown as empty.
  // A note the page knows ("moved", "team") is said in the page's words.
  if (p.siteNote) rec.push(profileNoteText(p.siteNote) ? drow("Site note", profileNoteText(p.siteNote)) : drow("Not read", `${p.siteNote}${/not read$/.test(p.siteNote) ? ": unknown, not empty" : ""}`));
  const groups = p.api
    ? [{ id: "self", title: "Written by the account holder", prov: PROVENANCE.self, rows: self }, { id: "record", title: `${p.site}'s own record`, prov: PROVENANCE.record, rows: rec }]
    : [{ id: "tool", title: `Read from the page by ${(p.sources || []).join(", ") || "a tool"}`, prov: PROVENANCE.tool, rows: [...self, ...rec] }];
  const kept = groups.filter((g) => g.rows.length);
  const count = kept.reduce((n, g) => n + g.rows.length, 0);
  return count ? { groups: kept, count } : null;
}
// The same detail as indented Markdown lines under a row, each marked with how it is known.
export const detailMarkdown = (detail) => (detail?.groups || []).flatMap((g) => g.rows.map((r) => `  - ${r.k}: ${r.url && r.link_kind !== "none" ? `[${r.v}](${r.url})` : r.v}${r.how ? ` (${r.how})` : ""}${r.more ? ` · [${r.more.label}](${r.more.url})` : ""} _(${g.prov})_`));

// ---- accounts and keys behind an address --------------------------------------------------------
export const EMAIL_ACCOUNTS_SOURCE = "Accounts and keys";
export const EMAIL_ACCOUNTS_DESC = "the GitHub account that GitHub ties to this address, and OpenPGP keys published for it";
const GH_LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const COMMIT_URL = /^https:\/\/github\.com\/[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}\/commit\/[0-9a-f]{7,64}$/;
const HOWS = ["commit_author", "public_profile_email"];
const LOOKUPS = { github_commits: "GitHub commit search", github_users: "GitHub user search", openpgp: "keys.openpgp.org" };
const LOOKUP_STATES = ["ok", "none", "rate_limited", "failed"];
// The words the page uses for each way an account is tied to the address.
export const HOW_TEXT = {
  commit_author: "GitHub attributes commits that carry this address to this account, so the account has this address confirmed.",
  public_profile_email: "GitHub's search matched this address on the account's public profile. The profile itself was not read to confirm it.",
  organization: "GitHub's search matched this address on this organization's public profile. The profile was not read, and GitHub does not confirm an organization's address.",
};
export const SELF_DECLARED_NOTE = "Names, dates and time zones written inside a commit are self-declared: whoever makes a commit can write anything there.";
export const KEY_NOTE = "The key server verified each address on a key by mail. The names on a key, and its creation date, are self-declared.";
// What the commits say: counts are GitHub's, everything else was written by the committer.
function commitPart(v) {
  const d = isObj(v) ? v : {};
  return {
    commits_seen: num(d.commits_seen), own_repo_commits: num(d.own_repo_commits),
    names: list(d.names, 8).map((n) => (isObj(n) && line(n.name, 100) ? { name: line(n.name, 100), commits: num(n.commits), own_repo: n.own_repo === true } : null)).filter(Boolean),
    first_commit: when(d.first_commit), last_commit: when(d.last_commit), dates_ignored: num(d.dates_ignored),
    commit_utc_offsets: list(d.commit_utc_offsets, 8).map((o) => (isObj(o) && /^[+-]\d{2}:\d{2}$/.test(String(o.offset)) ? { offset: String(o.offset), commits: num(o.commits) } : null)).filter(Boolean),
    evidence: [...new Set(list(d.evidence, 5).filter((u) => typeof u === "string" && COMMIT_URL.test(u)))],
  };
}
function readKey(k) {
  if (!isObj(k)) return null;
  const user_ids = list(k.user_ids, 10).map((u) => (isObj(u) ? { name: line(u.name, 100), email: email(u.email), comment: line(u.comment, 100) } : null)).filter((u) => u && (u.name || u.email));
  const version = int(k.version) ?? 0;
  const fp = typeof k.fingerprint === "string" && /^[0-9a-f]{40}$/i.test(k.fingerprint) ? k.fingerprint.toUpperCase() : "";
  if (k.parsed !== true || !fp) return { parsed: false, version, reason: line(k.reason, 200), user_ids };
  return {
    parsed: true, version, fingerprint: fp, key_id: fp.slice(-16), created: when(k.created), algorithm: line(k.algorithm, 40), bits: int(k.bits), curve: line(k.curve, 40),
    // The address is rebuilt from the fingerprint: a stored case cannot point a key somewhere else.
    url: `https://keys.openpgp.org/vks/v1/by-fingerprint/${fp}`, user_ids, subkeys: num(k.subkeys), revoked: k.revoked === true, how: "keyserver_verified_address",
  };
}
export const readEmailAccounts = memo((raw) => {
  if (failed(raw)) return errorOf(raw);
  if (!Array.isArray(raw.accounts) || !Array.isArray(raw.keys) || !isObj(raw.sources)) return null;
  const seen = new Set();
  const accounts = raw.accounts.slice(0, 20).map((a) => {
    const login = isObj(a) && typeof a.login === "string" && GH_LOGIN.test(a.login) ? a.login : "";
    if (!login || seen.has(login.toLowerCase())) return null;
    seen.add(login.toLowerCase());
    const hows = [...new Set([a.how, ...list(a.hows, 4)].filter((x) => HOWS.includes(x)))];
    if (!hows.length) return null;
    const how = hows.includes("commit_author") ? "commit_author" : "public_profile_email";
    // confirmed: GitHub attributes commits with the address to the account. A search match is
    // never confirmed, whatever a stored case says. how_note: the server's sentence for a match.
    return { login, url: `https://github.com/${login}`, how, hows, confirmed: how === "commit_author", ...(how !== "commit_author" && line(a.how_note, 200) ? { how_note: line(a.how_note, 200) } : {}), account_type: ["User", "Organization", "Bot"].includes(a.account_type) ? a.account_type : "", ...(how === "commit_author" ? commitPart(a) : {}) };
  }).filter(Boolean);
  const un = commitPart(raw.unattributed);
  const sources = {};
  for (const id of Object.keys(LOOKUPS)) {
    const s = raw.sources[id];
    if (!isObj(s) || !LOOKUP_STATES.includes(s.state)) continue;
    const down = s.state === "failed" || s.state === "rate_limited";
    sources[id] = { state: s.state, ...Object.fromEntries(["total", "seen", "skipped", "count", "retry_after"].filter((k) => int(s[k]) !== null).map((k) => [k, int(s[k])])), ...(s.incomplete === true ? { incomplete: true } : {}), ...(s.only_skipped === true ? { only_skipped: true } : {}), ...(!down && line(s.note, 300) ? { note: line(s.note, 300) } : {}), ...(down ? { error: line(s.error, 200), error_code: line(s.error_code, 40), error_detail: line(s.error_detail, 200) } : {}) };
  }
  return { email: email(raw.email), cached: raw.cached === true, accounts, unattributed: un.commits_seen ? un : null, keys: raw.keys.slice(0, 10).map(readKey).filter(Boolean), sources };
});
export const lookupName = (id) => (Object.hasOwn(LOOKUPS, id) ? LOOKUPS[id] : String(id));
// GitHub returned commits for the address and none could be counted. That is not "no commits".
export const commitsNote = (d) => { const r = readEmailAccounts(d); const s = r && !failed(r) ? r.sources.github_commits : null; return s?.only_skipped ? s.note || "GitHub returned commits for this address and none could be counted." : ""; };
// The lookups that did not answer: unknown, never "no account" or "no key".
export const emailLookupsDown = (d) => { const r = readEmailAccounts(d); return r && !failed(r) ? Object.entries(r.sources).filter(([, s]) => s.state === "failed" || s.state === "rate_limited").map(([id, s]) => ({ id, name: LOOKUPS[id], state: s.state })) : []; };
// The names written in an account's commits, the ones from its own repositories first.
export const commitNames = (a) => (a?.names || []).slice().sort((x, y) => (y.own_repo ? 1 : 0) - (x.own_repo ? 1 : 0) || y.commits - x.commits);
const namesText = (a, n = 3) => commitNames(a).slice(0, n).map((x) => `${x.name}${x.own_repo ? " (in a repository the account owns)" : ""}`).join(", ");
const offsetsText = (a) => (a?.commit_utc_offsets || []).map((o) => `UTC${o.offset} in ${o.commits} ${o.commits === 1 ? "commit" : "commits"}`).join(", ");
const plural = (n, one, many = `${one}s`) => `${fmt(n)} ${n === 1 ? one : many}`;
const shortFp = (fp) => fp.replace(/(.{4})/g, "$1 ").trim();
const keyAlgo = (k) => [k.algorithm, k.curve, k.bits ? `${k.bits} bits` : ""].filter(Boolean).join(" ");

// The detail of one account row: what GitHub says, then what the commits say.
function commitDetail(a) {
  const rec = [], self = [];
  if (a.commits_seen) rec.push({ k: "Commits seen", v: plural(a.commits_seen, "commit"), url: "", link_kind: "none" });
  if (a.own_repo_commits) rec.push({ k: "In its own repositories", v: plural(a.own_repo_commits, "commit"), url: "", link_kind: "none" });
  a.evidence.forEach((u, i) => rec.push({ k: i ? "" : "Evidence", v: u.replace(/^https:\/\/github\.com\//, "").replace(/\/commit\/([0-9a-f]{7})[0-9a-f]*$/, " @ $1"), url: u, link_kind: "evidence" }));
  for (const n of commitNames(a)) self.push({ k: "Name in commits", v: n.name, url: "", link_kind: "none", how: `${plural(n.commits, "commit")}${n.own_repo ? ", in a repository the account owns" : ", in other repositories"}` });
  if (dayOf(a.first_commit)) self.push({ k: "First commit seen", v: dayOf(a.first_commit), url: "", link_kind: "none" });
  if (dayOf(a.last_commit)) self.push({ k: "Last commit seen", v: dayOf(a.last_commit), url: "", link_kind: "none" });
  if (a.dates_ignored) self.push({ k: "Dates left out", v: `${plural(a.dates_ignored, "commit")} with an impossible date`, url: "", link_kind: "none" });
  for (const o of a.commit_utc_offsets) self.push({ k: "UTC offset in commits", v: `UTC${o.offset}`, url: "", link_kind: "none", how: plural(o.commits, "commit") });
  const groups = [{ id: "record", title: "GitHub's own record", prov: PROVENANCE.record, rows: rec }, { id: "self", title: "Written inside the commits (anyone can write anything there)", prov: PROVENANCE.self, rows: self }].filter((g) => g.rows.length);
  const count = groups.reduce((n, g) => n + g.rows.length, 0);
  return count ? { groups, count } : null;
}

// The ledger rows of an email case, from the checked answer. Each is complete: tier, link, card,
// detail and action. Nothing here is a profile, so none of it reaches the identity clusters.
//   Linked       an account GitHub attributes commits with this address to, and each key the key
//                server published for the address (it verified the address by mail)
//   Unverified   an account GitHub's user search matched to the address (reported: the profile
//                was not read, so nothing confirms it shows the address), and commits that carry
//                the address and that GitHub ties to no account
// A search match is never "Exists (matches)": that group is for profiles that were read.
export function emailAccountItems(d) {
  const r = readEmailAccounts(d);
  if (!r || failed(r)) return [];
  const out = [];
  for (const a of r.accounts) {
    const strong = a.how === "commit_author", org = a.account_type === "Organization";
    const both = a.hows.includes("public_profile_email") && strong;
    const why = strong ? HOW_TEXT.commit_author.replace(/\.$/, "") + (both ? ", and GitHub's search matched it on the public profile" : "") : (org ? HOW_TEXT.organization : HOW_TEXT.public_profile_email).replace(/\.$/, "");
    const facts = [org ? "Organization" : a.account_type === "Bot" ? "Bot account" : "", strong && a.commits_seen ? `${plural(a.commits_seen, "commit")} seen` : "", strong && a.own_repo_commits ? `${fmt(a.own_repo_commits)} in its own repositories` : ""].filter(Boolean);
    const named = strong ? namesText(a, 2) : "";
    out.push({
      tier: strong ? "linked" : "unverified", what: `GitHub (${a.login})`, url: a.url, link_kind: strong ? "verified_profile" : "evidence", key: `acct:github~${a.login.toLowerCase()}`, sources: [EMAIL_ACCOUNTS_SOURCE], source: EMAIL_ACCOUNTS_SOURCE,
      meta: [why, strong && a.commits_seen ? `${plural(a.commits_seen, "commit")} seen` : "", named ? `names written in commits (self-declared): ${named}` : ""].filter(Boolean).join(" · "),
      card: { handle: a.login, facts, bio: "", why, basis: strong ? "" : "Reported by GitHub's user search. Nothing was read.", note: strong ? (named ? `Names written in its commits (self-declared): ${named}.` : "") : "Investigate the account to read its profile." },
      detail: strong ? commitDetail(a) : null, emailAccount: { login: a.login, how: a.how, type: a.account_type },
      ...(strong && a.evidence[0] ? { more: { url: a.evidence[0], label: "Evidence commit", link_kind: "evidence" } } : {}),
      action: { label: "Investigate this", pivot: "investigate", value: a.login, type: "username", via: `the GitHub login ${a.login}`, source: strong ? "GitHub's commit attribution for this address" : "GitHub's search match for this address" },
    });
  }
  if (r.unattributed) {
    const u = r.unattributed, named = namesText(u, 3);
    out.push({
      tier: "unverified", what: "Commits GitHub ties to no account", url: u.evidence[0] || "", link_kind: u.evidence[0] ? "evidence" : "none", ...(u.evidence[0] ? { link_label: "Evidence commit" } : {}), key: "commits:unattributed", sources: [EMAIL_ACCOUNTS_SOURCE], source: EMAIL_ACCOUNTS_SOURCE,
      meta: [`${plural(u.commits_seen, "commit")} carry this address and belong to no GitHub account`, named ? `names written in them (self-declared): ${named}` : "", offsetsText(u) ? `time zones written in them (self-declared): ${offsetsText(u)}` : ""].filter(Boolean).join(" · "),
      detail: commitDetail(u), nofind: true,
    });
  }
  for (const k of r.keys) {
    const ids = k.user_ids.map((u) => [u.name, u.email && `<${u.email}>`].filter(Boolean).join(" ")).filter(Boolean);
    if (!k.parsed) {
      out.push({ tier: "linked", what: `OpenPGP key (version ${k.version || "unknown"}, not read)`, url: "", link_kind: "none", key: `pgp:unread:${k.version}:${out.length}`, sources: [EMAIL_ACCOUNTS_SOURCE], source: EMAIL_ACCOUNTS_SOURCE,
        meta: ["published for this address on keys.openpgp.org", k.reason || "CrawlR cannot read this key format", ids.length ? `user IDs: ${ids.join(", ")}` : ""].filter(Boolean).join(" · "), hint: "Search the address at keys.openpgp.org to download the key." });
      continue;
    }
    const rows = [
      { k: "Fingerprint", v: shortFp(k.fingerprint), url: k.url, link_kind: "evidence" }, { k: "Algorithm", v: keyAlgo(k), url: "", link_kind: "none" },
      { k: "Subkeys", v: String(k.subkeys), url: "", link_kind: "none" }, ...(k.revoked ? [{ k: "State", v: "revoked", url: "", link_kind: "none" }] : []),
      ...k.user_ids.filter((u) => u.email).map((u) => ({ k: "Verified address", v: u.email, url: "", link_kind: "none", how: "the key server checked it by mail" })),
    ].filter((x) => x.v);
    const self = [...(dayOf(k.created) ? [{ k: "Created", v: dayOf(k.created), url: "", link_kind: "none" }] : []), ...k.user_ids.filter((u) => u.name).map((u) => ({ k: "Name on the key", v: [u.name, u.comment && `(${u.comment})`].filter(Boolean).join(" "), url: "", link_kind: "none" }))];
    const groups = [{ id: "record", title: "The key server's record", prov: PROVENANCE.record, rows }, { id: "self", title: "Written in the key by whoever made it", prov: PROVENANCE.self, rows: self }].filter((g) => g.rows.length);
    out.push({
      tier: "linked", what: `OpenPGP key ${k.key_id.replace(/(.{4})/g, "$1 ").trim()}`, url: k.url, link_kind: "evidence", key: `pgp:${k.fingerprint.toLowerCase()}`, sources: [EMAIL_ACCOUNTS_SOURCE], source: EMAIL_ACCOUNTS_SOURCE,
      meta: ["published for this address on keys.openpgp.org, which verified the address by mail", keyAlgo(k), dayOf(k.created) ? `created ${dayOf(k.created)} (self-declared)` : "", k.revoked ? "revoked" : "", ids.length ? `user IDs: ${ids.join(", ")}` : ""].filter(Boolean).join(" · "),
      detail: { groups, count: groups.reduce((n, g) => n + g.rows.length, 0) }, pgp: { fingerprint: k.fingerprint },
    });
  }
  return out;
}
// Facts about the address itself. They belong to no person, and each says how it is known.
export function emailAccountFacts(d) {
  const r = readEmailAccounts(d);
  if (!r || failed(r)) return [];
  const out = [], src = EMAIL_ACCOUNTS_SOURCE;
  for (const a of r.accounts.filter((x) => x.how === "commit_author")) {
    out.push({ k: "GitHub account", v: a.login, source: `${src} · site record`, url: a.url });
    const top = commitNames(a)[0];
    if (top) out.push({ k: "Name in commits", v: top.name, source: `${src} · self-declared`, url: "" });
    if (dayOf(a.first_commit) && dayOf(a.last_commit)) out.push({ k: "Commits seen", v: `${dayOf(a.first_commit)} to ${dayOf(a.last_commit)}`, source: `${src} · self-declared dates`, url: "" });
    if (a.commit_utc_offsets[0]) out.push({ k: "UTC offset in commits", v: a.commit_utc_offsets.slice(0, 3).map((o) => `UTC${o.offset}`).join(", "), source: `${src} · self-declared`, url: "" });
  }
  for (const k of r.keys.filter((x) => x.parsed)) out.push({ k: "OpenPGP key", v: shortFp(k.fingerprint), source: `${src} · site record`, url: k.url });
  return out;
}
// Places to look next: the account's login, and every other address a key carries.
// { kind, value, from, source, tied }
export function emailAccountLeads(d, target) {
  const r = readEmailAccounts(d);
  if (!r || failed(r)) return [];
  const out = [], me = String(target ?? "").trim().toLowerCase();
  for (const a of r.accounts) out.push({ kind: "handle", value: a.login, from: a.how === "commit_author" ? "GitHub account that commits with this address (site record)" : a.account_type === "Organization" ? "GitHub organization that GitHub's search matched to this address (unconfirmed)" : "GitHub account that GitHub's search matched to this address (profile not read)", source: EMAIL_ACCOUNTS_SOURCE, tied: true });
  for (const k of r.keys) for (const u of k.user_ids) if (u.email && u.email !== me) out.push({ kind: "email", value: u.email, from: "another address on the same OpenPGP key (verified by the key server)", source: EMAIL_ACCOUNTS_SOURCE, tied: true });
  return out;
}
// "1 account, 1 key" for the run log.
export function emailAccountsText(d) {
  const r = readEmailAccounts(d);
  if (!r || failed(r)) return "";
  const down = emailLookupsDown(r).map((x) => `${x.name} ${x.state === "rate_limited" ? "rate limited" : "failed"}`);
  return [r.accounts.length ? plural(r.accounts.length, "GitHub account") : "", r.keys.length ? plural(r.keys.length, "OpenPGP key") : "", r.unattributed ? `${plural(r.unattributed.commits_seen, "commit")} tied to no account` : "", r.sources.github_commits?.only_skipped ? "commits were returned and none could be counted" : "", down.length ? `unknown: ${down.join(", ")}` : ""].filter(Boolean).join(", ");
}
// What the model is told: the same statements, with the provenance in the field names.
export function emailAccountsForAi(d) {
  const r = readEmailAccounts(d);
  if (!r || failed(r)) return null;
  const git = (a) => ({ commits_seen: a.commits_seen, own_repo_commits: a.own_repo_commits, self_declared_names: commitNames(a).slice(0, 5).map((n) => ({ name: n.name, commits: n.commits, own_repo: n.own_repo })), self_declared_first_commit: dayOf(a.first_commit), self_declared_last_commit: dayOf(a.last_commit), self_declared_utc_offsets: a.commit_utc_offsets.slice(0, 4) });
  return {
    accounts: r.accounts.map((a) => ({ login: a.login, url: a.url, tie: a.how, account_type: a.account_type, ...(a.how === "commit_author" ? git(a) : {}) })),
    unattributed_commits: r.unattributed ? git(r.unattributed) : null,
    keys: r.keys.map((k) => (k.parsed ? { fingerprint: k.fingerprint, algorithm: keyAlgo(k), self_declared_created: dayOf(k.created), revoked: k.revoked, verified_addresses: k.user_ids.map((u) => u.email).filter(Boolean), self_declared_names: k.user_ids.map((u) => u.name).filter(Boolean) } : { unread: true, version: k.version })),
    not_answered: emailLookupsDown(r).map((x) => `${x.name}: ${x.state}`),
    ...(commitsNote(r) ? { commit_search_note: commitsNote(r) } : {}),
  };
}

// ---- GitHub activity ------------------------------------------------------------------------------
export const ACTIVITY_SOURCE = "GitHub activity";
export const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const ACTIVITY_STATES = ["ok", "none", "not_found"];
// GitHub lists 300 public events at most. A count far beyond that is not one a source returned.
const EVENTS_MAX = 100000;
const counts = (v, n) => (Array.isArray(v) && v.length === n && v.every((x) => Number.isFinite(x) && x >= 0) ? v.map((x) => Math.min(Math.floor(x), EVENTS_MAX)) : null);
const hourOf = (v) => (Number.isInteger(v) && v >= 0 && v <= 23 ? v : null);
// Offsets listed going east, in words. A list that crosses the date line (+12, then -11) is two
// runs joined by "or", so it is never read as one span from the first to the last.
const utc = (n) => `UTC${n === 0 ? "" : n > 0 ? `+${n}` : n}`;
export function offsetsLabel(offsets) {
  const runs = [];
  for (const o of offsets) { if (runs.length && o === runs.at(-1).at(-1) + 1) runs.at(-1).push(o); else runs.push([o]); }
  return runs.map((r) => (r.length === 1 ? utc(r[0]) : `${utc(r[0])} to ${utc(r.at(-1))}`)).join(" or ");
}
// With no usable list, the two ends: one span only when it does not wrap.
const endsLabel = (a, b) => (a <= b ? (a === b ? utc(a) : `${utc(a)} to ${utc(b)}`) : `${utc(a)} to UTC+12 or UTC-11 to ${utc(b)}`);
// The server's own sentence for a handle GitHub cannot hold. No other note is kept.
export const NOT_A_LOGIN_NOTE = "GitHub cannot hold this handle: a login is 1 to 39 letters, digits or hyphens, so nothing was asked.";
// Why no estimate was made. The code is the server's; the sentence is written here from the
// checked numbers, so a stored case or a case file cannot put words of its own in it.
// `unit` is the word for what was counted: "public events" on GitHub, a post site's own word there.
const REASON_CODES = ["too_few_events", "too_few_days", "no_quiet_window", "quiet_window_too_long", "ambiguous_quiet_window"];
export const BOT_REASON = "The account is marked as automated, so its hours say nothing about a person's day.";
function reasonText(code, r, unit = "public events") {
  if (code === "too_few_events") return `Too few ${unit} to say anything about hours: ${fmt(r.events)} seen.`;
  if (code === "too_few_days") return `The ${unit.split(" ").at(-1)} fall on too few days to show a daily pattern: ${fmt(r.window.active_days)} seen.`;
  if (code === "bot_account") return BOT_REASON;
  if (code === "no_quiet_window") return "No quiet stretch long enough to be a night: the account is active around the clock.";
  if (code === "quiet_window_too_long") return "The account is only active in a few hours of the day, so the quiet stretch is too long to place a night in.";
  if (code === "ambiguous_quiet_window") return "Two quiet stretches of about the same length, so neither can be called the night.";
  return "No estimate was made.";
}
export const ESTIMATE_ASSUMPTION = "Assumes one person who sleeps at least 6 hours inside the quiet stretch, with the middle of that sleep between 02:00 and 05:00 local time.";
export const ESTIMATE_CAVEAT = "A hint, not a fact. Shift work, scheduled jobs, bots and shared accounts all break it, and a UTC offset is not a place.";
// The answer is read into numbers and known words only. Every count is capped, every hour is 0 to
// 23, every offset is UTC-12 to UTC+14, and the list of offsets is used only when it runs east
// from the first end to the last one hour at a time. The label and the three sentences of an
// estimate (basis, assumption, caveat) are never kept from the answer: activityView writes them
// from the checked numbers, so a case file cannot add a claim ("lives in ...") to the estimate.
const off = (v) => (Number.isInteger(v) && v >= -12 && v <= 14 ? v : null);
function readEstimate(e) {
  const from = isObj(e) ? off(e.utc_offset_from) : null, to = isObj(e) ? off(e.utc_offset_to) : null;
  if (from === null || to === null) return null;
  const listed = [...new Set(list(e.utc_offsets, 27).filter((x) => off(x) !== null))];
  const east = listed.every((o, i) => i === 0 || o === listed[i - 1] + 1 || (listed[i - 1] >= 12 && o === listed[i - 1] - 23));
  const offs = listed.length && listed[0] === from && listed.at(-1) === to && east ? listed : [];
  const qs = hourOf(e.quiet_start_hour), qe = hourOf(e.quiet_end_hour), quiet = qs !== null && qe !== null;
  return {
    utc_offset_from: from, utc_offset_to: to, utc_offsets: offs,
    // A range that runs past the date line is two runs, and is never shown as one span.
    crosses_date_line: from > to,
    label: offs.length ? offsetsLabel(offs) : endsLabel(from, to),
    quiet_start_hour: quiet ? qs : null, quiet_end_hour: quiet ? qe : null,
    // The length of the stretch follows from its two ends.
    quiet_hours: quiet ? ((qe - qs + 24) % 24 || 24) : null, quiet_events: quiet ? capped(e.quiet_events, EVENTS_MAX) : null,
  };
}
// The part every activity answer shares, GitHub's and a post site's: the two histograms, the
// window, the count and the estimate. null when an "ok" answer has no histograms. `never` is a
// reason code that rules an estimate out whatever the answer carries (an automated account).
function activityBody(raw, never = "") {
  const hours = counts(raw.hours_utc, 24), days = counts(raw.weekdays_utc, 7);
  if (raw.state === "ok" && (!hours || !days)) return null;
  const w = isObj(raw.window) ? raw.window : {};
  const est = never ? null : readEstimate(raw.estimate);
  return {
    cached: raw.cached === true, complete: raw.complete !== false, pages: num(raw.pages, 20), events: num(raw.events, EVENTS_MAX),
    later_pages: ["rate_limited", "failed"].includes(raw.later_pages) ? raw.later_pages : "",
    window: { first: when(w.first), last: when(w.last), days: num(w.days, 400), active_days: Math.min(num(w.active_days, 400), num(w.days, 400)) },
    hours_utc: hours || Array(24).fill(0), weekdays_utc: days || Array(7).fill(0), estimate: est,
    code: never || (!est && isObj(raw.estimate_reason) && REASON_CODES.includes(raw.estimate_reason.code) ? raw.estimate_reason.code : "none"),
  };
}
export const readActivity = memo((raw) => {
  if (failed(raw)) return errorOf(raw);
  if (!ACTIVITY_STATES.includes(raw.state)) return null;
  const username = typeof raw.username === "string" && GH_LOGIN.test(raw.username) ? raw.username : "";
  // A handle GitHub cannot hold was never asked about: the answer says so in `note`.
  if (raw.state === "not_found") return { username, found: false, state: "not_found", events: 0, ...(raw.note === NOT_A_LOGIN_NOTE ? { note: NOT_A_LOGIN_NOTE } : {}) };
  const b = activityBody(raw);
  if (!b) return null;
  const out = {
    username, found: true, state: raw.state, cached: b.cached, complete: b.complete, pages: b.pages, events: b.events,
    ...(b.later_pages ? { later_pages: b.later_pages } : {}),
    window: b.window, hours_utc: b.hours_utc, weekdays_utc: b.weekdays_utc,
    types: list(raw.types, 12).map((t) => (isObj(t) && /^[A-Za-z]{1,40}$/.test(String(t.type)) ? { type: t.type, count: num(t.count, EVENTS_MAX) } : null)).filter(Boolean),
    repos: list(raw.repos, 10).map((x) => (isObj(x) && REPO.test(String(x.name)) ? { name: x.name, url: `https://github.com/${x.name}`, count: num(x.count, EVENTS_MAX) } : null)).filter(Boolean),
    estimate: b.estimate,
  };
  out.estimate_reason = b.estimate ? null : { code: b.code, text: reasonText(b.code, out) };
  return out;
});
const EVENT_WORD = { PushEvent: "pushes", PullRequestEvent: "pull requests", IssuesEvent: "issues", IssueCommentEvent: "issue comments", WatchEvent: "stars", ForkEvent: "forks", CreateEvent: "branches or repositories created", DeleteEvent: "branches deleted", PullRequestReviewEvent: "reviews", PullRequestReviewCommentEvent: "review comments", ReleaseEvent: "releases", PublicEvent: "repositories made public", MemberEvent: "collaborators added", GollumEvent: "wiki edits", CommitCommentEvent: "commit comments" };
export const eventWord = (t) => (Object.hasOwn(EVENT_WORD, t) ? EVENT_WORD[t] : String(t).replace(/Event$/, "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase());
const hh = (n) => `${String(n).padStart(2, "0")}:00`;
// The three sentences of an estimate, from the checked numbers and nothing else.
function estimateWords(r, one = "public event", many = `${one}s`) {
  const e = r.estimate, quiet = e.quiet_start_hour !== null && e.quiet_end_hour !== null ? `The longest quiet stretch is ${hh(e.quiet_start_hour)} to ${hh(e.quiet_end_hour)} UTC.` : "";
  return { label: e.label, basis: [`Based on ${plural(r.events, one, many)}${r.window.days ? ` over ${plural(r.window.days, "day")} (${fmt(r.window.active_days)} with activity)` : ""}.`, quiet].filter(Boolean).join(" "), assumption: ESTIMATE_ASSUMPTION, caveat: ESTIMATE_CAVEAT, quiet: "" };   // the basis names the quiet stretch; it is not said twice
}
// The two strips of an activity reading and their words. `things` starts both text alternatives
// ("Events", "Public posts").
function histView(r, things) {
  const top = Math.max(1, ...r.hours_utc), topDay = Math.max(1, ...r.weekdays_utc);
  const hours = r.hours_utc.map((count, hour) => ({ hour, count, pct: Math.round((count / top) * 100) }));
  const days = r.weekdays_utc.map((count, i) => ({ day: WEEKDAYS[i], count, pct: Math.round((count / topDay) * 100) }));
  const busiest = hours.filter((x) => x.count > 0).sort((a, b) => b.count - a.count || a.hour - b.hour).slice(0, 3);
  return {
    window: dayOf(r.window.first) && dayOf(r.window.last) ? `${dayOf(r.window.first)} to ${dayOf(r.window.last)}` : "", hours, days,
    hoursAlt: `${things} by hour of day, UTC: ${hours.map((x) => `${hh(x.hour)} ${x.count}`).join(", ")}.`,
    daysAlt: `${things} by weekday, UTC: ${days.map((x) => `${x.day} ${x.count}`).join(", ")}.`,
    busiest: busiest.length ? `Busiest hours (UTC): ${busiest.map((x) => `${hh(x.hour)} (${x.count})`).join(", ")}.` : "",
  };
}
// Everything the page says about the activity, in words, so the two strips always have a text
// alternative and the exports say the same thing.
//   { state, text, window, hours: [{ hour, count, pct }], days: [{ day, count, pct }], hoursAlt,
//     daysAlt, busiest, repos, types, estimate: { label, basis, assumption, caveat } | null, noEstimate }
export function activityView(d) {
  const r = readActivity(d);
  if (!r || failed(r)) return null;
  if (r.state === "not_found") return { state: "not_found", text: r.note === NOT_A_LOGIN_NOTE ? NOT_A_LOGIN_NOTE : "GitHub has no account with this name.", events: 0 };
  if (r.state === "none") return { state: "none", text: "The account exists and has no public events in the window GitHub keeps (about 90 days, 300 events at most).", events: 0 };
  const g = histView(r, "Events");
  const partial = r.complete ? "" : ` GitHub ${r.later_pages === "rate_limited" ? "rate limited" : "failed on"} a later page, so older events are missing.`;
  return {
    state: "ok", events: r.events, complete: r.complete, username: r.username,
    text: `${plural(r.events, "public event")}${g.window ? ` from ${g.window}` : ""}${r.window.days ? ` (${plural(r.window.days, "day")}, active on ${r.window.active_days})` : ""}. Times are UTC.${partial}`,
    ...g,
    repos: r.repos, types: r.types.map((t) => ({ ...t, word: eventWord(t.type) })),
    estimate: r.estimate ? estimateWords(r) : null,
    noEstimate: r.estimate ? "" : reasonText(r.estimate_reason?.code, r),
  };
}
export function activityForAi(d) {
  const v = activityView(d);
  if (!v) return null;
  if (v.state !== "ok") return { state: v.state, note: v.text };
  return { state: "ok", summary: v.text, hours_utc: v.hours.map((x) => x.count), weekdays_utc: Object.fromEntries(v.days.map((x) => [x.day, x.count])), top_repositories: v.repos.slice(0, 5).map((x) => `${x.name} (${x.count})`), event_types: v.types.slice(0, 6).map((t) => `${t.word} (${t.count})`),
    utc_offset_estimate: v.estimate ? { range: v.estimate.label, basis: v.estimate.basis, assumption: v.estimate.assumption, caveat: v.estimate.caveat } : null, no_estimate_reason: v.noEstimate };
}
// standing: githubStanding(ev) from evidence.js. When the account is not the case's own, the
// heading and the first line say whose activity this is.
export function activityMarkdown(d, standing = { own: true, text: "" }) {
  const v = activityView(d);
  if (!v) return [];
  const head = standing.own ? ["## GitHub activity"] : ["## GitHub activity (not the person this case is about)", `_${standing.text}_`];
  if (v.state !== "ok") return [...head, `- ${v.text}`, ""];
  return [...head, `- ${v.text} _(site record)_`, ...(v.busiest ? [`- ${v.busiest}`] : []), `- ${v.daysAlt}`,
    ...(v.repos.length ? [`- Most active in: ${v.repos.slice(0, 5).map((x) => `[${x.name}](${x.url}) (${x.count})`).join(", ")}`] : []),
    ...(v.types.length ? [`- Kinds of event: ${v.types.slice(0, 6).map((t) => `${t.word} (${t.count})`).join(", ")}`] : []),
    v.estimate ? `- UTC offset estimate: ${v.estimate.label}. ${v.estimate.basis} ${v.estimate.assumption} ${v.estimate.caveat} This is a range of time offsets, never a place.` : `- No UTC offset estimate: ${v.noEstimate}`, ""];
}

// ---- archived copies of one profile ---------------------------------------------------------------
// Asked on a click, for one read profile (POST /api/recon/profile-archive). The answer is kept with
// the case as collected.archives, keyed by the row it belongs to.
//   ok            the archive holds copies: first and last capture, and `count`, which is the
//                 number of DAYS with a capture (never the number of captures)
//   none          the archive answered and holds no copy. An answer.
//   rate_limited, failed   the archive could not be asked. Unknown, never "no copies".
//   refused       no request was made, and `note` says why
// A snapshot address is rebuilt here from its timestamp and the profile address, so a stored case
// or a case file cannot point one somewhere else. A profile address that carries a query (Hacker
// News: see ownProfileQuery in links.js) is never looked up: the snapshot address would carry
// that query, and with it the handle, on archive.org.
export const ARCHIVE_SOURCE = "Internet Archive";
export const ARCHIVE_STATES = ["ok", "none", "rate_limited", "failed", "refused"];
export const ARCHIVE_REFUSALS = [
  "CrawlR does not look up archived copies of pages on adult or dating sites.",
  "This is not a plain http or https web address, so it was not looked up.",
  "This address is not on a public named host, so it was not looked up.",
];
export const ARCHIVE_NONE_NOTE = "The archive holds no capture of the page itself. Captures that were a redirect or an error are not counted, so the address may still appear in the archive.";
const SNAPSHOT_BASE = "https://web.archive.org/web/";
const stamp = (iso) => { const t = when(iso); return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(t) ? t.replace(/[-:TZ]/g, "") : ""; };
// May archived copies of this address be looked up? http(s), no credentials, no port, no query,
// no fragment, a path of its own, and never an adult or dating site.
export function archivable(u) {
  const s = safeLink(u), x = s ? parseUrl(s) : null;
  return !!x && !x.port && !x.search && !x.hash && !s.includes("*") && x.pathname.replace(/\/+$/, "").length > 0 && s.length <= 600;
}
export function readArchive(raw, url) {
  if (!isObj(raw) || !ARCHIVE_STATES.includes(raw.state) || !archivable(url)) return null;
  const base = { url, state: raw.state, count: 0, first: "", last: "", snapshots: [], distinct_versions: 0, truncated: false, asked_at: Number.isFinite(raw.asked_at) && raw.asked_at > 0 ? raw.asked_at : 0 };
  if (raw.state === "refused") return { ...base, note: ARCHIVE_REFUSALS.includes(raw.note) ? raw.note : "This address was not looked up." };
  if (raw.state === "failed" || raw.state === "rate_limited") return { ...base, ...errorOf(raw) };
  if (raw.state === "none") return { ...base, ...(raw.note === ARCHIVE_NONE_NOTE ? { note: ARCHIVE_NONE_NOTE } : {}) };
  const snaps = [], seen = new Set();
  for (const sn of list(raw.snapshots, 8)) { const ts = isObj(sn) ? stamp(sn.timestamp) : ""; if (ts && !seen.has(ts)) { seen.add(ts); snaps.push({ timestamp: when(sn.timestamp), url: `${SNAPSHOT_BASE}${ts}/${url}` }); } }
  const first = stamp(raw.first) ? when(raw.first) : "", last = stamp(raw.last) ? when(raw.last) : "";
  // "ok" with nothing to show for it showed nothing: unknown, not "none".
  if (!first || !last || !snaps.length || !(int(raw.count) > 0)) return { ...base, state: "failed", error: "The archive's answer could not be read.", error_code: "bad_response", error_detail: "" };
  return { ...base, count: int(raw.count), first, last, snapshots: snaps, distinct_versions: num(raw.distinct_versions), truncated: raw.truncated === true };
}
// collected.archives: { [row key]: answer } (byRow, below).
export const readArchives = byRow((v) => readArchive(v, typeof v.url === "string" ? v.url.trim() : ""));
// What the row says, in words: { state, text, snapshots: [{ label, url, link_kind }], retry }.
export function archiveView(a) {
  if (!a) return null;
  if (a.state === "ok") {
    const one = a.count === 1;
    return { state: "ok", retry: false,
      text: `The Internet Archive holds copies of this page captured on ${plural(a.count, "day")}${a.truncated ? " or more" : ""}${one ? `, on ${dayOf(a.first)}` : `, first on ${dayOf(a.first)} and last on ${dayOf(a.last)}`}${a.distinct_versions > 1 ? `, in ${fmt(a.distinct_versions)} different versions` : ""}. A copy can show a bio or a link that has since been removed. Open one to read it: CrawlR does not fetch them.`,
      snapshots: a.snapshots.map((sn) => ({ label: dayOf(sn.timestamp), url: sn.url, link_kind: "evidence" })), first: dayOf(a.first), last: dayOf(a.last), count: a.count };
  }
  if (a.state === "none") return { state: "none", retry: false, snapshots: [], text: `The Internet Archive answered and holds no copy of this page.${a.note ? ` ${a.note}` : ""}` };
  if (a.state === "refused") return { state: "refused", retry: false, snapshots: [], text: `Not looked up. ${a.note}` };
  return { state: a.state, retry: true, snapshots: [], text: a.state === "rate_limited" ? "The Internet Archive is rate limiting requests, so whether it holds copies is unknown. Try again in a minute." : "The Internet Archive could not be asked, so whether it holds copies is unknown." };
}
export const archiveMarkdown = (v) => (v ? [`  - Archived copies: ${v.text}${v.snapshots.length ? ` Snapshots: ${v.snapshots.map((x) => `[${x.label}](${x.url})`).join(", ")}` : ""} _(${ARCHIVE_SOURCE}${v.state === "ok" || v.state === "none" ? " · archive record" : ""})_`] : []);

// ---- commit emails ----------------------------------------------------------------------------------
// Asked on a click, for one read GitLab, Codeberg or Gitea.com profile (POST /api/recon/commit-emails).
// Kept with the case as collected.commitEmails, keyed by the row. Two things are kept apart:
//   state          about the account: one of the seven profile states
//   emails_state   about the addresses: "found" (rows), "none" (everything asked answered and no
//                  address of the account was on a commit) or "unknown" (a part did not answer and
//                  nothing was read). "unknown" is never "no addresses".
// complete: false with rows means "these, and maybe more". Every name, address and date in a row
// was typed by the commit's author: self-declared, and a lead to check.
export const COMMIT_EMAILS_SOURCE = "Commit emails";
// id -> [site name, the host the profile and its repositories must be on]
export const COMMIT_EMAIL_SITES = { gitlab: ["GitLab", "gitlab.com"], codeberg: ["Codeberg", "codeberg.org"], gitea: ["Gitea.com", "gitea.com"] };
export const COMMIT_HOWS = ["forge_attributed", "author_line_match"];
export const COMMIT_HOW_TEXT = {
  forge_attributed: "The site links these commits to this account by the address, so the account holds the address there.",
  author_line_match: "A commit under this account's name carries this address. Anybody can commit under any name, so this ties the address to the account only weakly.",
};
export const COMMIT_EMAILS_NOTE = "Names, addresses and dates inside commits are typed by the author and checked by nobody. They are self-declared and can be forged. A row is a lead to check, not a confirmed address.";
// May commit emails be asked for this row? { site, username } or null. A source id alone
// answers for the site, with an empty username.
export function commitEmailsFor(p) {
  const a = askable(p, (id) => Object.hasOwn(COMMIT_EMAIL_SITES, id));
  return a ? { site: a.id, username: a.username } : null;
}
const FORGE_REPO = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const REPOS_SECTION = ["ok", "none", "not_asked", "blocked", "rate_limited", "unknown", "failed", "not_found"];
const REPO_STATES = ["ok", "empty", "blocked", "rate_limited", "unknown", "failed"];
// Three repositories of thirty commits are read at most. A count beyond this is not one the source returned.
const COMMITS_MAX = 10000;
export const readCommitEmail = memo((raw) => {
  if (typeof raw.site !== "string" || !Object.hasOwn(COMMIT_EMAIL_SITES, raw.site)) return null;
  const [site_name, host] = COMMIT_EMAIL_SITES[raw.site];
  let state = PROFILE_STATES.includes(raw.state) ? raw.state : failed(raw) ? "failed" : "";
  if (!state) return null;
  const profile_url = state === "found" && onHost(safeLink(raw.profile_url), host) ? safeLink(raw.profile_url) : "";
  // "found" with no profile on the site behind it showed nothing: unknown, not found.
  if (state === "found" && !profile_url) state = "unknown";
  const found = state === "found", seen = new Set();
  const emails = (found ? list(raw.emails, 10) : []).map((e) => {
    const addr = isObj(e) ? email(e.email) : "";
    if (!addr || seen.has(addr)) return null;
    seen.add(addr);
    return {
      // An unknown tie is the weaker one.
      email: addr, name: line(e.name, 100), how: e.how === "forge_attributed" ? "forge_attributed" : "author_line_match", commits: num(e.commits, COMMITS_MAX),
      first_commit: when(e.first_commit), last_commit: when(e.last_commit), repos: [...new Set(list(e.repos, 3).filter((r) => typeof r === "string" && FORGE_REPO.test(r)))],
    };
  }).filter(Boolean).sort((a, b) => COMMIT_HOWS.indexOf(a.how) - COMMIT_HOWS.indexOf(b.how));
  const sec = isObj(raw.sections) && REPOS_SECTION.includes(raw.sections.repos) ? raw.sections.repos : found ? "unknown" : "not_asked";
  const repos = (found ? list(raw.repos, 3) : []).map((r) => (isObj(r) && typeof r.name === "string" && FORGE_REPO.test(r.name)
    ? { name: r.name, url: `https://${host}/${r.name}`, fork: r.fork === true ? true : r.fork === false ? false : null, state: REPO_STATES.includes(r.state) ? r.state : "unknown", commits_seen: num(r.commits_seen, COMMITS_MAX) } : null)).filter(Boolean);
  // Complete: the account answered, the repository list answered, and so did every repository asked.
  const complete = raw.complete === true && (state === "not_found" || state === "not_asked" || (found && (sec === "ok" || sec === "none") && repos.every((r) => r.state === "ok" || r.state === "empty")));
  // "none" is an answer, so it needs everything asked to have answered. "found" with no readable
  // row, and every state in which the site did not say, is unknown.
  const emails_state = emails.length ? "found" : state === "not_found" || (found && complete && raw.emails_state === "none") ? "none" : "unknown";
  const c = isObj(raw.counts) ? raw.counts : {};
  return {
    site: raw.site, site_name, username: line(raw.username, 64), state, cached: raw.cached === true,
    handle: found ? line(raw.handle, 80) : "", profile_url, display_name: found ? line(raw.display_name, 200) : "",
    emails, emails_state, complete, sections: { account: state, repos: sec }, repos,
    counts: Object.fromEntries(["repos_listed", "repos_read", "commits_seen", "own", "noreply", "other_authors"].map((k) => [k, num(c[k], COMMITS_MAX)])),
    ...retryAfter(raw), ...(state === "failed" || state === "rate_limited" ? errorOf(raw) : {}), asked_at: askedAt(raw),
  };
});
export const readCommitEmails = byRow(readCommitEmail);
const REPO_DOWN = { blocked: "was refused", rate_limited: "was rate limited", unknown: "gave an answer that could not be read", failed: "failed", not_found: "was not found" };
// What the row says, in words:
//   { state, text, rows: [{ email, name, how, howText, strong, commits, first, last, repos: [{ name, url, link_kind }] }], partial, retry, note }
// state: "found", "none" or "unknown" for an account that was read, else the account's own state.
// "unknown" and every state in which the site did not say have retry: true and never read as "none found".
export function commitEmailsView(d) {
  const a = readCommitEmail(d);
  if (!a) return null;
  const site = a.site_name, base = { rows: [], partial: false, note: COMMIT_EMAILS_NOTE };
  const unknown = `whether its commits carry an address is unknown`;
  if (a.state === "not_found") return { ...base, state: "not_found", retry: false, text: `${site} has no account with this name, so no commits were read.` };
  if (a.state === "not_asked") return { ...base, state: "not_asked", retry: false, text: `${site} cannot hold this handle, so nothing was asked.` };
  if (a.state === "blocked") return { ...base, state: "blocked", retry: true, text: `${site} refused the request, so ${unknown}.` };
  if (a.state === "rate_limited") return { ...base, state: "rate_limited", retry: true, text: `${site} is rate limiting requests, so ${unknown}.${waitText(a.retry_after)}` };
  if (a.state === "failed") return { ...base, state: "failed", retry: true, text: `${site} could not be asked, so ${unknown}.` };
  if (a.state === "unknown") return { ...base, state: "unknown", retry: true, text: `${site} gave an answer CrawlR could not read, so ${unknown}.` };
  const urls = Object.fromEntries(a.repos.map((r) => [r.name, r.url])), [, host] = COMMIT_EMAIL_SITES[a.site];
  const rows = a.emails.map((e) => ({
    email: e.email, name: e.name, how: e.how, howText: COMMIT_HOW_TEXT[e.how], strong: e.how === "forge_attributed", commits: e.commits, first: dayOf(e.first_commit), last: dayOf(e.last_commit),
    repos: e.repos.map((name) => ({ name, url: urls[name] || `https://${host}/${name}`, link_kind: "evidence" })),
  }));
  const read = `the ${plural(a.counts.commits_seen, "commit")} read`;
  const down = a.sections.repos !== "ok" && a.sections.repos !== "none" ? `the repository list ${REPO_DOWN[a.sections.repos] || "did not answer"}` : (() => { const r = a.repos.find((x) => x.state !== "ok" && x.state !== "empty"); return r ? `${r.name} ${REPO_DOWN[r.state]}` : "a part did not answer"; })();
  if (a.emails_state === "found") {
    const n = `${plural(rows.length, "address", "addresses")} of this account on ${read}`;
    return { ...base, state: "found", rows, partial: !a.complete, retry: !a.complete, text: a.complete ? `${n}.` : `These, and maybe more: ${n}, and ${down}.` };
  }
  if (a.emails_state === "none") {
    const why = a.sections.repos === "none" ? "The account has no public repository of its own, so there were no commits to read." : `No address of this account on ${read}.`;
    const left = [a.counts.noreply ? `${plural(a.counts.noreply, "commit")} of its own ${a.counts.noreply === 1 ? "carries" : "carry"} a "noreply" placeholder, which is not an address` : "", a.counts.other_authors ? `${plural(a.counts.other_authors, "commit")} by other authors ${a.counts.other_authors === 1 ? "was" : "were"} left out` : ""].filter(Boolean).join(", and ");
    return { ...base, state: "none", retry: false, text: `${why}${left ? ` ${left.charAt(0).toUpperCase()}${left.slice(1)}.` : ""}` };
  }
  return { ...base, state: "unknown", retry: true, text: `Could not read the commits: ${down}. Whether an address is there is unknown.${a.retry_after ? waitText(a.retry_after) : ""}` };
}
// Each address is a place to look next, one hop on a click: [{ kind: "email", value, from, how, strong }].
// Whether a lead is tied to the person is decided by the row's standing, not here.
export function commitEmailLeads(d) {
  const a = readCommitEmail(d);
  if (!a || a.emails_state !== "found") return [];
  return a.emails.map((e) => ({ kind: "email", value: e.email, how: e.how, strong: e.how === "forge_attributed",
    from: e.how === "forge_attributed" ? `an address ${a.site_name} ties to this account through its commits (written in the commit, so self-declared)` : `an address on a commit made under this ${a.site_name} account's name (the weaker tie: anybody can commit under any name)` }));
}
// Indented Markdown lines under the row.
export const commitEmailsMarkdown = (v) => (v ? [`  - Commit emails: ${v.text} _(${COMMIT_EMAILS_SOURCE}${v.rows.length ? " · self-declared" : ""})_`,
  ...v.rows.map((r) => `    - ${r.email}${r.name ? `, name on the commits: ${r.name}` : ""}, ${plural(r.commits, "commit")}${r.first && r.last ? ` (${r.first === r.last ? r.first : `${r.first} to ${r.last}`})` : ""}${r.repos.length ? ` in ${r.repos.map((x) => `[${x.name}](${x.url})`).join(", ")}` : ""}. ${r.howText}`),
  ...(v.rows.length ? [`    - ${v.note}`] : [])] : []);
// What the model is told: at most 5 addresses, each with its tie and marked self-declared.
export function commitEmailsForAi(d) {
  const a = readCommitEmail(d), v = a ? commitEmailsView(a) : null;
  if (!v) return null;
  return { site: a.site_name, state: v.state, complete: a.complete, summary: v.text, addresses: a.emails.slice(0, 5).map((e) => ({ email: e.email, tie: e.how, self_declared: true, commits: e.commits })), ...(a.emails.length ? { caution: COMMIT_EMAILS_NOTE } : {}) };
}

// ---- post activity ----------------------------------------------------------------------------------
// Asked on a click, for one read Hacker News, Mastodon or Lobsters profile (POST /api/recon/post-activity).
// Kept with the case as collected.postActivity, keyed by the row. The reading has the shape
// readActivity returns, so one renderer draws both, plus `site`, `instance`, `unit`, `bot` and `read`.
//   ok            posts were counted
//   none          the account exists and nothing was listed. An answer (on Lobsters: no submitted
//                 stories; the account may still comment)
//   not_found     the site's own "no such account"; not_asked: true when the site cannot hold the
//                 handle and no request was made
//   rate_limited, failed   the site could not be asked. Unknown, never "no posts".
export const POST_ACTIVITY_SOURCE = "Post activity";
// What a site counts. unit / one: the word for it, used where GitHub's reading says "public events".
export const POST_ACTIVITY_SITES = {
  hackernews: { name: "Hacker News", unit: "public posts", one: "public post", cap: 1000, types: { comment: "comments", story: "stories", poll: "polls", pollopt: "poll options", job: "job posts" } },
  mastodon: { name: "Mastodon", unit: "public posts", one: "public post", cap: 200, types: { post: "posts", reply: "replies", boost: "boosts" } },
  lobsters: { name: "Lobsters", unit: "submitted stories", one: "submitted story", cap: 100, types: { story: "stories" } },
};
export const POST_ACTIVITY_STATES = ["ok", "none", "not_found", "rate_limited", "failed"];
export const POST_WINDOW_DAYS = 365;
// May post activity be asked for this row? { site, username, instance? } or null. The instance
// of a Mastodon row comes from its source id or its address, and is one of the known ones. The
// handle is sent as the row has it: Hacker News names are case sensitive.
export function postActivityFor(p) {
  const a = askable(p, (id) => id === "hackernews" || id === "lobsters" || !!mastodonInstance(id));
  if (!a) return null;
  const instance = mastodonInstance(a.id);
  return instance ? { site: "mastodon", username: a.username, instance } : { site: a.id, username: a.username };
}
// "Hacker News", "Mastodon (fosstodon.org)": the name a reading goes by.
export const postActivityLabel = (a) => (a && Object.hasOwn(POST_ACTIVITY_SITES, a.site) ? (a.site === "mastodon" && a.instance && a.instance !== "mastodon.social" ? `Mastodon (${a.instance})` : POST_ACTIVITY_SITES[a.site].name) : "");
const notAHandle = (name) => `${name} cannot hold this handle, so nothing was asked.`;
export const readPostActivity = memo((raw) => {
  const site = typeof raw.site === "string" && Object.hasOwn(POST_ACTIVITY_SITES, raw.site) ? raw.site : "";
  const state = POST_ACTIVITY_STATES.includes(raw.state) ? raw.state : failed(raw) ? "failed" : "";
  // An answer about an instance CrawlR does not read is not an answer. No instance is mastodon.social.
  const instance = site === "mastodon" ? (raw.instance ? mastodonInstance(raw.instance) : MASTODON_INSTANCES[0]) : "";
  if (!site || !state || (site === "mastodon" && !instance)) return null;
  const spec = POST_ACTIVITY_SITES[site];
  const head = { site, site_name: spec.name, instance, username: line(raw.username, 64), unit: spec.unit };
  if (state === "failed" || state === "rate_limited") return { ...head, found: null, state, ...errorOf(raw), ...retryAfter(raw), asked_at: askedAt(raw) };
  if (state === "not_found") return { ...head, found: false, state, events: 0, ...(raw.not_asked === true || raw.note === notAHandle(spec.name) ? { not_asked: true } : {}), asked_at: askedAt(raw) };
  // An automated account is counted and never estimated. Only Mastodon says which accounts are.
  const bot = site === "mastodon" && raw.bot === true;
  const b = activityBody(raw, bot ? "bot_account" : "");
  if (!b) return null;
  // The count is the histogram's own sum, so the sentence and the strip cannot disagree. "ok"
  // with nothing counted showed nothing: it reads as "none".
  const events = b.hours_utc.reduce((n, x) => n + x, 0), ok = state === "ok" && events > 0;
  const rd = isObj(raw.read) ? raw.read : {};
  const out = {
    ...head, found: true, state: ok ? "ok" : "none", cached: b.cached, complete: b.complete, pages: b.pages, events: ok ? Math.min(events, EVENTS_MAX) : 0,
    ...(b.later_pages ? { later_pages: b.later_pages } : {}),
    window: ok ? b.window : { first: "", last: "", days: 0, active_days: 0 }, hours_utc: ok ? b.hours_utc : Array(24).fill(0), weekdays_utc: ok ? b.weekdays_utc : Array(7).fill(0),
    types: ok ? list(raw.types, 8).map((t) => (isObj(t) && typeof t.type === "string" && Object.hasOwn(spec.types, t.type) ? { type: t.type, count: num(t.count, EVENTS_MAX) } : null)).filter(Boolean) : [],
    repos: [], estimate: ok ? b.estimate : null,
  };
  out.estimate_reason = out.estimate ? null : { code: ok ? b.code : "none", text: reasonText(ok ? b.code : "none", out, spec.unit) };
  return { ...out, bot, read: { posts: num(rd.posts, EVENTS_MAX), outside_window: num(rd.outside_window, EVENTS_MAX), capped: rd.capped === true, available: capped(rd.available) }, asked_at: askedAt(raw) };
});
export const readPostActivities = byRow(readPostActivity);
const cap1 = (s) => s.charAt(0).toUpperCase() + s.slice(1);
// What is counted on each site, as the strip's footnote. Written here, not kept from the answer.
function postFootnote(a) {
  const win = (thing) => `Only the ${POST_WINDOW_DAYS} days before the newest ${thing} are counted.`;
  if (a.site === "hackernews") return `Counted: stories and comments, the newest ${fmt(1000)} at most. ${win("post")}`;
  if (a.site === "mastodon") return `Counted: public posts, replies and boosts of the local account on ${a.instance}, the newest 200 at most. ${win("post")}`;
  return `Counted: submitted stories only, the newest 100 at most. Lobsters has no public list of a user's comments, so comments are not counted. ${win("story")}`;
}
// The keys activityView returns (state, text, events, complete, username, window, hours, days,
// hoursAlt, daysAlt, busiest, repos, types, estimate, noEstimate), in the site's own unit word, and:
//   site, label, unit, bot   which reading this is
//   footnote                 what is counted, and what was read and left out
//   partial, capped          the two sentences for a short reading ("" when it is whole). partial
//                            is already part of `text`, capped of `footnote`.
//   retry                    true when the site could not be asked: unknown, never "no posts"
export function postActivityView(d) {
  const a = readPostActivity(d);
  if (!a) return null;
  const spec = POST_ACTIVITY_SITES[a.site], label = postActivityLabel(a), where = a.site === "mastodon" ? a.instance : spec.name;
  const base = { site: a.site, label, unit: a.unit, username: a.username, events: 0, bot: false, footnote: "", partial: "", capped: "", retry: false };
  if (a.state === "rate_limited") return { ...base, state: "rate_limited", retry: true, text: `${where} is rate limiting requests, so when this account posts is unknown.${waitText(a.retry_after)}` };
  if (a.state === "failed") return { ...base, state: "failed", retry: true, text: `${where} could not be asked, so when this account posts is unknown.` };
  if (a.state === "not_found") return { ...base, state: "not_found", text: a.not_asked ? notAHandle(spec.name) : a.site === "mastodon" ? `${where} has no local account with this name.` : `${where} has no account with this name.${a.site === "hackernews" ? " Hacker News names are case sensitive." : ""}` };
  const footnote = postFootnote(a);
  if (a.state === "none") return { ...base, state: "none", footnote, bot: a.bot,
    text: a.site === "lobsters" ? "The account exists and has no submitted stories. Lobsters has no public list of a user's comments, so the account may still comment." : a.site === "mastodon" ? `The account exists and has no public posts on ${where}.` : "The account exists and has no public posts: no story and no comment is listed." };
  const g = histView(a, cap1(a.unit));
  const partial = a.complete ? "" : `Partial: ${where} ${a.later_pages === "rate_limited" ? "rate limited" : "failed on"} a later page, so older ${a.unit.split(" ").at(-1)} are missing.`;
  const capped = a.read.capped ? `The newest ${fmt(a.read.posts)} were read; ${a.read.available !== null && a.read.available > a.read.posts ? `the site says the account has ${fmt(a.read.available)}` : "the account has more"}.` : "";
  const older = a.read.outside_window ? `${cap1(plural(a.read.outside_window, "older one"))} ${a.read.outside_window === 1 ? "was" : "were"} read and not counted.` : "";
  return {
    ...base, state: "ok", events: a.events, complete: a.complete, bot: a.bot,
    text: `${plural(a.events, spec.one, spec.unit)}${g.window ? ` from ${g.window}` : ""}${a.window.days ? ` (${plural(a.window.days, "day")}, active on ${a.window.active_days})` : ""}. Times are UTC.${partial ? ` ${partial}` : ""}`,
    ...g, repos: [], types: a.types.map((t) => ({ ...t, word: spec.types[t.type] })),
    estimate: a.estimate ? estimateWords(a, spec.one, spec.unit) : null, noEstimate: a.estimate ? "" : reasonText(a.estimate_reason?.code, a, a.unit),
    footnote: [footnote, capped, older].filter(Boolean).join(" "), partial, capped,
  };
}
export function postActivityForAi(d) {
  const v = postActivityView(d);
  if (!v) return null;
  if (v.state !== "ok") return { site: v.label, state: v.state, note: v.text };
  return { site: v.label, state: "ok", summary: v.text, counted: v.footnote, hours_utc: v.hours.map((x) => x.count), weekdays_utc: Object.fromEntries(v.days.map((x) => [x.day, x.count])), kinds: v.types.slice(0, 5).map((t) => `${t.word} (${t.count})`),
    ...(v.bot ? { automated_account: true } : {}),
    utc_offset_estimate: v.estimate ? { range: v.estimate.label, basis: v.estimate.basis, assumption: v.estimate.assumption, caveat: v.estimate.caveat } : null, no_estimate_reason: v.noEstimate };
}
// standing: { own, text } as activityMarkdown takes it, for the account the reading is about.
export function postActivityMarkdown(d, standing = { own: true, text: "" }) {
  const v = postActivityView(d);
  if (!v) return [];
  const head = standing.own ? [`## ${v.label} post activity`] : [`## ${v.label} post activity (not the person this case is about)`, `_${standing.text}_`];
  if (v.state !== "ok") return [...head, `- ${v.text}`, ""];
  return [...head, `- ${v.text} _(site record)_`, ...(v.busiest ? [`- ${v.busiest}`] : []), `- ${v.daysAlt}`,
    ...(v.types.length ? [`- Kinds of post: ${v.types.map((t) => `${t.word} (${t.count})`).join(", ")}`] : []),
    v.estimate ? `- UTC offset estimate: ${v.estimate.label}. ${v.estimate.basis} ${v.estimate.assumption} ${v.estimate.caveat} This is a range of time offsets, never a place.` : `- No UTC offset estimate: ${v.noEstimate}`,
    `- ${v.footnote}`, ""];
}

// ---- do the offset ranges fit? -----------------------------------------------------------------------
// Made here from readings the case already holds; no request. The same rule as the server's tested
// reference (compare_offsets in modules/activity_pattern.py). Only readings of accounts in one
// identity group are compared, and the verdict never moves a profile between groups.
//   agree            two or more ranges, and at least one offset is in all of them
//   disagree         two or more ranges, and no offset is in all of them
//   not_enough_data  fewer than two readings carry a range
export const OFFSETS_AGREE_NOTE = "This supports one person behind these accounts and does not prove it: a large share of the world lives in any few offsets.";
export const OFFSETS_DISAGREE_NOTE = "This does not show two people: one account may be scheduled, automated, or used only at work.";
export const OFFSETS_NOT_A_PLACE = "A range of UTC offsets is never a place.";
// answers: [{ label, answer }], each answer a checked reading (readActivity or readPostActivity).
// Returns { verdict, compared, shared, label, labels, text, caution }.
export function compareOffsets(answers) {
  const used = [];
  for (const x of Array.isArray(answers) ? answers : []) {
    const a = isObj(x) ? x.answer : null, offs = isObj(a) && a.state === "ok" && isObj(a.estimate) ? a.estimate.utc_offsets : null;
    if (Array.isArray(offs) && offs.length && offs.every((o) => Number.isInteger(o) && o >= -11 && o <= 12)) used.push({ label: line(x.label, 60) || "An account", offs });
  }
  const labels = used.map((u) => u.label);
  if (used.length < 2) return { verdict: "not_enough_data", compared: used.length, shared: [], label: "", labels, text: used.length === 1 ? "Only one account has enough activity to compare." : "", caution: "" };
  const shared = used[0].offs.filter((o) => used.slice(1).every((u) => u.offs.includes(o)));   // keeps the first range's eastward order
  const label = shared.length ? offsetsLabel(shared) : "";
  return shared.length
    ? { verdict: "agree", compared: used.length, shared, label, labels, text: `${andList(labels)} fit the same range (${label}).`, caution: `${OFFSETS_AGREE_NOTE} ${OFFSETS_NOT_A_PLACE}` }
    : { verdict: "disagree", compared: used.length, shared, label, labels, text: `${andList(labels)} do not fit one range.`, caution: `${OFFSETS_DISAGREE_NOTE} ${OFFSETS_NOT_A_PLACE}` };
}

// ---- what changed between two archived copies ------------------------------------------------------------
// Asked on a click, for two captures the profile archive listed (POST /api/recon/archive-diff). The
// last pair compared for a row is kept as collected.archiveDiffs[row key].
//   ok            both captures were read; `removed` is what the older has and the newer lacks,
//                 `added` the other way round
//   same          both were read and no text line or link differs (same_capture: the archive
//                 answered both times with one capture, so nothing was compared)
//   none          a capture is missing: `missing` names the side, and the side says why
//   rate_limited, failed   the archive could not be asked. Unknown, never "no difference".
//   refused       no request was made, and `note` says why
// Snapshot addresses are rebuilt from the timestamps and the profile address. A text line is a
// plain string ("<" is text). A link is an address found on an archived page: CrawlR did not
// build it and never fetches it.
export const ARCHIVE_DIFF_STATES = ["ok", "same", "none", "rate_limited", "failed", "refused"];
export const ARCHIVE_DIFF_REFUSALS = {
  adult_site: ARCHIVE_REFUSALS[0], bad_url: ARCHIVE_REFUSALS[1], not_public_host: ARCHIVE_REFUSALS[2],
  bad_timestamp: "A capture time must be one the capture list returned, so nothing was fetched.",
  same_timestamp: "Both capture times are the same capture, so there is nothing to compare.",
};
export const ARCHIVE_SIDE_NOTES = {
  missing: "The archive holds no capture of this address at or near that time.",
  redirect: "That capture is a redirect to another page, not the profile itself.",
  not_a_page: "That capture is not an HTML or text page, so it was not read.",
};
export const ARCHIVE_SAME_CAPTURE_NOTE = "The archive answered both times with the same capture.";
// How a difference is to be read. Shown with every "ok" answer.
export const ARCHIVE_DIFF_CAVEATS = [
  "The two copies are compared by line and by link, not by position: a line that only moved is not listed.",
  "Removed does not mean deleted by the owner. The site may have dropped a field, or the capture may be of another variant of the page.",
  "Numbers that change all the time, such as followers or stars, show up as a removed line and an added one.",
  "Captures far apart differ in layout too, so menus and footers of both designs end up in the lists. Neighbouring captures give a cleaner answer.",
];
export const ARCHIVE_INEXACT_NOTE = "The archive had no capture at exactly the time asked and answered with the nearest one. Each column is labelled with the capture that was really read.";
const SIDE_STATES = ["ok", "none", "rate_limited", "failed"];
const BODY_MAX = 4e6, LINES_MAX = 5000, LINKS_MAX = 2000;
function diffSide(s, url) {
  if (!isObj(s) || !SIDE_STATES.includes(s.state)) return null;
  const ts = stamp(s.timestamp) ? when(s.timestamp) : "", asked = stamp(s.asked) ? when(s.asked) : ts;
  const reason = s.state === "none" ? (Object.hasOwn(ARCHIVE_SIDE_NOTES, s.reason) ? s.reason : "missing") : "";
  return {
    // exact follows from the two times: the capture read is the one asked for, or it is not.
    state: s.state, timestamp: ts, asked, exact: ts === asked, url: ts ? `${SNAPSHOT_BASE}${stamp(ts)}/${url}` : "",
    bytes: num(s.bytes, BODY_MAX), truncated: s.truncated === true, title: line(s.title, 200), text_lines: num(s.text_lines, LINES_MAX), links: num(s.links, LINKS_MAX),
    ...(reason ? { reason, note: ARCHIVE_SIDE_NOTES[reason] } : {}),
  };
}
const IP_HOST = /^[\d.]+$|:/;
function diffList(v, url) {
  const d = isObj(v) ? v : {}, seen = new Set(), home = hostOf(url);
  const text = list(d.text, 120).map((t) => (typeof t === "string" ? line(t, 300) : "")).filter(Boolean);
  const links = list(d.links, 60).map((l) => {
    const u = isObj(l) ? safeLink(l.url) : "", x = u ? parseUrl(u) : null;
    if (!x || x.port || IP_HOST.test(x.hostname) || seen.has(u)) return null;
    seen.add(u);
    // A link on the profile's own host is never external, whatever the answer says.
    return { url: u, external: l.external === true && hostOf(u) !== home };
  }).filter(Boolean);
  return { text, text_total: Math.max(num(d.text_total, LINES_MAX), text.length), links, links_total: Math.max(num(d.links_total, LINKS_MAX), links.length) };
}
const NO_DIFF = () => ({ text: [], text_total: 0, links: [], links_total: 0 });
// url: the profile address the captures are of. An address that may not be looked up has no answer.
export function readArchiveDiff(raw, url) {
  if (!isObj(raw) || !ARCHIVE_DIFF_STATES.includes(raw.state) || !archivable(url)) return null;
  const base = { url, state: raw.state, from: null, to: null, removed: NO_DIFF(), added: NO_DIFF(), complete: false, swapped: raw.swapped === true, cached: raw.cached === true, asked_at: askedAt(raw) };
  if (raw.state === "refused") { const reason = Object.hasOwn(ARCHIVE_DIFF_REFUSALS, raw.reason) ? raw.reason : ""; return { ...base, swapped: false, reason, note: reason ? ARCHIVE_DIFF_REFUSALS[reason] : "This address was not looked up." }; }
  const from = diffSide(raw.from, url), to = diffSide(raw.to, url);
  if (raw.state === "failed" || raw.state === "rate_limited") return { ...base, from, to, ...errorOf(raw), ...retryAfter(raw) };
  const unread = { ...base, from, to, state: "failed", error: "The archive's answer could not be read.", error_code: "bad_response", error_detail: "" };
  if (raw.state === "none") {
    const missing = [["from", from], ["to", to]].filter(([, s]) => s?.state === "none").map(([k]) => k);
    return missing.length ? { ...base, from, to, missing } : unread;
  }
  // "ok" and "same" need two captures that were read, the older one first.
  if (from?.state !== "ok" || to?.state !== "ok" || !from.timestamp || !to.timestamp || from.timestamp > to.timestamp) return unread;
  const same_capture = from.timestamp === to.timestamp;
  const removed = diffList(raw.removed, url), added = diffList(raw.added, url);
  const nothing = !removed.text_total && !removed.links_total && !added.text_total && !added.links_total;
  // "ok" with no difference behind it is "same"; one capture compared with itself compared nothing.
  if (raw.state === "same" || same_capture || nothing) return { ...base, state: "same", from, to, complete: !from.truncated && !to.truncated, ...(same_capture ? { same_capture: true } : {}) };
  const whole = [removed, added].every((x) => x.text_total === x.text.length && x.links_total === x.links.length);
  return { ...base, from, to, removed, added, complete: raw.complete === true && whole && !from.truncated && !to.truncated };
}
export const readArchiveDiffs = byRow((v) => readArchiveDiff(v, typeof v.url === "string" ? v.url.trim() : ""));
// The pairs the page may offer, from a checked profile archive answer: [{ from, to, label, default?, distant? }]
// with the older capture as `from`. Neighbouring captures, the newest pair first (the default), then
// the first capture against the last, marked distant. [] unless the archive answered "ok" with two
// or more snapshots: a lookup that was refused or failed offers no comparison.
export function archiveDiffPairs(a) {
  if (!isObj(a) || a.state !== "ok" || !archivable(a.url)) return [];
  const ts = [...new Set(list(a.snapshots, 8).map((s) => (isObj(s) && stamp(s.timestamp) ? when(s.timestamp) : "")).filter(Boolean))].sort();
  if (ts.length < 2) return [];
  const pair = (from, to, x = {}) => ({ from, to, label: capLabel(from, to).join(" to "), ...x });
  const out = ts.slice(1).map((to, i) => pair(ts[i], to)).reverse();
  out[0].default = true;
  const first = stamp(a.first) && when(a.first) < ts[0] ? when(a.first) : ts[0], last = stamp(a.last) && when(a.last) > ts.at(-1) ? when(a.last) : ts.at(-1);
  if (!out.some((p) => p.from === first && p.to === last)) out.push(pair(first, last, { distant: true }));
  return out;
}
// Two capture times as labels: the days, or day and time when both fall on one day.
const capLabel = (a, b) => (dayOf(a) !== dayOf(b) ? [dayOf(a), dayOf(b)] : [a, b].map((t) => (t ? `${dayOf(t)} ${t.slice(11, 16)} UTC` : "")));
const bareLink = (u) => Array.from(String(u).replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "")).slice(0, 120).join("");
// What the page shows:
//   { state, text, from: { label, url, link_kind: "evidence", note }, to: { ... },
//     removed: { text: [line], links: [{ label, url, link_kind, external }], more }, added: { ... }, caveats: [sentence], retry }
// A link is an unverified URL (dashed) when it passes the link rules, else text only (link_kind
// "none"): never a bare homepage, never with the case's handle or address in its query.
// subjects, secrets: the link rules' own, as profileDetail takes them.
export function archiveDiffView(d, { subjects = [], secrets = [] } = {}) {
  const a = readArchiveDiff(d, isObj(d) ? d.url : "");
  if (!a) return null;
  const labels = capLabel(a.from?.timestamp || "", a.to?.timestamp || "");
  const side = (s, i) => (s ? { label: labels[i] || "", url: s.url, link_kind: s.url ? "evidence" : "none", state: s.state, title: s.title,
    note: [s.state === "none" ? s.note : s.state !== "ok" ? "This capture could not be read." : "", s.state === "ok" && !s.exact ? `Asked for ${capLabel(s.asked, s.timestamp)[0]}: the archive answered with this capture, the nearest one, and it is the one that was read.` : "", s.truncated ? "The page is larger than 2 MB, so only its start was read." : ""].filter(Boolean).join(" ") } : null);
  const part = (d) => {
    const mt = d.text_total - d.text.length, ml = d.links_total - d.links.length;
    return { text: d.text, links: d.links.map((l) => ({ label: bareLink(l.url), ...foundLink({ url: l.url, subjects, secrets }), external: l.external })),
      more: mt > 0 || ml > 0 ? `And ${[mt > 0 ? `${plural(mt, "more line")}` : "", ml > 0 ? `${plural(ml, "more link")}` : ""].filter(Boolean).join(" and ")}: open the two captures to see them.` : "" };
  };
  const base = { state: a.state, from: side(a.from, 0), to: side(a.to, 1), removed: part(a.removed), added: part(a.added), caveats: [], retry: false };
  const days = labels.filter(Boolean).join(" and ");
  if (a.state === "ok") {
    const n = (d) => `${plural(d.text_total, "line")} and ${plural(d.links_total, "link")}`;
    return { ...base, text: `Between the captures of ${days}: ${n(a.removed)} removed, ${n(a.added)} added.${a.complete ? "" : " There may be more differences than shown."}`, caveats: [...ARCHIVE_DIFF_CAVEATS, ...(a.from.exact && a.to.exact ? [] : [ARCHIVE_INEXACT_NOTE])] };
  }
  if (a.state === "same") return { ...base, text: a.same_capture ? `${ARCHIVE_SAME_CAPTURE_NOTE} Nothing was compared.` : `The captures of ${days} show the same text and the same links. Pictures, layout and scripts are not compared.` };
  if (a.state === "none") return { ...base, text: `Nothing was compared. ${a.missing.map((k) => `The ${k === "from" ? "older" : "newer"} capture: ${a[k].note}`).join(" ")}` };
  if (a.state === "refused") return { ...base, text: `Not compared. ${a.note}` };
  return { ...base, retry: true, text: a.state === "rate_limited" ? `The Internet Archive is rate limiting requests, so what changed is unknown.${waitText(a.retry_after)}` : "The Internet Archive could not be asked, so what changed is unknown. A failed answer is kept for 10 minutes, so wait before trying again." };
}
// A removed link that leaves the profile's site is a place to look next: [{ kind: "url", value, from, bare? }].
// bare: the address is a site's front page with no path (a personal site, or a platform's
// homepage: the lead rules decide). Only an "ok" answer gives leads; at most 20.
export function archiveDiffLeads(d, { site = "" } = {}) {
  const a = readArchiveDiff(d, isObj(d) ? d.url : "");
  if (!a || a.state !== "ok") return [];
  const [d1, d2] = capLabel(a.from.timestamp, a.to.timestamp), name = line(site, 60);
  return a.removed.links.filter((l) => l.external).slice(0, 20).map((l) => ({ kind: "url", value: l.url, from: `removed from the archived ${name ? `${name} ` : ""}profile between ${d1} and ${d2}`, ...(isBareHome(l.url) ? { bare: true } : {}) }));
}
// Indented Markdown lines under the row.
export function archiveDiffMarkdown(v) {
  if (!v) return [];
  const caps = [v.from, v.to].filter((s) => s?.url).map((s) => `[${s.label}](${s.url})`).join(", ");
  const part = (name, d) => [...(d.text.length ? [`    - ${name} text: ${d.text.map((t) => `"${t}"`).join("; ")}`] : []), ...(d.links.length ? [`    - ${name} links: ${d.links.map((l) => (l.link_kind === "none" ? l.label : `[${l.label}](${l.url}) (unverified URL)`)).join(", ")}`] : []), ...(d.more ? [`    - ${d.more}`] : [])];
  return [`  - Archive diff: ${v.text}${caps ? ` Captures: ${caps}` : ""} _(${ARCHIVE_SOURCE}${v.state === "ok" || v.state === "same" ? " · archive record" : ""})_`, ...part("Removed", v.removed), ...part("Added", v.added), ...v.caveats.map((c) => `    - ${c}`)];
}
// The text of an answer as the minor guard's content check reads it, the same on the page as on
// the server: guard_texts in modules/archive_diff.py takes the title of the older capture, the
// title of the newer one when it differs, the removed lines and then the added ones, and joins
// them, one per line, into pieces of at most 2000 characters (a new piece starts when the next
// line would not fit). Every state that carries text counts: a title comes back with "same", and
// with "none" when one of the two captures was read. routers/recon_identity.py records one entry
// per piece under the site name "Internet Archive" with the address of the older capture (the
// newer one's when there is no older side). Characters are counted as Python counts them (code
// points), so both sides cut at the same line.
export function archiveDiffTexts(d) {
  const a = readArchiveDiff(d, isObj(d) ? d.url : "");
  if (!a) return [];
  const lines = [];
  for (const s of [a.from, a.to]) if (s?.title && !lines.includes(s.title)) lines.push(s.title);
  lines.push(...a.removed.text, ...a.added.text);
  const chunks = [];
  let cur = "", size = 0;
  for (const t of lines) {
    const n = Array.from(t).length;
    if (cur && size + 1 + n > 2000) { chunks.push(cur); cur = ""; size = 0; }
    size = cur ? size + 1 + n : n;
    cur = cur ? `${cur}\n${t}` : t;
  }
  if (cur) chunks.push(cur);
  return chunks.map((bio) => ({ source: ARCHIVE_SOURCE, url: (a.from || a.to)?.url || "", bio }));
}

// ---- case files and history ---------------------------------------------------------------------------
// The keys as a case may carry them. A value that is not a readable answer is dropped;
// a failure is kept as a failure, so the source stays "unknown" and never becomes "not found".
export const DEEP_READERS = { profiles: readProfileSources, emailAccounts: readEmailAccounts, githubActivity: readActivity, archives: readArchives, commitEmails: readCommitEmails, postActivity: readPostActivities, archiveDiffs: readArchiveDiffs };
export function readDeep(results) {
  if (!isObj(results)) return results;
  const out = { ...results };
  for (const [k, read] of Object.entries(DEEP_READERS)) if (k in out) { const v = read(out[k]); if (v) out[k] = v; else delete out[k]; }
  return out;
}
