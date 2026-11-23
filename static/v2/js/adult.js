// Adult and dating site coverage. An explicit opt-in for the page session: sextortion and romance-scam
// investigations, catfish checks, trust and safety work, and people checking their own exposure.
// Pure functions: no DOM, no network, no storage. Old saved cases and case files go through the
// same code.
//
// The rules this module holds, so they can be tested in one place:
//   - Off on every page load and never stored. The switch is a session mode (modes.js): held in
//     memory only, it stays on across handles, new cases, Clear and cases opened from History
//     until it is switched off or the page is reloaded. Whether it applies is decided per case.
//   - A case shows adult rows only when it recorded that the mode was on (collected.adultMode ===
//     true), it is a username case, and the minor guard did not stop it. There is no override.
//   - The minor guard has two stages. Before a run: the handle itself (an explicit age under 18,
//     or one of three words). After the ordinary sources and before any adult request: the names
//     and bios of the profiles they found (contentCheck in evidence.js). The rules are in
//     data/minor-rules.json, applied by minorscan.js here and by the server, which repeats both
//     stages on every adult request and wins if the two ever disagree.
//   - The adult pass is its own set of requests (adultRequests), made only with a clean check in
//     hand. Sherlock's and Maigret's adult rows are stored apart (sherlockAdult, maigretAdult).
//     A case saved before that holds them inside sherlock and maigret, and still renders.
//   - A case that was stopped records why (collected.adultBlock) and shows no adult row at all.
//   - Rows from adult and dating sites never enter the ordinary flow: withoutAdult() removes them
//     before the ledger, identity clustering, facts, leads, the avatar comparison, profile
//     enrichment, Deep Dive and the AI payload see anything.
//   - Existence and text only. A row carries a site name, a state, a link kind and, when a profile
//     was read, a display name, a join date, a follower count and a plain-text bio. Image fields
//     are never read, and cleanAdult() drops them from what is stored.
import { esc, link } from "./core.js";
import { classifyLink, mdLink, mdNote, parseUrl, regHost, NO_PAGE_HINT } from "./links.js";
import { looksBoilerplate } from "./identity.js";
import { ADULT_SITE_HOSTS, ADULT_SITE_NAMES } from "./adult-sites.js";
import { handleToken, rulesReady, sourceRoles } from "./minorscan.js";

export const ADULT_SWITCH = "Adult sites";
export const ADULT_NOTICE = "Adult and dating sites are existence checks only. A match shows a handle is taken there, not who owns it.";
export const ADULT_GROUP = "Adult and dating sites";
export const ADULT_SECTION = "Adult and dating sites (existence checks only)";
export const ADULT_SOURCE = "Adult site check";
// One sentence for the Sources panel, the consent gate and the acceptable-use statement.
export const ADULT_COPY = "Adult and dating sites are checked only when you switch that on: existence checks only, not for a handle that states an age under 18, not when a profile found for the handle suggests a minor, and only for lawful purposes.";
// What the consent gate and the acceptable-use statement add about how long the switch lasts.
export const ADULT_LASTS = "The switch is off when the page loads, and stays on until you switch it off or reload.";
const lc = (s) => String(s ?? "").trim().toLowerCase();
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const failed = (d) => !!(d && (d.error || d.error_code));
const fmtNum = (n) => Number(n ?? 0).toLocaleString("en-US");
const plural = (n, one, many = one + "s") => `${fmtNum(n)} ${n === 1 ? one : many}`;
export const handleOf = (target) => String(target ?? "").trim().replace(/^@/, "");

// ---- the minor guard ---------------------------------------------------------------------------
// Stage 1, the handle. The rules are in data/minor-rules.json and are applied by minorscan.js;
// the server applies the same file to every request and wins if the two ever disagree (HTTP 400
// with code "minor_guard"). Only an explicit age under 18 or one of three words blocks. A bare
// number in a handle never does. Without the rules file everything is refused.
// The reasons are the server's fixed sentences. None repeats the handle or mentions a number in it.
export const GUARD_REASONS = {
  age: "The handle states an age under 18.",
  word: "The handle contains a word that marks it as a minor's.",
  rules: "The minor rules could not be loaded.",
};
export const CONTENT_REASONS = {
  age: "A profile found for this handle states an age under 18.",
  school: "A profile found for this handle suggests a school-age person.",
  birth: "A profile found for this handle states a birth date under 18.",
  soft: "A profile found for this handle suggests a minor, and the handle carries a matching age or birth year.",
};
export const RULES_UNAVAILABLE = "Adult sites cannot be switched on: the rules that keep them away from minors could not be loaded. Reload the page.";
// { blocked, kind, reason }: kind is "age", "word" or "rules".
export function minorGuard(target) {
  const kind = handleToken(handleOf(target));
  return kind ? { blocked: true, kind, reason: GUARD_REASONS[kind] } : { blocked: false, kind: "", reason: "" };
}
// A fixed sentence set inside another one. Anything that is not one of the sentences above (an
// older server's wording, a case saved before this rule set) becomes one neutral clause.
const KNOWN_REASONS = new Set([...Object.values(GUARD_REASONS), ...Object.values(CONTENT_REASONS)]);
const asClause = (r) => { const t = String(r ?? "").trim(); return KNOWN_REASONS.has(t) ? t[0].toLowerCase() + t.slice(1, -1) : "the server refused this handle"; };
// What the switch says for a handle that fails stage 1, before anything has run.
export const guardText = (reason) => `Adult and dating sites are not checked for this handle: ${asClause(reason)}.`;

// ---- a case the guard stopped --------------------------------------------------------------------
// collected.adultBlock records why the adult group is absent: { kind, source, snippet, url }.
//   age, school, birth   a profile's text (source is the site, snippet the quoted text)
//   soft                 a weaker sign in a profile together with a birth year in the handle
//   handle, word         the handle itself          rules    the rules could not be loaded
//   server               the server refused         pivot    opened from a case that was stopped
//   unread               no source that reads profiles answered, so there was nothing to check
//   fresh                the server had no record of this run any more: a fresh run is needed
// The last two are not about a minor: the adult pass simply did not run, and a new run decides again.
// It can only ever hide the adult group. Text in it is remote: every use goes through esc or h.
export const BLOCK_KINDS = ["age", "school", "birth", "soft", "handle", "word", "rules", "server", "pivot", "unread", "fresh"];
// The kinds that say nothing about the person: the pass did not run, and why.
export const NOT_RUN_KINDS = ["unread", "fresh"];
const CONTENT_KINDS = ["age", "school", "birth", "soft"];
export const SNIPPET_MAX = 60, BLOCK_SOURCE_MAX = 80;
const oneLine = (v, n) => Array.from(typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f\s]+/g, " ").trim() : "").slice(0, n).join("");
// The stored record, checked and bounded, or null. Used for every read: a live run, History, a case file.
export function readBlock(v) {
  if (!isObj(v) || !BLOCK_KINDS.includes(v.kind)) return null;
  const out = { kind: v.kind, source: "", snippet: "", url: "" };
  if (CONTENT_KINDS.includes(v.kind)) {
    out.source = oneLine(v.source, BLOCK_SOURCE_MAX).replace(/[<>]/g, "") || "a profile";
    out.snippet = oneLine(v.snippet, SNIPPET_MAX);
    const x = typeof v.url === "string" && v.url.length <= 600 ? parseUrl(v.url) : null;
    if (x && /^https?:$/.test(x.protocol) && !x.username && !x.password && !adultHost(v.url)) out.url = v.url.trim();
  }
  if (v.kind === "pivot") { out.source = oneLine(v.source, 64).replace(/[<>]/g, ""); out.via = v.via === "content" ? "content" : "handle"; }
  // unread: were the profile readers switched off, or did they fail?
  if (v.kind === "unread") out.via = v.via === "off" ? "off" : "failed";
  return out;
}
// A case with a block on record. Any value under the key counts, so a damaged record still hides.
export const isBlocked = (collected) => isObj(collected) && collected.adultBlock !== undefined && collected.adultBlock !== null;
const PIVOT_VIA = { content: "where a profile suggested a minor", handle: "whose handle states an age under 18" };
// The reason as a clause, with no leading capital and no full stop.
export function blockClause(block) {
  const b = readBlock(block);
  if (!b) return "the minor guard stopped this case";
  if (CONTENT_KINDS.includes(b.kind)) return `${asClause(CONTENT_REASONS[b.kind])} (${b.source}: "${b.snippet}")`;
  if (b.kind === "handle") return asClause(GUARD_REASONS.age);
  if (b.kind === "word") return asClause(GUARD_REASONS.word);
  if (b.kind === "rules") return asClause(GUARD_REASONS.rules);
  if (b.kind === "pivot") return `this case was opened from ${b.source || "another case"}, ${PIVOT_VIA[b.via]}`;
  if (b.kind === "unread") return "no source that reads profiles answered for this handle, so there was nothing to check";
  if (b.kind === "fresh") return "a fresh run is needed";
  return "the server refused this handle";
}
export const BLOCK_LEAD = "Adult and dating sites were not checked";
// The server answered 409 to the adult pass though the ordinary sources ran here: its record
// lapsed, the session cookie was lost, or the server restarted. The same words in the notice,
// the mode strip and the run log row.
export const MAINSTREAM_FIRST_TEXT = "Adult sites need a fresh run. Re-run the case to enable them.";
const UNREAD_NEXT = { off: "Switch on Maigret or Platform check and run again.", failed: "Run the case again." };
export function blockText(block) {
  const b = readBlock(block);
  if (b?.kind === "fresh") return MAINSTREAM_FIRST_TEXT;
  if (b?.kind === "unread") return `${BLOCK_LEAD}: ${blockClause(b)}. ${UNREAD_NEXT[b.via]}`;
  return `${BLOCK_LEAD}: ${blockClause(block)}.`;
}
// The same sentence as markup, with the source as a link to the profile it was read on.
export function blockHtml(block, handle = "") {
  const b = readBlock(block);
  if (!b || !CONTENT_KINDS.includes(b.kind) || !b.url) return esc(blockText(block));
  const lk = classifyLink({ url: b.url, want: "verified_profile", site: b.source, subjects: [handle] });
  return `${esc(BLOCK_LEAD)}: ${esc(asClause(CONTENT_REASONS[b.kind]))} (${lk.url ? link(lk.url, b.source, "", { kind: lk.link_kind }) : esc(b.source)}: "${esc(b.snippet)}").`;
}
// From the result of a content check (minorscan.js) or from the server's refusal.
export const blockFromScan = (scan) => (scan && scan.blocked ? readBlock(scan.signal ? { kind: scan.kind, source: scan.signal.source, snippet: scan.signal.snippet, url: scan.signal.url } : { kind: "rules" }) : null);
export const blockFromRefusal = (err) => readBlock(CONTENT_KINDS.includes(err?.block?.kind) ? err.block : { kind: err?.reason === GUARD_REASONS.age ? "handle" : err?.reason === GUARD_REASONS.word ? "word" : err?.reason === GUARD_REASONS.rules ? "rules" : "server" });
// What the model is told: that the group was skipped and where the sign was. Never the snippet.
export function blockForAi(collected) {
  const b = isBlocked(collected) ? readBlock(collected.adultBlock) : null;
  if (!b) return null;
  return { kind: b.kind, source: CONTENT_KINDS.includes(b.kind) ? b.source.replace(/[^A-Za-z0-9 ._()\/-]/g, "").slice(0, 60) : "" };
}

// ---- the run: what is asked, and when ---------------------------------------------------------------
// The words of the run log's one "Adult sites" row.
// The server's verdict for a handle, with no site contacted: asked only to have a block the
// page made counted on the server (routers/recon.py, /minor-guard).
export const GUARD_VERDICT = { url: "/api/recon/minor-guard", body: (handle) => ({ username: handleOf(handle) }) };
export const ADULT_LOG = {
  waiting: "Adult sites: waiting on profile check",
  // silent: sources whose failure is worth saying though the check could go ahead (GitHub).
  clean: (n, silent = []) => { const also = silent.length ? `; ${silent.join(", ")} did not answer` : ""; return n > 0 ? `Adult sites: profile check clean (${plural(n, "profile")} read${also}), checking` : `Adult sites: profile check: no profile text was found for this handle${also}, checking`; },
  blocked: (block) => (readBlock(block)?.kind === "fresh" ? MAINSTREAM_FIRST_TEXT : `Adult sites: not checked · ${blockClause(block)}`),
  cancelled: "Adult sites: not run (cancelled)",
};
export const CANCELLED_TEXT = `${BLOCK_LEAD}: the run was cancelled before the profile check.`;
// Could the profile check read anything? The adult pass needs at least one source that reads
// profiles (Maigret or the platform check: `sources.profile_readers` in the rules file, the same
// list the server uses) to have answered without an error. Sherlock, GitHub or enrichment alone
// is not enough: unknown is not clean. A site that blocked the platform check is not a failure
// of that source. switched: { maigret, platformCheck } as the Sources panel has them.
//   { ok, via: "" | "failed" | "off", silent: [names of sources that failed and are worth saying] }
export function readiness(collected, switched = {}) {
  const roles = sourceRoles(), c = isObj(collected) ? collected : {};
  const ok = roles.profileReaders.some(([, key]) => isObj(c[key]) && !failed(c[key]));
  const anyOn = roles.profileReaders.some(([, key]) => switched[key] !== false);
  return { ok, via: ok ? "" : anyOn ? "failed" : "off", silent: roles.reportedWhenFailed.filter(([, key]) => isObj(c[key]) && failed(c[key])).map(([, , name]) => name) };
}
// The requests of the adult pass. There are none without the result of a content check that
// came back clean, so nothing can ask an adult site before the profiles have been read.
// sources: which of Sherlock and Maigret are switched on.
export function adultRequests(handle, scan, { sherlock = true, maigret = true } = {}) {
  if (!scan || typeof scan !== "object" || scan.blocked !== false || !rulesReady() || minorGuard(handle).blocked) return [];
  const body = usernameBody(handle, true);
  return [
    ...(sherlock ? [{ key: "sherlockAdult", label: "Sherlock · adult and dating sites", url: "/api/recon/sherlock", body }] : []),
    ...(maigret ? [{ key: "maigretAdult", label: "Maigret · adult and dating sites", url: "/api/recon/maigret", body }] : []),
    { key: "adultCheck", label: ADULT_SOURCE, url: "/api/recon/adult-check", body: { username: handle } },
  ];
}
// Guard-only text (the whole bio, other text fields, a birth date, an age) rides on a profile
// row under `guard`. The content check reads it and nothing else may: this removes it, and
// withoutAdult and scrubCollected call it, so it is never stored, exported or sent to the AI.
export function stripGuard(collected) {
  if (!isObj(collected)) return collected;
  const out = { ...collected };
  const bare = (r) => { if (!isObj(r)) return r; const { guard, ...rest } = r; return isObj(rest.profile) && "guard" in rest.profile ? { ...rest, profile: bare(rest.profile) } : rest; };
  for (const [k, list] of [["maigret", "results"], ["platformCheck", "results"], ["enricher", "profiles"]]) if (isObj(out[k]) && Array.isArray(out[k][list])) out[k] = { ...out[k], [list]: out[k][list].map(bare) };
  return out;
}

// ---- when the mode applies -------------------------------------------------------------------
// May this run plan an adult pass? The switch must be on, the target a username, and the handle
// must pass stage 1. Whether the pass then runs is decided after the ordinary sources (stage 2).
export const adultOn = (type, target, want) => want === true && type === "username" && !minorGuard(target).blocked;
// May this case show adult rows? Only a case that recorded the mode and no block, for a username
// whose handle passes stage 1.
export const adultAllowed = (collected, target, type = "username") => isObj(collected) && collected.adultMode === true && !isBlocked(collected) && type === "username" && !minorGuard(target).blocked;
// The body of a Sherlock or Maigret request. nsfw is always sent. The ordinary run sends false.
// The adult pass sends true together with adult_only: the two are never one request.
export const usernameBody = (handle, adult) => ({ username: handle, nsfw: adult === true, ...(adult === true ? { adult_only: true } : {}) });

// ---- which sites are adult or dating sites ------------------------------------------------------
// The platforms the adult site check knows, with the address of a profile there. This is the
// only place an adult site check row's link comes from: the address stored in a case is never
// used, so a case file cannot point one of these rows at a picture or at another site.
// "" means the platform has no public page for a handle. Mirrors RULES in modules/adult_check.py
// (tests/js/adult.test.mjs fails if the two drift).
export const ADULT_PLATFORMS = {
  "OnlyFans": "https://onlyfans.com/{username}", "Fansly": "https://fansly.com/{username}", "Pornhub": "https://www.pornhub.com/users/{username}",
  "xHamster": "https://xhamster.com/users/{username}", "Chaturbate": "https://chaturbate.com/{username}/", "Stripchat": "https://stripchat.com/{username}",
  "ManyVids": "", "Clips4Sale": "", "FetLife": "https://fetlife.com/{username}", "JustFor.Fans": "https://justfor.fans/{username}",
  "LoyalFans": "https://www.loyalfans.com/{username}", "Tinder": "https://tinder.com/@{username}", "Bumble": "", "Hinge": "", "OkCupid": "", "Plenty of Fish": "", "Grindr": "",
};
const HANDLE_OK = /^[A-Za-z0-9._-]{1,64}$/;
const alnum = (v) => lc(v).replace(/\s*\(.*\)$/, "").replace(/[^a-z0-9]/g, "");
const PLATFORM_KEY = Object.fromEntries(Object.keys(ADULT_PLATFORMS).map((n) => [alnum(n), n]));
export const platformUrl = (platform, handle) => { const t = ADULT_PLATFORMS[PLATFORM_KEY[alnum(platform)]]; return t && HANDLE_OK.test(handle) && !String(handle).startsWith("-") ? t.replace("{username}", handle) : ""; };

// Hosts that are adult or dating sites whatever a row or a tool says about them. The same list
// as the server's denylist, so an unmarked row in an old saved case or a leaked answer is still
// treated as adult, and a link to one of them found on a profile is never an ordinary lead.
export const ADULT_HOSTS = ADULT_SITE_HOSTS;
const HOST_SET = new Set(ADULT_HOSTS);
// A site is matched by its name in a tool's data, as the server does, or by a platform's name.
const NAME_SET = new Set([...ADULT_SITE_NAMES.map(lc), ...Object.keys(ADULT_PLATFORMS).map(lc)]);
// The listed host a link or an address belongs to ("" when it is not one of them). Subdomains count.
export function adultHost(u) {
  const t = String(u ?? "").trim();
  const x = parseUrl(/^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `https://${t}`);
  if (!x) return "";
  const labels = x.hostname.toLowerCase().replace(/\.$/, "").split(".");
  if (labels[0] === "www") labels.shift();
  for (let i = 0; i < labels.length - 1; i++) { const h = labels.slice(i).join("."); if (HOST_SET.has(h)) return h; }
  return "";
}
const namedAdult = (name) => NAME_SET.has(lc(name)) || NAME_SET.has(lc(name).replace(/\s*\(.*\)$/, ""));

// ---- telling adult rows apart ----------------------------------------------------------------
// New responses mark the row (adult: true). Rows saved before that carry Maigret's own tags, and
// a row for a listed site is adult whether or not anything marked it.
const ADULT_TAG = /\b(adult|dating|porn|erotic|webcam|nsfw)\b/i;
export const isAdultRow = (r) => isObj(r) && (r.adult === true || namedAdult(r.site || r.name || r.platform) || !!adultHost(r.url) || ADULT_TAG.test(typeof r.category === "string" ? r.category : "") || (Array.isArray(r.tags) && r.tags.some((t) => ADULT_TAG.test(String(t)))));
const categoryOf = (r) => (/dating/i.test(String(r?.category ?? "")) ? "dating" : "adult");
const siteKey = (s) => lc(s).replace(/\s*\(.*\)$/, "");
const rowsOf = (d) => (isObj(d) && Array.isArray(d.results) ? d.results : []);
// Where the adult pass of Sherlock and of Maigret is stored. Every row under these keys is an adult row.
export const ADULT_PASS_KEYS = ["sherlockAdult", "maigretAdult"];
function adultSiteNames(c) {
  const out = new Set();
  for (const k of ["sherlock", "maigret"]) for (const r of rowsOf(c[k])) if (isAdultRow(r)) out.add(siteKey(r.site || r.name));
  for (const k of ADULT_PASS_KEYS) for (const r of rowsOf(c[k])) if (isObj(r)) out.add(siteKey(r.site || r.name));
  for (const r of rowsOf(c.adultCheck)) if (isObj(r)) out.add(siteKey(r.platform));
  for (const d of [c.maigret, c.maigretAdult]) for (const n of Array.isArray(d?.adult_errors) ? d.adult_errors : []) out.add(siteKey(n));
  out.delete("");
  return out;
}

// ---- links to adult sites found on ordinary profiles -----------------------------------------------
// A GitHub website field, a README, a bio or a profile's link list can point at one of these
// sites. Such a link is never a lead, a fact or part of what the AI is sent. With the mode on it
// is listed in the adult group as "linked from <where>", as text.
const URLISH = /(?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"')\]]*)?/gi;
const stripAdultLinks = (text, seen) => (typeof text === "string" ? text.replace(URLISH, (m) => { const h = adultHost(m); if (h && seen) seen(h); return h ? "" : m; }).replace(/[ \t]{2,}/g, " ").trim() : text);
// Returns the case with those links removed, and calls found(host, where) for each one.
function scrubLinks(c, out, found = () => {}) {
  const set = (k, v) => { out[k] = v; };
  const keep = (where) => (u) => { const h = adultHost(typeof u === "string" ? u : u?.url); if (h) found(h, where); return !h; };
  const text = (v, where) => stripAdultLinks(v, (h) => found(h, where));
  const gh = out.github;
  if (isObj(gh)) set("github", { ...gh, ...(typeof gh.blog === "string" ? { blog: adultHost(gh.blog) ? (found(adultHost(gh.blog), "the GitHub website field"), "") : gh.blog } : {}), ...(typeof gh.bio === "string" ? { bio: text(gh.bio, "the GitHub bio") } : {}) });
  const dp = out.githubDeep;
  if (isObj(dp)) set("githubDeep", { ...dp, ...(Array.isArray(dp.social_accounts) ? { social_accounts: dp.social_accounts.filter(keep("GitHub social accounts")) } : {}), ...(Array.isArray(dp.readme_links) ? { readme_links: dp.readme_links.filter(keep("the GitHub profile README")) } : {}) });
  const gr = out.gravatar;
  if (isObj(gr)) set("gravatar", { ...gr, ...(Array.isArray(gr.links) ? { links: gr.links.filter(keep("the Gravatar profile")) } : {}), ...(Array.isArray(gr.urls) ? { urls: gr.urls.filter(keep("the Gravatar profile")) } : {}), ...(typeof gr.about === "string" ? { about: text(gr.about, "the Gravatar profile") } : {}), ...(typeof gr.bio === "string" ? { bio: text(gr.bio, "the Gravatar profile") } : {}) });
  const each = (k, list, name, fields) => {
    if (!isObj(out[k]) || !Array.isArray(out[k][list])) return;
    set(k, { ...out[k], [list]: out[k][list].map((r) => {
      if (!isObj(r)) return r;
      const where = `the ${String(name(r) || "profile").slice(0, 60)} profile`;
      const fix = (o) => { const n = { ...o }; for (const f of fields.text) if (typeof n[f] === "string") n[f] = text(n[f], where); for (const f of fields.lists) if (Array.isArray(n[f])) n[f] = n[f].filter(keep(where)); return n; };
      return isObj(r.profile) ? { ...fix(r), profile: fix(r.profile) } : fix(r);
    }) });
  };
  each("maigret", "results", (r) => r.site || r.name, { text: ["bio"], lists: ["links"] });
  each("enricher", "profiles", (r) => r.platform, { text: ["bio"], lists: ["links"] });
  each("profileScrape", "results", (r) => r.site, { text: ["bio"], lists: ["links"] });
  return out;
}
export function adultMentions(collected) {
  const seen = new Map();
  if (isObj(collected)) scrubLinks(collected, withoutRows(collected), (host, where) => { if (!seen.has(host)) seen.set(host, []); if (!seen.get(host).includes(where)) seen.get(host).push(where); });
  return [...seen].map(([host, from]) => ({ host, from }));
}
const MAIGRET_ADULT_KEYS = ["nsfw", "adult_checked", "adult_errors", "adult_error", "adult_error_code"];

// The case as every ordinary consumer sees it: no adult row, no adult check, no flag, and no link
// to an adult site. A site that any source marked as adult is also dropped from the follow-up
// sources, so it can never be read into a profile by another route. The tools' own counts are
// recomputed, so nothing downstream reads "2 results" beside an empty list.
function withoutRows(collected) {
  const c = stripGuard(collected), out = { ...c };
  delete out.adultCheck; delete out.adultMode; delete out.adultBlock;
  for (const k of ADULT_PASS_KEYS) delete out[k];
  const names = adultSiteNames(c);
  for (const k of ["sherlock", "maigret"]) {
    if (!isObj(c[k])) continue;
    out[k] = { ...c[k] };
    if (Array.isArray(c[k].results)) {
      const rows = c[k].results.filter((r) => !isAdultRow(r));
      const dropped = rows.length !== c[k].results.length;
      out[k].results = rows;
      if (dropped || MAIGRET_ADULT_KEYS.some((x) => x in c[k])) {
        const real = rows.filter((r) => r?.confidence !== "false_positive");
        if ("total" in c[k]) out[k].total = rows.length;
        if ("possible" in c[k]) out[k].possible = real.length;
        if ("verified" in c[k] && typeof c[k].verified === "number") out[k].verified = real.filter((r) => r?.verified).length;
      }
    }
    for (const x of MAIGRET_ADULT_KEYS) delete out[k][x];
  }
  const drop = (k, list, field) => { if (isObj(c[k]) && Array.isArray(c[k][list])) out[k] = { ...c[k], [list]: c[k][list].filter((r) => !isObj(r) || !(names.has(siteKey(r[field])) || namedAdult(r[field]) || adultHost(r.url))) }; };
  drop("enricher", "profiles", "platform"); drop("platformCheck", "results", "platform"); drop("profileScrape", "results", "site");
  if (isObj(c.linkChecks)) out.linkChecks = Object.fromEntries(Object.entries(c.linkChecks).filter(([k]) => !/^adult:/.test(k)));
  return out;
}
export function withoutAdult(collected) {
  return isObj(collected) ? scrubLinks(collected, withoutRows(collected)) : {};
}
// What the source tally reads: the adult-free case, plus ONE "Adult site check" source when the
// case had the mode on. That source is the adult site check together with the adult pass of
// Sherlock and of Maigret, as its parts: a site a tool reported is a site that answered, a site
// Maigret could not ask and a pass that failed are parts that did not. Sherlock and Maigret
// themselves are never counted for adult rows, and the header never gains a second adult source.
export function adultSource(collected) {
  const c = collected, parts = [];
  if (isObj(c.adultCheck)) parts.push(c.adultCheck);
  for (const k of ADULT_PASS_KEYS) if (isObj(c[k])) parts.push(c[k]);
  if (!parts.length) return null;
  if (parts.every(failed)) return parts[0];
  const check = isObj(c.adultCheck) && !failed(c.adultCheck) ? c.adultCheck : null;
  const rows = check ? rowsOf(check).filter(isObj).map((r) => ({ platform: r.platform, state: r.state, found: r.found })) : [];
  let checked = check && Number.isInteger(check.checked) ? check.checked : rows.filter((r) => r.state !== "no_public_url").length;
  const part = (platform, state) => { rows.push({ platform, state, found: state === "found" ? true : null }); checked += 1; };
  if (isObj(c.adultCheck) && failed(c.adultCheck)) part(ADULT_SOURCE, "unknown");
  for (const [k, name] of [["sherlockAdult", "Sherlock"], ["maigretAdult", "Maigret"]]) {
    const d = c[k];
    if (!isObj(d)) continue;
    if (failed(d)) { part(`${name} adult pass`, "unknown"); continue; }
    for (const r of rowsOf(d)) if (isObj(r)) part(String(r.site || r.name || "").slice(0, 120), "found");
    for (const n of Array.isArray(d.adult_errors) ? d.adult_errors.slice(0, 200) : []) if (typeof n === "string") part(n.slice(0, 120), "unknown");
  }
  return { username: check?.username, checked, total: rows.filter((r) => r.state === "found").length, results: rows };
}
export function tallyView(collected, target, type) {
  const out = withoutAdult(collected);
  if (adultAllowed(collected, target, type)) { const src = adultSource(collected); if (src) out.adultCheck = src; }
  return out;
}

// ---- what is kept ------------------------------------------------------------------------------
// Text that may be shown: a string with no markup and no address in it. A bio that is a link, or
// that carries one, is not plain text and is dropped whole.
const NOT_TEXT = /<\s*[a-z!/]|<[^>]{1,200}>|https?:|\/\/|www\.|data:|\.(?:jpe?g|png|gif|webp|svg|avif|bmp|mp4|m4v|webm|mov|m3u8)\b/i;
const BARE_LINK = /\b[\w-]+\.(?:com|net|org|io|me|tv|co|ly|gg|xxx|fans)\b/i;
const flat = (v) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "");
// A name or a bio, as the server's plain_text rule has it.
export const plainText = (v, n = 200) => { const t = flat(v); return t && !NOT_TEXT.test(t) && !BARE_LINK.test(t) ? t.slice(0, n) : ""; };
// One of the server's own sentences (why a site was blocked, how to check by hand). It may name a site.
const plainNote = (v, n = 200) => { const t = flat(v); return t && !NOT_TEXT.test(t) ? t.slice(0, n) : ""; };
const dateText = (v) => (String(v ?? "").trim().match(/^\d{4}(?:-\d{2}(?:-\d{2})?)?/) || [""])[0];
const countOf = (v) => { const n = typeof v === "number" ? v : /^\d{1,12}$/.test(String(v ?? "").trim()) ? Number(v) : NaN; return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null; };
const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
const STATES = ["found", "not_found", "blocked", "unknown", "no_public_url"];

// One adult row of a Sherlock or Maigret answer, with only the fields CrawlR uses.
function cleanToolRow(r) {
  const out = { site: str(r.site || r.name, 120), url: safeToolUrl(r.site || r.name, str(r.url, 600)), confidence: str(r.confidence, 24), category: categoryOf(r), verified: r.verified === true, adult: true };
  if (isObj(r.profile)) {
    const p = { name: plainText(r.profile.name, 80), created_at: dateText(r.profile.created_at), followers: countOf(r.profile.followers), bio: r.profile.bio_boilerplate || looksBoilerplate(r.profile.bio) ? "" : plainText(r.profile.bio) };
    out.profile = Object.fromEntries(Object.entries(p).filter(([, v]) => v !== "" && v !== null));
  }
  return out;
}
function cleanCheckRow(r, handle = "") {
  const state = STATES.includes(r.state) ? r.state : "unknown";
  const read = state === "found";
  return {
    platform: str(r.platform, 120), category: categoryOf(r), url: platformUrl(r.platform, handle), state, found: read ? true : state === "not_found" ? false : null,
    evidence: plainNote(r.evidence, 200), display_name: read ? plainText(r.display_name, 80) : "", joined: read ? dateText(r.joined) : "", followers: read ? countOf(r.followers) : null,
    bio: read ? plainText(r.bio) : "", hint: plainNote(r.hint, 300),
  };
}
// One response as it is stored. Mode off: any adult row is dropped (the server should not have
// sent one). Mode on: adult rows keep the whitelisted text fields and nothing else.
export function scrubResponse(key, data, on) {
  if (!isObj(data)) return data;
  if (key === "adultCheck") {
    if (!on) return null;
    return failed(data) ? data : { ...Object.fromEntries(["username", "checked", "total", "cached"].filter((k) => k in data).map((k) => [k, data[k]])), results: rowsOf(data).filter(isObj).map((r) => cleanCheckRow(r, handleOf(data.username))) };
  }
  // The adult pass of a tool: every row is an adult row and keeps only the whitelisted text fields.
  if (ADULT_PASS_KEYS.includes(key)) {
    if (!on) return null;
    return failed(data) || !Array.isArray(data.results) ? data : { ...data, results: data.results.filter(isObj).map(cleanToolRow) };
  }
  if (key !== "sherlock" && key !== "maigret") return data;
  if (!on) return withoutAdult({ [key]: data })[key];
  return Array.isArray(data.results) ? { ...data, results: data.results.map((r) => (isAdultRow(r) ? cleanToolRow(r) : r)) } : data;
}
// A whole case as it is kept in memory and in History.
export function scrubCollected(collected, target, type) {
  if (!isObj(collected)) return {};
  if (!adultAllowed(collected, target, type)) {
    // No adult row is kept. Why the group is absent is: a block survives, checked and bounded.
    const out = withoutAdult(collected), block = type === "username" && isBlocked(collected) ? readBlock(collected.adultBlock) || { kind: "server", source: "", snippet: "", url: "" } : null;
    if (block) out.adultBlock = block;
    return out;
  }
  const out = stripGuard(collected);
  for (const k of ["sherlock", "maigret", "adultCheck", ...ADULT_PASS_KEYS]) if (isObj(out[k])) out[k] = scrubResponse(k, out[k], true);
  return out;
}

// ---- the group ---------------------------------------------------------------------------------
// One row per site, from Sherlock, Maigret and the adult site check together. Order: a profile
// was read, a tool reported it, blocked or unknown, no public page, not found.
const RANK = { not_checked: -1, read: 0, reported: 1, blocked: 2, unknown: 2, no_public_url: 3, not_found: 4, mentioned: 5 };
// The one row that stands in the group's place when the minor guard stopped the case.
export const isBlockRow = (r) => r?.adult?.state === "not_checked";
// The rows that are sites: everything but that one.
export const adultFound = (rows) => (rows || []).filter((r) => !isBlockRow(r));
export const NOT_CHECKED_BLURB = "These sites were not asked about this handle. The row below says why, with the profile text that triggered it when there is one, so it can be checked. There is no way to override it.";
// The same, when the pass simply did not run (nothing to read, or a fresh run is needed).
export const NOT_RUN_BLURB = "These sites were not asked about this handle. The row below says why and what to do.";
function blockRow(collected, target) {
  const b = readBlock(collected.adultBlock) || { kind: "server", source: "", snippet: "", url: "" };
  const clause = blockClause(b);
  const row = { tier: "adult", what: "Not checked", url: "", link_kind: "none", key: "adult:block", glyph: "–", meta: NOT_RUN_KINDS.includes(b.kind) ? blockText(b) : clause[0].toUpperCase() + clause.slice(1) + ".", sources: ["Profile check"], source: "Profile check", adult: { state: "not_checked", category: "adult", block: b }, no_check: true };
  if (b.url) { const lk = classifyLink({ url: b.url, want: "verified_profile", site: b.source, subjects: [handleOf(target)] }); if (lk.url) row.more = { url: lk.url, label: `Open the ${b.source} profile`, link_kind: lk.link_kind }; }
  return row;
}
export const ADULT_WORD = { read: "profile read", reported: "reported by a tool and nothing read", blocked: "Blocked by site", unknown: "could not be checked", no_public_url: "no public page", not_found: "not found", mentioned: "linked from a profile" };
const FROM_CHECK = { found: "read", not_found: "not_found", blocked: "blocked", unknown: "unknown", no_public_url: "no_public_url" };
// A neutral mark beside the site name: its initials. Never an image. The CSP would allow a
// remote favicon, but fetching one tells the adult site, or a favicon service, about the visit.
export const siteGlyph = (name) => (String(name ?? "").replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2) || "?").toUpperCase();

// A tool's address for an adult row is shown only when it is a page on that site: not a picture,
// a video or a CDN asset, and not an address on some other host. Otherwise the row is text.
const MEDIA_EXT = /\.(?:jpe?g|png|gif|webp|svg|avif|bmp|ico|tiff?|mp4|m4v|webm|mov|avi|mkv|m3u8|mp3|css|js|json)$/i;
const MEDIA_SEG = /^(?:avatars?|thumbs?|thumbnails?|banners?|covers?|media|images?|imgs?|photos?|pictures?|pics?|videos?|uploads?|static|assets?|cdn|content|files?|previews?|posters?)$/i;
const MEDIA_HOST = /^(?:cdn\d*|img\d*|images?|static\d*|media\d*|assets?|files?|thumbs?|pics?|video|vod|stream)[.-]/i;
export function safeToolUrl(site, url) {
  const x = parseUrl(url);
  if (!x || x.username || x.password) return "";
  let path = x.pathname; try { path = decodeURIComponent(path); } catch { /* keep the raw path */ }
  if (MEDIA_EXT.test(path.replace(/\/+$/, "")) || path.split("/").some((seg) => MEDIA_SEG.test(seg)) || MEDIA_HOST.test(x.hostname) || MEDIA_EXT.test(x.search)) return "";
  // The host must be the site's own: its name and its registrable domain must agree.
  const reg = regHost(x.href), label = alnum(reg.split(".").slice(0, -1).join(".")), full = alnum(reg), name = alnum(site);
  const own = name.length > 2 && label.length > 2 && (name.includes(label) || label.includes(name) || name === full);
  return own ? String(url).trim() : "";
}
export function adultRows(collected, target, type = "username") {
  if (type === "username" && isBlocked(collected)) return [blockRow(collected, target)];
  collected = stripGuard(collected);
  if (!adultAllowed(collected, target, type)) return [];
  const c = collected, handle = handleOf(target);
  const sites = new Map();
  const say = (name, source, state, d = {}) => {
    const k = siteKey(name);
    if (!k) return;
    let s = sites.get(k);
    if (!s) { s = { name: String(name).slice(0, 120), category: "", said: [], text: {}, url: "", readUrl: "", hint: "", noisy: false, from: [] }; sites.set(k, s); }
    s.said.push({ source, state, evidence: plainNote(d.evidence, 200) });
    if (d.category && (!s.category || d.category === "dating")) s.category = d.category;
    if (d.url && !s.url) s.url = String(d.url);
    if (state === "read" && d.url && !s.readUrl) s.readUrl = String(d.url);
    if (d.hint && !s.hint) s.hint = d.hint;
    if (d.noisy) s.noisy = true;
    if (state === "read") for (const [f, v] of Object.entries(d.text || {})) if (v !== "" && v !== null && v !== undefined && !(f in s.text)) s.text[f] = v;
  };
  // The adult pass of each tool, and (a case saved before the pass was its own request) the
  // adult rows inside the tool's ordinary answer.
  for (const [source, d, all] of [["Sherlock", c.sherlock, false], ["Maigret", c.maigret, false], ["Sherlock", c.sherlockAdult, true], ["Maigret", c.maigretAdult, true]]) {
    if (!isObj(d) || failed(d)) continue;
    for (const r of rowsOf(d)) {
      if (!isObj(r) || !(all || isAdultRow(r))) continue;
      const row = cleanToolRow(r), p = row.profile || {};
      say(row.site, source, row.verified ? "read" : "reported", { url: safeToolUrl(row.site, row.url), category: row.category, noisy: row.confidence === "false_positive", text: { name: p.name, joined: p.created_at, followers: p.followers, bio: p.bio } });
    }
  }
  // Sites Maigret's adult pass could not ask: unknown, never "not found".
  for (const mg of [c.maigret, c.maigretAdult]) if (isObj(mg) && !failed(mg)) for (const n of Array.isArray(mg.adult_errors) ? mg.adult_errors.slice(0, 200) : []) if (typeof n === "string" && !sites.get(siteKey(n))?.said.some((x) => x.source === "Maigret")) say(n, "Maigret", "unknown");
  // An older platform check listed OnlyFans as "check by hand". Nothing was asked, so it is unknown.
  if (isObj(c.platformCheck) && !failed(c.platformCheck)) for (const r of rowsOf(c.platformCheck)) if (isObj(r) && namedAdult(r.platform) && (r.manual === true || r.state === "manual")) say(str(r.platform, 120), "Platform check", "unknown", { url: platformUrl(r.platform, handle), category: "adult" });
  if (isObj(c.adultCheck) && !failed(c.adultCheck)) for (const raw0 of rowsOf(c.adultCheck)) {
    if (!isObj(raw0)) continue;
    const r = cleanCheckRow(raw0, handle);
    // The address is CrawlR's own template for that platform and this handle, never the stored one.
    const own = platformUrl(r.platform, handle);
    say(r.platform, ADULT_SOURCE, FROM_CHECK[r.state], { category: r.category, evidence: r.evidence, hint: r.hint, text: { name: r.display_name, joined: r.joined, followers: r.followers, bio: r.bio } });
    const s1 = sites.get(siteKey(r.platform));
    if (s1) { s1.url = own; s1.readUrl = own; }
  }

  const rows = [];
  for (const [k, s] of sites) {
    const best = s.said.reduce((a, b) => (RANK[b.state] < RANK[a.state] ? b : a));
    const state = best.state;
    const sources = [...new Set(s.said.map((x) => x.source))];
    const how = ADULT_WORD[state] + ((state === "blocked" || state === "unknown") && best.evidence ? ` (${best.evidence.replace(/\.$/, "")})` : "");
    // What the other sources said, when it differs: a tool's report beside a check that found no page.
    const others = state === "reported" ? [...new Set(s.said.filter((x) => x.state !== state).map((x) => `${x.source}: ${ADULT_WORD[x.state]}`))] : [];
    const t = s.text;
    const text = state === "read" ? [t.name ? `name on profile: ${t.name}` : "", t.joined ? `joined ${t.joined}` : "", t.followers !== undefined && t.followers !== null && t.followers !== "" ? plural(t.followers, "follower") : "", t.bio ? `bio: ${t.bio}` : ""] : [];
    const lk = state === "read" && !(s.readUrl || s.url) ? { url: "", link_kind: "none" }
      : state === "read" ? classifyLink({ url: s.readUrl || s.url, want: "verified_profile", site: s.name, subjects: [handle] })
      : state === "no_public_url" ? { url: "", link_kind: "none", hint: s.hint || NO_PAGE_HINT }
        : state === "not_found" ? { url: "", link_kind: "none" }
          : !s.url ? { url: "", link_kind: "none" }
            : classifyLink({ url: s.url, want: "templated_unverified", site: s.name, subjects: [handle] });
    const row = {
      tier: "adult", what: s.name, url: lk.url, link_kind: lk.link_kind, key: `adult:${k}`.slice(0, 80), glyph: siteGlyph(s.name),
      meta: [s.category === "dating" ? "dating site" : "adult site", how, ...others, s.noisy && state === "reported" ? "this site often answers yes to any name" : "", ...text].filter(Boolean).join(" · "),
      sources, source: sources.join(", "), adult: { state, category: s.category || "adult" },
    };
    if (lk.hint) row.hint = lk.hint;
    else if (state === "blocked" && s.hint) row.hint = s.hint;
    // No adult row ever goes to the link check. That check can call a page missing on a status
    // code alone; in this group found and not found come only from the adult site check's own
    // reading of the page. A stored link check result for one of these rows is ignored.
    row.no_check = true;
    rows.push(row);
  }
  // Links to adult sites found on ordinary profiles: listed here, as text, and nowhere else.
  for (const m of adultMentions(c)) {
    if (rows.some((r) => adultHost(r.url) === m.host || alnum(r.what) === alnum(m.host.split(".").slice(0, -1).join(".")) || alnum(r.what) === alnum(m.host))) { const r = rows.find((x) => adultHost(x.url) === m.host || alnum(x.what) === alnum(m.host.split(".").slice(0, -1).join(".")) || alnum(x.what) === alnum(m.host)); r.meta += ` · linked from ${m.from.join(", ")}`; continue; }
    rows.push({ tier: "adult", what: m.host, url: "", link_kind: "none", key: `adult:link:${m.host}`.slice(0, 80), glyph: siteGlyph(m.host.split(".")[0]), meta: `linked from ${m.from.join(", ")} · not checked: this says nothing about whether the handle exists there`, sources: ["Profile links"], source: "Profile links", adult: { state: "mentioned", category: "adult" }, no_check: true });
  }
  return rows.sort((a, b) => RANK[a.adult.state] - RANK[b.adult.state] || a.what.localeCompare(b.what));
}

// ---- counts and wording ----------------------------------------------------------------------
export function adultCounts(rows0) {
  const rows = adultFound(rows0);
  const n = (st) => rows.filter((r) => r.adult?.state === st).length;
  const c = { read: n("read"), reported: n("reported"), blocked: n("blocked"), unknown: n("unknown"), noPage: n("no_public_url"), notFound: n("not_found") };
  return { ...c, mentioned: n("mentioned"), taken: c.read + c.reported, unchecked: c.blocked + c.unknown, total: (rows || []).length };
}
// The one neutral line the brief gets. These rows are in no other count.
export const adultBriefText = (rows) => { const b = (rows || []).find(isBlockRow); if (b) return blockText(b.adult.block); const c = adultCounts(rows); return `Adult and dating sites: ${plural(c.taken, "handle")} taken, ${fmtNum(c.unchecked)} could not be checked. Existence only.`; };
// The line under the group's heading: what the count is made of.
export const adultSummary = (rows) => { if ((rows || []).some(isBlockRow)) return ""; const c = adultCounts(rows); return [`${plural(c.taken, "handle")} taken (${fmtNum(c.read)} read, ${fmtNum(c.reported)} reported)`, `${fmtNum(c.unchecked)} could not be checked`, c.noPage ? `${fmtNum(c.noPage)} with no public page` : "", `${fmtNum(c.notFound)} not found`, c.mentioned ? `${fmtNum(c.mentioned)} only linked from a profile` : ""].filter(Boolean).join(" · ") + "."; };

// What the AI is told: the site, its kind, the state and what the link is worth. No names, no
// bios, no URLs. Sent as its own field and never inside `accounts`.
export const adultForAi = (rows) => adultFound(rows).filter((r) => r.adult.state !== "mentioned").slice(0, 200).map((r) => ({ site: String(r.what).slice(0, 120), category: r.adult.category, state: r.adult.state, url_kind: r.link_kind || "none" }));

// ---- exports ---------------------------------------------------------------------------------
// Markdown that cannot open a link or a tag: the snippet in a block is text someone else wrote.
const mdPlain = (t) => String(t).replace(/[\\`*_\[\]()<>|#!]/g, " ").replace(/\s+/g, " ").trim();
export const adultMarkdown = (rows) => ((rows || []).some(isBlockRow) ? [`## ${ADULT_GROUP}`, `> ${mdPlain(blockText(rows.find(isBlockRow).adult.block))}`, ""] : rows && rows.length ? [`## ${ADULT_SECTION} (${rows.length})`, `> ${ADULT_NOTICE}`, "", ...rows.map((i) => `- ${mdLink(i)}${mdNote(i) ? ` · ${mdNote(i)}` : ""} _(${i.source})_`), ""] : []);
// The same rows as a plain list, for the report and the source card. Text and links only.
export function adultListHtml(rows) {
  if (!rows || !rows.length) return "";
  if (rows.some(isBlockRow)) return `<p class="muted small">${esc(blockText(rows.find(isBlockRow).adult.block))}</p>`;
  return `<p class="muted small">${esc(ADULT_NOTICE)}</p><ul class="adult-list">${rows.map((i) => `<li><span class="site-glyph" aria-hidden="true">${esc(i.glyph)}</span>${link(i.url, i.what, "", { kind: i.link_kind })} <span class="dim small">${esc(i.meta)}</span>${i.hint ? `<span class="ev-hint"><b>How to check</b> ${esc(i.hint)}</span>` : ""}</li>`).join("")}</ul>`;
}

// What the adult site check did, for the run log and its card. `checked` is the number of sites
// it sent a request to; the rest have no public page or cannot be told apart automatically.
export function adultCheckText(d) {
  const rows = rowsOf(d).filter(isObj);
  const checked = Number.isInteger(d?.checked) && d.checked >= 0 && d.checked <= rows.length ? d.checked : rows.filter((r) => r.state !== "no_public_url").length;
  const found = rows.filter((r) => r.state === "found").length, blocked = rows.filter((r) => r.state === "blocked").length;
  return [`${fmtNum(checked)} checked`, `${fmtNum(found)} found`, blocked ? `${fmtNum(blocked)} blocked by site` : "", rows.length - checked > 0 ? `${fmtNum(rows.length - checked)} not checkable automatically` : ""].filter(Boolean).join(", ");
}

// ---- what a model or a pasted reply wrote about these sites -------------------------------------
// A heading that is about adult or dating sites, however it is worded.
const ADULT_HEADING = /\b(?:adults?|dating|nsfw|onlyfans|fansly|porn\w*|erotic\w*|escorts?|fetish\w*|webcams?|cam\s?(?:sites?|models?|girls?)|sex|sexual\w*|hook-?ups?|xxx)\b|18\s?\+/i;
export const isAdultHeading = (title) => ADULT_HEADING.test(String(title ?? ""));
const PROSE_BAD = /!\[|\]\(|https?:|www\.|<\s*[a-z!/]|\.(?:jpe?g|png|gif|webp|svg|mp4|webm)\b/i;
// Splits a report into the text outside such sections and the text inside them. A section runs
// from its heading to the next heading of the same or a higher level. The inside text keeps only
// lines with no address and no markup: the model was sent no address for these sites.
export function splitAdultProse(md) {
  const rest = [], prose = [];
  let level = 0;
  for (const line of String(md ?? "").split("\n")) {
    const m = line.match(/^(#{1,6})\s+(.+)/);
    if (m) {
      if (level && m[1].length > level && !isAdultHeading(m[2])) { if (!PROSE_BAD.test(line)) prose.push(line.replace(/^#+\s+/, "")); continue; }
      level = isAdultHeading(m[2]) ? m[1].length : 0;
      if (!level) rest.push(line);
      continue;
    }
    if (!level) rest.push(line);
    else if (line.trim() && !PROSE_BAD.test(line)) prose.push(line);
  }
  return { rest: rest.join("\n"), prose: prose.join("\n").trim() };
}
// A report as it may be exported: its adult sections are dropped unless the case has adult rows.
export const reportForExport = (md, hasAdult) => { const { rest, prose } = splitAdultProse(md); return hasAdult && prose ? `${rest.trimEnd()}\n\n## ${ADULT_SECTION}\n${prose}\n` : rest; };
