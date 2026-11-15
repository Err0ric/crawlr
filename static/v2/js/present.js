// Presentation rules with no DOM: how certain a row is and how that is drawn, what an evidence
// card may say, the verdict tiles above a case, History grouped by target, and the check on a
// thumbnail before it is shown. Everything here is a pure function, so tests/js/design.test.mjs
// can hold each rule.

// ---- certainty grammar -----------------------------------------------------------------
// Line style says whether something was read or only reported: solid means a source read or
// checked it, dashed means it was reported and nothing checked it. Color says which tier.
// Every state also has a word, so neither line nor color is ever the only signal.
//   tone: the color token (flag, linked, match, different, unverified); "" is neutral ink
export const CERTAINTY = {
  flag:       { word: "Flag",             tone: "flag",       line: "solid" },
  linked:     { word: "Linked",           tone: "linked",     line: "solid" },
  matches:    { word: "Matches",          tone: "match",      line: "solid" },
  different:  { word: "Different person", tone: "different",  line: "solid" },
  unverified: { word: "Unverified",       tone: "unverified", line: "dashed" },
};
export const certaintyOf = (tier) => CERTAINTY[tier] || { word: "", tone: "", line: "solid" };
// How one row is drawn. The tier decides, with one refinement: an Unverified row whose templated
// URL the link check looked at. The tier stays Unverified, because nothing was read about who
// owns the page, but the row no longer says "nothing checked this":
//   page checked     solid neutral edge, solid pill "Page checked"
//   page not found   solid muted edge, greyed pill "Page not found"
//   blocked, or could not be checked: unchanged, dashed "Unverified" (the reason is on the row)
//   handle taken     a sign-up check said the handle is in use and nothing was read: dashed, like
//                    every row nothing read, with its own words
export function rowCertainty(it) {
  const c = certaintyOf(it?.tier);
  if (it?.tier === "unverified" && it.taken) return { word: "Handle taken", tone: "unverified", line: "dashed" };
  if (it?.tier === "unverified" && it.check === "verified") return { word: "Page checked", tone: "", line: "solid", checked: true };
  if (it?.tier === "unverified" && (it.check === "not_found" || it.gone)) return { word: "Page not found", tone: "", line: "solid", gone: true };
  return c;
}

// ---- favicons -----------------------------------------------------------------------------
// The host a site icon may be asked for, or "". It is always the registrable domain of the
// site (never a subdomain: sites such as DeviantArt put the handle there), never an IP address,
// a single-label or internal name, and never a domain that has the handle as a label.
const TWO_LEVEL = new Set("co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au co.nz co.jp ne.jp or.jp com.br com.mx com.ar com.tr com.cn com.hk com.tw com.sg co.in co.kr co.za com.ua co.il com.pl".split(" "));
const INTERNAL_TLD = new Set("local localhost internal intranet lan home corp private test example invalid onion arpa".split(" "));
export function iconDomain(url, handle = "") {
  let u;
  try { u = new URL(String(url)); } catch { return ""; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return "";
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!/^[a-z0-9.-]{4,253}$/.test(host) || /^[0-9.]+$/.test(host) || host.includes(":")) return "";
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((l) => !l) || INTERNAL_TLD.has(labels[labels.length - 1]) || /^\d+$/.test(labels[labels.length - 1])) return "";
  const take = labels.length >= 3 && TWO_LEVEL.has(labels.slice(-2).join(".")) ? 3 : 2;
  const reg = labels.slice(-take);
  const h = String(handle ?? "").trim().replace(/^@/, "").toLowerCase();
  if (h.length >= 2 && reg.slice(0, -1).some((l) => l === h || l.includes(h))) return "";
  return reg.join(".");
}
// Which rows may ask for a site icon at all: account rows only, never an adult or dating row,
// and never in a case opened from a case file (its hosts were chosen by whoever made the file)
// until the investigator runs it.
export const mayFavicon = (it, { imported = false } = {}) => !imported && !!it && String(it.key || "").startsWith("acct:") && !!it.card && it.tier !== "adult" && !it.glyph && !it.adult;

// ---- thumbnails and storage ------------------------------------------------------------------
// Thumbnails are the first thing dropped when the browser's storage is full: every stored run
// except `keepId` loses them, oldest first matters less than keeping the runs themselves.
export function withoutThumbs(list, keepId = "") {
  return (Array.isArray(list) ? list : []).map((e0) => {
    if (!e0 || e0.id === keepId) return e0;
    // The thumbnails of profiles read for a similar handle go the same way.
    const sim = e0.results?.similar;
    const hasSim = sim && typeof sim === "object" && Object.values(sim).some((v) => (v?.probe?.profiles || []).some?.((p) => p && p.thumb));
    const e = hasSim ? { ...e0, results: { ...e0.results, similar: Object.fromEntries(Object.entries(sim).map(([k, v]) => [k, v?.probe && Array.isArray(v.probe.profiles) ? { ...v, probe: { ...v.probe, profiles: v.probe.profiles.map((p) => (p && p.thumb ? { ...p, thumb: "" } : p)) } } : v])) } } : e0;
    const av = e?.results?.avatarHash;
    if (!av || !Array.isArray(av.results) || !av.results.some((r) => r && "thumb" in r)) return e;
    return { ...e, results: { ...e.results, avatarHash: { ...av, results: av.results.map((r) => { if (!r || !("thumb" in r)) return r; const { thumb, ...rest } = r; return rest; }) } } };
  });
}
// Writes History. When the browser refuses (storage full) thumbnails go first, then the current
// run's, and only then is the older half of History dropped, as before.
export function writeHistory(list, keepId, write) {
  if (write(list)) return list;
  let next = withoutThumbs(list, keepId);
  if (write(next)) return next;
  next = withoutThumbs(next, "");
  if (write(next)) return next;
  next = next.slice(0, Math.max(1, Math.floor(next.length / 2)));
  write(next);
  return next;
}

// ---- thumbnails --------------------------------------------------------------------------
// A profile picture is only ever shown from the small data URI the server's avatar comparison
// made (48 px, grayscale). Anything else, from a source or from a case file, is dropped: a
// thumbnail may be a short PNG or WebP data URI and nothing but that.
export const THUMB_MAX_CHARS = 4400;      // 3000 bytes as base64, plus the prefix
export const THUMB_MAX_COUNT = 30;
const THUMB_RE = /^data:image\/(?:png|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
export const safeThumb = (s) => (typeof s === "string" && s.length <= THUMB_MAX_CHARS && THUMB_RE.test(s) ? s : "");
// The avatar comparison as a case file may carry it: at most 30 rows, and a thumbnail only when
// it passes safeThumb and the row is a real picture. Every other field is left as it was.
export function boundAvatarHash(v) {
  if (!v || typeof v !== "object" || Array.isArray(v) || !Array.isArray(v.results)) return v;
  let kept = 0;
  const results = v.results.map((r) => {
    if (!r || typeof r !== "object" || !("thumb" in r)) return r;
    const { thumb, ...rest } = r;
    const ok = safeThumb(thumb) && r.default !== true && !r.error && !r.error_code && kept < THUMB_MAX_COUNT;
    if (ok) kept++;
    return ok ? { ...rest, thumb } : rest;
  });
  return { ...v, results };
}

// ---- evidence card -------------------------------------------------------------------------
// The year an account was made, from the many shapes sources use ("2011-09-03T15:26:22Z",
// "Wed, 15 Aug 2012 09:21:06 +0000", a Unix time). "" when no plausible year can be read.
export function joinedYear(v, now = new Date()) {
  const s = String(v ?? "").trim();
  if (!s) return "";
  let y = 0;
  if (/^\d{9,10}$/.test(s)) y = Number(s) * 1000 <= now.getTime() ? new Date(Number(s) * 1000).getUTCFullYear() : 0;
  else { const m = s.match(/(?:^|\D)((?:19|20)\d{2})(?:\D|$)/); y = m ? Number(m[1]) : 0; }
  return y >= 1990 && y <= now.getUTCFullYear() ? String(y) : "";
}
const count = (n) => (Number.isFinite(Number(n)) && n !== null && n !== "" && Number(n) >= 0 ? Number(n).toLocaleString("en-US") : "");
const clipText = (s, n) => { const t = String(s ?? "").replace(/\s+/g, " ").trim(); return t.length > n ? `${t.slice(0, n - 1).trimEnd()}…` : t; };

// What one account card says under its title. Facts are only what a source returned for that
// profile; nothing is filled in. When there is none, `basis` says what kind of check put the row
// here, so the card never looks like it knows more than it does.
//   row:     { tier, sources[], kinds: Set("read" | "reported" | "registered" | "noise") }
//   profile: the read profile for this row, or null ({ name, shownName, location, bio, created, repos, followers })
// Returns { facts: string[], bio: string, basis: string }.
export function cardSnippet(row, profile, now = new Date()) {
  const facts = [];
  const p = profile || null;
  if (p) {
    if (p.shownName) facts.push(String(p.shownName));
    if (p.location) facts.push(clipText(p.location, 60));
    const repos = count(p.repos), followers = count(p.followers), karma = count(p.karma), year = joinedYear(p.created, now);
    if (repos) facts.push(`${repos} ${repos === "1" ? "repo" : "repos"}`);
    if (followers) facts.push(`${followers} ${followers === "1" ? "follower" : "followers"}`);
    if (karma) facts.push(`${karma} karma`);
    if (year) facts.push(`joined ${year}`);
  }
  const bio = p ? clipText(p.bio, 140) : "";
  const kinds = row?.kinds instanceof Set ? row.kinds : new Set(row?.kinds || []);
  const by = (row?.sources || []).filter(Boolean).join(", ");
  const basis = facts.length || bio ? ""
    : kinds.has("registered") ? "The site's sign-up or reset form answered for this address. No profile was read."
      : p ? `Profile page read${by ? ` by ${by}` : ""}. It carries no name, bio or dates.`
        : kinds.has("reported") || kinds.has("read") ? `Reported${by ? ` by ${by}` : ""}. Nothing was read.` : "";
  return { facts, bio, basis };
}

// ---- verdict strip ---------------------------------------------------------------------------
// Four tiles at most, each a real count from the rows the ledger shows. A tile is:
//   { id, label, value, tone, line, state, sub, jump }
//   state  "count"   value is a number above zero
//          "zero"    the sources answered and there is nothing (drawn quiet)
//          "unknown" a source this count depends on failed and nothing was found: never shown as 0
//          "off"     no source that feeds this count ran
//          "word"    value is a word (a hash verdict, a line type)
//   jump   { tier } opens that group, { tab } opens that tab
// failedKeys: keys in `collected` whose source failed (from sourceTally).
const ran = (c, k) => c && c[k] !== undefined && c[k] !== null && !(c[k] && c[k].skipped);
// down: why a count cannot be trusted as a total. A feed that failed, answered only in part, or
// was asked and never answered (a cancelled run) makes a zero "unknown" and a count "at least".
function tile(id, label, n, { tone = "", line = "solid", feeds = [], collected = {}, failed = new Set(), partial = new Set(), missing = new Set(), jump = null, sub = "" } = {}) {
  const fed = feeds.filter((k) => ran(collected, k) || missing.has(k));
  const f = fed.filter((k) => failed.has(k)).length, m = fed.filter((k) => missing.has(k) && !ran(collected, k)).length, pt = fed.filter((k) => partial.has(k) && !failed.has(k)).length;
  const down = f + m + pt;
  const state = n > 0 ? "count" : !fed.length && feeds.length ? "off" : down ? "unknown" : "zero";
  const why = f ? (f === 1 ? "a source failed" : `${f} sources failed`) : m ? (m === 1 ? "a source did not answer before the run was cancelled" : `${m} sources did not answer before the run was cancelled`) : pt === 1 ? "a source answered only in part" : `${pt} sources answered only in part`;
  const atLeast = state === "count" && down > 0;
  return {
    id, label, jump, state, atLeast, caveat: state === "unknown" || atLeast,
    value: state === "unknown" ? "unknown" : state === "off" ? "not checked" : n,
    tone: state === "count" ? tone : "",
    line: state === "unknown" || state === "off" ? "dashed" : state === "zero" ? "solid" : line,
    sub: state === "unknown" ? `${why}, so this is not zero` : atLeast ? `at least: ${why}` : sub,
  };
}
// caveat: the line under the word changes what the word means ("the range, not the phone"), so it is shown at every width.
const word = (id, label, value, { tone = "", unknown = false, sub = "", jump = null, caveat = false } = {}) => ({ id, label, value: unknown ? "unknown" : value, tone: unknown ? "" : tone, line: unknown ? "dashed" : "solid", state: unknown ? "unknown" : "word", sub, jump, ...(caveat && sub ? { caveat: true } : {}) });

// extra: values the caller already computed with the functions the page uses.
//   hash:  { verdict, detection: { positives, total } | null, answered, asked }
//   phone: { known, valid, validWord, validSub, lineType, lineSub, place, placeSub }   (phoneTileExtra in phone.js)
//   name:  { answered, asked }   (directories)
// running: a run is in flight, so there are no tiles (a count mid-run is half a picture).
// partialKeys: sources that answered only in part. missingKeys: sources that were asked and had
// not answered when the run was cancelled.
export function investigateTiles({ items = [], collected = {}, type = "", failedKeys = [], partialKeys = [], missingKeys = [], running = false, extra = {} } = {}) {
  if (running) return [];
  const failed = new Set(failedKeys);
  const n = (t) => items.filter((i) => i.tier === t).length;
  const o = { collected, failed, partial: new Set(partialKeys), missing: new Set(missingKeys) };
  if (type === "hash") {
    const x = extra.hash;
    if (!x) return [];
    const V = { MALICIOUS: ["Malicious", "flag"], TEST_FILE: ["Test file", ""], CLEAN: ["Known clean", "linked"] }[x.verdict];
    return [
      word("verdict", "Verdict", V ? V[0] : "", { tone: V ? V[1] : "", unknown: !V, sub: V ? "" : x.answered ? "no source has seen it" : "no source answered", jump: { tier: n("flag") ? "flag" : "info" } }),
      x.detection ? word("engines", "Engines flagging it", `${x.detection.positives} of ${x.detection.total}`, { jump: { tab: "sources" } }) : word("engines", "Engines flagging it", "", { unknown: true, sub: "no ratio from keyless sources", jump: { tab: "sources" } }),
      word("answered", "Sources answered", `${x.answered} of ${x.asked}`, { unknown: x.asked > 0 && x.answered === 0, sub: x.answered < x.asked ? "the rest are unknown, not clean" : "", jump: { tab: "sources" } }),
    ];
  }
  if (type === "phone") {
    // Valid, Line type, Assigned in, Flags. Each is read from the numbering data, so it is solid
    // when there is a value. A lookup that failed, or a value this number cannot have, is dashed
    // "unknown" with the reason under it.
    const x = extra.phone || {}, down = failed.has("phone") || !x.known;
    const why = (sub) => (down ? "the lookup failed" : sub || "not known for this number");
    const info = { tier: n("info") ? "info" : "flag" };
    return [
      word("valid", "Valid", x.validWord || "", { tone: x.valid === true ? (x.fiction ? "" : "linked") : x.valid === false ? "flag" : "", unknown: down || !x.validWord, sub: down || !x.validWord ? why(x.validSub) : x.validSub || "", caveat: down || !x.validWord || !!x.validCaveat, jump: down ? { tab: "sources" } : info }),
      word("line", "Line type", x.lineType || "", { unknown: down || !x.lineType, sub: down || !x.lineType ? why(x.lineSub) : x.lineSub || "", caveat: down || !x.lineType || !!x.lineCaveat, jump: down ? { tab: "sources" } : info }),
      word("place", "Assigned in", x.place || "", { unknown: down || !x.place, sub: down || !x.place ? why(x.placeSub) : x.placeSub || "", caveat: true, jump: down ? { tab: "sources" } : info }),
      tile("flags", "Flags", n("flag"), { ...o, tone: "flag", feeds: ["phone"], jump: { tier: "flag" }, sub: "read these first" }),
    ];
  }
  if (type === "name") {
    const x = extra.name || { answered: 0, asked: 0 };
    return [
      tile("people", "Candidates", n("people"), { ...o, feeds: ["nameResult"], jump: { tier: "people" }, sub: "people who share the name" }),
      x.asked ? word("directories", "Directories answered", `${x.answered} of ${x.asked}`, { unknown: x.answered === 0, sub: x.answered < x.asked ? "the rest are unknown" : "", jump: { tab: "sources" } }) : word("directories", "Directories answered", "", { unknown: true, sub: "none was asked", jump: { tab: "sources" } }),
      tile("handles", "Handles to try", n("handles"), { ...o, jump: { tier: "handles" }, sub: "guesses, not findings" }),
      tile("notable", "Public figure", n("notable"), { ...o, feeds: ["nameResult"], jump: { tier: "notable" }, sub: "exact match in Wikidata" }),
    ];
  }
  const people = ["github", "githubDeep", "gravatar", "maigret", "enricher", "platformCheck", "holehe", "avatarHash"];
  // A templated URL the link check found is still Unverified (nothing was read about who owns it),
  // and the tile says how many of those pages were checked.
  const pages = items.filter((i) => i.tier === "unverified" && i.check === "verified").length;
  const linked = tile("linked", "Linked", n("linked"), { ...o, tone: "linked", feeds: people, jump: { tier: "linked" }, sub: "tied to the primary identity" });
  const unverified = tile("unverified", "Unverified", n("unverified"), { ...o, tone: "unverified", line: "dashed", feeds: ["sherlock", "maigret", "platformCheck", "hunter", "harvester"], jump: { tier: "unverified" }, sub: pages ? `reported, ${pages} ${pages === 1 ? "page" : "pages"} checked` : "reported, nothing read" });
  const leads = tile("lead", "Leads", n("lead"), { ...o, feeds: people, jump: { tier: "lead" }, sub: "places to look next" });
  if (type === "email") {
    const breaches = items.filter((i) => String(i.key || "").startsWith("breach:")).length;
    // Flags takes the third place when the case has flags that are not breaches; otherwise that
    // tile would repeat the breach count, and Unverified says more.
    const otherFlags = n("flag") - breaches;
    return [linked, tile("breaches", "Breaches", breaches, { ...o, tone: "flag", feeds: ["hibp"], jump: { tier: "flag" }, sub: "known exposures of this address" }),
      otherFlags > 0 ? tile("flags", "Flags", otherFlags, { ...o, tone: "flag", feeds: ["hibp"], jump: { tier: "flag" }, sub: "besides the breaches" }) : unverified, leads];
  }
  const diff = n("different");
  return [linked,
    tile("exists", "Exists", n("matches") + diff, { ...o, tone: "match", feeds: ["sherlock", "maigret", "platformCheck", "enricher", "github"], jump: { tier: n("matches") ? "matches" : "different" }, sub: diff ? `profiles read, ${diff} a different person` : "profiles read" }),
    unverified, leads];
}

// Recon. extra: { certDays: number | null }
export function reconTiles({ items = [], collected = {}, type = "domain", failedKeys = [], partialKeys = [], missingKeys = [], running = false, extra = {} } = {}) {
  if (type === "asn" || running) return [];
  const failed = new Set(failedKeys);
  const o = { collected, failed, partial: new Set(partialKeys), missing: new Set(missingKeys) };
  const n = (t) => items.filter((i) => i.tier === t).length;
  const key = (re) => items.filter((i) => re.test(String(i.key || ""))).length;
  const every = [...new Set([...Object.keys(collected).filter((k) => k !== "ipAsn" && k !== "notAnswered"), ...missingKeys])];
  const out = [
    tile("flags", "Flags", n("flag"), { ...o, tone: "flag", feeds: every, jump: { tier: "flag" }, sub: "read these first" }),
    tile("services", "Open ports", key(/^port:/), { ...o, feeds: ["shodan", "portscan"], jump: { tier: items.some((i) => i.tier === "surface") ? "surface" : "flag" }, sub: "seen from outside" }),
  ];
  if (type === "domain") out.push(tile("subdomains", "Subdomains", n("inventory"), { ...o, feeds: ["subdomains", "harvest"], jump: { tier: "inventory" }, sub: "from DNS and certificate logs" }));
  const days = Number.isFinite(extra.certDays) ? extra.certDays : null;
  out.push(tile("expiring", "Expiring soon", key(/^(tls|whois):expiry$/), { ...o, tone: "flag", feeds: type === "domain" ? ["ssl", "whois"] : ["ssl"], jump: { tier: "flag" }, sub: days === null ? "certificate or domain" : `certificate has ${days} ${days === 1 ? "day" : "days"} left` }));
  return out;
}

// ---- History grouped by target ------------------------------------------------------------------
// One entry per target and workbench, newest run first, in the order History already has.
// Presentation only: nothing stored is changed, merged or removed.
//   { key, target, type, kind, runs[], count, last, imported }
export function groupHistory(list) {
  const groups = new Map();
  for (const e of Array.isArray(list) ? list : []) {
    if (!e || typeof e !== "object" || typeof e.target !== "string") continue;
    const key = `${e.type || ""}|${e.target.trim().toLowerCase()}`;
    let g = groups.get(key);
    if (!g) { g = { key, target: e.target, type: e.type || "", kind: e.kind || "", runs: [] }; groups.set(key, g); }
    g.runs.push(e);
  }
  return [...groups.values()].map((g) => {
    const runs = g.runs.slice().sort((a, b) => (Number(b.timestamp) || 0) - (Number(a.timestamp) || 0));
    return { ...g, target: runs[0].target, kind: runs[0].kind || g.kind, runs, count: runs.length, last: runs[0], imported: runs.some((r) => !!r.imported) };
  });
}
// What changed between a target's last two runs. keysOf(entry) returns the finding keys of one
// saved run, built by the same code that draws the case. null when there is only one run or the
// runs cannot be compared.
export function lastRunDiff(group, keysOf) {
  if (!group || group.count < 2 || typeof keysOf !== "function") return null;
  let now, before;
  try { now = keysOf(group.runs[0]); before = keysOf(group.runs[1]); } catch { return null; }
  if (!Array.isArray(now) || !Array.isArray(before)) return null;
  const a = new Set(before), b = new Set(now);
  const added = [...b].filter((k) => !a.has(k)).length, removed = [...a].filter((k) => !b.has(k)).length;
  return { added, removed, same: b.size - added };
}
export const diffText = (d) => (!d ? "" : !d.added && !d.removed ? "no changes since the run before" : `${d.added} new, ${d.removed} gone since the run before`);
