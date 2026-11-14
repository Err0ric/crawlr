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
    const repos = count(p.repos), followers = count(p.followers), year = joinedYear(p.created, now);
    if (repos) facts.push(`${repos} ${repos === "1" ? "repo" : "repos"}`);
    if (followers) facts.push(`${followers} ${followers === "1" ? "follower" : "followers"}`);
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
function tile(id, label, n, { tone = "", line = "solid", feeds = [], collected = {}, failed = new Set(), jump = null, sub = "" } = {}) {
  const fed = feeds.filter((k) => ran(collected, k));
  const down = fed.filter((k) => failed.has(k));
  const state = n > 0 ? "count" : !fed.length && feeds.length ? "off" : down.length ? "unknown" : "zero";
  const failedText = `${down.length === 1 ? "a source" : `${down.length} sources`} failed`;
  return {
    id, label, jump, state,
    value: state === "unknown" ? "unknown" : state === "off" ? "not checked" : n,
    tone: state === "count" ? tone : "",
    line: state === "unknown" || state === "off" ? "dashed" : line,
    sub: state === "unknown" ? `${failedText}, so this is not zero` : state === "count" && down.length ? `at least: ${failedText}` : sub,
  };
}
const word = (id, label, value, { tone = "", unknown = false, sub = "", jump = null } = {}) => ({ id, label, value: unknown ? "unknown" : value, tone: unknown ? "" : tone, line: unknown ? "dashed" : "solid", state: unknown ? "unknown" : "word", sub, jump });

// extra: values the caller already computed with the functions the page uses.
//   hash:  { verdict, detection: { positives, total } | null, answered, asked }
//   phone: { lineType, carrier }
//   name:  { answered, asked }   (directories)
export function investigateTiles({ items = [], collected = {}, type = "", failedKeys = [], extra = {} } = {}) {
  const failed = new Set(failedKeys);
  const n = (t) => items.filter((i) => i.tier === t).length;
  const o = { collected, failed };
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
    const x = extra.phone || {}, down = failed.has("phone");
    return [
      word("line", "Line type", x.lineType || "", { unknown: !x.lineType, sub: x.lineType ? "" : down ? "the lookup failed" : "needs a NumLookup key", jump: { tab: "sources" } }),
      word("carrier", "Carrier", x.carrier || "", { unknown: !x.carrier, sub: x.carrier ? "" : down ? "the lookup failed" : "needs a NumLookup key", jump: { tab: "sources" } }),
      tile("flags", "Flags", n("flag"), { ...o, tone: "flag", feeds: ["phone"], jump: { tier: "flag" } }),
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
  const people = ["github", "gravatar", "maigret", "enricher", "platformCheck", "holehe"];
  const linked = tile("linked", "Linked", n("linked"), { ...o, tone: "linked", feeds: people, jump: { tier: "linked" }, sub: "tied to the primary identity" });
  const unverified = tile("unverified", "Unverified", n("unverified"), { ...o, tone: "unverified", line: "dashed", feeds: ["sherlock", "maigret", "platformCheck", "hunter", "harvester"], jump: { tier: "unverified" }, sub: "reported, nothing read" });
  const leads = tile("lead", "Leads", n("lead"), { ...o, feeds: people, jump: { tier: "lead" }, sub: "places to look next" });
  if (type === "email") {
    const breaches = items.filter((i) => String(i.key || "").startsWith("breach:")).length;
    return [linked, tile("breaches", "Breaches", breaches, { ...o, tone: "flag", feeds: ["hibp"], jump: { tier: "flag" }, sub: "known exposures of this address" }), unverified, leads];
  }
  const diff = n("different");
  return [linked,
    tile("exists", "Exists", n("matches") + diff, { ...o, tone: "match", feeds: ["sherlock", "maigret", "platformCheck", "enricher", "github"], jump: { tier: n("matches") ? "matches" : "different" }, sub: diff ? `profiles read, ${diff} a different person` : "profiles read" }),
    unverified, leads];
}

// Recon. extra: { certDays: number | null }
export function reconTiles({ items = [], collected = {}, type = "domain", failedKeys = [], extra = {} } = {}) {
  if (type === "asn") return [];
  const failed = new Set(failedKeys);
  const o = { collected, failed };
  const n = (t) => items.filter((i) => i.tier === t).length;
  const key = (re) => items.filter((i) => re.test(String(i.key || ""))).length;
  const every = Object.keys(collected).filter((k) => k !== "ipAsn");
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
