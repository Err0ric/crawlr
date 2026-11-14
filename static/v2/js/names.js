// Name cases. A name is shared by many people, so everything a name search returns is a
// candidate to look at and never a finding about one person.
// Pure: no DOM, no network. Old saved cases and case files go through the same code.
//
// What a name case holds in `collected`:
//   nameSearch      the name as typed (a string). Older cases have only this.
//   nameQualifiers  { location, employer, keyword }: optional, used to rank, never to search
//   nameResult      the answer of POST /api/recon/name-search, or its failure
//   nameProfiles    { <GitHub login>: { found, name, bio, location, company } | { error } }:
//                   what "Show profile" loaded, one click per row
// All four are outside data once they have been saved or exported, so every reader here checks
// shape, clips text and rebuilds each URL from an ID that fits its directory's pattern.
//
// Candidates never become facts, never enter identity clusters or the avatar comparison, and
// carry no picture. Their rows live in four ledger groups of their own (NAME_TIERS).

import { classifyLink, parseUrl } from "./links.js";

export const NAME_NOTICE = "A name is shared by many people. Everything below is a candidate to look at, not a finding about one person.";
export const NAME_SOURCE = "Name search";
export const NAME_SOURCE_DESC = "people with this name in Wikidata, GitHub, ORCID, OpenAlex and Bluesky";
export const NAME_NOT_USABLE = "That is not a usable name. Use 2 to 80 letters; spaces, hyphens, apostrophes and periods are allowed.";
export const NO_ONE_SELECTED = "No single person is selected. Pick a candidate or a handle to investigate.";
export const NEXT_STEP = "Pick the person you mean, then investigate their handle.";
export const DIRECTORIES = ["Wikidata", "GitHub", "ORCID", "OpenAlex", "Bluesky"];
export const QUALIFIERS = ["location", "employer", "keyword"];
export const QUALIFIER_LABEL = { location: "Location", employer: "Employer or school", keyword: "Keyword" };
export const QUALIFIER_HINT = "Optional. Used to rank the people found, not to search for them.";
export const MATCH_WORD = { exact: "exact name", tokens: "all name words", partial: "family name and initial", none: "name on profile does not match" };
export const PATTERN_WORD = {
  name: "the name as one word",
  givenfamily: "given name + family name", "given.family": "given name + dot + family name", given_family: "given name + underscore + family name",
  gfamily: "given initial + family name", givenf: "given name + family initial", familygiven: "family name + given name",
  "family.given": "family name + dot + given name", "given-family": "given name + hyphen + family name",
  givenmfamily: "given name + middle initial + family name", "given.m.family": "given name + dot + middle initial + dot + family name",
  gmfamily: "given and middle initials + family name", givenmiddlefamily: "given name + middle name + family name",
};
// Handles that spell out both names. A profile using one of them fits the name (the server's rule).
const SHORT_PATTERNS = new Set(["gfamily", "givenf", "gmfamily"]);

export const NAME_TIERS = [
  { id: "notable",   title: "Public figure",         cls: "", open: true,  blurb: "Wikidata lists a person with exactly this name. That does not make them the person you are looking for." },
  { id: "people",    title: "People with this name", cls: "", open: true,  blurb: "People and accounts the directories returned for this name, best name fit first. Two rows can be two different people, or one person in two directories. Nothing is fetched or followed until you click." },
  { id: "handles",   title: "Handles to try",        cls: "", open: false, blurb: "Built from the name. Nothing has been checked: a handle here may not exist, or may belong to someone else." },
  { id: "websearch", title: "Search the web",        cls: "", open: true,  blurb: "These open a search on another site. The name and anything you typed above go to that site." },
];
const NAME_TIER_IDS = new Set(NAME_TIERS.map((t) => t.id));
export const isNameTier = (id) => NAME_TIER_IDS.has(id);
// "Handles to try" is collapsed when there are people to look at, and open when there are none.
export const nameTierView = (tiers, items) => { const people = (items || []).some((i) => i.tier === "people"); return tiers.map((t) => (t.id === "handles" ? { ...t, open: !people } : t)); };

// ---- text ----------------------------------------------------------------------------
// One line of plain text, clipped. Anything that is not a string is dropped.
const line = (v, n) => (typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").replace(/\s+/g, " ").trim().slice(0, n).trim() : "");
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const list = (arr) => (arr.length < 2 ? arr.join("") : `${arr.slice(0, -1).join(", ")} and ${arr[arr.length - 1]}`);
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;

// Lowercase, accents removed, punctuation out: the form two spellings are compared in.
// The same folding as modules/name_search.py, so a row re-matched here agrees with the server.
const ASCII_MAP = { "ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "ł": "l", "þ": "th", "ı": "i", "ħ": "h" };
export function fold(text) {
  return String(text ?? "").normalize("NFKD").toLowerCase()
    .replace(/[ßæœøđðłþıħ]/g, (c) => ASCII_MAP[c]).replace(/\p{Mn}/gu, "").replace(/['’ʼ]/g, "")
    .replace(/[^\p{L}\p{N}]+/gu, " ").trim();
}
export function parseName(name) {
  const parts = String(name ?? "").trim().split(/\s+/).filter(Boolean);
  if (parts.length < 2) return { given: parts[0] || "", middle: "", family: "", single_token: true };
  return { given: parts[0], middle: parts.slice(1, -1).join(" "), family: parts[parts.length - 1], single_token: false };
}
// How well the best of `names` fits the searched name: "exact", "tokens" (every word is there),
// "partial" (the family name plus the given initial) or null. `fullHandles` are the suggested
// handles that spell out both names.
export function matchName(searched, names, { handle = "", fullHandles = [] } = {}) {
  const folded = fold(searched), words = folded.split(" ").filter(Boolean);
  if (!words.length) return null;
  const parsed = parseName(searched), given = fold(parsed.given), family = fold(parsed.family);
  let best = null;
  for (const raw of [].concat(names || [])) {
    const w = fold(raw).split(" ").filter(Boolean);
    if (!w.length) continue;
    if (w.join(" ") === folded) return "exact";
    if (words.every((x) => w.includes(x))) best = "tokens";
    else if (best === null && !parsed.single_token && family && w.includes(family) && w.some((x) => x !== family && x[0] === given[0])) best = "partial";
  }
  if (best !== "tokens" && handle && fullHandles.includes(String(handle).toLowerCase())) best = "tokens";
  return best;
}
// Which qualifiers appear as whole words in the given fields.
export function qualifierHits(qualifiers, ...fields) {
  const text = ` ${fold(fields.filter(Boolean).join(" \n "))} `;
  return QUALIFIERS.filter((k) => { const q = fold(qualifiers?.[k]); return !!q && text.includes(` ${q} `); });
}

// ---- reading what was stored ---------------------------------------------------------
const ID = {
  Wikidata: /^Q[1-9]\d{0,11}$/,
  GitHub: /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/,
  ORCID: /^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$/,
  OpenAlex: /^A\d{1,15}$/,
  Bluesky: /^(?=.{3,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/,
};
const URL_OF = {
  Wikidata: (id) => `https://www.wikidata.org/wiki/${id}`,
  GitHub: (id) => `https://github.com/${id}`,
  ORCID: (id) => `https://orcid.org/${id}`,
  OpenAlex: (id) => `https://openalex.org/${id}`,
  Bluesky: (id) => `https://bsky.app/profile/${id}`,
};
const KIND = { Wikidata: "public_figure", GitHub: "account", ORCID: "researcher", OpenAlex: "researcher", Bluesky: "account" };
const STATES = ["ok", "none", "failed", "rate_limited"];
const HANDLE_OK = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_CANDIDATES = 30, MAX_HANDLES = 12, MAX_PROFILES = 30;
const sameUrl = (a, b) => { const x = parseUrl(a); return !!x && !x.username && !x.password && x.href.replace(/\/$/, "").toLowerCase() === b.toLowerCase(); };

export function readQualifiers(q) {
  return Object.fromEntries(QUALIFIERS.map((k) => [k, line(isObj(q) ? q[k] : "", 80)]));
}
const hasQualifiers = (q) => QUALIFIERS.some((k) => q[k]);

// The English Wikipedia article for the public figure, and nothing else on that host.
function wikipediaUrl(u) {
  const x = parseUrl(u);
  return x && x.protocol === "https:" && x.hostname === "en.wikipedia.org" && !x.username && !x.password && !x.port && /^\/wiki\/[^/?#]{1,300}$/.test(x.pathname) && !x.search ? `https://en.wikipedia.org${x.pathname}` : "";
}
function readCandidate(c) {
  if (!isObj(c) || !Object.hasOwn(ID, c.source)) return null;
  const handle = typeof c.handle === "string" ? c.handle.trim() : "";
  if (!ID[c.source].test(handle) || !["exact", "tokens", "partial"].includes(c.name_match)) return null;
  // The link is rebuilt from the checked ID. A stored URL that is anything else is not shown.
  const built = URL_OF[c.source](handle);
  return {
    source: c.source, kind: KIND[c.source], name: line(c.name, 120), handle, url: sameUrl(c.url, built) ? built : "",
    description: line(c.description, 240), location: line(c.location, 120), affiliation: line(c.affiliation, 200),
    name_match: c.name_match, qualifier_hits: QUALIFIERS.filter((k) => Array.isArray(c.qualifier_hits) && c.qualifier_hits.includes(k)),
  };
}
// The name search answer, read defensively. Returns null when there is nothing usable, the three
// error keys when the whole request failed, or the same shape the server sends.
export function readNameResult(raw) {
  if (!isObj(raw)) return null;
  if (raw.error || raw.error_code) return { error: line(String(raw.error || "Failed"), 200) || "Failed", error_code: /^[a-z_]{1,40}$/.test(raw.error_code) ? raw.error_code : "unknown", error_detail: line(raw.error_detail, 300) };
  if (!Array.isArray(raw.candidates) || !isObj(raw.sources)) return null;
  const name = line(raw.name, 80);
  const seen = new Set(), candidates = [];
  for (const c of raw.candidates.slice(0, 200)) {
    const r = readCandidate(c);
    const k = r && `${r.source}:${r.handle.toLowerCase()}`;
    if (!r || seen.has(k) || candidates.length >= MAX_CANDIDATES) continue;
    seen.add(k); candidates.push(r);
  }
  const sources = {};
  for (const d of DIRECTORIES) {
    const s = raw.sources[d];
    if (!isObj(s) || !STATES.includes(s.state)) continue;
    const count = candidates.filter((c) => c.source === d).length;
    const bad = s.state === "failed" || s.state === "rate_limited";
    // A directory is "ok" only while it has rows here; rows that did not pass the checks are gone.
    sources[d] = { state: bad ? s.state : count ? "ok" : "none", count, total: Number.isInteger(s.total) && s.total >= 0 ? s.total : null,
      ...(bad ? { error: line(s.error, 200), error_code: /^[a-z_]{1,40}$/.test(s.error_code) ? s.error_code : "unknown", error_detail: line(s.error_detail, 300) } : {}) };
  }
  const hs = new Set(), handles = [];
  for (const x of Array.isArray(raw.handles) ? raw.handles.slice(0, 60) : []) {
    const value = isObj(x) && typeof x.value === "string" ? x.value : "";
    if (!HANDLE_OK.test(value) || value.startsWith("-") || !Object.hasOwn(PATTERN_WORD, x.pattern) || hs.has(value) || handles.length >= MAX_HANDLES) continue;
    hs.add(value); handles.push({ value, pattern: x.pattern });
  }
  let notable = null;
  if (isObj(raw.notable) && line(raw.notable.name, 120)) {
    const wd = typeof raw.notable.url === "string" && /^https:\/\/www\.wikidata\.org\/wiki\/Q[1-9]\d{0,11}$/.test(raw.notable.url) ? raw.notable.url : "";
    notable = { name: line(raw.notable.name, 120), description: line(raw.notable.description, 240), url: wd, wikipedia: wikipediaUrl(raw.notable.wikipedia) };
  }
  return { name, parsed: parseName(name), candidates, sources, handles, notable, cached: raw.cached === true };
}
// What "Show profile" keeps from GitHub's answer: four text fields. No picture, no counts.
export function readProfile(v) {
  if (!isObj(v)) return null;
  if (v.error || v.error_code) return { error: line(String(v.error || "Failed"), 200) || "Failed", error_code: /^[a-z_]{1,40}$/.test(v.error_code) ? v.error_code : "unknown" };
  if (v.found === false) return { found: false };
  if (v.found !== true) return null;
  return { found: true, name: line(v.name, 120), bio: line(v.bio, 240), location: line(v.location, 120), company: line(v.company, 200) };
}
export function readProfiles(map) {
  const out = {};
  if (isObj(map)) for (const [k, v] of Object.entries(map)) {
    if (Object.keys(out).length >= MAX_PROFILES) break;
    const p = ID.GitHub.test(k) ? readProfile(v) : null;
    if (p) out[k] = p;
  }
  return out;
}
// The name-case values of a stored case, re-checked. Everything else in `collected` is left alone.
export function scrubNames(collected) {
  if (!isObj(collected)) return {};
  const out = { ...collected };
  if ("nameResult" in out) { const r = readNameResult(out.nameResult); if (r) out.nameResult = r; else delete out.nameResult; }
  if ("nameProfiles" in out) { const p = readProfiles(out.nameProfiles); if (Object.keys(p).length) out.nameProfiles = p; else delete out.nameProfiles; }
  if ("nameQualifiers" in out) { const q = readQualifiers(out.nameQualifiers); if (hasQualifiers(q)) out.nameQualifiers = q; else delete out.nameQualifiers; }
  if ("nameSearch" in out && typeof out.nameSearch !== "string") delete out.nameSearch;
  return out;
}

// ---- the case as the screen shows it -------------------------------------------------
// people: the candidates in the server's order, each GitHub row merged with its loaded profile.
//   profile: "" (not a GitHub row), "none" (not loaded), "read", "gone" (GitHub has no such
//   account now) or "unknown" (the lookup failed or was rate limited)
//   name_match: the server's, or re-evaluated against the name on the loaded profile ("none"
//   when that name does not fit at all). Rows that do not fit go to the end of the group.
export function nameCase(collected, target = "") {
  const read = readNameResult(collected?.nameResult);
  const result = read && !read.error ? read : null;
  const qualifiers = readQualifiers(collected?.nameQualifiers);
  const profiles = readProfiles(collected?.nameProfiles);
  // The name comes from the case, never from the target box: a string the server refused is not searched anywhere.
  const name = (result && result.name) || line(collected?.nameSearch, 200);
  const fullHandles = (result?.handles || []).filter((x) => !SHORT_PATTERNS.has(x.pattern)).map((x) => x.value.toLowerCase());
  const people = (result?.candidates || []).map((c) => {
    if (c.source !== "GitHub") return { ...c, profile: "" };
    const p = profiles[c.handle];
    if (!p) return { ...c, profile: "none" };
    if (p.error || p.error_code) return { ...c, profile: "unknown", profile_error: p.error_code === "rate_limited" ? "GitHub rate limited the lookup" : "the lookup failed" };
    if (!p.found) return { ...c, profile: "gone" };
    return { ...c, profile: "read", name: p.name, description: p.bio, location: p.location, affiliation: p.company,
      name_match: p.name ? matchName(result.name, [p.name], { handle: c.handle, fullHandles }) || "none" : c.name_match,
      qualifier_hits: qualifierHits(qualifiers, p.location, p.company, p.bio) };
  });
  const last = (r) => (r.name_match === "none" || r.profile === "gone" ? 1 : 0);
  people.sort((a, b) => last(a) - last(b));
  const asked = result ? DIRECTORIES.filter((d) => result.sources[d]) : [];
  const down = asked.filter((d) => result.sources[d].state === "failed" || result.sources[d].state === "rate_limited");
  const given = QUALIFIERS.filter((k) => qualifiers[k]);
  return {
    name, result, failed: read && read.error ? read : null, qualifiers, given, people, asked, down, answered: asked.filter((d) => !down.includes(d)),
    notable: result?.notable || null, handles: result?.handles || [], single: !!result?.parsed.single_token,
    matchAll: given.length ? people.filter((r) => r.name_match !== "none" && given.every((k) => r.qualifier_hits.includes(k))).length : 0,
  };
}

// "Wikidata 1 · GitHub 8 · ORCID none · OpenAlex rate limited · Bluesky 1": the run log line.
const STATE_WORD = { none: "none", failed: "failed", rate_limited: "rate limited" };
export function directoryText(raw) {
  const r = readNameResult(raw);
  if (!r || r.error) return "";
  return DIRECTORIES.filter((d) => r.sources[d]).map((d) => `${d} ${r.sources[d].state === "ok" ? r.sources[d].count : STATE_WORD[r.sources[d].state]}`).join(" · ");
}
const whyDown = (s) => (s.state === "rate_limited" ? "rate limited" : s.error || "failed");

// The words on a candidate row: what the directory gave, how the name fits, which qualifiers hit.
function personMeta(r) {
  const at = r.kind === "account" && r.name ? `@${r.handle}` : r.source === "ORCID" ? `ORCID ${r.handle}` : "";
  const state = r.profile === "none" ? "GitHub gives the login only. Show profile loads the name and bio."
    : r.profile === "unknown" ? `profile unknown: ${r.profile_error}`
      : r.profile === "gone" ? "GitHub has no account with this login now"
        : r.profile === "read" && !r.name ? "no name on profile" : "";
  return [at, r.description, r.location, r.affiliation, r.profile === "gone" ? "" : MATCH_WORD[r.name_match] || "", ...r.qualifier_hits.map((k) => `matches ${k}`), state].filter(Boolean).join(" · ");
}
// The username worth investigating for an account row: a GitHub login, or the first label of a
// name.bsky.social handle. A Bluesky handle on its own domain is a domain, not a username.
function usernameOf(r) {
  if (r.kind !== "account" || r.profile === "gone") return "";
  const u = r.source === "Bluesky" ? (r.handle.endsWith(".bsky.social") ? r.handle.slice(0, -".bsky.social".length) : "") : r.handle;
  return HANDLE_OK.test(u) && !u.startsWith("-") && !u.includes(".") ? u : "";
}
const investigate = (value) => ({ label: "Investigate this", pivot: "investigate", value, type: "username" });

// ---- outbound searches -----------------------------------------------------------------
// The one place a name goes into a third-party URL, and only when the investigator opens it.
// These rows have their own link kind ("search"): they are not evidence and prove nothing.
const enc = encodeURIComponent;
const bare = (s) => String(s ?? "").replace(/["“”]/g, " ").replace(/\s+/g, " ").trim();
const term = (s) => (/\s/.test(s) ? `"${s}"` : s);
export function searchLinks(name, qualifiers = {}) {
  const n = bare(line(String(name ?? ""), 200)), q = readQualifiers(qualifiers);
  if (!n) return [];
  const extras = QUALIFIERS.map((k) => bare(q[k])).filter(Boolean);
  const query = enc([`"${n}"`, ...extras.map(term)].join(" "));
  const sent = (keys) => `sends the name${keys.length ? ` and your ${list(keys)}` : ""}`;
  const given = QUALIFIERS.filter((k) => bare(q[k]));
  const loc = bare(q.location), emp = bare(q.employer);
  return [
    { site: "Google", kind: "web search", url: `https://www.google.com/search?q=${query}`, keys: given },
    { site: "Bing", kind: "web search", url: `https://www.bing.com/search?q=${query}`, keys: given },
    { site: "DuckDuckGo", kind: "web search", url: `https://duckduckgo.com/?q=${query}`, keys: given },
    { site: "LinkedIn", kind: "people search", url: `https://www.linkedin.com/search/results/people/?keywords=${enc([n, emp].filter(Boolean).join(" "))}`, keys: emp ? ["employer"] : [] },
    { site: "Facebook", kind: "people search", url: `https://www.facebook.com/search/people/?q=${enc(n)}`, keys: [] },
    { site: "TruePeopleSearch", kind: "people search", url: `https://www.truepeoplesearch.com/results?name=${enc(n)}${loc ? `&citystatezip=${enc(loc)}` : ""}`, keys: loc ? ["location"] : [] },
    { site: "FastPeopleSearch", kind: "people search", url: `https://www.fastpeoplesearch.com/name/${enc(n)}`, keys: [] },
    { site: "Spokeo", kind: "people search", url: `https://www.spokeo.com/${enc(n)}`, keys: [] },
    { site: "BeenVerified", kind: "people search", url: `https://www.beenverified.com/people/${enc(n)}/`, keys: [] },
    { site: "WhitePages", kind: "people search", url: `https://www.whitepages.com/name/${enc(n)}`, keys: [] },
  ].map((s) => ({ site: s.site, url: s.url, meta: `${s.kind} · ${sent(s.keys)}` }));
}

// ---- ledger rows -----------------------------------------------------------------------
// Rows for the four name groups, in order. A row's link: the public figure links to Wikipedia
// and Wikidata as evidence, a candidate links to the record its directory returned, a suggested
// handle has no link, and a search row is an outbound search.
export function nameItems(collected, target = "") {
  const nc = nameCase(collected, target);
  const items = [];
  if (nc.notable) {
    const links = [[nc.notable.wikipedia, "Wikipedia"], [nc.notable.url, "Wikidata"]].filter(([u]) => u).map(([u, label]) => ({ ...classifyLink({ url: u, want: "evidence", subjects: [nc.notable.name] }), label })).filter((l) => l.link_kind === "evidence");
    items.push({ tier: "notable", what: nc.notable.name, meta: nc.notable.description, source: "Wikidata", key: "name:notable",
      url: links[0]?.url || "", link_kind: links[0] ? "evidence" : "none", ...(links[0] ? { link_label: links[0].label } : {}), ...(links[1] ? { more: { url: links[1].url, label: links[1].label, link_kind: "evidence" } } : {}) });
  }
  for (const r of nc.people) {
    const u = usernameOf(r);
    items.push({ tier: "people", what: r.name || r.handle, meta: personMeta(r), source: r.source, key: `cand:${r.source.toLowerCase()}:${r.handle.toLowerCase()}`,
      // The directory returned this record, so its address is a read profile, not a guess.
      // An account GitHub says is gone has no page to open.
      ...(({ url, link_kind }) => ({ url, link_kind }))(classifyLink({ url: r.profile === "gone" ? "" : r.url, want: "verified_profile", site: r.source, subjects: [r.handle] })),
      ...(u ? { action: investigate(u) } : {}),
      ...(r.profile === "none" || r.profile === "unknown" ? { fetch: { label: r.profile === "none" ? "Show profile" : "Try again", login: r.handle } } : {}),
      ...(r.name_match === "none" || r.profile === "gone" ? { gone: true } : {}) });
  }
  for (const x of nc.handles) items.push({ tier: "handles", what: x.value, url: "", link_kind: "none", meta: PATTERN_WORD[x.pattern], source: "built from the name", key: `handle:${x.value.toLowerCase()}`, action: investigate(x.value) });
  for (const s of searchLinks(nc.name, nc.qualifiers)) {
    const l = classifyLink({ url: s.url, want: "search", subjects: [nc.name] });
    if (l.link_kind === "search") items.push({ tier: "websearch", what: s.site, url: l.url, link_kind: "search", meta: s.meta, source: "opens on that site", key: `search:${s.site.toLowerCase()}` });
  }
  return items;
}

// ---- notices, "What we know", "At a glance" ---------------------------------------------
// What stands above the rows: the caveat, always, then the state of the search in words. The
// three states stay apart: every directory answered and none had the name, some could not be
// asked, or none could.
export function nameNotices(collected, target = "") {
  const nc = nameCase(collected, target);
  const out = [{ level: "note", text: NAME_NOTICE }];
  if (!nc.result) return out;
  const src = nc.result.sources;
  const downText = list(nc.down.map((d) => `${d} (${whyDown(src[d])})`));
  if (!nc.asked.length) out.push({ level: "err", title: "No directory was asked.", text: "The search returned no answer from any directory, so nothing is known either way." });
  else if (!nc.answered.length) out.push({ level: "err", title: "No directory could be asked.", text: `${downText}. That is unknown, not "nobody has this name". Run it again in a few minutes.` });
  else if (!nc.people.length && !nc.down.length) out.push({ level: "note", title: "No directory had this name.", text: `${list(nc.answered)} answered, and none lists a person with this name. Check the spelling, or try the handles and searches below.` });
  else if (!nc.people.length) out.push({ level: "err", title: "No one found in the directories that answered.", text: `${list(nc.answered)} answered and had no one by this name. ${downText} could not be asked, so this is not a clean negative.` });
  else if (nc.down.length) out.push({ level: "err", title: `${plural(nc.down.length, "directory", "directories")} could not be asked.`, text: `${downText}. The rows below say nothing about ${nc.down.length === 1 ? "it" : "them"}: unknown, not "nobody there".` });
  return out;
}
const qualifierText = (nc) => list(nc.given.map((k) => `${QUALIFIER_LABEL[k].toLowerCase()} "${nc.qualifiers[k]}"`));
// "What we know" for a name case. No identity is selected, so there are no facts.
export function nameKnown(collected, target = "") {
  const nc = nameCase(collected, target);
  const lines = [];
  if (nc.notable) lines.push(`A public figure has this name: ${nc.notable.name}${nc.notable.description ? `, ${nc.notable.description}` : ""} (Wikidata). That does not make them the person you mean.`);
  if (nc.given.length) lines.push(`Ranking by ${qualifierText(nc)}. ${nc.given.length === 1 ? "It was" : "They were"} compared with what came back and not sent to any directory.`);
  return { lead: NO_ONE_SELECTED, lines };
}
// "At a glance" rows for a name case: [{ level, text, ev? }].
export function nameBrief(collected, target = "") {
  const nc = nameCase(collected, target);
  const rows = [];
  const add = (level, text, ev) => rows.push({ level, text, ...(ev ? { ev } : {}) });
  if (nc.failed) return rows;   // the failed source line says it
  if (!nc.result) { add("info", "No directory was searched for this case. The links under Search the web open searches for you to run by hand."); return rows; }
  const src = nc.result.sources;
  const withRows = nc.answered.filter((d) => src[d].count > 0);
  if (nc.single) add("flag", "A one-word name matches too many people, so only exact matches on Wikidata, GitHub and Bluesky were looked for. Use a first and last name for a wider search.");
  if (nc.people.length) add("info", `${plural(nc.people.length, "candidate")} in ${withRows.length} of ${plural(nc.asked.length, "directory", "directories")} (${withRows.map((d) => `${d} ${src[d].count}`).join(", ")}). They share the name; they are not one person, and one person can appear once per directory.`);
  else if (nc.answered.length && !nc.down.length) add("info", `None of the ${plural(nc.answered.length, "directory", "directories")} asked lists a person with this name.`);
  else if (nc.answered.length) add("info", `No one by this name in the ${plural(nc.answered.length, "directory", "directories")} that answered.`);
  if (nc.notable) add("info", `A public figure has this name: ${nc.notable.name}${nc.notable.description ? `, ${nc.notable.description}` : ""}. Do not assume the person you mean is this one.`, nc.notable.wikipedia ? { url: nc.notable.wikipedia, label: "Wikipedia" } : nc.notable.url ? { url: nc.notable.url, label: "Wikidata" } : null);
  else if (src.Wikidata && !nc.down.includes("Wikidata")) add("info", "Wikidata lists no public figure with exactly this name.");
  else if (src.Wikidata) add("info", "Wikidata could not be asked, so whether a public figure has this name is unknown.");
  if (nc.people.length && nc.given.length) {
    const unread = nc.people.filter((r) => r.profile === "none").length;
    add(nc.matchAll ? "ok" : "info", `${nc.matchAll} of ${plural(nc.people.length, "candidate")} ${nc.matchAll === 1 ? "matches" : "match"} ${qualifierText(nc)}.${unread ? ` ${plural(unread, "GitHub row")} ${unread === 1 ? "has" : "have"} no details to compare until you choose Show profile.` : ""}`);
  } else if (nc.people.length > 1) add("info", "No location, employer or keyword was given. Adding one under the name puts the people it fits first.");
  if (nc.down.length) add("flag", `${list(nc.down.map((d) => `${d} (${whyDown(src[d])})`))} could not be asked, so ${nc.down.length === 1 ? "it is" : "they are"} unknown, not "nobody by this name".`);
  if (nc.people.length) add("info", `Next: ${NEXT_STEP[0].toLowerCase()}${NEXT_STEP.slice(1)} Nothing is followed until you click.`);
  else if (nc.handles.length) add("info", "Next: try one of the handles built from the name, or open a search. Nothing has been checked for them, and nothing is followed until you click.");
  return rows;
}

// ---- AI and exports --------------------------------------------------------------------
// What the model is told about a name case: text only, the rows as the screen shows them. Null
// when no directory answered, so the request is the same as before name search existed.
export function nameForAi(collected, target = "") {
  const nc = nameCase(collected, target);
  if (!nc.result) return null;
  return {
    name: nc.name.slice(0, 200), qualifiers: nc.qualifiers,
    notable: nc.notable ? { name: nc.notable.name, description: nc.notable.description } : null,
    candidates: nc.people.map((r) => ({ source: r.source, name: r.name, handle: r.handle, description: r.description, location: r.location, affiliation: r.affiliation, name_match: r.name_match, qualifier_hits: r.qualifier_hits })),
  };
}
// The opening of a name case in the Markdown export: the caveat, the search state, what is known.
export function nameMarkdownHead(collected, target = "") {
  const k = nameKnown(collected, target);
  return [`> ${NAME_NOTICE}`, "", ...nameNotices(collected, target).slice(1).flatMap((n) => [`**${n.title}** ${n.text}`, ""]), "## What we know", `- ${k.lead}`, ...k.lines.map((l) => `- ${l}`), ""];
}
