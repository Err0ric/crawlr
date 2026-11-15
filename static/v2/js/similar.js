// Similar handles: handles close to the one being investigated, each checked on a click.
// Pure: no DOM, no network. A saved case and a case file go through the same readers.
//
// What a case holds in `collected.similar`:
//   { <variant, lowercase>: { variant, checked_at, probe: { profiles[], sources{} } | error: { error, error_code }, added: [profile id] } }
// It is outside data once saved or exported: readSimilar() checks every handle against the
// server's pattern, rebuilds every URL from the site and the handle, clips text, passes a
// thumbnail through safeThumb and keeps a state only when it is a known one.
//
// "added" is the investigator's decision, and it is never trusted on its own: a profile takes
// part in the case only while lineUp() still says it lines up, evaluated again from the profiles
// the case holds. A crafted file cannot add a profile the rules would not offer.

import { clusterIdentities, standing, meaningfulName, usableAvatar, linkParts } from "./identity.js";
import { parseName, handlePatterns, PATTERN_WORD } from "./names.js";
import { parseUrl } from "./links.js";
import { safeThumb, THUMB_MAX_COUNT } from "./present.js";

export const SIMILAR_GROUP = "Similar handles";
export const SIMILAR_BLURB = "Handles close to this one. Nothing has been checked. Check one to see whether its name or picture lines up with this case. One click checks one handle, and nothing is requested before a click.";
export const SIMILAR_SOURCE = "Similar handle check";
export const MAX_VARIANTS = 16, MAX_STORED = 24, NAME_RESERVED = 6;

const HANDLE_OK = /^[A-Za-z0-9._-]{2,64}$/;
const valid = (v) => HANDLE_OK.test(v) && !v.startsWith("-");
const lc = (s) => String(s ?? "").trim().toLowerCase();
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const line = (v, n) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, n) : "");
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// The handle similar handles are built from: the searched username, or the part of an email
// before the @ (without a +tag). Never anything from the email's domain.
export function similarBase(target, type) {
  const t = String(target ?? "").trim();
  const hd = type === "email" ? t.split("@")[0].replace(/\+.*$/, "") : type === "username" ? t.replace(/^@/, "") : "";
  return /^[A-Za-z0-9._-]{1,64}$/.test(hd) && !hd.startsWith("-") ? hd : "";
}

// ---- variants ----------------------------------------------------------------------------
// Each rule gives a value, a reason in plain words and a rank: lower is more plausible.
const LEET = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t" };
const TO_DIGIT = [["o", "0"], ["e", "3"], ["a", "4"], ["i", "1"], ["s", "5"], ["l", "1"], ["t", "7"]];
const SEP_WORD = { _: "underscore", ".": "dot", "-": "hyphen" };
const SEP_A = { _: "an underscore", ".": "a dot", "-": "a hyphen" };

// Variants of one handle, most plausible first. Lowercase, valid for the server's username
// pattern, without duplicates and never the handle itself. [{ value, reason, close }]
export function handleVariants(handle) {
  const orig = String(handle ?? "").trim().replace(/^@/, "");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(orig) || orig.startsWith("-")) return [];
  const s = orig.toLowerCase();
  const found = [];
  const add = (value, reason, rank) => { if (valid(value) && value !== s) found.push({ value, reason, rank, i: found.length }); };
  const alpha = /^[a-z]+$/.test(s), noDigits = !/\d/.test(s);

  // Digits that stand for letters: a run of them inside a word (after a letter, or one digit at
  // the start of a word) and followed by a letter. Digits at the end are a number, not letters.
  const runs = [...s.matchAll(/(?<=^|[a-z._-])[013457]+(?=[a-z])/g)].filter((m) => m[0].length === 1 || /[a-z]/.test(s[m.index - 1] || ""));
  if (runs.length) {
    const spots = runs.flatMap((m) => [...m[0]].map((d, k) => ({ at: m.index + k, d })));
    // A 1 stands for an i or an l. Both are offered, the i first.
    const put = (list, one = "i") => { const a = [...s]; for (const x of list) a[x.at] = x.d === "1" ? one : LEET[x.d]; return a.join(""); };
    const pairs = (one) => [...new Set(spots.map((x) => `${x.d} as ${x.d === "1" ? one : LEET[x.d]}`))];
    const why = (one) => (spots.length === 1 ? `the ${spots[0].d} read as the letter ${spots[0].d === "1" ? one : LEET[spots[0].d]}` : `digits read as letters (${pairs(one).join(", ")})`);
    add(put(spots), why("i"), 10);
    if (spots.some((x) => x.d === "1")) add(put(spots, "l"), why("l"), 11);
    if (spots.length > 1) for (const x of spots.slice(0, 2)) add(put([x]), `the ${x.d} read as the letter ${x.d === "1" ? "i" : LEET[x.d]}`, 30);
  }

  // Decorations taken off: x at each end, and a few words people put around a handle.
  const xs = s.match(/^(x+)([._-]?)(.{3,}?)\2\1$/);
  if (xs && (xs[2] || xs[1].length > 1)) add(xs[3], "without the x at each end", 12);
  const front = s.match(/^(the[._-]?real|real|official)[._-]?(.{4,})$/) || s.match(/^(the|its|im|i[._-]?am)[._-](.{3,})$/)
    || (/^(The|Its|Im|IAm)[A-Z]/.test(orig) ? s.match(/^(the|its|im|iam)(.{3,})$/) : null);
  if (front) add(front[2], `without "${front[1].replace(/[._-]/g, " ").replace(/^thereal$/, "the real")}" in front`, 12);
  const back = s.match(/^(.{3,}?)[._-]?(official)$/);
  if (back) add(back[1], `without "${back[2]}" at the end`, 12);
  const both = front && front[2].match(/^(.{3,}?)[._-]?(official)$/);
  if (both) add(both[1], "without the words around it", 13);

  // A number at either end.
  const tail = s.match(/^(.*[a-z])[._-]?(\d+)$/);
  if (tail) add(tail[1], /^(19|20)\d\d$/.test(tail[2]) ? "without the year at the end" : tail[2].length === 1 ? "without the digit at the end" : "without the digits at the end", 14);
  const lead = s.match(/^(\d+)[._-]?([a-z].*)$/);
  if (lead && !runs.some((m) => m.index === 0)) add(lead[2], lead[1].length === 1 ? "without the digit at the start" : "without the digits at the start", 14);

  // Separators: at the ends, taken out, swapped, or put in at a word boundary.
  const trimmed = s.replace(/^[._-]+|[._-]+$/g, "");
  if (trimmed !== s) add(trimmed, "without the separator at the start or the end", 16);
  const kinds = [...new Set(trimmed.match(/[._-]/g) || [])];
  if (kinds.length) {
    add(s.replace(/[._-]+/g, ""), kinds.length === 1 && (trimmed.match(/[._-]/g) || []).length === 1 ? `without the ${SEP_WORD[kinds[0]]}` : "without the separators", 20);
    for (const to of ["_", ".", "-"]) if (!(kinds.length === 1 && kinds[0] === to)) add(trimmed.replace(/[._-]+/g, to), kinds.length === 1 ? `with ${SEP_A[to]} in place of the ${SEP_WORD[kinds[0]]}` : `with ${SEP_A[to]} as the only separator`, to === "-" ? 23 : 22);
    if (tail) add(tail[1].replace(/[._-]+/g, ""), "without the digits and the separators", 26);
  } else {
    // A change of case in the handle as typed, or where trailing digits begin.
    const words = orig.replace(/([a-z])([A-Z])/g, "$1 $2").split(" ");
    if (words.length > 1 && words.length <= 4 && words.every((w) => w.length >= 2)) for (const to of ["_", "."]) add(words.join(to).toLowerCase(), `with ${SEP_A[to]} between the words`, 24);
    else if (tail && tail[1].length >= 2 && !/\d/.test(tail[1])) add(`${tail[1]}_${tail[2]}`, "with an underscore before the digits", 25);
  }

  // An underscore added at either end.
  if (!s.endsWith("_")) add(`${s}_`, "with an underscore at the end", 34);
  if (!s.startsWith("_")) add(`_${s}`, "with an underscore at the start", 36);

  // Doubled letters written once. A letter is only added where the handle already repeats one at its end.
  const once = s.replace(/([a-z])\1+/g, "$1");
  if (once !== s) add(once, (s.match(/([a-z])\1+/g) || []).length === 1 ? `the doubled ${s.match(/([a-z])\1+/)[1]} written once` : "the doubled letters written once", 40);
  const rep = s.match(/([a-z])\1+$/);
  if (rep) add(s + rep[1], `the repeated ${rep[1]} once more`, 42);

  // Letters written as digits, for a handle that has no digits of its own.
  if (noDigits && (s.match(/[a-z]/g) || []).length >= 4) {
    const at = (ch) => s.indexOf(ch, 1);
    const can = TO_DIGIT.filter(([ch]) => at(ch) > 0);
    for (const [ch, d] of can.slice(0, 2)) add(s.slice(0, at(ch)) + d + s.slice(at(ch) + 1), `the letter ${ch} written as ${d}`, 50);
    const many = can.filter(([ch]) => "oeais".includes(ch));
    if (many.length > 1) add(s[0] + s.slice(1).replace(/[oeais]/g, (ch) => TO_DIGIT.find(([c]) => c === ch)[1]), `letters written as digits (${many.map(([ch, d]) => `${ch} as ${d}`).join(", ")})`, 55);
  }

  // A few common decorations put on, for a plain word only.
  if (alpha && s.length >= 3) { add(`real${s}`, 'with "real" in front', 60); add(`the${s}`, 'with "the" in front', 61); add(`${s}official`, 'with "official" at the end', 62); }

  const seen = new Set(), out = [];
  // close: the handle with something taken off or read differently, which is likelier than one with something put on.
  for (const v of found.sort((a, b) => a.rank - b.rank || a.i - b.i)) if (!seen.has(v.value)) { seen.add(v.value); out.push({ value: v.value, reason: v.reason, close: v.rank < 30 }); }
  return out.slice(0, MAX_VARIANTS);
}

// Handles built from a person's name, with the patterns a name case uses. A single word is not
// enough to build from. [{ value, reason }]
export function nameVariants(name, handle = "") {
  const parsed = parseName(line(name, 80));
  if (parsed.single_token) return [];
  return handlePatterns(parsed).filter((x) => valid(x.value) && x.value !== lc(handle)).map((x) => ({ value: x.value, reason: `built from the name on the primary profile (${PATTERN_WORD[x.pattern]})`, fromName: true }));
}

// The variants a case offers, most plausible first: the handle with something taken off or read
// differently, then handles built from the primary identity's name when it has one, then the
// handle with something put on. Never anything from an email's domain. At most MAX_VARIANTS, a
// few places kept for the name.
export function similarHandles(handle, { name = "" } = {}) {
  const h = lc(String(handle ?? "").replace(/^@/, ""));
  const all = handleVariants(handle);
  const seen = new Set([h, ...all.map((x) => x.value)]);
  const named = (name ? nameVariants(name, h) : []).filter((x) => !seen.has(x.value) && seen.add(x.value)).slice(0, NAME_RESERVED);
  const own = all.slice(0, MAX_VARIANTS - named.length).map(({ close, ...x }) => ({ ...x, late: !close }));
  return [...own.filter((x) => !x.late), ...named, ...own.filter((x) => x.late)].map(({ late, ...x }) => x);
}
// The group's first line. It says "nothing has been checked" only while that is true.
export const similarBlurb = (items) => { const n = (items || []).filter((i) => i.tier === "similar" && i.sim?.state === "checked").length; return n ? `Handles close to this one. ${plural(n, "handle")} checked so far, each on a click. Check another to see whether its name or picture lines up with this case. Nothing is requested before a click.` : SIMILAR_BLURB; };

// ---- the stored checks ---------------------------------------------------------------------
// The sites a probe may name, and the profile address for a handle on each. An address is always
// built here, never taken from the answer or from a file.
export const PROBE_SITES = {
  GitHub:    { id: "github",    label: "GitHub",      url: (h) => `https://github.com/${h}` },
  Facebook:  { id: "facebook",  label: "Facebook",    url: (h) => `https://www.facebook.com/${h}` },
  Instagram: { id: "instagram", label: "Instagram",   url: (h) => `https://www.instagram.com/${h}/` },
  X:         { id: "x",         label: "X (Twitter)", url: (h) => `https://x.com/${h}` },
  Threads:   { id: "threads",   label: "Threads",     url: (h) => `https://www.threads.com/@${h}` },
  TikTok:    { id: "tiktok",    label: "TikTok",      url: (h) => `https://www.tiktok.com/@${h}` },
  Reddit:    { id: "reddit",    label: "Reddit",      url: (h) => `https://www.reddit.com/user/${h}` },
  Discord:   { id: "discord",   label: "Discord",     url: () => "" },
  Bluesky:   { id: "bluesky",   label: "Bluesky",     url: (h) => `https://bsky.app/profile/${h.toLowerCase()}.bsky.social` },
};
export const PROBE_STATES = ["found", "taken", "not_found", "blocked", "unknown", "rate_limited", "failed", "not_asked"];
export const STATE_WORD = { found: "Profile read", taken: "Handle taken, owner unknown", not_found: "Not found", blocked: "Blocked by site", unknown: "Could not tell", rate_limited: "Rate limited", failed: "Failed", not_asked: "Not asked" };
const HEX16 = /^[0-9a-f]{16}$/i;
export const profileId = (variant, site) => `acct:${PROBE_SITES[site]?.id || ""}~${lc(variant)}`;

// One probe answer, read defensively: { profiles, sources } or null.
export function readProbe(raw, variant) {
  if (!isObj(raw) || !valid(String(variant ?? ""))) return null;
  const sources = {};
  if (isObj(raw.sources)) for (const site of Object.keys(PROBE_SITES)) if (PROBE_STATES.includes(raw.sources[site])) sources[site] = raw.sources[site];
  const profiles = [], seen = new Set();
  for (const p of Array.isArray(raw.profiles) ? raw.profiles.slice(0, 20) : []) {
    // Only a profile that was read is a profile. Discord's "taken" is a state and nothing more.
    if (!isObj(p) || !Object.hasOwn(PROBE_SITES, p.site) || p.site === "Discord" || p.state !== "found" || seen.has(p.site)) continue;
    seen.add(p.site);
    const hash = typeof p.avatar_hash === "string" && HEX16.test(p.avatar_hash) ? p.avatar_hash.toLowerCase() : "";
    const dflt = hash ? p.avatar_default === true : false;
    profiles.push({
      site: p.site, url: PROBE_SITES[p.site].url(variant), state: "found", name: line(p.name, 100), bio: line(p.bio, 300), location: line(p.location, 100), created: line(p.created, 40),
      followers: Number.isFinite(p.followers) && p.followers >= 0 ? Math.floor(p.followers) : null, note: p.note === "suspended" ? "suspended" : "",
      links: (Array.isArray(p.links) ? p.links : []).filter((u) => typeof u === "string" && u.length <= 300 && ((x) => x && !x.username && !x.password)(parseUrl(u))).slice(0, 6),
      avatar_hash: hash, avatar_default: dflt, thumb: hash && !dflt ? safeThumb(p.thumb) : "",
    });
    sources[p.site] = "found";
  }
  // A source that says "found" with no profile behind it did not show anything.
  for (const [site, st] of Object.entries(sources)) if (st === "found" && !seen.has(site)) sources[site] = "unknown";
  return { profiles, sources };
}

// The whole map, as a case may carry it. `handle` is the case's own handle: a "variant" equal to
// it is dropped. Thumbnails are bounded across the map.
export function readSimilar(raw, handle = "") {
  const out = {};
  if (!isObj(raw)) return out;
  const own = lc(String(handle ?? "").replace(/^@/, ""));
  let thumbs = 0;
  for (const [k, v] of Object.entries(raw).slice(0, 200)) {
    if (Object.keys(out).length >= MAX_STORED) break;
    if (!isObj(v) || typeof v.variant !== "string" || !valid(v.variant) || lc(v.variant) !== k || k === own) continue;
    const entry = { variant: v.variant.toLowerCase(), checked_at: Number.isFinite(v.checked_at) && v.checked_at > 0 ? v.checked_at : 0, added: [] };
    const probe = readProbe(v.probe, entry.variant);
    if (probe) {
      for (const p of probe.profiles) if (p.thumb && ++thumbs > THUMB_MAX_COUNT) p.thumb = "";
      entry.probe = probe;
      const ids = new Set(probe.profiles.map((p) => profileId(entry.variant, p.site)));
      entry.added = [...new Set((Array.isArray(v.added) ? v.added : []).filter((id) => typeof id === "string" && ids.has(id)))];
    } else if (isObj(v.error)) entry.error = { error: line(v.error.error, 200) || "The check failed.", error_code: line(v.error.error_code, 40) };
    else continue;
    out[k] = entry;
  }
  return out;
}

// A probed profile in the shape identity.js compares. Its only links are the ones the source
// returned; a link to a site of its own (not a multi-user service) is its website.
export function asProfile(variant, p) {
  const site = PROBE_SITES[p.site];
  const websites = p.links.filter((u) => { const l = linkParts(u); return l && !l.platform; });
  return {
    id: profileId(variant, p.site), site: site.label, url: p.url, handle: variant, name: p.name, location: p.location, bio: p.bio, image: "",
    links: p.links.filter((u) => !websites.includes(u)), websites, anchor: "", sources: [SIMILAR_SOURCE], facts: [], leads: [], evidence: p.note === "suspended" ? "the site marks this account as suspended" : "",
    created: p.created, repos: null, followers: p.followers, thumb: p.thumb, avatarHash: p.avatar_hash, avatarDefault: p.avatar_default, similar: { variant },
  };
}

// ---- does it line up? ----------------------------------------------------------------------
// Compares one probed profile with the case's primary identity, using the rules that group the
// case's own profiles (clusterIdentities and standing in identity.js): the profile is placed
// among the case's profiles and the rules say where it lands. Nothing here decides on its own.
//   outcome  "picture"   the same picture as a profile of the primary identity (strong)
//            "link"      a link ties them by the cross-link or shared-link rule (strong)
//            "name"      the name is the same, or fits, with nothing conflicting (supporting, not proof)
//            "conflict"  the name conflicts: a different person
//            "nothing"   nothing to compare, and `why` says which side has nothing
//   canAdd   true only for picture, link and name
// baseProfiles: the case's own read profiles (never ones added from a similar handle).
export const LINEUP_PILL = {
  picture: { word: "Same picture", tone: "linked" }, link: { word: "Links back", tone: "linked" }, name: { word: "Same name", tone: "match" },
  conflict: { word: "Name conflicts", tone: "different" }, nothing: { word: "Nothing to compare", tone: "" },
};
const STRONG = new Set(["cross-link", "avatar", "shared-link"]);
const cap = (s) => String(s).charAt(0).toUpperCase() + String(s).slice(1);
export function lineUp(pp, baseProfiles, { handle = "" } = {}) {
  const base = (baseProfiles || []).filter((p) => p && p.id !== pp?.id && !p.similar);
  const nothing = (why, text) => ({ outcome: "nothing", strength: "", why, text, reason: "", canAdd: false });
  if (!pp || !pp.id) return nothing("unreadable", "Read, but nothing to compare.");
  const before = clusterIdentities(base, { handle });
  const primary = before.clusters.find((c) => c.primary);
  if (!primary) return nothing("no_primary", "Read, but nothing to compare: this case has no primary identity.");
  const after = clusterIdentities([...base, pp], { handle });
  const prim = after.clusters.find((c) => c.primary);
  const siteOf = (id) => base.find((p) => p.id === id)?.site || "another";
  const named = meaningfulName(pp.name, [pp.handle, handle]);
  const members = base.filter((p) => primary.members.includes(p.id));
  // The primary identity must still be the one it was: a probed profile never picks another.
  // Only a signal between the profile and one of the case's own primary profiles counts.
  if (prim && (primary.anchorId ? prim.anchorId === primary.anchorId : prim.members.some((id) => primary.members.includes(id)))) {
    const s = standing(pp, after, { handle });
    const mine = prim.links.filter((l) => l.a === pp.id || l.b === pp.id).map((l) => ({ other: l.a === pp.id ? l.b : l.a, signals: l.signals })).filter((l) => primary.members.includes(l.other));
    if (s.tier === "linked") {
      const pic = mine.find((l) => l.signals.some((g) => g.type === "avatar"));
      if (pic) return { outcome: "picture", strength: "strong", why: "", text: `Same picture as the ${siteOf(pic.other)} profile`, reason: `same picture as the ${siteOf(pic.other)} profile`, canAdd: true };
      const lk = mine.flatMap((l) => l.signals).find((g) => STRONG.has(g.type));
      if (lk) return { outcome: "link", strength: "strong", why: "", text: cap(lk.detail), reason: lk.detail, canAdd: true };
    }
    if (s.tier === "matches" && after.byProfile[pp.id] === prim.id && named) {
      const nm = mine.map((l) => ({ other: l.other, g: l.signals.find((x) => x.type === "name" || x.type === "weak-name") })).find((x) => x.g);
      if (nm) {
        const same = nm.g.type === "name";
        return { outcome: "name", strength: "supporting", why: "", text: same ? `Name on profile: ${pp.name}, the same as on ${siteOf(nm.other)}` : `Name on profile: ${pp.name}, which fits the name on ${siteOf(nm.other)}`, reason: same ? `same name as on ${siteOf(nm.other)}` : `name fits the one on ${siteOf(nm.other)}`, canAdd: true };
      }
    }
    if (s.tier === "different") return { outcome: "conflict", strength: "", why: "", text: `Name on profile: ${pp.name}, which conflicts with ${primary.label}`, reason: "", canAdd: false };
  }
  const picture = usableAvatar(pp);
  if (!named && !picture) return nothing("profile_empty", "Read, but nothing to compare: this profile carries no name and no picture.");
  if (!primary.tokens.length && !members.some(usableAvatar)) return nothing("primary_empty", "Read, but nothing to compare: the primary identity carries no name and no picture.");
  if (named && !primary.tokens.length) return nothing("no_tie", `Name on profile: ${pp.name}. The primary identity carries no name to compare it with, and no picture or link ties it to this case.`);
  return nothing("no_tie", named ? `Name on profile: ${pp.name}. It neither matches nor conflicts with ${primary.label}, and no picture or link ties it to this case.` : "Read, but nothing ties it to this case: it carries no name, and its picture is not one the case has.");
}

// Every checked variant against the case: per profile, its line-up and whether it is added.
// A profile counts as added only when it was added AND still lines up.
//   { <variant>: { variant, checked_at, error?, sources, profiles: [{ ...p, id, profile, lineup, added }] } }
// handle: the searched handle as the identity rules use it ("" for an email case).
// own: the handle the variants were built from, which is never a variant of itself.
export function evaluateSimilar(similar, baseProfiles, { handle = "", own = handle } = {}) {
  const out = {};
  for (const [k, e] of Object.entries(readSimilar(similar, own))) {
    const profiles = (e.probe?.profiles || []).map((p) => {
      const profile = asProfile(e.variant, p);
      const lineup = lineUp(profile, baseProfiles, { handle });
      return { ...p, id: profile.id, profile, lineup, added: lineup.canAdd && e.added.includes(profile.id) };
    });
    out[k] = { variant: e.variant, checked_at: e.checked_at, ...(e.error ? { error: e.error } : {}), sources: e.probe?.sources || {}, profiles };
  }
  return out;
}
// The profiles that take part in the case: added by the investigator and still lining up.
export const addedProfiles = (evaluated) => Object.values(evaluated || {}).flatMap((e) => e.profiles.filter((p) => p.added).map((p) => ({ ...p.profile, similar: { variant: e.variant, reason: p.lineup.reason, outcome: p.lineup.outcome } })));

// ---- words ---------------------------------------------------------------------------------
// What one checked variant amounts to: "added" | "lines_up" | "someone_else" | "no_compare" | "none" | "failed".
export function variantOutcome(e) {
  if (!e) return "";
  if (e.error) return "failed";
  if (e.profiles.some((p) => p.added)) return "added";
  if (e.profiles.some((p) => p.lineup.canAdd)) return "lines_up";
  if (e.profiles.some((p) => p.lineup.outcome === "conflict")) return "someone_else";
  return e.profiles.length ? "no_compare" : "none";
}
const DOWN = ["blocked", "unknown", "rate_limited", "failed"];
// One sentence on a checked variant, and its sources grouped by state (everything but "found").
export function variantSummary(e) {
  if (e.error) return `Could not be checked: ${e.error.error}`;
  const n = e.profiles.length, down = Object.values(e.sources).filter((s) => DOWN.includes(s)).length;
  if (!n) return down ? `No profile was read. ${plural(down, "site")} could not be checked, so ${down === 1 ? "that one is" : "those are"} unknown, not absent.` : "No profile under this handle on the sites checked.";
  const c = (f) => e.profiles.filter(f).length;
  const added = c((p) => p.added), up = c((p) => p.lineup.canAdd && !p.added), other = c((p) => p.lineup.outcome === "conflict"), rest = n - added - up - other;
  return `${plural(n, "profile")} read: ${[added && `${added} added to this case`, up && `${up} ${up === 1 ? "lines" : "line"} up with this case`, other && `${other} ${other === 1 ? "belongs" : "belong"} to someone else`, rest && `${rest} could not be compared`].filter(Boolean).join(", ")}.`;
}
export function sourceStates(e) {
  const by = {};
  for (const site of Object.keys(PROBE_SITES)) { const st = e.sources?.[site]; if (st && st !== "found") (by[st] ||= []).push(PROBE_SITES[site].label); }
  return PROBE_STATES.filter((st) => by[st]).map((st) => ({ state: st, word: STATE_WORD[st], sites: by[st] }));
}
// What the live region says.
export function probeStatus(variant, phase, e) {
  if (phase === "loading") return `Checking the handle ${variant}.`;
  if (phase === "added") return `Added to this case from the handle ${variant}.`;
  if (phase === "removed") return `Removed from this case. The handle ${variant} stays under Similar handles.`;
  return e ? `Checked the handle ${variant}. ${variantSummary(e)}` : `The handle ${variant} could not be checked.`;
}
// One line for the brief, only once something was checked.
export function similarBrief(evaluated) {
  const all = Object.values(evaluated || {}).filter((e) => !e.error);
  if (!all.length) return "";
  const n = (o) => all.filter((e) => variantOutcome(e) === o).length;
  const parts = [n("added") && `${n("added")} added`, n("lines_up") && `${n("lines_up")} ${n("lines_up") === 1 ? "lines" : "line"} up and ${n("lines_up") === 1 ? "is" : "are"} not added`, n("someone_else") && `${n("someone_else")} ${n("someone_else") === 1 ? "belongs" : "belong"} to someone else`,
    n("no_compare") && `${n("no_compare")} could not be compared`, n("none") && `${n("none")} had no profile that could be read`].filter(Boolean);
  return `${plural(all.length, "similar handle")} checked: ${parts.join(", ")}.`;
}

// ---- ledger rows ---------------------------------------------------------------------------
// One row per variant: the generated ones in order, then any checked earlier that are no longer
// generated. An unchecked row has "Check"; every row has "Investigate this" (a separate case).
// facts: what a probed profile's card shows (built by the caller with cardSnippet).
export function similarItems({ handle, name = "", evaluated = {}, snippet = () => ({ facts: [], bio: "" }) }) {
  const h = String(handle ?? "").replace(/^@/, "");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(h) || h.startsWith("-")) return [];
  const rows = similarHandles(h, { name });
  const listed = new Set(rows.map((r) => r.value));
  for (const e of Object.values(evaluated)) if (!listed.has(e.variant)) rows.push({ value: e.variant, reason: "checked earlier in this case" });
  return rows.map((r) => {
    const e = evaluated[r.value] || null;
    const state = !e ? "new" : e.error ? "failed" : "checked";
    return {
      tier: "similar", what: r.value, url: "", link_kind: "none", key: `similar:${r.value}`, source: r.fromName ? "built from the name" : "built from the handle",
      meta: [r.reason, e ? variantSummary(e) : "not checked"].join(" · "),
      action: { label: "Investigate this", pivot: "investigate", value: r.value, type: "username" },
      sim: {
        variant: r.value, reason: r.reason, state, summary: e ? variantSummary(e) : "", sources: e && !e.error ? sourceStates(e) : [],
        profiles: (e?.profiles || []).map((p) => ({ id: p.id, site: PROBE_SITES[p.site].label, url: p.url, thumb: p.thumb, note: p.note, ...snippet(p), lineup: p.lineup, pill: LINEUP_PILL[p.lineup.outcome], added: p.added })),
      },
    };
  });
}
