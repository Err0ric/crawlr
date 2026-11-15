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

import { clusterIdentities, standing, meaningfulName, compareNames, nameTokens, personalName, usableAvatar, linkParts } from "./identity.js";
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
  // An email case only for a whole address: "info@" is not one.
  const hd = type === "email" ? (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t) ? t.split("@")[0].replace(/\+.*$/, "") : "") : type === "username" ? t.replace(/^@/, "") : "";
  return /^[A-Za-z0-9._-]{1,64}$/.test(hd) && !hd.startsWith("-") ? hd : "";
}

// ---- variants ----------------------------------------------------------------------------
// Each rule gives a value, a reason in plain words and a rank: lower is more plausible.
const LEET = { 0: "o", 1: "l", 3: "e", 4: "a", 5: "s", 7: "t" };
const TO_DIGIT = [["o", "0"], ["e", "3"], ["a", "4"], ["i", "1"], ["s", "5"], ["l", "1"], ["t", "7"]];
// Ordinary words that begin with a decoration. Nothing is taken off a handle that starts with one.
const DECOR_STOP = ["realestate", "realtor", "reality", "realm", "really", "realis", "theory", "theatre", "theater", "thermal", "therapy", "therapist", "these", "there", "they", "itself", "image", "imagine", "important", "official"].filter((w, i, a) => a.indexOf(w) === i);
const TITLES = new Set(["dr", "mr", "mrs", "ms", "miss", "prof", "sir"]);
const SEP_WORD = { _: "underscore", ".": "dot", "-": "hyphen" };
const SEP_A = { _: "an underscore", ".": "a dot", "-": "a hyphen" };

// Variants of one handle, most plausible first. Lowercase, valid for the server's username
// pattern, without duplicates and never the handle itself. [{ value, reason, close }]
export function handleVariants(handle) {
  const orig = String(handle ?? "").trim().replace(/^@/, "");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(orig) || orig.startsWith("-")) return [];
  const s = orig.toLowerCase();
  const found = [];
  // Never a variant that begins or ends with two separators.
  const add = (value, reason, rank) => { if (valid(value) && value !== s && !/^[._-]{2}|[._-]{2}$/.test(value)) found.push({ value, reason, rank, i: found.length }); };
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
  // A word is taken off only at a real boundary (a separator, or a change of case in the handle as
  // typed), only when at least 3 characters are left, and never from a handle that is an ordinary
  // word beginning with it ("realtor", "therapist").
  const flat = s.replace(/[._-]/g, "");
  const wordy = !flat.startsWith("thereal") && DECOR_STOP.some((w) => flat.startsWith(w));
  const cased = (orig.match(/^(TheReal|The|Real|Its|Im|IAm|Official)(?=[A-Z0-9])/) || [])[1];
  const front = wordy ? null : s.match(/^(the[._-]?real|the|real|its|im|i[._-]?am|official)[._-]+(.{3,})$/) || (cased ? [null, cased.toLowerCase(), s.slice(cased.length)] : null);
  const frontWord = front ? front[1].replace(/[._-]/g, " ").replace(/^thereal$/, "the real").replace(/^iam$/, "i am") : "";
  if (front && front[2].length >= 3) add(front[2], `without "${frontWord}" in front`, 12);
  const back = s.match(/^(.{3,}?)[._-]+(official)$/) || (/[a-z0-9]Official$/.test(orig) && s.length >= 11 ? [null, s.slice(0, -8), "official"] : null);
  if (back) add(back[1], `without "${back[2]}" at the end`, 12);
  const both = front && front[2].match(/^(.{3,}?)[._-]+(official)$/);
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
  if (alpha && s.length >= 3 && !/^(the|real|its|official)|official$/.test(s)) { add(`real${s}`, 'with "real" in front', 60); add(`the${s}`, 'with "the" in front', 61); add(`${s}official`, 'with "official" at the end', 62); }

  const seen = new Set(), out = [];
  // close: the handle with something taken off or read differently, which is likelier than one with something put on.
  for (const v of found.sort((a, b) => a.rank - b.rank || a.i - b.i)) if (!seen.has(v.value)) { seen.add(v.value); out.push({ value: v.value, reason: v.reason, close: v.rank < 30 }); }
  return out.slice(0, MAX_VARIANTS);
}

// Handles built from a person's name, with the patterns a name case uses. A single word is not
// enough to build from. [{ value, reason }]
// Only a name that looks like a person's: two or three words once a title (Dr, Prof) is dropped,
// with no digit and no word that describes an organisation or a role ("Linux Kernel Dev").
export function nameVariants(name, handle = "") {
  const words = line(name, 80).split(" ").filter((w) => w && !TITLES.has(w.toLowerCase().replace(/\./g, "")));
  if (words.length < 2 || words.length > 3 || !personalName(nameTokens(words.join(" ")))) return [];
  const parsed = parseName(words.join(" "));
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
const AVATAR_STATES = ["ok", "none", "default", "failed"];

// One probe answer, read defensively: { profiles, sources } or null.
// avatar_state per profile: "ok" (a real picture was hashed), "default" (a placeholder), "none"
// (the profile has no picture) or "failed" (there is one, and it could not be fetched or read).
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
      avatar_state: hash ? (dflt ? "default" : "ok") : p.avatar_state === "failed" ? "failed" : "none",
    });
    sources[p.site] = "found";
  }
  // A source that says "found" with no profile behind it did not show anything.
  for (const [site, st] of Object.entries(sources)) if (st === "found" && !seen.has(site)) sources[site] = "unknown";
  return { profiles, sources };
}

// The whole map, as a case may carry it. `handle` is the case's own handle: a "variant" equal to
// it is dropped. Thumbnails are bounded across the map.
// from_file: the answer came with a case file and was not checked in this browser (see fromFile).
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
    // Nothing from a file is ever "added": that is a decision taken in this browser.
    if (v.from_file === true) { entry.from_file = true; entry.added = []; }
    out[k] = entry;
  }
  return out;
}
// The similar handles of a case that was opened from a case file. Whoever made the file chose
// what is in it, so: only a handle this case would offer itself is kept (`allowed`, from
// similarHandles for the case's own handle and primary name), every "added" mark is dropped (the
// investigator can check the handle here and add it again), a failed check is dropped, and what
// is left is marked as coming from the file until it is checked in this browser.
export function fromFile(raw, handle, allowed) {
  const ok = new Set([].concat(allowed || []).map(lc));
  const out = {};
  for (const [k, e] of Object.entries(readSimilar(raw, handle))) if (ok.has(k) && e.probe) out[k] = { ...e, added: [], from_file: true };
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
    created: p.created, repos: null, followers: p.followers, thumb: p.thumb, avatarHash: p.avatar_hash, avatarDefault: p.avatar_default, avatarState: p.avatar_state, similar: { variant },
  };
}

// ---- does it line up? ----------------------------------------------------------------------
// Compares one probed profile with the case's primary identity. Whether a picture matches, a link
// ties two profiles or a name fits is decided by the rules that group the case's own profiles
// (clusterIdentities and standing in identity.js): the profile is placed among them and the
// rules say where it lands. What follows from that is decided here, and it is deliberately
// stricter for a name, because a name is shared by many people:
//   outcome            Add    tier     meaning
//   "picture"          yes    linked   the same picture as a profile of the primary identity
//   "picture_conflict" yes    linked   the same picture, but the name on it conflicts. Said in
//                                      those words on the card and on the row: one person can use
//                                      two names, and two people can use one picture.
//   "link"             yes    linked   a link ties them by the cross-link or shared-link rule
//   "name"             yes    matches  both carry a full name (two words or more) made of the same
//                                      words, and the handle was not built from that name
//   "name_weak"        no              the name fits but is one word, or is only part of the other
//   "name_built"       no              the name is the same, but the handle was built from that
//                                      very name, so finding the name under it proves nothing
//   "conflict"         no              the name conflicts: a different person
//   "nothing"          no              nothing to compare; `why` says which side has nothing
// baseProfiles: the case's own read profiles (never ones added from a similar handle).
// opts.fromName: the variant was built from the primary identity's name.
export const LINEUP_PILL = {
  picture: { word: "Same picture", tone: "linked" }, picture_conflict: { word: "Same picture, name differs", tone: "linked" }, link: { word: "Links back", tone: "linked" },
  name: { word: "Same full name", tone: "match" }, name_weak: { word: "Same name, not enough to add", tone: "" }, name_built: { word: "Same name, proves nothing", tone: "" },
  conflict: { word: "Name conflicts", tone: "different" }, nothing: { word: "Nothing to compare", tone: "" },
};
export const LINEUP_TIER = { picture: "linked", picture_conflict: "linked", link: "linked", name: "matches" };
export const NAME_CAVEAT = "A name alone is supporting, not proof.";
const BUILT = "this handle was built from the name on the primary profile";
const STRONG = new Set(["cross-link", "avatar", "shared-link"]);
const cap = (s) => String(s).charAt(0).toUpperCase() + String(s).slice(1);
const sameWords = (a, b) => a.length >= 2 && b.length >= 2 && a.length === b.length && a.every((t) => b.includes(t));
export function lineUp(pp, baseProfiles, { handle = "", fromName = false } = {}) {
  const base = (baseProfiles || []).filter((p) => p && p.id !== pp?.id && !p.similar);
  const res = (outcome, text, extra = {}) => ({ outcome, strength: LINEUP_TIER[outcome] === "linked" ? "strong" : outcome === "name" ? "supporting" : "", why: "", text, reason: "", canAdd: !!LINEUP_TIER[outcome], tier: LINEUP_TIER[outcome] || "", ...extra });
  const nothing = (why, text) => res("nothing", text, { why });
  if (!pp || !pp.id) return nothing("unreadable", "Read, but nothing to compare.");
  const before = clusterIdentities(base, { handle });
  const primary = before.clusters.find((c) => c.primary);
  if (!primary) return nothing("no_primary", "Read, but nothing to compare: this case has no primary identity.");
  const after = clusterIdentities([...base, pp], { handle });
  const prim = after.clusters.find((c) => c.primary);
  const byId = (id) => base.find((p) => p.id === id);
  const siteOf = (id) => byId(id)?.site || "another";
  const named = meaningfulName(pp.name, [pp.handle, handle]);
  const members = base.filter((p) => primary.members.includes(p.id));
  const keys = [...(before.handles || []), pp.handle, handle];
  // The name on the profile against every name the primary identity carries.
  const differs = !!named && primary.tokens.length > 0 && primary.tokens.every((t) => compareNames(t, named, keys) === "conflict");
  const but = differs ? `, but the name on it differs (${pp.name}, against ${primary.label})` : "";
  const built = fromName ? `; ${BUILT}` : "";
  // The primary identity must still be the one it was: a probed profile never picks another.
  // Only a signal between the profile and one of the case's own primary profiles counts.
  if (prim && (primary.anchorId ? prim.anchorId === primary.anchorId : prim.members.some((id) => primary.members.includes(id)))) {
    const s = standing(pp, after, { handle });
    const mine = prim.links.filter((l) => l.a === pp.id || l.b === pp.id).map((l) => ({ other: l.a === pp.id ? l.b : l.a, signals: l.signals })).filter((l) => primary.members.includes(l.other));
    if (s.tier === "linked") {
      const pic = mine.find((l) => l.signals.some((g) => g.type === "avatar"));
      if (pic) return res(differs ? "picture_conflict" : "picture", differs ? `Same picture${but}` : `Same picture as the ${siteOf(pic.other)} profile`, { reason: `same picture as the ${siteOf(pic.other)} profile${but}${built}` });
      const lk = mine.flatMap((l) => l.signals).find((g) => STRONG.has(g.type));
      if (lk) return res("link", `${cap(lk.detail)}${but}`, { reason: `${lk.detail}${but}${built}` });
    }
    if (s.tier === "matches" && after.byProfile[pp.id] === prim.id && named) {
      const nm = mine.map((l) => ({ other: l.other, g: l.signals.find((x) => x.type === "name" || x.type === "weak-name") })).find((x) => x.g);
      if (nm) {
        // A full name on both sides, made of the same words. Anything less is not enough to add.
        const full = members.find((m) => sameWords(meaningfulName(m.name, [m.handle, handle]) || [], named));
        if (full && fromName) return res("name_built", `Name on profile: ${pp.name}, the same as on ${full.site}. But ${BUILT}, so the match proves nothing`, { why: "built" });
        if (full) return res("name", `Name on profile: ${pp.name}, the same full name as on ${full.site}`, { reason: `same full name. ${NAME_CAVEAT.replace(/\.$/, "")}` });
        return res("name_weak", `Name on profile: ${pp.name}, which fits the name on ${siteOf(nm.other)}. That is not enough to add it: ${named.length < 2 ? "a single word is shared by many people" : "the two names are not the same full name"}${fromName ? `, and ${BUILT}` : ""}`, { why: named.length < 2 ? "single_word" : "not_equal" });
      }
    }
    if (s.tier === "different") return res("conflict", `Name on profile: ${pp.name}, which conflicts with ${primary.label}`);
  }
  const picture = usableAvatar(pp), lost = pp.avatarState === "failed";
  if (!named && !picture) return nothing(lost ? "picture_failed" : "profile_empty", lost ? "Read, but nothing to compare: this profile carries no name, and the picture could not be compared." : "Read, but nothing to compare: this profile carries no name and no picture.");
  if (!primary.tokens.length && !members.some(usableAvatar)) return nothing("primary_empty", "Read, but nothing to compare: the primary identity carries no name and no picture.");
  const tail = lost ? "The picture could not be compared, and no link ties it to this case." : "No picture or link ties it to this case.";
  if (named && !primary.tokens.length) return nothing("no_tie", `Name on profile: ${pp.name}. The primary identity carries no name to compare it with. ${tail}`);
  return nothing("no_tie", named ? `Name on profile: ${pp.name}. It neither matches nor conflicts with ${primary.label}. ${tail}` : "Read, but nothing ties it to this case: it carries no name, and its picture is not one the case has.");
}

// Every checked variant against the case: per profile, its line-up and whether it is added.
// A profile counts as added only when it was added AND still lines up, and never when the answer
// came with a case file and was not checked here.
//   { <variant>: { variant, checked_at, error?, fromFile, fromName, sources, profiles: [{ ...p, id, profile, lineup, added }] } }
// handle: the searched handle as the identity rules use it ("" for an email case).
// own: the handle the variants were built from, which is never a variant of itself.
// name: the primary identity's name, when it has one: a variant built from it is marked.
export function evaluateSimilar(similar, baseProfiles, { handle = "", own = handle, name = "" } = {}) {
  const out = {};
  const built = new Set(name ? nameVariants(name, own).map((x) => x.value) : []);
  for (const [k, e] of Object.entries(readSimilar(similar, own))) {
    const fromName = built.has(k), file = e.from_file === true;
    const profiles = (e.probe?.profiles || []).map((p) => {
      const profile = asProfile(e.variant, p);
      const lineup = lineUp(profile, baseProfiles, { handle, fromName });
      // What a file says was read is not something this browser saw: nothing is added on it.
      if (file) lineup.canAdd = false;
      return { ...p, id: profile.id, profile, lineup, added: lineup.canAdd && e.added.includes(profile.id) };
    });
    out[k] = { variant: e.variant, checked_at: e.checked_at, ...(e.error ? { error: e.error } : {}), fromFile: file, fromName, sources: e.probe?.sources || {}, profiles };
  }
  return out;
}
// The profiles the investigator added and that still line up. Each is a row of the case and
// nothing more: it is never a member of an identity (see buildEvidence).
export const addedProfiles = (evaluated) => Object.values(evaluated || {}).flatMap((e) => e.profiles.filter((p) => p.added).map((p) => ({ ...p.profile, similar: { variant: e.variant, reason: p.lineup.reason, outcome: p.lineup.outcome, tier: p.lineup.tier } })));

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
export const FROM_FILE = "From the case file, not checked here.";
// One sentence on a checked variant, and its sources grouped by state (everything but "found").
export function variantSummary(e) {
  if (e.error) return `Could not be checked: ${e.error.error}`;
  const n = e.profiles.length, down = Object.values(e.sources).filter((s) => DOWN.includes(s)).length;
  if (e.fromFile) return `${FROM_FILE} The file lists ${plural(n, "profile")} for this handle. Check it here before relying on it.`;
  if (!n) return down ? `No profile was read. ${plural(down, "site")} could not be checked, so ${down === 1 ? "that one is" : "those are"} unknown, not absent.` : "No profile under this handle on the sites checked.";
  const c = (f) => e.profiles.filter(f).length;
  const weak = (p) => p.lineup.outcome === "name_weak" || p.lineup.outcome === "name_built";
  const added = c((p) => p.added), up = c((p) => p.lineup.canAdd && !p.added), other = c((p) => p.lineup.outcome === "conflict"), names = c(weak), rest = n - added - up - other - names;
  return `${plural(n, "profile")} read: ${[added && `${added} added to this case`, up && `${up} ${up === 1 ? "lines" : "line"} up with this case`, other && `${other} ${other === 1 ? "belongs" : "belong"} to someone else`, names && `${names} ${names === 1 ? "shares" : "share"} a name, which is not enough to add`, rest && `${rest} could not be compared`].filter(Boolean).join(", ")}.`;
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
// One line for the brief, only once something was checked in this browser.
export function similarBrief(evaluated) {
  const all = Object.values(evaluated || {}).filter((e) => !e.error && !e.fromFile);
  if (!all.length) return "";
  const n = (o) => all.filter((e) => variantOutcome(e) === o).length;
  const parts = [n("added") && `${n("added")} added`, n("lines_up") && `${n("lines_up")} ${n("lines_up") === 1 ? "lines" : "line"} up and ${n("lines_up") === 1 ? "is" : "are"} not added`, n("someone_else") && `${n("someone_else")} ${n("someone_else") === 1 ? "belongs" : "belong"} to someone else`,
    n("no_compare") && `${n("no_compare")} could not be compared`, n("none") && `${n("none")} had no profile that could be read`].filter(Boolean);
  return `${plural(all.length, "similar handle")} checked: ${parts.join(", ")}.`;
}

// ---- ledger rows ---------------------------------------------------------------------------
// One row per variant: the generated ones in order, then any checked earlier that are no longer
// generated. A row that was not checked here has "Check"; every row has "Investigate this" (a
// separate case). state: "new" | "checked" | "failed" | "file" (an answer from a case file).
// snippet: what a probed profile's card shows (built by the caller with cardSnippet).
export function similarItems({ handle, name = "", evaluated = {}, snippet = () => ({ facts: [], bio: "" }) }) {
  const h = String(handle ?? "").replace(/^@/, "");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(h) || h.startsWith("-")) return [];
  const rows = similarHandles(h, { name });
  const listed = new Set(rows.map((r) => r.value));
  for (const e of Object.values(evaluated)) if (!listed.has(e.variant)) rows.push({ value: e.variant, reason: "checked earlier in this case" });
  return rows.map((r) => {
    const e = evaluated[r.value] || null;
    const state = !e ? "new" : e.error ? "failed" : e.fromFile ? "file" : "checked";
    return {
      tier: "similar", what: r.value, url: "", link_kind: "none", key: `similar:${r.value}`, source: r.fromName ? "built from the name" : "built from the handle",
      meta: [r.reason, e ? variantSummary(e) : "not checked"].join(" · "),
      action: { label: "Investigate this", pivot: "investigate", value: r.value, type: "username" },
      sim: {
        variant: r.value, reason: r.reason, state, summary: e ? variantSummary(e) : "", sources: e && !e.error ? sourceStates(e) : [],
        // A profile a file lists was not read here: its link is a template nothing checked, and it carries no line-up.
        profiles: (e?.profiles || []).map((p) => ({ id: p.id, site: PROBE_SITES[p.site].label, url: p.url, link_kind: e.fromFile ? "templated_unverified" : "verified_profile", thumb: e.fromFile ? "" : p.thumb, note: p.note, ...snippet(p),
          lineup: e.fromFile ? { ...p.lineup, outcome: "file", text: "Listed in the case file. Nothing was read here", canAdd: false } : p.lineup, pill: e.fromFile ? { word: "From the file", tone: "unverified", dashed: true } : LINEUP_PILL[p.lineup.outcome], added: p.added })),
      },
    };
  });
}
