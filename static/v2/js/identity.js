// Identity clusters: which of the profiles found under one handle belong to the same person.
// Pure functions, no DOM and no network, so the rules can be tested exactly.
//
// A profile: { id, site, url, handle, name, location, avatarHash, avatarDefault, links[], websites[], proven[], bio, anchor? }
//   anchor: "github" for GitHub's API record of the searched handle, "gravatar" for the Gravatar
//   record of the searched email. An anchor is the authoritative record for the target itself.
//   websites: the links that came from a personal-site field (GitHub blog, a profile's website).
//
// Rules, in the order they are applied:
//   1. Strong signals join two profiles whatever their names say:
//        cross-link    each links to the other, or the linking profile is the anchor (or already
//                      tied to the anchor by a strong signal). The link must be the other's exact
//                      URL, or have the other's handle as the first path segment on that site.
//                      A link the other side has confirmed joins by itself: a Keybase proof, or
//                      a link Mastodon marks as verified (`proven` on the profile). An account a
//                      profile only lists is an ordinary link and follows the rule above.
//        same avatar   both have a real picture (not a default, not a near-blank hash) and the
//                      64-bit dHashes differ by at most 6 bits
//        shared link   both link to the same page (host and path; on a multi-user site, the same
//                      profile page). A bare site with no path counts only when it is not a
//                      multi-user service and both carry it as their website.
//      Anything weaker is a supporting signal: it is shown, and never joins. A profile that merely
//      links to the anchor is one ("not confirmed from the other side").
//   2. A name that only repeats the handle ("torvalds", "ToRvaLDs", "Torvalds Torvalds") says
//      nothing about who owns the account. Such a profile has no name.
//   3. Names are compared with case, accents and punctuation folded, as sets of words, and also
//      with the spaces removed ("LinusTorvalds"). Equal names join.
//   4. A name contained in a longer one ("Eric" in "Eric Henderson") joins only when exactly one
//      cluster fits, so it can never tip a choice between two people. This is decided for every
//      such name at once, so the order of the input does not matter.
//   5. Two names conflict only when both look like a person's multi-word name in the same script
//      and share no word (an initial counts as sharing; the handle itself does not). A phrase
//      ("Linux kernel dev"), another script or a shared word is not a conflict. Clusters never
//      join by name across a conflict.
//   6. A matching location is recorded as support. It never joins or splits anything by itself.
//   7. A profile with no name and no strong signal stays unassigned. An anchor always gets a cluster.
//   8. The primary cluster is the one holding the GitHub anchor, else the Gravatar anchor, else the
//      one with the most members joined by a strong signal. With no anchor and no strong signal
//      there is no primary: nothing ties any profile to the target, and nobody is picked.
//   9. The investigator may pick the person the case is about (opts.pick: the member ids of the
//      cluster they chose). The pick changes which cluster is primary and nothing else: clusters
//      are evidence and are built the same way with or without it. A pick is matched by members,
//      so it survives a re-run; it holds only while exactly one cluster carries its members, and
//      otherwise the automatic choice of rule 8 stands. A pick that names the automatic choice is
//      no pick at all: the result is the automatic one and is never worded as a judgment. The
//      result says which of the two it is (`picked`) and what the automatic choice is (`auto`,
//      `autoWhy`), so the page can say so. opts.pickFile: the pick came with a case file, so it is
//      its author's and is never worded as "you picked".
//  10. A profile outside the primary cluster is compared with the fullest names the primary
//      carries. A one-word name beside a full one ("Sam" beside "Sam Example") is ignored for
//      this: it fits almost anything, so it must not rescue a profile whose full name conflicts
//      with the identity's full name. When the primary carries one-word names only, a profile
//      with an unrelated full name is neither a match nor a conflict: it stays in "matches" and
//      is marked `unsettled`, and the row says the name could not be compared.
//      A one-word name of the primary that does fit the profile's name ("Petra" on a profile tied
//      to the identity, beside "Petra Novak") is the one case where it counts against the full
//      name: the two disagree, so the profile is `unsettled` (with `mixed`), never `different`.

const fold = (s) => String(s ?? "").normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase();

// Words of a name: letters and digits only, everything else is a separator.
export const nameTokens = (name) => fold(name).replace(/[^\p{L}\p{N}]+/gu, " ").trim().split(/\s+/).filter(Boolean);
const handleKey = (h) => fold(h).replace(/^@/, "").replace(/[^\p{L}\p{N}]+/gu, "");
const handleKeys = (handles) => new Set([].concat(handles ?? []).map(handleKey).filter(Boolean));

// Tokens of a name that carries identity information, or null when it does not.
export function meaningfulName(name, handles = []) {
  const tokens = [...new Set(nameTokens(name))];
  if (!tokens.length || tokens.join("").length < 2) return null;
  const keys = handleKeys(handles);
  // "J Doe" for the handle jdoe is still a name: only a word-for-word echo of the handle is dropped.
  if (tokens.every((t) => keys.has(t))) return null;
  return tokens;
}

// Words that describe an account instead of naming a person.
const DESCRIPTIVE = new Set(("official real the a an of and for by at in on fan fans club team group inc llc ltd gmbh co corp company studio studios labs lab media music gaming games tv radio news blog page channel account bot dev developer developers engineer kernel linux code coder hacker security research photography photo art design shop store support help info admin user member guest anonymous unknown test demo project org foundation community").split(" "));
const LATIN = /^[a-z0-9]+$/;
const script = (tokens) => (tokens.every((t) => LATIN.test(t)) ? "latin" : "other");
export const personalName = (tokens) => personal(tokens);
const personal = (tokens) => tokens.length >= 2 && tokens.every((t) => !/\d/.test(t) && !DESCRIPTIVE.has(t)) && tokens.some((t) => t.length > 1);
// One word matches another when they are equal, or one is an initial of the other.
const tokenMatch = (x, y) => x === y || (x.length === 1 && y.startsWith(x)) || (y.length === 1 && x.startsWith(y));
const subset = (a, b) => a.every((t) => b.includes(t));

// "same" | "subset" | "conflict" | "neutral" for two token lists from meaningfulName().
//   same      equal sets of words, or equal with the spaces removed
//   subset    every word of one is in the other (the shorter may be a single word)
//   conflict  two personal multi-word names in one script that share no word
//   neutral   neither: no reason to join, and no reason to call them different people
// handles: words that are only the searched handle, which cannot count as a shared word.
export function compareNames(a, b, handles = []) {
  if ((subset(a, b) && subset(b, a)) || a.join("") === b.join("")) return "same";
  if (a.length === 1 && b.length > 1 && [b.join(""), b.slice().reverse().join("")].includes(a[0])) return "same";
  if (b.length === 1 && a.length > 1 && [a.join(""), a.slice().reverse().join("")].includes(b[0])) return "same";
  if (subset(a, b) || subset(b, a)) return "subset";
  const keys = handleKeys(handles);
  const ax = a.filter((t) => !keys.has(t)), bx = b.filter((t) => !keys.has(t));
  if (personal(a) && personal(b) && script(a) === script(b) && !ax.some((x) => bx.some((y) => tokenMatch(x, y)))) return "conflict";
  return "neutral";
}

// ---- links ---------------------------------------------------------------------------
const HOST_ALIAS = { "twitter.com": "x.com", "mobile.twitter.com": "x.com", "threads.net": "threads.com", "youtu.be": "youtube.com", "m.youtube.com": "youtube.com", "m.facebook.com": "facebook.com", "fb.com": "facebook.com", "telegram.me": "t.me", "en.gravatar.com": "gravatar.com" };
// Sites where many unrelated people have a page: a shared link to the site itself links nobody.
export const PLATFORM_HOSTS = new Set(("x.com github.com gist.github.com gitlab.com bitbucket.org instagram.com facebook.com youtube.com reddit.com tiktok.com twitch.tv steamcommunity.com linkedin.com bsky.app threads.com discord.com discord.gg medium.com substack.com pinterest.com snapchat.com t.me keybase.io soundcloud.com spotify.com patreon.com ko-fi.com buymeacoffee.com paypal.com paypal.me cash.app venmo.com linktr.ee about.me gravatar.com wordpress.com blogspot.com tumblr.com mastodon.social mastodon.online mastodon.world fosstodon.org hachyderm.io infosec.exchange mas.to mstdn.social codeberg.org gitea.com launchpad.net stackoverflow.com dev.to hashnode.com huggingface.co kaggle.com npmjs.com pypi.org hub.docker.com hackerone.com bugcrowd.com tryhackme.com hackthebox.com itch.io deviantart.com behance.net dribbble.com flickr.com vimeo.com dailymotion.com vk.com ok.ru weibo.com telegram.org whatsapp.com wa.me google.com docs.google.com drive.google.com sites.google.com bit.ly t.co goo.gl tinyurl.com apple.com microsoft.com amazon.com wikipedia.org en.wikipedia.org archive.org web.archive.org orcid.org researchgate.net academia.edu trello.com leetcode.com codepen.io replit.com producthunt.com angel.co crunchbase.com xing.com goodreads.com last.fm letterboxd.com imgur.com giphy.com quora.com ycombinator.com news.ycombinator.com lobste.rs matrix.to signal.me kernel.org").split(" "));
// Reference and utility sites: a page there is something anyone links, never a personal page.
const REFERENCE = new Set("kernel.org wikipedia.org en.wikipedia.org archive.org web.archive.org google.com docs.google.com drive.google.com apple.com microsoft.com amazon.com bit.ly t.co goo.gl tinyurl.com ycombinator.com news.ycombinator.com pypi.org npmjs.com hub.docker.com".split(" "));
// Hosts that look like a shared service even when they are not on the list above.
const MULTI_USER = /(^|\.)(social|forum|forums|community|blog|blogs|wiki|git|code|chat|members?|users?|people|mastodon|pixelfed|lemmy|misskey|pleroma)\b|(mastodon|fosstodon|pixelfed|lemmy|misskey|\.social$|\.community$|\.chat$)/i;

// { host, path, key } for an http(s) link, or null. Bare "example.org/x" is accepted.
export function linkParts(u) {
  let s = String(u ?? "").trim();
  if (!s || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = `https://${s}`;
  let url;
  try { url = new URL(s); } catch { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  let host = url.hostname.toLowerCase().replace(/^www\./, "");
  if (!host.includes(".")) return null;
  host = HOST_ALIAS[host] || host;
  let path = url.pathname;
  try { path = decodeURIComponent(path); } catch { /* keep the raw path */ }
  path = path.replace(/\/+$/, "").toLowerCase();
  // Hacker News has one path for every user and names the user in the query (see ownProfileQuery
  // in links.js), so the name is part of what the link points at.
  if (host === "news.ycombinator.com" && path === "/user" && /^[A-Za-z0-9_-]{2,15}$/.test(url.searchParams.get("id") || "")) path = `/user?id=${url.searchParams.get("id").toLowerCase()}`;
  return { host, path, key: host + path, platform: PLATFORM_HOSTS.has(host) || MULTI_USER.test(host) };
}
export const isPlatformHost = (host) => { const h = String(host || "").toLowerCase().replace(/^www\./, ""); return PLATFORM_HOSTS.has(HOST_ALIAS[h] || h) || MULTI_USER.test(h); };

// URLs written in free text (a bio that is a link, for example).
export const urlsIn = (text) => (String(text ?? "").match(/\bhttps?:\/\/[^\s<>"')\]]+/gi) || []).map((u) => u.replace(/[.,;:!?]+$/, ""));

// Does profile a link to profile b? Returns the link that does, or "".
// The link is b's exact URL, or has b's handle as the FIRST path segment on b's site:
// github.com/mallory/torvalds is mallory's repository, not a link to torvalds.
function crossLink(a, b, links = a._links) {
  const target = linkParts(b.url);
  if (!target) return "";
  const hk = fold(b.handle).replace(/^@/, "");
  for (const l of links) {
    if (l.key === target.key && l.path) return l.raw;
    if (hk && l.host === target.host && (l.path.split("/")[1] || "").replace(/^[@~]/, "") === hk && l.path.split("/").length === 2) return l.raw;
  }
  return "";
}
// A link from a to b that the other side has confirmed, so it does not need the anchor to vouch
// for it. A profile carries these as `proven: [{ url, proof }]` (see collectProfiles):
//   keybase        the owner of the other account published a signed statement there, and
//                  Keybase checked it
//   verified_link  Mastodon found a rel="me" link back on the page it links to
// An account a profile merely lists is not one of these: it is an ordinary link, and a lead.
export const PROOF_DETAIL = {
  keybase: (a, b) => `a Keybase proof ties the ${b} account to the ${a} profile`,
  verified_link: (a, b) => `${a} shows a verified link to the ${b} profile, which links back`,
};
function provenLink(a, b) {
  for (const proof of Object.keys(PROOF_DETAIL)) if (crossLink(a, b, a._proven.filter((l) => l.proof === proof))) return proof;
  return "";
}
// A link both profiles carry. { strong, detail } or null.
//   strong: the same page (host and path), or a bare personal site both list as their website.
//   weak:   the same bare site otherwise. Shown as support, never joins.
function sharedLink(a, b) {
  let weak = null;
  for (const l of a._links) for (const m of b._links) {
    if (l.key !== m.key) continue;
    // The same page. On a multi-user site only a profile page counts (one path segment): two
    // people linking the same repository or article are not thereby one person.
    if (l.path && !REFERENCE.has(l.host) && (!l.platform || l.path.split("/").length === 2)) return { strong: true, detail: `both link to ${l.key}` };
    if (l.path) { weak = weak || { strong: false, detail: `both link to ${l.key}, a page anyone might link` }; continue; }
    if (!l.platform && l.site && m.site) return { strong: true, detail: `both give ${l.host} as their website` };
    if (!l.platform) weak = { strong: false, detail: `both mention ${l.host}, which is not enough to tie them` };
  }
  return weak;
}

// ---- avatars -------------------------------------------------------------------------
const HEX16 = /^[0-9a-f]{16}$/i;
const BITS = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];
export function hamming(a, b) {
  if (!HEX16.test(String(a)) || !HEX16.test(String(b))) return null;
  let n = 0;
  for (let i = 0; i < 16; i++) n += BITS[parseInt(a[i], 16) ^ parseInt(b[i], 16)];
  return n;
}
export const popcount = (hex) => (HEX16.test(String(hex)) ? [...String(hex)].reduce((n, c) => n + BITS[parseInt(c, 16)], 0) : null);
export const AVATAR_MAX_DISTANCE = 6;
// A hash that is nearly all zeros or all ones is a flat image: a logo, a blank, a solid colour.
// It carries too little to compare, so it is treated like a default picture and never links.
export const lowInformation = (hex) => { const n = popcount(hex); return n === null || n < 8 || n > 56; };
export const usableAvatar = (p) => !p.avatarDefault && !!p.avatarHash && !lowInformation(p.avatarHash);
const sameAvatar = (a, b) => { if (!usableAvatar(a) || !usableAvatar(b)) return false; const d = hamming(a.avatarHash, b.avatarHash); return d !== null && d <= AVATAR_MAX_DISTANCE; };

const foldLoc = (s) => fold(s).replace(/[^\p{L}\p{N}]+/gu, " ").trim();

// ---- clustering ----------------------------------------------------------------------
const STRONG = new Set(["cross-link", "avatar", "shared-link"]);
const ANCHOR_RANK = { github: 0, gravatar: 1 };

export function clusterIdentities(profiles, opts = {}) {
  const searched = [].concat(opts.handle || []).filter(Boolean);
  // Sorted by id, so the result never depends on the order the sources answered in.
  const ps = (profiles || []).filter((p) => p && p.id).slice().sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)).map((p, i) => {
    const sites = new Set((p.websites || []).map((w) => linkParts(w)?.key).filter(Boolean));
    const links = [...(p.links || []), ...(p.websites || []), ...urlsIn(p.bio)].map((raw0) => { const l = linkParts(raw0); return l ? { ...l, raw: String(raw0), site: sites.has(l.key) } : null; }).filter(Boolean);
    const self = linkParts(p.url);
    const proven = (Array.isArray(p.proven) ? p.proven : []).map((x) => { const l = x && Object.hasOwn(PROOF_DETAIL, x.proof) ? linkParts(x.url) : null; return l ? { ...l, raw: String(x.url), proof: x.proof } : null; }).filter((l) => l && (!self || l.key !== self.key));
    return { ...p, _i: i, _tokens: meaningfulName(p.name, [p.handle, ...searched]), _links: links.filter((l) => !self || l.key !== self.key), _proven: proven };
  });
  const keys = [...searched, ...ps.map((p) => p.handle)];
  const rel2 = (a, b) => compareNames(a, b, keys);
  const parent = ps.map((_, i) => i);
  const find = (i) => { while (parent[i] !== i) { parent[i] = parent[parent[i]]; i = parent[i]; } return i; };
  const union = (a, b) => { const ra = find(a), rb = find(b); if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb); };
  const pairs = new Map();   // "i|j" -> [{ type, detail }]
  const pk = (i, j) => (i < j ? `${i}|${j}` : `${j}|${i}`);
  const note = (i, j, type, detail) => { const k = pk(i, j); if (!pairs.has(k)) pairs.set(k, []); if (!pairs.get(k).some((s) => s.type === type)) pairs.get(k).push({ type, detail }); };
  const strongPair = (i, j) => (pairs.get(pk(i, j)) || []).some((s) => STRONG.has(s.type));

  // 1. strong signals. One-way links wait until it is known who is tied to the anchor.
  const oneWay = [];   // [from, to]
  for (let i = 0; i < ps.length; i++) for (let j = i + 1; j < ps.length; j++) {
    const a = ps[i], b = ps[j];
    // A proof or a verified link is confirmed from the other side already: it joins by itself.
    const pf = provenLink(a, b), pb = pf ? "" : provenLink(b, a);
    if (pf) note(i, j, "cross-link", PROOF_DETAIL[pf](a.site, b.site));
    else if (pb) note(i, j, "cross-link", PROOF_DETAIL[pb](b.site, a.site));
    const fwd = crossLink(a, b), back = crossLink(b, a);
    if (fwd && back) note(i, j, "cross-link", `${a.site} and ${b.site} link to each other`);
    else if (fwd) oneWay.push([i, j]);
    else if (back) oneWay.push([j, i]);
    if (sameAvatar(a, b)) note(i, j, "avatar", "same avatar image");
    const sh = sharedLink(a, b);
    if (sh) note(i, j, sh.strong ? "shared-link" : "shared-site", sh.detail);
    if (strongPair(i, j)) union(i, j);
  }
  // A link from the anchor, or from a profile already tied to it, is the target vouching for the
  // other account. A link from anywhere else is only that profile's claim.
  const anchors = ps.map((p, i) => (p.anchor in ANCHOR_RANK ? i : -1)).filter((i) => i >= 0);
  for (let changed = true; changed;) {
    changed = false;
    for (const [from, to] of oneWay) {
      if (strongPair(from, to) || !anchors.some((a) => find(a) === find(from))) continue;
      note(from, to, "cross-link", `${ps[from].site} links to ${ps[to].site}`); union(from, to); changed = true;
    }
  }
  for (const [from, to] of oneWay) if (!strongPair(from, to)) note(from, to, "one-way-link", `${ps[from].site} links to the ${ps[to].site} profile, not confirmed from the other side`);

  // 3 to 5. names. Clusters are compared as wholes, so one conflicting member blocks the join.
  const members = () => { const m = new Map(); ps.forEach((p, i) => { const r = find(i); if (!m.has(r)) m.set(r, []); m.get(r).push(i); }); return [...m.values()]; };
  const namesOf = (idx) => idx.map((i) => ps[i]._tokens).filter(Boolean);
  const relation = (A, B) => {
    let best = "";
    for (const a of namesOf(A)) for (const b of namesOf(B)) {
      const r = rel2(a, b);
      if (r === "conflict") return "conflict";
      if (r === "same" || (r === "subset" && best !== "same")) best = r;
    }
    return best;
  };
  const joinByName = (A, B, type) => {
    for (const i of A) for (const j of B) {
      const a = ps[i]._tokens, b = ps[j]._tokens; if (!a || !b) continue;
      const r = rel2(a, b); if (r !== "same" && r !== "subset") continue;
      note(i, j, type, r === "same" ? `same name, "${ps[i].name}"` : `"${a.length < b.length ? ps[i].name : ps[j].name}" is part of "${a.length < b.length ? ps[j].name : ps[i].name}"`);
      const la = foldLoc(ps[i].location), lb = foldLoc(ps[j].location);
      if (la && la === lb) note(i, j, "location", `same location, ${ps[i].location}`);
    }
    union(A[0], B[0]);
  };
  // Equal names first. Every pair is decided on the clusters as they stood before this pass.
  { const groups = members(); for (let x = 0; x < groups.length; x++) for (let y = x + 1; y < groups.length; y++) if (relation(groups[x], groups[y]) === "same") joinByName(groups[x], groups[y], "name"); }
  // Then a name contained in a longer one: it joins only when exactly one cluster fits. All
  // decisions are taken before any is applied, so no join can depend on the order of another.
  {
    const groups = members(), todo = [];
    const shorter = (X, Y) => namesOf(X).some((a) => namesOf(Y).some((b) => rel2(a, b) === "subset" && a.length < b.length));
    for (let x = 0; x < groups.length; x++) {
      const fits = groups.map((g, y) => (y !== x && relation(groups[x], g) === "subset" && shorter(groups[x], g) ? y : -1)).filter((y) => y >= 0);
      if (fits.length === 1) todo.push([groups[x], groups[fits[0]]]);
    }
    for (const [X, Y] of todo) joinByName(X, Y, "weak-name");
  }

  // 7. build clusters
  const clusters = [], unassigned = [];
  for (const idx of members()) {
    // The anchor leads its cluster, so the cluster is named and listed after the record it rests on.
    const mem = idx.map((i) => ps[i]).sort((a, b) => (a.anchor in ANCHOR_RANK ? 0 : 1) - (b.anchor in ANCHOR_RANK ? 0 : 1) || a._i - b._i);
    const named = mem.some((p) => p._tokens), anchored = mem.some((p) => p.anchor in ANCHOR_RANK);
    if (!named && !anchored && idx.length === 1) { unassigned.push(mem[0].id); continue; }
    const links = [];
    for (const [k, signals] of pairs) { const [i, j] = k.split("|").map(Number); if (idx.includes(i) && idx.includes(j)) links.push({ a: ps[i].id, b: ps[j].id, signals }); }
    const strongIds = new Set(links.filter((l) => l.signals.some((s) => STRONG.has(s.type))).flatMap((l) => [l.a, l.b]));
    // Label: the fullest name on any member, else the handle.
    const names = [...new Map(mem.filter((p) => p._tokens).map((p) => [p._tokens.slice().sort().join(" "), String(p.name).trim()])).values()];
    const best = mem.filter((p) => p._tokens).sort((a, b) => b._tokens.length - a._tokens.length || String(b.name).length - String(a.name).length || (a.anchor in ANCHOR_RANK ? 0 : 1) - (b.anchor in ANCHOR_RANK ? 0 : 1) || a._i - b._i)[0];
    const anchor = mem.filter((p) => p.anchor in ANCHOR_RANK).sort((a, b) => ANCHOR_RANK[a.anchor] - ANCHOR_RANK[b.anchor])[0];
    clusters.push({
      id: `c:${mem[0].id}`, label: best ? String(best.name).trim() : String(anchor?.handle || mem[0].handle || mem[0].site || ""), named,
      names, tokens: mem.map((p) => p._tokens).filter(Boolean), locations: [...new Set(mem.map((p) => String(p.location || "").trim()).filter(Boolean))],
      members: mem.map((p) => p.id), links, strong: strongIds.size, strongIds: [...strongIds], anchor: anchor ? anchor.anchor : "", anchorId: anchor ? anchor.id : "", first: Math.min(...mem.map((p) => p._i)), primary: false,
    });
  }

  // 8. primary: an anchor, else the cluster with the most strongly tied members. Never a guess.
  const rank = (c) => [c.anchor in ANCHOR_RANK ? ANCHOR_RANK[c.anchor] : 9, -c.strong, -c.members.length, c.first];
  const cmp = (a, b) => { const ra = rank(a), rb = rank(b); for (let i = 0; i < ra.length; i++) if (ra[i] !== rb[i]) return ra[i] - rb[i]; return 0; };
  clusters.sort(cmp);
  const top = clusters[0];
  const tie = top && !top.anchor && clusters[1] && !clusters[1].anchor && clusters[1].strong === top.strong;
  const auto = top && (top.anchor || (top.strong > 0 && !tie)) ? top : null;
  if (auto) auto.why = auto.anchor === "github" ? "it holds GitHub's own record for this handle" : auto.anchor === "gravatar" ? "it holds the Gravatar record for this email" : "it is the only group of profiles tied together by a strong signal";
  const autoWhy = auto ? auto.why : "";
  // 9. the investigator's pick, matched by members. Zero or several clusters: the pick is void.
  const want = new Set([].concat(opts.pick || []).filter((x) => typeof x === "string"));
  const hit = want.size ? clusters.filter((c) => c.members.some((id) => want.has(id))) : [];
  const picked = hit.length === 1 && hit[0] !== auto;
  const primary = picked ? hit[0] : auto;
  if (primary) { primary.primary = true; if (picked) { primary.picked = true; if (opts.pickFile === true) primary.pickFile = true; primary.why = opts.pickFile === true ? PICK_WHY_FILE : PICK_WHY; } }
  const byProfile = {};
  for (const c of clusters) for (const id of c.members) byProfile[id] = c.id;
  for (const c of clusters) delete c.first;
  // Signals between profiles that did not end up together: support, shown but never joining.
  const supports = [];
  for (const [k, signals] of pairs) { const [i, j] = k.split("|").map(Number); if (find(i) !== find(j)) supports.push({ a: ps[i].id, b: ps[j].id, signals }); }
  return { clusters, primary: primary ? primary.id : null, auto: auto ? auto.id : null, autoWhy, picked, unassigned, byProfile, supports, handles: keys };
}

export const PICK_WHY = "you picked this person";
export const PICK_WHY_FILE = "the case file picked this person";
// The member ids a stored pick names: at most 40 account ids, or null. Outside data is read here.
export function readPick(v) {
  const m = v && typeof v === "object" && !Array.isArray(v) && Array.isArray(v.members) ? [...new Set(v.members.filter((x) => typeof x === "string" && /^acct:[^\u0000-\u001f]{1,80}$/.test(x)))].slice(0, 40) : [];
  if (!m.length) return null;
  return { members: m, at: Number.isFinite(v.at) && v.at > 0 ? v.at : 0, ...(v.file === true ? { file: true } : {}) };
}

// How one profile stands to the primary cluster: "linked" | "matches" | "different".
//   linked     it is the anchor, or a strong signal ties it to the primary cluster
//   matches    its name fits the primary identity, or it has no name that conflicts
//   different  its name conflicts with every name the primary identity carries
// With no primary cluster nothing is tied to the target, so every profile is "matches" and
// nobody is called a different person.
// via, tie: the profile is called different because it is grouped with another person (via: that
// person's name; tie: the signals that group them), not because of a name of its own.
// unsettled: the profile carries a full name and the primary identity only one-word names that
// share nothing with it (rule 10). against: the names the profile was compared with.
// mixed (with unsettled): the name fits a one-word name of the identity (`fits`) and conflicts
// with its full name (`against`), so neither settles it.
export const NO_PRIMARY = "exists, nothing ties it to the target";
export function standing(profile, result, opts = {}) {
  const primary = result.clusters.find((c) => c.primary);
  if (!primary) return { tier: "matches", why: NO_PRIMARY };
  const keys = [...(result.handles || []), ...[].concat(opts.handle || [])];
  const support = (result.supports || []).filter((l) => (l.a === profile.id && primary.members.includes(l.b)) || (l.b === profile.id && primary.members.includes(l.a))).flatMap((l) => l.signals.map((s) => s.detail));
  const inPrimary = result.byProfile[profile.id] === primary.id;
  if (inPrimary) {
    if (profile.id === primary.anchorId) return { tier: "linked", why: "" };
    const link = primary.links.find((l) => (l.a === profile.id || l.b === profile.id) && l.signals.some((s) => STRONG.has(s.type)));
    if (link) return { tier: "linked", why: link.signals.filter((s) => STRONG.has(s.type)).map((s) => s.detail).join(", ") };
    const byName = primary.links.find((l) => l.a === profile.id || l.b === profile.id);
    return { tier: "matches", why: byName ? byName.signals.map((s) => s.detail).join(", ") : primary.picked ? (primary.pickFile ? (primary.members.length > 1 ? "part of the identity picked in the case file" : "the profile picked in the case file; nothing else ties it to the target") : primary.members.length > 1 ? "part of the identity you picked" : "the profile you picked; nothing else ties it to the target") : "" };
  }
  const tokens = meaningfulName(profile.name, [profile.handle, ...keys]);
  const extra = support.length ? support.join(", ") : "";
  // 10. the fullest names decide. One-word names count only when the identity has nothing fuller.
  const full = primary.tokens.filter(personal);
  const against = (full.length ? primary.names.filter((n) => personal(meaningfulName(n, keys) || [])) : primary.names).slice(0, 3);
  const conflicts = (t) => full.length > 0 && full.every((f) => compareNames(f, t, keys) === "conflict");
  // Does a name of the primary fit this one? Equal, contained, an initial, or a shared stem.
  const fitsName = (p, t) => ["same", "subset"].includes(compareNames(p, t, keys)) || p.some((x) => t.some((y) => tokenMatch(x, y) || (x.length >= 3 && y.startsWith(x)) || (y.length >= 3 && x.startsWith(y))));
  // The one-word names of an identity that also has a full one, and the ones among them that fit `t`.
  const short = full.length ? primary.tokens.filter((t) => !personal(t)) : [];
  const fitting = (t) => short.filter((p) => fitsName(p, t));
  const shortNames = (list) => primary.names.filter((n) => { const m = meaningfulName(n, keys); return m && list.some((p) => p.join(" ") === m.join(" ")); }).slice(0, 3);
  // A profile grouped with another person stands where that person stands: an account with no
  // name of its own that a proof ties to "Sam Example" is not Petra Novak's because it is silent.
  const own = result.clusters.find((c) => c.id === result.byProfile[profile.id]) || null;
  if (own && own !== primary && !(tokens && conflicts(tokens))) {
    const theirs = own.tokens.filter(personal);
    if (theirs.length && theirs.every(conflicts) && !theirs.some((t) => fitting(t).length)) {
      const tie = own.links.filter((l) => l.a === profile.id || l.b === profile.id).flatMap((l) => l.signals.map((s) => s.detail));
      return { tier: "different", why: "", against, via: own.label, tie: [...new Set(tie)].slice(0, 2).join(", ") };
    }
  }
  if (!tokens) return { tier: "matches", why: extra || "no name on the profile" };
  if (!primary.tokens.length) return { tier: "matches", why: extra || "the primary record carries no name to compare" };
  if (full.length) {
    if (!conflicts(tokens)) return { tier: "matches", why: extra || "name does not conflict" };
    const fit = fitting(tokens);
    if (fit.length) return { tier: "matches", why: extra, unsettled: true, mixed: true, against, fits: shortNames(fit).length ? shortNames(fit) : fit.map((p) => p.join(" ")).slice(0, 3) };
    return { tier: "different", why: "", against };
  }
  const related = primary.tokens.some((t) => fitsName(t, tokens));
  if (personal(tokens) && !related && primary.tokens.every((t) => script(t) === script(tokens))) return { tier: "matches", why: extra, unsettled: true, against };
  return { tier: "matches", why: extra || "name does not conflict" };
}

// Old saved runs hold bios the backend had not yet filtered. These are the same tells, kept
// here only so those runs do not show site boilerplate as a fact. New runs arrive already
// blanked (bio_boilerplate: true) and never reach this list.
const BOILERPLATE = [/streams live on Twitch/i, /Watch awesome short videos/i, /\bon Patreon for exclusive\b/i, /\bis on (Facebook|Snapchat)\b/i, /\d+ Followers, \d+ Following/i, /Join Facebook to connect/i, /Sign up to (see|chat|follow)/i, /See Instagram photos and videos/i];
export const looksBoilerplate = (bio) => BOILERPLATE.some((re) => re.test(String(bio ?? "")));
