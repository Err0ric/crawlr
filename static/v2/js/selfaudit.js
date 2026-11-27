// Reduce your footprint: the self-audit rules.
//
// The investigator has said "This is me" on the case (collected.selfAudit, kept in the browser).
// This module turns what the case found into a ranked list of things the account holder can do
// to reduce their public footprint. Each item says what is exposed, where it was seen and the
// concrete steps. It is advice, never a guarantee: it covers only what these sources could see,
// and a source that failed may hide more (see `gaps`).
//
// Pure: no DOM, no network, no AI. Every value that came from a source is a plain string in the
// item fields. The page escapes them; nothing here builds HTML.
//
// Whose rows:
//   yours     a row of the primary identity: filed Linked, or in the primary cluster
//   check     a row filed "Exists (matches)" that nothing ties to the primary identity. It is
//             probably yours, and each item that uses one says to check first.
//   other     a row filed as a different person, and a Launchpad record nobody claimed. These
//             are never "yours": they go into ONE item that says they may be someone else's.
//   unread    a row a tool reported and nothing read. Counted in one item, never listed.
// Adult and dating site rows are never part of this: the case is read without them, and a row or
// an address on such a site is dropped again here. No item names a people-search site or a data
// broker, and no fix carries a handle or an address in a URL.
import { breachList, githubStanding, canonSite } from "./evidence.js";
import { readProfileSources, readEmailAccounts, readActivity, readArchives, readArchiveDiffs, readCommitEmails, readPostActivities, postActivityLabel, commitEmailsFor, postActivityFor, unclaimedProfile, profileCoverage, emailLookupsDown, dayOf } from "./deep.js";
import { withoutAdult, adultHost, isAdultRow } from "./adult.js";
import { isBareHome, hostOf } from "./links.js";
import { isPlatformHost } from "./identity.js";

export const SELF_AUDIT_TITLE = "Reduce your footprint";
export const SELF_AUDIT_NOTE = "Built by rules from what this case found, with no AI. It is advice, not a guarantee: it covers only what these sources could see, and a source that failed may hide more.";
export const SELF_AUDIT_GROUPS = { ties: "ties accounts together", contact: "exposes contact details", other: "worth knowing" };
const G = SELF_AUDIT_GROUPS;

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const list = (arr, n = 4) => { const a = arr.slice(0, n), more = arr.length - a.length; return more ? `${a.join(", ")} and ${more} more` : a.length < 2 ? a.join("") : `${a.slice(0, -1).join(", ")} and ${a.at(-1)}`; };
const uniq = (arr) => [...new Set(arr)];
const lc = (v) => String(v ?? "").trim().toLowerCase();
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// A forge's placeholder is not an address of the person.
const NOREPLY = /(^|[.@])(users\.)?noreply\.[a-z0-9.-]+$|^noreply@/i;
const failedAnswer = (d) => isObj(d) && !!(d.error || d.error_code) && d.error_code !== "not_found";
const ACCOUNT_TIERS = ["linked", "matches", "different", "unverified"];

// ---- whose row is it ------------------------------------------------------------------------------
// The checked case behind every rule: the account rows, each with its standing.
function caseOf(ev, collected, target, type) {
  const c = withoutAdult(collected);
  const rows = (ev.items || []).filter((i) => typeof i.key === "string" && i.key.startsWith("acct:") && ACCOUNT_TIERS.includes(i.tier) && !i.similar && !isAdultRow({ site: i.what, url: i.url }));
  const byKey = new Map(rows.map((r) => [r.key, r]));
  const ps = readProfileSources(c.profiles);
  // A Launchpad record the site made by itself, read from the checked record and not from a row field.
  const unclaimed = new Set((ps && !ps.error && !ps.error_code ? ps.profiles : []).filter(unclaimedProfile).map((p) => `acct:${canonSite(p.site)}`));
  const standing = (row) => (!row ? "" : unclaimed.has(row.key) ? "other" : row.tier === "different" ? "other" : row.tier === "linked" || row.inPrimary === true ? "yours" : row.tier === "matches" ? "check" : "unread");
  const of = (s) => rows.filter((r) => standing(r) === s);
  const main = (ev.identity?.views || []).find((v) => v.primary) || null;
  return { c, ev, rows, byKey, unclaimed, standing, of, main, type, target: String(target ?? "").trim(), handle: type === "username" ? String(target ?? "").trim().replace(/^@/, "") : "" };
}
// Where something was seen: the site, with the row's own link when it has one. Never a bare
// homepage and never an adult or dating site.
function place(row, label, extra = {}) {
  const out = { label: String(label ?? row?.what ?? "") };
  const url = row && typeof row.url === "string" ? row.url : "";
  if (url && row.link_kind && row.link_kind !== "none" && /^https:\/\//i.test(url) && !adultHost(url) && !isBareHome(url)) { out.url = url; out.link_kind = row.link_kind; }
  return { ...out, ...extra };
}
const linkPlace = (label, url, link_kind) => (url && /^https:\/\//i.test(url) && !adultHost(url) && !isBareHome(url) ? { label, url, link_kind } : { label });
// The rows a fact's sources name. A fact keeps the site names it was read on; a name that is no
// row of this case (a tool, a details lookup) is no place.
const factRows = (k, f) => uniq((f.how?.sources?.length ? f.how.sources : String(f.source ?? "").split(", ")).map((s) => k.byKey.get(`acct:${canonSite(s)}`)).filter(Boolean));
const CHECK_FIRST = (names) => `Nothing in the case ties ${list(names, 3)} to you, so check that ${names.length === 1 ? "it is" : "they are"} yours first.`;

// ---- 1. an address in public commits ----------------------------------------------------------------
const FORGE_FIX = {
  github: 'On GitHub: Settings, Emails, then "Keep my email addresses private" and "Block command line pushes that expose my email".',
  gitlab: "On GitLab: use the private commit email shown in your profile settings.",
  codeberg: 'On Codeberg: turn on "Hide email address" in the settings and use the noreply address it gives you.',
  gitea: 'On Gitea.com: turn on "Hide email address" in the settings and use the noreply address it gives you.',
};
const TIE_WEIGHT = { forge_attributed: 100, pushed: 92, author_line_match: 85 };
const TIE_TEXT = {
  forge_attributed: "The site links those commits to your account by this address.",
  pushed: "They are commits your account pushed, with this address in the author line.",
  author_line_match: "The commits carry your account's name next to this address. Names and addresses in commits are typed by the author, so this is the weaker tie.",
};
function commitEmailItems(k) {
  const found = new Map();   // address -> { forges, places, ties, check }
  const note = (addr, forge, site, tie, where, check = "") => {
    const a = lc(addr);
    if (!EMAIL.test(a) || NOREPLY.test(a)) return;
    const cur = found.get(a) || { forges: [], sites: [], places: [], ties: [], check: [] };
    if (!cur.forges.includes(forge)) cur.forges.push(forge);
    if (!cur.sites.includes(site)) cur.sites.push(site);
    if (!cur.places.some((p) => p.label === where.label)) cur.places.push(where);
    cur.ties.push(tie);
    if (check && !cur.check.includes(check)) cur.check.push(check);
    found.set(a, cur);
  };
  // GitLab, Codeberg and Gitea.com rows, asked on a click.
  for (const [key, a] of Object.entries(readCommitEmails(k.c.commitEmails || {}))) {
    const row = k.byKey.get(key), st = k.standing(row);
    if ((st !== "yours" && st !== "check") || a.emails_state !== "found") continue;
    for (const e of a.emails) note(e.email, a.site, a.site_name, e.how, place(row, `${a.site_name}${e.repos.length ? ` (${list(e.repos, 2)})` : ""}`, st === "check" ? { check: true } : {}), st === "check" ? a.site_name : "");
  }
  // GitHub's details, only while the GitHub account is the case's own.
  const gh = k.byKey.get("acct:github"), dp = k.c.githubDeep;
  if (gh && githubStanding(k.ev).own && isObj(dp) && !failedAnswer(dp) && dp.found !== false && (!isObj(dp.sections) || !dp.sections.commit_emails || dp.sections.commit_emails === "ok")) {
    const by = new Map();
    for (const e of (Array.isArray(dp.commit_emails) ? dp.commit_emails : []).slice(0, 10)) if (isObj(e) && EMAIL.test(lc(e.email))) { const a = lc(e.email); by.set(a, [...(by.get(a) || []), typeof e.repo === "string" && /^[\w.-]{1,100}\/[\w.-]{1,100}$/.test(e.repo) ? e.repo : ""].filter(Boolean)); }
    for (const [addr, repos] of by) note(addr, "github", "GitHub", "pushed", place(gh, `GitHub${repos.length ? ` (${list(uniq(repos), 2)})` : ""}`));
  }
  // An email case: the account GitHub attributes commits with the searched address to.
  if (k.type === "email") {
    const r = readEmailAccounts(k.c.emailAccounts);
    if (r && !r.error && !r.error_code) {
      for (const a of r.accounts.filter((x) => x.how === "commit_author")) note(k.target, "github", "GitHub", "forge_attributed", linkPlace(`GitHub (${a.login})`, a.url, "verified_profile"));
      if (r.unattributed) note(k.target, "github", "GitHub", "author_line_match", linkPlace("Commits GitHub ties to no account", r.unattributed.evidence[0] || "", "evidence"));
    }
  }
  return [...found].map(([addr, f]) => {
    const tie = Object.keys(TIE_WEIGHT).find((t) => f.ties.includes(t));
    return {
      id: `commit-email:${addr}`, kind: "commit-email", group: G.contact, title: `An address in your public commits: ${addr}`,
      exposed: [`${addr} can be read from public commits on ${list(f.sites, 3)}.`, TIE_TEXT[tie], f.check.length ? CHECK_FIRST(f.check) : ""].filter(Boolean).join(" "),
      where: f.places,
      fix: [...f.forges.map((id) => FORGE_FIX[id]).filter(Boolean), "Then set git config user.email to that address on every machine you commit from."].join(" "),
      why: "Commits already pushed keep the old address: history is copied into every clone and fork, so rewriting it rarely gets the address out.",
      weight: TIE_WEIGHT[tie] + Math.min(f.places.length - 1, 4) - (f.check.length === f.places.length ? 15 : 0),
    };
  });
}

// ---- 2. an address shown on a public profile --------------------------------------------------------
function profileEmailItems(k) {
  const found = new Map();
  for (const v of k.ev.identity?.views || []) for (const f of v.facts || []) {
    if (f.k !== "Email" || !EMAIL.test(lc(f.v))) continue;
    for (const row of factRows(k, f)) {
      const st = k.standing(row);
      if (st !== "yours" && st !== "check") continue;
      const cur = found.get(lc(f.v)) || { rows: [], check: [] };
      if (!cur.rows.includes(row)) { cur.rows.push(row); if (st === "check") cur.check.push(row.what); }
      found.set(lc(f.v), cur);
    }
  }
  return [...found].map(([addr, f]) => ({
    id: `profile-email:${addr}`, kind: "profile-email", group: G.contact, title: `An address shown on a public profile: ${addr}`,
    exposed: [`${addr} is shown on your ${list(f.rows.map((r) => r.what), 4)} ${f.rows.length === 1 ? "profile" : "profiles"}, where anyone can read it and a scraper can collect it.`, f.check.length ? CHECK_FIRST(f.check) : ""].filter(Boolean).join(" "),
    where: f.rows.map((r) => place(r, r.what, f.check.includes(r.what) ? { check: true } : {})),
    fix: "Remove it from the profile, or replace it with a contact alias that forwards to you and that you can switch off.",
    why: "Archived copies of the profile can keep showing the old address.",
    weight: 80 + Math.min(f.rows.length - 1, 4) - (f.check.length === f.rows.length ? 15 : 0),
  }));
}

// ---- 3. breaches (an email case) --------------------------------------------------------------------
const FIXED_DATA = /phone|(physical|home|postal|street|mailing) address|^addresses$/i;
const BREACH_FIX = "Change the password you used there, and everywhere you reused it. Use a password manager so every site has its own password, and turn on two-factor sign-in.";
const fixedData = (bs) => uniq(bs.flatMap((b) => b.data_classes.filter((x) => FIXED_DATA.test(x)).map((x) => x.toLowerCase())));
const FIXED_WHY = (classes) => `The leaked data includes ${list(classes, 3)}. Those cannot be changed like a password, so expect phishing that quotes them.`;
function breachItems(k) {
  if (k.type !== "email" || !isObj(k.c.hibp) || failedAnswer(k.c.hibp)) return [];
  const bs = breachList(k.c.hibp);
  const where = (b) => { const row = (k.ev.items || []).find((i) => i.key === `breach:${lc(b.name)}`); return linkPlace(`${b.name}${b.year ? ` (${b.year})` : ""}`, row?.url || "", row?.link_kind && row.link_kind !== "none" ? row.link_kind : ""); };
  const clean = (o) => (o.link_kind ? o : { label: o.label });
  if (bs.length > 3) {
    const fixed = fixedData(bs);
    return [{ id: "breaches", kind: "breach", group: G.contact, title: `Your address is in ${bs.length} known breaches`,
      exposed: `Your address is in ${bs.length} known breaches (${list(bs.map((b) => b.name), 4)}). Each one puts it, and whatever else that site held, in lists that are traded.`,
      where: bs.slice(0, 12).map((b) => clean(where(b))), fix: BREACH_FIX.replace("you used there", "you used on each of them"), ...(fixed.length ? { why: FIXED_WHY(fixed) } : {}), weight: 78 }];
  }
  return bs.map((b) => {
    const fixed = fixedData([b]), pw = b.data_classes.some((x) => /password/i.test(x));
    return { id: `breach:${lc(b.name)}`, kind: "breach", group: G.contact, title: `Your address is in the ${b.name} breach`,
      exposed: `Your address is in the ${b.name} breach${b.year ? ` (${b.year})` : ""}${b.data_classes.length ? `, with ${list(b.data_classes.map((x) => x.toLowerCase()), 4)}` : ""}.`,
      where: [clean(where(b))], fix: BREACH_FIX, ...(fixed.length ? { why: FIXED_WHY(fixed) } : {}), weight: pw ? 78 : 66 };
  });
}

// ---- 4. an OpenPGP key with a name on the key server ----------------------------------------------
function keyItems(k) {
  if (k.type !== "email") return [];
  const r = readEmailAccounts(k.c.emailAccounts);
  if (!r || r.error || r.error_code) return [];
  return r.keys.filter((x) => x.parsed).map((key) => {
    const names = uniq(key.user_ids.map((u) => u.name).filter(Boolean)), others = uniq(key.user_ids.map((u) => u.email).filter((e) => e && e !== lc(k.target)));
    if (!names.length && !others.length) return null;
    const carries = [names.length ? `the name ${list(names, 2)}` : "", others.length ? `${plural(others.length, "other address", "other addresses")} (${list(others, 2)})` : ""].filter(Boolean).join(" and ");
    return { id: `pgp-key:${key.fingerprint.toLowerCase()}`, kind: "pgp-key", group: G.contact, title: "An OpenPGP key on a public key server",
      exposed: `A key published for your address on keys.openpgp.org carries ${carries}. The key server lists an address only after its owner confirmed it by mail.${key.revoked ? " The key is revoked, and it is still published." : ""}`,
      where: [linkPlace("keys.openpgp.org", key.url, "evidence")],
      fix: 'On keys.openpgp.org, "Manage key" takes an address out of the search.',
      why: "The name is written inside the key, so it stays in every copy of the key held elsewhere.",
      weight: 62 + (others.length ? 4 : 0) };
  }).filter(Boolean);
}

// ---- 5. archived copies -----------------------------------------------------------------------------
function archiveItems(k) {
  const held = [], diffs = readArchiveDiffs(k.c.archiveDiffs || {});
  for (const [key, a] of Object.entries(readArchives(k.c.archives || {}))) {
    const row = k.byKey.get(key), st = k.standing(row);
    if ((st !== "yours" && st !== "check") || a.state !== "ok") continue;
    const d = diffs[key], removed = !!d && d.state === "ok" && (d.removed.text_total > 0 || d.removed.links_total > 0);
    held.push({ row, a, st, removed });
  }
  if (!held.length) return [];
  const one = (h) => `${h.row.what} (${plural(h.a.count, "day")}${h.a.truncated ? " or more" : ""}, ${dayOf(h.a.first) === dayOf(h.a.last) ? dayOf(h.a.first) : `${dayOf(h.a.first)} to ${dayOf(h.a.last)}`})`;
  const gone = held.filter((h) => h.removed).map((h) => h.row.what), check = held.filter((h) => h.st === "check").map((h) => h.row.what);
  return [{ id: "archive-copies", kind: "archive", group: G.other, title: "Archived copies of your profiles",
    exposed: [`The Internet Archive holds copies of ${held.length === 1 ? "your profile on" : "your profiles on"} ${list(held.map(one), 4)}.`, gone.length ? `A comparison of two copies of ${list(gone, 3)} shows text or links that were later taken off the live page, so the old version is still readable there.` : "", check.length ? CHECK_FIRST(check) : ""].filter(Boolean).join(" "),
    where: held.map((h) => place(h.row, h.row.what, h.st === "check" ? { check: true } : {})),
    fix: "The Internet Archive takes removal and exclusion requests by email (info@archive.org) from the owner of the account or site. Send the address of the page and proof that it is yours. It is a request, and the archive decides.",
    why: "Deleting or editing the live profile does not delete the copies already captured.",
    weight: 44 + (gone.length ? 6 : 0) }];
}

// ---- 6. the same picture on several accounts --------------------------------------------------------
const signalRows = (k, type) => { const sig = (k.main?.signals || []).filter((s) => s.type === type); const names = uniq(sig.flatMap((s) => [s.a, s.b]).filter(Boolean)); return { sig, rows: names.map((n) => k.rows.find((r) => r.what === n && k.standing(r) === "yours")).filter(Boolean) }; };
function avatarItems(k) {
  const { rows } = signalRows(k, "avatar");
  if (rows.length < 2) return [];
  return [{ id: "same-picture", kind: "avatar", group: G.ties, title: "The same picture on several accounts",
    exposed: `The same picture is on your ${list(rows.map((r) => r.what), 5)} accounts. A matching picture ties accounts together even when the handles or names differ.`,
    where: rows.map((r) => place(r)), fix: "Use different pictures on accounts that should not be linked.",
    why: "Archived copies of a profile keep its old picture.", weight: 58 + Math.min(rows.length - 2, 4) }];
}

// ---- 7. the same handle on many sites ---------------------------------------------------------------
function handleItems(k) {
  if (k.type !== "username" || !k.handle) return [];
  const yours = k.of("yours"), check = k.of("check");
  if (yours.length + check.length < 3) return [];
  const exposed = yours.length
    ? [`Your handle ${k.handle} is on ${plural(yours.length, "site")} the case ties to you (${list(yours.map((r) => r.what), 6)}).`, check.length ? `${plural(check.length, "more account")} ${check.length === 1 ? "fits" : "fit"} and nothing ties ${check.length === 1 ? "it" : "them"} to you: check which are yours (${list(check.map((r) => r.what), 4)}).` : ""]
    : [`The handle ${k.handle} has a readable profile on ${plural(check.length, "site")} (${list(check.map((r) => r.what), 6)}), and nothing in the case ties them together: check which are yours.`];
  return [{ id: "same-handle", kind: "handle", group: G.ties, title: "The same handle on many sites",
    exposed: [...exposed, "One handle is what made this search possible: whoever knows it on one site can look for it on the others."].filter(Boolean).join(" "),
    where: [...yours.map((r) => place(r)), ...check.map((r) => place(r, r.what, { check: true }))],
    fix: "Use different handles for accounts that should stay apart.",
    why: "Renaming an account leaves old links pointing at the old name, and archived copies keep it.",
    weight: 50 + Math.min(yours.length + check.length - 3, 6) }];
}

// ---- 8. cross-links and proofs ----------------------------------------------------------------------
function crossLinkItems(k) {
  const { sig, rows } = signalRows(k, "cross-link");
  if (!sig.length || rows.length < 2) return [];
  const keybase = sig.some((s) => /Keybase proof/.test(s.detail || ""));
  return [{ id: "cross-links", kind: "cross-link", group: G.ties, title: "Links and proofs between your accounts",
    exposed: `Your accounts point at each other: ${uniq(sig.map((s) => String(s.detail || "")).filter(Boolean)).slice(0, 4).join("; ")}. These are ties you set up, and anyone can follow them.`,
    where: rows.map((r) => place(r)),
    fix: `Keep the ones you want public and remove the rest: take the link off the profile on both sides.${keybase ? " A Keybase proof has to be revoked on Keybase, and the proof post deleted on the other site." : ""}`,
    why: "A link you remove today can still be read in an archived copy of the profile.", weight: 54 + Math.min(sig.length - 1, 3) }];
}

// ---- 9. details you wrote on your profiles ----------------------------------------------------------
const DETAIL_WORD = { Name: "name", Location: "location", Employer: "employer", Website: "website" };
function detailItems(k) {
  const parts = [], rows = [], domains = [];
  for (const f of k.main?.facts || []) {
    if (!Object.hasOwn(DETAIL_WORD, f.k) || !String(f.v ?? "").trim()) continue;
    const on = factRows(k, f).filter((r) => k.standing(r) === "yours");
    if (!on.length) continue;
    // A website is named by its host: no item sentence carries a web address.
    parts.push(`${DETAIL_WORD[f.k]} ${f.k === "Website" ? hostOf(f.v) || String(f.v).trim().replace(/^https?:\/\//i, "") : String(f.v).trim()} (${list(on.map((r) => r.what), 3)})`);
    for (const r of on) if (!rows.includes(r)) rows.push(r);
    if (f.k === "Website") { const h = hostOf(/^https?:\/\//i.test(f.v) ? f.v : `https://${f.v}`); if (h && !isPlatformHost(h) && !adultHost(h) && !domains.includes(h)) domains.push(h); }
  }
  if (!parts.length) return [];
  return [{ id: "profile-details", kind: "details", group: G.other, title: "Details you wrote on your profiles",
    exposed: `Your profiles state: ${parts.slice(0, 6).join("; ")}${parts.length > 6 ? `; and ${parts.length - 6} more` : ""}. Each detail is small, and together they narrow down who you are.`,
    where: rows.map((r) => place(r)),
    fix: `Trim what does not need to be public on each profile.${domains.length ? ` A personal domain can expose more through its WHOIS and DNS records: a Recon run of ${domains[0]} shows what.` : ""}`,
    weight: 48 + Math.min(parts.length - 1, 4) }];
}

// ---- 10. activity hours -----------------------------------------------------------------------------
function activityItems(k) {
  const seen = [];
  const gh = k.byKey.get("acct:github"), ga = isObj(k.c.githubActivity) ? readActivity(k.c.githubActivity) : null;
  if (gh && githubStanding(k.ev).own && ga && ga.state === "ok" && ga.estimate) seen.push({ row: gh, label: "GitHub", range: ga.estimate.label });
  for (const [key, a] of Object.entries(readPostActivities(k.c.postActivity || {}))) {
    const row = k.byKey.get(key);
    if (k.standing(row) === "yours" && a.state === "ok" && a.estimate) seen.push({ row, label: postActivityLabel(a) || row.what, range: a.estimate.label });
  }
  if (!seen.length) return [];
  return [{ id: "activity-hours", kind: "activity", group: G.other, title: "The hours you are usually active",
    exposed: `Public timestamps on ${list(seen.map((s) => s.label), 4)} show when you are usually active (${seen.slice(0, 4).map((s) => `${s.label}: ${s.range}`).join("; ")}). A range of UTC offsets is not a place, and it still narrows things down.`,
    where: seen.map((s) => place(s.row, s.label)),
    fix: "Scheduling posts or pushing commits in batches blurs the pattern from now on.",
    why: "Nothing takes back the timestamps that are already public.", weight: 10 }];
}

// ---- 11. accounts that may not be yours, and the ones nothing read ----------------------------------
function unrecognisedItems(k) {
  const other = k.of("other");
  if (!other.length) return [];
  const launchpad = other.some((r) => k.unclaimed.has(r.key));
  const subject = k.type === "email" ? "your address" : "your handle";
  return [{ id: "unrecognised-accounts", kind: "unrecognised", group: G.other, title: "Accounts under your handle that you may not recognise",
    exposed: [`A search for ${subject} also finds ${list(other.map((r) => r.what), 6)}. ${other.length === 1 ? "It" : "They"} may be someone else's: the same handle, another person.`, launchpad ? "Launchpad makes a record by itself for a person named in an imported bug, translation or package, so nobody may have signed up for that one." : ""].filter(Boolean).join(" "),
    where: other.map((r) => place(r)),
    fix: "If one is yours and forgotten, sign in and close it or clean it up. If it is not yours there is nothing to fix: just know that a search for your handle finds it.",
    weight: 36 }];
}
function unverifiedItems(k) {
  const n = k.of("unread").filter((r) => !r.nofind && !r.taken).length;
  if (!n) return [];
  return [{ id: "unverified-accounts", kind: "unverified", group: G.other, title: "Accounts a tool reported and nothing read",
    exposed: k.type === "email"
      ? `${plural(n, "more account")} ${n === 1 ? "was" : "were"} matched to your address by a search and never read. A search match is not a confirmed account.`
      : `${plural(n, "more account")} under your handle ${n === 1 ? "was" : "were"} reported by a tool and never read. Many sites answer yes to any name, so some of them may not exist.`,
    where: [],
    fix: "Open the ones you recognise and check them. Close or clean up any that are yours and forgotten. The rest need nothing from you.",
    weight: 20 }];
}

// ---- 12. what this list could not see ---------------------------------------------------------------
const SOURCE_NAMES = { username: { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", profiles: "Profile sources", platformCheck: "Platform check", enricher: "Profile enrichment", githubDeep: "GitHub details", githubActivity: "GitHub activity", avatarHash: "Avatar comparison" }, email: { holehe: "Holehe", hibp: "Breaches", gravatar: "Gravatar", emailAccounts: "Accounts and keys" } };
function gapsOf(k) {
  const out = [], c = k.c;
  const down = Object.entries(SOURCE_NAMES[k.type]).filter(([key]) => failedAnswer(c[key])).map(([, name]) => name);
  if (down.length) out.push(`${list(down, 5)} failed, so what ${down.length === 1 ? "it" : "they"} would have shown is unknown. Run the case again before reading this list as complete.`);
  if (k.type === "username") {
    const cov = profileCoverage(c.profiles).down;
    if (cov.length) out.push(`${plural(cov.length, "profile source")} did not answer (${list(cov.map((x) => `${x.site}: ${x.state === "rate_limited" ? "rate limited" : x.state === "blocked" ? "blocked by site" : x.state === "failed" ? "failed" : "could not tell"}`), 5)}). An account there is unknown, not absent.`);
    const blocked = k.rows.filter((r) => r.tier === "unverified" && /^Blocked by site/.test(r.meta || ""));
    if (blocked.length) out.push(`${list(blocked.map((r) => r.what), 5)} blocked the check, so whether an account is there is unknown.`);
    if (k.ev.identity?.noPrimary) out.push("Nothing ties these accounts together, so the case cannot tell which are yours. Pick your own profile under the names and this list is rebuilt around it.");
    const gh = k.byKey.get("acct:github");
    if (gh && githubStanding(k.ev).own) {
      if (!isObj(c.githubDeep)) out.push("GitHub details were not read, so whether your public commits there show an address is unknown.");
      else if (!failedAnswer(c.githubDeep) && isObj(c.githubDeep.sections) && c.githubDeep.sections.commit_emails && c.githubDeep.sections.commit_emails !== "ok") out.push("GitHub's commits could not be read, so whether they show an address is unknown.");
    }
  } else {
    const lk = emailLookupsDown(c.emailAccounts);
    if (lk.length) out.push(`${list(lk.map((x) => `${x.name} (${x.state === "rate_limited" ? "rate limited" : "failed"})`), 4)} did not answer, so accounts and keys behind the address may be missing here.`);
    if (!isObj(c.hibp)) out.push("The breach check did not run, so breaches are unknown.");
    if (!isObj(c.emailAccounts)) out.push("Accounts and keys were not looked up, so commits and keys that carry the address are unknown.");
  }
  // Lookups made on a click, one row at a time: asked and unanswered, or never asked.
  const mine = k.of("yours"), names = (rows) => list(rows.map((r) => r.what), 4);
  const ce = readCommitEmails(c.commitEmails || {}), pa = readPostActivities(c.postActivity || {}), ar = readArchives(c.archives || {});
  const ask = (row) => ({ site: row.what, url: row.url, handle: row.card?.handle || "" });
  const ceDown = mine.filter((r) => ce[r.key] && ce[r.key].emails_state === "unknown"), cePart = mine.filter((r) => ce[r.key] && ce[r.key].emails_state === "found" && !ce[r.key].complete);
  if (ceDown.length) out.push(`The commits on ${names(ceDown)} could not be read, so whether they show an address is unknown.`);
  if (cePart.length) out.push(`The commits on ${names(cePart)} were read in part: the addresses listed, and maybe more.`);
  const ceNot = mine.filter((r) => !ce[r.key] && r.link_kind === "verified_profile" && commitEmailsFor(ask(r)));
  if (ceNot.length) out.push(`Commit emails were not looked up for ${names(ceNot)}. Ask on that row to see whether your commits show an address.`);
  const arDown = mine.filter((r) => ar[r.key] && (ar[r.key].state === "failed" || ar[r.key].state === "rate_limited"));
  if (arDown.length) out.push(`The Internet Archive could not be asked about ${names(arDown)}, so whether it holds copies is unknown.`);
  const arNot = mine.filter((r) => !ar[r.key] && r.archive);
  if (arNot.length) out.push(`Archived copies were not looked up for ${plural(arNot.length, "profile")} of yours (${names(arNot)}).`);
  const paDown = mine.filter((r) => pa[r.key] && (pa[r.key].state === "failed" || pa[r.key].state === "rate_limited"));
  if (paDown.length) out.push(`Post activity on ${names(paDown)} could not be read, so what its timestamps show is unknown.`);
  const paNot = mine.filter((r) => !pa[r.key] && r.link_kind === "verified_profile" && postActivityFor(ask(r)));
  if (paNot.length) out.push(`Post activity was not looked up for ${names(paNot)}.`);
  return out;
}

// ---- the list ---------------------------------------------------------------------------------------
const RULES = [commitEmailItems, profileEmailItems, breachItems, keyItems, archiveItems, avatarItems, handleItems, crossLinkItems, detailItems, activityItems, unrecognisedItems, unverifiedItems];
const EMPTY = () => ({ items: [], counts: { ties: 0, contact: 0, other: 0 }, gaps: [] });
// ev: buildEvidence(collected, target, type). Only a username or an email case has a list.
//   { items: [{ id, kind, title, exposed, where: [{ label, url?, link_kind?, check? }], fix, why?, weight, group }],
//     counts: { ties, contact, other }, gaps: [sentence] }
// where[].check: the case does not tie that account to the primary identity ("probably yours, check").
export function selfAudit(ev, collected, { target = "", type = ev?.type || "" } = {}) {
  if (!ev || !Array.isArray(ev.items) || !isObj(collected) || (type !== "username" && type !== "email")) return EMPTY();
  const k = caseOf(ev, collected, target, type);
  const seen = new Set(), items = [];
  for (const rule of RULES) for (const it of rule(k)) if (!seen.has(it.id)) { seen.add(it.id); items.push(it); }
  items.sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id));
  const n = (g) => items.filter((i) => i.group === g).length;
  return { items, counts: { ties: n(G.ties), contact: n(G.contact), other: n(G.other) }, gaps: gapsOf(k) };
}

// One sentence for a summary: "7 things to look at: 3 tie accounts together, 2 expose contact details."
export function selfAuditText(result) {
  const items = result?.items || [], c = result?.counts || {}, gaps = (result?.gaps || []).length;
  const unknown = gaps ? ` ${plural(gaps, "part")} of the picture ${gaps === 1 ? "is" : "are"} unknown.` : "";
  if (!items.length) return `The rules found nothing to act on in what these sources could see.${unknown}`;
  const parts = [c.ties ? `${c.ties} ${c.ties === 1 ? "ties" : "tie"} accounts together` : "", c.contact ? `${c.contact} ${c.contact === 1 ? "exposes" : "expose"} contact details` : ""].filter(Boolean);
  return `${plural(items.length, "thing")} to look at${parts.length ? `: ${parts.join(", ")}` : ""}.${unknown}`;
}

// Markdown lines for the export. Source values are escaped, and a place is linked only when it
// carries a link of its own.
const md = (v) => String(v ?? "").replace(/\s+/g, " ").trim().replace(/([\\`*_[\]<>|#])/g, "\\$1");
const mdWhere = (w) => (w.url && /^https:\/\/[^\s()<>]+$/.test(w.url) ? `[${md(w.label)}](${w.url})` : md(w.label)) + (w.check ? " (check that it is yours)" : "");
export function selfAuditMarkdown(result, { target = "" } = {}) {
  if (!result || !Array.isArray(result.items)) return [];
  const out = [`## ${SELF_AUDIT_TITLE}`, `_${target ? `For ${md(target)}, marked "This is me" on the case. ` : ""}${SELF_AUDIT_NOTE}_`, ""];
  if (!result.items.length) out.push(`- ${selfAuditText({ ...result, gaps: [] })}`);
  result.items.forEach((it, i) => {
    out.push(`${i + 1}. **${md(it.title)}** _(${it.group})_`, `   - Exposed: ${md(it.exposed)}`);
    if (it.where.length) out.push(`   - Seen on: ${it.where.map(mdWhere).join(", ")}`);
    out.push(`   - Fix: ${md(it.fix)}`);
    if (it.why) out.push(`   - Why: ${md(it.why)}`);
  });
  if (result.gaps.length) out.push("", "What this list could not see:", ...result.gaps.map((g) => `- ${md(g)}`));
  out.push("");
  return out;
}
