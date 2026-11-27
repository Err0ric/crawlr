// What the evidence says, and what to do next. Built from rules, with no model involved: every
// line is a count or a statement of what the case holds, and every suggestion is one hop the
// investigator starts with a click. Pure: no DOM, no network.
//
// Both functions read the result of buildEvidence (evidence.js), so they describe exactly what the
// ledger shows. This module does not import evidence.js: evidence.js calls it for the exports and
// for what the AI is told.
//
// assessCase(ev, opts) ->
//   { mode: "picked" | "auto" | "none", who, strength: "strong" | "moderate" | "thin" | "none",
//     headline, ties: [{ kind, n, text }], lines: [{ level: "ok" | "info" | "flag", text }] }
// suggestNext(ev, opts) ->
//   { top, more, parked, followed, note }, each entry
//   { id, score, title, reason, tag?, action: { kind, label, ... } | null }
//   action.kind:
//     pivot     { pivot: "investigate" | "recon", value, type?, via, source }   a new case, one click
//     archive   { key }                                                        one archive lookup for that row
//     post-activity  { key }                                                   one post activity reading for that row (row.canPostActivity)
//     commit-emails  { key }                                                   one commit email reading for that row (row.canCommitEmails)
//     archive-diff   { key, from, to }                                         one comparison of two archived copies of that row's
//                                                                              profile: the default pair of row.archiveDiffPairs
//     open      { url, link_kind }                                             a page the investigator opens by hand
//     copy      { text }                                                       a search copied as text, never a link
//     jump      { tier }                                                       opens a group of the findings
//     focus     { where: "identity" | "footprint" }                            moves to the people under the handle, or to the
//                                                                              "Reduce your footprint" view of a case marked "This is me"
//     rerun     {}                                                             runs the same target again

import { profileCoverage, emailLookupsDown, readEmailAccounts, PROFILE_STATE_WORD, PROVENANCE } from "./deep.js";
import { minorGuard, readBlock, isBlocked, adultHost } from "./adult.js";
import { readSteps, selfAuditOn } from "./casework.js";
import { isPlatformHost } from "./identity.js";

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const list = (arr, n = 4) => arr.slice(0, n).join(", ") + (arr.length > n ? ` and ${arr.length - n} more` : "");
const uniq = (arr) => [...new Set(arr)];
const ACCOUNT_TIERS = ["linked", "matches", "different", "unverified"];
// A record Launchpad made by itself (row.unclaimed) is nobody's account: it is counted nowhere here.
const isAccount = (i) => i.key?.startsWith("acct:") && ACCOUNT_TIERS.includes(i.tier) && !i.similar && !i.unclaimed;

// ---- how a fact is known --------------------------------------------------------------------------
// One line for a fact of "What we know": the kind of knowledge, and how many sites say the same.
//   kinds    "record" (the site's own record), "self" (written by the account holder), "tool" (a tool
//            read it from a page)
//   sites    the number of profiles that carry the same value
//   weak     every profile that carries it is joined to the identity by its name only
//   commit   the value was typed into a commit by its author: self-declared, and not something
//            the account holder wrote on a profile
export function factHow({ kinds = [], sites = 1, sources = [], weak = false, commit = false } = {}) {
  const ks = ["record", "self", "tool"].filter((k) => kinds.includes(k));
  if (!ks.length) return null;
  const prov = ks.map((k) => PROVENANCE[k]).join(" and ");
  const text = [sites > 1 ? `the same on ${sites} sites (${list(sources, 4)})` : ks.includes("self") ? (commit ? "typed into a commit by its author" : "written by the account holder") : ks.includes("record") ? "the site's own record" : "read from the page by a tool",
    weak ? "from a profile joined by its name only" : ""].filter(Boolean).join(" · ");
  return { kinds: ks, prov, agree: sites, sources: sources.slice(0, 8), weak, text };
}

// ---- what the evidence says ------------------------------------------------------------------------
const STRENGTH_WORD = { strong: "Strong", moderate: "Moderate", thin: "Thin", none: "None" };
export const strengthWord = (s) => (Object.hasOwn(STRENGTH_WORD, s) ? STRENGTH_WORD[s] : "");
const PROOF = /Keybase proof|verified link/;
const MINOR_KINDS = ["age", "school", "birth", "soft", "handle", "word", "pivot"];

// opts: { collected, target, type, failed: [source names that failed], incomplete: [names] }
export function assessCase(ev, { collected = {}, type = ev?.type || "", failed = [] } = {}) {
  const none = { mode: "none", who: "", strength: "none", headline: "", ties: [], lines: [] };
  if (!ev || (type !== "username" && type !== "email")) return none;
  const id = ev.identity || { views: [] };
  const main = id.views.find((v) => v.primary) || null;
  const accounts = ev.items.filter(isAccount);
  const tier = (t) => accounts.filter((i) => i.tier === t);
  const lines = [], ties = [];
  const add = (level, text) => lines.push({ level, text });
  const mode = id.picked ? "picked" : main ? "auto" : "none";

  // -- the ties that hold the identity together, by kind --
  const sig = main ? main.signals : [];
  const pair = (s) => `${s.a} and ${s.b}`;
  const of = (f) => uniq(sig.filter(f).map(pair));
  const proofs = of((s) => s.type === "cross-link" && PROOF.test(s.detail));
  const links = of((s) => s.type === "cross-link" && !PROOF.test(s.detail));
  const pictures = of((s) => s.type === "avatar");
  const profilesOf = (f) => uniq(sig.filter(f).flatMap((s) => [s.a, s.b]));
  const pictured = profilesOf((s) => s.type === "avatar"), named = profilesOf((s) => s.type === "name" || s.type === "weak-name");
  const shared = of((s) => s.type === "shared-link");
  const names = of((s) => s.type === "name" || s.type === "weak-name");
  if (main?.anchor) ties.push({ kind: "record", n: 1, text: main.anchor === "github" ? "GitHub's own record for this handle" : "Gravatar's record for this email" });
  if (proofs.length) ties.push({ kind: "proof", n: proofs.length, text: `${plural(proofs.length, "proof or verified link", "proofs or verified links")} confirmed from the other side (${list(proofs, 3)})` });
  if (links.length) ties.push({ kind: "link", n: links.length, text: `${plural(links.length, "cross-link")} (${list(links, 3)})` });
  if (pictures.length) ties.push({ kind: "picture", n: pictured.length, text: `the same picture on ${plural(pictured.length, "profile")} (${list(pictured, 4)})` });
  if (shared.length) ties.push({ kind: "site", n: shared.length, text: `${plural(shared.length, "shared link")} (${list(shared, 3)})` });
  if (names.length) ties.push({ kind: "name", n: named.length, text: `a matching name on ${plural(named.length, "profile")} (${list(named, 4)}), which is supporting and not proof` });
  // An email case: what ties accounts and keys to the address itself.
  const ea = type === "email" ? readEmailAccounts(collected.emailAccounts) : null;
  const eaOk = ea && !ea.error && !ea.error_code ? ea : null;
  const authors = eaOk ? eaOk.accounts.filter((a) => a.how === "commit_author") : [];
  const keys = eaOk ? eaOk.keys.filter((k) => k.parsed) : [];
  if (authors.length) ties.push({ kind: "record", n: authors.length, text: `GitHub attributes commits with this address to ${list(authors.map((a) => a.login), 3)} (GitHub's record)` });
  if (keys.length) ties.push({ kind: "record", n: keys.length, text: `${plural(keys.length, "OpenPGP key")} the key server verified for this address by mail` });
  const registered = accounts.filter((i) => /registered with this email/.test(i.meta || ""));
  if (registered.length) ties.push({ kind: "tool", n: registered.length, text: `${plural(registered.length, "sign-up check")} that say the address is registered (a tool report, not a record)` });

  // -- how strong, and why --
  const strongKinds = [proofs, links, pictures, shared].filter((x) => x.length).length;
  const tied = main ? uniq(sig.filter((s) => ["cross-link", "avatar", "shared-link"].includes(s.type)).flatMap((s) => [s.a, s.b])).length : 0;
  const records = (main?.anchor ? 1 : 0) + authors.length + keys.length;
  let strength = "none";
  if (main || records) {
    if ((tied >= 3 && (proofs.length || strongKinds >= 2)) || records >= 2) strength = "strong";
    else if (tied >= 2 || (records >= 1 && (authors.length || keys.length))) strength = "moderate";
    else strength = "thin";
  }
  const who = main ? main.label : "";
  // A pick is said here, once, as whose judgment it is. A pick that came with a case file is its
  // author's: it is never worded as "your pick".
  const byFile = !!id.pickFile;
  const pickHead = id.picked ? `Filed around ${who || "the picked identity"}, ${byFile ? "the person picked in the case file" : "your pick"}${id.autoLabel ? `, not the automatic choice (${id.autoLabel})` : ""}. ` : "";
  // The one record of an email case, named for what it is: a key ties a key to the address, not an account.
  const oneRecord = authors.length ? `GitHub's commit attribution ties the account ${authors[0].login} to this address.` : keys.length ? "One OpenPGP key is verified for this address by the key server. It ties a key to the address, not an account." : "One record ties an account to this address.";
  const readCount = accounts.filter((i) => i.tier !== "unverified").length;
  const head = {
    strong: tied >= 3 ? `${plural(tied, "account")} are tied into one identity by signals that do not depend on a name.` : `${plural(records, "record")} tie this ${type === "email" ? "address" : "handle"} to an account or a key. Each is the site's own statement, not a guess.`,
    moderate: tied >= 2 ? `${plural(tied, "account")} are tied together by at least one strong signal. One more independent tie would make this firm.` : `${oneRecord} A second, independent tie would make this firm.`,
    thin: id.picked && !main?.anchor && !tied ? `The identity rests on ${byFile ? "that pick" : "your pick"}${names.length ? " and on a matching name" : ""}. No link, picture, proof or record ties these profiles to the target.`
      : main?.anchor && !tied ? `The identity rests on one record (${main.sites[0]}). No other account is tied to it by a link, a picture or a proof${names.length ? "; names agree, and a name alone is supporting, not proof" : ""}.`
        : "The identity rests on a name. A name alone is supporting, not proof.",
    // A row nothing read (a tool's report, a search match) is not a profile that was read.
    none: readCount ? "No identity is established: profiles were read, and nothing ties any of them to the target." : accounts.length ? "No identity is established: accounts were reported, and no profile was read." : "No identity is established: no profile was read.",
  }[strength];
  const headline = `${STRENGTH_WORD[strength]}. ${pickHead}${head}`;
  if (ties.length) add(strength === "strong" ? "ok" : "info", `What holds it together: ${ties.map((t) => t.text).join("; ")}.`);

  // -- what corroborates what --
  const facts = main ? main.facts.filter((f) => f.how) : [];
  const agree = facts.filter((f) => f.how.agree >= 2 && ["Name", "Location", "Employer", "Website", "Email"].includes(f.k));
  for (const f of agree.slice(0, 3)) add("ok", `${f.k} "${f.v}" is the same on ${f.how.agree} profiles (${list(f.how.sources, 4)}).${f.how.kinds.every((k) => k === "self") ? " All of them are self-declared, so they agree with each other and prove nothing more than that." : ""}`);
  // -- what differs inside the identity --
  for (const k of ["Location", "Employer"]) {
    const vals = facts.filter((f) => f.k === k);
    if (vals.length > 1) add("info", `${k} is given ${vals.length} ways: ${list(vals.map((f) => `${f.v} (${f.source})`), 3)}. They may be the same place or employer written differently, or a change over time.`);
  }
  // -- when the accounts are active: do the UTC offset ranges of this identity's readings fit? --
  // A hint either way. It never changes the strength above or which profiles belong together,
  // and a range of offsets is never a place.
  const cmp = ev.offsets || null;
  const RANGES = "The UTC offset ranges estimated from when the accounts are active:";
  if (cmp?.verdict === "disagree") add("flag", `${RANGES} ${cmp.text} ${cmp.caution}`);
  else if (cmp?.verdict === "agree") add("info", `Supporting, not proof. ${RANGES} ${cmp.text} ${cmp.caution}`);
  // -- a record nobody claimed --
  const unclaimed = ev.items.filter((i) => i.unclaimed);
  if (unclaimed.length) add("info", `${list(unclaimed.map((i) => i.what), 3)} holds a record under this handle that is not a claimed account: the site made it by itself, so it is counted as nobody's account and nothing is read from it.`);
  // -- other people, and names that could not be compared --
  const different = tier("different");
  if (different.length) {
    const by = new Map();
    for (const i of different) { const k = i.via || i.person || "another name"; by.set(k, [...(by.get(k) || []), i.what]); }
    add("flag", `${plural(different.length, "account")} ${different.length === 1 ? "belongs" : "belong"} to ${by.size === 1 ? "another person" : `${by.size} other people`} whose name conflicts with ${who || "the primary identity"}: ${list([...by].map(([name, sites]) => `${name} (${list(sites, 4)})`), 3)}. Nothing is removed. Check whether ${by.size === 1 ? "that person is" : "they are"} connected to ${who || "this identity"} before leaving ${different.length === 1 ? "it" : "them"} out.`);
  }
  const unsettled = accounts.filter((i) => i.unsettled);
  const bare = unsettled.filter((i) => !i.unsettled.mixed), mixed = unsettled.filter((i) => i.unsettled.mixed);
  if (bare.length) add("flag", `${plural(bare.length, "profile")} ${bare.length === 1 ? "carries" : "carry"} a full name that could not be compared, because the primary identity has only a one-word name (${list(bare.map((i) => i.what), 3)}). Pick the person you mean.`);
  if (mixed.length) add("flag", `${plural(mixed.length, "profile")} ${mixed.length === 1 ? "carries" : "carry"} a name that fits a one-word name of the primary identity and conflicts with its full name (${list(mixed.map((i) => `${i.what}: "${i.unsettled.name}"`), 3)}). Neither settles it, so ${mixed.length === 1 ? "it is" : "they are"} not filed as a different person. Check ${mixed.length === 1 ? "it" : "them"} by hand.`);
  // -- self-declared only --
  if (facts.length) {
    const self = facts.filter((f) => f.how.kinds.every((k) => k === "self")), rec = facts.filter((f) => f.how.kinds.includes("record")), tool = facts.filter((f) => f.how.kinds.every((k) => k === "tool"));
    const said = uniq(self.map((f) => f.k.toLowerCase()));
    if (said.length) add("info", `Self-declared only: ${list(said, 6)}. The account holder wrote ${said.length === 1 ? "it" : "them"}, and no site vouches for ${said.length === 1 ? "it" : "them"}.${rec.length ? ` The sites' own records here are ${list(uniq(rec.map((f) => f.k.toLowerCase())), 4)}.` : ""}${tool.length ? ` ${plural(tool.length, "value")} ${tool.length === 1 ? "was" : "were"} read from a page by a tool, which cannot tell the two apart.` : ""}`);
  }
  // -- what could not be asked --
  const cov = type === "username" ? profileCoverage(collected.profiles) : { down: [] };
  const downLookups = type === "email" ? emailLookupsDown(collected.emailAccounts) : [];
  const blocked = tier("unverified").filter((i) => /^Blocked by site/.test(i.meta || ""));
  const down = [...failed.map((n) => `${n} (failed)`), ...cov.down.map((x) => `${x.site} (${PROFILE_STATE_WORD[x.state]})`), ...downLookups.map((x) => `${x.name} (${x.state === "rate_limited" ? "rate limited" : "failed"})`), ...blocked.map((i) => `${i.what} (blocked the check)`)];
  if (down.length) add("info", `Could not be asked: ${list(uniq(down), 6)}. Each is unknown, not absent.`);
  // -- how much of the footprint is unread --
  const unread = tier("unverified").filter((i) => !i.nofind), read = accounts.length - tier("unverified").length;
  if (unread.length) add("info", `${unread.length} of ${plural(read + unread.length, "account")} ${unread.length === 1 ? "was" : "were"} only reported by a tool and never read (${Math.round((unread.length / (read + unread.length)) * 100)}% of the footprint). Those are leads, not findings.`);
  return { mode, who, strength, headline, ties, lines };
}

// ---- suggested next steps -------------------------------------------------------------------------
// The list is built from what the case holds and nothing else. It never suggests an adult or
// dating site, a people-search site or a data broker, and it suggests nothing at all for a case
// the minor guard stopped. A handle the guard would refuse is never offered as a lead.
export const SUGGEST_CAP = 6;
const HANDLE_OK = /^[A-Za-z0-9._-]{1,64}$/;
const quoted = (v) => `"${String(v).replace(/["\u0000-\u001f]/g, " ").trim()}"`;

// opts: { collected, target, type, failed: [{ name }], rateLimited: [names], running }
export function suggestNext(ev, { collected = {}, target = "", type = ev?.type || "", failed = [] } = {}) {
  const empty = { top: [], more: [], parked: [], followed: [], note: "" };
  if (!ev || (type !== "username" && type !== "email")) return empty;
  // A case the minor guard stopped: nothing is suggested, and the page says why.
  const block = isBlocked(collected) ? readBlock(collected.adultBlock) : null;
  if ((type === "username" && minorGuard(target).blocked) || (block && MINOR_KINDS.includes(block.kind))) return { ...empty, note: "No next steps are suggested for this case: a sign of a minor was found for this handle." };
  const id = ev.identity || { views: [] };
  const main = id.views.find((v) => v.primary) || null;
  const accounts = ev.items.filter(isAccount);
  const out = [];
  const put = (s) => { if (!out.some((x) => x.id === s.id)) out.push(s); };

  // 1. an identity the case could not settle
  const people = id.views.filter((v) => v.named);
  const unsettled = accounts.filter((i) => i.unsettled);
  if (!id.picked) {
    if (id.noPrimary && people.length) put({ id: "pick:none", score: 100, title: "Choose who this case is about", reason: `${people.length === 1 ? "One name appears" : `${people.length} names appear`} under this handle (${list(people.map((v) => v.label), 3)}) and nothing ties ${people.length === 1 ? "it" : "any of them"} to the target, so nobody was chosen. Pick the person you mean and the case is filed around them.`, action: { kind: "focus", where: "identity", label: "Go to the names" } });
    else if (unsettled.length) put({ id: "pick:unsettled", score: 85, title: "Choose who this case is about", reason: `${unsettled.every((i) => i.unsettled.mixed) ? "The names on the primary identity do not settle" : "The primary identity carries only a one-word name, which cannot be compared with"} ${list(unsettled.map((i) => `${i.unsettled.name || "the name"} on ${i.what}`), 2)}. Pick the person you mean.`, action: { kind: "focus", where: "identity", label: "Go to the names" } });
    else if (main && people.filter((v) => !v.primary && v.different).length) { const others = people.filter((v) => !v.primary && v.different); put({ id: "pick:others", score: 40, title: "Confirm who this case is about", reason: `${main.label} was chosen automatically. ${list(others.map((v) => v.label), 3)} ${others.length === 1 ? "uses" : "use"} this handle too. If you mean ${others.length === 1 ? "that person" : "one of them"}, pick the name and the case is filed around it.`, action: { kind: "focus", where: "identity", label: "Go to the names" } }); }
  }

  // 2. leads: a handle or an address to investigate, a domain to open in Recon
  for (const l of ev.items.filter((i) => i.tier === "lead" && i.action && i.lead)) {
    const { kind, value } = l.lead, from = (l.from || []).join(", "), src = l.source || "";
    if (kind === "handle" && (!HANDLE_OK.test(value) || minorGuard(value).blocked)) continue;
    if (kind === "domain" && (adultHost(`https://${value}`) || isPlatformHost(value))) continue;
    const record = /site record/.test(from), proven = /proven on Keybase|verified link/.test(from), guess = /the part before the @/.test(from), shown = /search matched to this address/.test(from);
    const base = { id: l.key, action: { kind: "pivot", pivot: l.action.pivot, value, ...(kind === "handle" ? { type: "username" } : kind === "domain" ? { type: "domain" } : {}), label: l.action.label, via: `${kind === "handle" ? "the handle" : kind === "email" ? "the address" : "the domain"} ${value}`, source: from || src } };
    if (kind === "handle") put({ ...base, score: record ? 95 : proven ? 90 : guess ? 45 : shown ? (/unconfirmed/.test(from) ? 58 : 72) : l.tied ? 80 : 55, title: `Investigate ${value}`,
      reason: record ? "GitHub attributes commits that carry this address to this account. That is GitHub's own record, and the strongest lead in the case."
        : proven ? `Another handle the other side has confirmed (${from}). It is very likely the same person under another name.`
          : guess ? "The part before the @. It is a guess at a handle, not a finding, and may belong to someone else."
            : shown ? `A ${from}. That is weaker than a commit attribution: the profile was not read to confirm it.`
              : `A handle found here: ${from}.${l.tied ? "" : " That profile is not tied to the target, so this is a weaker lead."} It may be the same person under another name.` });
    // An address on a commit under the account's name only (not one the site ties to the account) ranks lower.
    else if (kind === "email") { const weakTie = /the weaker tie/.test(from) && !/ties to this account/.test(from); put({ ...base, score: l.tied ? (weakTie ? 62 : 75) : weakTie ? 44 : 50, title: `Investigate ${value}`, reason: `An address found here: ${from}.${l.tied ? "" : " That profile is not tied to the target, so this is a weaker lead."} An email case can show the accounts, keys and breaches behind it.` }); }
    else if (kind === "domain") put({ ...base, score: /the email's domain/.test(from) ? 65 : l.tied ? 70 : 48, title: `Open ${value} in Recon`, reason: /the email's domain/.test(from) ? "The domain of this address. Its DNS, mail setup and certificates describe the organisation behind it." : `A site found here: ${from}.${l.tied ? "" : " That profile is not tied to the target."} Its registration, DNS and certificates can show who runs it.` });
  }

  // 3. archived copies of a profile tied to the person: the best one that was not asked yet
  const archivable = accounts.filter((i) => i.archive && !i.archive.view && (i.tier === "linked" || i.inPrimary))
    .sort((a, b) => (a.tier === "linked" ? 0 : 1) - (b.tier === "linked" ? 0 : 1) || (b.detail?.count || 0) - (a.detail?.count || 0) || a.what.localeCompare(b.what));
  archivable.slice(0, 2).forEach((i, n) => put({ id: `archive:${i.key}`, score: 60 - n * 8, title: `See archived copies of the ${i.what} profile`, reason: `${i.tier === "linked" ? "Tied to this identity." : "Part of this identity."} An archived copy can show a bio or a link that was removed since. One request to the Internet Archive, which is sent this profile's address.`, action: { kind: "archive", key: i.key, label: "Archived copies" } }));
  const retry = accounts.filter((i) => i.archive?.view?.retry && (i.tier === "linked" || i.inPrimary));
  if (retry.length) put({ id: `archive:${retry[0].key}`, score: 34, title: `Ask the Internet Archive about ${retry[0].what} again`, reason: "It could not be asked last time, so whether it holds copies is unknown.", action: { kind: "archive", key: retry[0].key, label: "Try again" } });

  // 3b. three more lookups for a profile of this identity, each one click and one row. Never for
  //     a row filed as a different person, a record nobody claimed or an adult site: a row has
  //     canCommitEmails, canPostActivity and archiveDiffPairs only when the lookup may be asked.
  const mine = accounts.filter((i) => i.tier === "linked" || i.inPrimary).sort((a, b) => (a.tier === "linked" ? 0 : 1) - (b.tier === "linked" ? 0 : 1) || a.what.localeCompare(b.what));
  const standing = (i) => (i.tier === "linked" ? "Tied to this identity." : "Part of this identity.");
  mine.filter((i) => i.canCommitEmails && !i.commitEmails).slice(0, 2).forEach((i, n) => put({ id: `commits:${i.key}`, score: 58 - n * 8, title: `Read the commit emails of the ${i.what} account`,
    reason: `${standing(i)} A commit in its public repositories can carry an email address. What is found is typed by the commit's author, so it is self-declared and a lead to check, not a confirmed address. At most 5 requests to ${i.what}.`, action: { kind: "commit-emails", key: i.key, label: "Commit emails" } }));
  mine.filter((i) => i.canPostActivity && !i.postActivity).slice(0, 2).forEach((i, n) => put({ id: `posts:${i.key}`, score: 56 - n * 8, title: `Read when the ${i.what} account posts`,
    reason: `${standing(i)} The hours its public posts fall on can show a range of UTC offsets, and whether that range fits the other accounts of this identity. It is a hint and never a place, and it cannot show who is behind the account. A few requests to ${i.what}.`, action: { kind: "post-activity", key: i.key, label: "Post activity" } }));
  mine.filter((i) => i.archiveDiffPairs?.length && !i.archiveDiff).slice(0, 1).forEach((i) => { const pair = i.archiveDiffPairs.find((x) => x.default) || i.archiveDiffPairs[0]; put({ id: `diff:${i.key}`, score: 54, title: `Compare two archived copies of the ${i.what} profile`,
    reason: `${standing(i)} The Internet Archive lists copies from ${i.archive.view.count} days. Comparing the two newest (${pair.label}) shows text and links that were removed or added between them, and a removed link is a lead. Two requests to the Internet Archive.`, action: { kind: "archive-diff", key: i.key, from: pair.from, to: pair.to, label: "Compare copies" } }); });

  // 4. unread accounts two tools agree on
  const unverified = accounts.filter((i) => i.tier === "unverified" && !i.nofind);
  const two = unverified.filter((i) => !i.taken && (i.tools ?? (i.sources || []).length) > 1 && !i.check);
  if (two.length) put({ id: "check:two", score: 52, title: two.length === 1 ? "Check the account two tools agree on" : `Check the ${two.length} accounts two tools agree on`, reason: `${list(two.map((i) => i.what), 4)}: reported by two tools, and nothing was read. Opening the group lets the link check ask each page whether it exists.`, action: { kind: "jump", tier: "unverified", label: "Open Unverified" } });

  // 5. a site that blocked the check, to open by hand
  const blocked = unverified.concat(accounts.filter((i) => i.tier === "unverified" && i.nofind)).filter((i) => /^Blocked by site/.test(i.meta || "") && i.url && i.link_kind !== "none" && !adultHost(i.url));
  uniq(blocked).slice(0, 2).forEach((i, n) => put({ id: `open:${i.key}`, score: 46 - n * 6, title: `Open ${i.what} by hand`, reason: `${i.what} blocked the check, so this account is unknown, not absent. The address is built from the handle and nothing has checked it.`, action: { kind: "open", url: i.url, link_kind: i.link_kind, label: `Open ${i.what}` } }));

  // 6. reverse confirm: one distinctive value, searched by itself. Offered as text to copy, never
  //    as a link: a search address would carry the value in its query.
  const facts = main ? main.facts : [];
  const site = facts.find((f) => f.k === "Website");
  const siteHost = (() => { try { return site ? new URL(/^https?:/i.test(site.v) ? site.v : `https://${site.v}`).hostname.replace(/^www\./, "") : ""; } catch { return ""; } })();
  const keyFact = (ev.facts || []).find((f) => f.k === "OpenPGP key");
  const distinct = siteHost && !isPlatformHost(siteHost) && !adultHost(`https://${siteHost}`) ? { value: siteHost, what: "the personal site", text: `${quoted(siteHost)} -site:${siteHost}` }
    : keyFact ? { value: keyFact.v, what: "the key fingerprint", text: quoted(keyFact.v.replace(/\s+/g, "")) } : null;
  if (distinct) put({ id: `search:${distinct.value}`, score: 42, title: `Search ${distinct.what} on its own`, reason: `Reverse confirm: search ${distinct.value} in a search engine and see whether the results lead back to these accounts. The search is copied as text, so nothing leaves this page until you paste it.`, action: { kind: "copy", text: distinct.text, label: "Copy search" } });

  // 7. a similar handle worth a check
  const sim = ev.items.filter((i) => i.tier === "similar" && i.sim?.state === "new");
  if (sim.length) put({ id: "similar:check", score: 35, title: "Check a handle close to this one", reason: `${plural(sim.length, "similar handle")} ${sim.length === 1 ? "has" : "have"} not been checked (${list(sim.map((i) => i.what), 3)}). A check reads GitHub, the platform check and Bluesky for one handle and says whether its name or picture lines up.`, action: { kind: "jump", tier: "similar", label: "Open Similar handles" } });

  // 8. a source that did not answer
  const cov = type === "username" ? profileCoverage(collected.profiles) : { down: [] };
  const limited = [...cov.down.filter((x) => x.state === "rate_limited").map((x) => x.site), ...(type === "email" ? emailLookupsDown(collected.emailAccounts).filter((x) => x.state === "rate_limited").map((x) => x.name) : [])];
  const failedNames = failed.map((f) => (typeof f === "string" ? f : f?.name)).filter(Boolean);
  if (limited.length || failedNames.length) put({ id: "rerun:gaps", score: failedNames.length ? 38 : 30, title: "Run this case again later", reason: `${[limited.length ? `${list(limited, 4)} ${limited.length === 1 ? "was" : "were"} rate limited` : "", failedNames.length ? `${list(failedNames, 4)} failed` : ""].filter(Boolean).join(", and ")}, so that part of the picture is unknown. A minute is usually enough for a rate limit.`, action: { kind: "rerun", label: "Run again" } });

  // 9. self-audit: what the account holder could do about an exposure. A case marked "This is
  //    me" has the whole list in its own view, so these two hints give way to one pointer to it.
  const commitEmails = facts.filter((f) => f.k === "Commit email");
  const onGitHub = commitEmails.filter((f) => /\bGitHub\b/.test(f.source || "")), onForge = commitEmails.filter((f) => !/\bGitHub\b/.test(f.source || ""));
  const breaches = ev.items.filter((i) => i.tier === "flag" && i.key?.startsWith("breach:"));
  const audit = selfAuditOn(collected, type);
  if (audit && (commitEmails.length || (type === "email" && breaches.length))) put({ id: "audit:footprint", score: 28, tag: "self-audit", title: "Open Reduce your footprint", reason: `You marked this case as being about you. ${[commitEmails.length ? `${plural(commitEmails.length, "address", "addresses")} on public commits` : "", type === "email" && breaches.length ? plural(breaches.length, "known breach", "known breaches") : ""].filter(Boolean).join(" and ")} ${commitEmails.length + (type === "email" ? breaches.length : 0) === 1 ? "is" : "are"} among the things that view lists, each with what to do about it.`, action: { kind: "focus", where: "footprint", label: "Open the view" } });
  if (!audit && commitEmails.length) put({ id: "audit:commit-email", score: 26, tag: "self-audit", title: "If this is your account: hide your commit email", reason: `${plural(commitEmails.length, "address", "addresses")} can be read from this account's public commits.${onGitHub.length ? ' On GitHub: Settings, Emails, then "Keep my email addresses private" and "Block command line pushes that expose my email".' : ""}${onForge.length ? " On GitLab, Codeberg or Gitea.com: choose the private commit address the site offers in the account's email settings, and set it as the address git uses." : ""} Old commits keep the address they were made with.`, action: null });
  if (!audit && type === "email" && breaches.length) put({ id: "audit:breaches", score: 28, tag: "self-audit", title: "If this is your address: change the exposed passwords", reason: `It is in ${plural(breaches.length, "known breach", "known breaches")} (${list(breaches.map((b) => b.what.replace(/^Breach: /, "")), 3)}). Change the password used on ${breaches.length === 1 ? "that site" : "those sites"} and anywhere it was reused, and turn on two-step sign-in.`, action: null });

  out.sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  const steps = readSteps(collected.nextSteps);
  const open = out.filter((s) => !steps[s.id]);
  const held = (state) => Object.entries(steps).filter(([, s]) => s.state === state).map(([sid, s]) => ({ id: sid, title: out.find((x) => x.id === sid)?.title || s.title, at: s.at, live: out.find((x) => x.id === sid) || null }));
  return { top: open.slice(0, SUGGEST_CAP), more: open.slice(SUGGEST_CAP), parked: held("parked"), followed: held("followed"), note: "" };
}

// ---- for the exports and the AI ----------------------------------------------------------------
export function analysisMarkdown(a, s) {
  const out = [];
  if (a?.headline) out.push("## What the evidence says", "_Built from rules, with no model involved._", `- **How firmly the accounts are tied to one identity:** ${a.headline}`, ...a.lines.map((l) => `- ${l.level === "flag" ? "**Check:** " : ""}${l.text}`), "");
  const step = (x) => `- **${x.title}.** ${x.reason}${x.action?.kind === "copy" ? ` Search text: \`${x.action.text}\`` : ""}`;
  if (s && (s.top.length || s.more.length)) out.push("## Suggested next steps", "_Ranked by rules. Each is one step the investigator starts by hand; none was followed automatically._", ...[...s.top, ...s.more].map(step), "");
  if (s?.note) out.push("## Suggested next steps", `- ${s.note}`, "");
  if (s?.followed.length) out.push("## Leads followed from this case", ...s.followed.map((x) => `- ${x.title}`), "");
  if (s?.parked.length) out.push("## Parked leads", ...s.parked.map((x) => `- ${x.title} (parked by the investigator)`), "");
  return out;
}
// What the model is told. The pick is named as the investigator's judgment, with the automatic
// choice beside it, and the assessment is given as the place to start from.
// A pick that came with a case file is told as that: its author picked, not the person asking.
export function analysisForAi(a, identity, trail = "") {
  if (!a || (!a.headline && !identity?.views?.length)) return null;
  const main = identity?.views?.find((v) => v.primary) || null;
  const byFile = !!(identity?.picked && identity.pickFile);
  return {
    identity_choice: {
      mode: identity?.picked ? (byFile ? "picked_in_case_file" : "picked_by_investigator") : main ? "automatic" : "none",
      primary: main ? main.label : "", primary_accounts: main ? main.sites.slice(0, 12) : [],
      automatic_choice: identity?.autoLabel || "", automatic_reason: identity?.autoWhy || "",
      note: byFile ? "This identity was picked in the case file the case was opened from. It is the judgment of whoever made that file, not a finding of the tool. Account statuses are filed against the picked identity." : identity?.picked ? "The investigator picked this identity as the person the case is about. It is their judgment, not a finding of the tool. Account statuses are filed against the picked identity." : main ? "Chosen by the tool's rules, not by the investigator." : "Nobody is chosen: nothing ties any profile to the target.",
    },
    strength: a.strength, headline: a.headline, lines: a.lines.map((l) => `${l.level === "flag" ? "CHECK: " : ""}${l.text}`).slice(0, 12),
    ...(trail ? { pivot_trail: trail } : {}),
  };
}
