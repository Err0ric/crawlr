// The self-audit rules ("Reduce your footprint", selfaudit.js): what a case found, turned into a
// ranked list of things the account holder can do. Each rule fires on its input and not without
// it; only rows of the primary identity are "yours"; a row filed as a different person and a
// Launchpad record nobody claimed are never "yours"; adult rows never appear; a failed source is a
// gap and never "nothing exposed"; the wording is advice.
// Pure functions through the real buildEvidence. No browser, no network. Names are invented.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {}, createElement: () => ({ innerHTML: "" }) };
const J = "../../static/v2/js/";
const { buildEvidence } = await import(J + "evidence.js");
const SA = await import(J + "selfaudit.js");
const { selfAudit, selfAuditMarkdown, selfAuditText, SELF_AUDIT_TITLE, SELF_AUDIT_NOTE, SELF_AUDIT_GROUPS } = SA;

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/deep.json", import.meta.url), "utf8"));
const adultFx = JSON.parse(fs.readFileSync(new URL("./fixtures/adult.json", import.meta.url), "utf8"));
const U = fx.cases[0], E = fx.cases[1], H = U.target, M = E.target;
const clone = (v) => JSON.parse(JSON.stringify(v));
const audit = (c, t = H, type = "username") => selfAudit(buildEvidence(c, t, type), c, { target: t, type });
const item = (r, id) => r.items.find((i) => i.id === id);
const kinds = (r, kind) => r.items.filter((i) => i.kind === kind);
const labels = (it) => (it?.where || []).map((w) => w.label);
const words = (r) => JSON.stringify(r);
const itemText = (r) => r.items.flatMap((i) => [i.title, i.exposed, i.fix, i.why || "", ...i.where.map((w) => w.label)]).join("\n");
// The fixture's GitLab account carries another person's name. Renamed, it is the target's own.
const OWN = () => JSON.parse(JSON.stringify(U.collected).replaceAll("Petra Novak", "Sam Example").replaceAll("Brno", "Leeds").replaceAll("Kovo Labs", "Tidepool Lab"));
const CE = (site, host, name, emails, x = {}) => ({ site, site_name: name, username: H, state: "found", cached: false, handle: H, profile_url: `https://${host}/${H}`, display_name: "Sam Example", emails, emails_state: "found", complete: true, sections: { account: "found", repos: "ok" },
  repos: [{ name: `${H}/maps`, url: `https://${host}/${H}/maps`, fork: false, state: "ok", commits_seen: 6 }], counts: { repos_listed: 1, repos_read: 1, commits_seen: 6, own: 5, noreply: 0, other_authors: 1 }, ...x });
const addr = (email, how = "forge_attributed") => ({ email, name: "Sam Example", how, commits: 3, first_commit: "2026-01-15T09:00:00Z", last_commit: "2026-10-30T09:00:00Z", repos: [`${H}/maps`] });
const GITLAB = (emails, x) => ({ "acct:gitlab": CE("gitlab", "gitlab.com", "GitLab", emails, x) });
const ARCH = (url, x = {}) => ({ url, state: "ok", count: 9, first: "2015-01-01T00:00:00Z", last: "2024-01-02T03:04:05Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }, { timestamp: "2024-01-02T03:04:05Z" }], ...x });
const side = (ts) => ({ state: "ok", timestamp: ts, asked: ts, exact: true, bytes: 64235, truncated: false, title: "samexample", text_lines: 68, links: 28 });
const DIFF = (url, x = {}) => ({ url, state: "ok", from: side("2019-03-04T05:06:07Z"), to: side("2024-01-02T03:04:05Z"), removed: { text: ["Night shift cartographer at Example Maps."], text_total: 1, links: [], links_total: 0 }, added: { text: ["S E"], text_total: 1, links: [], links_total: 0 }, complete: true, swapped: false, cached: false, ...x });
const HOURS = [0, 0, 0, 0, 0, 0, 1, 4, 11, 14, 12, 9, 6, 10, 13, 15, 12, 9, 8, 6, 4, 2, 1, 0];
const POSTS = (x = {}) => ({ site: "mastodon", site_name: "Mastodon", username: H, instance: "mastodon.social", found: true, state: "ok", cached: false, complete: true, pages: 2, events: 137, window: { first: "2025-11-18T08:04:43Z", last: "2026-11-16T11:05:27Z", days: 364, active_days: 73 }, hours_utc: HOURS.slice(), weekdays_utc: [29, 31, 27, 24, 19, 4, 3], types: [{ type: "post", count: 137 }],
  estimate: { utc_offset_from: -1, utc_offset_to: 2, utc_offsets: [-1, 0, 1, 2], label: "Lisbon", quiet_start_hour: 23, quiet_end_hour: 6, quiet_events: 1, basis: "Lives in Lisbon." }, read: { posts: 137, outside_window: 0, capped: false, available: 137 }, ...x });
const FAIL = { error: "The source timed out.", error_code: "timeout" };

// ---- 1. the shape, and the fixed words ---------------------------------------------------------------------
const base = audit(U.collected);
{
  ok(SELF_AUDIT_TITLE === "Reduce your footprint" && /no AI/.test(SELF_AUDIT_NOTE) && /advice, not a guarantee/.test(SELF_AUDIT_NOTE) && /could see/.test(SELF_AUDIT_NOTE) && /failed may hide more/.test(SELF_AUDIT_NOTE), "the title and the note: rules, no AI, advice, and only what the sources could see");
  ok(base.items.length > 0 && Array.isArray(base.gaps) && base.counts.ties + base.counts.contact + base.counts.other === base.items.length, "a username case has a list, gaps and counts that add up");
  const groups = Object.values(SELF_AUDIT_GROUPS);
  ok(base.items.every((i) => typeof i.id === "string" && i.id && typeof i.kind === "string" && typeof i.title === "string" && i.title && typeof i.exposed === "string" && /[.]$/.test(i.exposed) && Array.isArray(i.where) && typeof i.fix === "string" && i.fix && Number.isFinite(i.weight) && groups.includes(i.group) && (!("why" in i) || (typeof i.why === "string" && i.why))), "every item has an id, a kind, a title, what is exposed, where, a fix, a weight and a group");
  ok(base.items.every((i) => i.where.every((w) => typeof w.label === "string" && w.label && (!("url" in w) || (/^https:\/\//.test(w.url) && typeof w.link_kind === "string" && w.link_kind !== "none")))), "a place is a label, with a link and its kind only when it has one");
  ok(base.items.every((i, x) => x === 0 || base.items[x - 1].weight >= i.weight), "the list is ranked by weight");
  const again = audit(clone(U.collected));
  ok(new Set(base.items.map((i) => i.id)).size === base.items.length && again.items.map((i) => i.id).join() === base.items.map((i) => i.id).join() && words(again) === words(base), "ids are unique, and the same case gives the same list");
  const ev = buildEvidence(U.collected, H, "username"), rowUrls = new Map(ev.items.filter((i) => i.url).map((i) => [i.url, i.link_kind]));
  ok(base.items.every((i) => i.where.every((w) => !w.url || rowUrls.get(w.url) === w.link_kind)), "a link is a row's own link with the row's own kind, never one built here");
}

// ---- 2. commit emails --------------------------------------------------------------------------------------
{
  ok(kinds(base, "commit-email").length === 0, "no commit address was found, so no item speaks of one");
  const c = { ...OWN(), commitEmails: GITLAB([addr("sam@example.org"), addr("sam.old@example.com", "author_line_match")]) };
  const r = audit(c), a = item(r, "commit-email:sam@example.org"), b = item(r, "commit-email:sam.old@example.com");
  ok(a && b && kinds(r, "commit-email").length === 2, "one item per address read from a GitLab row of the primary identity");
  ok(/sam@example\.org can be read from public commits on GitLab\./.test(a.exposed) && /links those commits to your account/.test(a.exposed) && labels(a).join() === "GitLab (samexample/maps)" && a.where[0].url === "https://gitlab.com/samexample" && a.where[0].link_kind === "verified_profile" && !a.where[0].check, "it says the address, the forge, the repository and how it is tied");
  ok(/private commit email/.test(a.fix) && /git config user\.email/.test(a.fix) && !/GitHub/.test(a.fix) && /already pushed keep the old address/.test(a.why) && /clone and fork/.test(a.why) && a.group === SELF_AUDIT_GROUPS.contact, "the fix names GitLab's private commit email and git config, and why old commits keep the address");
  ok(/weaker tie/.test(b.exposed) && a.weight > b.weight, "an address the forge attributes outranks one matched by the author line");
  ok(r.items[0].id === "commit-email:sam@example.org", "and it is the first thing on the list");
  // The same address on GitHub too: one item, both places, both sets of steps.
  const c2 = clone(c); c2.githubDeep.commit_emails = [{ email: "Sam@Example.org", name: "Sam Example", repo: "samexample/tilecut" }, { email: "12345+samexample@users.noreply.github.com", name: "Sam", repo: "samexample/tilecut" }];
  const r2 = audit(c2), a2 = item(r2, "commit-email:sam@example.org");
  ok(kinds(r2, "commit-email").length === 2 && labels(a2).join("|") === "GitLab (samexample/maps)|GitHub (samexample/tilecut)" && /Keep my email addresses private/.test(a2.fix) && /Block command line pushes that expose my email/.test(a2.fix) && /On GitLab/.test(a2.fix) && a2.weight > a.weight, "the same address on two forges is one item that lists both, and a noreply placeholder is no address");
  const gh = audit({ ...U.collected, githubDeep: { ...U.collected.githubDeep, commit_emails: [{ email: "sam@example.org", repo: "samexample/tilecut" }] } });
  ok(item(gh, "commit-email:sam@example.org") && /On GitHub: Settings, Emails/.test(item(gh, "commit-email:sam@example.org").fix) && !/GitLab|Codeberg/.test(item(gh, "commit-email:sam@example.org").fix), "GitHub's commit emails give an item with GitHub's own steps");
  const cb = audit({ ...OWN(), commitEmails: GITLAB([], { emails_state: "none" }) });
  ok(kinds(cb, "commit-email").length === 0 && !cb.gaps.some((g) => /commits on GitLab/.test(g)), "commits that were read and carry no address are neither an item nor a gap");
  const unk = audit({ ...OWN(), commitEmails: GITLAB([], { emails_state: "unknown", complete: false, sections: { account: "found", repos: "rate_limited" }, repos: [] }) });
  ok(kinds(unk, "commit-email").length === 0 && unk.gaps.some((g) => /commits on GitLab could not be read/.test(g) && /unknown/.test(g)), "commits that could not be read are a gap: unknown, never 'no address'");
  const part = audit({ ...OWN(), commitEmails: GITLAB([addr("sam@example.org")], { complete: false, sections: { account: "found", repos: "ok" }, repos: [{ name: `${H}/maps`, state: "ok", commits_seen: 6 }, { name: `${H}/bread`, state: "failed", commits_seen: 0 }] }) });
  ok(item(part, "commit-email:sam@example.org") && part.gaps.some((g) => /read in part/.test(g) && /maybe more/.test(g)), "a partial read gives the item and says there may be more");
  ok(audit(OWN()).gaps.some((g) => /Commit emails were not looked up for GitLab/.test(g)) && !base.gaps.some((g) => /Commit emails were not looked up/.test(g)), "a forge row of yours that was never asked is a gap; another person's forge row is not");
}

// ---- 3. a row filed as a different person is never yours -------------------------------------------------
{
  const c = { ...U.collected, commitEmails: GITLAB([addr("petra@example.net")]), archives: { "acct:gitlab": ARCH("https://gitlab.com/samexample") }, postActivity: {} };
  const ev = buildEvidence(c, H, "username"), r = selfAudit(ev, c, { target: H, type: "username" });
  ok(ev.items.find((i) => i.key === "acct:gitlab").tier === "different", "the fixture's GitLab account is filed as a different person");
  ok(kinds(r, "commit-email").length === 0 && kinds(r, "archive").length === 0 && !/petra@example\.net/.test(words(r)), "its commit address and its archived copies are not on the list");
  const un = item(r, "unrecognised-accounts");
  ok(un && un.title === "Accounts under your handle that you may not recognise" && labels(un).includes("GitLab") && /may be someone else's: the same handle, another person/.test(un.exposed) && /If one is yours and forgotten, sign in and close it or clean it up/.test(un.fix) && /If it is not yours there is nothing to fix/.test(un.fix), "it lands in the one item about accounts that may be someone else's");
  ok(!/report|take over|takedown|impersonat|claim it/i.test([un.title, un.exposed, un.fix, un.why || ""].join(" ")), "which never suggests reporting or taking over another person's account");
  ok(r.items.filter((i) => i.id !== "unrecognised-accounts").every((i) => !labels(i).some((l) => /^GitLab/.test(l)) && !/GitLab/.test(i.exposed)), "and no other item names it");
  ok(!item(audit(OWN()), "unrecognised-accounts"), "with no such row there is no such item");
}

// ---- 4. a Launchpad record nobody claimed ------------------------------------------------------------------
{
  const c = clone(U.collected);
  c.profiles.profiles.push({ site: "Launchpad", source: "launchpad", handle: H, url: `https://launchpad.net/~${H}`, state: "found", display_name: "Sam Example", name: "Sam Example", bio: "", location: "Leeds", emails: ["sam.lp@example.org"], accounts: [], links: [], stats: {}, items: [], note: "not an active account" });
  c.profiles.sources.launchpad = { site: "Launchpad", state: "found" };
  c.archives = { "acct:launchpad": ARCH(`https://launchpad.net/~${H}`) };
  const r = audit(c), un = item(r, "unrecognised-accounts");
  ok(un && labels(un).includes("Launchpad") && /Launchpad makes a record by itself/.test(un.exposed) && /nobody may have signed up/.test(un.exposed), "an unclaimed Launchpad record is in the unrecognised item, with why");
  ok(r.items.filter((i) => i.id !== "unrecognised-accounts").every((i) => !labels(i).includes("Launchpad") && !/Launchpad/.test(i.exposed)) && !/sam\.lp@example\.org/.test(words(r)) && kinds(r, "archive").length === 0, "it is not yours: not in the handle count, not an address of yours, not an archived profile of yours");
  ok(!/Launchpad makes/.test(item(base, "unrecognised-accounts").exposed), "the Launchpad sentence is only there for such a record");
}

// ---- 5. the other rules, each on its input and not without it --------------------------------------------
{
  // an address on a public profile
  const pe = audit({ ...U.collected, github: { ...U.collected.github, email: "sam@example.org" } }), a = item(pe, "profile-email:sam@example.org");
  ok(a && labels(a).join() === "GitHub" && !a.where[0].check && /Remove it from the profile/.test(a.fix) && /contact alias/.test(a.fix) && a.group === SELF_AUDIT_GROUPS.contact, "an address on a profile of yours: remove it or use an alias");
  const npm = item(base, "profile-email:sam@samexample.example");
  ok(npm && npm.where[0].check === true && /Nothing in the case ties npm to you, so check that it is yours first/.test(npm.exposed) && npm.weight < a.weight, "an address on a profile that only fits is 'probably yours, check', and weighs less");
  const none = clone(U.collected); for (const p of none.profiles.profiles) p.emails = [];
  ok(kinds(audit(none), "profile-email").length === 0, "no address on a profile, no item");

  // the same picture
  const av = item(base, "same-picture");
  ok(av && labels(av).join() === "GitHub,Keybase,Mastodon" && /on your GitHub, Keybase and Mastodon accounts/.test(av.exposed) && /ties accounts together even when the handles or names differ/.test(av.exposed) && /different pictures/.test(av.fix) && /Archived copies of a profile keep its old picture/.test(av.why) && av.group === SELF_AUDIT_GROUPS.ties, "the same picture on three accounts ties them, and archives keep old pictures");
  const plain = clone(U.collected); delete plain.avatarHash; for (const p of plain.profiles.profiles) { p.avatar_hash = ""; p.thumb = ""; }
  ok(!item(audit(plain), "same-picture"), "no matching picture, no item");

  // the same handle
  const hd = item(base, "same-handle");
  ok(hd && /Your handle samexample is on 7 sites the case ties to you/.test(hd.exposed) && /3 more accounts fit and nothing ties them to you/.test(hd.exposed) && /what made this search possible/.test(hd.exposed) && /different handles/.test(hd.fix) && /old links/.test(hd.why) && /archived copies/.test(hd.why), "the handle item counts your rows, and keeps the ones that only fit apart");
  ok(hd.where.filter((w) => w.check).map((w) => w.label).sort().join() === "Lichess,Reddit,npm" && !labels(hd).includes("GitLab") && !labels(hd).includes("Twitch"), "it lists your rows and the ones to check, never a different person's row or an unread one");
  const one = audit({ github: U.collected.github });
  ok(!item(one, "same-handle") && !item(one, "same-picture") && !item(one, "cross-links") && !item(one, "unrecognised-accounts") && !item(one, "unverified-accounts"), "one account alone: no handle, picture, cross-link, unrecognised or unverified item");

  // cross-links and proofs
  const cl = item(base, "cross-links");
  ok(cl && /a Keybase proof ties the GitHub account to the Keybase profile/.test(cl.exposed) && /revoked on Keybase/.test(cl.fix) && /proof post deleted/.test(cl.fix) && labels(cl).includes("Keybase") && labels(cl).includes("Hacker News") && cl.group === SELF_AUDIT_GROUPS.ties, "proofs and verified links are deliberate ties, and a Keybase proof is revoked on Keybase");

  // self-declared details
  const dt = item(base, "profile-details"), d1 = item(one, "profile-details");
  ok(dt && /name Sam Example \(/.test(dt.exposed) && /location Leeds \(GitHub/.test(dt.exposed) && /employer Tidepool Lab \(GitHub\)/.test(dt.exposed) && /Trim what does not need to be public/.test(dt.fix) && /a Recon run of samexample\.example/.test(dt.fix) && !/https?:/.test(dt.fix), "details: which fact is on which sites, and a Recon run of the personal domain, as words");
  ok(d1 && labels(d1).join() === "GitHub" && !item(audit({ sherlock: U.collected.sherlock }), "profile-details"), "one profile with details has the item; a case with no read profile has none");
  ok(!/Petra Novak|Brno|Kovo Labs/.test(words(base)), "another person's name, place and employer are nowhere on the list");

  // activity hours
  const act = item(base, "activity-hours");
  ok(act && labels(act).join() === "GitHub" && /not a place/.test(act.exposed) && /Scheduling posts or pushing commits in batches/.test(act.fix) && /already public/.test(act.why) && act === base.items.at(-1), "activity hours: low on the list, never a place, and nothing takes back old timestamps");
  const pa = audit({ ...U.collected, postActivity: { "acct:mastodon.social": POSTS(), "acct:gitlab": POSTS({ instance: "mastodon.social" }) } }), act2 = item(pa, "activity-hours");
  ok(act2 && labels(act2).join() === "GitHub,Mastodon" && /Mastodon: UTC/.test(act2.exposed) && !/Lisbon/.test(words(pa)), "a post activity reading of your row joins it, and a place written into the answer does not");
  const quiet = clone(U.collected); delete quiet.githubActivity;
  ok(!item(audit(quiet), "activity-hours") && !item(audit({ ...quiet, postActivity: { "acct:mastodon.social": POSTS({ estimate: null }) } }), "activity-hours"), "no reading with an offset estimate, no item");
  ok(!item(audit({ ...quiet, postActivity: { "acct:mastodon.social": { site: "mastodon", instance: "mastodon.social", username: H, ...FAIL } } }), "activity-hours") && audit({ ...quiet, postActivity: { "acct:mastodon.social": { site: "mastodon", instance: "mastodon.social", username: H, ...FAIL } } }).gaps.some((g) => /Post activity on Mastodon could not be read/.test(g)), "a reading that failed is a gap");

  // archived copies
  ok(kinds(base, "archive").length === 0, "no archive answer, no archive item");
  const ar = audit({ ...U.collected, archives: { "acct:github": ARCH("https://github.com/samexample"), "acct:lichess": ARCH("https://lichess.org/@/samexample", { count: 1, first: "2020-02-02T00:00:00Z", last: "2020-02-02T00:00:00Z", snapshots: [{ timestamp: "2020-02-02T00:00:00Z" }] }) } }), ai = item(ar, "archive-copies");
  ok(ai && /GitHub \(9 days, 2015-01-01 to 2024-01-02\)/.test(ai.exposed) && /Lichess \(1 day, 2020-02-02\)/.test(ai.exposed) && /info@archive\.org/.test(ai.fix) && /proof that it is yours/.test(ai.fix) && /It is a request, and the archive decides/.test(ai.fix) && /does not delete the copies already captured/.test(ai.why), "archived copies: what is held, how removal is requested, and that it is a request");
  ok(ai.where.find((w) => w.label === "Lichess").check === true && !/later taken off/.test(ai.exposed), "a profile that only fits is marked to check, and nothing is said about removed text without a comparison");
  const df = audit({ ...U.collected, archives: { "acct:github": ARCH("https://github.com/samexample") }, archiveDiffs: { "acct:github": DIFF("https://github.com/samexample") } });
  ok(/shows text or links that were later taken off the live page/.test(item(df, "archive-copies").exposed) && item(df, "archive-copies").weight > ai.weight && !/Night shift cartographer/.test(words(df)), "a comparison with removed text says the old text is still readable, without quoting it");
  const down = audit({ ...U.collected, archives: { "acct:github": { url: "https://github.com/samexample", state: "failed", ...FAIL } } });
  ok(kinds(down, "archive").length === 0 && down.gaps.some((g) => /Internet Archive could not be asked about GitHub/.test(g) && /unknown/.test(g)), "an archive lookup that failed is a gap, not 'no copies'");
  ok(kinds(audit({ ...U.collected, archives: { "acct:github": { url: "https://github.com/samexample", state: "none" } } }), "archive").length === 0, "an archive that holds no copy gives no item");

  // rows nothing read
  const uv = item(base, "unverified-accounts");
  ok(uv && /^9 more accounts under your handle were reported by a tool and never read/.test(uv.exposed) && uv.where.length === 0 && !/Duolingo|Twitch|Flickr|Patreon/.test(words(uv)) && /Open the ones you recognise/.test(uv.fix), "unread rows are one item with a count, and are never listed as yours");
}

// ---- 6. ranking ----------------------------------------------------------------------------------------------
{
  const r = audit({ ...OWN(), commitEmails: GITLAB([addr("sam@example.org")]), github: { ...U.collected.github, email: "hello@example.org" } });
  const at = (id) => r.items.findIndex((i) => i.id === id);
  ok(at("commit-email:sam@example.org") === 0 && at("commit-email:sam@example.org") < at("activity-hours") && item(r, "commit-email:sam@example.org").weight > item(r, "activity-hours").weight, "a forge-attributed commit email outranks activity hours");
  ok(at("profile-email:hello@example.org") < at("same-picture") && at("same-picture") < at("profile-details") && at("profile-details") < at("unverified-accounts") && at("unverified-accounts") < at("activity-hours"), "contact details and ties come before things that are only worth knowing");
  ok(r.counts.ties === 3 && r.counts.contact === kinds(r, "commit-email").length + kinds(r, "profile-email").length && /^\d+ things to look at: 3 tie accounts together, \d+ expose contact details\.( \d+ parts? of the picture (is|are) unknown\.)?$/.test(selfAuditText(r)), "the counts and the one-line summary say how many of each");
}

// ---- 7. an email case ----------------------------------------------------------------------------------------
{
  const r = audit(E.collected, M, "email");
  const mf = item(r, "breach:mapforum"), ts = item(r, "breach:trailshare");
  ok(mf && ts && /MapForum breach \(2019\), with email addresses and passwords/.test(mf.exposed) && /Change the password you used there, and everywhere you reused it/.test(mf.fix) && /password manager/.test(mf.fix) && /two-factor sign-in/.test(mf.fix) && mf.weight > ts.weight && !("why" in mf), "up to three breaches are one item each: change the password, a password manager, two-factor sign-in");
  const many = clone(E.collected); many.hibp.breaches.push({ name: "PedalPost", year: 2021, data_classes: ["Email addresses", "Phone numbers", "Physical addresses"] }, { name: "GearSwap", year: 2020, data_classes: ["Email addresses"] });
  const g = audit(many, M, "email"), all = item(g, "breaches");
  ok(all && kinds(g, "breach").length === 1 && labels(all).length === 4 && /Your address is in 4 known breaches/.test(all.exposed) && /phone numbers and physical addresses/.test(all.why) && /cannot be changed like a password, so expect phishing that quotes them/.test(all.why), "more than three are grouped, and leaked phone numbers and addresses are named as things that cannot be changed");
  ok(kinds(audit({ ...E.collected, hibp: { email: M, breaches: [] } }, M, "email"), "breach").length === 0, "no breach, no item");
  const hd = audit({ ...E.collected, hibp: FAIL }, M, "email");
  ok(kinds(hd, "breach").length === 0 && hd.gaps.some((x) => /^Breaches failed/.test(x) && /unknown/.test(x)) && audit((({ hibp, ...rest }) => rest)(E.collected), M, "email").gaps.some((x) => /breach check did not run/.test(x)), "a breach check that failed or did not run is a gap");
  const key = kinds(r, "pgp-key")[0];
  ok(kinds(r, "pgp-key").length === 1 && /carries the name Mara Lindqvist and 1 other address \(mara@lindqvist\.example\)/.test(key.exposed) && /only after its owner confirmed it by mail/.test(key.exposed) && /"Manage key" takes an address out of the search/.test(key.fix) && /stays in every copy of the key held elsewhere/.test(key.why) && key.where[0].label === "keys.openpgp.org" && /^https:\/\/keys\.openpgp\.org\/vks\/v1\/by-fingerprint\/[0-9A-F]{40}$/.test(key.where[0].url) && !/revoked/.test(key.exposed), "a key with a name: what the key server lists, how an address is taken out of the search, and what stays");
  const rv = clone(E.collected); rv.emailAccounts.keys[0].revoked = true;
  ok(/The key is revoked, and it is still published/.test(kinds(audit(rv, M, "email"), "pgp-key")[0].exposed), "a revoked key is said to be revoked");
  const nk = clone(E.collected); nk.emailAccounts.keys = [];
  ok(kinds(audit(nk, M, "email"), "pgp-key").length === 0, "no key, no item");
  const ce = item(r, `commit-email:${M}`);
  ok(ce && labels(ce).join("|") === "GitHub (mara-lind)|Commits GitHub ties to no account" && ce.where[0].url === "https://github.com/mara-lind" && /Keep my email addresses private/.test(ce.fix) && r.items[0] === ce, "the account GitHub attributes commits with the address to: the address is in public commits, first on the list");
  ok(!labels(ce).some((l) => /tidepool-lab/.test(l)) && !item(r, "same-handle") && item(r, "profile-details") && labels(item(r, "profile-details")).join() === "Gravatar", "a search match nobody read is not a place of yours, an email case has no handle item, and Gravatar's details are yours");
  const lk = clone(E.collected); lk.emailAccounts.sources.openpgp = { state: "failed", ...FAIL };
  ok(audit(lk, M, "email").gaps.some((x) => /keys\.openpgp\.org \(failed\) did not answer/.test(x)), "a key server that did not answer is a gap");
}

// ---- 8. adult and dating sites never appear --------------------------------------------------------------
{
  const c = adultFx.collected, t = adultFx.target, ev = buildEvidence(c, t, "username");
  const adult = ev.items.filter((i) => i.tier === "adult");
  const r = selfAudit(ev, c, { target: t, type: "username" }), out = `${words(r)}\n${selfAuditMarkdown(r, { target: t }).join("\n")}\n${selfAuditText(r)}`.toLowerCase();
  const names = uniq([...adult.map((i) => String(i.what)), ...[...(c.sherlock.results || []), ...(c.maigret.results || []), ...(c.adultCheck?.results || [])].filter((x) => x.adult || /adult|dating/.test(x.category || "")).flatMap((x) => [x.site || x.name || x.platform || "", (() => { try { return new URL(x.url).hostname; } catch { return ""; } })()])]).filter((x) => x && x.length > 3);
  ok(adult.length > 0 && names.length > 5 && r.items.length > 0, "the adult fixture has adult rows, and the case still has a list");
  ok(names.every((x) => !out.includes(x.toLowerCase())) && !/onlyfans|fansly|adult|dating|escort|cam\b/.test(out), "no adult or dating site, by name or by host, is anywhere in the output");
}
function uniq(a) { return [...new Set(a)]; }

// ---- 9. a failed source is a gap, never "nothing exposed" ------------------------------------------------
{
  const r = audit({ ...U.collected, maigret: FAIL });
  ok(r.gaps.some((g) => /^Maigret failed, so what it would have shown is unknown\./.test(g)), "a source that failed is named in a gap sentence");
  ok(base.gaps.some((g) => /profile sources? did not answer/.test(g) && /Lobsters: blocked by site/.test(g) && /unknown, not absent/.test(g)) && base.gaps.some((g) => /^Twitch blocked the check/.test(g)), "sites that blocked or did not answer are gaps: unknown, not absent");
  const empty = audit({ sherlock: FAIL, maigret: FAIL, profiles: FAIL });
  const said = `${selfAuditText(empty)}\n${selfAuditMarkdown(empty, { target: H }).join("\n")}`;
  ok(empty.items.length === 0 && empty.gaps.length === 1 && /Sherlock, Maigret and Profile sources failed/.test(empty.gaps[0]), "a case where everything failed has no items and says what failed");
  ok(/found nothing to act on in what these sources could see\. 1 part of the picture is unknown\./.test(selfAuditText(empty)) && !/nothing (is |was )?exposed|no exposure|you are (safe|clean)|all clear/i.test(said) && /What this list could not see:/.test(said) && /Sherlock, Maigret and Profile sources failed/.test(said), "and neither the summary nor the export reads the empty list as nothing exposed");
  const np = audit({ profiles: { username: H, profiles: U.collected.profiles.profiles.filter((p) => ["lichess", "hackernews"].includes(p.source)), sources: U.collected.profiles.sources } });
  ok(buildEvidence({ profiles: { username: H, profiles: U.collected.profiles.profiles.filter((p) => ["lichess", "hackernews"].includes(p.source)), sources: U.collected.profiles.sources } }, H, "username").identity.primary === null ? np.gaps.some((g) => /cannot tell which are yours/.test(g)) || np.items.every((i) => i.where.every((w) => w.check || !w.url)) : true, "with no primary identity nothing is called yours without a check");
  ok(base.gaps.every((g) => typeof g === "string" && /[.]$/.test(g)) && !base.gaps.some((g) => /GitHub details were not read/.test(g)) && audit((({ githubDeep, ...rest }) => rest)(U.collected)).gaps.some((g) => /GitHub details were not read/.test(g)), "a lookup that was not asked for is a gap too");
}

// ---- 10. other case types have no list -------------------------------------------------------------------
{
  for (const [t, type, c] of [["example.org", "domain", { dns: {} }], ["44d88612fea8a8f36de82e1278abb02f", "hash", { hash: { hash: "44d88612fea8a8f36de82e1278abb02f" } }], ["+44 20 7946 0958", "phone", { phone: {} }], ["Sam Example", "name", { nameResult: {} }], ["8.8.8.8", "ip", {}]]) {
    const r = selfAudit(buildEvidence(c, t, type), c, { target: t, type });
    ok(r.items.length === 0 && r.gaps.length === 0 && r.counts.ties + r.counts.contact + r.counts.other === 0, `a ${type} case has no list`);
  }
  ok(selfAudit(null, {}, { target: H, type: "username" }).items.length === 0 && selfAudit(buildEvidence(U.collected, H, "username"), null, { target: H, type: "username" }).items.length === 0 && selfAuditMarkdown(null).length === 0, "nothing to read gives nothing");
}

// ---- 11. wording -----------------------------------------------------------------------------------------------
{
  const big = audit({ ...OWN(), commitEmails: GITLAB([addr("sam@example.org"), addr("sam.old@example.com", "author_line_match")]), github: { ...U.collected.github, email: "hello@example.org" }, archives: { "acct:github": ARCH("https://github.com/samexample") }, archiveDiffs: { "acct:github": DIFF("https://github.com/samexample") }, postActivity: { "acct:mastodon.social": POSTS() } });
  const many = clone(E.collected); many.hibp.breaches.push({ name: "PedalPost", year: 2021, data_classes: ["Phone numbers"] }, { name: "GearSwap", year: 2020, data_classes: [] }); many.emailAccounts.keys[0].revoked = true;
  const lists = [base, big, audit(U.collected), audit(E.collected, M, "email"), audit(many, M, "email")];
  const text = lists.map((r) => `${itemText(r)}\n${r.gaps.join("\n")}\n${selfAuditText(r)}`).join("\n") + `\n${SELF_AUDIT_NOTE}`;
  ok(!/[\u2014\u2013]/.test(text) && !/[\u2014\u2013]/.test(fs.readFileSync(new URL(`${J}selfaudit.js`, import.meta.url), "utf8")), "no em dash in any sentence or in the module");
  ok(!/will remove|removes all|\bsafe\b|\bsecure[ds]?\b|protects you|cannot be found|untraceable|anonymous|fully|completely|permanently|guaranteed/i.test(lists.map(itemText).join("\n")) && !/guarantee/i.test(lists.map(itemText).join("\n")), "no item promises anything: no 'will remove', no 'safe'");
  ok(!/\b(?!WHOIS\b|HTTPS?\b)[A-Z]{5,}\b/.test(text) && !/!/.test(text) && !/stalk|doxx|hackers?\b(?! News)|criminal|danger|attack|victim|urgent|immediately|at risk/i.test(text), "no capitals for emphasis and no fear language");
  ok(!/people.search|data broker|background check|spokeo|whitepages|opt.out/i.test(text), "no people-search site or data broker is named");
  ok(lists.every((r) => r.items.every((i) => !/https?:\/\//.test(`${i.fix} ${i.why || ""} ${i.exposed}`) && !/[?&][a-z_]+=/.test(`${i.fix} ${i.why || ""}`))), "no fix carries a web address, so none carries a handle or an address in a query");
  ok(lists.every((r) => r.items.every((i) => /\byou(r)?\b/i.test(`${i.exposed} ${i.fix}`))) && lists.every((r) => r.items.every((i) => i.title[0] === i.title[0].toUpperCase() && !/[.]$/.test(i.title))), "every item speaks to the account holder, with a sentence case title");
  ok(lists.every((r) => r.items.every((i) => i.fix.split(/(?<=[.])\s+(?=[A-Z"])/).length <= 6)), "a fix is a few sentences, not an essay");
}

// ---- 12. the Markdown export -----------------------------------------------------------------------------
{
  const c = { ...OWN(), commitEmails: GITLAB([addr("sam@example.org")]) }, r = audit(c), md = selfAuditMarkdown(r, { target: H }), all = md.join("\n");
  ok(md[0] === "## Reduce your footprint" && md[1].includes(SELF_AUDIT_NOTE) && /marked "This is me"/.test(md[1]) && md.at(-1) === "", "the export starts with the heading and the note");
  ok(/^1\. \*\*An address in your public commits: sam@example\.org\*\* _\(exposes contact details\)_$/m.test(all) && /^ {3}- Exposed: sam@example\.org can be read/m.test(all) && /^ {3}- Seen on: \[GitLab \(samexample\/maps\)\]\(https:\/\/gitlab\.com\/samexample\)$/m.test(all) && /^ {3}- Fix: On GitLab/m.test(all) && /^ {3}- Why: Commits already pushed/m.test(all), "items are numbered, each with what is exposed, where it was seen, the fix and why");
  ok(md.filter((l) => /^\d+\. \*\*/.test(l)).length === r.items.length && /\(check that it is yours\)/.test(all) && /^What this list could not see:$/m.test(all) && r.gaps.every((g) => all.includes(`- ${g.replace(/([\\`*_[\]<>|#])/g, "\\$1")}`)), "every item and every gap is in it, and a row to check says so");
  ok(!/Seen on:\s*$/m.test(all) && !/\]\(\s*\)/.test(all), "an item with no place has no empty 'Seen on' line, and no link is empty");
}

// ---- 13. hostile values stay plain text ------------------------------------------------------------------
{
  const X = '<img src=x onerror=alert(1)>', Y = '"><script>alert(2)</script>', Z = "[click](javascript:alert(3))";
  const c = clone(U.collected);
  c.github.name = X; c.github.location = Y; c.github.company = Z; c.github.email = "sam@example.org";
  c.githubDeep.commit_emails = [{ email: "javascript:alert(1)", repo: "x" }, { email: "<b>@example.org", repo: "samexample/tilecut" }, { email: "ok@example.org", repo: "../../etc/passwd" }];
  const r = audit(c), dt = item(r, "profile-details"), out = words(r), md = selfAuditMarkdown(r, { target: `${H}<b>` }).join("\n");
  ok(dt && dt.exposed.includes(X) && dt.exposed.includes(Y) && dt.exposed.includes(Z), "a hostile name, place and employer pass through as the plain strings they are");
  ok(!/&lt;|&gt;|&quot;|&amp;|<a |<span|<li|<\/?(div|p|ul|ol|strong|em)\b/i.test(out) && !/innerHTML|createElement|<[a-z]+[ >]/.test(fs.readFileSync(new URL(`${J}selfaudit.js`, import.meta.url), "utf8").replace(/\/\/.*$/gm, "")), "the module builds no HTML and escapes nothing itself: the page does that");
  ok(!/javascript:alert\(1\)/.test(out) && item(r, "commit-email:ok@example.org") && labels(item(r, "commit-email:ok@example.org")).join() === "GitHub" && r.items.every((i) => i.where.every((w) => !w.url || /^https:\/\//.test(w.url))), "something that is not an address is no address, a bad repository name is dropped, and every link is https");
  ok(!/(?<!\\)<img|(?<!\\)<script|(?<!\\)\]\(javascript/.test(md) && md.includes("\\<img src=x onerror=alert(1)\\>") && md.includes("\\[click\\](javascript:alert(3))") && md.includes("samexample\\<b\\>"), "the Markdown export escapes them, so none becomes markup or a link");
  // What a case file can carry in the on-click answers goes through the readers first.
  const f = audit({ ...OWN(), commitEmails: { "acct:gitlab": CE("gitlab", "evil.example", "GitLab", [addr("x@example.org")]), "acct:nowhere": CE("gitlab", "gitlab.com", "GitLab", [addr("y@example.org")]), "<script>": CE("gitlab", "gitlab.com", "GitLab", [addr("z@example.org")]) }, archives: { "acct:github": ARCH("javascript:alert(1)") }, postActivity: { "acct:mastodon.social": POSTS({ instance: "evil.example" }) } });
  ok(kinds(f, "commit-email").length === 0 && kinds(f, "archive").length === 0 && labels(item(f, "activity-hours")).join() === "GitHub", "an answer about another host, a row the case does not have, or an address that may not be looked up is not used");
}

// ---- a source that never ran or never answered is a gap too ---------------------------------------------
{
  // A run that was cancelled: the sources that were asked and did not answer are named.
  const cut = audit({ notAnswered: { keys: ["sherlock", "maigret", "profiles", "github"] } });
  ok(cut.items.length === 0 && cut.gaps.some((g) => /^Sherlock, Maigret, GitHub and Profile sources were asked and did not answer/.test(g) && /unknown/.test(g) && /Run the case again/.test(g)), "a cancelled run names every source that never answered as a gap");
  ok(/1 part of the picture is unknown\./.test(selfAuditText(cut)) && cut.gaps.length === 1 && /What this list could not see:/.test(selfAuditMarkdown(cut, { target: H }).join("\n")), "so the summary and the export never read a cancelled case as a clean one");
  const part = audit({ ...(({ platformCheck, ...rest }) => rest)(U.collected), notAnswered: { keys: ["platformCheck"] } });
  ok(!audit({ ...U.collected, notAnswered: { keys: ["platformCheck"] } }).gaps.some((g) => /asked and did not answer/.test(g)), "a source the case holds an answer from is not called unanswered, whatever the record says");
  ok(part.gaps.some((g) => /^Platform check was asked and did not answer, so what it would have shown is unknown\./.test(g)), "one source that never answered is said in the singular");
  // What the case records about itself is outside data: only known source names are said.
  const odd = audit({ ...U.collected, notAnswered: { keys: ["<b>x</b>", 7, null, "constructor", "adultCheck", "sherlockAdult", "hibp"] } });
  ok(!odd.gaps.some((g) => /did not answer, so what/.test(g) && /<b>|constructor|adult|Breaches/i.test(g)) && audit({ ...U.collected, notAnswered: "sherlock" }).gaps.length === audit(U.collected).gaps.length && audit({ ...U.collected, notAnswered: { keys: "sherlock" } }).gaps.length === audit(U.collected).gaps.length, "a key that is not a source of this kind of case is not said, an adult pass is never named, and a malformed record is ignored");
  // A username case where an account source did not run at all (switched off, or the run never got there).
  const one = audit({ github: { found: false } });
  ok(one.items.length === 0 && one.gaps.some((g) => /^Sherlock, Maigret and Profile sources did not run/.test(g) && /unknown/.test(g)), "a username case with no answer from Sherlock, Maigret or the profile sources says so");
  const noSher = audit((({ sherlock, ...rest }) => rest)(U.collected));
  ok(noSher.gaps.some((g) => /^Sherlock did not run, so accounts only it would have reported are unknown\./.test(g)) && !audit(U.collected).gaps.some((g) => /did not run, so accounts/.test(g)), "one of them missing is said alone, and a full run says nothing of the kind");
  ok(!audit({ ...U.collected, sherlock: FAIL }).gaps.some((g) => /Sherlock did not run/.test(g)) && !audit({ ...(({ sherlock, ...rest }) => rest)(U.collected), notAnswered: { keys: ["sherlock"] } }).gaps.some((g) => /Sherlock did not run/.test(g)), "a source that failed or never answered is said once, as that");
  // An email case: the same for the sources asked there.
  const mail = audit({ ...(({ holehe, gravatar, ...rest }) => rest)(E.collected), notAnswered: { keys: ["holehe", "gravatar", "sherlock"] } }, M, "email");
  ok(mail.gaps.some((g) => /^Holehe and Gravatar were asked and did not answer/.test(g)) && !mail.gaps.some((g) => /Sherlock/.test(g)), "an email case names its own sources");
}

console.log(bad ? `${bad} of ${n} self-audit checks failed` : `${n}/${n} self-audit checks passed`);
if (bad) process.exit(1);
