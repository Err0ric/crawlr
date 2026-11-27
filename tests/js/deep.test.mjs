// The record sources: the profile sources (25 sites), the accounts and keys behind an address,
// GitHub activity, and the lookups made on a click for one profile: commit emails, post activity,
// archived copies and what two of them do not share. Readers (hostile input included), how a record becomes a profile, what a
// proof is worth to the identity rules, the email rows and their wording, the person timeline,
// leads, the minor guard's text, case files, exports and what the AI is told. No browser, no network.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };
const J = "../../static/v2/js/";
const D = await import(J + "deep.js");
const { buildEvidence, collectProfiles, profileTexts, avatarImages, aiPayloadFor, aiSignature, caseMarkdown, caseAnalysis, sourcePlan, canonSite } = await import(J + "evidence.js");
const { clusterIdentities, linkParts } = await import(J + "identity.js");
const { personTimeline } = await import(J + "timeline.js");
const { sourceTally, sourceCoverage, sourceHasResults, partialGaps } = await import(J + "core.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");
const { stripGuard } = await import(J + "adult.js");
const { investigateBrief } = await import(J + "brief.js");
const { evDetail } = await import(J + "workbench.js");
const { sourceCards, activityHtml } = await import(J + "renderers.js");
const { investigateTiles } = await import(J + "present.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/deep.json", import.meta.url), "utf8"));
const U = fx.cases[0], E = fx.cases[1], H = U.target;
const clone = (v) => JSON.parse(JSON.stringify(v));
const row = (ev, key) => ev.items.find((i) => i.key === key);
const THUMB = U.collected.avatarHash.results[0].thumb;

// ---- 1. the plan -----------------------------------------------------------------------------
ok(sourcePlan("username", H).includes("profiles") && !sourcePlan("email", E.target).includes("profiles") && sourcePlan("email", E.target).includes("emailaccounts") && !sourcePlan("username", H).includes("emailaccounts"), "profile sources run for a username, accounts and keys for an email, and neither for the other");
ok(!["sherlock", "maigret", "platform", "profiles"].some((s) => sourcePlan("email", E.target).includes(s)), "an email case derives no handle: no username source is planned for it");

// ---- 2. the profile reader ---------------------------------------------------------------------
{
  const r = D.readProfileSources(U.collected.profiles);
  ok(r.profiles.length === 7 && r.profiles.every((p) => p.state === "found" && D.PROFILE_SITES[p.source][0] === p.site), "every read profile is kept, named by CrawlR's own table");
  ok(D.readProfileSources(r) === r && D.readProfileSources(clone(r)).profiles.length === 7 && JSON.stringify(D.readProfileSources(clone(r))) === JSON.stringify(r), "reading its own output changes nothing");
  ok(r.sources.chesscom.state === "rate_limited" && r.sources.lobsters.state === "blocked" && r.sources.codeforces.state === "failed" && r.sources.devto.state === "not_found", "each site keeps its own state");
  const cov = D.profileCoverage(r);
  ok(cov.read === 7 && cov.down.map((x) => x.site).sort().join() === "Chess.com,Codeforces,Lobsters" && !(cov.by.not_found || []).some((s) => ["Chess.com", "Codeforces", "Lobsters"].includes(s)), "blocked, rate limited and failed are never listed as not found");
  ok(/7 profiles read on 16 sites, 3 did not answer \(.*Chess\.com rate limited/.test(D.profileSourcesText(r)), "the run log names the sites that did not answer, with their state");
  // hostile input
  const bad1 = clone(U.collected.profiles);
  bad1.profiles[0].url = "https://evil.example/keybase.io/samexample";                        // not on the site
  bad1.profiles[1].thumb = "https://evil.example/a.png"; bad1.profiles[1].website = "javascript:alert(1)"; bad1.profiles[1].bio = "x".repeat(5000);
  bad1.profiles[1].accounts = [{ site: "X", handle: "a", url: "https://user:pw@x.com/a", proof: "keybase" }, { site: "Pornhub", handle: "a", url: "https://www.pornhub.com/users/a", proof: "listed" }, { site: "<b>X</b>", handle: "b", url: "https://x.com/b", proof: "signed-by-god", proof_url: "https://evil.example/p" }];
  bad1.profiles[1].links = ["data:text/html,x", "https://ok.example/page", "https://www.pornhub.com/users/a"];
  bad1.profiles[1].guard = { bio: "secret" }; bad1.profiles[1].stats = { followers: -4, "<script>": 2, posts: 7 };
  bad1.profiles[2].state = "maybe"; bad1.profiles[3].source = "constructor"; bad1.profiles[4].created = "<img src=x>"; bad1.profiles[4].emails = ["not an address", "A@B.example", "x@y.example\n<b>"];
  bad1.profiles.push({ ...bad1.profiles[5] });                                                // a second row for one site
  bad1.sources.keybase.state = "found"; bad1.sources.hackernews = { site: "<i>HN</i>", state: "found" }; bad1.sources.evil = { site: "Evil", state: "found" }; bad1.sources.npm = { site: "npm", state: "exploded" };
  const b = D.readProfileSources(bad1);
  const ma = b.profiles.find((p) => p.source === "mastodon");
  ok(!b.profiles.some((p) => p.source === "keybase") && b.sources.keybase.state === "unknown", "a profile whose address is not on its site is dropped, and its source reads unknown, never found");
  ok(ma.thumb === "" && ma.website === "" && ma.bio.length === 300 && !("guard" in ma), "a thumbnail that is not a checked data URI, a script address and guard-only text do not survive, and text is clipped");
  ok(ma.accounts.length === 1 && ma.accounts[0].proof === "listed" && !("proof_url" in ma.accounts[0]) && ma.accounts[0].site === "<b>X</b>", "an account with credentials or on an adult site is dropped, an unknown proof is only 'listed', and a name is kept as text");
  ok(ma.links.join() === "https://ok.example/page" && JSON.stringify(ma.stats) === JSON.stringify({ posts: 7 }), "links are http(s) and never an adult site; counts are whole numbers under plain keys");
  ok(!b.profiles.some((p) => p.source === "hackernews") && b.sources.hackernews.state === "unknown" && b.sources.hackernews.site === "Hacker News" && !("evil" in b.sources) && !("npm" in b.sources), "a state outside the known set is not a state, and a site outside the 16 is not a site");
  ok(b.profiles.find((p) => p.source === "gitlab").created === "" && b.profiles.find((p) => p.source === "gitlab").emails.join() === "a@b.example" && b.profiles.filter((p) => p.source === "lichess").length === 1, "a date must be a date, an address an address, and a site has one row");
  ok(D.readProfileSources(null) === null && D.readProfileSources({ profiles: "x" }) === null && D.readProfileSources({ error: "<b>boom</b>", error_code: "timeout" }).error_code === "timeout", "what is not an answer is nothing, and a failure stays a failure");
}

// ---- 3. a record becomes a profile, one row per site ---------------------------------------------
const ev = buildEvidence(U.collected, H, "username");
// The same case without the enrichment's one-word name "Sam". A one-word name beside a full one
// no longer rescues a profile whose full name conflicts (identity.js, rule 10), so GitLab's
// "Petra Novak" is a different person with it and without it.
const NOENR = (({ enricher, ...rest }) => rest)(U.collected), evD = buildEvidence(NOENR, H, "username");
{
  ok(canonSite("Hacker News") === canonSite("HackerNews") && canonSite("GitLab") === canonSite("Gitlab") && canonSite("dev.to") === canonSite("DEV Community") && canonSite("Mastodon") === canonSite("mastodon.social") && canonSite("Chess.com") === canonSite("Chess"), "the sites' own names and the tools' spellings are one site");
  const hn = row(ev, "acct:hackernews"), gl = row(ev, "acct:gitlab"), li = row(ev, "acct:lichess");
  ok(ev.items.filter((i) => /hacker ?news/i.test(i.what)).length === 1 && hn.what === "Hacker News" && hn.source === "Profile sources, Sherlock", "a site a tool also reported is one row, named by the record, with every source on it");
  ok(hn.link_kind === "verified_profile" && gl.link_kind === "verified_profile" && li.link_kind === "verified_profile" && li.url === `https://lichess.org/@/${H}`, "the record's address is the row's link, and it is a read profile's link");
  ok(row(evD, "acct:gitlab").tier === "different" && row(evD, "acct:gitlab").person === "Petra Novak" && gl.tier === "different" && gl.source.startsWith("Profile sources") && /Petra Novak/.test(gl.meta), "the record wins over a tool's row for the same site, and a conflicting name is still a different person");
  ok(hn.card.facts.includes("3,187 karma") && hn.card.facts.includes("joined 2013") && row(ev, "acct:mastodon.social").card.facts.includes("312 followers"), "the card's one line carries the record's counts and year");
  const ps = collectProfiles(U.collected, H, "username");
  const ma = ps.find((p) => p.id === "acct:mastodon.social");
  ok(ma.api === true && ma.avatarHash && ma.thumb === THUMB && ma.hashed === true && ma.proven.length === 1 && ma.proven[0].proof === "verified_link", "the profile carries the server's picture hash and its confirmed links");
  ok(avatarImages(U.collected, H, "username").map((i) => i.id).join() === "acct:github", "a profile whose picture the server already hashed is not sent to the avatar comparison again");
  const facts = ev.identity.views.find((v) => v.primary).facts;
  ok(facts.some((f) => f.k === "Location" && f.v === "Leeds, UK" && f.source === "Keybase") && !facts.some((f) => /Petra|Brno|Kovo/.test(f.v)), "facts come from the primary identity's records and never from another person's");
}

// ---- 4. what a proof is worth ------------------------------------------------------------------
{
  const kb = row(ev, "acct:keybase"), ma = row(ev, "acct:mastodon.social"), hn = row(ev, "acct:hackernews");
  ok(kb.tier === "linked" && /a Keybase proof ties the GitHub account to the Keybase profile/.test(kb.card.why), "a Keybase proof ties the two accounts: Linked, and the row says by what");
  ok(ma.tier === "linked" && /Mastodon shows a verified link to the GitHub profile, which links back/.test(ma.card.why), "a verified link does the same");
  ok(hn.tier === "linked" && /Keybase proof/.test(hn.card.why), "and a proof carries to the account it names");
  const P = (id, site, url, x = {}) => ({ id, site, url, handle: "sam", name: "", links: [], websites: [], proven: [], bio: "", ...x });
  const one = (a, b) => clusterIdentities([a, b], { handle: "sam" });
  const strong = (r) => r.clusters.some((c) => c.members.length === 2 && c.links.some((l) => l.signals.some((s) => s.type === "cross-link")));
  const X = P("acct:x", "X", "https://x.com/sam");
  ok(strong(one(P("acct:keybase", "Keybase", "https://keybase.io/sam", { proven: [{ url: "https://x.com/sam", proof: "keybase" }] }), X)), "with no anchor at all, a proof still joins the two profiles");
  ok(strong(one(P("acct:mastodon.social", "Mastodon", "https://mastodon.social/@sam", { proven: [{ url: "https://x.com/sam", proof: "verified_link" }] }), X)), "so does a verified link");
  const listed = one(P("acct:mastodon.social", "Mastodon", "https://mastodon.social/@sam", { links: ["https://x.com/sam"], proven: [{ url: "https://x.com/sam", proof: "listed" }] }), X);
  ok(!strong(listed) && listed.supports.some((l) => l.signals.some((s) => s.type === "one-way-link")), "an account a profile only lists joins nothing: it is a one-way link, shown as support");
  ok(!strong(one(P("acct:keybase", "Keybase", "https://keybase.io/sam", { proven: [{ url: "https://x.com/someone_else", proof: "keybase" }] }), X)), "a proof of another account ties nothing to this one");
  ok(!strong(one(P("acct:keybase", "Keybase", "https://keybase.io/sam", { proven: [{ url: "https://x.com/sam", proof: "trust me" }] }), X)), "a proof of an unknown kind is not a proof");
  // Hacker News: one path for every user, so the user is part of what a link points at
  ok(linkParts("https://news.ycombinator.com/user?id=Sam").key === "news.ycombinator.com/user?id=sam" && linkParts("https://news.ycombinator.com/user?id=sam").key !== linkParts("https://news.ycombinator.com/user?id=pat").key, "two Hacker News users are two links");
  const HN = P("acct:hackernews", "Hacker News", "https://news.ycombinator.com/user?id=sam");
  ok(strong(one(P("acct:keybase", "Keybase", "https://keybase.io/sam", { proven: [{ url: "https://news.ycombinator.com/user?id=sam", proof: "keybase" }] }), HN)) && !strong(one(P("acct:keybase", "Keybase", "https://keybase.io/sam", { proven: [{ url: "https://news.ycombinator.com/user?id=pat", proof: "keybase" }] }), HN)), "a proof of one Hacker News user does not tie another");
}

// ---- 5. what a row shows when it is opened ---------------------------------------------------------
{
  const kb = row(ev, "acct:keybase").detail, gl = row(ev, "acct:gitlab").detail, st = row(ev, "acct:strava").detail, np = row(ev, "acct:npm").detail;
  const g = (d, id) => d.groups.find((x) => x.id === id);
  ok(g(kb, "self").prov === "self-declared" && g(kb, "self").rows.some((r) => r.k === "Name" && r.v === "Sam Example") && g(kb, "record").prov === "site record" && g(kb, "record").title === "Keybase's own record", "a record is split by who wrote each value: the account holder, or the site");
  const proof = g(kb, "record").rows.find((r) => r.k === "Proven account" && /GitHub/.test(r.v));
  ok(proof.how === "proven on Keybase" && proof.link_kind === "evidence" && proof.more.label === "Proof" && /^https:\/\/gist\.github\.com\//.test(proof.more.url), "a proven account says how it is known and links to the proof");
  const ma = row(ev, "acct:mastodon.social").detail;
  ok(g(ma, "record").rows.some((r) => r.k === "Verified link" && r.how === "verified link") && g(ma, "self").rows.some((r) => r.k === "Listed account" && r.how === "listed on the profile" && /sam_rides/.test(r.v)), "a verified link is the site's record, a listed account is the holder's word");
  ok(g(ma, "record").rows.some((r) => r.k === "Joined" && r.v === "2017-04-03") && g(ma, "record").rows.some((r) => r.k === "Last active" && r.v === "2026-11-21") && g(ma, "record").rows.some((r) => r.k === "Posts" && r.v === "2,841"), "dates and counts are the site's record");
  ok(g(np, "record").rows.filter((r) => r.k === "Package").length === 3 && g(np, "self").rows.some((r) => r.k === "Public email" && r.v === "sam@samexample.example" && r.link_kind === "none"), "npm packages are listed with links, and an address is text");
  ok(g(gl, "self").rows.some((r) => r.k === "Company" && r.v === "Kovo Labs"), "a different person's record shows what it says, on its own row");
  ok(st.groups.length === 1 && st.groups[0].id === "tool" && st.groups[0].prov === "tool report" && /Maigret/.test(st.groups[0].title), "a profile a tool parsed from a page is one group, marked as a tool report");
  ok(row(ev, "acct:hugging face") === undefined && /could not be read/.test(JSON.stringify(row(ev, "acct:huggingface").detail)), "a picture that could not be read is said, not passed over");
  const html = evDetail(row(ev, "acct:keybase"));
  ok(/^<details class="ev-more" >/.test(html) && /<summary>What was read<span class="ev-more-n">\d+ values<\/span><\/summary>/.test(html) && !/<details[^>]* open/.test(html) && /<details class="ev-more" open>/.test(evDetail(row(ev, "acct:keybase"), true)), "the detail is a disclosure, closed until opened, and a redraw can keep it open");
  const xss = clone(U.collected); xss.profiles.profiles[0].display_name = "<img src=x onerror=alert(1)>"; xss.profiles.profiles[0].location = "\"><script>alert(1)</script>";
  const hx = evDetail(row(buildEvidence(xss, H, "username"), "acct:keybase"));
  ok(!/<img|<script/.test(hx) && /&lt;img src=x onerror=alert\(1\)&gt;/.test(hx), "every value in it is escaped");
  ok(evDetail(row(ev, "acct:twitch")) === "" && evDetail({}) === "", "a row nothing read has no detail");
}

// ---- 6. leads -------------------------------------------------------------------------------------
{
  const leads = ev.items.filter((i) => i.tier === "lead");
  const L1 = (k) => leads.find((l) => l.key === k);
  ok(/Mastodon profile, listed on the profile/.test(L1("lead:handle:sam_rides").meta) && L1("lead:handle:sam_rides").action.label === "Investigate this", "a listed account is a lead that says where it came from and how it is known");
  ok(/Keybase profile, proven on Keybase/.test(L1("lead:domain:tidepool.example").meta) && L1("lead:domain:tidepool.example").action.pivot === "recon", "a proven site is a lead with its proof named");
  ok(L1("lead:email:sam@samexample.example") && /npm public email/.test(L1("lead:email:sam@samexample.example").meta), "an address on a record is a lead");
  ok(new Set(leads.map((l) => l.key)).size === leads.length && !leads.some((l) => /github\.com\/samexample$|news\.ycombinator/.test(l.what)) && !leads.some((l) => l.lead.value.toLowerCase() === H), "leads are listed once, and never repeat an account row or the searched handle");
  ok(!leads.some((l) => /Petra|Kovo/.test(l.meta + l.what)), "a different person's record gives no lead");
}

// ---- 7. coverage: three states, and unknown is none of them -------------------------------------------
{
  const SRC = { profiles: "Profile sources", emailAccounts: "Accounts and keys", githubActivity: "GitHub activity" };
  const t = sourceTally({ profiles: U.collected.profiles, githubActivity: U.collected.githubActivity }, SRC).rows;
  const pr = t.find((r) => r.key === "profiles");
  ok(pr.state === "partial" && /13 of 16 profile sites answered/.test(pr.text) && partialGaps(t).some((r) => r.key === "profiles"), "some sites silent: partial, and a count that depends on it is a lower bound");
  const all = clone(U.collected.profiles); all.profiles = []; for (const k of Object.keys(all.sources)) all.sources[k] = { site: k, state: "failed", error: "x", error_code: "timeout" };
  ok(sourceTally({ profiles: all }, SRC).rows[0].state === "failed" && !sourceHasResults(all), "every site silent: the source failed, which is not 'nothing found'");
  const none = clone(U.collected.profiles); none.profiles = []; for (const k of Object.keys(none.sources)) none.sources[k] = { site: k, state: "not_found" };
  ok(sourceTally({ profiles: none }, SRC).rows[0].state === "none", "every site answered and has no record: nothing found");
  const npm = clone(none); npm.sources.npm = { site: "npm", state: "unknown", note: "No package lists this maintainer. An account without packages cannot be seen." }; npm.sources.bluesky = { site: "Bluesky", state: "not_asked" };
  ok(sourceCoverage(npm).answered === 15 && sourceCoverage(npm).total === 15 && D.profileCoverage(npm).notes[0].site === "npm" && !(D.profileCoverage(npm).by.not_found || []).includes("npm"), "npm's 'cannot tell' is the site's answer and keeps its note; a site that was not asked is not counted; neither is 'not found'");
  ok(/No package lists this maintainer/.test(sourceCards.profiles(npm)) && /the handle cannot exist there/.test(sourceCards.profiles(npm)), "the card shows the note and says why a site was not asked");
  const card = sourceCards.profiles(U.collected.profiles);
  ok(/Rate limited<\/dt><dd>Chess\.com/.test(card) && /Blocked by site<\/dt><dd>Lobsters/.test(card) && /Failed<\/dt><dd>Codeforces/.test(card) && !/Not found<\/dt><dd>[^<]*(Chess\.com|Lobsters|Codeforces)/.test(card), "the card lists each state apart");
  const tiles = investigateTiles({ items: ev.items, collected: U.collected, type: "username", partialKeys: ["profiles"] });
  ok(tiles.find((x) => x.id === "linked").atLeast === true, "the Linked tile reads 'at least' while a profile site is silent");
  const b = investigateBrief({ collected: U.collected, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], incomplete: ["Profile sources"], type: "username", target: H }).rows.map((r) => r.text).join("\n");
  // The silent sites and the proofs are said in "What the evidence says", once; the brief keeps the count line's "at least".
  const says = caseAnalysis(ev, { collected: U.collected, target: H, type: "username" }).assessment.lines.map((l) => l.text).join("\n");
  ok(/Could not be asked: Chess\.com \(rate limited\), Codeforces \(failed\), Lobsters \(blocked by site\)/.test(says) && /confirmed from the other side/.test(says) && !/did not answer the profile lookup|a proof the other side confirmed/.test(b) && /^At least .*Profile sources did not fully answer/m.test(b), "the assessment names the silent sites as unknown and says what a proof ties; the brief does not repeat it");
}

// ---- 8. the accounts and keys behind an address ---------------------------------------------------
const ee = buildEvidence(E.collected, E.target, "email");
{
  const r = D.readEmailAccounts(E.collected.emailAccounts);
  ok(r.accounts.length === 2 && r.keys.length === 2 && r.unattributed.commits_seen === 3 && D.readEmailAccounts(r) === r, "the answer is read whole, and reading it again changes nothing");
  const gh = row(ee, "acct:github~mara-lind"), org = row(ee, "acct:github~tidepool-lab"), un = row(ee, "commits:unattributed");
  ok(gh.tier === "linked" && gh.url === "https://github.com/mara-lind" && /GitHub attributes commits that carry this address to this account, so the account has this address confirmed, and GitHub's search matched it on the public profile/.test(gh.card.why) && D.readEmailAccounts(E.collected.emailAccounts).accounts[0].confirmed === true, "an account GitHub attributes the commits to is Linked, in the contract's words");
  ok(gh.more.label === "Evidence commit" && /^https:\/\/github\.com\/mara-lind\/tidepool\/commit\/[0-9a-f]{40}$/.test(gh.more.url) && gh.action.label === "Investigate this" && gh.action.value === "mara-lind" && gh.action.type === "username", "it carries the evidence commit and one click to investigate the login as a handle");
  ok(/Names written in its commits \(self-declared\): Mara Lindqvist \(in a repository the account owns\), mara\./.test(gh.card.note), "names in commits are labeled self-declared, the one from its own repository first");
  const self = gh.detail.groups.find((g) => g.id === "self"), rec = gh.detail.groups.find((g) => g.id === "record");
  ok(self.prov === "self-declared" && /anyone can write anything there/.test(self.title) && self.rows.some((x) => x.k === "UTC offset in commits" && x.v === "UTC+01:00") && self.rows.some((x) => x.k === "First commit seen" && x.v === "2021-06-14") && self.rows.some((x) => x.k === "Dates left out"), "commit names, dates and UTC offsets sit under self-declared");
  ok(rec.prov === "site record" && rec.rows.some((x) => x.k === "Commits seen" && x.v === "5 commits") && rec.rows.filter((x) => x.link_kind === "evidence").length === 2, "the counts and the evidence commits are GitHub's record");
  ok(org.tier === "unverified" && org.what === "GitHub (tidepool-lab)" && gh.what === "GitHub (mara-lind)" && org.link_kind === "evidence" && /Nothing was read/.test(org.card.basis) && org.card.facts.includes("Organization") && /GitHub's search matched this address on this organization's public profile\. The profile was not read, and GitHub does not confirm an organization's address/.test(org.card.why + ".") && !org.detail && D.readEmailAccounts(E.collected.emailAccounts).accounts[1].confirmed === false, "an organization GitHub's search matched is weaker, labeled as one, said to be unconfirmed, and never worded as a profile that was read");
  ok(un.tier === "unverified" && un.nofind === true && /belong to no GitHub account/.test(un.meta) && /names written in them \(self-declared\): M\. Lindqvist, build-bot/.test(un.meta) && un.link_label === "Evidence commit", "commits GitHub ties to no account are apart, unverified, and not a finding");
  const key = ee.items.find((i) => i.key.startsWith("pgp:a1b2")), unread = ee.items.find((i) => i.key.startsWith("pgp:unread"));
  ok(key.tier === "linked" && key.url === "https://keys.openpgp.org/vks/v1/by-fingerprint/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" && /verified the address by mail/.test(key.meta) && /created 2022-05-17 \(self-declared\)/.test(key.meta) && /EdDSA Ed25519/.test(key.meta), "a key is Linked to the address the key server verified, with its algorithm, and its date marked self-declared");
  ok(key.detail.groups[0].rows.some((x) => x.k === "Fingerprint" && x.link_kind === "evidence") && key.detail.groups[0].rows.filter((x) => x.k === "Verified address").length === 2 && key.detail.groups[1].rows.some((x) => x.k === "Name on the key"), "its detail has the fingerprint, the verified addresses and the self-declared name");
  ok(unread.link_kind === "none" && /version 6, not read/.test(unread.what) && typeof unread.hint === "string", "a key CrawlR cannot read is listed as that, with no link and a way to check");
  ok(!ee.identity.views.some((v) => /mara-lind|tidepool-lab/.test(v.sites.join())) && ee.identity.views.find((v) => v.primary).label === "Mara Lindqvist" && ee.identity.views.find((v) => v.primary).sites.join() === "Gravatar", "none of these rows is a profile: the identity is built from read profiles alone");
  ok(ee.general.some((f) => f.k === "GitHub account" && f.v === "mara-lind" && /site record/.test(f.source)) && ee.general.some((f) => f.k === "Name in commits" && /self-declared/.test(f.source)) && ee.general.some((f) => f.k === "OpenPGP key" && f.link_kind === "evidence"), "the facts are about the address and each says how it is known");
  const leads = ee.items.filter((i) => i.tier === "lead");
  ok(leads.find((l) => l.key === "lead:handle:mara-lind").action.label === "Investigate this" && /site record/.test(leads.find((l) => l.key === "lead:handle:mara-lind").meta) && /unconfirmed/.test(leads.find((l) => l.key === "lead:handle:tidepool-lab").meta), "the login is a lead, one click, with the strength of its tie");
  ok(/another address on the same OpenPGP key/.test(leads.find((l) => l.key === "lead:email:mara@lindqvist.example").meta) && !leads.some((l) => l.lead.value === E.target), "another address on the key is a lead; the searched address is not");
  // a lookup that did not answer
  const lim = clone(E.collected.emailAccounts); lim.accounts = []; lim.unattributed = null; lim.sources.github_commits = { state: "rate_limited", retry_after: 41, error: "GitHub is rate limiting requests.", error_code: "rate_limited" }; lim.sources.github_users = { state: "none" };
  ok(sourceCoverage(D.readEmailAccounts(lim)).answered === 2 && sourceTally({ emailAccounts: lim }, { emailAccounts: "Accounts and keys" }).rows[0].state === "partial" && D.emailLookupsDown(lim)[0].name === "GitHub commit search", "a rate limited lookup makes the source partial, and it is named");
  ok(/unknown: rate limited/.test(sourceCards.emailAccounts(lim)) && /never means "no account" or "no key"/.test(sourceCards.emailAccounts(lim)), "the card says unknown, never 'no account'");
  const bl = investigateBrief({ collected: { ...E.collected, emailAccounts: lim }, items: buildEvidence({ ...E.collected, emailAccounts: lim }, E.target, "email").items, facts: [], identity: ee.identity, failed: [], type: "email", target: E.target }).rows.map((x) => x.text).join("\n");
  ok(/Could not be asked: GitHub commit search \(rate limited\)/.test(caseAnalysis(buildEvidence({ ...E.collected, emailAccounts: lim }, E.target, "email"), { collected: { ...E.collected, emailAccounts: lim }, target: E.target, type: "email" }).assessment.lines.map((l) => l.text).join("\n")) && !/could not be asked/.test(bl), "and the assessment names it as what could not be asked");
  const br = investigateBrief({ collected: E.collected, items: ee.items, facts: ee.facts, identity: ee.identity, failed: [], type: "email", target: E.target });
  ok(br.rows.some((x) => x.level === "ok" && /GitHub attributes commits that carry this address to the account mara-lind/.test(x.text) && /self-declared/.test(x.text) && x.link_kind === "evidence") && br.actions.some((a) => a.label === "Investigate mara-lind" && a.pivot === "investigate"), "the brief states the attribution with its evidence and offers the one hop");
  // hostile input
  const h1 = clone(E.collected.emailAccounts);
  h1.accounts[0].login = "mara-lind/../evil"; h1.accounts[1].url = "https://evil.example/tidepool-lab"; h1.accounts[1].how = "vibes"; h1.accounts[1].hows = ["public_profile_email"]; h1.accounts.push({ login: "ok-login", how: "nothing" });
  h1.unattributed.evidence = ["https://evil.example/x/y/commit/abcdef1", "https://github.com/a/b/commit/abcdef1"]; h1.unattributed.commit_utc_offsets = [{ offset: "Paris", commits: 3 }];
  h1.keys[0].url = "https://evil.example/key"; h1.keys[0].user_ids.push({ name: "<b>x</b>", email: "javascript:alert(1)" }); h1.keys.push({ parsed: true, fingerprint: "zz" }); h1.sources.openpgp.state = "great";
  const hr = D.readEmailAccounts(h1);
  ok(hr.accounts.length === 1 && hr.accounts[0].login === "tidepool-lab" && hr.accounts[0].url === "https://github.com/tidepool-lab" && hr.accounts[0].how === "public_profile_email", "a login must be a GitHub login, its address is rebuilt, and a tie of an unknown kind is no tie");
  ok(hr.unattributed.evidence.join() === "https://github.com/a/b/commit/abcdef1" && hr.unattributed.commit_utc_offsets.length === 0, "evidence must be a GitHub commit address, and an offset an offset");
  ok(hr.keys[0].url.startsWith("https://keys.openpgp.org/vks/v1/by-fingerprint/A1B2") && hr.keys[0].user_ids.at(-1).email === "" && hr.keys.at(-1).parsed === false && !("openpgp" in hr.sources), "a key's address is rebuilt from its fingerprint, a bad one is unread, and an unknown state is dropped");
}

// ---- 9. GitHub activity ----------------------------------------------------------------------------
{
  const v = D.activityView(U.collected.githubActivity);
  ok(v.state === "ok" && v.hours.length === 24 && v.days.length === 7 && v.hours[15].pct === 100 && /137 public events from 2026-09-01 to 2026-11-24 \(85 days, active on 61\)\. Times are UTC\./.test(v.text), "the view has 24 hours, 7 days and the window it covers");
  ok(/^Events by hour of day, UTC: 00:00 0, 01:00 0,/.test(v.hoursAlt) && /23:00 0\.$/.test(v.hoursAlt) && /Monday 29, .*Sunday 3\.$/.test(v.daysAlt) && /Busiest hours \(UTC\): 15:00 \(15\), 09:00 \(14\), 14:00 \(13\)\./.test(v.busiest), "both strips have a text alternative that reads out every count");
  ok(v.estimate.label === "UTC-1 to UTC+2" && v.estimate.basis && v.estimate.assumption && /A hint, not a fact/.test(v.estimate.caveat), "the estimate travels with its basis, its assumption and its caveat");
  const html = activityHtml(U.collected.githubActivity);
  ok((html.match(/role="img" aria-label="Events by/g) || []).length === 2 && (html.match(/class="act-col/g) || []).length === 31 && /a hint, not a fact/.test(html) && /A range of time offsets is not a place/.test(html) && !/<img|<script|<svg(?! class="ext")/.test(html), "the page draws two strips of plain elements, each an image with its words, and the estimate is never a place");
  ok(/Based on 137 public events over 85 days \(61 with activity\)\. The longest quiet stretch is/.test(html) && /Assumes one person who sleeps at least 6 hours inside the quiet stretch/.test(html), "basis and assumption are shown with the estimate, written from the numbers");
  const noest = clone(U.collected.githubActivity); noest.estimate = null; noest.estimate_reason = { code: "no_quiet_window", text: "Lives in Berlin." };
  ok(D.activityView(noest).estimate === null && /none made/.test(activityHtml(noest)) && /No quiet stretch long enough to be a night: the account is active around the clock\./.test(activityHtml(noest)) && !/Berlin/.test(activityHtml(noest)), "no estimate shows the reason, in the page's own words for the server's code");
  const place = clone(U.collected.githubActivity); place.estimate.label = "Central European Time (Berlin)"; place.estimate.utc_offset_from = 1; place.estimate.utc_offset_to = 2;
  ok(D.activityView(place).estimate.label === "UTC+1 to UTC+2", "a label that names a place is written again from the numbers");
  ok(D.readActivity({ ...clone(U.collected.githubActivity), hours_utc: [1, 2, 3] }) === null && D.readActivity({ state: "fine" }) === null, "an answer without 24 hours is not an answer");
  ok(D.readActivity({ ...clone(U.collected.githubActivity), repos: [{ name: "a/b", url: "https://evil.example/", count: 1 }, { name: "../x", count: 2 }, { name: "a/..", count: 2 }] }).repos.map((x) => x.url).join() === "https://github.com/a/b", "a repository's address is rebuilt from its name");
  const quiet = { username: H, found: true, state: "none", events: 0, hours_utc: Array(24).fill(0), weekdays_utc: Array(7).fill(0) };
  ok(!sourceHasResults(D.readActivity(quiet)) && sourceTally({ githubActivity: D.readActivity(quiet) }, { githubActivity: "GitHub activity" }).rows[0].state === "none" && /no public events/.test(D.activityView(quiet).text), "an account with no public events answered, with nothing to show");
  const gone = D.readActivity({ username: H, found: false, state: "not_found" });
  ok(gone.found === false && sourceTally({ githubActivity: gone }, { githubActivity: "x" }).rows[0].state === "none", "no such account is an answer");
  const fail = D.readActivity({ username: H, found: null, state: "rate_limited", error: "GitHub is rate limiting requests.", error_code: "rate_limited" });
  ok(fail.error_code === "rate_limited" && sourceTally({ githubActivity: fail }, { githubActivity: "x" }).rows[0].state === "failed" && D.activityView(fail) === null, "rate limited is a failure: unknown, and nothing is drawn from it");
  const part = D.readActivity({ ...clone(U.collected.githubActivity), complete: false, later_pages: "rate_limited" });
  ok(sourceTally({ githubActivity: part }, { githubActivity: "x" }).rows[0].state === "partial" && /older events are missing/.test(D.activityView(part).text), "a later page that failed makes it partial, and the page says events are missing");
}

// ---- 10. the timeline of a person case ---------------------------------------------------------------
{
  const tl = personTimeline(U.collected, H, "username", "2026-11-26").events;
  ok(tl.length >= 10 && tl.every((e, i) => !i || tl[i - 1].date <= e.date), "dated facts, oldest first");
  ok(tl[0].title === "Hacker News account created" && tl[0].date === "2013-09-12" && tl[0].basis === "record" && tl[0].basis_text === "site record" && tl[0].source === "Profile sources" && tl[0].link_kind === "evidence", "each names its source, how the date is known, and where to check it");
  ok(tl.some((e) => e.title === "GitHub account created" && e.date === "2014-02-19") && tl.some((e) => e.title === "Last seen active on Lichess" && e.date === "2026-11-25") && tl.some((e) => e.title === "Latest public GitHub event" && e.source === "GitHub activity"), "joined dates, last active and the activity window are all there");
  ok(!personTimeline(NOENR, H, "username", "2026-11-26").events.some((e) => /GitLab/.test(e.title)) && !tl.some((e) => /GitLab/.test(e.title)) && /not proven to be the same person/.test(tl.find((e) => /Lichess account/.test(e.title)).detail), "a profile filed as a different person is left out, and one that only matches says it is not proven");
  ok(tl.find((e) => e.title === "Strava account created").detail.includes("Read from the profile page by a tool") && /not proven to be the same person/.test(tl.find((e) => e.title === "Lichess account created").detail) && tl.find((e) => e.title === "GitHub account created").detail === "", "a matching account says it is not proven, and a tool's reading says so");
  ok(tl.every((e) => !e.future) && tl.at(-1).when === "1 day ago", "nothing is in the future, and each says how long ago");
  const te = personTimeline(E.collected, E.target, "email", "2026-11-26").events;
  const t = (re) => te.find((e) => re.test(e.title));
  ok(t(/Earliest commit seen with this address \(mara-lind\)/).basis === "self" && t(/Earliest commit seen/).date === "2021-06-14" && t(/Latest commit seen/).date === "2025-02-20" && /written inside the commit/.test(t(/Latest commit seen/).detail), "first and last commit are self-declared, and say why");
  ok(t(/OpenPGP key .* created/).basis_text === "self-declared" && t(/OpenPGP key/).date === "2022-05-17" && t(/OpenPGP key/).link_kind === "evidence", "a key's creation date is self-declared too");
  ok(t(/Breach: MapForum/).date === "2019-03-14" && t(/Breach: MapForum/).basis_text === "breach index record" && t(/Breach: TrailShare/).date === "2022-01-01" && /the index gives the year only/.test(t(/Breach: TrailShare/).detail), "breaches are the index's record, and a year-only date says so");
  ok(t(/ties to no account/).basis === "self", "commits tied to no account are on it, marked self-declared");
  ok(personTimeline({ hash: { hash: "x" } }, "x", "hash").events.length === 0 && personTimeline(U.collected, "Sam Example", "name").events.length === 0, "only a username or an email case has one");
  const forged = clone(E.collected); forged.emailAccounts.accounts[0].last_commit = "2060-01-01T00:00:00Z"; forged.emailAccounts.keys[0].created = "1971-01-01T00:00:00Z";
  const tf = personTimeline(forged, E.target, "email", "2026-11-26").events;
  ok(tf.find((e) => /Latest commit seen/.test(e.title)).future === true && !tf.some((e) => /OpenPGP key/.test(e.title)), "a date in the future is marked as that, and one from before the web is not a date");
  const failedSrc = { ...U.collected, profiles: { error: "x", error_code: "timeout" } };
  ok(!personTimeline(failedSrc, H, "username", "2026-11-26").events.some((e) => /Hacker News|Mastodon|Lichess/.test(e.title)), "a failed source leaves a gap, not a date");
}

// ---- 11. the minor guard reads the new source, and its text is not kept --------------------------------
{
  const c = clone(U.collected);
  c.profiles.profiles[1].guard = { bio: "the whole bio, i'm 15", age: "15" };
  const texts = profileTexts(c);
  const ma = texts.find((t) => t.source === "Mastodon"), gl = texts.find((t) => t.source === "GitLab"), kb = texts.find((t) => t.source === "Keybase");
  ok(ma.bio === "the whole bio, i'm 15" && ma.age === "15" && ma.name === "Sam Example" && gl.text === "Kovo Labs\nBrno" && kb.bio === "Maps, bikes and small tools. Leeds.", "the scan reads each record's name, bio and guard-only bio, with company and location as further text");
  const order = texts.map((t) => t.source);
  ok(order.indexOf("GitHub") < order.indexOf("Keybase") && order.indexOf("Instagram") < order.indexOf("Keybase") && order.slice(order.indexOf("Keybase")).join() === "Keybase,Mastodon,Hacker News,GitLab,Hugging Face", "after the sources the rules file orders, as the server appends them");
  ok(!profileTexts({ profiles: { error: "x", error_code: "timeout", profiles: c.profiles.profiles } }).length && !profileTexts({ profiles: { profiles: [{ site: "Pornhub", url: "https://www.pornhub.com/users/a", state: "found", bio: "i'm 15" }, { site: "X", url: "https://x.com/a", state: "blocked", bio: "i'm 15" }] } }).length, "a failed answer, an adult site and a row that was not read are never scanned");
  ok(!JSON.stringify(stripGuard(c)).includes("the whole bio") && !("guard" in D.readProfileSources(c.profiles).profiles[1]) && !JSON.stringify(buildEvidence(c, H, "username")).includes("the whole bio"), "guard-only text is stripped before the case is kept, and never reaches a row");
}

// ---- 12. case files: a case saved with the new keys opens, hostile ones are cleaned ---------------------
{
  const file = (collected, target = H, type = "username") => JSON.stringify(buildCaseFile({ mode: "investigate", target, type, ran: 1700000000000, collected }));
  const r = parseCaseFile(file({ ...U.collected, profiles: { ...clone(U.collected.profiles), profiles: clone(U.collected.profiles.profiles).map((p) => ({ ...p, guard: { bio: "guard text" } })) } }));
  ok(r.ok && r.entry.results.profiles.profiles.length === 7 && r.entry.results.githubActivity.events === 137 && !JSON.stringify(r.entry.results).includes("guard text"), "a username case round-trips, without guard-only text");
  ok(JSON.stringify(buildEvidence(r.entry.results, H, "username").items.map((i) => [i.key, i.tier])) === JSON.stringify(ev.items.map((i) => [i.key, i.tier])), "and draws the same ledger");
  const re = parseCaseFile(file(E.collected, E.target, "email"));
  ok(re.ok && re.entry.results.emailAccounts.accounts.length === 2 && buildEvidence(re.entry.results, E.target, "email").items.some((i) => i.key === "acct:github~mara-lind"), "an email case round-trips");
  const evil = clone(U.collected);
  evil.profiles.profiles[1].thumb = "data:image/svg+xml;base64,PHN2Zz4="; evil.profiles.profiles[1].url = "https://mastodon.social.evil.example/@samexample";
  evil.profiles.profiles[2].accounts = [{ site: "X", handle: "x", url: "javascript:alert(1)", proof: "keybase" }];
  evil.githubActivity = { state: "ok", hours_utc: "many" }; evil.emailAccounts = "text";
  const rv = parseCaseFile(file(evil));
  ok(rv.ok && !rv.entry.results.profiles.profiles.some((p) => p.source === "mastodon") && rv.entry.results.profiles.sources.mastodon.state === "unknown" && !("githubActivity" in rv.entry.results) && !("emailAccounts" in rv.entry.results) && !/svg\+xml|javascript:|evil\.example/.test(JSON.stringify(rv.entry.results.profiles)), "a profile pointed off its site, a bad thumbnail and a script address do not survive, and an unreadable answer is dropped");
  const old = parseCaseFile(file({ github: U.collected.github, sherlock: U.collected.sherlock }));
  ok(old.ok && !("profiles" in old.entry.results) && buildEvidence(old.entry.results, H, "username").items.length > 5 && personTimeline(old.entry.results, H, "username").events.length === 1, "a case saved before these sources still opens, and its timeline holds what it has");
  const failedKeep = parseCaseFile(file({ ...U.collected, profiles: { error: "The source failed.", error_code: "timeout", error_detail: "" } }));
  ok(failedKeep.entry.results.profiles.error_code === "timeout", "a recorded failure stays a failure");
  ok(JSON.stringify(D.readDeep({ profiles: 7, emailAccounts: null, other: { a: 1 } })) === JSON.stringify({ other: { a: 1 } }), "History reads the same three keys the same way, and leaves the rest alone");
}

// ---- 13. exports and what the AI is told --------------------------------------------------------------
{
  const md = caseMarkdown({ collected: U.collected, target: H, type: "username", timeline: personTimeline(U.collected, H, "username", "2026-11-26").events, now: new Date("2026-11-26T00:00:00Z") });
  ok(/## Lookups that did not answer\n- \*\*Chess\.com\*\* \(Profile sources\): rate limited \(unknown, not a negative result\)/.test(md), "the export lists the sites that did not answer as unknown");
  ok(/  - Proven account: \[GitHub samexample\]\(https:\/\/github\.com\/samexample\) \(proven on Keybase\) · \[Proof\]\(https:\/\/gist[^)]+\) _\(site record\)_/.test(md) && /  - Bio: Cartography nerd[^\n]* _\(self-declared\)_/.test(md) && /  - Location: Leeds _\(tool report\)_/.test(md), "every value under a row is marked site record, self-declared or tool report");
  ok(/## Timeline\n_Every date was reported/.test(md) && /- 2013-09-12 · \[Hacker News account created\]\(https:\/\/news\.ycombinator\.com\/user\?id=samexample\) _\(Profile sources · site record\)_/.test(md), "the timeline is exported with each date's source and basis");
  ok(/## GitHub activity\n- 137 public events/.test(md) && /UTC offset estimate: UTC-1 to UTC\+2\. .*A hint, not a fact\..*never a place\./.test(md), "the activity is exported with the estimate's caveat");
  const me = caseMarkdown({ collected: E.collected, target: E.target, type: "email", timeline: personTimeline(E.collected, E.target, "email", "2026-11-26").events });
  ok(/  - Name in commits: Mara Lindqvist \(3 commits, in a repository the account owns\) _\(self-declared\)_/.test(me) && /  - Commits seen: 5 commits _\(site record\)_/.test(me) && /· self-declared\)_/.test(me) && !/## GitHub activity/.test(me), "an email case's export marks what the commits say as self-declared");
  ok(!/\u2014/.test(md + me), "no em dash in an export");
  const ai = aiPayloadFor(U.collected, H, "username", { source_status: { "Profile sources": "partial: 13 of 16 profile sites answered" } });
  const kb = ai.profile_sources.profiles.find((p) => p.site === "Keybase"), gl = ai.profile_sources.profiles.find((p) => p.site === "GitLab");
  ok(kb.status === "linked" && gl.status === "different" && aiPayloadFor(NOENR, H, "username").profile_sources.profiles.find((p) => p.site === "GitLab").status === "different" && kb.self_declared.name === "Sam Example" && /proven on Keybase/.test(kb.site_record.proven_accounts) && ai.profile_sources.profiles.find((p) => p.site === "Mastodon").site_record.joined === "2017-04-03", "the model gets each record with its standing, split into self-declared and site record");
  ok(ai.profile_sources.not_answered.join("; ") === "Chess.com: rate limited; Codeforces: failed; Lobsters: blocked by site" && !ai.profile_sources.not_found.some((s) => /Chess|Codeforces|Lobsters/.test(s)), "and the silent sites as not answered, never as not found");
  ok(ai.github_activity.utc_offset_estimate.range === "UTC-1 to UTC+2" && ai.github_activity.utc_offset_estimate.caveat && ai.github_activity.hours_utc.length === 24 && !("email_accounts" in ai), "the activity goes with its caveat; an email-only field is absent");
  ok(!JSON.stringify(ai.profile_sources).includes("data:image") && !("thumb" in ai.profile_sources.profiles[0]), "no picture is sent");
  const ae = aiPayloadFor(E.collected, E.target, "email");
  ok(ae.email_accounts.accounts[0].tie === "commit_author" && ae.email_accounts.accounts[0].self_declared_names[0].name === "Mara Lindqvist" && ae.email_accounts.accounts[1].account_type === "Organization" && ae.email_accounts.keys[0].self_declared_created === "2022-05-17" && ae.email_accounts.keys[1].unread === true && !("profile_sources" in ae) && !("github_activity" in ae), "an email case tells the model the tie, with self-declared values named as such");
  ok(ae.accounts.some((a) => a.status === "linked" && /GitHub attributes commits/.test(a.note)), "and the account is in the ledger's own account list");
  const base = { github: U.collected.github, sherlock: U.collected.sherlock };
  ok(aiSignature(U.collected, H, "username") !== aiSignature({ ...U.collected, githubActivity: null }, H, "username") && !("profile_sources" in aiPayloadFor(base, H, "username")) && aiSignature(base, H, "username") === aiSignature(clone(base), H, "username"), "a report is reused only when the record sources say the same, and an older case gains no field");
  const failAi = aiPayloadFor({ ...U.collected, profiles: { error: "x", error_code: "timeout" } }, H, "username");
  ok(!("profile_sources" in failAi), "a failed source sends no data: its status line says it is unknown");
}

// ---- 15. answer shapes that changed after the backend review ------------------------------------------
{
  // GitHub activity: a range across the date line is two runs, never one span.
  const act = clone(U.collected.githubActivity);
  act.estimate = { ...act.estimate, utc_offset_from: 10, utc_offset_to: -9, utc_offsets: [10, 11, 12, -11, -10, -9], label: "UTC+10 to UTC+12 or UTC-11 to UTC-9", crosses_date_line: true };
  const r = D.readActivity(act);
  ok(r.estimate.label === "UTC+10 to UTC+12 or UTC-11 to UTC-9" && r.estimate.crosses_date_line === true && D.activityView(act).estimate.label === r.estimate.label, "a two-run label across the date line is kept as two runs");
  const bad1 = clone(act); bad1.estimate.label = "Tokyo or Auckland";
  ok(D.readActivity(bad1).estimate.label === "UTC+10 to UTC+12 or UTC-11 to UTC-9", "a label that is not offsets is written again from the list, still as two runs");
  const bad2 = clone(bad1); bad2.estimate.utc_offsets = [];
  ok(D.readActivity(bad2).estimate.label === "UTC+10 to UTC+12 or UTC-11 to UTC-9" && !/UTC\+10 to UTC-9/.test(D.readActivity(bad2).estimate.label) && D.readActivity(bad2).estimate.crosses_date_line === true, "with no list the two ends are never joined into one wrapped span");
  ok(D.offsetsLabel([-1, 0, 1, 2]) === "UTC-1 to UTC+2" && D.offsetsLabel([0]) === "UTC" && D.offsetsLabel([12, -11]) === "UTC+12 or UTC-11", "runs are listed going east");
  const nf = { username: "", found: false, state: "not_found", cached: false, note: "GitHub cannot hold this handle: a login is 1 to 39 letters, digits or hyphens, so nothing was asked." };
  ok(D.activityView(nf).text === nf.note && D.activityView({ username: "x", found: false, state: "not_found" }).text === "GitHub has no account with this name.", "a handle GitHub cannot hold says so, in place of no account with this name");
  ok(D.readActivity({ state: "rate_limited", cached: false, error: "x", error_code: "rate_limited" }).error_code === "rate_limited", "a rate limited answer stays a failure");
  // Profiles: asked, retry_after, and a record that came back in part.
  const ps = clone(U.collected.profiles); ps.asked = ["gitlab", "keybase", "nonsense", "gitlab"]; ps.sources.chesscom.retry_after = 540;
  ps.profiles.find((p) => p.source === "hackernews").bio = ""; ps.profiles.find((p) => p.source === "hackernews").note = "bio not read";
  const pr = D.readProfileSources(ps);
  ok(pr.asked.join() === "gitlab,keybase" && pr.sources.chesscom.retry_after === 540 && !("retry_after" in pr.sources.lobsters) && JSON.stringify(D.readProfileSources(clone(pr))) === JSON.stringify(pr), "the sites asked in this call and a wait are kept, and reading again changes nothing");
  const hn = row(buildEvidence({ ...U.collected, profiles: ps }, H, "username"), "acct:hackernews");
  ok(/Hacker News answered in part: bio not read\. That part is unknown, not empty\./.test(hn.card.note) && !/no name, bio or dates/.test(hn.card.basis || "") && hn.detail.groups.flatMap((g) => g.rows).some((x) => x.k === "Not read" && x.v === "bio not read: unknown, not empty"), "a bio that was not read is unknown, and is never worded as no bio");
  const bare = clone(ps); Object.assign(bare.profiles.find((p) => p.source === "hackernews"), { created: "", stats: {}, links: [], note: "bio and karma not read" });
  const hb = row(buildEvidence({ profiles: bare }, H, "username"), "acct:hackernews");
  ok(!/carries no name, bio or dates/.test(hb.card.basis || "") && /bio and karma not read/.test(hb.card.note), "even when nothing else was read");
  // Email accounts: confirmed, how_note, and commits that were returned and could not be counted.
  const ea = clone(E.collected.emailAccounts);
  ea.accounts[0].confirmed = true; ea.accounts[1].confirmed = true; ea.accounts[1].how_note = "GitHub's search matched this address on the profile. The profile itself was not read to confirm it.";
  ea.sources.github_commits = { state: "none", total: 4, seen: 0, skipped: 4, only_skipped: true, note: "GitHub returned 4 commits for this address and none could be counted: each was made by an app account, or its row was malformed or did not carry the address." };
  const er = D.readEmailAccounts(ea);
  ok(er.accounts[0].confirmed === true && er.accounts[1].confirmed === false && /was not read to confirm it/.test(er.accounts[1].how_note) && !("how_note" in er.accounts[0]), "confirmed is true for a commit attribution only, whatever the answer says, and the search note is kept");
  ok(er.sources.github_commits.only_skipped === true && /none could be counted/.test(D.commitsNote(ea)) && /commits were returned and none could be counted/.test(D.emailAccountsText(ea)) && D.commitsNote(E.collected.emailAccounts) === "", "commits that were returned and could not be counted are not the same as no commits");
  const eb = investigateBrief({ collected: { ...E.collected, emailAccounts: ea }, items: buildEvidence({ ...E.collected, emailAccounts: ea }, E.target, "email").items, facts: [], identity: null, failed: [], type: "email", target: E.target });
  ok(eb.rows.some((x) => /none could be counted.* That is not the same as no commits\./.test(x.text)) && eb.rows.some((x) => /matched to this address by GitHub's search of public profiles\. The profile was not read to confirm it/.test(x.text)) && !eb.rows.some((x) => /shows? this address/.test(x.text)), "the brief says both, and never that a profile shows the address");
  ok(/GitHub's search matched this address/.test(D.HOW_TEXT.public_profile_email) && /was not read/.test(D.HOW_TEXT.public_profile_email) && !/shows this address/.test(JSON.stringify(D.HOW_TEXT)) && D.emailAccountsForAi(ea).commit_search_note.includes("none could be counted"), "the wording for a search match says the profile was not read, on the page and to the model");
}

// ---- 16. the 25 profile sources ------------------------------------------------------------------------
const HOSTS = ["mastodon.social", "mastodon.online", "mstdn.social", "fosstodon.org", "hachyderm.io", "infosec.exchange", "mas.to", "mastodon.world"];
// One found row per source, at the address the server builds for it.
const PATHS = { gitlab: "/samexample", keybase: "/samexample", hackernews: "/user?id=samexample", dockerhub: "/u/samexample", npm: "/~samexample", devto: "/samexample", lichess: "/@/samexample", chesscom: "/member/samexample", codeberg: "/samexample", bluesky: "/profile/samexample.example.org",
  wikipedia: "/wiki/Special:Contributions/Samexample", gravatar: "/samexample", codeforces: "/profile/samexample", lobsters: "/~samexample", huggingface: "/samexample", launchpad: "/~samexample", gitea: "/samexample" };
const all25 = () => {
  const profiles = Object.entries(D.PROFILE_SITES).map(([source, [site, host]]) => ({ site, source, handle: "samexample", url: `https://${host}${PATHS[source] ?? "/@SamExample"}`, state: "found", display_name: "Sam Example", bio: "Maps and bread. Invented person for a test fixture.", stats: {} }));
  return { username: "samexample", cached: false, profiles, sources: Object.fromEntries(profiles.map((p) => [p.source, { site: p.site, state: "found" }])) };
};
{
  const ids = Object.keys(D.PROFILE_SITES);
  ok(ids.length === 25 && ids.join() === "gitlab,keybase,hackernews,mastodon,mastodon_mastodon_online,mastodon_mstdn_social,mastodon_fosstodon_org,mastodon_hachyderm_io,mastodon_infosec_exchange,mastodon_mas_to,mastodon_mastodon_world,dockerhub,npm,devto,lichess,chesscom,codeberg,bluesky,wikipedia,gravatar,codeforces,lobsters,huggingface,launchpad,gitea", "25 sources, in the server's order");
  ok(/on 25 sites/.test(D.PROFILE_SOURCE_DESC) && D.MASTODON_INSTANCES.join() === HOSTS.join() && D.PROFILE_SITES.mastodon[0] === "Mastodon" && D.PROFILE_SITES.mastodon_fosstodon_org.join() === "Mastodon (fosstodon.org),fosstodon.org" && D.PROFILE_SITES.launchpad.join() === "Launchpad,launchpad.net" && D.PROFILE_SITES.gitea.join() === "Gitea.com,gitea.com", "the copy says 25, and each instance is a site of its own, named by its host");
  const r = D.readProfileSources(all25());
  ok(r.profiles.length === 25 && r.profiles.map((p) => p.source).join() === ids.join() && Object.keys(r.sources).length === 25 && D.profileCoverage(r).read === 25 && /25 profiles read on 25 sites/.test(D.profileSourcesText(r)), "a found row on each of the 25 is kept, the Launchpad ~ path and every instance's /@Handle included");
  ok(r.profiles.find((p) => p.source === "launchpad").url === "https://launchpad.net/~samexample" && r.profiles.find((p) => p.source === "mastodon_mas_to").url === "https://mas.to/@SamExample" && r.profiles.find((p) => p.source === "mastodon_mas_to").site === "Mastodon (mas.to)", "the addresses and names are the table's");
  const off = all25(); off.profiles.find((p) => p.source === "mastodon_fosstodon_org").url = "https://mastodon.social/@SamExample"; off.profiles.find((p) => p.source === "launchpad").url = "https://launchpad.net/"; off.profiles.find((p) => p.source === "gitea").url = "https://gitea.com.evil.example/samexample"; off.profiles.find((p) => p.source === "mastodon_mas_to").site = "Mastodon (evil.example)";
  const ro = D.readProfileSources(off);
  ok(ro.profiles.length === 22 && ro.sources.mastodon_fosstodon_org.state === "unknown" && ro.sources.launchpad.state === "unknown" && ro.sources.gitea.state === "unknown" && ro.profiles.find((p) => p.source === "mastodon_mas_to").site === "Mastodon (mas.to)", "a row on another instance's host, a bare homepage or a lookalike host is dropped and reads unknown; a site cannot be renamed");
  ok(HOSTS.every((h, i) => D.mastodonInstance(ids[3 + i]) === h && D.mastodonInstance(`https://${h}/@SamExample`) === h && D.mastodonInstance(h.toUpperCase()) === h), "an instance is named by its source id, its host or a profile address on it");
  ok(["", "mastodon_evil_example", "evil.example", "https://evil.example/@a", "http://fosstodon.org/@a", "https://fosstodon.org.evil.example/@a", "https://a:b@fosstodon.org/@a", "https://fosstodon.org:8443/@a", "gitlab", null, 7, {}].every((v) => D.mastodonInstance(v) === ""), "and nothing else is an instance: an unknown host, http, a port, credentials, another source");
  // notes the page knows
  ok(["not an active account", "team", "moved", "suspended", "bot", "organization"].every((k) => D.profileNoteText(k).length > 20) && D.profileNoteText("bio not read") === "" && D.profileNoteText("constructor") === "" && /Not a claimed account\. Launchpad makes such a record by itself/.test(D.PROFILE_NOTE_TEXT["not an active account"]) && /moved to another instance\. This row is the old account/.test(D.PROFILE_NOTE_TEXT.moved), "each known note has the page's own sentence, and an unknown note has none");
  const lp = { source: "launchpad", url: "https://launchpad.net/~samexample", state: "found", handle: "samexample", note: "not an active account" };
  ok(D.unclaimedProfile(lp) && D.unclaimedProfile({ site: "Launchpad", url: lp.url, siteNote: "not an active account" }) && !D.unclaimedProfile({ ...lp, note: "" }) && !D.unclaimedProfile({ ...lp, note: "team" }) && !D.unclaimedProfile({ source: "gitea", url: "https://gitea.com/samexample", note: "not an active account" }) && !D.unclaimedProfile(null), "a Launchpad record the site made itself is not a claimed account; nothing else is unclaimed");
  // the run log does not count a record nobody claimed as a profile that was read
  const un = all25(); un.profiles.find((p) => p.source === "launchpad").note = "not an active account";
  ok(D.profileCoverage(un).unclaimed.join() === "Launchpad" && D.profileCoverage(un).read === 25 && /^24 profiles read on 25 sites, 1 record nobody claimed \(Launchpad\)$/.test(D.profileSourcesText(un)) && D.profileCoverage(all25()).unclaimed.length === 0 && !/nobody claimed/.test(D.profileSourcesText(all25())), "an unclaimed Launchpad record is said apart in the run log and is not a profile read");
  const only = { username: "samexample", cached: false, profiles: [un.profiles.find((p) => p.source === "launchpad")], sources: { launchpad: { site: "Launchpad", state: "found" }, gitea: { site: "Gitea.com", state: "not_found" } } };
  ok(/^0 profiles read on 2 sites, 1 record nobody claimed \(Launchpad\)$/.test(D.profileSourcesText(only)), "alone, it reads as no profile read");
  ok(D.profileSourceId("gitea") === "gitea" && D.profileSourceId("constructor") === "" && D.profileSourceId({ what: "Mastodon (fosstodon.org)", url: "https://fosstodon.org/@SamExample", source: "Profile sources, Sherlock" }) === "mastodon_fosstodon_org" && D.profileSourceId({ site: "Launchpad" }) === "launchpad" && D.profileSourceId({ site: "GitLab", url: "https://evil.example/samexample" }) === "" && D.profileSourceId({ url: "https://www.npmjs.com/~samexample" }) === "npm", "a row's source is its id, else the host of its address, else its site name, and an address elsewhere is none");
  const det = D.profileDetail({ site: "Mastodon (fosstodon.org)", handle: "SamExample", api: true, siteNote: "moved", stats: { starred: 31, karma: 1204 } });
  ok(det.groups[0].rows.some((x) => x.k === "Site note" && x.v === D.PROFILE_NOTE_TEXT.moved) && det.groups[0].rows.some((x) => x.k === "Starred" && x.v === "31") && det.groups[0].rows.some((x) => x.k === "Karma" && x.v === "1,204") && !det.groups[0].rows.some((x) => x.k === "Not read"), "a known note is said in the page's words, and the new counts have labels");
}

// ---- 17. commit emails -------------------------------------------------------------------------------------
const CE = () => ({
  site: "codeberg", site_name: "Codeberg", username: "samexample", state: "found", cached: false, handle: "samexample", profile_url: "https://codeberg.org/samexample", display_name: "Sam Example",
  emails: [
    { email: "sam@example.org", name: "Sam Example", how: "forge_attributed", how_note: "x", self_declared: true, commits: 3, first_commit: "2026-01-15T09:00:00Z", last_commit: "2026-10-30T09:00:00Z", repos: ["samexample/maps", "samexample/tiles-fork"] },
    { email: "Sam.Old@Example.com", name: "Sam Example", how: "author_line_match", how_note: "y", self_declared: true, commits: 1, first_commit: "2025-10-10T08:00:00Z", last_commit: "2025-10-10T08:00:00Z", repos: ["samexample/maps"] }],
  emails_state: "found", complete: true, sections: { account: "found", repos: "ok" },
  repos: [{ name: "samexample/maps", url: "https://codeberg.org/samexample/maps", fork: false, state: "ok", commits_seen: 6 }, { name: "samexample/bread", url: "https://codeberg.org/samexample/bread", fork: false, state: "empty", commits_seen: 0 }, { name: "samexample/tiles-fork", url: "https://codeberg.org/samexample/tiles-fork", fork: true, state: "ok", commits_seen: 2 }],
  counts: { repos_listed: 3, repos_read: 2, commits_seen: 8, own: 5, noreply: 1, other_authors: 3 }, requests: 5, note: "Lives in Berlin.",
});
const ceDown = (state, x = {}) => ({ site: "gitlab", site_name: "GitLab", username: "samexample", state, cached: false, emails: [], emails_state: "unknown", complete: false, sections: { account: state, repos: "not_asked" }, repos: [], counts: {}, requests: 1, ...x });
{
  const r = D.readCommitEmail(CE());
  ok(r.state === "found" && r.emails_state === "found" && r.complete === true && r.emails.length === 2 && r.emails[1].email === "sam.old@example.com" && r.emails[0].how === "forge_attributed" && r.repos.length === 3 && r.repos[2].fork === true && r.counts.other_authors === 3 && !("note" in r) && !("how_note" in r.emails[0]) && !("requests" in r), "a good answer is read whole, and no sentence is kept from it");
  ok(Object.keys(r).join().startsWith("site,site_name,username,state,cached,handle,profile_url,display_name,emails") && r.site_name === "Codeberg" && r.profile_url === "https://codeberg.org/samexample" && r.display_name === "Sam Example" && r.emails.map((e) => e.name).join() === "Sam Example,Sam Example", "the site name, the profile address, the display name and each row's name are kept, in order, for the minor guard");
  ok(D.readCommitEmail(r) === r && JSON.stringify(D.readCommitEmail(clone(r))) === JSON.stringify(r), "reading its own output changes nothing");
  const v = D.commitEmailsView(CE());
  ok(v.state === "found" && v.text === "2 addresses of this account on the 8 commits read." && v.partial === false && v.retry === false && v.note === D.COMMIT_EMAILS_NOTE && !/Berlin/.test(JSON.stringify(v)), "the view counts what was read and carries the page's own caution, never the answer's");
  ok(v.rows[0].strong === true && v.rows[0].howText === D.COMMIT_HOW_TEXT.forge_attributed && v.rows[1].strong === false && /only weakly/.test(v.rows[1].howText) && v.rows[0].first === "2026-01-15" && v.rows[0].last === "2026-10-30" && v.rows[0].repos.map((x) => x.url).join() === "https://codeberg.org/samexample/maps,https://codeberg.org/samexample/tiles-fork" && v.rows[0].repos.every((x) => x.link_kind === "evidence"), "each row says how it is tied, in the page's words, with its dates and its repositories as evidence links");
  ok(/self-declared and can be forged/.test(D.COMMIT_EMAILS_NOTE) && /lead to check/.test(D.COMMIT_EMAILS_NOTE) && /holds the address there/.test(D.COMMIT_HOW_TEXT.forge_attributed) && /Anybody can commit under any name/.test(D.COMMIT_HOW_TEXT.author_line_match), "the fixed sentences say self-declared and weak where they are");
  // hostile input
  const h = CE();
  h.site_name = "<b>Evil</b>"; h.profile_url = "https://codeberg.org/samexample"; h.display_name = "Sam‮ Example" + "x".repeat(500);
  h.emails = [{ email: "javascript:alert(1)", name: "x" }, { email: "ok@example.org", name: "<img src=x>\u0007" + "n".repeat(300), how: "signed-by-god", commits: -3, first_commit: "<b>", last_commit: "2026-01-01T00:00:00Z", repos: ["../../etc/passwd", "samexample/..", "samexample/maps", "a/b", "c/d", "e/f"] }, { email: "OK@example.org", name: "dup" }, { email: "sam@example.org", name: "Sam", how: "forge_attributed", commits: 1e12 }, ...Array.from({ length: 20 }, (_, i) => ({ email: `a${i}@example.org`, name: "n" }))];
  h.repos = [{ name: "samexample/maps", url: "https://evil.example/x", fork: "yes", state: "great", commits_seen: 2 }, { name: "x", state: "ok" }, { name: "a/b/c", state: "ok" }, { name: "q/r", state: "ok" }];
  h.counts = { commits_seen: 1e15, own: -1, other_authors: "many" }; h.retry_after = 1e9;
  const hr = D.readCommitEmail(h);
  ok(hr.site_name === "Codeberg" && Array.from(hr.display_name).length === 200 && !/‮/.test(hr.display_name) && hr.emails.length === 8 && hr.emails[0].email === "sam@example.org" && hr.emails[0].commits === 10000, "the site name is CrawlR's, text is cleaned and clipped, ten rows are read at most, and the stronger tie is listed first");
  const okRow = hr.emails.find((e) => e.email === "ok@example.org");
  ok(okRow.how === "author_line_match" && okRow.name.startsWith("<img src=x>") && Array.from(okRow.name).length === 100 && okRow.commits === 0 && okRow.first_commit === "" && okRow.repos.join() === "samexample/maps" && hr.emails.filter((e) => e.email === "ok@example.org").length === 1 && !hr.emails.some((e) => /javascript/.test(e.email)), "an address must be an address, an unknown tie is the weaker one, a name stays text, a date is a date, and a repository is owner/name");
  ok(hr.repos.length === 1 && hr.repos[0].url === "https://codeberg.org/samexample/maps" && hr.repos[0].fork === null && hr.repos[0].state === "unknown" && hr.counts.commits_seen === 10000 && hr.counts.own === 0 && hr.counts.other_authors === 0 && hr.retry_after === 86400 && hr.complete === false, "a repository's address is rebuilt on the site's host, an unknown state is unknown, and counts are capped");
  for (const u of ["https://evil.example/samexample", "javascript:alert(1)", "https://codeberg.org/", "https://user:pw@codeberg.org/samexample", "https://gitlab.com/samexample", ""]) { const x = D.readCommitEmail({ ...CE(), profile_url: u }); ok(x.state === "unknown" && x.emails.length === 0 && x.emails_state === "unknown" && x.profile_url === "" && D.commitEmailsView(x).retry === true && D.commitEmailLeads(x).length === 0, `a "found" whose profile is not on the site (${u || "none"}) showed nothing: unknown, and no address is kept`); }
  ok(D.readCommitEmail({ ...CE(), site: "github" }) === null && D.readCommitEmail({ ...CE(), site: "constructor" }) === null && D.readCommitEmail({ ...CE(), state: "maybe" }) === null && D.readCommitEmail(null) === null && D.readCommitEmail("x") === null, "another site, an unknown state or no object is not an answer");
  // found with nothing behind it, and partial reads
  const empty = D.readCommitEmail({ ...CE(), emails: [{ email: "nope" }], emails_state: "found" });
  ok(empty.emails_state === "unknown" && D.commitEmailsView(empty).state === "unknown" && /^Could not read the commits/.test(D.commitEmailsView(empty).text), "'found' with no readable row is unknown, never found and never none");
  const part = { ...CE(), complete: false, repos: [{ name: "samexample/maps", fork: null, state: "blocked", commits_seen: 0 }, { name: "samexample/bread", fork: null, state: "ok", commits_seen: 2 }], counts: { commits_seen: 2 } };
  const pv = D.commitEmailsView(part);
  ok(pv.state === "found" && pv.partial === true && pv.retry === true && pv.text === "These, and maybe more: 2 addresses of this account on the 2 commits read, and samexample/maps was refused.", "rows from a partial read are 'these, and maybe more', and say which part did not answer");
  ok(D.readCommitEmail({ ...CE(), complete: true, repos: part.repos }).complete === false && D.readCommitEmail({ ...CE(), complete: true, sections: { account: "found", repos: "failed" } }).complete === false, "'complete' cannot be claimed over a part that did not answer");
  const unk = D.commitEmailsView({ ...CE(), emails: [], emails_state: "unknown", complete: false, sections: { account: "found", repos: "rate_limited" }, repos: [], retry_after: 300 });
  ok(unk.state === "unknown" && unk.retry === true && unk.text === "Could not read the commits: the repository list was rate limited. Whether an address is there is unknown. Try again in 5 minutes." && !/no address|none/i.test(unk.text), "a list that did not answer is unknown, with a retry, never 'none found'");
  const lie = D.readCommitEmail({ ...CE(), emails: [], emails_state: "none", complete: false, sections: { account: "found", repos: "blocked" }, repos: [] });
  ok(lie.emails_state === "unknown", "'none' is an answer, so it cannot be claimed while a part did not answer");
  const none = D.commitEmailsView({ ...CE(), emails: [], emails_state: "none" });
  ok(none.state === "none" && none.retry === false && none.text === "No address of this account on the 8 commits read. 1 commit of its own carries a \"noreply\" placeholder, which is not an address, and 3 commits by other authors were left out." && none.rows.length === 0, "none is an answer, worded with the commits that were read");
  const norepo = D.commitEmailsView({ ...CE(), emails: [], emails_state: "none", sections: { account: "found", repos: "none" }, repos: [], counts: {} });
  ok(norepo.state === "none" && /has no public repository of its own/.test(norepo.text), "an account with no repository of its own says so");
  // each account state has its own sentence
  const t = (state, x) => D.commitEmailsView(ceDown(state, x));
  ok(t("not_found", { emails_state: "none", complete: true }).text === "GitLab has no account with this name, so no commits were read." && t("not_found").retry === false && D.readCommitEmail(ceDown("not_found")).emails_state === "none", "no such account is an answer");
  ok(/refused the request, so whether its commits carry an address is unknown/.test(t("blocked").text) && /rate limiting requests, so whether .* unknown\. Try again in 5 minutes\./.test(t("rate_limited", { retry_after: 300, error: "x", error_code: "rate_limited" }).text) && /could not be asked, so whether .* unknown/.test(t("failed", { error: "x", error_code: "timeout" }).text) && /could not read, so whether .* unknown/.test(t("unknown").text) && t("not_asked", { complete: true }).text === "GitLab cannot hold this handle, so nothing was asked.", "blocked, rate limited, failed, unknown and not asked each have their own sentence");
  ok(["blocked", "rate_limited", "failed", "unknown"].every((s) => t(s).retry === true && t(s).state === s && D.readCommitEmail(ceDown(s, { emails_state: "none", complete: true })).emails_state === "unknown" && D.readCommitEmail(ceDown(s, { complete: true })).complete === false && !/no address|none found/i.test(t(s).text)) && t("not_asked").retry === false, "a site that did not say is unknown with a retry, whatever the answer claims, and is never worded as no address");
  const f = D.readCommitEmail(ceDown("failed", { error: "<b>boom</b>", error_code: "timeout", error_detail: "ReadTimeout" }));
  ok(f.error_code === "timeout" && f.error === "<b>boom</b>" && !("error" in D.readCommitEmail(ceDown("blocked", { error: "x" }))) && D.readCommitEmail({ site: "gitea", error: "x", error_code: "request_failed" }).state === "failed" && JSON.stringify(D.readCommitEmail(clone(f))) === JSON.stringify(f), "a failure keeps its error fields, and a request that failed outright is a failed answer for its site");
  // leads, exports, the model
  const leads = D.commitEmailLeads(CE());
  ok(leads.length === 2 && leads.every((l) => l.kind === "email") && leads[0].value === "sam@example.org" && leads[0].strong === true && /Codeberg ties to this account through its commits/.test(leads[0].from) && leads[1].strong === false && leads[1].how === "author_line_match" && /the weaker tie/.test(leads[1].from) && D.commitEmailLeads(ceDown("failed")).length === 0, "each address is a lead that says how it is tied, and the weaker tie says so");
  const md = D.commitEmailsMarkdown(v).join("\n");
  ok(/^  - Commit emails: 2 addresses of this account on the 8 commits read\. _\(Commit emails · self-declared\)_/.test(md) && /    - sam@example\.org, name on the commits: Sam Example, 3 commits \(2026-01-15 to 2026-10-30\) in \[samexample\/maps\]\(https:\/\/codeberg\.org\/samexample\/maps\)/.test(md) && md.includes(D.COMMIT_EMAILS_NOTE) && !/\u2014/.test(md) && D.commitEmailsMarkdown(null).length === 0, "the export lists each address with its tie and the caution");
  const many = CE(); many.emails = Array.from({ length: 10 }, (_, i) => ({ email: `a${i}@example.org`, name: "Sam Example", how: "author_line_match", commits: 1 }));
  const ai = D.commitEmailsForAi(many);
  ok(ai.addresses.length === 5 && ai.addresses.every((x) => x.self_declared === true && x.tie === "author_line_match" && Object.keys(x).join() === "email,tie,self_declared,commits") && ai.state === "found" && ai.complete === true && ai.site === "Codeberg" && D.commitEmailsForAi(ceDown("failed")).state === "failed" && D.commitEmailsForAi(ceDown("failed")).addresses.length === 0 && !JSON.stringify(D.commitEmailsForAi(CE())).includes("Sam Example"), "the model gets five addresses at most, each with its tie and marked self-declared, and no name");
  // which rows may be asked
  ok(JSON.stringify(D.commitEmailsFor({ source: "gitea", handle: "samexample", url: "https://gitea.com/samexample", state: "found" })) === '{"site":"gitea","username":"samexample"}' && D.commitEmailsFor({ what: "GitLab", url: "https://gitlab.com/SamExample" }).username === "SamExample" && D.commitEmailsFor("codeberg").site === "codeberg", "a read GitLab, Codeberg or Gitea.com row may be asked, with the handle the row has");
  ok(D.commitEmailsFor("github") === null && D.commitEmailsFor({ source: "gitlab", handle: "samexample", state: "not_found" }) === null && D.commitEmailsFor({ site: "GitHub", url: "https://github.com/samexample", handle: "samexample" }) === null && D.commitEmailsFor({ site: "Pornhub", url: "https://www.pornhub.com/users/samexample", handle: "samexample" }) === null && D.commitEmailsFor({ source: "gitlab", url: "https://gitlab.com/", handle: "" }) === null && D.commitEmailsFor(null) === null, "no other site, no row that was not found, and no row without a handle");
  // the map
  const m = D.readCommitEmails({ "acct:codeberg": CE(), "acct:gitlab": ceDown("blocked"), "lead:x": CE(), "acct:bad": { site: "github", state: "found" }, "acct:n": "text", ["acct:" + "k".repeat(200)]: CE(), "__proto__x": CE() });
  ok(Object.keys(m).join() === "acct:codeberg,acct:gitlab" && m["acct:gitlab"].state === "blocked" && D.readCommitEmails(m) === m && JSON.stringify(D.readCommitEmails(clone(m))) === JSON.stringify(m) && Object.keys(D.readCommitEmails(Object.fromEntries(Array.from({ length: 60 }, (_, i) => [`acct:s${i}`, CE()])))).length === 40 && D.readCommitEmails("x") === null, "the map keeps account rows only, forty at most, and reading it again changes nothing");
}

// ---- 18. post activity ---------------------------------------------------------------------------------------
const HOURS = [0, 0, 2, 0, 1, 0, 2, 2, 4, 2, 12, 12, 15, 9, 11, 30, 16, 13, 15, 9, 12, 1, 1, 4];   // 173
const PA = (x = {}) => ({
  site: "mastodon", site_name: "Mastodon", username: "SamExample", instance: "fosstodon.org", found: true, state: "ok", cached: false, complete: true, pages: 5, unit: "public posts", counts: "Lives in Berlin.", window_days_max: 365, bot: false, events: 173,
  window: { first: "2025-11-18T08:04:43Z", last: "2026-11-16T11:05:27Z", days: 364, active_days: 73 }, hours_utc: HOURS.slice(), weekdays_utc: [28, 32, 34, 22, 38, 16, 3],
  types: [{ type: "post", count: 75 }, { type: "reply", count: 65 }, { type: "boost", count: 33 }],
  estimate: { utc_offset_from: -3, utc_offset_to: 2, utc_offsets: [-3, -2, -1, 0, 1, 2], crosses_date_line: false, label: "Lisbon", quiet_start_hour: 0, quiet_end_hour: 8, quiet_hours: 8, quiet_events: 7, basis: "Lives in Lisbon.", assumption: "x", caveat: "y" },
  estimate_reason: null, read: { posts: 200, outside_window: 27, capped: true, available: 568 }, ...x,
});
{
  const r = D.readPostActivity(PA());
  ok(r.site === "mastodon" && r.instance === "fosstodon.org" && r.unit === "public posts" && r.bot === false && r.state === "ok" && r.found === true && r.events === 173 && r.hours_utc.length === 24 && r.weekdays_utc.length === 7 && r.repos.length === 0 && r.estimate.label === "UTC-3 to UTC+2" && r.estimate_reason === null && JSON.stringify(r.read) === '{"posts":200,"outside_window":27,"capped":true,"available":568}' && !("counts" in r), "a good answer has the shape of a GitHub reading plus site, instance, unit, bot and read, and its label is written from the numbers");
  const gh = D.readActivity(U.collected.githubActivity);
  ok(["username", "found", "state", "cached", "complete", "pages", "events", "window", "hours_utc", "weekdays_utc", "types", "repos", "estimate", "estimate_reason"].every((k) => k in r && k in gh), "every key of a GitHub reading is there");
  ok(D.readPostActivity(r) === r && JSON.stringify(D.readPostActivity(clone(r))) === JSON.stringify(r), "reading its own output changes nothing");
  const v = D.postActivityView(PA()), gv = D.activityView(U.collected.githubActivity);
  ok(Object.keys(gv).every((k) => k in v) && v.hours.length === 24 && v.days.length === 7 && v.hours[15].pct === 100 && v.repos.length === 0, "the view has every key the GitHub view has, so one renderer draws both");
  ok(v.text === "173 public posts from 2025-11-18 to 2026-11-16 (364 days, active on 73). Times are UTC." && /^Public posts by hour of day, UTC: 00:00 0,/.test(v.hoursAlt) && /^Public posts by weekday, UTC: Monday 28,/.test(v.daysAlt) && v.label === "Mastodon (fosstodon.org)" && v.types.map((t) => t.word).join() === "posts,replies,boosts", "the sentences and both text alternatives use the site's own word");
  ok(v.estimate.label === "UTC-3 to UTC+2" && v.estimate.basis === "Based on 173 public posts over 364 days (73 with activity). The longest quiet stretch is 00:00 to 08:00 UTC." && v.estimate.assumption === D.ESTIMATE_ASSUMPTION && v.estimate.caveat === D.ESTIMATE_CAVEAT && !/Lisbon|Berlin/.test(JSON.stringify(v)), "the estimate's words are the page's, and a place in the answer does not survive");
  ok(v.footnote === "Counted: public posts, replies and boosts of the local account on fosstodon.org, the newest 200 at most. Only the 365 days before the newest post are counted. The newest 200 were read; the site says the account has 568. 27 older ones were read and not counted." && v.capped === "The newest 200 were read; the site says the account has 568." && v.partial === "" && v.retry === false, "the footnote says what is counted, that the newest were read and how many the site says there are");
  const pp = D.postActivityView(PA({ complete: false, later_pages: "failed" }));
  ok(pp.complete === false && pp.partial === "Partial: fosstodon.org failed on a later page, so older posts are missing." && pp.text.endsWith(pp.partial), "a later page that failed makes it partial, and the page says posts are missing");
  // Hacker News and Lobsters
  const hn = PA({ site: "hackernews", username: "samExample", instance: "fosstodon.org", bot: true, types: [{ type: "comment", count: 150 }, { type: "story", count: 20 }, { type: "boost", count: 3 }, { type: "PushEvent", count: 1 }], read: { posts: 1000, outside_window: 0, capped: true, available: null } });
  const hr = D.readPostActivity(hn), hv = D.postActivityView(hn);
  ok(hr.instance === "" && hr.bot === false && hr.username === "samExample" && hr.types.map((t) => t.type).join() === "comment,story" && hr.estimate !== null && hv.label === "Hacker News" && hv.capped === "The newest 1,000 were read; the account has more." && /^Counted: stories and comments, the newest 1,000 at most\./.test(hv.footnote), "Hacker News has no instance and no automated flag, keeps the handle's case, and knows its own kinds only");
  const lb = PA({ site: "lobsters", types: [{ type: "story", count: 173 }, { type: "comment", count: 9 }], read: { posts: 173, outside_window: 0, capped: false, available: null } });
  const lv = D.postActivityView(lb);
  ok(D.readPostActivity(lb).unit === "submitted stories" && lv.text.startsWith("173 submitted stories from") && /^Submitted stories by hour of day/.test(lv.hoursAlt) && /Based on 173 submitted stories over/.test(lv.estimate.basis) && lv.types.length === 1 && /Lobsters has no public list of a user's comments, so comments are not counted\. Only the 365 days before the newest story are counted\./.test(lv.footnote) && lv.capped === "", "Lobsters counts submitted stories, and says comments are not counted");
  // an automated account, and reasons
  const bot = D.readPostActivity(PA({ bot: true, estimate_reason: { code: "bot_account", text: "x" } }));
  ok(bot.bot === true && bot.estimate === null && bot.estimate_reason.code === "bot_account" && D.postActivityView(bot).noEstimate === D.BOT_REASON && D.postActivityView(bot).estimate === null && JSON.stringify(D.readPostActivity(clone(bot))) === JSON.stringify(bot), "an automated account is counted and never estimated, whatever estimate the answer carries");
  const few = D.postActivityView(PA({ estimate: null, estimate_reason: { code: "too_few_days", text: "Lives in Berlin." } })), odd = D.postActivityView(PA({ estimate: null, estimate_reason: { code: "vibes", text: "Lives in Berlin." } }));
  ok(few.noEstimate === "The posts fall on too few days to show a daily pattern: 73 seen." && odd.noEstimate === "No estimate was made." && D.readPostActivity(PA({ estimate: null, estimate_reason: { code: "bot_account" } })).estimate_reason.code === "none", "a reason is written here from its code, an unknown code says only that none was made, and 'automated' cannot be claimed for an account that is not");
  // none, not found
  const none = (site, x = {}) => ({ site, username: "samexample", found: true, state: "none", cached: false, complete: true, pages: 1, events: 0, window: { first: "", last: "", days: 0, active_days: 0 }, hours_utc: Array(24).fill(0), weekdays_utc: Array(7).fill(0), types: [], estimate: null, estimate_reason: null, read: { posts: 0, outside_window: 0, capped: false, available: 0 }, ...x });
  ok(D.postActivityView(none("lobsters")).text === "The account exists and has no submitted stories. Lobsters has no public list of a user's comments, so the account may still comment." && !/inactive/.test(D.postActivityView(none("lobsters")).text) && /no public posts: no story and no comment/.test(D.postActivityView(none("hackernews")).text) && D.postActivityView(none("mastodon")).text === "The account exists and has no public posts on mastodon.social." && D.postActivityView(none("mastodon")).retry === false && D.readPostActivity(none("mastodon")).instance === "mastodon.social", "none is an answer, worded per site: Lobsters has no submitted stories, never 'inactive'; no instance is mastodon.social");
  const claim = D.readPostActivity(PA({ hours_utc: Array(24).fill(0), events: 900 }));
  ok(claim.state === "none" && claim.events === 0 && claim.estimate === null && claim.types.length === 0 && D.readPostActivity(PA({ events: 5000 })).events === 173, "'ok' with nothing counted reads as none, and the count is the histogram's own sum");
  const nf = D.readPostActivity({ site: "hackernews", site_name: "Hacker News", username: "Samexample", found: false, state: "not_found", cached: false });
  const na = D.readPostActivity({ site: "hackernews", username: "has.dot", found: false, state: "not_found", note: "Hacker News cannot hold this handle, so nothing was asked." });
  ok(nf.found === false && !("not_asked" in nf) && D.postActivityView(nf).text === "Hacker News has no account with this name. Hacker News names are case sensitive." && na.not_asked === true && !("note" in na) && D.postActivityView(na).text === "Hacker News cannot hold this handle, so nothing was asked." && D.readPostActivity(clone(na)).not_asked === true && !("not_asked" in D.readPostActivity({ site: "lobsters", state: "not_found", note: "Lives in Berlin." })) && D.postActivityView({ site: "mastodon", instance: "mas.to", state: "not_found" }).text === "mas.to has no local account with this name.", "no such account is an answer; a handle the site cannot hold is flagged, in the page's sentence, and no other note is kept");
  // unknown states
  const rl = D.readPostActivity({ site: "lobsters", site_name: "Lobsters", username: "samexample", found: null, state: "rate_limited", cached: false, error: "Rate limited by the source.", error_code: "rate_limited", error_detail: "HTTP 429 from lobste.rs", retry_after: 60 });
  const fl = D.readPostActivity({ site: "mastodon", username: "samexample", instance: "https://Mastodon.Social/", found: null, state: "failed", error: "The source returned an error.", error_code: "upstream", error_detail: "HTTP 401 from mastodon.social" });
  ok(rl.state === "rate_limited" && rl.found === null && rl.retry_after === 60 && rl.error_code === "rate_limited" && fl.state === "failed" && fl.instance === "mastodon.social" && fl.error_code === "upstream" && JSON.stringify(D.readPostActivity(clone(rl))) === JSON.stringify(rl), "rate limited and failed keep their error fields and the wait");
  const rv = D.postActivityView(rl), fv = D.postActivityView(fl);
  ok(rv.retry === true && rv.text === "Lobsters is rate limiting requests, so when this account posts is unknown. Try again in a minute." && fv.retry === true && fv.text === "mastodon.social could not be asked, so when this account posts is unknown." && ![rv, fv].some((x) => /no (public )?posts|no submitted|no account|not found/i.test(x.text)) && D.readPostActivity({ site: "lobsters", error: "x", error_code: "timeout" }).state === "failed", "a site that could not be asked is unknown with a retry, never 'no posts' and never 'not found'");
  // hostile input
  ok(D.readPostActivity(PA({ instance: "evil.example" })) === null && D.readPostActivity(PA({ instance: { a: 1 } })) === null && D.readPostActivity(PA({ site: "github" })) === null && D.readPostActivity(PA({ site: "constructor" })) === null && D.readPostActivity(PA({ state: "fine" })) === null && D.readPostActivity(PA({ hours_utc: [1, 2] })) === null && D.readPostActivity(null) === null, "an instance CrawlR does not read, another site, an unknown state or an answer without 24 hours is not an answer");
  const bad1 = D.readPostActivity(PA({ username: "Sam‮Example\u0007" + "x".repeat(200), unit: "<b>crimes</b>", events: 1e15, pages: 1e9, window: { first: "<img>", last: "2026-11-16T11:05:27Z", days: 1e9, active_days: 1e9 }, read: { posts: -5, outside_window: "x", capped: "yes", available: 1e15 }, estimate: { utc_offset_from: 1, utc_offset_to: 2, utc_offsets: [1, 2], label: "Central European Time (Berlin)", quiet_start_hour: 99, quiet_end_hour: 8 } }));
  ok(Array.from(bad1.username).length === 64 && !/[‮\u0007]/.test(bad1.username) && bad1.unit === "public posts" && bad1.events === 173 && bad1.pages === 20 && bad1.window.first === "" && bad1.window.days === 400 && bad1.window.active_days === 400 && JSON.stringify(bad1.read) === '{"posts":0,"outside_window":0,"capped":false,"available":1000000000}' && bad1.estimate.label === "UTC+1 to UTC+2" && bad1.estimate.quiet_start_hour === null, "text is cleaned and clipped, the unit is the site's, counts are capped, and a label that names a place is written again");
  // exports and the model
  const md = D.postActivityMarkdown(PA()).join("\n"), mo = D.postActivityMarkdown(PA(), { own: false, text: "This account is filed as a different person." }).join("\n");
  ok(/^## Mastodon \(fosstodon\.org\) post activity\n- 173 public posts from/.test(md) && /UTC offset estimate: UTC-3 to UTC\+2\. .*A hint, not a fact\..*never a place\./.test(md) && /- Kinds of post: posts \(75\), replies \(65\), boosts \(33\)/.test(md) && /- Counted: public posts, replies and boosts/.test(md) && /post activity \(not the person this case is about\)\n_This account is filed as a different person\._/.test(mo) && !/\u2014/.test(md) && /^## Lobsters post activity\n- Lobsters is rate limiting/.test(D.postActivityMarkdown(rl).join("\n")) && D.postActivityMarkdown(null).length === 0, "the export has the estimate's caveat and the footnote, says whose account it is, and an unknown state stays unknown");
  const ai = D.postActivityForAi(PA());
  ok(ai.site === "Mastodon (fosstodon.org)" && ai.state === "ok" && ai.hours_utc.length === 24 && ai.utc_offset_estimate.range === "UTC-3 to UTC+2" && ai.utc_offset_estimate.caveat === D.ESTIMATE_CAVEAT && ai.kinds.length === 3 && /Counted:/.test(ai.counted) && JSON.stringify(ai).length < 2000 && D.postActivityForAi(rl).state === "rate_limited" && /unknown/.test(D.postActivityForAi(rl).note) && D.postActivityForAi({}) === null && D.postActivityForAi(bot).automated_account === true, "the model gets a bounded reading with the caveat, and an unknown state as unknown");
  // which rows may be asked
  const j = (v) => JSON.stringify(D.postActivityFor(v));
  ok(j({ source: "hackernews", handle: "samExample", url: "https://news.ycombinator.com/user?id=samExample", state: "found" }) === '{"site":"hackernews","username":"samExample"}' && j({ source: "mastodon_fosstodon_org", handle: "SamExample", url: "https://fosstodon.org/@SamExample" }) === '{"site":"mastodon","username":"SamExample","instance":"fosstodon.org"}' && j({ source: "mastodon", handle: "sam" }) === '{"site":"mastodon","username":"sam","instance":"mastodon.social"}' && j({ what: "Lobsters", url: "https://lobste.rs/~samexample" }) === '{"site":"lobsters","username":"samexample"}' && j({ what: "Hacker News", url: "https://news.ycombinator.com/user?id=samExample" }) === '{"site":"hackernews","username":"samExample"}', "a read Hacker News, Lobsters or Mastodon row may be asked, with the handle as the row has it and the instance from the row");
  ok(HOSTS.every((h) => D.postActivityFor({ url: `https://${h}/@SamExample` }).instance === h) && D.postActivityFor({ what: "Mastodon (evil.example)", url: "https://evil.example/@SamExample", handle: "SamExample" }) === null && D.postActivityFor({ source: "gitlab", handle: "samexample" }) === null && D.postActivityFor({ source: "lobsters", handle: "samexample", state: "blocked" }) === null && D.postActivityFor({ source: "hackernews", handle: "" }) === null && D.postActivityFor({ site: "Pornhub", url: "https://www.pornhub.com/users/a", handle: "a" }) === null && D.postActivityFor(undefined) === null, "every known instance may be asked; an unknown instance, another site, a row that was not found or has no handle may not");
  const m = D.readPostActivities({ "acct:hackernews": hn, "acct:fosstodon.org": PA(), "acct:lobsters": rl, "acct:x": PA({ instance: "evil.example" }), "note": PA(), "acct:y": 7 });
  ok(Object.keys(m).join() === "acct:hackernews,acct:fosstodon.org,acct:lobsters" && m["acct:lobsters"].state === "rate_limited" && D.readPostActivities(m) === m && JSON.stringify(D.readPostActivities(clone(m))) === JSON.stringify(m), "the map keeps account rows only, a failure stays a failure, and reading it again changes nothing");
}

// ---- 19. do the offset ranges fit? --------------------------------------------------------------------------
{
  const est = (offs) => ({ state: "ok", estimate: { utc_offsets: offs } });
  const gh = D.readActivity({ ...clone(U.collected.githubActivity), estimate: { utc_offset_from: -5, utc_offset_to: -2, utc_offsets: [-5, -4, -3, -2] } });
  const hn = D.readPostActivity(PA({ site: "hackernews", estimate: { utc_offset_from: -6, utc_offset_to: -3, utc_offsets: [-6, -5, -4, -3] } }));
  const a = D.compareOffsets([{ label: "Hacker News", answer: hn }, { label: "GitHub", answer: gh }]);
  ok(a.verdict === "agree" && a.compared === 2 && a.shared.join() === "-5,-4,-3" && a.label === "UTC-5 to UTC-3" && a.labels.join() === "Hacker News,GitHub" && a.text === "Hacker News and GitHub fit the same range (UTC-5 to UTC-3).", "two readings that share offsets agree, in the contract's words");
  ok(a.caution === `${D.OFFSETS_AGREE_NOTE} ${D.OFFSETS_NOT_A_PLACE}` && /supports .* does not prove/.test(D.OFFSETS_AGREE_NOTE) && /does not show two people/.test(D.OFFSETS_DISAGREE_NOTE) && /never a place/.test(D.OFFSETS_NOT_A_PLACE), "agreement is supporting, not proof, and a range is never a place");
  const d = D.compareOffsets([{ label: "Hacker News", answer: hn }, { label: "GitHub", answer: est([5, 6, 7]) }, { label: "Lobsters", answer: est([-4, -3]) }]);
  ok(d.verdict === "disagree" && d.compared === 3 && d.shared.length === 0 && d.label === "" && d.text === "Hacker News, GitHub and Lobsters do not fit one range." && d.caution.startsWith(D.OFFSETS_DISAGREE_NOTE), "no offset in all of them: they disagree, and that does not show two people");
  const one = D.compareOffsets([{ label: "Hacker News", answer: hn }, { label: "GitHub", answer: D.readActivity({ ...clone(U.collected.githubActivity), estimate: null }) }, { label: "Lobsters", answer: { state: "rate_limited", error: "x" } }, { label: "X", answer: { state: "none", estimate: { utc_offsets: [1] } } }]);
  ok(one.verdict === "not_enough_data" && one.compared === 1 && one.text === "Only one account has enough activity to compare." && one.labels.join() === "Hacker News" && one.caution === "", "a reading with no estimate, or in any state but ok, takes no part: one reading is not a comparison");
  const zero = D.compareOffsets([{ label: "A", answer: null }, null, "x"]);
  ok(zero.verdict === "not_enough_data" && zero.compared === 0 && zero.text === "" && D.compareOffsets(null).compared === 0 && D.compareOffsets([{ label: "A", answer: est([1, "2"]) }, { label: "B", answer: est([13]) }, { label: "C", answer: est([]) }]).compared === 0, "nothing to compare says nothing, and a list that is not whole offsets from -11 to 12 is not a range");
  const line = D.compareOffsets([{ label: "Mastodon (mas.to)", answer: est([10, 11, 12, -11, -10]) }, { label: "GitHub", answer: est([11, 12, -11, -10, -9]) }]);
  ok(line.verdict === "agree" && line.shared.join() === "11,12,-11,-10" && line.label === "UTC+11 to UTC+12 or UTC-11 to UTC-10" && !/UTC\+11 to UTC-10/.test(line.text) && line.text === "Mastodon (mas.to) and GitHub fit the same range (UTC+11 to UTC+12 or UTC-11 to UTC-10).", "a shared run across the date line is two runs joined by 'or', never one span");
  ok(D.compareOffsets([{ label: "A", answer: est([12]) }, { label: "B", answer: est([12, -11]) }]).label === "UTC+12" && D.compareOffsets([{ label: "<b>A</b>‮", answer: est([0]) }, { answer: est([0]) }]).text === "<b>A</b> and An account fit the same range (UTC).", "a label is cleaned text, and a reading without one still has a name");
}

// ---- 20. what changed between two archived copies ----------------------------------------------------------
const PURL = "https://codeberg.org/samexample";
const side = (ts, x = {}) => ({ state: "ok", timestamp: ts, asked: ts, exact: true, url: "https://evil.example/snap", bytes: 64235, truncated: false, title: "samexample (Sam Example) · Codeberg", text_lines: 68, links: 28, ...x });
const TITLE = "samexample (Sam Example) · Codeberg";
const AD = (x = {}) => ({
  url: PURL, state: "ok", from: side("2019-03-04T05:06:07Z"), to: side("2024-01-02T03:04:05Z"),
  removed: { text: ["Sam Example", "Night shift cartographer at Example Maps.", "Lisbon"], text_total: 3, links: [{ url: "https://social.example.net/@samexample", external: true }, { url: "https://codeberg.org/samexample/oldmaps", external: false }], links_total: 2 },
  added: { text: ["S E"], text_total: 1, links: [{ url: "https://photos.example.com/samexample", external: true }], links_total: 1 },
  complete: true, swapped: false, cached: false, ...x,
});
{
  const r = D.readArchiveDiff(AD(), PURL);
  ok(r.state === "ok" && r.complete === true && r.from.url === "https://web.archive.org/web/20190304050607/https://codeberg.org/samexample" && r.to.url === "https://web.archive.org/web/20240102030405/https://codeberg.org/samexample" && r.from.exact === true && r.from.title === "samexample (Sam Example) · Codeberg" && r.removed.text.length === 3 && r.removed.links.length === 2 && r.removed.links[1].external === false && r.added.links[0].external === true, "a good answer is read whole, and each snapshot address is rebuilt from its timestamp and the profile address");
  ok(JSON.stringify(D.readArchiveDiff(clone(r), PURL)) === JSON.stringify(r) && JSON.stringify(D.readArchiveDiff(D.readArchiveDiff(r, PURL), PURL)) === JSON.stringify(r), "reading its own output changes nothing");
  const v = D.archiveDiffView(r, { subjects: ["samexample"], secrets: ["samexample"] });
  ok(v.state === "ok" && v.text === "Between the captures of 2019-03-04 and 2024-01-02: 3 lines and 2 links removed, 1 line and 1 link added." && v.from.label === "2019-03-04" && v.to.label === "2024-01-02" && v.from.link_kind === "evidence" && v.from.url === r.from.url && v.from.note === "" && v.retry === false, "the view names both captures, with their snapshot links");
  ok(v.removed.links[0].link_kind === "templated_unverified" && v.removed.links[0].label === "social.example.net/@samexample" && v.removed.links[0].external === true && v.removed.more === "" && v.caveats.join("|") === D.ARCHIVE_DIFF_CAVEATS.join("|") && /by line and by link, not by position/.test(v.caveats[0]) && /Removed does not mean deleted by the owner/.test(v.caveats[1]) && /followers or stars/.test(v.caveats[2]) && /Captures far apart differ in layout/.test(v.caveats[3]), "a link found on an archived page is an unverified URL, and the reading notes are fixed sentences");
  // hostile input
  const h = AD();
  h.removed.text = ["<script>alert(1)</script>", "a‮b\u0000c", "x".repeat(900), 7, { a: 1 }, "", "  spaced   out  ", ...Array(200).fill("line")];
  h.removed.text_total = 1e12;
  h.removed.links = [{ url: "javascript:alert(1)", external: true }, { url: "https://user:pw@example.org/a", external: true }, { url: "https://www.pornhub.com/users/a", external: true }, { url: "https://example.org:8443/a", external: true }, { url: "https://192.0.2.7/a", external: true }, { url: "https://example.org/" + "a".repeat(400), external: true }, { url: "mailto:sam@example.org", external: true }, { url: "https://codeberg.org/other", external: true }, { url: "https://ok.example.org/page", external: "yes" }, { url: "https://ok.example.org/page", external: true }, { url: "https://search.example.org/find?q=samexample", external: true }, { url: "https://twitter.com/", external: true }, ...Array.from({ length: 100 }, (_, i) => ({ url: `https://many.example.org/p${i}`, external: true }))];
  h.from.title = "T‮" + "t".repeat(500); h.from.bytes = 1e15; h.to.truncated = true;
  const hr = D.readArchiveDiff(h, PURL);
  ok(hr.removed.text[0] === "<script>alert(1)</script>" && hr.removed.text[1] === "a b c" && Array.from(hr.removed.text[2]).length === 300 && hr.removed.text[3] === "spaced out" && hr.removed.text.length === 117 && hr.removed.text.every((t) => typeof t === "string" && t) && hr.removed.text_total === 5000, "a line is a cleaned, clipped string: '<' stays text, control and direction characters go, and at most 120 are read");
  const urls = hr.removed.links.map((l) => l.url);
  ok(!urls.some((u) => /javascript|user:pw|pornhub|8443|192\.0\.2|mailto|a{400}/.test(u)) && urls.filter((u) => u === "https://ok.example.org/page").length === 1 && hr.removed.links.find((l) => l.url === "https://ok.example.org/page").external === false && hr.removed.links.find((l) => l.url === "https://codeberg.org/other").external === false && hr.removed.links.length === 52 && hr.removed.links_total === 52, "a link is http(s) with no credentials, port or bare address, never an adult site, listed once, and a link on the profile's own host is never external");
  ok(Array.from(hr.from.title).length === 200 && !/‮/.test(hr.from.title) && hr.from.bytes === 4e6 && hr.complete === false && JSON.stringify(D.readArchiveDiff(clone(hr), PURL)) === JSON.stringify(hr), "a title is clipped, a count capped, and 'complete' cannot be claimed over a truncated capture or a capped list");
  const hv = D.archiveDiffView(hr, { subjects: ["samexample"], secrets: ["samexample", "sam@example.org"] });
  const lk = (u) => hv.removed.links.find((l) => l.label === u);
  ok(lk("search.example.org/find?q=samexample").link_kind === "none" && lk("search.example.org/find?q=samexample").url === "" && lk("twitter.com").link_kind === "none" && lk("ok.example.org/page").link_kind === "templated_unverified" && /^And 4,883 more lines: open the two captures to see them\.$/.test(hv.removed.more) && / There may be more differences than shown\.$/.test(hv.text) && /larger than 2 MB/.test(hv.to.note), "a link with the case's handle in its query, or a bare homepage, is text only; a capped list says how many more");
  ok(D.readArchiveDiff(AD(), "https://www.pornhub.com/users/a") === null && D.readArchiveDiff(AD(), "javascript:alert(1)") === null && D.readArchiveDiff(AD(), "https://news.ycombinator.com/user?id=samexample") === null && D.readArchiveDiff(AD({ state: "great" }), PURL) === null && D.readArchiveDiff(null, PURL) === null && D.archiveDiffView(null) === null, "an address that may not be looked up, or an unknown state, has no answer");
  // 'ok' with nothing behind it
  const hollow = [AD({ from: null }), AD({ to: side("not a time") }), AD({ from: side("2024-01-02T03:04:05Z"), to: side("2019-03-04T05:06:07Z") }), AD({ to: side("2024-01-02T03:04:05Z", { state: "failed" }) })].map((x) => D.readArchiveDiff(x, PURL));
  ok(hollow.every((x) => x.state === "failed" && x.error_code === "bad_response" && x.removed.text.length === 0 && D.archiveDiffView(x).retry === true && D.archiveDiffLeads(x).length === 0 && D.archiveDiffTexts(x).every((t) => t.bio === TITLE)), "'ok' without two captures that were read, the older first, showed nothing: unknown, and nothing but a page title is taken from it");
  const empty = D.readArchiveDiff(AD({ removed: {}, added: null }), PURL);
  ok(empty.state === "same" && !empty.same_capture, "'ok' with no difference behind it is 'same'");
  // inexact captures
  const ix = D.readArchiveDiff(AD({ to: side("2024-01-05T00:00:00Z", { asked: "2024-01-02T03:04:05Z", exact: true }) }), PURL), iv = D.archiveDiffView(ix);
  ok(ix.to.exact === false && ix.to.asked === "2024-01-02T03:04:05Z" && iv.to.label === "2024-01-05" && /^Asked for 2024-01-02: the archive answered with this capture, the nearest one/.test(iv.to.note) && iv.caveats.at(-1) === D.ARCHIVE_INEXACT_NOTE && iv.caveats.length === 5, "a capture that is not the one asked for is labelled with the capture really read, whatever 'exact' claims");
  // same
  const sm = D.readArchiveDiff(AD({ state: "same", to: side("2019-06-01T00:00:00Z"), removed: AD().removed }), PURL);
  ok(sm.state === "same" && sm.removed.text.length === 0 && sm.complete === true && D.archiveDiffView(sm).text === "The captures of 2019-03-04 and 2019-06-01 show the same text and the same links. Pictures, layout and scripts are not compared." && D.archiveDiffView(sm).caveats.length === 0, "same: nothing differs, and pictures and layout were not compared");
  const sc = D.readArchiveDiff(AD({ state: "same", to: side("2019-03-04T05:06:07Z", { asked: "2019-06-01T00:00:00Z" }), note: "The archive answered both times with the same capture." }), PURL), sc2 = D.readArchiveDiff(AD({ to: side("2019-03-04T05:06:07Z") }), PURL);
  ok(sc.same_capture === true && D.archiveDiffView(sc).text === "The archive answered both times with the same capture. Nothing was compared." && sc2.state === "same" && sc2.same_capture === true && sc2.removed.text.length === 0 && JSON.stringify(D.readArchiveDiff(clone(sc), PURL)) === JSON.stringify(sc), "one capture compared with itself is flagged: nothing was compared, whatever lists the answer carries");
  // none
  const nn = D.readArchiveDiff(AD({ state: "none", missing: ["from", "to"], to: side("2024-01-02T03:04:05Z", { state: "none", bytes: 0, title: "", reason: "redirect", note: "Lives in Berlin." }), complete: false }), PURL);
  ok(nn.state === "none" && nn.missing.join() === "to" && nn.to.reason === "redirect" && nn.to.note === D.ARCHIVE_SIDE_NOTES.redirect && nn.removed.text.length === 0 && D.archiveDiffView(nn).text === "Nothing was compared. The newer capture: That capture is a redirect to another page, not the profile itself." && D.archiveDiffView(nn).retry === false && D.archiveDiffView(nn).to.note === D.ARCHIVE_SIDE_NOTES.redirect, "a missing capture names its side and its reason, in the page's sentence");
  ok(D.readArchiveDiff(AD({ state: "none", from: side("2019-03-04T05:06:07Z", { state: "none", reason: "vibes" }), to: side("2024-01-02T03:04:05Z", { state: "none", reason: "not_a_page" }) }), PURL).missing.join() === "from,to" && D.readArchiveDiff(AD({ state: "none", from: side("2019-03-04T05:06:07Z", { state: "none", reason: "vibes" }) }), PURL).from.reason === "missing" && D.readArchiveDiff(AD({ state: "none" }), PURL).state === "failed", "an unknown reason is only 'missing', and 'none' with no missing side is unknown");
  // unknown states
  const rl = D.readArchiveDiff(AD({ state: "rate_limited", to: side("2024-01-02T03:04:05Z", { state: "rate_limited" }), error: "Rate limited by the source.", error_code: "rate_limited", error_detail: "HTTP 429 from web.archive.org", retry_after: 60 }), PURL);
  const fl = D.readArchiveDiff(AD({ state: "failed", from: side("2019-03-04T05:06:07Z", { state: "failed" }), error: "The source took too long to answer.", error_code: "timeout", error_detail: "ReadTimeout" }), PURL);
  ok(rl.state === "rate_limited" && rl.retry_after === 60 && rl.removed.text.length === 0 && rl.to.state === "rate_limited" && fl.error_code === "timeout" && fl.from.state === "failed" && fl.removed.links.length === 0, "rate limited and failed keep their error fields and no difference");
  ok(D.archiveDiffView(rl).retry === true && D.archiveDiffView(rl).text === "The Internet Archive is rate limiting requests, so what changed is unknown. Try again in a minute." && D.archiveDiffView(fl).retry === true && /could not be asked, so what changed is unknown/.test(D.archiveDiffView(fl).text) && ![rl, fl].some((x) => /same text|no difference|holds no capture|Nothing was compared/.test(D.archiveDiffView(x).text)) && D.archiveDiffView(fl).from.note === "This capture could not be read.", "an archive that could not be asked is unknown with a retry, never 'no difference' and never 'no capture'");
  // refused
  ok(Object.keys(D.ARCHIVE_DIFF_REFUSALS).join() === "adult_site,bad_url,not_public_host,bad_timestamp,same_timestamp" && D.ARCHIVE_DIFF_REFUSALS.adult_site === D.ARCHIVE_REFUSALS[0] && Object.keys(D.ARCHIVE_DIFF_REFUSALS).every((k) => { const x = D.readArchiveDiff({ url: "", state: "refused", from: null, to: null, reason: k, note: "Lives in Berlin.", removed: AD().removed }, PURL); return x.reason === k && x.note === D.ARCHIVE_DIFF_REFUSALS[k] && x.from === null && x.removed.text.length === 0 && D.archiveDiffView(x).text === `Not compared. ${D.ARCHIVE_DIFF_REFUSALS[k]}` && D.archiveDiffView(x).retry === false; }), "each of the five refusals has the page's own sentence, and no request means no retry");
  const ru = D.readArchiveDiff({ state: "refused", reason: "because", note: "Lives in Berlin." }, PURL);
  ok(ru.reason === "" && ru.note === "This address was not looked up." && JSON.stringify(D.readArchiveDiff(clone(ru), PURL)) === JSON.stringify(ru), "an unknown reason says only that nothing was looked up");
  // leads
  const leads = D.archiveDiffLeads(r, { site: "Codeberg" });
  ok(leads.length === 1 && JSON.stringify(leads[0]) === '{"kind":"url","value":"https://social.example.net/@samexample","from":"removed from the archived Codeberg profile between 2019-03-04 and 2024-01-02"}', "a removed link that leaves the site is a lead that says where it came from; an added link and a link on the site are not");
  ok(!D.archiveDiffLeads(hr, { site: "Codeberg" }).some((l) => /pornhub|javascript|user:pw/.test(l.value)) && D.archiveDiffLeads(hr).length === 20 && D.archiveDiffLeads(hr, { site: "<b>X</b>‮" })[0].from.startsWith("removed from the archived <b>X</b> profile between") && D.archiveDiffLeads(hr).find((l) => l.value === "https://twitter.com/").bare === true && [sm, nn, rl, fl, ru, null].every((x) => D.archiveDiffLeads(x).length === 0), "no adult site is ever a lead, a front page is marked bare, twenty at most, and only an 'ok' answer gives any");
  // pairs
  const arch = D.readArchive({ state: "ok", count: 9, first: "2015-01-01T00:00:00Z", last: "2024-01-02T03:04:05Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }, { timestamp: "2021-05-06T07:08:09Z" }, { timestamp: "2024-01-02T03:04:05Z" }] }, PURL);
  const pairs = D.archiveDiffPairs(arch);
  ok(pairs.length === 3 && JSON.stringify(pairs[0]) === '{"from":"2021-05-06T07:08:09Z","to":"2024-01-02T03:04:05Z","label":"2021-05-06 to 2024-01-02","default":true}' && pairs[1].from === "2019-03-04T05:06:07Z" && pairs[1].to === "2021-05-06T07:08:09Z" && JSON.stringify(pairs[2]) === '{"from":"2015-01-01T00:00:00Z","to":"2024-01-02T03:04:05Z","label":"2015-01-01 to 2024-01-02","distant":true}', "the default pair is the last two snapshots, then the neighbours before it, then first against last, marked distant");
  const two = D.archiveDiffPairs(D.readArchive({ state: "ok", count: 2, first: "2019-03-04T05:06:07Z", last: "2019-03-04T09:00:00Z", snapshots: [{ timestamp: "2019-03-04T09:00:00Z" }, { timestamp: "2019-03-04T05:06:07Z" }] }, PURL));
  ok(two.length === 1 && two[0].from === "2019-03-04T05:06:07Z" && two[0].label === "2019-03-04 05:06 UTC to 2019-03-04 09:00 UTC" && two[0].default === true && !two[0].distant, "two snapshots are one pair, older first, and two captures of one day are told apart by the time");
  ok(D.archiveDiffPairs(D.readArchive({ state: "ok", count: 1, first: "2019-03-04T05:06:07Z", last: "2019-03-04T05:06:07Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }] }, PURL)).length === 0 && D.archiveDiffPairs(D.readArchive({ state: "refused", note: D.ARCHIVE_REFUSALS[0] }, PURL)).length === 0 && D.archiveDiffPairs(D.readArchive({ state: "failed", error: "x", error_code: "timeout" }, PURL)).length === 0 && D.archiveDiffPairs({ ...arch, url: "https://www.pornhub.com/users/a" }).length === 0 && D.archiveDiffPairs(null).length === 0, "one snapshot, a refused or failed lookup, or an adult site offers no comparison");
  // exports
  const md = D.archiveDiffMarkdown(v).join("\n");
  ok(/^  - Archive diff: Between the captures of 2019-03-04 and 2024-01-02: .* Captures: \[2019-03-04\]\(https:\/\/web\.archive\.org\/web\/20190304050607\/https:\/\/codeberg\.org\/samexample\), \[2024-01-02\]\([^)]+\) _\(Internet Archive · archive record\)_/.test(md) && /    - Removed text: "Sam Example"; "Night shift cartographer at Example Maps\."; "Lisbon"/.test(md) && /    - Removed links: \[social\.example\.net\/@samexample\]\(https:\/\/social\.example\.net\/@samexample\) \(unverified URL\)/.test(md) && md.includes(D.ARCHIVE_DIFF_CAVEATS[1]) && !/\u2014/.test(md) && !/archive record/.test(D.archiveDiffMarkdown(D.archiveDiffView(fl)).join("\n")) && D.archiveDiffMarkdown(null).length === 0, "the export has both captures, the lines, the links marked unverified and the reading notes");
  // the minor guard's text: the server's pieces, in the server's order
  const texts = D.archiveDiffTexts(r);
  ok(texts.length === 1 && JSON.stringify(texts[0]) === JSON.stringify({ source: "Internet Archive", url: r.from.url, bio: `${TITLE}\nSam Example\nNight shift cartographer at Example Maps.\nLisbon\nS E` }) && D.archiveDiffTexts(D.readArchiveDiff(AD({ to: side("2024-01-02T03:04:05Z", { title: "samexample (S E) · Codeberg" }) }), PURL))[0].bio.split("\n").slice(0, 2).join("|") === `${TITLE}|samexample (S E) · Codeberg`, "the scan reads the older title, the newer one when it differs, the removed lines, then the added ones, one per line, under the 'from' snapshot");
  const long = AD(); long.removed.text = Array.from({ length: 10 }, (_, i) => `r${i} ` + "é".repeat(296)); long.removed.text_total = 10; long.added.text = Array.from({ length: 5 }, (_, i) => `a${i} ` + "\u{1F600}".repeat(296)); long.added.text_total = 5;
  const lt = D.archiveDiffTexts(D.readArchiveDiff(long, PURL));
  // The server's rule (guard_texts in modules/archive_diff.py), written out: a piece is closed when the next line would take it past 2000 characters.
  const ref = []; { let cur = ""; for (const t of [TITLE, ...long.removed.text, ...long.added.text]) { if (cur && Array.from(cur).length + 1 + Array.from(t).length > 2000) { ref.push(cur); cur = ""; } cur = cur ? `${cur}\n${t}` : t; } if (cur) ref.push(cur); }
  ok(lt.length === 3 && lt.map((x) => x.bio).join("|") === ref.join("|") && lt.every((x) => Array.from(x.bio).length <= 2000 && x.url === r.from.url && x.source === "Internet Archive") && lt[0].bio.split("\n").length === 7 && lt[0].bio.startsWith(`${TITLE}\n`) && lt[2].bio.split("\n").length === 3, "long text is cut into the server's pieces of at most 2000 characters, counted as the server counts them");
  ok([sm, nn, rl, fl].every((x) => { const t = D.archiveDiffTexts(x); return t.length === 1 && t[0].bio === TITLE && t[0].url === x.from.url; }) && D.archiveDiffTexts(ru).length === 0 && D.archiveDiffTexts(null).length === 0, "an answer that read a capture and found no difference still has its page title to scan; a refusal has nothing");
  // the map, case files and History
  const m = D.readArchiveDiffs({ "acct:codeberg": AD(), "acct:gitlab": { ...AD({ state: "failed", error: "x", error_code: "timeout" }), url: "https://gitlab.com/samexample" }, "acct:adult": { ...AD(), url: "https://www.pornhub.com/users/a" }, "acct:hn": { ...AD(), url: "https://news.ycombinator.com/user?id=samexample" }, "acct:nourl": { state: "ok" }, "x": AD(), "acct:t": "text" });
  ok(Object.keys(m).join() === "acct:codeberg,acct:gitlab" && m["acct:gitlab"].state === "failed" && D.readArchiveDiffs(m) === m && JSON.stringify(D.readArchiveDiffs(clone(m))) === JSON.stringify(m), "the map keeps account rows whose address may be looked up, a failure stays a failure, and reading it again changes nothing");
  ok(Object.keys(D.DEEP_READERS).join() === "profiles,emailAccounts,githubActivity,archives,commitEmails,postActivity,archiveDiffs", "the three new keys are read wherever a case is opened");
  const deep = D.readDeep({ commitEmails: { "acct:codeberg": CE(), "acct:x": { site: "evil" } }, postActivity: { "acct:fosstodon.org": PA(), "bad": PA() }, archiveDiffs: { "acct:codeberg": AD() }, other: 1 });
  ok(Object.keys(deep.commitEmails).join() === "acct:codeberg" && Object.keys(deep.postActivity).join() === "acct:fosstodon.org" && deep.archiveDiffs["acct:codeberg"].from.url.startsWith("https://web.archive.org/web/2019") && deep.other === 1 && !("commitEmails" in D.readDeep({ commitEmails: "text" })) && !("archiveDiffs" in D.readDeep({ archiveDiffs: [1] })), "History reads them through their readers, and drops what is not a map");
  const file = JSON.stringify(buildCaseFile({ mode: "investigate", target: H, type: "username", ran: 1700000000000, collected: { ...U.collected, commitEmails: { "acct:codeberg": { ...CE(), profile_url: "https://evil.example/samexample" } }, postActivity: { "acct:hackernews": PA({ site: "hackernews", estimate: { ...PA().estimate, label: "Lives in Lisbon" } }) }, archiveDiffs: { "acct:codeberg": { ...AD(), from: side("2019-03-04T05:06:07Z", { title: "<script>x</script>" }) } } } }));
  const pf = parseCaseFile(file);
  ok(pf.ok && pf.entry.results.commitEmails["acct:codeberg"].state === "unknown" && pf.entry.results.commitEmails["acct:codeberg"].emails.length === 0 && pf.entry.results.postActivity["acct:hackernews"].estimate.label === "UTC-3 to UTC+2" && pf.entry.results.archiveDiffs["acct:codeberg"].from.url === r.from.url && !/evil\.example|Lives in|<script>x<\/script>","text_lines":0/.test(JSON.stringify([pf.entry.results.commitEmails, pf.entry.results.postActivity, pf.entry.results.archiveDiffs])), "a case file's three new keys go through the same readers: a 'found' with nothing behind it is unknown, a place is not kept, a snapshot is rebuilt");
}

if (bad) { console.log(`${bad} of ${n} record source checks failed`); process.exit(1); }
console.log(`${n}/${n} record source checks passed`);
