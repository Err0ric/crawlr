// The three record sources: the profile sources, the accounts and keys behind an address, and
// GitHub activity. Readers (hostile input included), how a record becomes a profile, what a
// proof is worth to the identity rules, the email rows and their wording, the person timeline,
// leads, the minor guard's text, case files, exports and what the AI is told. No browser, no network.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };
const J = "../../static/v2/js/";
const D = await import(J + "deep.js");
const { buildEvidence, collectProfiles, profileTexts, avatarImages, aiPayloadFor, aiSignature, caseMarkdown, sourcePlan, canonSite } = await import(J + "evidence.js");
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
  ok(/Chess\.com \(rate limited\), Codeforces \(failed\), Lobsters \(blocked by site\) did not answer the profile lookup, so those sites are unknown, not absent/.test(b) && /tied to the primary identity by a proof the other side confirmed/.test(b), "the brief names the silent sites as unknown and says what a proof ties");
}

// ---- 8. the accounts and keys behind an address ---------------------------------------------------
const ee = buildEvidence(E.collected, E.target, "email");
{
  const r = D.readEmailAccounts(E.collected.emailAccounts);
  ok(r.accounts.length === 2 && r.keys.length === 2 && r.unattributed.commits_seen === 3 && D.readEmailAccounts(r) === r, "the answer is read whole, and reading it again changes nothing");
  const gh = row(ee, "acct:github~mara-lind"), org = row(ee, "acct:github~tidepool-lab"), un = row(ee, "commits:unattributed");
  ok(gh.tier === "linked" && gh.url === "https://github.com/mara-lind" && /GitHub attributes commits that carry this address to this account, so the account has this address confirmed, and its public profile shows it/.test(gh.card.why), "an account GitHub attributes the commits to is Linked, in the contract's words");
  ok(gh.more.label === "Evidence commit" && /^https:\/\/github\.com\/mara-lind\/tidepool\/commit\/[0-9a-f]{40}$/.test(gh.more.url) && gh.action.label === "Investigate this" && gh.action.value === "mara-lind" && gh.action.type === "username", "it carries the evidence commit and one click to investigate the login as a handle");
  ok(/Names written in its commits \(self-declared\): Mara Lindqvist \(in a repository the account owns\), mara\./.test(gh.card.note), "names in commits are labeled self-declared, the one from its own repository first");
  const self = gh.detail.groups.find((g) => g.id === "self"), rec = gh.detail.groups.find((g) => g.id === "record");
  ok(self.prov === "self-declared" && /anyone can write anything there/.test(self.title) && self.rows.some((x) => x.k === "UTC offset in commits" && x.v === "UTC+01:00") && self.rows.some((x) => x.k === "First commit seen" && x.v === "2021-06-14") && self.rows.some((x) => x.k === "Dates left out"), "commit names, dates and UTC offsets sit under self-declared");
  ok(rec.prov === "site record" && rec.rows.some((x) => x.k === "Commits seen" && x.v === "5 commits") && rec.rows.filter((x) => x.link_kind === "evidence").length === 2, "the counts and the evidence commits are GitHub's record");
  ok(org.tier === "matches" && org.card.facts.includes("Organization") && /This organization's public profile shows this address\. GitHub does not confirm an organization's address/.test(org.card.why + ".") && !org.detail, "an organization that shows the address is weaker, labeled as one, and said to be unconfirmed");
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
  ok(/GitHub commit search \(rate limited\) could not be asked, so whether an account or a key exists there is unknown/.test(bl), "and so does the brief");
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
  ok(/Based on 137 public events/.test(html) && /It assumes the quiet stretch is the night/.test(html), "basis and assumption are shown with the estimate");
  const noest = clone(U.collected.githubActivity); noest.estimate = null; noest.estimate_reason = { code: "no_quiet_stretch", text: "Events are spread across the whole day, so no quiet stretch stands out." };
  ok(D.activityView(noest).estimate === null && /none made/.test(activityHtml(noest)) && /Events are spread across the whole day/.test(activityHtml(noest)), "no estimate shows the reason");
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

if (bad) { console.log(`${bad} of ${n} record source checks failed`); process.exit(1); }
console.log(`${n}/${n} record source checks passed`);
