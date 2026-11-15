// Adult and dating site coverage: an opt-in for the page session, existence and text only.
// Checks the source plan and request bodies both ways, the separate ledger group, that its rows
// never reach clustering, facts, leads, the avatar list, the account counts or `accounts`, the
// exports and the AI payload both ways, that nothing ever renders an image, the minor guard and
// its drift from core/adult_guard.py, and that the switch is never stored. The switch itself is a
// session mode: see modes.test.mjs. No browser, no network.
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };   // ai.js and report.js register delegated listeners on import
// Any write to storage during this suite is recorded: the switch must never cause one.
const writes = [];
globalThis.localStorage = { getItem: (k) => (k === "crawlr_v2_sources" ? JSON.stringify({ "maigret.nsfw": true, sherlock: true }) : null), setItem: (k, v) => writes.push([k, v]), removeItem: (k) => writes.push([k, null]) };
const J = "../../static/v2/js/";
const A = await import(J + "adult.js");
const { buildEvidence, sourcePlan, collectProfiles, avatarImages, accountsFor, tierCounts, isFinding, TIERS, ledgerTiers, aiPayloadFor, caseMarkdown } = await import(J + "evidence.js");
const { investigateBrief } = await import(J + "brief.js");
const { sourceTally, sourceCoverage, statusForAi, post, ApiError } = await import(J + "core.js");
const L = await import(J + "links.js");
const { evWhat, renderTiers } = await import(J + "workbench.js");
const { sourceCards } = await import(J + "renderers.js");
const { reportHtml } = await import(J + "report.js");
const { buildCaseFile, parseCaseFile } = await import(J + "casefile.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const read = (p) => fs.readFileSync(new URL(p, import.meta.url), "utf8");
const fx = JSON.parse(read("./fixtures/adult.json"));
const T = fx.target, C = fx.collected;
const clone = (o) => JSON.parse(JSON.stringify(o));
const el = () => ({ innerHTML: "", hidden: false, id: "t" });
const row = (ev, key) => ev.items.find((i) => i.key === key);
const adultOf = (ev) => ev.items.filter((i) => i.tier === "adult");
const NOW = new Date("2026-11-14T12:00:00Z");

// Every site only the adult rows name, and every image address planted in the fixture.
const ADULT_SITES = ["Velvet Lounge", "Crimson Chat", "Rosewater", "HomeOnly Dates", "AnyYes Cams", "MatchHarbor", "Lumen Fans", "Ember Dating", "TagOnly Dates", "Amber Room", "Opal Nights", "RoyalCams", "Dusk Personals", "Fansly", "Pornhub", "xHamster", "Chaturbate", "Tinder", "JustFor.Fans", "FetLife", "LoyalFans", "OnlyFans", "ManyVids"];
const ADULT_HOSTS = ["velvetlounge.example", "crimsonchat.example", "rosewater.example", "homeonly.example", "anyyes.example", "matchharbor.example", "lumenfans.example", "emberdating.example", "tagonly.example", "amberroom.example", "imagehost.example", "royalcams.com", "fansly.com", "pornhub.com", "xhamster.com", "chaturbate.com", "tinder.com", "justfor.fans", "fetlife.com", "loyalfans.com", "onlyfans.com", "evil.example", "jdoe-private.example"];
const ADULT_TEXT = ["Jordan D.", "Hiking, coffee", "Night owl", "Tea drinker", "Old shape, tagged only", "See my gallery", "new posts daily"];
const lower = (t) => String(t).toLowerCase();
const MEDIA_KEY = /image|avatar|thumb|photo|media|banner/i;
const MEDIA_URL = /https?:\/\/[^\s"'<>]+\.(?:jpe?g|png|gif|webp|mp4)/gi;
const planted = new Set();
(function walk(v, key = "", inAdult = false) {
  if (Array.isArray(v)) { v.forEach((x) => walk(x, key, inAdult)); return; }
  if (v && typeof v === "object") { const a = inAdult || A.isAdultRow(v) || "platform" in v; for (const [k, x] of Object.entries(v)) walk(x, k, a); return; }
  if (typeof v !== "string" || !inAdult) return;
  if (MEDIA_KEY.test(key) && /^https?:/.test(v)) planted.add(v);
  for (const u of v.match(MEDIA_URL) || []) planted.add(u);
})(C);
ok(planted.size >= 9, `the fixture plants image and media addresses on purpose (${planted.size})`);
const names = (text, list) => list.filter((s) => lower(text).includes(lower(s)));
const noImages = (html, what) => {
  ok(!/<img\b/i.test(html) && !/&lt;img/i.test(html) && !/<(?:picture|video|source|iframe|object|embed|svg:image)\b/i.test(html) && !/\bsrcset=|\bbackground(?:-image)?:\s*url/i.test(html), `${what}: no image or media element`);
  ok(![...planted].some((u) => html.includes(u) || html.includes(u.replace(/&/g, "&amp;"))), `${what}: no image address from the fixture`);
  ok(!/\.(?:jpe?g|png|gif|webp|mp4)\b/i.test(html), `${what}: no image address at all`);
  ok(!/icons\.duckduckgo\.com|favicon/i.test(html), `${what}: no favicon request`);
};

// ---- 1. the source plan and the request bodies, both ways ------------------------------------
{
  ok(sourcePlan("username", T).join() === "sherlock,maigret,github,platform" && !sourcePlan("username", T, { adult: false }).includes("adult"), "mode off: the adult site check is not in the plan");
  ok(sourcePlan("username", T, { adult: true }).join() === "sherlock,maigret,github,platform,adult", "mode on: it is its own source, after the others");
  ok(!sourcePlan("username", T, { adult: "true" }).includes("adult") && !sourcePlan("username", T, { adult: 1 }).includes("adult"), "only the literal true turns it on");
  for (const t of ["email", "hash", "phone", "name"]) ok(!sourcePlan(t, t === "email" ? "jdoe_example@example.org" : T, { adult: true }).includes("adult"), `a ${t} case never plans it`);
  ok(JSON.stringify(A.usernameBody(T, false)) === JSON.stringify({ username: T, nsfw: false }) && A.usernameBody(T, undefined).nsfw === false && A.usernameBody(T, "yes").nsfw === false, "mode off sends nsfw false to Sherlock and Maigret");
  ok(A.usernameBody(T, true).nsfw === true && A.usernameBody(T, A.adultOn("username", T, true)).nsfw === true, "mode on sends nsfw true");
  ok(A.adultOn("username", T, true) && !A.adultOn("email", T, true) && !A.adultOn("username", T, false) && !A.adultOn("username", "anna15", true), "the mode needs the switch, a username and a handle the guard passes");
  // defence in depth: an adult row in an answer is dropped when the mode is off
  for (const k of ["sherlock", "maigret"]) {
    const off = A.scrubResponse(k, clone(C[k]), false);
    ok(off.results.length > 0 && !off.results.some(A.isAdultRow) && !names(JSON.stringify(off), [...ADULT_SITES, ...ADULT_HOSTS]).length, `mode off: adult rows in a ${k} answer are dropped before it is stored`);
    const on = A.scrubResponse(k, clone(C[k]), true);
    ok(on.results.filter(A.isAdultRow).length === C[k].results.filter(A.isAdultRow).length && ![...planted].some((u) => JSON.stringify(on.results.filter(A.isAdultRow)).includes(u)), `mode on: ${k} adult rows are kept without their image fields`);
  }
  ok(A.scrubResponse("adultCheck", clone(C.adultCheck), false) === null, "mode off: an adult site check answer is never kept");
  const kept = A.scrubResponse("adultCheck", clone(C.adultCheck), true);
  ok(kept.results.length === 10 && kept.results.every((r) => Object.keys(r).sort().join() === "bio,category,display_name,evidence,followers,found,hint,joined,platform,state,url") && ![...planted].some((u) => JSON.stringify(kept).includes(u)), "mode on: each adult site check row keeps the contract's text fields and nothing else");
  ok(kept.results.every((r) => r.url === A.platformUrl(r.platform, T)) && !/cdn\.fansly|evil\.example/.test(JSON.stringify(kept)), "and its address is rebuilt from the platform's template, never the one in the answer");
  ok(A.scrubResponse("github", C.github, false) === C.github, "other sources are untouched");
}

// ---- 2. the group ---------------------------------------------------------------------------
const ev = buildEvidence(C, T, "username");
const adult = adultOf(ev);
{
  ok(TIERS.map((t) => t.id).join().includes("unverified,adult,lead"), "the group sits after Unverified and before Leads");
  const tier = TIERS.find((t) => t.id === "adult");
  ok(tier.title === "Adult and dating sites" && tier.open === false && tier.blurb.startsWith(A.ADULT_NOTICE), "it is titled, collapsed by default, and opens with the notice");
  ok(adult.length === 23 && new Set(adult.map((i) => i.key)).size === 23 && adult.every((i) => i.key.startsWith("adult:")), "one row per site across Sherlock, Maigret and the adult site check");
  const states = adult.map((i) => i.adult.state);
  const order = ["read", "reported", "blocked", "unknown", "no_public_url", "not_found"];
  const rank = { read: 0, reported: 1, blocked: 2, unknown: 2, no_public_url: 3, not_found: 4 };
  ok(states.every((s, i) => i === 0 || rank[states[i - 1]] <= rank[s]) && order.every((s) => states.includes(s)), "rows are ordered: read, reported, blocked or unknown, no public page, not found");
  ok(ev.items.findIndex((i) => i.tier === "adult") > ev.items.findIndex((i) => i.tier === "unverified") && ev.items.filter((i) => i.tier === "adult").length === adult.length, "the rows sit together after the unverified rows");
  const say = (k) => row(ev, k).meta;
  ok(/^adult site · profile read · name on profile: Jay · joined 2019-04-02 · 88 followers · bio: Night owl\. Tea drinker\./.test(say("adult:fansly")) && row(ev, "adult:fansly").source === "Sherlock, Adult site check", "a read profile says so, with its name, join date, followers and plain-text bio, and one row covers both sources");
  ok(/^dating site · profile read · name on profile: Jordan D\. · joined 2021-03-09 · 1,204 followers · bio: Hiking, coffee and bad puns\.$/.test(say("adult:matchharbor")), "a Maigret profile read on a dating site reads the same way");
  ok(say("adult:crimson chat") === "adult site · reported by a tool and nothing read", "a tool's report says nothing was read");
  ok(/^dating site · reported by a tool and nothing read · Adult site check: not found/.test(say("adult:tinder")), "a report beside a check that disagrees says both");
  ok(/this site often answers yes to any name/.test(say("adult:anyyes cams")), "a noisy site's report says so");
  ok(/^adult site · Blocked by site \(The site refused the request\)$/.test(say("adult:loyalfans")) && say("adult:dusk personals") === "adult site · could not be checked" && /could not be checked \(The site sends the same page for every handle, so it cannot be checked automatically\)/.test(say("adult:onlyfans")), "blocked and unknown use the ledger's words, with the check's reason");
  ok(say("adult:manyvids") === "adult site · no public page" && /ManyVids has no public page/.test(row(ev, "adult:manyvids").hint), "no public page comes with its hint");
  ok(say("adult:justfor.fans") === "adult site · not found" && /^adult site · not found/.test(say("adult:chaturbate")), "not found is said plainly");
  ok(adult.filter((i) => i.adult.state === "read" && i.sources.includes("Adult site check")).length === 3 && C.adultCheck.results.filter((r) => r.state === "not_found").length === 3, "the fixture has three found and three not-found check rows");
  ok(say("adult:lumen fans") === "adult site · profile read · name on profile: jd · joined 2020" && say("adult:pornhub") === "adult site · profile read", "a bio or a name that carries markup or a link is dropped whole");
  ok(A.plainText("Likes tea") === "Likes tea" && A.plainText("see https://x.example/a") === "" && A.plainText("<b>hi</b>") === "" && A.plainText("my page: lumen.fans/jd") === "" && A.plainText("pic.jpg") === "" && A.plainText(["x"]) === "" && A.plainText({ toString: () => "x" }) === "", "plain text means a string with no markup, link or media name");
  const c = A.adultCounts(adult);
  ok(c.read === 6 && c.reported === 10 && c.blocked === 2 && c.unknown === 2 && c.noPage === 1 && c.notFound === 2 && c.taken === 16 && c.unchecked === 4 && c.total === 23, "counts by state");
  ok(A.adultSummary(adult) === "16 handles taken (6 read, 10 reported) · 4 could not be checked · 1 with no public page · 2 not found.", "the group says what its count is made of");
  ok(adult.every((i) => /^[A-Z0-9?]{1,2}$/.test(i.glyph)), "each row's mark is the site's initials");
  ok(!adult.some(isFinding), "the rows are not counted as findings");
  ok(row(ev, "adult:royalcams")?.adult.state === "reported" && !ev.items.some((i) => i.tier !== "adult" && /royalcams/i.test(i.key + i.url)), "a row for a listed site that nothing marked is still an adult row");
}

// ---- 3. these rows never reach the ordinary flow ----------------------------------------------
{
  const base = buildEvidence(A.withoutAdult(C), T, "username");
  const others = ev.items.filter((i) => i.tier !== "adult");
  ok(JSON.stringify(others) === JSON.stringify(base.items) && base.items.length > 0, "every other row is exactly what the case gives without its adult rows");
  ok(JSON.stringify(ev.facts) === JSON.stringify(base.facts) && JSON.stringify(ev.identity) === JSON.stringify(base.identity), "facts and identities are untouched by them");
  for (const t of ["linked", "matches", "different", "unverified", "noise", "lead", "flag"]) ok(!names(JSON.stringify(ev.items.filter((i) => i.tier === t)), [...ADULT_SITES, ...ADULT_HOSTS]).length, `no adult site is in ${t}`);
  const profiles = collectProfiles(C, T, "username");
  ok(profiles.length === 2 && profiles.map((p) => p.site).sort().join() === "GitHub,Mastodon" && !names(JSON.stringify(profiles), [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length, "identity clustering never sees them: profile collection skips them");
  ok(ev.identity.views.length === 1 && ev.identity.views[0].sites.join() === "GitHub,Mastodon", "a dating profile named like the target does not join the primary identity");
  const allFacts = [...ev.facts, ...ev.general, ...ev.identity.views.flatMap((v) => v.facts)];
  ok(!names(JSON.stringify(allFacts), [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT, "Jay"]).length, "they produce no facts in What we know");
  ok(!ev.items.some((i) => i.tier === "lead" && /jdoe-private|lumenfans|matchharbor/.test(JSON.stringify(i))), "they produce no leads, not even from a link on the profile");
  const imgs = avatarImages(C, T, "username");
  ok(imgs.length === 2 && imgs.every((i) => /githubusercontent|mastodon/.test(i.url)) && ![...planted].some((u) => JSON.stringify(imgs).includes(u)), "they never go to the avatar comparison");
  const acc = accountsFor(ev.items);
  ok(acc.length === 3 && !names(JSON.stringify(acc), [...ADULT_SITES, ...ADULT_HOSTS]).length, "accountsFor holds none of them");
  ok(JSON.stringify(tierCounts(ev.items)) === JSON.stringify(tierCounts(base.items)), "tier counts are the same with and without them");
  const brief = (e, c) => investigateBrief({ collected: c, items: e.items, facts: e.facts, identity: e.identity, failed: [], type: "username", target: T }).rows.map((r) => r.text);
  const b = brief(ev, C), b0 = brief(base, A.withoutAdult(C));
  const line = "Adult and dating sites: 16 handles taken, 4 could not be checked. Existence only.";
  ok(b.includes(line) && b.filter((t) => /adult|dating/i.test(t)).length === 1, "the brief gets one neutral line");
  ok(JSON.stringify(b.filter((t) => t !== line)) === JSON.stringify(b0) && /^1 linked account, 1 that exist and match, 0 that belong to a different person, and 1 unverified\./.test(b[0]), "and its account counts do not include them");
  ok(!b0.some((t) => /adult|dating/i.test(t)), "a case without the mode has no such line");
  // the main view of the case: what follow-up sources and the AI are built from
  const main = A.withoutAdult({ ...C, enricher: { profiles: [{ platform: "Velvet Lounge", url: "https://velvetlounge.example/u/jdoe_example", display_name: "Jay", bio: "x" }, { platform: "Keybase", display_name: "J" }] }, platformCheck: { results: [{ platform: "Fansly", state: "found", url: "https://fansly.com/jdoe_example" }, { platform: "Reddit", state: "not_found" }] }, linkChecks: { "adult:crimson chat": { state: "verified", url: "https://crimsonchat.example/jdoe_example" }, "acct:keybase": { state: "blocked", url: "https://keybase.io/jdoe_example" } } });
  ok(!("adultCheck" in main) && !("adultMode" in main) && !main.sherlock.results.some(A.isAdultRow) && !main.maigret.results.some(A.isAdultRow) && !("adult_errors" in main.maigret), "the main view has no adult row, check or flag");
  ok(main.enricher.profiles.length === 1 && main.platformCheck.results.length === 1 && Object.keys(main.linkChecks).join() === "acct:keybase", "a site marked adult is dropped from the follow-up sources and the stored link checks too");
  ok(!names(JSON.stringify(main), [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length, "nothing about those sites is left in it");
}

// ---- 4. links: the same rules as every other row, and never the link check -------------------------
{
  const kind = (k) => row(ev, k).link_kind;
  ok(adult.every((i) => L.LINK_KINDS.includes(i.link_kind)), "every row has a link kind");
  ok(adult.filter((i) => i.adult.state === "read").every((i) => i.link_kind === "verified_profile" && i.url) && kind("adult:fansly") === "verified_profile", "verified_profile only when a profile was read");
  ok(["adult:crimson chat", "adult:rosewater", "adult:ember dating", "adult:fetlife", "adult:anyyes cams", "adult:onlyfans", "adult:tinder"].every((k) => kind(k) === "templated_unverified"), "a reported, blocked or unknown row has a templated, unverified URL");
  ok(adult.filter((i) => i.link_kind === "verified_profile").every((i) => i.adult.state === "read"), "nothing else is a verified profile");
  ok(kind("adult:manyvids") === "none" && kind("adult:homeonly dates") === "none" && row(ev, "adult:homeonly dates").hint === L.GENERIC_HINT, "no public page and homepage links are plain text with a hint");
  ok(kind("adult:justfor.fans") === "none" && row(ev, "adult:justfor.fans").url === "" && kind("adult:dusk personals") === "none" && !row(ev, "adult:dusk personals").hint, "a not-found row and a row with no address are not links");
  for (const i of adult) {
    const html = evWhat(i);
    const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
    if (i.link_kind === "none") ok(!hrefs.length && !i.url, `${i.key}: kind none renders no link`);
    else ok(hrefs.length === 1 && !L.isBareHome(hrefs[0], [T]) && /rel="noopener noreferrer nofollow"/.test(html) && new RegExp(`data-link-kind="${i.link_kind}"`).test(html), `${i.key}: one link, never a homepage, with its kind`);
    if (i.link_kind === "templated_unverified") ok(/class="lk lk-unverified"/.test(html) && /<span class="lk-flag" aria-hidden="true">unverified URL<\/span>/.test(html) && /\(unverified URL, opens in a new tab\)/.test(html), `${i.key}: the dashed unverified URL treatment`);
  }
  // item 2: an address is only ever a page on that site
  ok(row(ev, "adult:fansly").url === "https://fansly.com/jdoe_example" && row(ev, "adult:xhamster").url === "https://xhamster.com/users/jdoe_example" && !adult.some((i) => /cdn\.fansly|evil\.example|imagehost|avatar/.test(i.url)), "an adult site check row links to the platform's own template for the handle, whatever address the case holds");
  const crafted = buildEvidence({ adultMode: true, adultCheck: { username: "alice", checked: 2, total: 2, results: [{ platform: "Fansly", category: "adult", url: "https://cdn.fansly.com/alice/avatar.jpg", state: "found", found: true }, { platform: "Made Up Place", category: "adult", url: "https://madeup.example/alice.png", state: "found", found: true }, { platform: "Tinder", category: "dating", url: "javascript:alert(1)", state: "blocked", found: null }] } }, "alice", "username");
  ok(row(crafted, "adult:fansly").url === "https://fansly.com/alice" && row(crafted, "adult:made up place").link_kind === "none" && row(crafted, "adult:made up place").url === "" && row(crafted, "adult:tinder").url === "https://tinder.com/@alice" && !/avatar\.jpg|alice\.png|javascript/.test(JSON.stringify(crafted.items) + adultOf(crafted).map(evWhat).join("")), "a case file cannot point an adult site check row at a picture: a platform CrawlR has no template for is text");
  ok(JSON.stringify(Object.keys(A.ADULT_PLATFORMS).map((n) => [n, A.ADULT_PLATFORMS[n]])) === JSON.stringify([...read("../../modules/adult_check.py").matchAll(/"name": "([^"]+)", "category": "\w+", "url": "([^"]*)"/g)].map((m) => [m[1], m[2]])), "the platform templates are the ones in modules/adult_check.py");
  ok(A.platformUrl("fansly", "a b") === "" && A.platformUrl("Fansly", "-x") === "" && A.platformUrl("Fansly", "x/../y") === "" && A.platformUrl("ManyVids", "alice") === "" && A.platformUrl("Chaturbate", "alice") === "https://chaturbate.com/alice/", "a template is filled only with a plain handle");
  ok(kind("adult:amber room") === "none" && row(ev, "adult:amber room").url === "" && kind("adult:opal nights") === "none" && row(ev, "adult:opal nights").url === "" && !/<a\b/.test(evWhat(row(ev, "adult:amber room")) + evWhat(row(ev, "adult:opal nights"))), "a tool row whose address is a media file, or is on another host, is text");
  const S = A.safeToolUrl;
  for (const u of ["https://velvet.example/avatars/alice", "https://velvet.example/alice.jpg", "https://velvet.example/u/alice/banner", "https://cdn.velvet.example/alice", "https://img2.velvet.example/alice", "https://velvet.example/media/alice", "https://velvet.example/v/alice.mp4", "https://velvet.example/thumbs/1", "https://velvet.example/a?f=x.png", "https://other.example/velvet/alice", "https://user:pw@velvet.example/alice", "ftp://velvet.example/alice", "//velvet.example/alice", ""]) ok(S("Velvet", u) === "", `not a page on the site: ${u || "(empty)"}`);
  ok(S("Velvet", "https://velvet.example/u/alice") === "https://velvet.example/u/alice" && S("Velvet Lounge", "https://www.velvetlounge.example/alice") && S("xHamster", "https://xhamster.com/users/alice") && S("JustFor.Fans", "https://justfor.fans/alice") && S("datingRU", "https://dating.ru/alice"), "a profile page on the site's own domain is kept");
  // item 1: no adult row is ever sent to the link check, and a stored result changes nothing
  ok(adult.every((i) => i.no_check === true && !i.check && !i.gone) && L.pendingChecks(ev.items, "adult").length === 0 && L.pendingChecks(ev.items).every((r) => r.id.startsWith("acct:")), "no adult row is ever offered to the link check");
  ok(L.pendingChecks(adult.map((i) => ({ ...i, no_check: false })), "adult").length === 0 && L.pendingChecks(ev.items, "unverified").length === 1, "the link check itself takes account rows only");
  const stored = Object.fromEntries(adult.filter((i) => i.url).map((i) => [i.key, { state: "not_found", url: i.url, evidence: "The site answered 404: there is no page at this address." }]));
  const ev2 = buildEvidence({ ...C, linkChecks: { ...stored, "adult:crimson chat": { state: "verified", url: "https://crimsonchat.example/jdoe_example", final_url: "https://crimsonchat.example/other" } } }, T, "username");
  ok(JSON.stringify(adultOf(ev2)) === JSON.stringify(adult), "stored link check results, a 404 included, change no adult row: found and not found come only from the adult site check");
  ok(Object.keys(L.readChecks(stored)).length === 0 && Object.keys(L.mergeChecks({}, [{ id: "adult:crimson chat", url: "https://crimsonchat.example/jdoe_example" }], [{ id: "adult:crimson chat", state: "not_found" }])).length === 1 && !adultOf(buildEvidence({ ...C, linkChecks: { "adult:crimson chat": { state: "not_found", url: "https://crimsonchat.example/jdoe_example" } } }, T, "username")).some((i) => i.gone || i.adult.state !== adult.find((x) => x.key === i.key).adult.state), "and such results are not read back from a stored case");
  ok(!/row\.gone|applyCheck|markUnsendable/.test(read(J + "adult.js").replace(/\/\/.*$/gm, "")), "adult.js never applies a link check");
  ok(buildEvidence({ ...A.withoutAdult(C), linkChecks: stored }, T, "username").items.every((i) => i.tier !== "adult"), "stored checks alone bring no adult row back");
}

// ---- 5. nothing renders an image ---------------------------------------------------------------
const GOOD_AI = { summary: "## Case summary\nA handle.\n\n## Identity assessment\n| Attribute | Assessment | Confidence | Evidence |\n|---|---|---|---|\n| Name | Jordan Doe | High | GitHub |\n\n## Platform footprint\n| Platform | Profile URL | Confidence | Why it matters |\n|---|---|---|---|\n| GitHub | https://github.com/jdoe_example | High | own record |\n\n## Adult and dating sites (existence checks only)\nA handle with this name exists on Velvet Lounge.\n![x](https://cdn.velvetlounge.example/avatars/jdoe_example.jpg)\nSee https://velvetlounge.example/u/jdoe_example for more.\n", profile: {} };
{
  const tiers = ledgerTiers(T, "username").map((t) => (t.id === "adult" ? { ...t, note: A.adultSummary(adult) } : t));
  const box = el();
  renderTiers(box, ev.items, tiers, new Set(), "", { check: (t) => L.pendingChecks(ev.items, t).length });
  const group = box.innerHTML.match(/<section class="tier[^"]*"\s+data-tier="adult">[\s\S]*?<\/section>/)[0];
  ok(/class="tier\s+collapsed/.test(group) && /aria-expanded="false"/.test(group) && /<span class="tier-title">Adult and dating sites<\/span><span class="count">23<\/span>/.test(group), "the group renders collapsed, with its title and count");
  ok(group.includes(A.ADULT_NOTICE) && group.includes("16 handles taken (6 read, 10 reported)") && !/Check these links|tier-check/.test(group) && /Check these links \(1\)/.test(box.innerHTML), "it carries the notice and what the count is made of, and never the link check button");
  ok((group.match(/class="site-glyph" aria-hidden="true"/g) || []).length === 23 && !/<svg(?! class="ext")/.test(group), "each row has a neutral text mark");
  noImages(group, "the ledger group");
  noImages(adult.map(evWhat).join(""), "each row on its own");
  ok(box.innerHTML.indexOf('data-tier="adult"') > box.innerHTML.indexOf('data-tier="unverified"') && box.innerHTML.indexOf('data-tier="adult"') > -1, "it renders after Unverified");
  const card = sourceCards.adultCheck(C.adultCheck, adult);
  ok(/<h3 class="card-title">Adult site check<\/h3>/.test(card) && card.includes(A.ADULT_NOTICE) && (card.match(/<li>/g) || []).length === 10 && /existence only/.test(card), "the adult site check card lists its ten sites as text");
  noImages(card, "the adult site check card");
  for (const k of ["sherlock", "maigret"]) {
    const c2 = sourceCards[k](C[k], {});
    ok(!names(c2, [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length && /Keybase/.test(c2), `the ${k} card lists no adult row`);
    noImages(c2, `the ${k} card`);
  }
  ok(/1 read/.test(sourceCards.maigret(C.maigret, {})) && /1 unverified/.test(sourceCards.maigret(C.maigret, {})), "and its counts leave them out");
  const report = reportHtml({ ai: GOOD_AI, target: T, items: ev.items, facts: ev.facts, collected: C });
  const sec = report.match(/<section class="rsec adult" id="rs-adult">[\s\S]*?<\/section>/)?.[0] || "";
  ok(sec && /<h3>Adult and dating sites \(existence checks only\)<\/h3>/.test(sec) && (sec.match(/<li>/g) || []).length === 23 && sec.includes(A.ADULT_NOTICE), "the report has the labelled section, with every row");
  noImages(sec, "the report's adult section");
  ok(/A handle with this name exists on Velvet Lounge\./.test(sec) && !/for more/.test(sec), "the model's own lines are shown there only when they carry no address or markup");
  ok(report.lastIndexOf('<section class="rsec') === report.indexOf('<section class="rsec adult"'), "it is the last section of the report");
  ok(![...report.matchAll(/<img\b[^>]*>/g)].some((m) => names(m[0], ADULT_HOSTS).length) && ![...planted].some((u) => report.includes(u)) && !/class="tile[^"]*"[^>]*>(?:(?!<\/a>|<\/div>)[\s\S])*(?:Velvet|MatchHarbor|Fansly)/.test(report), "no tile, favicon or picture anywhere in the report belongs to an adult site");
  const plain = reportHtml({ ai: { summary: "One paragraph, no sections.", profile: {} }, target: T, items: ev.items, facts: ev.facts, collected: C });
  ok(/<section class="rsec adult"/.test(plain) && !/<img\b[^>]*(?:example)/.test(plain), "a report without sections still gets the section, as text");
}

// ---- 6. exports --------------------------------------------------------------------------------
const OFF = (() => { const c = clone(C); delete c.adultMode; return c; })();   // the rows without the flag
{
  const on = caseMarkdown({ collected: C, target: T, type: "username", now: NOW });
  const heads = on.split("\n").filter((l) => l.startsWith("## "));
  ok(heads.at(-1) === "## Adult and dating sites (existence checks only) (23)" && heads.includes("## Unverified (1)") && !heads.includes("## Adult and dating sites (17)"), "Markdown: the labelled section comes after every other finding");
  const [before, after] = on.split("## Adult and dating sites (existence checks only)");
  ok(!names(before, [...ADULT_SITES, ...ADULT_HOSTS]).length && names(after, ADULT_SITES).length === 23 && after.includes(`> ${A.ADULT_NOTICE}`), "and every adult row is inside it, under the notice");
  ok(/\[Crimson Chat\]\(https:\/\/crimsonchat\.example\/jdoe_example\) \(unverified URL\)/.test(after) && /- ManyVids · adult site · no public page · how to check:/.test(after) && !/\]\(https:\/\/homeonly\.example\/?\)/.test(after), "with the same link rules: unverified marked, no homepage link");
  ok(!/!\[/.test(on) && ![...planted].some((u) => on.includes(u)) && !/\.(?:jpe?g|png|gif|webp|mp4)\b/i.test(after), "Markdown: no image");
  const withAi = caseMarkdown({ collected: C, target: T, type: "username", now: NOW, ai: { summary: "report text" }, notes: "n" });
  ok(withAi.indexOf("## Adult and dating sites (existence checks only)") < withAi.indexOf("## AI analysis") && withAi.indexOf("## Leads from profiles") < withAi.indexOf("## Adult and dating sites (existence checks only)"), "it sits after the findings and before the AI report and notes");
  for (const [label, c] of [["without the flag", OFF], ["with the rows scrubbed", A.withoutAdult(C)], ["flag set to a string", { ...OFF, adultMode: "true" }]]) {
    const md = caseMarkdown({ collected: c, target: T, type: "username", now: NOW });
    ok(!/adult|dating/i.test(md) && !names(md, [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length && /## Unverified \(1\)/.test(md), `Markdown ${label}: no section and no adult row anywhere`);
    const e0 = buildEvidence(c, T, "username");
    const rep = reportHtml({ ai: GOOD_AI, target: T, items: e0.items, facts: e0.facts, collected: c });
    ok(!/rsec adult/.test(rep) && !names(rep, [...ADULT_SITES, ...ADULT_HOSTS]).length, `report ${label}: no section, and what the model wrote about them is not shown`);
    const box = el(); renderTiers(box, e0.items, ledgerTiers(T, "username"), new Set(), "");
    ok(!/data-tier="adult"/.test(box.innerHTML) && !names(box.innerHTML, [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length, `screen, print and the HTML export ${label}: the ledger they are made from has no adult row`);
  }
  // the HTML export moves the group to the end under the labelled heading; print does it in CSS
  const wb = read(J + "workbench.js"), css = read("../../static/v2/css/app.css");
  ok(/querySelectorAll\('\.tier\[data-tier="adult"\]'\)[\s\S]{0,200}title\.textContent = ADULT_SECTION[\s\S]{0,80}parentElement\?\.append\(t\)/.test(wb), "the HTML export relabels the group and moves it after the other findings");
  ok(/@media print \{[^}]*\.tier\[data-tier="adult"\] \{ order: 99; \}\s*\.tier\[data-tier="adult"\] \.tier-title::after \{ content: " \(existence checks only\)"; \}/.test(css), "print does the same with the stylesheet");
  ok(!/url\(/.test(css.slice(css.indexOf("/* adult and dating sites"))) && !/#[0-9a-f]{3,8}\b/i.test(css.slice(css.indexOf("/* adult and dating sites"))), "the group's styles add no image and no new color");
  // the case file keeps the flag and the rows
  const file = JSON.stringify(buildCaseFile({ mode: "investigate", target: T, type: "username", ran: 1700000000000, collected: A.scrubCollected(C, T, "username"), ai: null, deep: null, notes: "", purpose: "Checking my own exposure" }));
  const back = parseCaseFile(file);
  ok(back.ok && back.entry.results.adultMode === true && back.entry.results.adultCheck.results.length === 10, "a case file keeps the flag and the rows");
  const again = buildEvidence(A.scrubCollected(back.entry.results, back.entry.target, back.entry.kind), back.entry.target, back.entry.kind);
  ok(JSON.stringify(adultOf(again).map((i) => [i.key, i.meta, i.link_kind, i.url])) === JSON.stringify(adult.map((i) => [i.key, i.meta, i.link_kind, i.url])), "and the group reads the same after the round trip");
  ok(![...planted].some((u) => file.includes(u)), "what is kept for a case holds none of the planted image addresses on adult rows");
  for (const v of ["true", 1, {}, [true], null, false]) { const r = parseCaseFile(JSON.stringify({ ...JSON.parse(file), collected: { ...OFF, adultMode: v } })); ok(r.ok && !("adultMode" in r.entry.results) && !adultOf(buildEvidence(A.scrubCollected(r.entry.results, T, "username"), T, "username")).length, `a case file whose flag is ${JSON.stringify(v)} shows no adult row`); }
  ok(parseCaseFile(JSON.stringify({ crawlr_case: 1, mode: "investigate", target: T, type: "username", collected: { adultMode: true } })).ok === false, "the flag alone is not a result");
  const mail = parseCaseFile(JSON.stringify({ crawlr_case: 1, mode: "investigate", target: "jdoe_example@example.org", type: "email", collected: { ...C } }));
  ok(mail.ok && !adultOf(buildEvidence(mail.entry.results, mail.entry.target, "email")).length && !Object.keys(A.scrubCollected(mail.entry.results, mail.entry.target, "email")).some((k) => /adult/i.test(k)), "an email case never shows adult rows, whatever the file says");
}

// ---- 7. the AI payload, both ways ---------------------------------------------------------------
{
  const status = { GitHub: "ok", Sherlock: "ok", "Adult site check": "partial: 6 of 8 sites answered" };
  const on = aiPayloadFor(C, T, "username", { source_status: status, active: false });
  ok(Array.isArray(on.adult_sites) && on.adult_sites.length === 23 && on.adult_sites.every((r) => Object.keys(r).join() === "site,category,state,url_kind"), "mode on: adult_sites is its own field, one {site, category, state, url_kind} per row");
  ok(on.adult_sites.every((r) => ["adult", "dating"].includes(r.category) && ["read", "reported", "blocked", "unknown", "no_public_url", "not_found"].includes(r.state) && L.LINK_KINDS.includes(r.url_kind)), "with known values only");
  ok(on.accounts.length === 3 && !names(JSON.stringify(on.accounts), ADULT_SITES).length, "never inside accounts");
  const rest = JSON.stringify({ ...on, adult_sites: undefined, source_status: undefined });
  ok(!names(rest, [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length && !/adult|nsfw/i.test(rest), "and nowhere else in the payload: the tool results are sent without those rows");
  ok(!names(JSON.stringify(on), [...ADULT_TEXT, "Jay"]).length && !/https?:\/\/[^"]*(?:fansly|pornhub|xhamster|onlyfans|tinder|chaturbate|royalcams|\.example\/(?!docs))/i.test(JSON.stringify(on).replace(/https:\/\/(?:github\.com|mastodon\.social|keybase\.io|avatars\.githubusercontent\.com|files\.mastodon\.social)[^"]*/g, "")) && ![...planted].some((u) => JSON.stringify(on).includes(u)), "no bio, no name, no URL and no image address is sent");
  ok(on.source_status["Adult site check"] === status["Adult site check"], "the source's status goes with it");
  for (const [label, c] of [["without the flag", OFF], ["scrubbed", A.withoutAdult(C)], ["for a handle the guard blocks", C]]) {
    const off = aiPayloadFor(c, label.startsWith("for") ? "jdoe_example15" : T, "username", { source_status: status });
    ok(!("adult_sites" in off) && !/adult|nsfw/i.test(JSON.stringify(off)) && !names(JSON.stringify(off), [...ADULT_SITES, ...ADULT_HOSTS, ...ADULT_TEXT]).length && off.accounts.length === 3, `mode off (${label}): no adult_sites field and no trace of those sites, the status row included`);
  }
  ok(!("adult_sites" in aiPayloadFor({ ...C }, "jdoe_example@example.org", "email")), "an email case sends none");
}

// ---- 8. the adult site check is counted like any other source -----------------------------------
{
  const NAMES = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", adultCheck: "Adult site check" };
  const one = (st) => ({ platform: `Site ${st}`, state: st, found: st === "found" ? true : st === "not_found" ? false : null });
  const t = sourceTally(C, NAMES);
  const r = t.rows.find((x) => x.key === "adultCheck");
  ok(r.name === "Adult site check" && r.state === "partial" && r.text === "partial: 6 of 8 sites answered" && r.hasResults, "the fixture's check is partial only because two of the eight sites it asked blocked it");
  // checked is the number of sites a request went to; the rest are never requested
  const never = [{ platform: "A", state: "no_public_url", found: null }, { platform: "B", state: "unknown", found: null, evidence: "The site sends the same page for every handle, so it cannot be checked automatically." }, { platform: "C", state: "unknown", found: null, evidence: "CrawlR has no confirmed rule for this site yet, so it was not checked automatically." }];
  const full = { username: T, checked: 2, total: 1, results: [one("found"), one("not_found"), ...never] };
  ok(sourceCoverage(full).answered === 2 && sourceCoverage(full).total === 2 && sourceTally({ adultCheck: full }, NAMES).rows[0].state === "results", "sites that are never requested do not make the source partial");
  ok(sourceTally({ adultCheck: { username: T, checked: 2, total: 0, results: [one("not_found"), one("not_found"), ...never] } }, NAMES).rows[0].state === "none" && sourceTally({ adultCheck: { username: T, checked: 2, total: 0, results: [one("blocked"), one("blocked"), ...never] } }, NAMES).rows[0].state === "failed", "nor failed: it is nothing found when every asked site answered, and failed only when every asked site blocked");
  ok(sourceTally({ adultCheck: { username: T, checked: 0, total: 0, results: never } }, NAMES).rows[0].state === "none", "a check that asked no site is not a failure");
  ok(A.adultCheckText({ checked: 7, total: 2, results: [one("found"), one("found"), one("not_found"), one("not_found"), one("not_found"), one("not_found"), one("not_found"), ...Array.from({ length: 10 }, (_, i) => ({ platform: `N${i}`, state: i < 6 ? "no_public_url" : "unknown", found: null }))] }) === "7 checked, 2 found, 10 not checkable automatically", "the run log and the card say: 7 checked, N found, 10 not checkable automatically");
  ok(A.adultCheckText(C.adultCheck) === "8 checked, 3 found, 2 blocked by site, 2 not checkable automatically" && sourceCards.adultCheck(C.adultCheck, adult).includes("8 checked, 3 found, 2 blocked by site, 2 not checkable automatically.") && /if \(key === "adultCheck"\) return adultCheckText\(data\);/.test(read(J + "investigate.js")), "the fixture reads the same way on the card, and the run log uses the same text");
  const blocked = sourceTally({ adultCheck: { username: T, checked: 3, total: 3, results: [one("blocked"), one("blocked"), one("unknown")] } }, NAMES).rows[0];
  ok(blocked.state === "failed" && blocked.text === "blocked by every site checked" && /^blocked:/.test(statusForAi(blocked)), "blocked everywhere is a failed source, never nothing found");
  const none = sourceTally({ adultCheck: { username: T, checked: 3, total: 3, results: [one("not_found"), one("not_found"), one("no_public_url")] } }, NAMES).rows[0];
  ok(none.state === "none" && !none.hasResults && statusForAi(none) === "not found", "answered everywhere with no page found is nothing found, whatever its total says");
  ok(sourceTally({ adultCheck: { error: "timeout", error_code: "timeout" } }, NAMES).rows[0].state === "failed" && !adultOf(buildEvidence({ adultMode: true, adultCheck: { error: "timeout", error_code: "timeout" } }, T, "username")).length, "a check that failed is a failed source and adds no row");
  ok(sourceCoverage(fx.collected.adultCheck).total === 8 && !sourceTally(A.withoutAdult(C), NAMES).rows.some((x) => x.key === "adultCheck"), "and a case without the mode has no such source");
}

// ---- 9. the minor guard --------------------------------------------------------------------------
{
  const g = (h) => A.minorGuard(h, NOW);
  const BLOCK = { anna15: "number", "15anna": "number", apollo13: "number", "13yo_gamer": "age", "user_15_yo": "age", age14: "age", im16: "age", "17f": "age", f15: "age", m16: "age", "14yrs": "age", under18: "age", u18: "age", born2012: "birth_year", "2011baby": "birth_year", jake_2010x: "birth_year", user2008: "birth_year", class_of_2027: "class_year", co2026: "class_year", kidrock: "word", "k1d_rocker": "word", schoolgirl99: "word", highschool_dan: "word", grade7: "word", "9thgrade": "word", l0li: "word", teenwolf: "word", "t33n_queen": "word", fifteen_candles: "word", preteen_x: "word", "@minor_threat": "word", tweenie: "word" };
  for (const [h, why] of Object.entries(BLOCK)) ok(g(h).blocked && g(h).reason === A.GUARD_REASONS[why], `blocked: ${h} (${why})`);
  for (const h of ["jdoe_example", "torvalds", "teen18", "teens19", "eighteen_plus", "nineteen_eighty", "user2007", "jdoe1990", "m4", "f1fan", "page3", "xx_14_xx", "between_us", "upgrade7x", "anna21", "18f", "25m", "class_of_2005", "canary", ""]) ok(!g(h).blocked && g(h).reason === "", `allowed: ${h || "(empty)"}`);
  ok(g("user2008").blocked && !A.minorGuard("user2008", new Date("2027-01-02")).blocked && A.minorGuard("user2009", new Date("2027-01-02")).blocked, "the birth year rule moves with the calendar");
  // a bare year blocks from 18 down to 6 years ago; a more recent year only next to a birth marker
  const Y = NOW.getFullYear();
  for (let y = Y - 18; y <= Y - 6; y++) ok(g(`user${y}`).reason === A.GUARD_REASONS.birth_year && g(`${y}_sam`).blocked, `a bare ${y} blocks`);
  for (let y = Y - 5; y <= Y; y++) ok(!g(`user${y}`).blocked && !g(`john_${y}`).blocked, `a bare ${y} does not: it is more often the year the account was made`);
  ok(!g(`user${Y - 19}`).blocked && !g(`user${Y + 1}`).blocked, "nor does a year outside the range");
  for (const h of [`born${Y - 1}`, `${Y - 3}baby`, `bday${Y - 5}`, `b.${Y - 2}`, `b_${Y}`, `${Y - 4}_kid`, `birthday${Y - 2}`, `${Y - 1}born`]) ok(g(h).reason === A.GUARD_REASONS.birth_year, `blocked next to a birth marker: ${h}`);
  for (const h of [`user${Y - 1}`, `john${Y - 2}`, `est${Y - 2}`, `bob${Y - 2}`, `b${Y - 2}`, `club${Y - 3}`]) ok(!g(h).blocked, `allowed: ${h}`);
  // short years, class years, school years and announced ages, from the current year
  const yy = (y) => String(y % 100).padStart(2, "0");
  const zero = Array.from({ length: 13 }, (_, i) => Y - 18 + i).filter((y) => y >= 2000 && y <= 2009);   // birth years written 0x
  ok(zero.length > 0, "there are still zero-led birth years under 18 to test");
  for (const y of zero) ok(g(`emma${yy(y)}`).reason === A.GUARD_REASONS.birth_year && g(`${yy(y)}emma`).blocked && g(`liz_${yy(y)}`).blocked && g(`born${yy(y)}`).blocked && g(`emma_2k${yy(y)}`).blocked && g(`2k${y % 100}`).blocked, `a short ${y} blocks: emma${yy(y)}, ${yy(y)}emma, liz_${yy(y)}, born${yy(y)}, 2k${y % 100}`);
  ok(g(`2k${(Y - 16) % 100}`).blocked && g(`emma_2k${(Y - 16) % 100}`).blocked && !g(`nba2k${(Y - 2) % 100}`).blocked && !g(`2k${(Y - 20) % 100}x`).blocked, "2k years follow the bare year range");
  for (const d of [0, 1, 5, 15]) ok(g(`classof${yy(Y + d)}`).reason === A.GUARD_REASONS.class_year && g(`co${yy(Y + d)}`).blocked, `a class year ${d} years ahead blocks, written short`);
  ok(!g(`classof${yy(Y - 1)}`).blocked && !g(`co${yy(Y + 16)}x`).blocked, "a class year that has passed, or is too far ahead, does not");
  ok(g(`born${yy(Y - 18)}`).blocked && g(`baby${yy(Y)}`).blocked && !g(`born${yy(Y - 19)}`).blocked && !g(`born${yy(Y - 21)}`).blocked && !g("born99").blocked, "a marked two-digit year blocks up to 18 years back, and reads a future one as the last century");
  for (const h of ["emma09", "08emma", "liz_08", "born09", "2k9", "emma_2k10", "classof27", "co27", "grade_5", "5thgrade", "year9", "yr9", "turning15", "quinceanera", "almost16x", "only_14", "2ndgrade", "grade1", "yr_11", "firstgrade_fan"]) ok(g(h).blocked, `blocked: ${h}`);
  for (const h of ["emma19", "born05", "born99", "year3", "nba2k24", "user2025", "retrograde9", "upgrade5", "year12x", "just20", "turning30", "emma20", "co2", "mayor9"]) ok(!g(h).blocked, `allowed: ${h}`);
  ok(g("born2025").blocked && g("2023baby").blocked && g("bday2021").blocked && g("b.2024").blocked && !g("user2025").blocked && !g("john2024").blocked && !g("est2024").blocked && !g("bob2024").blocked, "the lead's eight examples, as of 2026");
  ok(Object.values(BLOCK).length && !Object.keys(BLOCK).some((h) => g(h).reason.toLowerCase().includes(h.replace(/^@/, ""))), "a reason never repeats the handle");
  ok(A.guardText(A.GUARD_REASONS.age) === "Adult and dating sites are not checked for this handle: it suggests a minor (the handle states an age under 18).", "the sentence the switch shows");
  // nothing adult is asked for, shown or sent for such a handle, and nothing overrides that
  ok(!sourcePlan("username", "anna15", { adult: true }).includes("adult") && A.usernameBody("anna15", A.adultOn("username", "anna15", true)).nsfw === false, "a blocked handle plans no adult check and sends nsfw false");
  const young = buildEvidence(C, "jdoe_2012", "username");
  ok(!adultOf(young).length && !names(JSON.stringify(young.items), ADULT_SITES).length && !A.adultAllowed(C, "jdoe_2012", "username"), "a stored case for such a handle shows no adult row even with the flag set");
  ok(!("adultMode" in A.scrubCollected(C, "jdoe_2012", "username")) && !("adultCheck" in A.scrubCollected(C, "jdoe_2012", "username")), "and its adult data is dropped when it is opened");

  // drift: every pattern and reason here is the one in core/adult_guard.py, read as text
  const py = read("../../core/adult_guard.py");
  const SEP = (py.match(/^_SEP = r"([^"]+)"/m) || [])[1];
  ok(SEP === "[._-]*", "the Python file's separator is the one ported");
  const pyRx = {};
  for (const m of py.matchAll(/^(_[A-Z_0-9]+) = re\.compile\(\s*((?:\s*r?f?r?"[^"\n]*"\s*)+)\)/gm)) {
    pyRx[m[1]] = [...m[2].matchAll(/(r?f?r?)"([^"\n]*)"/g)].map(([, pre, body]) => (pre.includes("f") ? body.replaceAll("{_SEP}", SEP).replaceAll("{{", "{").replaceAll("}}", "}") : body)).join("");
  }
  const mine = Object.keys(A.GUARD_PATTERNS);
  ok(mine.length === 20 && mine.every((k) => k in pyRx), `every guard pattern has a counterpart in the Python file (${mine.filter((k) => !(k in pyRx)).join(", ") || "all"})`);
  for (const k of mine) ok(A.GUARD_PATTERNS[k].source === pyRx[k], `${k} matches core/adult_guard.py`);
  const guardNames = Object.keys(pyRx).filter((k) => !["_MEDIA_KEY", "_MEDIA_VALUE", "_LINK", "_TAG"].includes(k));
  ok(guardNames.every((k) => mine.includes(k)), `no guard pattern in the Python file is missing here (${guardNames.filter((k) => !mine.includes(k)).join(", ") || "none"})`);
  const pyReasons = Object.fromEntries([...py.slice(py.indexOf("REASONS = {"), py.indexOf("}", py.indexOf("REASONS = {"))).matchAll(/"(\w+)": "([^"]+)"/g)].map((m) => [m[1], m[2]]));
  ok(JSON.stringify(pyReasons) === JSON.stringify(A.GUARD_REASONS), "the reasons are the server's sentences");
  ok(/ADULT_AGE = 18\b/.test(py) && /^MIN_PLAIN_AGE = 6\b/m.test(py) && /^CLASS_AHEAD = 15\b/m.test(py) && /CLASS_AHEAD = 15\b/.test(read(J + "adult.js")) && /MIN_PLAIN_AGE = 6\b/.test(read(J + "adult.js")) && /_LETTER_MIN_AGE = 8\b/.test(py) && /str\.maketrans\("013457", "oieast"\)/.test(py) && /str\.maketrans\("013457", "oleast"\)/.test(py) && /ERROR_CODE = "minor_guard"/.test(py), "and so are the age limits, the digit readings and the error code");
}

// ---- 10. the switch: off on every page load, never stored, on for the page session ------------------
// The switch is a session mode now (static/v2/js/modes.js, tested in full by modes.test.mjs). What
// this suite still pins is the adult side of it: off by default, never stored, the minor guard
// with no override, the server's refusal, and that the run uses the tested plan and bodies.
{
  const before = writes.length;
  const M = await import(J + "modes.js");
  const yes = ({ accept }) => accept();
  const s = M.makeSessionModes(), suspended = M.makeSuspended();
  const view = (target, type) => M.startAdult({ on: s.on("adult"), type, target, suspended }).view;
  const v0 = view(T, "username");
  ok(v0.on === false && v0.state === "off" && v0.applies === false && v0.reason === "", "off by default, whatever an old stored preference says");
  s.request("adult", true, yes);
  ok(view(T, "username").applies === true && view(T, "username").on === true, "on for this handle, and it stays on for that case's re-runs");
  ok(view("someone_else", "username").applies === true && view(T, "username").applies === true, "another handle is another case and the mode is still on: it is not tied to one handle");
  ok(!("reset" in s) && s.on("adult"), "there is no reset: a new case, Clear and a case opened from History leave it on");
  ok(view(T, "email").on === true && view(T, "email").applies === false && view(T, "email").note === "Not used for this kind of target." && view(T, "username").applies === true && view("", "").applies === false, "it only applies to a username case, and stays on through any other");
  ok(M.makeSessionModes().on("adult") === false && (await import(J + "modes.js?fresh=" + n)).session.on("adult") === false, "a new page load starts with it off: the state lives in memory only");
  // the suspended state
  const blocked = view("anna15", "username");
  ok(blocked.on && blocked.state === "suspended" && !blocked.applies && blocked.reason === "Adult and dating sites are not checked for this handle: it suggests a minor (the handle starts or ends with a number from 10 to 17).", "a handle that suggests a minor suspends the mode for that case and says why");
  ok(A.adultOn("username", "anna15", view("anna15", "username").applies) === false && A.adultOn("username", "anna15", true) === false && s.on("adult"), "and there is no override, while the session mode stays on");
  // the server's guard wins when the two disagree
  suspended.add(T, { server: true, detail: "The handle contains a word that suggests a minor." });
  const refused = view(T, "username");
  ok(refused.state === "suspended" && !refused.applies && /it suggests a minor \(the handle contains a word that suggests a minor\)\.$/.test(refused.reason) && s.on("adult"), "a refusal from the server suspends the mode for that case, with its reason");
  ok(view("someone_else", "username").applies === true, "and only for that case");
  suspended.add("other_one", { server: true }); ok(view("other_one", "username").state === "suspended" && /it suggests a minor \(/.test(view("other_one", "username").reason), "a refusal with no reason still suspends it");
  ok(writes.length === before, "none of this wrote to storage");

  const strip = (f) => read(J + f).replace(/\/\/.*$/gm, "");
  const adultSrc = strip("adult.js"), inv = read(J + "investigate.js");
  ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|\bstore\b/.test(adultSrc) && !/localStorage|sessionStorage|indexedDB|document\.cookie|\bstore\b/.test(strip("modes.js")) && !/localStorage|sessionStorage|indexedDB|document\.cookie|\bstore\b/.test(strip("modeui.js")), "adult.js, modes.js and modeui.js never touch storage");
  const ui = strip("modeui.js");
  const handler = ui.slice(ui.indexOf('document.addEventListener("change"'), ui.indexOf('document.addEventListener("click"'));
  ok(handler.length > 100 && /session\.request\(id, e\.target\.checked === true, ask\(id\)\)/.test(handler) && !/setSrc|store\.|localStorage|crawlr_v2_sources/.test(handler) && !/adultToggle|data-adult-toggle/.test(inv), "the switch's handler asks the session, in memory, and writes no preference");
  ok(!/data-toggle="?adult|data-extra|maigret\.\$\{|nsfwOn|source-extra|maigret\.nsfw/.test(inv) && M.LEGACY_PREFS.includes("maigret.nsfw") && M.LEGACY_PREFS.includes("active") && !("maigret.nsfw" in M.cleanPrefs({ "maigret.nsfw": true, sherlock: true }).prefs), "the old stored Maigret preference is gone: reading the preferences drops it");
  ok((inv.match(/store\.set\("crawlr_v2_sources", srcState\)/g) || []).length === 1 && /const setSrc = \(id, v\) => \{ if \(!mayStore\(id\)\) return;/.test(inv) && !M.mayStore("adult") && !M.mayStore("active"), "crawlr_v2_sources is written in one place, and never with a mode");
  const fn = (name) => { const a = inv.indexOf(`export function ${name}(`); return inv.slice(a, inv.indexOf("\n}\n", a)); };
  ok(fn("loadHistory").length > 200 && fn("clearCase").length > 200 && !/session\.request|\.request\(|adultSwitch/.test(fn("loadHistory").replace(/\/\/.*$/gm, "")) && !/session\.|suspended|adultSwitch/.test(fn("clearCase")), "opening a case from History and clearing the case leave the mode alone");
  ok(/usernameBody\(handle, state\.adultMode\)/.test(inv) && /plan\.has\("adult"\)\) jobs\.push\(runSource\(ADULT_SOURCE, "\/api\/recon\/adult-check", \{ username: handle \}/.test(inv) && (inv.match(/adult-check/g) || []).length === 1, "the run uses the tested plan and bodies, and adult-check is called from one place, behind the plan");
  ok(/role="switch" id="\$\{base\}" data-session-mode="\$\{id\}"/.test(read(J + "modes.js")) && /aria-labelledby="\$\{base\}-l" aria-describedby="\$\{base\}-d"/.test(read(J + "modes.js")), "the switch is a labelled role=switch, described by its one-line description");
}

// ---- 11. old saved cases --------------------------------------------------------------------------
{
  // Saved while the old Maigret-only extra was on: rows tagged by Maigret, no adult flag anywhere.
  const old = { sherlock: { username: "jdoe_old", results: [{ site: "GitHub", url: "https://github.com/jdoe_old", confidence: "major_platform" }] }, maigret: { username: "jdoe_old", total: 4, results: [
    { site: "Reddit", url: "https://www.reddit.com/user/jdoe_old/", category: "discussion", verified: true, profile: { name: "J Old" } },
    { site: "SwipeBay", url: "https://swipebay.example/jdoe_old", category: "dating", verified: true, profile: { name: "J Old", bio: "hello", image: "https://swipebay.example/i/1.jpg" } },
    { site: "RedCurtain", url: "https://redcurtain.example/jdoe_old", category: "porn, video", verified: false },
    { site: "CamHarbor", url: "https://camharbor.example/jdoe_old", category: "webcam, erotic", verified: false }] } };
  const e = buildEvidence(old, "jdoe_old", "username");
  const all = JSON.stringify(e);
  ok(!adultOf(e).length && !/SwipeBay|RedCurtain|CamHarbor|swipebay|redcurtain|camharbor/.test(all) && e.items.some((i) => i.key === "acct:reddit"), "an old case with adult-tagged Maigret rows and no flag shows none of them, in any group");
  ok(!/SwipeBay|RedCurtain|CamHarbor/.test(caseMarkdown({ collected: old, target: "jdoe_old", type: "username", now: NOW })) && !/SwipeBay|RedCurtain|CamHarbor/.test(JSON.stringify(aiPayloadFor(old, "jdoe_old", "username"))) && !/SwipeBay|RedCurtain|CamHarbor/.test(sourceCards.maigret(old.maigret, {})), "nor in an export, the AI payload or the Maigret card");
  ok(avatarImages(old, "jdoe_old", "username").length === 0 && collectProfiles(old, "jdoe_old", "username").map((p) => p.site).join() === "Reddit", "nor in clustering or the avatar list");
  const kept = A.scrubCollected(old, "jdoe_old", "username");
  ok(kept.maigret.results.length === 1 && kept.maigret.results[0].site === "Reddit", "and they are dropped when the case is opened");
  ok(JSON.parse(globalThis.localStorage.getItem("crawlr_v2_sources"))["maigret.nsfw"] === true && (await import(J + "modes.js")).session.on("adult") === false && A.adultOn("username", "jdoe_old", (await import(J + "modes.js")).session.on("adult")) === false, "the old stored preference turns nothing on");
}

// ---- 12. the server's answer and the copy ---------------------------------------------------------
{
  const body = { detail: "This handle may belong to a minor, so adult and dating sites are not checked for it.", code: "minor_guard", reason: "The handle states an age under 18.", error: "x", error_code: "minor_guard", error_detail: "The handle states an age under 18." };
  globalThis.fetch = async () => ({ ok: false, status: 400, headers: { get: () => null }, json: async () => body });
  let err = null;
  try { await post("/api/recon/adult-check", { username: "x" }); } catch (e) { err = e; }
  ok(err instanceof ApiError && err.code === "minor_guard" && err.status === 400 && err.reason === "The handle states an age under 18.", "the server's 400 minor_guard answer reaches the run as its own error, with the reason");
  globalThis.fetch = async () => ({ ok: false, status: 400, headers: { get: () => null }, json: async () => ({ detail: { error_code: "minor_guard", reason: "The handle contains a word that suggests a minor." } }) });
  err = null; try { await post("/api/recon/sherlock", { username: "x", nsfw: true }); } catch (e) { err = e; }
  ok(err?.code === "minor_guard" && /word that suggests a minor/.test(err.reason), "in either shape");
  const inv = read(J + "investigate.js");
  ok(/err\.code === "minor_guard"\) \{ adultRefused\(err\.reason\)/.test(inv) && /d === GUARDED \? runSource\(label, url, usernameBody\(handle, false\)/.test(inv), "the run then suspends the mode for the case and asks the tool again without it");

  ok(A.ADULT_NOTICE === "Adult and dating sites are existence checks only. A match shows a handle is taken there, not who owns it." && A.ADULT_SWITCH === "Adult sites" && (await import(J + "modes.js")).MODE.adult.label === A.ADULT_SWITCH && A.ADULT_SECTION === "Adult and dating sites (existence checks only)", "the fixed strings");
  const app = read(J + "app.js"), html = read("../../static/v2/index.html");
  ok(app.split(A.ADULT_COPY).length === 2 && html.split(A.ADULT_COPY).length === 2, "the consent gate and the Sources panel say the one sentence");
  ok(/<b>Adult and dating sites are opt-in\.<\/b> They are checked only when you switch that on: existence checks only, never for a handle that suggests a minor, and only for lawful purposes\./.test(app) && /existence checks only/.test(A.ADULT_COPY) && /minor/.test(A.ADULT_COPY) && /lawful/.test(A.ADULT_COPY) && /when you switch that on:/.test(A.ADULT_COPY) && !/for a case/.test(A.ADULT_COPY), "it says opt-in, existence only, not for minors, lawful purposes");
  ok(A.ADULT_LASTS === "The switch is off when the page loads, and stays on until you switch it off or reload." && app.split(A.ADULT_LASTS).length === 3 && !/off for every new case|for a case:/.test(app + html), "the consent gate and the acceptable-use statement say how long the switch lasts, and no longer say it is off for every new case");
  ok(/const TERMS_KEY = "crawlr_terms_v3";/.test(app) && !/crawlr_terms_v2/.test(app), "the gate's wording changed, so its stored key was bumped and everyone sees it once more");
  const srcs = ["modes.js", "modeui.js", "adult.js", "evidence.js", "investigate.js", "renderers.js", "report.js", "workbench.js", "brief.js", "casefile.js", "core.js", "links.js", "app.js"].map((f) => read(J + f)).join("\n") + html + read("./fixtures/adult.json");
  ok(!srcs.includes(String.fromCharCode(8212)), "no em dash in anything this change touched");
}

// ---- 13. the tally, the tools' counts and the AI payload read the adult-free view ------------------
{
  const NAMES = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", adultCheck: "Adult site check" };
  // a run whose only Sherlock and Maigret rows are on adult sites
  const only = { adultMode: true, sherlock: { username: T, total: 2, possible: 2, nsfw: true, adult_checked: 30, results: C.sherlock.results.filter((r) => r.adult).slice(0, 2) }, maigret: { username: T, total: 2, possible: 2, verified: 1, nsfw: true, results: C.maigret.results.filter((r) => r.adult).slice(0, 2) }, adultCheck: C.adultCheck };
  const view = A.tallyView(only, T, "username");
  const t = sourceTally(view, NAMES);
  const st = (k) => t.rows.find((r) => r.key === k);
  ok(st("sherlock").state === "none" && !st("sherlock").hasResults && st("maigret").state === "none" && !st("maigret").hasResults, "Sherlock and Maigret are not 'with results' when their only rows are on adult sites");
  ok(st("adultCheck").hasResults && t.withResults === 1 && t.ran === 3, "the adult site check is tallied as its own source");
  ok(sourceTally(only, NAMES).rows.find((r) => r.key === "sherlock").hasResults === true, "(the raw case would have counted them, which is why the tally reads the view)");
  const m = A.withoutAdult(only);
  ok(m.sherlock.total === 0 && m.sherlock.possible === 0 && m.sherlock.results.length === 0 && m.maigret.total === 0 && m.maigret.possible === 0 && m.maigret.verified === 0 && !("adult_checked" in m.sherlock) && !("nsfw" in m.sherlock), "the tools' counts are recomputed: never total 2 beside an empty list");
  const mixed = A.withoutAdult(C);
  ok(mixed.sherlock.total === mixed.sherlock.results.length && mixed.sherlock.total === 2 && mixed.maigret.total === 2 && C.sherlock.total > 2, "in a mixed case the counts are the ordinary rows only");
  const untouched = { sherlock: { username: T, total: 40, possible: 38, results: [{ site: "GitHub", url: "https://github.com/x" }] } };
  ok(A.withoutAdult(untouched).sherlock.total === 40, "a case with no adult row keeps the counts it was saved with");
  const pay = aiPayloadFor(only, T, "username", { source_status: Object.fromEntries(t.rows.map((r) => [r.name, statusForAi(r)])) });
  ok(pay.sherlock.total === 0 && pay.sherlock.results.length === 0 && pay.maigret.total === 0 && pay.source_status.Sherlock === "not found" && pay.source_status.Maigret === "not found" && /^partial|ok/.test(pay.source_status["Adult site check"]) && pay.adult_sites.length > 0, "the AI payload carries the recomputed counts and the adult-free statuses");
  const off = sourceTally(A.tallyView({ ...only, adultMode: undefined }, T, "username"), NAMES);
  ok(!off.rows.some((r) => r.key === "adultCheck") && off.withResults === 0, "without the mode nothing adult is tallied at all");
  const inv = read(J + "investigate.js");
  ok(/const tally = \(\) => sourceTally\(\{ \.\.\.tallyView\(state\.collected, state\.target, state\.type\), linkCheck:/.test(inv) && !/sourceTally\(\{ \.\.\.state\.collected/.test(inv) && /sourceHasResults\(key === "sherlock" \|\| key === "maigret" \? withoutAdult\(\{ \[key\]: data \}\)\[key\] : data\)/.test(inv), "the app's one tally and its run log rows read that view");
}

// ---- 14. what a model or a pasted reply says about these sites ------------------------------------
{
  const reply = ["## Case summary", "Fine.", "", "## Adult and dating sites (existence checks only)", "A handle with this name exists on Fansly.", "![a](https://cdn.fansly.com/a.jpg)", "", "## NSFW footprint", "He is clearly into this. See https://onlyfans.com/jdoe_example", "Second line stays out of the body.", "### Sub heading", "Sub text.", "", "## OnlyFans and cam sites", "<img src=x>", "More.", "", "## Dating profiles", "Tinder: could not be checked.", "", "## Gaps and next pivots", "- one gap", "", "## Adult & dating (second copy)", "Again."].join("\n");
  const sp = A.splitAdultProse(reply);
  ok(!/adult|dating|nsfw|onlyfans|fansly|tinder|into this|Sub text|Again/i.test(sp.rest) && /## Case summary/.test(sp.rest) && /## Gaps and next pivots\n- one gap/.test(sp.rest), "every section whose heading is about adult or dating sites is taken out, whatever it is called and however many there are");
  ok(/A handle with this name exists on Fansly\./.test(sp.prose) && /Second line stays out of the body\./.test(sp.prose) && /Tinder: could not be checked\./.test(sp.prose) && /Again\./.test(sp.prose) && !/https?:|!\[|<img|cdn\.|\.jpg/.test(sp.prose), "what is kept of them has no address and no markup");
  for (const h of ["Adult and dating sites", "Adult sites", "NSFW", "Dating apps", "OnlyFans presence", "Porn sites", "Cam sites", "Sexual content", "18+ platforms", "Hookup apps", "Escort listings"]) ok(A.isAdultHeading(h), `an adult heading: ${h}`);
  for (const h of ["Case summary", "Identity assessment", "Platform footprint", "Exposure and risk", "Investigative leads", "Gaps and next pivots", "Camera gear", "Updating records"]) ok(!A.isAdultHeading(h), `not one: ${h}`);
  const on = reportHtml({ ai: { summary: reply, profile: {} }, target: T, items: ev.items, facts: ev.facts, collected: C });
  ok((on.match(/class="rsec adult"/g) || []).length === 1 && !/NSFW footprint|OnlyFans and cam sites|Dating profiles|second copy/.test(on) && !/into this|cdn\.fansly|<img src=x|&lt;img/.test(on) && /Second line stays out of the body\./.test(on.match(/<section class="rsec adult"[\s\S]*?<\/section>/)[0]), "mode on: one adult section, with every such part filtered into it and none rendered as another section");
  noImages(on.match(/<section class="rsec adult"[\s\S]*?<\/section>/)[0], "the report's adult section with a hostile reply");
  const e0 = buildEvidence(OFF, T, "username");
  const off = reportHtml({ ai: { summary: reply, profile: {} }, target: T, items: e0.items, facts: e0.facts, collected: OFF });
  ok(!/rsec adult/.test(off) && !/adult|dating|nsfw|onlyfans|fansly|tinder|into this|Sub text|Again\./i.test(off.replace(/<div class="dossier">[\s\S]*?<div class="report-scroll">/, "")) && /one gap/.test(off), "mode off: none of those sections is shown, in any form");
  const single = reportHtml({ ai: { summary: "## Adult sites\nHe uses https://onlyfans.com/x a lot.\nPlain line.", profile: {} }, target: T, items: e0.items, facts: e0.facts, collected: OFF });
  ok(!/onlyfans|Plain line|Adult sites/i.test(single.replace(/<div class="dossier">[\s\S]*?<div class="report-scroll">/, "")), "a reply that is only such a section shows nothing of it with the mode off");
  const mdOff = caseMarkdown({ collected: OFF, target: T, type: "username", now: NOW, ai: { summary: reply }, deep: { summary: reply } });
  ok(!/nsfw|onlyfans|fansly|into this|Tinder/i.test(mdOff) && /one gap/.test(mdOff) && !/adult|dating/i.test(mdOff), "the Markdown export drops them too with the mode off");
  const mdOn = caseMarkdown({ collected: C, target: T, type: "username", now: NOW, ai: { summary: reply }, deep: { summary: reply } });
  const aiPart = mdOn.slice(mdOn.indexOf("## AI analysis"), mdOn.indexOf("## Deep Dive")), deepPart = mdOn.slice(mdOn.indexOf("## Deep Dive"));
  ok(/## Adult and dating sites \(existence checks only\)\nA handle with this name exists on Fansly\./.test(aiPart) && !/into this|https:\/\/onlyfans|cdn\.fansly|NSFW footprint/.test(aiPart) && !/adult|dating|onlyfans|fansly/i.test(deepPart), "with the mode on the AI report keeps one filtered section, and a Deep Dive never has one");
}

// ---- 15. links to adult sites found on ordinary profiles -------------------------------------------
{
  // The fixture's GitHub profile points at four of them: website field, bio, README, social accounts.
  const leads = (e) => e.items.filter((i) => i.tier === "lead");
  ok(leads(ev).map((i) => i.key).sort().join() === "lead:domain:example.org,lead:url:https://example.org/docs" && !leads(ev).some((i) => A.adultHost(i.url) || A.adultHost(i.what)), "mode on: a link to an adult site is never a lead, and never has Open in Recon");
  const from = (k) => row(ev, k).meta;
  ok(/linked from the GitHub website field/.test(from("adult:onlyfans")) && /linked from the GitHub bio/.test(from("adult:fansly")) && /linked from the GitHub profile README/.test(from("adult:chaturbate")) && /linked from GitHub social accounts/.test(from("adult:tinder")), "it is said inside the adult group, on that site's row, as linked from where it was found");
  ok(!ev.facts.some((f) => A.adultHost(f.v) || A.adultHost(f.url)) && ev.facts.some((f) => f.k === "Bio" && f.v === "Maps, trains and") && !ev.facts.some((f) => f.k === "Website"), "and never a fact: the website field is dropped and the bio loses the address");
  const only = { adultMode: true, github: { found: true, name: "Jordan Doe", profile_url: "https://github.com/jdoe_example", blog: "grindr.com/jdoe", bio: "find me on https://www.bumble.com/jdoe ok" }, enricher: { profiles: [{ platform: "Mastodon", url: "https://mastodon.social/@jdoe_example", display_name: "Jordan Doe", bio: "also https://sub.pof.com/x and https://example.net/me" }] }, maigret: { results: [{ site: "Keybase", url: "https://keybase.io/jdoe_example", verified: true, profile: { name: "Jordan Doe", links: ["https://okcupid.com/profile/jdoe", "https://example.net/me"] } }] } };
  const eo = buildEvidence(only, T, "username");
  const rowsOnly = adultOf(eo);
  ok(rowsOnly.map((i) => i.key).join() === "adult:link:bumble.com,adult:link:grindr.com,adult:link:okcupid.com,adult:link:pof.com" && rowsOnly.every((i) => i.link_kind === "none" && i.url === "" && i.adult.state === "mentioned" && !i.action && !/<a\b|<button/.test(evWhat(i))), "a site that is only linked from a profile is a text row of the adult group: no link, no action");
  ok(/^linked from the GitHub website field · not checked/.test(row(eo, "adult:link:grindr.com").meta) && /linked from the Mastodon profile/.test(row(eo, "adult:link:pof.com").meta) && /linked from the Keybase profile/.test(row(eo, "adult:link:okcupid.com").meta), "each says where the link was found, and that nothing was checked");
  ok(leads(eo).every((i) => /example\.net/.test(i.what)) && leads(eo).length >= 1, "the ordinary links on the same profiles are still leads");
  ok(A.adultCounts(rowsOnly).taken === 0 && A.adultForAi(rowsOnly).length === 0 && /^Adult and dating sites: 0 handles taken, 0 could not be checked\./.test(A.adultBriefText(rowsOnly)), "such rows are not handles taken, and are not sent to the AI");
  for (const [label, c] of [["mode off", { ...only, adultMode: undefined }], ["mode off, the fixture", OFF]]) {
    const e = buildEvidence(c, T, "username");
    const everything = JSON.stringify([e.items, e.facts, e.general, e.identity]) + caseMarkdown({ collected: c, target: T, type: "username", now: NOW }) + JSON.stringify(aiPayloadFor(c, T, "username", { source_status: { GitHub: "ok" } })) + sourceCards.github(A.withoutAdult(c).github, A.withoutAdult(c).githubDeep);
    ok(!/onlyfans|fansly|chaturbate|tinder|grindr|bumble|okcupid|pof\.com/i.test(everything), `${label}: such a link appears nowhere: not in the ledger, the facts, an export or the AI payload`);
  }
  const inv = read(J + "investigate.js");
  ok(/const all = state\.collected, c = withoutAdult\(all\);/.test(inv.slice(inv.indexOf("function renderSourceCards"), inv.indexOf("function renderHead"))), "the source cards are drawn from the adult-free view");
  ok(A.adultHost("https://www.onlyfans.com/x") === "onlyfans.com" && A.adultHost("sub.fansly.com/y") === "fansly.com" && A.adultHost("https://notonlyfans.com") === "" && A.adultHost("https://onlyfans.com.evil.example/x") === "" && A.adultHost("https://github.com/onlyfans") === "" && A.adultHost("") === "" && A.adultHost("not a url") === "", "a host matches when it is a listed host or a subdomain of one, and nothing looser");
}

// ---- 16. the site list is the server's ------------------------------------------------------------
{
  const py = read("../../core/adult_sites.py");
  const platforms = [...py.slice(py.indexOf("PLATFORMS = {"), py.indexOf("}", py.indexOf("PLATFORMS = {"))).matchAll(/"([a-z0-9.-]+)": "(?:adult|dating)"/g)].map((m) => m[1]);
  const unflagged = [...py.slice(py.indexOf("UNFLAGGED = ("), py.indexOf("\n)", py.indexOf("UNFLAGGED = ("))).matchAll(/\("([^"]+)", "([^"]+)", "(?:adult|dating)"\)/g)].map((m) => [m[1], m[2]]);
  ok(platforms.length >= 17 && unflagged.length >= 10, `the server's hand lists are read as text (${platforms.length} platform hosts, ${unflagged.length} unflagged sites)`);
  ok(platforms.every((h) => A.ADULT_HOSTS.includes(h)) && unflagged.every(([, h]) => A.ADULT_HOSTS.includes(h)), `every host on them is on the client's list (${[...platforms, ...unflagged.map((x) => x[1])].filter((h) => !A.ADULT_HOSTS.includes(h)).join(", ") || "all"})`);
  ok(unflagged.every(([name, host]) => A.isAdultRow({ site: name, url: "" }) && A.isAdultRow({ site: "x", url: `https://${host}/someone` })), "and a row for any of them is adult by name or by host, with no mark on it");
  ok(A.ADULT_HOSTS.length > 100 && new Set(A.ADULT_HOSTS).size === A.ADULT_HOSTS.length && A.ADULT_HOSTS.every((h) => /^[a-z0-9.-]+\.[a-z0-9-]+$/.test(h)), "the generated list holds plain hosts (the whole list is compared with the server's in tests/test_confidence.py)");
  // the defensive drop uses it: an unmarked row in a leaked answer or an old saved case
  const leak = { username: T, total: 4, possible: 4, results: [{ site: "GitHub", url: "https://github.com/jdoe_example" }, { site: "RoyalCams", url: "https://royalcams.com/profile/jdoe_example" }, { site: "datingRU", url: "http://dating.ru/jdoe_example" }, { site: "Renamed", url: "https://www.fansly.com/jdoe_example" }] };
  const scrubbed = A.scrubResponse("sherlock", leak, false);
  ok(scrubbed.results.map((r) => r.site).join() === "GitHub" && scrubbed.total === 1 && scrubbed.possible === 1, "mode off: an unmarked row for a listed site is dropped from an answer, by name or by host");
  const oldCase = buildEvidence({ sherlock: leak }, T, "username");
  ok(oldCase.items.filter((i) => i.tier !== "similar").map((i) => i.key).join() === "acct:github" && !/royalcams|dating\.ru|fansly/i.test(JSON.stringify(oldCase) + JSON.stringify(aiPayloadFor({ sherlock: leak }, T, "username")) + sourceCards.sherlock(leak, {})), "an old saved case shows no such row anywhere");
  ok(adultOf(buildEvidence({ adultMode: true, sherlock: leak }, T, "username")).map((i) => i.key).join() === "adult:datingru,adult:renamed,adult:royalcams", "and with the mode on they are rows of the adult group");
}

// ---- 17. Deep Dive and the link check never get an adult host ----------------------------------------
{
  const { deepDiveUrls } = await import(J + "evidence.js");
  const { ADULT_SITE_HOSTS } = await import(J + "adult-sites.js");
  const urls = deepDiveUrls(C);
  ok(urls.length === 3 && urls.map((u) => u.site).sort().join() === "GitHub,Keybase,Mastodon" && !urls.some((u) => A.adultHost(u.url)) && !names(JSON.stringify(urls), ADULT_HOSTS).length, "the Deep Dive URL list holds no adult row");
  // every listed host, as an unmarked row with a made-up site name, with the mode on and off
  const every = { sherlock: { results: [{ site: "GitHub", url: "https://github.com/jdoe_example" }, ...ADULT_SITE_HOSTS.map((h, i) => ({ site: `Plain Site ${i}`, url: `https://${i % 2 ? "www." : ""}${h}/jdoe_example` }))] }, platformCheck: { results: ADULT_SITE_HOSTS.slice(0, 20).map((h, i) => ({ platform: `Other ${i}`, state: "found", found: true, url: `https://${h}/u/jdoe_example` })) } };
  for (const c of [every, { ...every, adultMode: true }]) {
    const list = deepDiveUrls(c);
    ok(list.length === 1 && list[0].url === "https://github.com/jdoe_example" && !list.some((u) => ADULT_SITE_HOSTS.some((h) => new URL(u.url).hostname === h || new URL(u.url).hostname.endsWith(`.${h}`))), `the Deep Dive URL list contains no host from adult-sites.js (mode ${c.adultMode ? "on" : "off"})`);
    const e = buildEvidence(c, T, "username");
    const sendable = L.pendingChecks(e.items);
    ok(sendable.length === 1 && sendable[0].id === "acct:github" && !sendable.some((r) => A.adultHost(r.url)), `no row on a listed host is offered to the link check (mode ${c.adultMode ? "on" : "off"})`);
  }
  const inv = read(J + "investigate.js");
  ok(/const profileUrls = \(\) => deepDiveUrls\(state\.collected\);/.test(inv) && /pendingChecks\(buildEvidence\(state\.collected, state\.target, state\.type\)\.items, tier\)\.filter\(\(r\) => !adultHost\(r\.url\)\)/.test(inv), "the app uses that list, and filters the link check's rows by host as well");
  ok(!/adult\s*:/.test(read(J + "linkcheck.js")) && /\{ username: username\(\), links: batch \}/.test(read(J + "linkcheck.js")), "the verifier's adult field is never sent");
  ok(L.KNOWN_EVIDENCE.includes("Adult and dating sites are checked only when that mode is on, and never for a handle that suggests a minor."), "the verifier's new sentence is known");
}

console.log(bad ? `${bad} of ${n} adult checks failed` : `${n}/${n} adult checks passed`);
process.exit(bad ? 1 : 0);
