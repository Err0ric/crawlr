// The presentation rules of the design pass: verdict tiles, History grouped by target, what an
// evidence card may say, thumbnails, and the certainty grammar (solid = read, dashed = reported).
// Run: node tests/js/design.test.mjs
import fs from "node:fs";
import { CERTAINTY, certaintyOf, safeThumb, boundAvatarHash, THUMB_MAX_CHARS, joinedYear, cardSnippet, investigateTiles, reconTiles, groupHistory, lastRunDiff, diffText } from "../../static/v2/js/present.js";
import { buildEvidence, isFinding } from "../../static/v2/js/evidence.js";
import { buildFindings } from "../../static/v2/js/reconfindings.js";
import { parseCaseFile, buildCaseFile } from "../../static/v2/js/casefile.js";
import { renderTiers, evWhat, evSrc, verdictHtml, identityHead, skeletonRows, skeletonCards } from "../../static/v2/js/workbench.js";
import { mark, sourceTally } from "../../static/v2/js/core.js";

const fx = (n) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${n}.json`, import.meta.url), "utf8"));
let pass = 0, fail = 0;
const ok = (c, name) => { if (c) pass++; else { fail++; console.log("FAIL", name); } };
const el = () => ({ innerHTML: "", hidden: false, id: "t" });
const tv = fx("torvalds"), extra = fx("identity-extras"), em = fx("email"), rc = fx("recon"), ad = fx("adult"), hs = fx("hash");
const THUMB = extra.avatarHash.results.find((r) => r.thumb).thumb;

// ---- certainty grammar ------------------------------------------------------------------
{
  ok(CERTAINTY.unverified.line === "dashed" && ["flag", "linked", "matches", "different"].every((t) => CERTAINTY[t].line === "solid"), "only what nothing read is dashed");
  ok(Object.values(CERTAINTY).every((c) => c.word && c.tone) && new Set(Object.values(CERTAINTY).map((c) => c.tone)).size === 5 && new Set(Object.values(CERTAINTY).map((c) => c.word)).size === 5, "every tier has its own word and its own color, so color is never the only signal");
  ok(certaintyOf("lead").word === "" && certaintyOf("adult").tone === "" && certaintyOf(undefined).line === "solid", "rows outside the five tiers carry no pill and no tier color");
}

// ---- thumbnails ---------------------------------------------------------------------------
{
  ok(safeThumb(THUMB) === THUMB && safeThumb("data:image/png;base64,iVBORw0KGgo=") !== "", "a small WebP or PNG data URI is kept");
  const bad = ["https://example.org/a.png", "data:image/svg+xml;base64,PHN2Zz4=", "data:text/html;base64,PGI+", "data:image/png;base64,AAAA\" onerror=\"x", "data:image/png;base64,AA AA", "data:image/png,AAAA", "javascript:alert(1)", "data:image/webp;base64," + "A".repeat(THUMB_MAX_CHARS), "", null, 7, { a: 1 }];
  ok(bad.every((b) => safeThumb(b) === ""), "an address, another media type, markup, a space or an oversized string is never a thumbnail");
  const b = boundAvatarHash({ results: [{ id: "a", hash: "c3c3e7e7ffff0f0f", default: false, thumb: THUMB }, { id: "b", hash: "00", default: true, thumb: THUMB }, { id: "c", hash: "11", default: false, thumb: "https://tracker.example.org/p.gif" }, { id: "d", error: "x", error_code: "timeout", thumb: THUMB }, { id: "e", hash: "22", default: false }] });
  ok(b.results[0].thumb === THUMB && !("thumb" in b.results[1]) && !("thumb" in b.results[2]) && !("thumb" in b.results[3]) && b.results[4].hash === "22" && b.results.length === 5, "bounding keeps a real picture's thumbnail and drops one on a placeholder, a failed row or an address");
  const many = boundAvatarHash({ results: Array.from({ length: 40 }, (_, i) => ({ id: `p${i}`, hash: "c3c3e7e7ffff0f0f", default: false, thumb: THUMB })) });
  ok(many.results.filter((r) => r.thumb).length === 30, "at most 30 thumbnails are kept");
  ok(boundAvatarHash(null) === null && boundAvatarHash({ error: "x" }).error === "x", "a failed or missing comparison passes through");

  // On import: a case file can carry a small image data URI in that field and nothing else.
  const collected = { ...tv.collected, avatarHash: { results: [{ id: "acct:github", hash: "c3c3e7e7ffff0f0f", default: false, thumb: "https://evil.example.org/track.png" }, { id: "acct:keybase", hash: "c3c3e7e7ffff0f0d", default: false, thumb: THUMB }, { id: "acct:x", hash: "c3c3e7e7ffff0f0d", default: false, thumb: "data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+" }] } };
  const res = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: tv.target, type: tv.type, ran: 1, collected })));
  const got = res.ok ? res.entry.results.avatarHash.results : [];
  ok(res.ok && !("thumb" in got[0]) && got[1].thumb === THUMB && !("thumb" in got[2]) && !JSON.stringify(res.entry).includes("evil.example.org") && !JSON.stringify(res.entry).includes("svg+xml"), "an imported case keeps only a checked thumbnail");
  // A stored case that skipped the import check is still drawn through safeThumb.
  const evil = buildEvidence({ ...tv.collected, avatarHash: { results: [{ id: "acct:github", hash: "c3c3e7e7ffff0f0f", default: false, thumb: "https://evil.example.org/track.png" }] } }, tv.target, tv.type);
  const box = el(); renderTiers(box, evil.items, [{ id: "linked", title: "Linked", cls: "", open: true, blurb: "" }], new Set(), "");
  ok(!evil.items.some((i) => i.thumb) && !box.innerHTML.includes("evil.example.org"), "an unchecked thumbnail never reaches a row or the page");
  ok(!mark("GitHub", { thumb: "https://evil.example.org/a.png", favicon: false }).includes("<img") && mark("GitHub", { thumb: THUMB }).includes('class="mark-thumb"') && !mark("GitHub", { thumb: THUMB, url: "https://github.com/x" }).includes("duckduckgo"), "the mark shows a checked thumbnail, and then asks for no favicon");
  ok(mark("Example Site", { url: "https://www.example.org/u/jdoe?x=1" }).includes('src="https://icons.duckduckgo.com/ip3/example.org.ico"') && !mark("Example Site", { url: "https://www.example.org/u/jdoe" }).includes("jdoe") && mark("Example Site", {}).includes(">ES<") && !mark("x", { url: "javascript:alert(1)" }).includes("<img") && !/onerror|onload/.test(mark("a", { url: "https://example.org" })), "a favicon is asked for by host alone, with initials underneath and no inline handler");
}

// ---- evidence cards -----------------------------------------------------------------------
{
  ok(joinedYear("2011-09-03T15:26:22Z") === "2011" && joinedYear("Wed, 15 Aug 2012 09:21:06 +0000") === "2012" && joinedYear("Monday 5th of September 2011 05:11:58 AM") === "2011" && joinedYear("1300000000", new Date("2026-01-01")) === "2011", "a join year is read from the shapes sources use");
  ok(joinedYear("") === "" && joinedYear("soon") === "" && joinedYear("3024-01-01") === "" && joinedYear("1783019524", new Date("2026-01-01")) === "" && joinedYear(null) === "", "no year is shown when none can be read, or when it is in the future");
  const none = cardSnippet({ kinds: new Set(["reported"]), sources: ["Sherlock", "Maigret"] }, null);
  ok(none.facts.length === 0 && none.bio === "" && none.basis === "Reported by Sherlock, Maigret. Nothing was read.", "a row nothing read says what kind of check found it and states no fact");
  const bare = cardSnippet({ kinds: new Set(["read"]), sources: ["Maigret"] }, { name: "", location: "", bio: "" });
  ok(bare.facts.length === 0 && bare.basis === "Profile page read by Maigret. It carries no name, bio or dates.", "a profile that was read and is empty says so");
  ok(cardSnippet({ kinds: new Set(["registered"]), sources: ["Holehe"] }, null).basis.startsWith("The site's sign-up or reset form answered"), "a registration check says what it is");
  const full = cardSnippet({ kinds: new Set(["read"]), sources: ["GitHub"] }, { shownName: "Linus Torvalds", location: "Portland, OR", repos: 12, followers: 331999, created: "2011-09-03T15:26:22Z", bio: "" });
  ok(JSON.stringify(full.facts) === JSON.stringify(["Linus Torvalds", "Portland, OR", "12 repos", "331,999 followers", "joined 2011"]) && full.basis === "" && full.bio === "", "facts are listed as the source returned them");
  ok(cardSnippet({}, { repos: null, followers: undefined, created: "", bio: "x".repeat(400) }).facts.length === 0 && cardSnippet({}, { bio: "x".repeat(400) }).bio.length === 140 && cardSnippet({}, { repos: 0, followers: 1 }).facts.join("|") === "0 repos|1 follower", "a missing count is not shown as zero, a real zero is, and a long bio is clipped");

  // Against a whole case: every fact on every card is a value some source returned.
  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  const cards = ev.items.filter((i) => i.card);
  const hay = JSON.stringify(c).toLowerCase();
  const years = new Set([c.github.created_at, ...c.maigret.results.map((r) => r.profile?.created_at)].map((v) => joinedYear(v)).filter(Boolean));
  const said = (f) => { const m = f.match(/^([\d,]+) (repos?|followers?)$/); if (m) return hay.includes(m[1].replace(/,/g, "")); const y = f.match(/^joined (\d{4})$/); if (y) return years.has(y[1]); return hay.includes(JSON.stringify(f).slice(1, -1).toLowerCase()); };
  ok(cards.length > 30 && cards.every((i) => i.card.facts.every(said)), "no card states a fact that is not in a source's answer");
  ok(cards.every((i) => i.card.facts.length || i.card.bio || i.card.basis), "every card says something: a fact, a bio excerpt, or what kind of check found it");
  ok(ev.items.filter((i) => i.key?.startsWith("acct:") && i.tier !== "noise").every((i) => i.card) && ev.items.filter((i) => i.tier === "lead" || i.tier === "noise").every((i) => !i.card), "account rows are cards; leads and noisy sites stay compact rows");
  const gh = ev.items.find((i) => i.key === "acct:github");
  ok(gh.card.handle === "torvalds" && gh.card.facts.includes("Linus Torvalds") && gh.card.facts.includes("joined 2011") && gh.card.why === "GitHub's own record for this handle" && gh.thumb === THUMB, "the GitHub card: handle, facts, why it is linked, and the server's thumbnail");
  ok(ev.items.filter((i) => i.thumb).every((i) => i.thumb === THUMB && ["acct:github", "acct:keybase"].includes(i.key)) && !ev.items.some((i) => i.key === "acct:x" && i.thumb), "only a real picture gives a row a thumbnail: a default one never does");
  const unv = ev.items.find((i) => i.tier === "unverified" && i.card);
  ok(unv.card.facts.length === 0 && /Nothing was read\.$/.test(unv.card.basis) && unv.card.why === "", "an unverified card states no fact about the person");
  ok(ev.identity.views.find((v) => v.primary).thumb === THUMB && ev.identity.views.filter((v) => !v.primary).every((v) => v.thumb === ""), "the primary identity carries its picture; other people's groups carry none here");

  // Markup: one component, three distinct states in words and line style.
  const tiers = ["linked", "matches", "different", "unverified", "lead", "noise"].map((id) => ({ id, title: id, cls: "", open: true, blurb: "" }));
  const box = el(); renderTiers(box, ev.items, tiers, new Set(), "");
  const row = (key) => box.innerHTML.split('<div class="ev ').find((r) => r.includes(`data-row="${key}"`)) || "";
  ok(/^rich tone-linked\s/.test(row("acct:github")) && row("acct:github").includes('<span class="cp tone-linked ">Linked</span>') && row("acct:github").includes('class="mark-thumb"') && !row("acct:github").includes("duckduckgo"), "a linked card: solid edge, the word Linked, the thumbnail");
  ok(/tone-unverified line-dashed/.test(row(unv.key)) && row(unv.key).includes('<span class="cp tone-unverified line-dashed">Unverified</span>'), "an unverified card: dashed edge, dashed pill, the word Unverified");
  ok(ev.items.filter((i) => i.tier === "different").every((i) => row(i.key).includes(">Different person</span>")) && ev.items.filter((i) => i.tier === "matches").every((i) => row(i.key).includes(">Matches</span>")), "matches and different person say so in words");
  const lead = ev.items.find((i) => i.tier === "lead");
  ok(!row(lead.key).includes('class="mark') && !row(lead.key).includes('class="cp'), "a lead is a compact row: no mark, no pill");
  ok(!/<img[^>]+src="(?!data:image\/webp;base64,|data:image\/png;base64,|https:\/\/icons\.duckduckgo\.com\/ip3\/[a-z0-9.-]+\.ico")/.test(box.innerHTML), "the only images in the ledger are checked thumbnails and favicons by host");
  ok(!/avatars\.githubusercontent|twimg|gravatar\.com\/avatar/.test(box.innerHTML.replace(/href="[^"]*"/g, "")), "no profile picture is hotlinked from its host");
  ok(evSrc({ source: "Sherlock, Maigret" }) === '<span class="chip">Sherlock</span><span class="chip">Maigret</span>' && evSrc({ source: "" }) === "", "sources are chips");
  ok(evWhat({ what: "x", card: { handle: "<b>h</b>", facts: ["<i>f</i>"], bio: "<u>b</u>", basis: "", why: "<s>w</s>", note: "" } }).includes("&lt;b&gt;h&lt;/b&gt;") && !/<(i|u|s)>/.test(evWhat({ what: "x", card: { handle: "", facts: ["<i>f</i>"], bio: "<u>b</u>", basis: "", why: "<s>w</s>", note: "" } })), "every card value is escaped");

  // Adult and dating rows stay text with an initials badge: no mark, no favicon, no thumbnail.
  const av = buildEvidence(ad.collected, ad.target, ad.type);
  const abox = el(); renderTiers(abox, av.items, [{ id: "adult", title: "Adult and dating sites", cls: "", open: true, blurb: "" }], new Set(), "");
  ok(av.items.some((i) => i.tier === "adult") && av.items.filter((i) => i.tier === "adult").every((i) => !i.card && !i.thumb) && !/<img|duckduckgo|class="mark/.test(abox.innerHTML) && abox.innerHTML.includes('class="site-glyph"'), "adult and dating rows: initials badge only, never an image");
}

// ---- verdict tiles ------------------------------------------------------------------------------
{
  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  const n = (t) => ev.items.filter((i) => i.tier === t).length;
  const tiles = investigateTiles({ items: ev.items, collected: c, type: "username", failedKeys: [] });
  const by = Object.fromEntries(tiles.map((t) => [t.id, t]));
  ok(tiles.map((t) => t.label).join("|") === "Linked|Exists|Unverified|Leads", "a username case: Linked, Exists, Unverified, Leads");
  ok(by.linked.value === n("linked") && by.exists.value === n("matches") + n("different") && by.unverified.value === n("unverified") && by.lead.value === n("lead"), "every tile is the count of the rows in its group");
  ok(by.linked.tone === "linked" && by.exists.tone === "match" && by.unverified.line === "dashed" && by.linked.line === "solid" && by.linked.jump.tier === "linked" && by.lead.jump.tier === "lead", "tiles use the tier colors and line styles, and jump to their group");

  // Unknown when the source failed: never a zero.
  const failed = { sherlock: { error: "timeout", error_code: "timeout" }, maigret: { error: "timeout", error_code: "timeout" }, github: { error: "rate limited", error_code: "rate_limited" } };
  const fe = buildEvidence(failed, "someone", "username");
  const ft = investigateTiles({ items: fe.items, collected: failed, type: "username", failedKeys: ["sherlock", "maigret", "github"] });
  ok(ft.every((t) => t.state === "unknown" && t.value === "unknown" && t.line === "dashed" && t.tone === "" && /failed/.test(t.sub)), "every tile of a case whose sources failed says unknown");
  ok(!verdictHtml(ft).includes(">0<") && verdictHtml(ft).includes(">unknown<") && (verdictHtml(ft).match(/data-jump-tab="sources"/g) || []).length === 4, "unknown is a word on the tile, and it opens By source where the failure is");
  const clean = { sherlock: { results: [], total: 0 }, maigret: { results: [], total: 0 }, github: { found: false } };
  const ct = investigateTiles({ items: [], collected: clean, type: "username", failedKeys: [] });
  ok(ct.every((t) => t.state === "zero" && t.value === 0 && t.tone === "") && (verdictHtml(ct).match(/ disabled>/g) || []).length === 4, "sources that answered and found nothing give a quiet zero");
  const part = investigateTiles({ items: ev.items, collected: { ...c, maigret: { error: "x", error_code: "timeout" } }, type: "username", failedKeys: ["maigret"] });
  ok(part.find((t) => t.id === "unverified").state === "count" && /^at least: a source failed$/.test(part.find((t) => t.id === "unverified").sub), "a count beside a failed source is marked as a lower bound");

  // Email: the breach tile is the breach source's, in all three states.
  const ee = buildEvidence({ ...em.collected, hibp: em.hibpV2 }, em.target, "email");
  const et = (col, failedKeys = []) => investigateTiles({ items: buildEvidence(col, em.target, "email").items, collected: col, type: "email", failedKeys }).find((t) => t.id === "breaches");
  ok(investigateTiles({ items: ee.items, collected: em.collected, type: "email" }).map((t) => t.label).join("|") === "Linked|Breaches|Unverified|Leads", "an email case: Linked, Breaches, Unverified, Leads");
  const found = et({ ...em.collected, hibp: em.hibpV2 });
  ok(found.state === "count" && found.value === ee.items.filter((i) => i.key.startsWith("breach:")).length && found.value > 0 && found.tone === "flag", "found: the number of breaches in the ledger");
  ok(et({ ...em.collected, hibp: { email: em.target, total: 0, breaches: [] } }).state === "zero", "not found: zero, quiet");
  const down = et({ ...em.collected, hibp: { error: "timeout", error_code: "timeout" } }, ["hibp"]);
  ok(down.state === "unknown" && down.value === "unknown", "failed: unknown, not zero");
  const { hibp, ...noHibp } = em.collected;
  ok(et(noHibp).state === "off" && et(noHibp).value === "not checked", "switched off: not checked, which is not zero either");

  // Hash, phone and name cases choose tiles that fit.
  const ht = investigateTiles({ items: [], collected: { hash: hs.malicious }, type: "hash", extra: { hash: { verdict: "MALICIOUS", detection: { positives: 59, total: 70 }, answered: 4, asked: 4 } } });
  ok(ht.map((t) => `${t.label}=${t.value}`).join("|") === "Verdict=Malicious|Engines flagging it=59 of 70|Sources answered=4 of 4" && ht[0].tone === "flag", "a hash case: verdict, engines, sources answered");
  const hu = investigateTiles({ items: [], collected: { hash: {} }, type: "hash", extra: { hash: { verdict: "UNKNOWN", detection: null, answered: 0, asked: 4 } } });
  ok(hu.every((t) => t.state === "unknown" && t.line === "dashed"), "a hash no source could be asked about is unknown on every tile");
  const nt = investigateTiles({ items: [{ tier: "people" }, { tier: "people" }, { tier: "handles" }], collected: { nameResult: {} }, type: "name", extra: { name: { answered: 3, asked: 5 } } });
  ok(nt.map((t) => `${t.label}=${t.value}`).join("|") === "Candidates=2|Directories answered=3 of 5|Handles to try=1|Public figure=0" && nt[1].sub === "the rest are unknown", "a name case counts candidates, never findings");
  const pt = investigateTiles({ items: [], collected: { phone: { error: "x", error_code: "timeout" } }, type: "phone", failedKeys: ["phone"], extra: { phone: { lineType: "", carrier: "" } } });
  ok(pt[0].value === "unknown" && pt[2].state === "unknown", "a failed phone lookup is unknown");

  // Recon.
  const rcol = { ...rc.collected, shodan: rc.internetdbV2, email_posture: rc.emailPostureV2 };
  const rf = buildFindings(rcol, rc.target, "domain");
  const rt = reconTiles({ items: rf.items, collected: rcol, type: "domain", failedKeys: [], extra: { certDays: 41 } });
  const rb = Object.fromEntries(rt.map((t) => [t.id, t]));
  ok(rt.map((t) => t.label).join("|") === "Flags|Open ports|Subdomains|Expiring soon", "a domain case: Flags, Open ports, Subdomains, Expiring soon");
  ok(rb.flags.value === rf.items.filter((i) => i.tier === "flag").length && rb.services.value === rf.items.filter((i) => i.key.startsWith("port:")).length && rb.subdomains.value === rf.items.filter((i) => i.tier === "inventory").length && rb.expiring.sub === "certificate has 41 days left", "recon tiles count the ledger's rows");
  const rdown = reconTiles({ items: [], collected: { shodan: { error: "x", error_code: "timeout" }, subdomains: { error: "x", error_code: "timeout" }, ssl: { error: "x", error_code: "timeout" } }, type: "domain", failedKeys: ["shodan", "subdomains", "ssl"] });
  ok(rdown.every((t) => t.value === "unknown"), "recon tiles whose sources failed say unknown");
  ok(reconTiles({ items: [], collected: {}, type: "asn" }).length === 0 && reconTiles({ items: [], collected: { ssl: {} }, type: "ip" }).map((t) => t.id).join() === "flags,services,expiring", "an ASN has no tiles, and an address has no subdomain tile");
  // The tally the pages pass in really marks those sources failed.
  ok(sourceTally(failed, { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub" }).rows.every((r) => r.state === "failed"), "the failed keys come from the one tally");
}

// ---- identity header ----------------------------------------------------------------------------
{
  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  const head = identityHead(ev.identity, "");
  ok(head.includes("Linus Torvalds") && head.includes(">Primary identity</span>") && /Primary identity because /.test(head) && head.includes('class="mark-thumb"') && head.includes('<span class="chip">GitHub</span>'), "the header names the primary identity, why, its picture and its accounts");
  const others = ev.identity.views.filter((v) => !v.primary);
  ok(others.length > 0 && others.every((v) => head.includes(`data-cluster-btn="${v.id}" aria-pressed="false"`)) && (head.match(/aria-pressed="true"/g) || []).length === 1, "every other person under the handle is one button, and the shown one is pressed");
  const other = identityHead(ev.identity, others.find((v) => v.different).id);
  ok(other.includes(">Different person</span>") && !other.includes(">Primary identity</span>") && !other.includes("mark-thumb"), "another person is labelled as one, without the primary's picture");
  const np = buildEvidence({ maigret: tv.collected.maigret }, tv.target, tv.type);
  const nh = identityHead(np.identity, "");
  ok(np.identity.noPrimary && nh.includes(">No primary identity</span>") && nh.includes("Nobody is selected") && /no primary identity is chosen/.test(nh) && !nh.includes("<img"), "with no primary identity the header says so plainly");
  ok(identityHead({ views: [], primary: null, noPrimary: false }, "") === "", "no profiles, no header");
}

// ---- skeletons -------------------------------------------------------------------------------
{
  const s = skeletonRows(["Sherlock", "Maigret"]);
  ok(s.includes("Waiting for 2 sources: Sherlock, Maigret.") && (s.match(/aria-hidden="true"/g) || []).length === 3 && !/class="ev |cp tone|type="checkbox"/.test(s), "placeholder rows are hidden from screen readers and share nothing with a result row");
  ok(skeletonRows([]) === "" && skeletonRows(undefined) === "" && skeletonRows(["GitHub"]).includes("Waiting for GitHub."), "no pending source, no placeholder");
  ok(skeletonCards(["<b>x</b>"]).includes("&lt;b&gt;x&lt;/b&gt;: waiting for an answer") && skeletonCards([]) === "", "a placeholder card names its source, escaped");
  const box = el(); renderTiers(box, [], [], new Set(), "<p>Collecting</p>", { pending: ["Sherlock"] });
  ok(box.innerHTML.startsWith("<p>Collecting</p>") && box.innerHTML.includes("sk-wrap"), "an empty ledger mid-run shows the placeholder under its message");
}

// ---- History grouped by target -------------------------------------------------------------------
{
  const run = (id, target, ts, extra = {}) => ({ id, target, type: "INVESTIGATE", kind: "username", timestamp: ts, results: {}, v2: true, ...extra });
  const list = [run("a3", "torvalds", 300), run("d1", "darkwire.tech", 250, { type: "RECON", kind: undefined }), run("a2", "Torvalds ", 200), run("h1", "torvalds", 150, { type: "email_headers" }), run("a1", "torvalds", 100, { imported: 5 }), run("d0", "darkwire.tech", 50, { type: "RECON" })];
  const before = JSON.stringify(list);
  const g = groupHistory(list);
  ok(g.map((x) => `${x.target}:${x.type}:${x.count}`).join("|") === "torvalds:INVESTIGATE:3|darkwire.tech:RECON:2|torvalds:email_headers:1", "one entry per target and workbench, in History's order");
  ok(g[0].runs.map((r) => r.id).join() === "a3,a2,a1" && g[0].last.id === "a3" && g[0].imported === true && g[1].imported === false, "runs are newest first, and a group remembers that one came from a case file");
  ok(JSON.stringify(list) === before && g.reduce((n, x) => n + x.count, 0) === list.length, "grouping changes nothing stored and loses no run");
  ok(groupHistory(null).length === 0 && groupHistory([null, 3, { target: 5 }, run("z", "x", 1)]).length === 1, "malformed entries are skipped");
  const keys = { a3: ["k1", "k2", "k4"], a2: ["k1", "k2", "k3"], a1: [] };
  const d = lastRunDiff(g[0], (e) => keys[e.id]);
  ok(d.added === 1 && d.removed === 1 && d.same === 2 && diffText(d) === "1 new, 1 gone since the run before", "the diff compares the last two runs only");
  ok(diffText(lastRunDiff(g[1], () => ["x"])) === "no changes since the run before" && lastRunDiff(g[2], () => []) === null && diffText(null) === "", "no change says so, and a single run has no diff");
  ok(lastRunDiff(g[0], () => { throw new Error("bad"); }) === null && lastRunDiff(g[0], () => null) === null, "a run that cannot be read gives no diff, never a wrong one");
  // With the real evidence builder: a site gone from the newer run is counted.
  const older = { ...tv.collected }, newer = { ...tv.collected, sherlock: { ...tv.collected.sherlock, results: tv.collected.sherlock.results.filter((r) => r.site !== "Kick") }, maigret: { ...tv.collected.maigret, results: tv.collected.maigret.results.filter((r) => r.site !== "Kick") } };
  const real = groupHistory([{ ...run("n", "torvalds", 2), results: newer }, { ...run("o", "torvalds", 1), results: older }])[0];
  const rd = lastRunDiff(real, (e) => buildEvidence(e.results, e.target, e.kind).items.filter(isFinding).map((i) => i.key));
  ok(rd.added === 0 && rd.removed === 1, "against two saved runs the diff is the ledger's own");
}

console.log(fail ? `${fail} of ${pass + fail} design checks failed` : `${pass}/${pass + fail} design checks passed`);
if (fail) process.exit(1);
