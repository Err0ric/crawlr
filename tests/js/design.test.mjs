// The presentation rules of the design pass: verdict tiles, History grouped by target, what an
// evidence card may say, thumbnails, and the certainty grammar (solid = read, dashed = reported).
// Run: node tests/js/design.test.mjs
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
import { CERTAINTY, certaintyOf, rowCertainty, iconDomain, mayFavicon, withoutThumbs, writeHistory, safeThumb, boundAvatarHash, THUMB_MAX_CHARS, joinedYear, cardSnippet, investigateTiles, reconTiles, groupHistory, lastRunDiff, diffText } from "../../static/v2/js/present.js";
import { investigateBrief } from "../../static/v2/js/brief.js";
// report.js pulls in ai.js, which wires a click listener on load.
globalThis.document ??= { addEventListener() {} };
const { reportHtml } = await import("../../static/v2/js/report.js");
import { buildEvidence, isFinding } from "../../static/v2/js/evidence.js";
import { buildFindings } from "../../static/v2/js/reconfindings.js";
import { parseCaseFile, buildCaseFile } from "../../static/v2/js/casefile.js";
import { renderTiers, evWhat, evSrc, verdictHtml, identityHead, skeletonRows, skeletonCards, pillOf, rowMark, EXPORT_STRIP } from "../../static/v2/js/workbench.js";
import { mark, sourceTally, partialGaps } from "../../static/v2/js/core.js";

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
  ok(mark("Example Site", { url: "https://www.example.org/u/jdoe?x=1", favicon: true }).includes('src="https://icons.duckduckgo.com/ip3/example.org.ico"') && !mark("Example Site", { url: "https://www.example.org/u/jdoe", favicon: true }).includes("jdoe") && mark("Example Site", {}).includes(">ES<") && !mark("Example Site", { url: "https://www.example.org/u/jdoe" }).includes("<img") && !mark("x", { url: "javascript:alert(1)", favicon: true }).includes("<img") && !/onerror|onload/.test(mark("a", { url: "https://example.org", favicon: true })), "a favicon is asked for by host alone, with initials underneath and no inline handler");
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
  ok(/^rich tone-linked\s/.test(row("acct:github")) && /<span class="cp tone-linked\s*">Linked<\/span>/.test(row("acct:github")) && row("acct:github").includes('class="mark-thumb"') && !row("acct:github").includes("duckduckgo"), "a linked card: solid edge, the word Linked, the thumbnail");
  ok(/tone-unverified line-dashed/.test(row(unv.key)) && /<span class="cp tone-unverified line-dashed\s*">Unverified<\/span>/.test(row(unv.key)), "an unverified card: dashed edge, dashed pill, the word Unverified");
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
  const pt = investigateTiles({ items: [], collected: { phone: { error: "x", error_code: "timeout" } }, type: "phone", failedKeys: ["phone"], extra: { phone: { known: false } } });
  ok(pt.map((t) => t.label).join("|") === "Valid|Line type|Assigned in|Flags" && pt.every((t) => t.state === "unknown" && t.line === "dashed") && pt[0].sub === "the lookup failed", "a failed phone lookup is unknown on every tile");
  const pv = investigateTiles({ items: [{ tier: "flag", key: "phone:voip" }, { tier: "info", key: "phone:valid" }], collected: { phone: { number: {} } }, type: "phone", extra: { phone: { known: true, valid: true, validWord: "Valid", validSub: "fits the numbering plan", lineType: "VoIP", lineSub: "by number range", place: "", placeSub: "" } } });
  ok(pv.map((t) => `${t.label}=${t.value}`).join("|") === "Valid=Valid|Line type=VoIP|Assigned in=unknown|Flags=1" && pv[0].tone === "linked" && pv[0].line === "solid" && pv[2].line === "dashed" && pv[2].sub === "not known for this number" && pv[3].tone === "flag", "a phone case: Valid, Line type, Assigned in, Flags, solid where the plan was read");

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
  ok(head.includes("Linus Torvalds") && head.includes(">Primary identity</span>") && /Primary identity, chosen automatically because /.test(head) && head.includes('class="mark-thumb"') && head.includes('<span class="chip">GitHub</span>'), "the header names the primary identity, why, its picture and its accounts");
  const others = ev.identity.views.filter((v) => !v.primary);
  ok(others.length > 0 && others.filter((v) => v.pickable).every((v) => head.includes(`data-pick="${v.id}" aria-pressed="false"`)) && (head.match(/aria-pressed="true"/g) || []).length === 1 && !head.includes('data-pick="unassigned"') && /automatic choice/.test(head), "every other person under the handle is one button that picks them, the primary one is pressed, and the group with no name cannot be picked");
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

// ---- favicons: which rows, which host --------------------------------------------------------
{
  ok(iconDomain("https://torvalds.deviantart.com/") === "deviantart.com" && iconDomain("https://www.github.com/torvalds") === "github.com" && iconDomain("https://a.b.example.co.uk/x") === "example.co.uk" && iconDomain("https://mastodon.social/@x") === "mastodon.social", "the icon host is the registrable domain, never a subdomain");
  ok(iconDomain("https://torvalds.deviantart.com/", "torvalds") === "deviantart.com" && iconDomain("https://torvalds.com/", "torvalds") === "" && iconDomain("https://blog.jdoe-example.net/", "jdoe") === "" && iconDomain("https://jdoe.co.uk/", "@JDoe") === "", "a domain that carries the handle is never sent, and a handle in a subdomain is cut off with the subdomain");
  ok(["http://192.168.1.10/a", "https://8.8.8.8/", "https://[2001:db8::1]/", "https://intranet/x", "https://printer.local/", "https://git.corp/", "https://db.internal/x", "https://x.localhost/", "https://a.test/", "https://abc.onion/", "ftp://example.org/", "javascript:alert(1)", "", null, "not a url", "https://example.123/"].every((u) => iconDomain(u) === ""), "no icon for an IP address, a single-label or internal name, or anything that is not http");
  const acct = { key: "acct:kick", card: { handle: "x" }, tier: "unverified", url: "https://kick.com/x" };
  ok(mayFavicon(acct) && !mayFavicon(acct, { imported: true }), "an account row may have an icon, but not in a case opened from a case file");
  ok(!mayFavicon({ ...acct, tier: "adult" }) && !mayFavicon({ ...acct, glyph: "OF" }) && !mayFavicon({ ...acct, adult: { state: "read" } }), "an adult or dating row never has one");
  ok(!mayFavicon({ key: "lead:domain:x.org", tier: "lead", url: "https://x.org" }) && !mayFavicon({ key: "host:a.example.org", tier: "hosts", url: "https://a.example.org" }) && !mayFavicon({ key: "sub:a.example.org", tier: "inventory", url: "https://a.example.org" }) && !mayFavicon({ key: "cand:github:x", tier: "people", url: "https://github.com/x" }) && !mayFavicon({ key: "port:80", tier: "surface" }) && !mayFavicon(null), "leads, host inventory, recon rows and name candidates never have one");
  ok(rowMark({ ...acct, what: "Kick" }).includes("ip3/kick.com.ico") && !rowMark({ ...acct, what: "Kick" }, { imported: true }).includes("<img") && !rowMark({ key: "acct:deviantart", what: "DeviantArt", card: { handle: "torvalds" }, tier: "matches", url: "https://torvalds.deviantart.com/" }).includes("torvalds") && rowMark({ key: "acct:deviantart", what: "DeviantArt", card: { handle: "torvalds" }, tier: "matches", url: "https://torvalds.deviantart.com/" }).includes("ip3/deviantart.com.ico"), "the row mark follows both rules");
  ok(!rowMark({ key: "acct:fansly", what: "Fansly", card: { handle: "x" }, tier: "unverified", url: "https://fansly.com/x" }).includes("<img"), "a row on an adult or dating host gets no icon even if it reached another tier");

  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  const tiers = ["linked", "matches", "different", "unverified", "lead", "noise"].map((id) => ({ id, title: id, cls: "", open: true, blurb: "" }));
  const live = el(); renderTiers(live, ev.items, tiers, new Set(), "", { handle: tv.target });
  const imp = el(); renderTiers(imp, ev.items, tiers, new Set(), "", { handle: tv.target, imported: true });
  const asked = [...live.innerHTML.matchAll(/icons\.duckduckgo\.com\/ip3\/([^"]+)\.ico/g)].map((m) => m[1]);
  ok(asked.length > 10 && asked.every((d) => d.split(".").length <= 3 && !d.includes(tv.target) && iconDomain(`https://${d}/`) === d), "a whole case asks only for registrable domains, none with the handle in it");
  ok(!/duckduckgo|<img(?![^>]+src="data:image\/)/.test(imp.innerHTML) && imp.innerHTML.includes('class="mark-thumb"') && imp.innerHTML.includes('class="mark-l"'), "a case opened from a case file asks for no icon at all: initials, and its own checked thumbnails");
  // Every icon the page can ask for sits on an account row.
  const rowsWithIcon = live.innerHTML.split('<div class="ev ').filter((r) => r.includes("duckduckgo"));
  ok(rowsWithIcon.every((r) => /data-row="acct:/.test(r)), "only account rows carry an icon");

  // The AI report: same helper, same rules, and never a remote picture.
  const ai = { summary: "## Case summary\nText.\n\n## Platform footprint\n| Platform | URL | Status | Why |\n|---|---|---|---|\n| GitHub | x | y | main account |\n" };
  const rep = reportHtml({ ai, target: tv.target, items: ev.items, facts: ev.facts, collected: c, type: tv.type });
  const repImp = reportHtml({ ai, target: tv.target, items: ev.items, facts: ev.facts, collected: c, type: tv.type, imported: true });
  const remote = (html) => [...html.matchAll(/<img[^>]+src="([^"]+)"/g)].map((m) => m[1]).filter((u) => !u.startsWith("data:image/") && !/^https:\/\/icons\.duckduckgo\.com\/ip3\/[a-z0-9.-]+\.ico$/.test(u));
  ok(remote(rep).length === 0 && !rep.includes("avatars.githubusercontent") && rep.includes('class="mark-thumb"'), "the report shows the linked account's thumbnail and no remote picture");
  ok(!repImp.includes("duckduckgo") && remote(repImp).length === 0, "the report of an imported case asks for no icon either");
  ok(/class="tile tone-linked/.test(rep) && /class="tile tone-unverified line-dashed/.test(rep) && /class="tile tone-match/.test(rep) && !/class="tile (c|l)\b/.test(rep) && /<span class="cp tone-linked">Linked \d+<\/span>/.test(rep) && /<span class="cp tone-unverified line-dashed">Unverified \d+<\/span>/.test(rep), "report tiles and legend use the ledger's certainty grammar");
  ok(!reportHtml({ ai, target: tv.target, items: ev.items, facts: ev.facts, collected: { ...c, avatarHash: undefined }, type: tv.type }).includes("avatars.githubusercontent"), "with no thumbnail the report shows initials, not the picture's address");
}

// ---- no remote image anywhere in the renderers -------------------------------------------------
{
  const dir = new URL("../../static/v2/js/", import.meta.url);
  const hits = [];
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".js"))) {
    const src = fs.readFileSync(new URL(f, dir), "utf8");
    for (const m of src.matchAll(/<img\b[^>]*>/g)) hits.push(`${f}: ${m[0].slice(0, 90)}`);
    if (/createElement\(["']img["']\)|new Image\(/.test(src)) hits.push(`${f}: creates an image element`);
  }
  ok(hits.length === 2 && hits.every((x) => x.startsWith("core.js: ")) && hits.some((x) => x.includes('class="mark-thumb" src="${esc(img)}"')) && hits.some((x) => x.includes('class="mark-fav" src="https://icons.duckduckgo.com/ip3/${esc(host)}.ico"')), "the only <img> in the JS is the mark helper's checked thumbnail and site icon: " + hits.join(" | "));
  // The export removes the review boxes, so its rows need their own columns (seen broken once).
  ok(/\.ev\{grid-template-columns:minmax\(0,1fr\) auto\}\.ev\.rich\{grid-template-columns:32px minmax\(0,1fr\) auto\}/.test(fs.readFileSync(new URL("workbench.js", dir), "utf8")), "the HTML export lays its rows out without the review box column");
  ok(EXPORT_STRIP.includes(".mark img.mark-fav") && EXPORT_STRIP.includes('img:not([src^="data:image/"])') && EXPORT_STRIP.includes(".sk-wrap") && EXPORT_STRIP.includes(".sk-card") && EXPORT_STRIP.includes(".who-switch"), "the HTML export strips site icons, any other remote image, and the placeholders");
}

// ---- tiles: mid-run, cancelled, partial ---------------------------------------------------------
{
  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  ok(investigateTiles({ items: ev.items, collected: c, type: "username", running: true }).length === 0 && reconTiles({ items: [], collected: { ssl: {} }, type: "domain", running: true }).length === 0, "no tile is drawn while a run is in flight");
  // Cancelled before anything answered: asked, no answer. Never a zero.
  const cancelled = investigateTiles({ items: [], collected: {}, type: "username", missingKeys: ["sherlock", "maigret", "github"] });
  ok(cancelled.length === 4 && cancelled.every((t) => t.state === "unknown" && t.value === "unknown" && /did not answer before the run was cancelled, so this is not zero$/.test(t.sub)), "a cancelled run's tiles say unknown, not 0");
  const half = investigateTiles({ items: ev.items, collected: { github: c.github, sherlock: c.sherlock }, type: "username", missingKeys: ["maigret"] });
  ok(half.find((t) => t.id === "unverified").atLeast && /^at least: a source did not answer/.test(half.find((t) => t.id === "unverified").sub), "a count from a cancelled run is a lower bound");
  ok(reconTiles({ items: [], collected: {}, type: "domain", missingKeys: ["shodan", "subdomains", "ssl", "whois"] }).every((t) => t.value === "unknown"), "the same for a cancelled recon");
  // The torvalds fixture has partial sources: its counts carry the caveat.
  const names = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", enricher: "Profile enrichment", platformCheck: "Platform check", githubDeep: "GitHub details", avatarHash: "Avatar comparison" };
  const rows = sourceTally(c, names).rows, partial = partialGaps(rows).map((r) => r.key);
  const pt = investigateTiles({ items: ev.items, collected: c, type: "username", partialKeys: partial });
  ok(partial.length >= 1 && pt.filter((t) => t.atLeast).length >= 1 && pt.filter((t) => t.atLeast).every((t) => t.caveat && /^at least: (a source|\d+ sources) answered only in part$/.test(t.sub)), "a partial source makes the counts it feeds 'at least'");
  const pz = investigateTiles({ items: [], collected: { platformCheck: c.platformCheck }, type: "username", partialKeys: ["platformCheck"] });
  ok(pz.find((t) => t.id === "unverified").value === "unknown", "a zero beside a partial source is unknown");
  const html = verdictHtml(pt);
  ok(html.includes('<span class="sr-only">at least </span>') && html.includes('<span aria-hidden="true">+</span>') && html.includes('class="vt-s caveat"') && !verdictHtml(investigateTiles({ items: ev.items, collected: c, type: "username" })).includes("caveat"), "'at least' is in the tile's name and its caveat line is marked to stay visible");
  // Pages the link check found.
  const checked = ev.items.map((i, n) => (i.tier === "unverified" && n % 2 ? { ...i, check: "verified" } : i));
  const k = checked.filter((i) => i.tier === "unverified" && i.check === "verified").length;
  ok(k > 0 && investigateTiles({ items: checked, collected: c, type: "username" }).find((t) => t.id === "unverified").sub === `reported, ${k} ${k === 1 ? "page" : "pages"} checked`, "the Unverified tile says how many pages were checked");
  // Email: Flags takes the third place only when there are flags besides breaches.
  const col = { ...em.collected, hibp: em.hibpV2 }, ee = buildEvidence(col, em.target, "email");
  ok(investigateTiles({ items: [...ee.items, { tier: "flag", key: "phone:voip" }], collected: col, type: "email" }).map((t) => `${t.label}=${t.value}`).slice(1, 3).join("|") === `Breaches=${ee.items.filter((i) => i.key.startsWith("breach:")).length}|Flags=1`, "an email case with other flags shows Linked, Breaches, Flags, Leads");
}

// ---- tiles and brief: sites that blocked the platform check are rows, not gaps -----------------------
{
  // The shape every username run has in production: GitHub found; Facebook, LinkedIn and Reddit
  // block the server; Discord says the handle is taken; the rest were read.
  const site = (platform, state, url) => ({ platform, url, state, found: state === "found" ? true : state === "not_found" ? false : null, evidence: "", display_name: "", public_url: true });
  const pc = { username: "err0ric", total: 4, checked: 8, results: [site("Facebook", "blocked", "https://www.facebook.com/err0ric"), site("LinkedIn", "blocked", "https://www.linkedin.com/in/err0ric"), site("Reddit", "blocked", "https://www.reddit.com/user/err0ric"),
    site("Discord", "taken", ""), site("Instagram", "found", "https://www.instagram.com/err0ric/"), site("X", "found", "https://x.com/err0ric"), site("Threads", "found", "https://www.threads.net/@err0ric"), site("TikTok", "found", "https://www.tiktok.com/@err0ric")] };
  const e0 = fx("err0ric");
  const names = { sherlock: "Sherlock", maigret: "Maigret", github: "GitHub", enricher: "Profile enrichment", platformCheck: "Platform check", adultCheck: "Adult site check", githubDeep: "GitHub details", avatarHash: "Avatar comparison" };
  const view = (c, missing = []) => {
    const ev = buildEvidence(c, e0.target, "username"), rows = sourceTally(c, names).rows;
    const failed = rows.filter((r) => r.state === "failed");
    const tiles = investigateTiles({ items: ev.items, collected: c, type: "username", failedKeys: failed.map((r) => r.key), partialKeys: partialGaps(rows).map((r) => r.key), missingKeys: missing });
    const brief = investigateBrief({ collected: c, items: ev.items, facts: ev.facts, identity: ev.identity, failed, incomplete: [...failed.map((r) => r.name), ...partialGaps(rows).map((r) => r.name), ...missing.map((k) => names[k])], type: "username", target: e0.target });
    return { rows, tiles, text: brief.rows.map((r) => r.text).join("\n") };
  };
  const c = { ...e0.collected, platformCheck: pc };
  const v = view(c);
  ok(v.rows.find((r) => r.key === "platformCheck").state === "partial" && v.rows.find((r) => r.key === "platformCheck").listed === true && partialGaps(v.rows).length === 0, "some sites blocking the platform check is still partial in the tally, and is not a gap in any count");
  ok(v.tiles.length === 4 && v.tiles.every((t) => !t.atLeast && t.state !== "unknown" && !/at least|not zero/.test(t.sub)), "production shape: every tile is a plain count, none says 'at least' or 'unknown'");
  ok(!/At least/.test(v.text) && /linked account/.test(v.text), "and the brief's count line is not prefixed with 'At least'");
  ok(!/blocked the check/.test(v.text) && /The handle is taken on Discord/.test(v.text), "the taken handle keeps its line; the blocked sites are named once, in the assessment, and not in the brief");
  // The adult site check is the same kind of source.
  const adult = { adultCheck: { results: [{ site: "A", state: "blocked" }, { site: "B", state: "not_found" }] } };
  ok(sourceTally(adult, names).rows[0].state === "partial" && partialGaps(sourceTally(adult, names).rows).length === 0, "the adult site check with a blocked site is not a gap either");
  // What still counts as down.
  const sher = view({ ...c, sherlock: { error: "timeout", error_code: "timeout" } });
  ok(sher.tiles.find((t) => t.id === "unverified").atLeast && /^at least: a source failed$/.test(sher.tiles.find((t) => t.id === "unverified").sub) && /^At least .*Sherlock did not fully answer/m.test(sher.text), "Sherlock failing still makes the counts 'at least', in the tiles and the brief");
  const allBlocked = view({ ...c, platformCheck: { ...pc, results: pc.results.slice(0, 3), checked: 3 } });
  ok(allBlocked.rows.find((r) => r.key === "platformCheck").state === "failed" && allBlocked.tiles.find((t) => t.id === "unverified").atLeast && /At least/.test(allBlocked.text), "the platform check with every site blocked failed, and that still counts");
  const reqFailed = view({ ...c, platformCheck: { error: "timeout", error_code: "timeout" } });
  ok(reqFailed.tiles.some((t) => t.atLeast) && /Platform check/.test(reqFailed.text), "and so does its request failing");
  const img = view({ ...c, avatarHash: { results: [{ id: "acct:github", hash: "00ff" }, { id: "acct:x", error: "timeout", error_code: "timeout" }] } });
  ok(partialGaps(img.rows).map((r) => r.key).join() === "avatarHash" && img.tiles.find((t) => t.id === "linked").atLeast, "a partial that can hide rows (a picture that was not read) still marks the tile it feeds");
  const cancelled = view({}, ["sherlock", "maigret", "github", "platformCheck"]);
  ok(cancelled.tiles.every((t) => t.state === "unknown" && t.value === "unknown"), "a cancelled run still gives unknown");
}

// ---- a link-checked row ---------------------------------------------------------------------------
{
  const u = { tier: "unverified", key: "acct:kick" };
  ok(rowCertainty(u).word === "Unverified" && rowCertainty(u).line === "dashed", "nothing checked: dashed Unverified");
  ok(rowCertainty({ ...u, check: "verified" }).word === "Page checked" && rowCertainty({ ...u, check: "verified" }).line === "solid" && rowCertainty({ ...u, check: "verified" }).tone === "", "page checked: a solid neutral line and the words Page checked");
  ok(rowCertainty({ ...u, check: "not_found", gone: true }).word === "Page not found" && rowCertainty({ ...u, check: "not_found" }).gone === true, "page not found says so");
  ok(["blocked", "unknown", "no_public_url"].every((s) => rowCertainty({ ...u, check: s }).word === "Unverified" && rowCertainty({ ...u, check: s }).line === "dashed"), "blocked and could-not-be-checked stay dashed Unverified");
  ok(rowCertainty({ ...u, unclaimed: true }).word === "Not a claimed account" && rowCertainty({ ...u, unclaimed: true }).line === "dashed" && rowCertainty({ ...u, unclaimed: true }).tone === "unverified" && rowCertainty({ tier: "matches", unclaimed: true }).word === "Matches" && /tone-unverified line-dashed\s*">Not a claimed account</.test(pillOf({ ...u, unclaimed: true })), "a record nobody claimed has its own words on a dashed pill");
  ok(rowCertainty({ tier: "linked", check: "verified" }).word === "Linked" && rowCertainty({ tier: "matches", check: "not_found" }).word === "Matches", "a read profile keeps its tier whatever a link check says");
  ok(/class="cp\s+is-checked\s*">Page checked</.test(pillOf({ ...u, check: "verified" })) && /is-gone\s*">Page not found</.test(pillOf({ ...u, check: "not_found" })) && /tone-unverified line-dashed\s*">Unverified</.test(pillOf({ ...u, check: "blocked" })), "the pill follows");
  const box = el(); renderTiers(box, [{ ...u, what: "Kick", url: "https://kick.com/x", link_kind: "verified_profile", check: "verified", source: "Sherlock", card: { handle: "x", facts: [], bio: "", basis: "Reported by Sherlock. Nothing was read.", why: "", note: "" } }], [{ id: "unverified", title: "Unverified", cls: "", open: true, blurb: "" }], new Set(), "");
  ok(/class="ev rich\s+is-checked/.test(box.innerHTML) && !/class="ev [^"]*line-dashed/.test(box.innerHTML) && box.innerHTML.includes('data-tier="unverified"'), "the row stays in Unverified, with a solid edge");
}

// ---- At a glance agrees with the tiles ---------------------------------------------------------
{
  const col = { github: tv.collected.github, sherlock: { error: "timeout", error_code: "timeout" }, maigret: { error: "timeout", error_code: "timeout" } };
  const ev = buildEvidence(col, tv.target, tv.type);
  const b = investigateBrief({ collected: col, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [{ name: "Sherlock" }, { name: "Maigret" }], incomplete: ["Sherlock", "Maigret"], type: "username", target: tv.target });
  ok(b.rows.every((r) => !(r.level === "ok" && /\b0 that|, 0 |and 0 /.test(r.text))) && b.rows.some((r) => r.level === "info" && /^At least 1 linked account\. Sherlock, Maigret did not fully answer/.test(r.text)), "with sources down no Good row asserts a zero: the counts are 'at least'");
  const full = investigateBrief({ collected: col, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], incomplete: [], type: "username", target: tv.target });
  ok(full.rows.some((r) => r.level === "ok" && /^1 linked account, 0 that exist and match/.test(r.text)), "with every source answered the plain counts stand");
}

// ---- storage: thumbnails go first ---------------------------------------------------------------
{
  const run = (id, thumb) => ({ id, target: "t", results: { github: { found: true }, avatarHash: { results: [{ id: "acct:github", hash: "aa", default: false, ...(thumb ? { thumb: THUMB } : {}) }] } } });
  const list = [run("new", true), run("old1", true), run("old2", false)];
  const before = JSON.stringify(list);
  const slim = withoutThumbs(list, "new");
  ok(slim[0].results.avatarHash.results[0].thumb === THUMB && !("thumb" in slim[1].results.avatarHash.results[0]) && slim[1].results.avatarHash.results[0].hash === "aa" && slim[1].results.github.found && slim[2] === list[2] && JSON.stringify(list) === before, "older runs lose their thumbnails and nothing else; the input is not changed");
  const sizes = [];
  const fits = (limit) => (l) => { const n = JSON.stringify(l).length; sizes.push(n); return n <= limit; };
  const all = JSON.stringify(list).length, noOld = JSON.stringify(slim).length, none = JSON.stringify(withoutThumbs(list, "")).length;
  ok(writeHistory(list, "new", fits(all)) === list, "storage with room keeps everything");
  ok(JSON.stringify(writeHistory(list, "new", fits(noOld))) === JSON.stringify(slim), "a full store drops older thumbnails first");
  const r3 = writeHistory(list, "new", fits(none));
  ok(r3.length === 3 && !JSON.stringify(r3).includes("data:image"), "then this run's, with every run still there");
  ok(writeHistory(list, "new", fits(10)).length === 1, "only then are older runs dropped");
}

// ---- the stylesheet keeps the grammar ---------------------------------------------------------------
{
  const css = fs.readFileSync(new URL("../../static/v2/css/app.css", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1].trim(), body: m[2] }));
  const bodyOf = (sel) => rules.filter((r) => r.sel.split(",").map((x) => x.trim()).includes(sel)).map((r) => r.body).join(";");
  ok(/border-left:\s*3px solid var\(--tone\)/.test(bodyOf(".ev")) && /border-left-style:\s*dashed/.test(bodyOf(".ev.line-dashed")), "a card's edge is solid, and dashed when nothing read it");
  ok(/border:\s*1px solid var\(--tone\)/.test(bodyOf(".cp")) && /border-style:\s*dashed/.test(bodyOf(".cp.line-dashed")), "a pill is solid, and dashed when nothing read it");
  ok(/border-left-style:\s*dashed/.test(bodyOf('.tier[data-tier="unverified"] .tier-rail')) && !/dashed/.test(bodyOf('.tier[data-tier="linked"] .tier-rail') + bodyOf('.tier[data-tier="matches"] .tier-rail') + bodyOf('.tier[data-tier="flag"] .tier-rail') + bodyOf('.tier[data-tier="different"] .tier-rail')), "only the Unverified rail is dashed");
  ok(/text-decoration:\s*underline dashed/.test(bodyOf(".lk-unverified")) && /border-style:\s*dashed/.test(bodyOf(".vt.line-dashed")) && /border-left-style:\s*dashed/.test(bodyOf(".tile.line-dashed")) && /border-left-style:\s*dashed/.test(bodyOf(".key-row.line-dashed")), "unverified links, unknown tiles, report tiles and the landing key are dashed the same way");
  ok(/border-left-style:\s*solid/.test(bodyOf(".ev.is-checked")) && /border-style:\s*solid/.test(bodyOf(".cp.is-checked")), "a checked page is drawn solid");
  for (const [tone, token] of [["flag", "--flag"], ["linked", "--linked"], ["match", "--match"], ["different", "--different"], ["unverified", "--unverified"]]) ok(bodyOf(`.ev.tone-${tone}`).includes(`--tone: var(${token})`) && bodyOf(`.cp.tone-${tone}`).includes(`--tone: var(${token})`), `tone ${tone} is ${token} on cards and pills`);
  // Purple: the primary action, the brand, the active mode, the skip link, selection and focus.
  const allowed = /focus-visible|^\.btn-primary(:hover)?$|^\.brand \.r$|aria-current=page|^\.skip$|^::selection$/;
  const purple = rules.filter((r) => /var\(--(violet|on-violet)/.test(r.body) && !/^:root|^@|data-theme/.test(r.sel));
  const stray = purple.filter((r) => !r.sel.split(",").every((x) => allowed.test(x.trim().replace(/^[^.:\[]*\{?/, "")) || allowed.test(x.trim())));
  ok(purple.length >= 5 && stray.length === 0, "purple is used only by the allowed selectors: " + stray.map((r) => r.sel).join(" | "));
  ok(!/\.btn-danger|--danger|\.fav-l|\.tile\.(c|l)\b/.test(css), "dead rules stay gone");
  ok(/\.vt-s:not\(\.caveat\)\s*\{\s*display:\s*none/.test(css) && !/\.vt-s\s*\{\s*display:\s*none/.test(css), "a tile's caveat is never hidden on a phone");
}

// ---- the lookups made on a click on a person's row, the activity readings, the footprint view ----
{
  const W = await import("../../static/v2/js/workbench.js"), D = await import("../../static/v2/js/deep.js");
  globalThis.location ??= { origin: "https://crawlr.lol" };   // link() resolves an address against the page
  const { activityViewHtml, activityHtml, sourceCards } = await import("../../static/v2/js/renderers.js");
  const EVIL = '<img src=x onerror=1>';
  // commit emails
  const ce = D.commitEmailsView({ site: "codeberg", site_name: "Codeberg", username: "samexample", state: "found", handle: "samexample", profile_url: "https://codeberg.org/samexample", display_name: "Sam Example", emails_state: "found", complete: true,
    emails: [{ email: "sam@example.org", name: `Sam ${EVIL}`, how: "forge_attributed", commits: 3, first_commit: "2026-01-15T09:00:00Z", last_commit: "2026-10-30T09:00:00Z", repos: ["samexample/maps"] }, { email: "old@example.com", name: "Sam Example", how: "author_line_match", commits: 1, first_commit: "2025-10-10T08:00:00Z", last_commit: "2025-10-10T08:00:00Z", repos: ["samexample/maps"] }],
    sections: { account: "found", repos: "ok" }, repos: [{ name: "samexample/maps", url: "https://codeberg.org/samexample/maps", fork: false, state: "ok", commits_seen: 6 }], counts: { repos_listed: 1, repos_read: 1, commits_seen: 6, own: 4, noreply: 0, other_authors: 2 } });
  const row = { key: "acct:codeberg", what: "Codeberg", canCommitEmails: { site: "codeberg", username: "samexample" } };
  const ch = W.commitHtml({ ...row, commitEmails: ce });
  ok(ce.rows.length === 2 && /class="ev-arch ev-ce "/.test(ch) && /<span class="ce-addr">sam@example\.org<\/span><span class="ed-prov">tied by the site<\/span>/.test(ch) && /<span class="ce-addr">old@example\.com<\/span><span class="ed-prov">author line only<\/span>/.test(ch) && ch.includes(D.COMMIT_HOW_TEXT.forge_attributed) && ch.includes("Anybody can commit under any name") && ch.includes(D.COMMIT_EMAILS_NOTE), "commit emails: each address in mono with its tie as a label and in words, and the caution");
  ok(!ch.includes("<img") && ch.includes("&lt;img src=x onerror=1&gt;") && /<span class="ed-prov">self-declared<\/span>/.test(ch) && /self-declared dates/.test(ch) && /data-link-kind="evidence"/.test(ch) && !/href="mailto:/.test(ch), "a name from a commit is escaped and marked self-declared, repositories are evidence links, an address is never a link");
  const unk = D.commitEmailsView({ site: "gitlab", username: "samexample", error: "x", error_code: "request_failed" });
  const uh = W.commitHtml({ ...row, commitEmails: unk });
  ok(/class="ev-arch ev-ce unknown"/.test(uh) && />Try again</.test(uh) && /unknown/.test(uh) && !/no address/i.test(uh) && !/ce-list/.test(uh), "an unknown reading has the dashed rule and Try again, and never says no addresses");
  ok(/data-commit-emails="acct:codeberg"/.test(evSrc(row)) && />Commit emails</.test(evSrc(row)) && !/data-commit-emails/.test(evSrc({ ...row, commitEmails: ce })) && /aria-disabled="true"/.test(evSrc({ ...row, commitBusy: true })) && !/data-commit-emails|data-post-activity/.test(evSrc({ key: "acct:x", what: "X" })), "the Commit emails button is on a row that can be asked, says when it is busy, and goes once the site answered");
  // post activity
  const HOURS = [0, 0, 0, 0, 0, 0, 2, 5, 12, 12, 15, 9, 11, 30, 16, 13, 15, 9, 12, 6, 3, 2, 1, 0];
  const pa = D.postActivityView({ site: "mastodon", site_name: "Mastodon", username: "samexample", instance: "fosstodon.org", found: true, state: "ok", complete: true, pages: 3, unit: "public posts", bot: false, events: 173, window: { first: "2025-11-18T08:04:43Z", last: "2026-11-16T11:05:27Z", days: 364, active_days: 73 }, hours_utc: HOURS, weekdays_utc: [28, 32, 34, 22, 38, 16, 3], weekday_labels: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"], types: [{ type: "post", count: 75 }, { type: "reply", count: 98 }],
    estimate: { utc_offset_from: -1, utc_offset_to: 1, utc_offsets: [-1, 0, 1], label: "UTC-1 to UTC+1", quiet_start_hour: 23, quiet_end_hour: 6, quiet_hours: 7, quiet_events: 0, basis: EVIL, assumption: EVIL, caveat: EVIL }, estimate_reason: null, read: { posts: 200, outside_window: 27, capped: true, available: 568 } });
  const prow = { key: "acct:fosstodon.org", what: "Mastodon (fosstodon.org)", canPostActivity: { site: "mastodon", username: "samexample", instance: "fosstodon.org" } };
  const ph = W.postHtml({ ...prow, postActivity: pa });
  ok(pa.state === "ok" && /class="ev-arch ev-pa "/.test(ph) && /data-open-reading="acct:fosstodon\.org"/.test(ph) && /a hint, not a fact, and never a place\./.test(ph) && !/Try again/.test(ph), "post activity: one line on the row and a control that opens the Timeline at the reading");
  const lim = D.postActivityView({ site: "lobsters", username: "samexample", state: "rate_limited", error: "x", error_code: "rate_limited" });
  ok(/class="ev-arch ev-pa unknown"/.test(W.postHtml({ ...prow, postActivity: lim })) && />Try again</.test(W.postHtml({ ...prow, postActivity: lim })) && !/data-open-reading/.test(W.postHtml({ ...prow, postActivity: lim })) && /data-post-activity/.test(evSrc(prow)) && !/data-post-activity/.test(evSrc({ ...prow, postActivity: lim })), "a site that could not be asked is unknown on the row, with Try again in the answer");
  const vh = activityViewHtml(pa);
  ok(/Public posts by hour of day, UTC/.test(vh) && /Kinds of post/.test(vh) && /act-foot/.test(vh) && /a hint, not a fact/.test(vh) && /A range of time offsets is not a place/.test(vh) && !vh.includes("<img") && !/Most active in/.test(vh), "one renderer draws a post reading: unit words, the footnote, the estimate tagged a hint that is not a place");
  ok(activityViewHtml(null) === "" && /act-unknown/.test(activityViewHtml(lim)) && activityHtml(tv.collected.githubActivity || { error: "x" }) !== undefined && /By hour of day, UTC/.test(activityViewHtml(D.activityView({ username: "a", found: true, state: "ok", complete: true, events: 50, window: { first: "2026-09-01T08:16:52Z", last: "2026-11-24T16:14:09Z", days: 85, active_days: 40 }, hours_utc: HOURS, weekdays_utc: [9, 9, 9, 9, 9, 3, 2], types: [], repos: [], estimate: null, estimate_reason: { code: "no_quiet_window" } }))), "and GitHub's reading with the same function");
  const blocks = W.activityBlocks({ own: [{ key: "acct:github", kind: "github", label: "GitHub", heading: "GitHub activity", own: true, note: "", view: pa }], other: [{ key: "acct:lobsters", kind: "post", label: `Lobsters ${EVIL}`, heading: "Lobsters post activity (not the person this case is about)", own: false, note: `Not theirs ${EVIL}`, view: lim }] },
    { verdict: "disagree", text: "GitHub and Mastodon do not fit one range.", caution: D.OFFSETS_NOT_A_PLACE }, activityViewHtml);
  ok(blocks.indexOf("When the GitHub account is active") < blocks.indexOf("account posts") && /class="cp tone-different">not the person this case is about</.test(blocks) && /class="act-other" role="note"/.test(blocks) && !blocks.includes("<img") && /id="actFit"/.test(blocks) && /a hint, not a fact/.test(blocks.split("</div>")[0]) && blocks.includes(D.OFFSETS_NOT_A_PLACE), "readings are blocks, the identity's first, another account's under its pill and note, and the comparison is a tagged hint");
  ok(W.activityBlocks({ own: [], other: [] }, null, activityViewHtml) === "" && !/actFit/.test(W.activityBlocks({ own: [{ key: "k", kind: "github", label: "GitHub", heading: "GitHub activity", own: true, note: "", view: pa }], other: [] }, { verdict: "not_enough_data", text: "", caution: "" }, activityViewHtml)), "no reading, no block; one reading, no comparison");
  // archive diff
  const PURL = "https://keybase.io/samexample";
  const arch = D.readArchive({ state: "ok", count: 3, first: "2019-03-04T05:06:07Z", last: "2024-01-02T03:04:05Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }, { timestamp: "2021-06-01T00:00:00Z" }, { timestamp: "2024-01-02T03:04:05Z" }], distinct_versions: 3 }, PURL);
  const pairs = D.archiveDiffPairs(arch), cap = (ts) => ({ state: "ok", timestamp: ts, asked: ts, exact: true, bytes: 9, truncated: false, title: "t", text_lines: 3, links: 2 });
  const dv = D.archiveDiffView({ url: PURL, state: "ok", from: cap("2021-06-01T00:00:00Z"), to: cap("2024-01-02T03:04:05Z"), removed: { text: [`Old bio ${EVIL}`, "<b>bold</b>"], text_total: 5, links: [{ url: "https://social.example.net/@samold", external: true }, { url: "https://old-site.example.org", external: true }], links_total: 2 }, added: { text: ["S E"], text_total: 1, links: [], links_total: 0 }, complete: false }, { subjects: ["samexample"], secrets: ["samexample"] });
  const drow = { key: "acct:keybase", what: "Keybase", archive: { url: PURL, view: D.archiveView(arch) }, archiveDiffPairs: pairs, archiveDiffUser: "samexample" };
  const form = W.archHtml(drow);
  ok(W.diffCaptures(pairs).length === 3 && (form.match(/<select /g) || []).length === 2 && /<label class="diff-f"><span>Older capture<\/span><select/.test(form) && /<label class="diff-f"><span>Newer capture<\/span><select/.test(form) && /value="2021-06-01T00:00:00Z" selected/.test(form) && /value="2024-01-02T03:04:05Z" selected/.test(form) && />Compare</.test(form) && form.includes(W.DIFF_HINT) && !/data-diff-result/.test(form), "the archive inset offers two labelled selects on the last two captures, one button and the hint");
  ok(W.archHtml({ ...drow, archiveDiffPairs: undefined }).indexOf("ev-diff") < 0 && W.diffHtml({ key: "k", what: "X" }) === "", "no pairs, no form");
  ok(W.diffHint(W.diffCaptures(pairs), "2021-06-01T00:00:00Z", "2024-01-02T03:04:05Z").ok && !W.diffHint(W.diffCaptures(pairs), "2021-06-01T00:00:00Z", "2024-01-02T03:04:05Z").warn && W.diffHint(W.diffCaptures(pairs), "2019-03-04T05:06:07Z", "2024-01-02T03:04:05Z").text === W.DIFF_DISTANT && !W.diffHint(W.diffCaptures(pairs), "2019-03-04T05:06:07Z", "2019-03-04T05:06:07Z").ok, "neighbours are fine, a distant pair is warned about, one capture twice cannot be sent");
  ok(JSON.stringify(W.diffChoice({ ...drow, diffPick: { from: "2019-03-04T05:06:07Z", to: "2021-06-01T00:00:00Z" } })) === '{"from":"2019-03-04T05:06:07Z","to":"2021-06-01T00:00:00Z"}' && W.diffChoice({ ...drow, diffPick: { from: "1999-01-01T00:00:00Z", to: "x" } }).from === "2021-06-01T00:00:00Z", "the selects keep a chosen pair, and only one the archive listed");
  const res = W.archHtml({ ...drow, archiveDiff: dv });
  ok(/data-diff-result/.test(res) && !res.includes("<img") && res.includes("&lt;b&gt;bold&lt;/b&gt;") && res.includes("&lt;img src=x onerror=1&gt;") && /<b>Removed<\/b>/.test(res) && /<b>Added<\/b>/.test(res) && res.includes('<span class="diff-mark" aria-hidden="true">−</span><span class="sr-only">Removed: </span>') && res.includes('<span class="diff-mark" aria-hidden="true">+</span><span class="sr-only">Added: </span>'), "a diff: text from a capture is escaped text, and removed and added carry a word and a mark");
  ok(/class="lk lk-unverified"[^>]*data-link-kind="templated_unverified"|data-link-kind="templated_unverified"/.test(res) && !/href="https:\/\/old-site\.example\.org"/.test(res) && /<span class="ed-prov">address<\/span>old-site\.example\.org/.test(res) && (res.match(/data-link-kind="evidence"/g) || []).length >= 2 && /And 3 more lines/.test(res) && /<details class="diff-cav">/.test(res), "an outside link is an unverified URL, a bare address is text, both captures are evidence links, the rest is counted, the caveats are in a disclosure");
  const failed = D.archiveDiffView(D.readArchiveDiff({ state: "failed", error: "x", error_code: "timeout" }, PURL));
  ok(/class="ev-diffres unknown"/.test(W.archHtml({ ...drow, archiveDiff: failed })) && />Try again</.test(W.archHtml({ ...drow, archiveDiff: failed })) && /unknown/.test(W.archHtml({ ...drow, archiveDiff: failed })) && />Comparing…</.test(W.archHtml({ ...drow, diffBusy: true })), "a comparison that failed is unknown with Try again, and a busy one says so");
  // the suggested steps
  const box = el(), sec = el();
  const step = (id, action) => ({ id, title: `T ${id}`, reason: "r", action });
  W.renderNext(sec, box, { top: [step("commits:acct:codeberg", { kind: "commit-emails", key: "acct:codeberg", label: "Commit emails" }), step("posts:acct:hackernews", { kind: "post-activity", key: "acct:hackernews", label: "Post activity" }), step("diff:acct:keybase", { kind: "archive-diff", key: "acct:keybase", from: "2021-06-01T00:00:00Z", to: "2024-01-02T03:04:05Z", label: "Compare copies" }), step("audit:footprint", { kind: "focus", where: "footprint", label: "Open the view" })], more: [], parked: [], followed: [], note: "" }, { look: new Set(["post:acct:hackernews"]) });
  ok(/data-commit-emails="acct:codeberg"[^>]*>Commit emails</.test(box.innerHTML) && /data-post-activity="acct:hackernews"[^>]*aria-disabled="true">Asking…</.test(box.innerHTML) && /data-archive-diff="acct:keybase" data-from="2021-06-01T00:00:00Z" data-to="2024-01-02T03:04:05Z"[^>]*>Compare copies</.test(box.innerHTML) && /data-next-focus="footprint">Open the view</.test(box.innerHTML), "the three lookups and the footprint view are steps with their own control, busy while in flight");
  // the footprint view
  const fp = W.footprintHtml({ items: [{ id: "a", kind: "k", title: `An address ${EVIL}`, exposed: `Exposed ${EVIL}`, where: [{ label: "Codeberg", url: "https://codeberg.org/samexample", link_kind: "verified_profile" }, { label: `npm ${EVIL}`, check: true }], fix: "Fix it", why: "Because", weight: 9, group: "exposes contact details" }], counts: { ties: 0, contact: 1, other: 0 }, gaps: [`A gap ${EVIL}`] }, { title: "Reduce your footprint", note: "Note.", sum: "1 thing to look at.", statement: "Statement." });
  ok(/<h2 class="fp-h" id="footprintH" tabindex="-1">Reduce your footprint<\/h2><span class="tag">rules, no AI<\/span>/.test(fp) && !fp.includes("<img") && /<span class="ed-prov">exposes contact details<\/span>/.test(fp) && /<dt>Exposed<\/dt>/.test(fp) && /<dt>Seen on<\/dt>/.test(fp) && /<dt>Fix<\/dt>/.test(fp) && /<dt>Why<\/dt>/.test(fp) && /data-link-kind="verified_profile"/.test(fp) && /<span class="ed-prov">check that it is yours<\/span>/.test(fp) && /What this list could not see/.test(fp) && !/<button|<input|<form/.test(fp), "the footprint view: escaped text, a group label, Exposed, Seen on, Fix, Why, the gaps, and no control");
  // the page: the switch, the tab, and what an export leaves out
  const html = fs.readFileSync(new URL("../../static/v2/index.html", import.meta.url), "utf8");
  ok(/<input type="checkbox" role="switch" id="selfSwitch" aria-labelledby="selfSwitchL" aria-describedby="selfSwitchD">/.test(html) && /id="selfSwitchL" for="selfSwitch">This is me</.test(html) && /Your own statement\. Adds a list of ways to reduce your public footprint\. Kept in this browser only\./.test(html) && /id="tabFootprint" data-tab="footprint"[^>]*aria-controls="panelFootprint"[^>]*hidden disabled/.test(html) && /id="panelFootprint" role="tabpanel" aria-labelledby="tabFootprint"/.test(html), "the page has the This is me switch with its description, and a footprint tab that starts hidden");
  ok(EXPORT_STRIP.includes(".selfset") && EXPORT_STRIP.includes(".ev-diff"), "an export leaves out the switch and the comparison form");
  // the Profile sources card
  const lp = { username: "samexample", cached: false, profiles: [{ site: "Launchpad", source: "launchpad", handle: "samexample", url: "https://launchpad.net/~samexample", state: "found", display_name: "Sam Example", note: "not an active account" }, { site: "Mastodon (fosstodon.org)", source: "mastodon_fosstodon_org", handle: "samexample", url: "https://fosstodon.org/@samexample", state: "found", display_name: "Sam Example", note: "moved" }], sources: { launchpad: { site: "Launchpad", state: "found" }, mastodon_fosstodon_org: { site: "Mastodon (fosstodon.org)", state: "found" }, gitea: { site: "Gitea.com", state: "blocked" } } };
  const card = sourceCards.profiles(lp);
  ok(/>1 read</.test(card) && /Not a claimed account/.test(card) && /moved to another instance/.test(card) && /Blocked by site<\/dt><dd>Gitea\.com/.test(card) && /3 of 3 sites were asked/.test(card), "the Profile sources card counts an unclaimed record apart and says a known note in the page's words");
}

console.log(fail ? `${fail} of ${pass + fail} design checks failed` : `${pass}/${pass + fail} design checks passed`);
if (fail) process.exit(1);
