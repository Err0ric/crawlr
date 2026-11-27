// The person a case is about (the investigator's pick), the fuller-name rule, the rule-based
// assessment and next steps, the pivot trail, parked and followed steps, and archived copies.
// Pure functions and the markup they feed. No browser, no network. Names are invented.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };
const J = "../../static/v2/js/";
const { clusterIdentities, standing, readPick } = await import(J + "identity.js");
const { buildEvidence, caseAnalysis, caseMarkdown, aiPayloadFor, aiSignature, tierCounts } = await import(J + "evidence.js");
const A = await import(J + "analysis.js");
const C = await import(J + "casework.js");
const D = await import(J + "deep.js");
const L = await import(J + "links.js");
const { personTimeline } = await import(J + "timeline.js");
const { investigateBrief } = await import(J + "brief.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");
const { identityHead, evWhat, evSrc, renderFacts, renderNext, renderAnalysis, trailHtml, archHtml } = await import(J + "workbench.js");
const { link } = await import(J + "core.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/deep.json", import.meta.url), "utf8"));
const U = fx.cases[0], E = fx.cases[1], H = U.target;
const clone = (v) => JSON.parse(JSON.stringify(v));
const row = (ev, key) => ev.items.find((i) => i.key === key);
const P = (id, o = {}) => ({ id: `acct:${id}`, site: id, url: `https://${id}.example/u/jdoe`, handle: "jdoe", name: "", location: "", links: [], bio: "", ...o });
const PICK = { pick: { members: ["acct:gitlab"], at: 1 } };

// ---- 1. the fuller-name rule, both directions ----------------------------------------------------
{
  // A one-word name beside a full one must not rescue a profile whose full name conflicts.
  const ps = [P("github", { anchor: "github", name: "Sam Example" }), P("insta", { name: "Sam" }), P("gitlab", { name: "Petra Novak" }), P("alias", { name: "NaraKa" })];
  const r = clusterIdentities(ps, { handle: "jdoe" });
  ok(r.byProfile["acct:insta"] === r.primary && standing(ps[2], r, { handle: "jdoe" }).tier === "different", "a full name that conflicts with the identity's full name is a different person, whatever one-word name the identity also carries");
  ok(standing(ps[2], r, { handle: "jdoe" }).against.join() === "Sam Example", "and it says which name it was compared with: the full one");
  ok(standing(ps[3], r, { handle: "jdoe" }).tier === "matches" && !standing(ps[3], r, { handle: "jdoe" }).unsettled, "a one-word alias on the profile's side is still not a conflict");
  // The identity carries a one-word name only: nothing is claimed either way.
  const one = [P("github", { anchor: "github", name: "Sam" }), P("gitlab", { name: "Petra Novak" }), P("strava", { name: "Samuel Example" }), P("x", { name: "S. Example" })];
  const r1 = clusterIdentities(one, { handle: "jdoe" });
  const s1 = standing(one[1], r1, { handle: "jdoe" });
  ok(s1.tier === "matches" && s1.unsettled === true && s1.against.join() === "Sam" && !/does not conflict/.test(s1.why), "against a one-word name an unrelated full name is neither a match nor a conflict: it is marked as not compared");
  ok(!standing(one[2], r1, { handle: "jdoe" }).unsettled && !standing(one[3], r1, { handle: "jdoe" }).unsettled, "a name the one word could be short for (Sam, Samuel; S.) is not marked");
  const ev = buildEvidence({ github: { found: true, name: "Sam", profile_url: "https://github.com/jdoe" }, maigret: { results: [{ site: "Gitlab", url: "https://gitlab.com/jdoe", verified: true, profile: { name: "Petra Novak" } }] } }, "jdoe", "username");
  const gl = row(ev, "acct:gitlab");
  ok(gl.tier === "matches" && gl.unsettled.name === "Petra Novak" && /Check whether this is the person you mean/.test(gl.card.check) && /could not be compared/.test(gl.card.check) && /name not compared/.test(gl.meta), "the row says the name could not be compared, and asks");
  ok(caseAnalysis(ev, { collected: {}, target: "jdoe", type: "username" }).suggestions.top[0].id === "pick:unsettled", "and the first suggestion is to choose who the case is about");
}

// ---- 2. the pick ------------------------------------------------------------------------------------
const auto = buildEvidence(U.collected, H, "username");
const picked = buildEvidence({ ...U.collected, ...PICK }, H, "username");
{
  ok(auto.identity.picked === false && auto.identity.views.find((v) => v.primary).label === "Sam Example" && auto.identity.autoLabel === "Sam Example" && /GitHub's own record/.test(auto.identity.autoWhy), "with no pick the primary identity is the automatic choice, and says why");
  const main = picked.identity.views.find((v) => v.primary);
  ok(picked.identity.picked === true && main.label === "Petra Novak" && main.picked && main.why === "you picked this person" && picked.identity.autoLabel === "Sam Example" && picked.identity.auto !== picked.identity.primary, "a pick makes that cluster primary, and the automatic choice is still named");
  ok(auto.identity.views.map((v) => v.id).join() === picked.identity.views.map((v) => v.id).join() && auto.identity.views.map((v) => v.members.join()).join("|") === picked.identity.views.map((v) => v.members.join()).join("|"), "the clusters themselves are evidence: a pick changes none of them");
  ok(auto.items.length === picked.items.filter((i) => i.tier !== "lead" && i.tier !== "similar").length + auto.items.filter((i) => i.tier === "lead" || i.tier === "similar").length - 0 && auto.items.filter((i) => i.key.startsWith("acct:")).map((i) => i.key).sort().join() === picked.items.filter((i) => i.key.startsWith("acct:")).map((i) => i.key).sort().join(), "nothing is removed: every account row is still there");
  ok(row(auto, "acct:github").tier === "linked" && row(picked, "acct:github").tier === "different" && row(picked, "acct:gitlab").tier === "matches" && row(auto, "acct:gitlab").tier === "different", "every row is filed against the picked person");
  ok(tierCounts(picked.items).linked === 0 && /the profile you picked; nothing else ties it to the target/.test(row(picked, "acct:gitlab").card.why), "the picked profile is not called Linked: a pick is a judgment, not a tie");
  // A profile with no name of its own that a proof ties to the other person goes with that person.
  const hn = row(picked, "acct:hackernews"), ig = row(picked, "acct:instagram");
  ok(hn.tier === "different" && hn.via === "Sam Example" && /It is grouped with Sam Example \(.*Keybase proof/.test(hn.card.check) && ig.tier === "different" && /"Sam" is part of "Sam Example"/.test(ig.card.check), "a profile grouped with another person stands where that person stands, and the row says what groups them");
  const gh = row(picked, "acct:github");
  ok(/^Check whether this account is connected to Petra Novak\. The name on it, "Sam Example", conflicts with "Petra Novak", and no link, picture or proof ties it/.test(gh.card.check) && /GitHub's own record for this handle, and the name on it conflicts with Petra Novak/.test(gh.card.why) && /filed as a different person: check whether this account is connected to Petra Novak/.test(gh.meta), "another person's row carries the check, with why it is thought to be someone else");
  ok(/<span class="ev-relate"><span class="tag warn">Check<\/span>/.test(evWhat(gh)) && !/ev-relate/.test(evWhat(row(picked, "acct:gitlab"))), "the check is drawn on the row with a word, not color alone");
  ok(picked.facts.some((f) => f.k === "Name" && f.v === "Petra Novak") && !picked.facts.some((f) => /Sam Example|Tidepool/.test(f.v)), "What we know is the picked person's, and nobody else's");
  ok(!picked.items.some((i) => i.tier === "lead" && /sam_rides|tidepool/.test(i.what)) && auto.items.some((i) => i.tier === "lead" && i.what === "sam_rides"), "leads come from the picked person's profiles only");
  const tl = personTimeline({ ...U.collected, ...PICK }, H, "username", "2026-11-26").events;
  ok(tl.some((e) => /GitLab account created/.test(e.title)) && !tl.some((e) => /GitHub account created|Mastodon/.test(e.title)), "the timeline is the picked person's");
  const b = investigateBrief({ collected: U.collected, items: picked.items, facts: picked.facts, identity: picked.identity, failed: [], type: "username", target: H });
  // The pick is said in the identity header and as the assessment's headline. The brief does not say it a third time.
  ok(!b.rows.some((r) => /You picked|your pick|automatic choice/.test(r.text)) && /You picked this person as the one this case is about\. That is your judgment, not a finding\./.test(identityHead(picked.identity, "")) && /^Thin\. Filed around Petra Novak, your pick, not the automatic choice \(Sam Example\)\./.test(caseAnalysis(picked, { collected: { ...U.collected, ...PICK }, target: H, type: "username" }).assessment.headline), "the pick is said in the header and as the assessment's headline, and not again in the brief");
  ok(aiSignature({ ...U.collected, ...PICK }, H, "username") !== aiSignature(U.collected, H, "username"), "a report written before a pick is not reused after it");
}
// matched by members, never by position; void when it names nobody or more than one cluster
{
  ok(buildEvidence({ ...U.collected, pick: { members: ["acct:nowhere"] } }, H, "username").identity.picked === false, "a pick that names no cluster of the case falls back to the automatic choice");
  ok(buildEvidence({ ...U.collected, pick: { members: ["acct:gitlab", "acct:github"] } }, H, "username").identity.picked === false, "a pick whose members are in two clusters is void");
  ok(buildEvidence({ ...U.collected, pick: { members: ["acct:gitlab", "acct:gone"] } }, H, "username").identity.picked === true, "a pick survives a member that is no longer there");
  ok(buildEvidence({ ...U.collected, pick: { members: ["acct:lichess"] } }, H, "username").identity.picked === false && auto.identity.views.find((v) => v.id === "unassigned").pickable === false, "the group of profiles with no name is not a person and cannot be picked");
  ok(readPick({ members: ["acct:gitlab", 7, "javascript:x", "acct:gitlab"], at: "x", label: "<b>" }).members.join() === "acct:gitlab" && readPick({ members: [] }) === null && readPick("x") === null && readPick({ members: Array(90).fill(0).map((_, i) => `acct:s${i}`) }).members.length === 40, "a stored pick is read as member ids and nothing else");
  for (const bad0 of [null, 7, "x", [], { members: "acct:gitlab" }, { members: [{}] }]) ok(buildEvidence({ ...U.collected, pick: bad0 }, H, "username").identity.picked === false, `a malformed pick is ignored (${JSON.stringify(bad0)})`);
  // no primary at all: a pick is the only way anyone is chosen
  const np = { maigret: { results: [{ site: "Gitlab", url: "https://gitlab.com/jdoe", verified: true, profile: { name: "Petra Novak" } }, { site: "Strava", url: "https://www.strava.com/athletes/jdoe", verified: true, profile: { name: "Sam Example" } }] } };
  const e0 = buildEvidence(np, "jdoe", "username"), e1 = buildEvidence({ ...np, pick: { members: ["acct:strava"] } }, "jdoe", "username");
  ok(e0.identity.noPrimary && !e0.identity.picked && e1.identity.picked && !e1.identity.noPrimary && e1.identity.autoLabel === "" && row(e1, "acct:gitlab").tier === "different" && row(e0, "acct:gitlab").tier === "matches", "with no automatic choice a pick chooses, and says nobody would be chosen automatically");
  ok(caseAnalysis(e0, { collected: np, target: "jdoe", type: "username" }).suggestions.top[0].id === "pick:none" && !caseAnalysis(e1, { collected: np, target: "jdoe", type: "username" }).suggestions.top.some((s) => s.id.startsWith("pick:")), "an unsettled identity is the first suggestion, until someone is picked");
}
// the header
{
  const h0 = identityHead(auto.identity, ""), h1 = identityHead(picked.identity, "");
  ok(/role="group" aria-label="The person this case is about"/.test(h0) && (h0.match(/data-pick="/g) || []).length === 2 && /aria-pressed="true">Sam Example<span class="who-tag">automatic choice<\/span>/.test(h0) && !/data-pick-auto/.test(h0) && /Primary identity, chosen automatically because it holds GitHub&#39;s own record/.test(h0), "the header says the choice is automatic, and each person is a button with a pressed state");
  ok(/>Your pick<\/span>/.test(h1) && !/tone-linked">Primary identity/.test(h1) && /aria-pressed="true">Petra Novak</.test(h1) && /data-pick-auto>Back to the automatic choice</.test(h1) && /You picked this person as the one this case is about\. That is your judgment, not a finding\./.test(h1) && /The automatic choice would be Sam Example, because it holds GitHub&#39;s own record for this handle\./.test(h1), "a pick is labelled as the investigator's, never in the color of a confirmed tie, with one click back");
  const fileEv = buildEvidence({ ...U.collected, pick: { members: ["acct:gitlab"], file: true } }, H, "username");
  ok(fileEv.identity.pickFile && /The case file you opened picked this person/.test(identityHead(fileEv.identity, "")) && !/You picked/.test(identityHead(fileEv.identity, "")), "a pick that came with a case file is not called yours");
}

// ---- 3. how each fact is known ------------------------------------------------------------------------
{
  const f = (k) => auto.facts.find((x) => x.k === k);
  ok(f("Name").how.agree === 5 && f("Name").how.kinds.join() === "self,tool" && /the same on 5 sites \(GitHub, /.test(f("Name").how.text), "a fact says how many of the identity's profiles say the same");
  ok(f("Active since").how.kinds.join() === "record" && f("Active since").how.prov === "site record" && f("Active since").how.text === "the site's own record" && f("Employer").how.prov === "self-declared" && f("Employer").how.text === "written by the account holder", "a join date is the site's record; a name or an employer is self-declared");
  ok(auto.facts.every((x) => !("pid" in x) && !("basis" in x)), "the bookkeeping does not leak into the fact");
  const e = { innerHTML: "" }; renderFacts(e, [f("Name")]);
  ok(/<span class="how"><span class="ed-prov">self-declared and tool report<\/span>the same on 5 sites/.test(e.innerHTML), "and the panel shows it under the value");
  ok(A.factHow({ kinds: [] }) === null && A.factHow({ kinds: ["tool"], sites: 1 }).text === "read from the page by a tool" && /joined by its name only/.test(A.factHow({ kinds: ["self"], weak: true }).text), "a tool report says so, and a fact from a profile joined by name only says that too");
}

// ---- 4. what the evidence says ------------------------------------------------------------------------------
const an = (ev, c, t = H, ty = "username", failed = []) => caseAnalysis(ev, { collected: c, target: t, type: ty, failed });
{
  const a = an(auto, U.collected).assessment;
  ok(a.strength === "strong" && /^Strong\. 4 accounts are tied into one identity/.test(a.headline) && a.mode === "auto", "four accounts tied by proofs, a picture and links is strong");
  ok(a.ties.find((t) => t.kind === "proof").n === 3 && a.ties.find((t) => t.kind === "picture").n === 3 && a.ties[0].kind === "record" && /supporting and not proof/.test(a.ties.find((t) => t.kind === "name").text), "the ties are counted by kind: the record, proofs, the picture, and names as support only");
  const text = a.lines.map((l) => l.text).join("\n");
  ok(/Name "Sam Example" is the same on 5 profiles/.test(text) && /Website .* self-declared, so they agree with each other and prove nothing more/.test(text), "it says what corroborates what, and that self-declared values only agree with each other");
  ok(a.lines.some((l) => l.level === "flag" && /1 account belongs to another person whose name conflicts with Sam Example: Petra Novak \(GitLab\)\. Nothing is removed\./.test(l.text)), "it says who else is under the handle, and that nothing was removed");
  ok(/Self-declared only: .*employer/.test(text) && /Could not be asked: Chess\.com \(rate limited\), Codeforces \(failed\), Lobsters \(blocked by site\), Twitch \(blocked the check\)\. Each is unknown, not absent\./.test(text) && /9 of 20 accounts were only reported by a tool and never read \(45% of the footprint\)/.test(text), "what is self-declared only, what could not be asked, and how much is unread");
  const p = an(picked, { ...U.collected, ...PICK }).assessment;
  ok(p.strength === "thin" && p.mode === "picked" && /^Thin\. Filed around Petra Novak, your pick, not the automatic choice \(Sam Example\)\. The identity rests on your pick\. No link, picture, proof or record ties these profiles to the target\./.test(p.headline) && p.lines.some((l) => /7 accounts belong to another person .*Sam Example \(GitHub, Hacker News, Instagram, Strava and 3 more\)/.test(l.text)), "a pick that rests on one profile is thin, and says so");
  const e = an(buildEvidence(E.collected, E.target, "email"), E.collected, E.target, "email").assessment;
  ok(e.strength === "strong" && /3 records tie this address to an account or a key/.test(e.headline) && e.ties.some((t) => /GitHub attributes commits with this address to mara-lind/.test(t.text)) && e.ties.some((t) => t.kind === "tool" && /sign-up checks/.test(t.text)), "an email case counts records: Gravatar, the commit attribution, the key; sign-up checks are tool reports");
  ok(an(buildEvidence({ github: { found: true, name: "Sam Example", profile_url: "https://github.com/jdoe" } }, "jdoe", "username"), {}).assessment.strength === "thin" && an(buildEvidence({}, "jdoe", "username"), {}).assessment.strength === "none" && an({ items: [], identity: { views: [] }, type: "hash" }, {}, "x", "hash").assessment.headline === "", "one record alone is thin, nothing is none, and other kinds of case get no assessment");
  ok(an(auto, U.collected, H, "username", ["GitHub details"]).assessment.lines.some((l) => /Could not be asked: GitHub details \(failed\)/.test(l.text)), "a failed source is among what could not be asked");
  const s = { hidden: true }, bd = { innerHTML: "" }; renderAnalysis(s, bd, a);
  ok(!s.hidden && /<span class="tag ok">Strong<\/span>/.test(bd.innerHTML) && /<span class="tag warn">Check<\/span>/.test(bd.innerHTML), "the strength and each line carry a word");
}

// ---- 5. suggested next steps ----------------------------------------------------------------------------------
{
  const s = an(auto, U.collected).suggestions, all = [...s.top, ...s.more];
  ok(s.top.length === A.SUGGEST_CAP && s.more.length > 0 && all.every((x, i) => !i || all[i - 1].score >= x.score), "ranked by score, six shown and the rest behind a disclosure");
  ok(s.top[0].id === "lead:handle:sam_rides" && s.top[0].action.kind === "pivot" && s.top[0].action.pivot === "investigate" && s.top[0].action.type === "username" && /the handle sam_rides/.test(s.top[0].action.via), "a handle a tied profile lists comes first, as one click that opens one case");
  const by = (re) => all.find((x) => re.test(x.id));
  ok(by(/^lead:domain:samexample\.example/).action.pivot === "recon" && by(/^archive:acct:mastodon/).action.kind === "archive" && by(/^check:two/).action.tier === "unverified" && by(/^open:acct:twitch/).action.link_kind === "templated_unverified" && by(/^similar:/).action.kind === "jump" && by(/^rerun:/).action.kind === "rerun" && by(/^pick:others/).action.kind === "focus", "each kind of step has the one control that does it");
  ok(/Chess\.com was rate limited/.test(by(/^rerun:/).reason) && /unknown, not absent/.test(by(/^open:/).reason), "a rate limit and a blocked site are said as unknown");
  // reverse confirm: text to copy, never a link
  const rc = by(/^search:/);
  ok(rc.action.kind === "copy" && rc.action.text === '"samexample.example" -site:samexample.example' && !("url" in rc.action) && /copied as text/.test(rc.reason), "a reverse-confirm search is offered as text to copy, never as a link");
  const sec = { hidden: true }, bd = { innerHTML: "" }; renderNext(sec, bd, s);
  const hrefs = [...bd.innerHTML.matchAll(/href="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, "&"));
  ok(hrefs.length === 1 && hrefs[0] === `https://www.twitch.tv/${H}` && hrefs.every((u) => !new URL(u).search) && /data-link-kind="templated_unverified"/.test(bd.innerHTML), "the only link in the list is a page to open by hand, with its kind, and no address carries a query");
  ok(!/google|bing|duckduckgo/i.test(bd.innerHTML) && /data-next-copy="&quot;samexample\.example&quot; -site:samexample\.example"/.test(bd.innerHTML) && /<code class="next-q">/.test(bd.innerHTML), "no search engine address is built anywhere in the list");
  ok((bd.innerHTML.match(/data-step-park=/g) || []).length === all.length && /<details class="next-more" ><summary>\d+ more suggestions?<\/summary>/.test(bd.innerHTML) && /data-confirm-run="1"/.test(bd.innerHTML), "every step can be parked, and a pivot asks before it ends a run in flight");
  // never: adult or dating sites, people-search sites, data brokers
  const text = JSON.stringify(an(buildEvidence(fxAdult().collected, fxAdult().target, "username"), fxAdult().collected, fxAdult().target).suggestions);
  ok(!/adult|dating|onlyfans|pornhub|tinder|spokeo|whitepages|beenverified|pipl|truepeople|intelius|radaris/i.test(text), "nothing adult, and no people-search site or data broker, is ever suggested");
  // a case the minor guard stopped
  const blocked = an(auto, { ...U.collected, adultBlock: { kind: "age", source: "Instagram", snippet: "16", url: "" } }).suggestions;
  ok(blocked.top.length === 0 && blocked.more.length === 0 && /No next steps are suggested/.test(blocked.note), "nothing is suggested for a case the minor guard stopped");
  ok(an(buildEvidence({}, "emma_15yo", "username"), {}, "emma_15yo").suggestions.note !== "" && an(auto, { ...U.collected, adultBlock: { kind: "fresh" } }).suggestions.top.length > 0, "nor for a handle that states an age under 18; a run that only needs repeating is not that");
  const lead = clone(U.collected); lead.profiles.profiles.find((p) => p.source === "mastodon").accounts.push({ site: "X", handle: "kid_14yo", url: "https://x.com/kid_14yo", proof: "listed" });
  ok(!JSON.stringify(an(buildEvidence(lead, H, "username"), lead).suggestions).includes("kid_14yo"), "a handle the guard would refuse is never offered as a lead");
  // an email case
  const ee = buildEvidence(E.collected, E.target, "email"), es = an(ee, E.collected, E.target, "email").suggestions, eall = [...es.top, ...es.more];
  ok(es.top[0].id === "lead:handle:mara-lind" && es.top[0].score === 95 && /GitHub's own record, and the strongest lead/.test(es.top[0].reason), "the account GitHub attributes commits to is the first step of an email case");
  ok(eall.find((x) => x.id === "lead:handle:tidepool-lab").score < eall.find((x) => x.id === "lead:handle:maralind").score && /profile was not read to confirm it/.test(eall.find((x) => x.id === "lead:handle:tidepool-lab").reason) && eall.find((x) => x.id === "lead:handle:mara").score === 45, "a search match and the part before the @ rank below it, and say why they are weaker");
  const audit = eall.find((x) => x.id === "audit:breaches");
  ok(audit.tag === "self-audit" && audit.action === null && /^If this is your address/.test(audit.title) && /two-step sign-in/.test(audit.reason), "a self-audit hint says what the account holder could do, and is no action of the tool");
  const ce = clone(U.collected); ce.githubDeep.commit_emails = [{ email: "sam@old.example", repo: "samexample/tilecut" }];
  const ca = [...an(buildEvidence(ce, H, "username"), ce).suggestions.top, ...an(buildEvidence(ce, H, "username"), ce).suggestions.more].find((x) => x.id === "audit:commit-email");
  ok(ca && /Keep my email addresses private/.test(ca.reason) && ca.action === null, "an exposed commit email comes with GitHub's own setting that hides it");
  ok(an({ items: [], identity: { views: [] }, type: "phone" }, {}, "+15551234567", "phone").suggestions.top.length === 0, "other kinds of case get no suggestions");
}
function fxAdult() { return JSON.parse(fs.readFileSync(new URL("./fixtures/adult.json", import.meta.url), "utf8")); }

// ---- 6. parked and followed --------------------------------------------------------------------------------------
{
  const steps = C.setStep(C.setStep({}, "lead:handle:sam_rides", "parked", "Investigate sam_rides"), "lead:domain:samexample.example", "followed", "Open samexample.example in Recon");
  const c = { ...U.collected, nextSteps: steps }, s = an(buildEvidence(c, H, "username"), c).suggestions;
  ok(![...s.top, ...s.more].some((x) => /sam_rides|lead:domain:samexample/.test(x.id)) && s.parked.length === 1 && s.parked[0].title === "Investigate sam_rides" && s.followed.length === 1, "a parked or followed step is not suggested again, and stays listed");
  ok(Object.keys(C.setStep(steps, "lead:handle:sam_rides", "")).join() === "lead:domain:samexample.example", "bringing one back removes the mark");
  const sec = { hidden: true }, bd = { innerHTML: "" }; renderNext(sec, bd, s);
  ok(/<details class="next-more next-held" ><summary>1 followed, 1 parked<\/summary>/.test(bd.innerHTML) && /data-step-back="lead:handle:sam_rides"/.test(bd.innerHTML) && !/data-step-back="lead:domain/.test(bd.innerHTML), "parked steps can be brought back; a followed one is a record");
  ok(Object.keys(C.readSteps({ "lead:handle:x": { state: "parked", title: "t".repeat(400), at: 1 }, bad: { state: "parked" }, "lead:handle:y": { state: "done" }, "lead:handle:z": "parked" })).join() === "lead:handle:x" && C.readSteps({ "lead:handle:x": { state: "parked", title: "t".repeat(400) } })["lead:handle:x"].title.length === 160 && Object.keys(C.readSteps([1])).length === 0, "stored steps are read defensively");
  const lead = buildEvidence(c, H, "username").items.find((i) => i.key === "lead:handle:sam_rides");
  ok(/data-step-park="lead:handle:sam_rides"/.test(evSrc(lead)) && /data-step-back=/.test(evSrc({ ...lead, step: "parked" })) && /<span class="tag">parked<\/span>/.test(evSrc({ ...lead, step: "parked" })) && !/data-step-/.test(evSrc({ ...lead, step: "followed" })) && /data-via="the handle sam_rides"/.test(evSrc(lead)) && /data-step="lead:handle:sam_rides"/.test(evSrc(lead)), "a lead row can be parked too, and its button says where the trail came from");
}

// ---- 7. the pivot trail -------------------------------------------------------------------------------------------
{
  const t1 = C.extendTrail({ target: "mara@tidepool.example", type: "email", id: "1795_abcde", at: 1700000000000 }, { label: "the GitHub login mara-lind", source: "GitHub's commit attribution for this address" });
  const t2 = C.extendTrail({ target: "mara-lind", type: "username", id: "1796_fghij", at: 1700000001000, trail: t1 }, { label: "the domain tidepool.example", source: "GitHub website field" });
  ok(t1.length === 1 && t2.length === 2 && t2[0].target === "mara@tidepool.example" && t2[1].via === "the domain tidepool.example", "each hop adds the case it left, the lead that was followed and where it was found");
  const v = C.trailView(t2, "tidepool.example", "domain");
  ok(v.length === 3 && v[2].here && v[0].type_word === "email address" && v[0].via === "the GitHub login mara-lind, from GitHub's commit attribution for this address" && C.trailText(v) === "mara@tidepool.example (email address), then the GitHub login mara-lind, from GitHub's commit attribution for this address > mara-lind (username), then the domain tidepool.example, from GitHub website field > tidepool.example (this case)", "the trail reads seed, lead, this case");
  const html = trailHtml(v, (id) => id === "1795_abcde");
  ok(/<ol class="trail-list">/.test(html) && (html.match(/<li/g) || []).length === 3 && /data-open-case="1795_abcde"/.test(html) && !/data-open-case="1796_fghij"/.test(html) && /<li aria-current="step">/.test(html), "the trail is a list; a step still in History is a button, one that is gone is text");
  ok(C.trailView([], "x", "username").length === 0 && trailHtml([]) === "", "a case that was typed has no trail");
  let long = []; for (let i = 0; i < 20; i++) long = C.extendTrail({ target: `h${i}`, type: "username", trail: long }, {});
  ok(long.length === C.TRAIL_MAX && long[0].target === "h8", "the trail is bounded, oldest steps first to go");
  const hostile = C.readTrail([{ target: "a\u0000b<img>", type: "username", id: "../x", at: -1, via: "v".repeat(900), source: 7 }, { target: "", type: "username" }, { target: "x", type: "kitten" }, "str", null]);
  ok(hostile.length === 1 && hostile[0].id === "" && hostile[0].at === 0 && hostile[0].via.length === 160 && hostile[0].source === "" && !/[\u0000-\u001f]/.test(hostile[0].target) && C.readTrail("x").length === 0, "a stored trail is read defensively");
  ok(/&lt;img&gt;/.test(trailHtml(C.trailView(hostile, "y", "username"))) && !/<img/.test(trailHtml(C.trailView(hostile, "y", "username"))), "and its text is escaped");
}

// ---- 8. archived copies ----------------------------------------------------------------------------------------------
const MURL = `https://mastodon.social/@${H}`;
const ANSWER = { url: MURL, state: "ok", count: 212, first: "2017-04-11T09:30:12Z", last: "2026-11-20T04:05:12Z", distinct_versions: 41, truncated: false, snapshots: [{ timestamp: "2017-04-11T09:30:12Z", url: `https://web.archive.org/web/20170411093012/${MURL}` }, { timestamp: "2026-11-20T04:05:12Z", url: "https://evil.example/web/20261120040512/x" }] };
{
  ok(row(auto, "acct:mastodon.social").archive.url === MURL && !row(auto, "acct:mastodon.social").archive.view && /data-archive="acct:mastodon\.social"/.test(evSrc(row(auto, "acct:mastodon.social"))), "a read profile offers the lookup, on a click");
  ok(!row(auto, "acct:hackernews").archive && L.ownProfileQuery(row(auto, "acct:hackernews").url) === H && !D.archivable(`https://news.ycombinator.com/user?id=${H}`), "a profile address that carries a query is never looked up: the snapshot address would carry it");
  ok(auto.items.filter((i) => i.archive).every((i) => i.key.startsWith("acct:") && i.link_kind === "verified_profile" && i.tier !== "unverified" && i.tier !== "adult") && !auto.items.some((i) => i.tier === "unverified" && i.archive), "only a profile a source read, never a reported row");
  ok(!D.archivable("https://onlyfans.com/x") && !D.archivable("https://user:pw@example.org/a") && !D.archivable("https://example.org:8443/a") && !D.archivable("https://example.org/") && !D.archivable("https://example.org/a*") && !D.archivable("ftp://example.org/a") && D.archivable("https://example.org/a"), "never an adult or dating site, credentials, a port, a bare homepage or a wildcard");
  const a = D.readArchive(ANSWER, MURL), v = D.archiveView(a);
  ok(a.snapshots.length === 2 && a.snapshots.every((s) => s.url.startsWith("https://web.archive.org/web/") && s.url.endsWith(MURL)) && a.snapshots[1].url === `https://web.archive.org/web/20261120040512/${MURL}`, "a snapshot address is rebuilt from its timestamp and the profile address, whatever the answer says");
  ok(/captured on 212 days, first on 2017-04-11 and last on 2026-11-20, in 41 different versions/.test(v.text) && !/212 captures|212 copies/.test(v.text) && v.snapshots.every((s) => s.link_kind === "evidence"), "the count is said as days with a capture");
  ok(JSON.stringify(D.readArchive(a, MURL)) === JSON.stringify(a) && D.readArchives(D.readArchives({ "acct:mastodon.social": a }))["acct:mastodon.social"].count === 212, "reading its own output changes nothing");
  const none = D.archiveView(D.readArchive({ state: "none", note: D.ARCHIVE_NONE_NOTE }, MURL)), lim = D.archiveView(D.readArchive({ state: "rate_limited", error: "x", error_code: "rate_limited" }, MURL)), fail = D.archiveView(D.readArchive({ state: "failed", error: "<b>x</b>" }, MURL)), ref = D.archiveView(D.readArchive({ state: "refused", note: D.ARCHIVE_REFUSALS[0] }, MURL));
  ok(/answered and holds no copy of this page\. The archive holds no capture of the page itself\. Captures that were a redirect or an error are not counted/.test(none.text) && !none.retry, "none is an answer, with the archive's own caveat");
  ok(/rate limiting requests, so whether it holds copies is unknown/.test(lim.text) && lim.retry && /could not be asked, so whether it holds copies is unknown/.test(fail.text) && fail.retry && !/<b>/.test(fail.text), "rate limited and failed are unknown, never no copies, and can be asked again");
  ok(/^Not looked up\. CrawlR does not look up archived copies of pages on adult or dating sites\.$/.test(ref.text) && D.archiveView(D.readArchive({ state: "refused", note: "<script>" }, MURL)).text === "Not looked up. This address was not looked up." && D.readArchive({ state: "none", note: "anything else" }, MURL).note === undefined, "a refusal says why, in CrawlR's own sentences only");
  ok(D.readArchive({ state: "ok", count: 3, first: "x", last: "y", snapshots: [] }, MURL).state === "failed" && D.readArchive({ state: "kitten" }, MURL) === null && D.readArchive(ANSWER, "https://onlyfans.com/x") === null && D.readArchive(ANSWER, `https://news.ycombinator.com/user?id=${H}`) === null, "an answer that shows nothing is unknown, and nothing is kept for an address that may not be looked up");
  ok(Object.keys(D.readArchives({ "acct:mastodon.social": ANSWER, "lead:x": ANSWER, "acct:evil": { ...ANSWER, url: "javascript:alert(1)" }, "acct:n": 7 })).join() === "acct:mastodon.social", "stored answers are kept only under an account row, for an address that may be looked up");
  // on the row, the timeline and the export
  const c = { ...U.collected, archives: { "acct:mastodon.social": a, "acct:github": { ...a, url: "https://example.org/other" } } }, ev = buildEvidence(c, H, "username"), r = row(ev, "acct:mastodon.social");
  ok(r.archive.view.state === "ok" && !row(ev, "acct:github").archive.view && !/data-archive=/.test(evSrc(r)), "an answer is shown on its row only when it is for that row's address, and the button is gone");
  const html = archHtml(r), hs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
  ok(hs.length === 2 && hs.every((u) => u.startsWith("https://web.archive.org/web/") && !new URL(u).search && !L.isBareHome(u, [H])) && (html.match(/data-link-kind="evidence"/g) || []).length === 2 && (html.match(/rel="noopener noreferrer nofollow"/g) || []).length === 2 && evWhat(r).includes(html), "each snapshot is an evidence link opened by hand, with no query in it");
  ok(/class="ev-arch unknown"/.test(archHtml({ archive: { view: lim } })) && /Try again/.test(evSrc({ ...r, archive: { url: MURL, view: lim } })) && /class="ev-arch "/.test(archHtml({ archive: { view: none } })), "an archive that could not be asked is drawn as unknown, with Try again");
  const tl = personTimeline(c, H, "username", "2026-11-26").events, first = tl.find((e) => e.title === "Mastodon profile first archived");
  ok(first && first.date === "2017-04-11" && first.basis === "archive" && first.basis_text === "archive record" && first.source === "Internet Archive" && first.link_kind === "evidence" && first.url === a.snapshots[0].url && /The account may be older/.test(first.detail), "the first capture is on the timeline as the archive's record");
  ok(!personTimeline({ ...c, ...PICK }, H, "username", "2026-11-26").events.some((e) => /first archived/.test(e.title)), "and not on the timeline of a person the profile does not belong to");
  const md = caseMarkdown({ collected: c, target: H, type: "username" });
  ok(/  - Archived copies: The Internet Archive holds copies of this page captured on 212 days.* Snapshots: \[2017-04-11\]\(https:\/\/web\.archive\.org\/web\/20170411093012\/https:\/\/mastodon\.social\/@samexample\)/.test(md), "the export carries the answer and the snapshot links");
  ok(![...an(ev, c).suggestions.top, ...an(ev, c).suggestions.more].some((x) => x.id === "archive:acct:mastodon.social"), "a profile that was asked about is not suggested again");
}

// ---- 9. exports, the AI payload and case files -------------------------------------------------------------------------
{
  const trail = C.extendTrail({ target: "mara@tidepool.example", type: "email", id: "1795_abcde", at: 1 }, { label: "the handle samexample", source: "Gravatar username" });
  const c = { ...U.collected, ...PICK, trail, nextSteps: C.setStep({}, "lead:handle:sam_rides", "parked", "Investigate sam_rides") };
  const md = caseMarkdown({ collected: c, target: H, type: "username" });
  ok(/## How this case was reached\n_Each step was a click by the investigator/.test(md) && /1\. \*\*mara@tidepool\.example\*\* \(email address\): followed the handle samexample, from Gravatar username\n2\. \*\*samexample\*\* \(this case\)/.test(md), "the export has the trail");
  ok(/## What we know \(primary identity: Petra Novak, from GitLab\)\n_The primary identity was picked by the investigator\. That is a judgment, not a finding\. The automatic choice would be Sam Example, because it holds GitHub's own record for this handle\._/.test(md), "the export says the identity was picked, and what the automatic choice was");
  ok(/- \*\*Location:\*\* .*Brno.* _\(GitLab · self-declared · written by the account holder\)_/.test(md) && /## What the evidence says\n_Built from rules, with no model involved\._\n- \*\*How firmly the accounts are tied to one identity:\*\* Thin\./.test(md) && /## Suggested next steps\n_Ranked by rules\./.test(md) && /## Parked leads\n- Investigate sam_rides \(parked by the investigator\)/.test(md), "and each fact's provenance, the assessment, the suggestions and what was parked");
  ok(/## Other people using this handle\n_Not removed from the case\. Check whether each is connected/.test(md) && /filed as a different person: check whether this account is connected to Petra Novak/.test(md), "other people stay in the export, with the check");
  ok(/_The primary identity was chosen automatically because it holds GitHub's own record for this handle\._/.test(caseMarkdown({ collected: U.collected, target: H, type: "username" })), "an automatic choice is said to be one");
  const ai = aiPayloadFor(c, H, "username", { source_status: { "GitHub details": "failed: timeout" } }).case_analysis;
  ok(ai.identity_choice.mode === "picked_by_investigator" && ai.identity_choice.primary === "Petra Novak" && ai.identity_choice.automatic_choice === "Sam Example" && /GitHub's own record/.test(ai.identity_choice.automatic_reason) && /their judgment, not a finding/.test(ai.identity_choice.note), "the model is told the identity was picked by the investigator, and what the automatic choice would have been");
  ok(ai.strength === "thin" && /^Thin\./.test(ai.headline) && ai.lines.some((l) => /^CHECK: 7 accounts/.test(l)) && ai.lines.some((l) => /GitHub details \(failed\)/.test(l)) && /mara@tidepool\.example \(email address\).*samexample \(this case\)/.test(ai.pivot_trail), "and it gets the assessment and the trail to start from");
  const a0 = aiPayloadFor(U.collected, H, "username").case_analysis;
  ok(a0.identity_choice.mode === "automatic" && !("pivot_trail" in a0) && !("case_analysis" in aiPayloadFor({ hash: { hash: "44d88612fea8a8f36de82e1278abb02f", verdict: "TEST_FILE" } }, "44d88612fea8a8f36de82e1278abb02f", "hash")), "an automatic choice is told as that, and other kinds of case carry no analysis");
  ok(aiPayloadFor(c, H, "username").accounts.find((x) => x.site === "GitHub").status === "different" && aiPayloadFor(c, H, "username").profile_sources.profiles.find((p) => p.site === "GitLab").status === "matches", "account statuses in the payload are filed against the pick");
  // a case file: the pick travels, marked as the file's; hostile values are dropped
  const file = (collected) => parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: H, type: "username", ran: 1700000000000, collected, ai: null, deep: null, notes: "", purpose: "" })));
  const back = file({ ...c, archives: { "acct:mastodon.social": D.readArchive(ANSWER, MURL) } });
  ok(back.ok && back.entry.results.pick.members.join() === "acct:gitlab" && back.entry.results.pick.file === true && back.entry.results.trail.length === 1 && back.entry.results.trail[0].file === true && !("nextSteps" in back.entry.results) && back.entry.results.archives["acct:mastodon.social"].count === 212, "a case file carries the pick, the trail and the archive answers, each marked as the file's; parked and followed steps are not imported, so a file cannot hide a suggestion");
  ok(buildEvidence(back.entry.results, H, "username").identity.pickFile === true, "and the pick is shown as the file's, not as yours");
  const hostile = file({ ...U.collected, pick: { members: "acct:gitlab" }, trail: { 0: "x" }, nextSteps: [1, 2], archives: { "acct:mastodon.social": { url: "javascript:alert(1)", state: "ok" } } });
  ok(hostile.ok && !("pick" in hostile.entry.results) && !("trail" in hostile.entry.results) && !("nextSteps" in hostile.entry.results) && Object.keys(hostile.entry.results.archives || {}).length === 0 && buildEvidence(hostile.entry.results, H, "username").identity.picked === false, "values that cannot be read are dropped, and the case falls back to the automatic choice");
  ok(!file({ pick: { members: ["acct:gitlab"] }, trail }).ok, "a file with a pick and a trail and no results is still refused");
  ok(JSON.stringify(C.readCasework(C.readCasework(c))) === JSON.stringify(C.readCasework(c)) && C.CASEWORK_KEYS.join() === "pick,trail,nextSteps,archives,selfAudit,commitEmails,postActivity,archiveDiffs", "reading the investigator's work twice changes nothing");
}

// ---- 9b. "This is me": the investigator's statement, kept in the browser only ----------------------------------------
{
  const { storedCase } = await import(J + "evidence.js");
  const NOW = 1700000000000;
  ok(JSON.stringify(C.readSelfAudit({ on: true, at: NOW, by: "x", note: "<b>" })) === JSON.stringify({ on: true, at: NOW }) && C.readSelfAudit({ on: true }).at === 0 && C.readSelfAudit({ on: true, at: "soon" }).at === 0 && C.readSelfAudit({ on: true, at: Date.now() + 9e9 }).at === 0, "the statement is read into its two checked fields");
  ok([{ on: "true" }, { on: 1 }, { on: false, at: NOW }, {}, null, "on", true, [{ on: true }], 7].every((v) => C.readSelfAudit(v) === null), "only the literal on: true counts");
  ok(C.selfAuditOn({ selfAudit: { on: true, at: NOW } }) && C.selfAuditOn({ selfAudit: { on: true } }, "username") && C.selfAuditOn({ selfAudit: { on: true } }, "email") && !C.selfAuditOn({ selfAudit: { on: true } }, "hash") && !C.selfAuditOn({ selfAudit: { on: true } }, "phone") && !C.selfAuditOn({ selfAudit: { on: true } }, "name") && !C.selfAuditOn({ selfAudit: { on: 1 } }) && !C.selfAuditOn({}) && !C.selfAuditOn(null) && !C.selfAuditOn("x"), "a case is marked only by a readable statement, and only a username or an email case can be");
  const c = { github: { found: true }, selfAudit: { on: true, at: 5 } }, on = C.setSelfAudit({ github: { found: true } }, true, NOW), off = C.setSelfAudit(on, false, NOW);
  ok(JSON.stringify(on.selfAudit) === JSON.stringify({ on: true, at: NOW }) && on.github.found === true && !("selfAudit" in off) && off.github.found === true && JSON.stringify(c.selfAudit) === JSON.stringify({ on: true, at: 5 }) && !("selfAudit" in C.setSelfAudit(c, "yes")) && JSON.stringify(C.setSelfAudit(null, true, NOW)) === JSON.stringify({ selfAudit: { on: true, at: NOW } }) && C.setSelfAudit({}, true).selfAudit.at > 0, "setting and taking back the statement returns a new case and leaves the old one alone");
  ok(JSON.stringify(C.readCasework({ selfAudit: { on: true, at: NOW, x: 1 } }).selfAudit) === JSON.stringify({ on: true, at: NOW }) && !("selfAudit" in C.readCasework({ selfAudit: { on: "yes" } })) && !("selfAudit" in C.readCasework({ selfAudit: { on: true, at: NOW } }, { file: true })), "History keeps the checked statement; a case file never brings one");
  // A file as somebody else could write it: Export itself leaves the statement out (casefile.test.mjs).
  const file = (collected) => parseCaseFile(JSON.stringify({ ...buildCaseFile({ mode: "investigate", target: H, type: "username", ran: NOW, collected: {}, ai: null, deep: null, notes: "", purpose: "" }), collected }));
  const back = file({ ...U.collected, selfAudit: { on: true, at: NOW }, nextSteps: { "audit:footprint": { state: "parked", title: "x", at: 1 } } });
  ok(back.ok && !("selfAudit" in back.entry.results) && !("nextSteps" in back.entry.results) && !C.selfAuditOn(back.entry.results) && !file({ selfAudit: { on: true, at: NOW } }).ok, "a case file cannot say This is me for the person who opens it, and the statement alone is no result");
  ok(JSON.stringify(storedCase({ ...U.collected, selfAudit: { on: true, at: NOW } }).selfAudit) === JSON.stringify({ on: true, at: NOW }), "the statement is kept with the case in History");
  // the answers of the lookups made on a click travel through their readers, in History and in a case file
  const CEA = { site: "gitlab", site_name: "GitLab", username: H, state: "found", handle: H, profile_url: `https://gitlab.com/${H}`, display_name: "", emails: [{ email: "Sam@Example.org", name: "S", how: "author_line_match", commits: 1, repos: [] }], emails_state: "found", complete: true, sections: { account: "found", repos: "ok" }, repos: [], counts: {} };
  const PAA = { site: "hackernews", username: H, state: "not_found", found: false };
  const kept = file({ ...U.collected, commitEmails: { "acct:gitlab": CEA, "acct:x": { site: "nowhere", state: "found" } }, postActivity: { "acct:hackernews": PAA, "acct:y": { site: "mastodon", instance: "evil.example", state: "ok" } }, archiveDiffs: { "acct:keybase": { url: "javascript:alert(1)", state: "ok" } } });
  ok(kept.ok && Object.keys(kept.entry.results.commitEmails).join() === "acct:gitlab" && kept.entry.results.commitEmails["acct:gitlab"].emails[0].email === "sam@example.org" && Object.keys(kept.entry.results.postActivity).join() === "acct:hackernews" && Object.keys(kept.entry.results.archiveDiffs || {}).length === 0 && !file({ commitEmails: { "acct:gitlab": CEA }, postActivity: { "acct:hackernews": PAA } }).ok, "commit emails, post activity and archive diffs in a case file are read like fresh answers, and alone they are not a case");
}

// ---- 10. name cases are left alone ------------------------------------------------------------------------------------------
{
  const nm = JSON.parse(fs.readFileSync(new URL("./fixtures/names.json", import.meta.url), "utf8"));
  const c = nm.cases?.[0] || nm, col = c.collected || {}, t = c.target || "Linus Torvalds";
  const e0 = buildEvidence(col, t, "name"), e1 = buildEvidence({ ...col, pick: { members: ["acct:github"] } }, t, "name");
  ok(e1.identity.picked === false && e1.identity.views.length === 0 && JSON.stringify(e0.items.map((i) => [i.key, i.tier])) === JSON.stringify(e1.items.map((i) => [i.key, i.tier])), "a name case has candidates, not clusters: a pick does nothing there");
}

console.log(bad ? `${bad} of ${n} case work checks failed` : `${n}/${n} case work checks passed`);
process.exit(bad ? 1 : 0);
