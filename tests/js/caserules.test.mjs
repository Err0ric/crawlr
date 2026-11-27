// Rules that hold a case together once the investigator has had a say in it, each found broken by a
// review and fixed:
//   a pick carries to every reader of the GitHub data; a pick that came with a case file is never
//   worded as "you"; a redundant pick is no pick; names are compared without calling a fitting
//   name a different person; a search match nobody read is unverified; a lookup that did not
//   answer is never counted as "not found"; stored and imported values are bounded and rebuilt;
//   and what is kept in History is always the cleaned form.
// Pure functions and the markup they feed. No browser, no network. Names are invented.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {}, createElement: () => ({ innerHTML: "" }) };
const J = "../../static/v2/js/";
const { clusterIdentities, standing } = await import(J + "identity.js");
const { buildEvidence, caseAnalysis, caseMarkdown, aiPayloadFor, githubStanding, storedCase, ledgerTiers, tierCounts, accountsFor } = await import(J + "evidence.js");
const A = await import(J + "analysis.js");
const C = await import(J + "casework.js");
const D = await import(J + "deep.js");
const { personTimeline } = await import(J + "timeline.js");
const { investigateBrief } = await import(J + "brief.js");
const { investigateTiles } = await import(J + "present.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");
const { identityHead, renderIdentityFacts, trailHtml, evSrc, evWhat } = await import(J + "workbench.js");
const { sourceTally, sourceCoverage, sourceHasResults, statusForAi, partialGaps, tallyText, detect, reconType } = await import(J + "core.js");
const { sourceCards, activityHtml } = await import(J + "renderers.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/deep.json", import.meta.url), "utf8"));
const U = fx.cases[0], E = fx.cases[1], H = U.target;
const clone = (v) => JSON.parse(JSON.stringify(v));
const row = (ev, key) => ev.items.find((i) => i.key === key);
const PICK = { pick: { members: ["acct:gitlab"], at: 1 } };
const P = (id, o = {}) => ({ id: `acct:${id}`, site: id, url: `https://${id}.example/u/jdoe`, handle: "jdoe", name: "", location: "", links: [], bio: "", ...o });
const briefOf = (c, t, type, ev = buildEvidence(c, t, type), extra = {}) => investigateBrief({ collected: c, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type, target: t, ...extra });
const text = (b) => b.rows.map((r) => r.text).join("\n");
const an = (c, t = H, type = "username", failed = []) => caseAnalysis(buildEvidence(c, t, type), { collected: c, target: t, type, failed });
const says = (c, t, type, failed) => { const a = an(c, t, type, failed).assessment; return [a.headline, ...a.lines.map((l) => l.text)].join("\n"); };
const src = (f) => fs.readFileSync(new URL(`${J}${f}`, import.meta.url), "utf8");

// ---- 1. a pick carries to the GitHub data ---------------------------------------------------------------
{
  const c = { ...U.collected, ...PICK };
  const auto = buildEvidence(U.collected, H, "username"), picked = buildEvidence(c, H, "username");
  ok(githubStanding(auto).own === true && githubStanding(auto).text === "" && row(picked, "acct:github").tier === "different" && githubStanding(picked).own === false, "GitHub's data is the case's own while its account is; after a pick of someone else it is not");
  ok(/which the findings file as a different person \(Sam Example\)\. It is that account's, not Petra Novak's\./.test(githubStanding(picked).text), "and the page has a sentence that says whose account it is");
  ok(/GitHub lists 137 public events/.test(text(briefOf(U.collected, H, "username"))) && !/GitHub lists|UTC offset/.test(text(briefOf(c, H, "username"))), "the brief gives GitHub's activity and offset only while the account is the person the case is about");
  ok(personTimeline(U.collected, H, "username", "2026-11-26").events.some((e) => /public GitHub event/.test(e.title)) && !personTimeline(c, H, "username", "2026-11-26").events.some((e) => /GitHub/.test(e.title)), "the timeline has GitHub's events only then too");
  const md = caseMarkdown({ collected: c, target: H, type: "username" }), md0 = caseMarkdown({ collected: U.collected, target: H, type: "username" });
  ok(/\n## GitHub activity\n/.test(md0) && !/\n## GitHub activity\n/.test(md) && /## GitHub activity \(not the person this case is about\)\n_This is the activity of the GitHub account, which the findings file as a different person/.test(md), "the export keeps the activity and heads it as another person's");
  const ai0 = aiPayloadFor(U.collected, H, "username"), ai = aiPayloadFor(c, H, "username");
  ok(ai0.github && ai0.github_deep && ai0.github_activity && !("github_not_target" in ai0), "with the automatic choice the model gets GitHub's record, details and activity");
  ok(ai.github === null && ai.github_deep === null && !("github_activity" in ai) && ai.github_not_target === "different" && ai.accounts.find((a) => a.site === "GitHub").status === "different", "after the pick it gets none of the three, and is told the account is not the target's");
  const others = new Set(ai.accounts.filter((a) => a.status === "different").map((a) => a.site));
  ok(others.has("Keybase") && ai.profile_sources.profiles.filter((p) => others.has(p.site)).every((p) => Object.keys(p).join() === "site,status") && !(ai.enricher?.profiles || []).some((p) => others.has(p.platform)) && (ai.platform_check?.results || []).filter((r) => others.has(r.platform)).every((r) => !("display_name" in r) && !("bio" in r)), "what was read on the other person's accounts does not travel in the per-site data");
  // Per-site data beside the accounts list: a row filed as a different person keeps its site and state only.
  const mix = { github: { found: true, name: "Sam Example", profile_url: "https://github.com/jdoe" },
    maigret: { results: [{ site: "Medium", url: "https://medium.com/@jdoe", verified: true, profile: { name: "Petra Novak", bio: "Potter in Brno" } }] },
    enricher: { profiles: [{ platform: "Medium", url: "https://medium.com/@jdoe", display_name: "Petra Novak", bio: "Potter in Brno" }, { platform: "Telegram", url: "https://t.me/jdoe", display_name: "Sam E", bio: "maps" }] },
    platformCheck: { results: [{ platform: "Medium", url: "https://medium.com/@jdoe", state: "found", display_name: "Petra Novak", bio: "Potter in Brno" }] } };
  const m = aiPayloadFor(mix, "jdoe", "username", { profileScrape: { results: [{ site: "Medium", url: "https://medium.com/@jdoe", display_name: "Petra Novak", bio: "Potter in Brno" }, { site: "Telegram", url: "https://t.me/jdoe", display_name: "Sam E" }] } });
  ok(m.accounts.find((a) => a.site === "Medium").status === "different" && m.enricher.profiles.map((p) => p.platform).join() === "Telegram" && JSON.stringify(m.platform_check.results) === JSON.stringify([{ platform: "Medium", url: "https://medium.com/@jdoe", state: "found" }]) && !("profile" in m.maigret.results[0]) && m.profile_scrape.results.map((r) => r.site).join() === "Telegram", "what a source read on another person's account is not sent beside the target's: enrichment, platform check, Maigret and a Deep Dive's page reads");
  ok(!/Potter in Brno/.test(JSON.stringify({ ...m, accounts: [] })) && m.github.name === "Sam Example", "and the target's own record still is");
}

// ---- 4. a pick that came with a case file is its author's -------------------------------------------------
{
  const file = (collected, mode = "investigate", target = H, type = "username") => parseCaseFile(JSON.stringify(buildCaseFile({ mode, target, type, ran: 1700000000000, collected, ai: null, deep: null, notes: "", purpose: "" })));
  const steps = C.setStep({}, "lead:handle:sam_rides", "parked", "Investigate sam_rides");
  const trail = C.extendTrail({ target: "mara@tidepool.example", type: "email", id: "a1", at: 1700000000000, trail: [] }, { label: "the handle samexample", source: "GitHub commit attribution" });
  const back = file({ ...U.collected, ...PICK, nextSteps: steps, trail });
  const c = back.entry.results, ev = buildEvidence(c, H, "username"), mine = buildEvidence({ ...U.collected, ...PICK }, H, "username");
  ok(back.ok && ev.identity.picked && ev.identity.pickFile === true && mine.identity.pickFile === false, "a file's pick is marked as the file's");
  const head = identityHead(ev.identity, ""), myHead = identityHead(mine.identity, "");
  ok(/<span class="cp">Picked in the case file<\/span>/.test(head) && !/Your pick|You picked|your pick|Clear my pick/.test(head) && /<span class="cp">Your pick<\/span>/.test(myHead), "the pill says where the pick came from");
  const el = { id: "facts", innerHTML: "" }; renderIdentityFacts(el, ev.identity, () => [], "", "");
  ok(/\(picked in the case file\)/.test(el.innerHTML) && /Picked in the case file: every row is filed against this identity/.test(el.innerHTML) && !/your pick|judgment/i.test(el.innerHTML), "so does What we know, in one short line that does not repeat the whole statement");
  const gl = row(ev, "acct:gitlab"), myGl = row(mine, "acct:gitlab");
  ok(/the profile picked in the case file; nothing else ties it to the target/.test(gl.meta) && /the profile picked in the case file/.test(gl.card.why) && !/you picked/.test(JSON.stringify(ev.items)) && /the profile you picked/.test(myGl.meta), "the row, its card and its export line never say 'you picked' for a file's pick");
  const a = an(c).assessment, mineA = an({ ...U.collected, ...PICK }).assessment;
  ok(/^Thin\. Filed around Petra Novak, the person picked in the case file, not the automatic choice \(Sam Example\)\. The identity rests on that pick\./.test(a.headline) && !/your pick/.test(a.headline) && /your pick/.test(mineA.headline), "the assessment names the pick as the file's");
  const md = caseMarkdown({ collected: c, target: H, type: "username" });
  ok(!/you picked|your pick|You picked/i.test(md) && /picked by the investigator \(in the case file\)/.test(md) && /the person picked in the case file/.test(md), "the Markdown export does too");
  const ai = aiPayloadFor(c, H, "username"), myAi = aiPayloadFor({ ...U.collected, ...PICK }, H, "username");
  ok(ai.case_analysis.identity_choice.mode === "picked_in_case_file" && /picked in the case file the case was opened from/.test(ai.case_analysis.identity_choice.note) && !/you picked|your pick/i.test(JSON.stringify(ai)) && myAi.case_analysis.identity_choice.mode === "picked_by_investigator", "and so is the model, with a mode of its own");
  // the trail
  ok(c.trail.length === 1 && c.trail[0].file === true && C.trailFromFile(C.trailView(c.trail, H, "username")) && !C.trailFromFile(C.trailView(trail, H, "username")), "a file's trail is marked step by step");
  ok(/How this case was reached, according to the case file/.test(trailHtml(C.trailView(c.trail, H, "username"))) && !/How you got here/.test(trailHtml(C.trailView(c.trail, H, "username"))) && /How you got here/.test(trailHtml(C.trailView(trail, H, "username"))), "its heading is never 'How you got here'");
  ok(/As recorded in the case file this case was opened from/.test(md) && !/Each step was a click by the investigator/.test(md) && /^As recorded in the case file this case was opened from: /.test(ai.case_analysis.pivot_trail), "the export and the model are told the trail is the file's");
  ok(C.extendTrail({ target: H, type: "username", id: "b2", at: 1, trail: c.trail }, { label: "the domain samexample.example" }).map((s) => !!s.file).join() === "true,false", "a step added in this browser to a file's trail is not the file's");
  // parked and followed steps do not travel
  ok(!("nextSteps" in c) && an(c).suggestions.parked.length === 0 && [...an(c).suggestions.top, ...an(c).suggestions.more].length === [...an({ ...U.collected, ...PICK }).suggestions.top, ...an({ ...U.collected, ...PICK }).suggestions.more].length, "a case file cannot park or follow a step: every suggestion the case supports is offered again");
  ok(Object.keys(C.readCasework({ nextSteps: steps }).nextSteps).length === 1 && !("nextSteps" in C.readCasework({ nextSteps: steps }, { file: true })), "History keeps the steps; only a file's are dropped");
}

// ---- 5. a search match nobody read is unverified ---------------------------------------------------------
{
  const ee = buildEvidence(E.collected, E.target, "email"), org = row(ee, "acct:github~tidepool-lab");
  ok(org.tier === "unverified" && /Nothing was read/.test(org.card.basis) && /Investigate the account to read its profile/.test(org.card.note) && org.link_kind === "evidence", "an account GitHub's search matched is Unverified: reported, nothing read");
  ok(!ee.items.some((i) => i.tier === "matches" && i.source === D.EMAIL_ACCOUNTS_SOURCE) && tierCounts(ee.items).matches === 0 && accountsFor(ee.items).find((a) => a.site === "GitHub (tidepool-lab)").status === "unverified", "nothing from the address lookup sits under 'a profile was read', on the page or for the model");
  ok(/Reported, and nothing was read: an account GitHub's search matched to this address/.test(ledgerTiers(E.target, "email").find((t) => t.id === "unverified").blurb) && /A tool reported the handle/.test(ledgerTiers(H, "username").find((t) => t.id === "unverified").blurb), "the Unverified group says what it holds in an email case");
  // only search matches: nothing was read, and the assessment must not say profiles were read
  const only = { emailAccounts: { email: E.target, cached: false, accounts: [{ login: "tidepool-lab", how: "public_profile_email", account_type: "Organization" }, { login: "mara-two", how: "public_profile_email", account_type: "User" }], unattributed: null, keys: [], sources: { github_commits: { state: "none" }, github_users: { state: "ok", count: 2 }, openpgp: { state: "none" } } } };
  const a = an(only, E.target, "email").assessment;
  ok(a.strength === "none" && /^None\. No identity is established: accounts were reported, and no profile was read\.$/.test(a.headline) && a.lines.some((l) => /2 of 2 accounts were only reported by a tool and never read \(100% of the footprint\)/.test(l.text)), "with only search matches the assessment says nothing was read");
  ok(/2 unverified/.test(text(briefOf(only, E.target, "email"))) && !/exist and match, [1-9]/.test(text(briefOf(only, E.target, "email"))), "and the brief counts them as unverified");
}

// ---- 6. commits were returned and none could be counted: partial, never "not found" -------------------------
{
  const d = { email: E.target, cached: false, accounts: [], unattributed: null, keys: [], sources: { github_commits: { state: "ok", only_skipped: true, total: 4, seen: 0, skipped: 4, note: "GitHub returned 4 commits for this address and none could be counted." }, github_users: { state: "none" }, openpgp: { state: "none" } } };
  const t = sourceTally({ emailAccounts: d }, { emailAccounts: "Accounts and keys" }), r = t.rows[0];
  ok(sourceCoverage(d).answered === 2 && sourceCoverage(d).total === 3 && r.state === "partial" && /partial: 2 of 3 lookups answered/.test(r.text) && !sourceHasResults(d), "the lookup is not counted as answered, so the source is partial");
  ok(statusForAi(r) === "partial: 2 of 3 lookups answered" && statusForAi(r) !== "not found" && partialGaps(t.rows).length === 1, "the model is told partial, never 'not found', and the gap makes counts lower bounds");
  const clean = { ...d, sources: { ...d.sources, github_commits: { state: "none" } } };
  ok(sourceTally({ emailAccounts: clean }, { emailAccounts: "Accounts and keys" }).rows[0].state === "none" && statusForAi(sourceTally({ emailAccounts: clean }, { emailAccounts: "Accounts and keys" }).rows[0]) === "not found", "a lookup that answered with nothing is still 'none'");
  ok(/unknown: commits were returned and none could be counted/.test(sourceCards.emailAccounts(d)), "and the card says the commit search is unknown");
}

// ---- 7. no profile site was asked: not asked, never "not found" ----------------------------------------------
{
  const sources = Object.fromEntries(Object.entries(D.PROFILE_SITES).map(([id, [site]]) => [id, { site, state: "not_asked" }]));
  const d = D.readProfileSources({ username: "a", cached: false, profiles: [], sources });
  const t = sourceTally({ profiles: d }, { profiles: "Profile sources" }), r = t.rows[0];
  ok(r.state === "skipped" && r.notAsked === true && /^not asked: /.test(r.text) && t.ran === 0 && t.skipped === 1 && t.failed === 0, "a lookup whose every site was left unasked is skipped, not 'none' and not failed");
  ok(/^not asked: this handle cannot exist on any of the profile sites$/.test(statusForAi(r)) && !/not found/.test(statusForAi(r)) && /1 skipped/.test(tallyText(t)), "the model is told 'not asked', and the tally counts it as skipped");
  const one = D.readProfileSources({ username: "a", cached: false, profiles: [], sources: { ...sources, gitlab: { site: "GitLab", state: "not_found" } } });
  ok(sourceTally({ profiles: one }, { profiles: "Profile sources" }).rows[0].state === "none", "one site that answered 'not found' is an answer");
  ok(/sourceCoverage\(data\);[\s\S]{0,400}cv\.notAsked && cv\.total === 0\) log\.set\(row, `\$\{label\} · \$\{cv\.notAsked\}`, "skip"\)/.test(src("investigate.js")) && /r\.state !== "skipped" \|\| r\.notAsked/.test(src("investigate.js")), "the run log row and the AI status read the same state");
}

// ---- 9. a pick that names the automatic choice is no pick ---------------------------------------------------
{
  const c = { ...U.collected, pick: { members: ["acct:github"], at: 1 } }, ev = buildEvidence(c, H, "username"), auto = buildEvidence(U.collected, H, "username");
  ok(ev.identity.picked === false && ev.identity.primary === auto.identity.primary && !ev.identity.views.some((v) => v.picked), "a stored pick of the automatic choice is not a pick");
  ok(!/Your pick|You picked|automatic choice would be/.test(identityHead(ev.identity, "")) && /Primary identity/.test(identityHead(ev.identity, "")) && an(c).assessment.mode === "auto" && aiPayloadFor(c, H, "username").case_analysis.identity_choice.mode === "automatic", "and nothing words it as one");
  const ps = [P("github", { anchor: "github", name: "Sam Example" }), P("gitlab", { name: "Petra Novak" })];
  ok(clusterIdentities(ps, { handle: "jdoe", pick: ["acct:github"] }).picked === false && clusterIdentities(ps, { handle: "jdoe", pick: ["acct:gitlab"] }).picked === true && clusterIdentities(ps, { handle: "jdoe", pick: ["acct:github", "acct:gitlab"] }).picked === false, "picked only when exactly one cluster matches and it is not the automatic one");
  ok(/if \(c\.pick && !buildEvidence\(c, target, type\)\.identity\.picked\) delete c\.pick;/.test(src("investigate.js")), "a pick that does not hold is dropped at the end of a run");
}

// ---- 10. keys of Object.prototype are not labels -----------------------------------------------------------
{
  const d = clone(U.collected); const kb = d.profiles.profiles.find((p) => p.source === "keybase");
  kb.stats = { followers: 41, constructor: 7, valueof: 3, tostring: 2 };
  const rows = row(buildEvidence(d, H, "username"), "acct:keybase").detail.groups.flatMap((g) => g.rows);
  ok(rows.some((r) => r.k === "Constructor" && r.v === "7") && !rows.some((r) => /native code|function /.test(r.k + r.v)), "a stat named like a prototype key gets a plain label");
  ok(["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__"].every((t) => typeof D.eventWord(t) === "string" && !/native code|function|\[object/.test(D.eventWord(t))) && D.eventWord("PushEvent") === "pushes", "an event type named like one is read as a word");
  const act = clone(U.collected.githubActivity); act.types = [{ type: "constructor", count: 3 }, { type: "toString", count: 2 }];
  ok(!/native code/.test(activityHtml(act)) && !/native code/.test(JSON.stringify(D.activityForAi(act))) && D.lookupName("constructor") === "constructor" && A.strengthWord("constructor") === "", "nothing on the page or for the model shows a function's source");
  const odd = buildEvidence({ maigret: { results: [{ site: "constructor", url: "https://constructor.example/jdoe", verified: true, profile: { name: "J Doe" } }, { site: "toString", url: "https://tostring.example/jdoe", verified: false }] }, platformCheck: { results: [{ platform: "hasOwnProperty", url: "", state: "taken" }] } }, "jdoe", "username");
  ok(odd.items.filter((i) => i.key.startsWith("acct:")).every((i) => typeof i.what === "string" && !/native code|\[object/.test(i.what + i.key + i.meta)) && row(odd, "acct:constructor")?.what === "constructor", "a site named like a prototype key is a site like any other");
}

// ---- 11. GitHub activity: bounded numbers, and words written here ---------------------------------------------
{
  const raw = clone(U.collected.githubActivity);
  const big = clone(raw); big.events = 1e308; big.hours_utc[3] = 1e308; big.weekdays_utc[0] = 1e300; big.window.days = 1e12; big.window.active_days = 1e12; big.pages = 1e9; big.types = [{ type: "PushEvent", count: 1e308 }]; big.repos = [{ name: "a/b", count: 1e308 }];
  const r = D.readActivity(big);
  ok(r.events <= 100000 && r.hours_utc[3] <= 100000 && r.weekdays_utc[0] <= 100000 && r.window.days <= 400 && r.window.active_days <= r.window.days && r.pages <= 20 && r.types[0].count <= 100000 && r.repos[0].count <= 100000, "every count is capped");
  const q = clone(raw); q.estimate.quiet_start_hour = 99; q.estimate.quiet_end_hour = -4; q.estimate.quiet_hours = 5000; q.estimate.quiet_events = 1e308;
  const rq = D.readActivity(q).estimate;
  ok(rq.quiet_start_hour === null && rq.quiet_end_hour === null && rq.quiet_hours === null && rq.quiet_events === null && D.activityView(q).estimate.quiet === "" && !/99|5000/.test(JSON.stringify(D.activityView(q).estimate)), "an hour outside 0 to 23 is no hour, and nothing is said about a quiet stretch");
  const ok1 = D.readActivity(raw).estimate;
  ok(ok1.quiet_start_hour === 23 && ok1.quiet_end_hour === 6 && ok1.quiet_hours === 7 && ok1.label === "UTC-1 to UTC+2" && ok1.utc_offsets.join() === "-1,0,1,2", "a real answer reads as it did, and the stretch's length follows from its ends");
  const lab = clone(raw); lab.estimate.label = "UTC+99 to UTC-99"; lab.estimate.utc_offset_from = 5; lab.estimate.utc_offset_to = -3; lab.estimate.utc_offsets = [5, 99, -3];
  const rl = D.readActivity(lab).estimate;
  ok(rl.label === "UTC+5 to UTC+12 or UTC-11 to UTC-3" && rl.crosses_date_line === true && rl.utc_offsets.length === 0, "the label is always written from the numbers, and a list that does not run east from one end to the other is not used");
  const wrap = clone(raw); wrap.estimate.utc_offset_from = 11; wrap.estimate.utc_offset_to = -10; wrap.estimate.utc_offsets = [11, 12, -11, -10]; wrap.estimate.label = "UTC+1";
  ok(D.readActivity(wrap).estimate.label === "UTC+11 to UTC+12 or UTC-11 to UTC-10", "a list that crosses the date line is two runs");
  const out = clone(raw); out.estimate.utc_offset_from = 40;
  ok(D.readActivity(out).estimate === null && D.activityView(out).noEstimate === "No estimate was made.", "an offset outside UTC-12 to UTC+14 is no estimate");
  const lie = clone(raw); lie.estimate.basis = "Lives in Berlin."; lie.estimate.assumption = "Works at Tidepool GmbH."; lie.estimate.caveat = "Certain."; lie.estimate.label = "Berlin";
  const v = D.activityView(lie).estimate, all = JSON.stringify([D.activityView(lie), D.activityForAi(lie), D.activityMarkdown(lie), activityHtml(lie), D.readActivity(lie)]);
  ok(!/Berlin|Tidepool GmbH|Certain\./.test(all) && !("basis" in D.readActivity(lie).estimate) && v.basis === "Based on 137 public events over 85 days (61 with activity). The longest quiet stretch is 23:00 to 06:00 UTC." && v.assumption === D.ESTIMATE_ASSUMPTION && v.caveat === D.ESTIMATE_CAVEAT, "the three sentences of an estimate are written here from the checked numbers; stored text is never kept");
  const why = clone(raw); why.estimate = null; why.estimate_reason = { code: "too_few_events", text: "Lives in Berlin." }; why.events = 12;
  ok(D.activityView(why).noEstimate === "Too few public events to say anything about hours: 12 seen." && D.readActivity({ ...why, estimate_reason: { code: "made_up", text: "Lives in Berlin." } }).estimate_reason.text === "No estimate was made.", "why no estimate was made is the server's code in the page's words");
  ok(D.activityView({ username: "a", found: false, state: "not_found", note: "Lives in Berlin." }).text === "GitHub has no account with this name." && D.activityView({ username: "", found: false, state: "not_found", note: D.NOT_A_LOGIN_NOTE }).text === D.NOT_A_LOGIN_NOTE, "a 'not found' note is the server's own sentence or nothing");
  const kb = clone(U.collected.profiles); kb.profiles[0].stats = { followers: 1e308 };
  ok(D.readProfileSources(kb).profiles[0].stats.followers <= 1e9, "a count on a profile is capped too");
}

// ---- 12. what is kept in History is always the cleaned form ---------------------------------------------------
{
  const raw = clone(U.collected);
  raw.profiles.profiles[0].guard = { bio: "GUARD ONLY TEXT born 2012", text: "more guard text", age: "13" };
  raw.profiles.profiles[0].bio = "x".repeat(900);
  raw.maigret.results[0].profile = { ...(raw.maigret.results[0].profile || {}), guard: { bio: "MAIGRET GUARD" } };
  const kept = storedCase(raw), s = JSON.stringify(kept);
  ok(!/GUARD ONLY TEXT|more guard text|MAIGRET GUARD|"guard"/.test(s) && /GUARD ONLY TEXT/.test(JSON.stringify(raw)), "guard-only text is never in what is stored, and the case in memory is left as it was");
  ok(kept.profiles.profiles[0].bio.length === 300 && kept.profiles.profiles[0].site === "Keybase" && JSON.stringify(storedCase(kept)) === s, "the record sources are stored in their checked, bounded shape, and storing twice changes nothing");
  ok(/results: storedCase\(state\.collected\)/.test(src("investigate.js")) && !/results: state\.collected[,\s]/.test(src("investigate.js")), "every save goes through it, whoever calls it and when");
}

// ---- 13. a name that fits a one-word name of the identity is not a different person ----------------------------
{
  const ps = [P("github", { anchor: "github", name: "Sam Example", links: ["https://insta.example/u/jdoe"] }), P("insta", { name: "Petra", links: ["https://github.example/u/jdoe"] }), P("gitlab", { name: "Petra Novak" })];
  const r = clusterIdentities(ps, { handle: "jdoe" }), st = standing(ps[2], r, { handle: "jdoe" });
  ok(r.byProfile["acct:insta"] === r.primary && r.byProfile["acct:gitlab"] !== r.primary && st.tier === "matches" && st.unsettled === true && st.mixed === true && st.against.join() === "Sam Example" && st.fits.join() === "Petra", "a full name that fits a one-word name of the identity and conflicts with its full name is unsettled, not a different person");
  const only = [P("github", { anchor: "github", name: "Sam Example" }), P("insta", { name: "Sam" }), P("gitlab", { name: "Petra Novak" })];
  const r2 = clusterIdentities(only, { handle: "jdoe" });
  ok(r2.byProfile["acct:insta"] === r2.primary && standing(only[2], r2, { handle: "jdoe" }).tier === "different" && !standing(only[2], r2, { handle: "jdoe" }).unsettled, "when the identity's only names are a full one and a one-word form of it, a conflicting full name is still a different person");
  // On the page: the row says both halves, and the assessment does not say "only a one-word name".
  const c = { github: { found: true, name: "Sam Example", profile_url: "https://github.com/jdoe", blog: "https://bsky.app/profile/jdoe" },
    maigret: { results: [{ site: "Bluesky", url: "https://bsky.app/profile/jdoe", verified: true, profile: { name: "Petra", links: ["https://github.com/jdoe"] } }, { site: "Medium", url: "https://medium.com/@jdoe", verified: true, profile: { name: "Petra Novak" } }] } };
  const ev = buildEvidence(c, "jdoe", "username"), med = row(ev, "acct:medium");
  ok(row(ev, "acct:bluesky").tier === "linked" && med.tier === "matches" && med.unsettled?.mixed === true && /fits the one-word name "Petra" on a profile of the primary identity and conflicts with its full name "Sam Example"\. Neither settles it/.test(med.card.check) && /name not settled/.test(med.meta), "the row says what fits and what conflicts");
  const t = says(c, "jdoe", "username");
  ok(/1 profile carries a name that fits a one-word name of the primary identity and conflicts with its full name \(Medium: "Petra Novak"\)/.test(t) && !/has only a one-word name/.test(t) && !/belongs to another person/.test(t), "and so does the assessment");
}

// ---- 14. the assessment for the model names the same failed sources as the page ---------------------------------
{
  const status = { "Platform check": "blocked: blocked by every site checked", "GitHub details": "failed: timeout", Sherlock: "ok" };
  const line = (opts) => aiPayloadFor(U.collected, H, "username", opts).case_analysis.lines.find((l) => /^Could not be asked/.test(l));
  ok(/Platform check \(failed\)/.test(line({ source_status: status })) && /GitHub details \(failed\)/.test(line({ source_status: status })), "a source whose status starts 'blocked' is among what could not be asked");
  ok(/Platform check \(failed\)/.test(line({ source_status: {}, failed: ["Platform check"] })) && !/GitHub details/.test(line({ source_status: status, failed: ["Platform check"] })), "and when the page passes its own failed list, that list is the one used");
  const page = an(U.collected, H, "username", ["Platform check"]).assessment.lines.find((l) => /^Could not be asked/.test(l.text)).text;
  ok(page === line({ source_status: status, failed: ["Platform check"] }), "so the line on the page and the line the model reads are the same");
  ok(/failed: rows\.filter\(\(r\) => r\.state === "failed"\)\.map\(\(r\) => r\.name\)/.test(src("investigate.js")), "the page passes the tally's failed rows");
}

// ---- 16, 20, 21. an email case: what the tiles and the brief count ---------------------------------------------
{
  const ev = buildEvidence(E.collected, E.target, "email");
  const tiles = (o = {}) => investigateTiles({ items: ev.items, collected: E.collected, type: "email", ...o });
  const linked = tiles().find((t) => t.id === "linked"), b = text(briefOf(E.collected, E.target, "email", ev));
  ok(linked.value === 7 && linked.sub === "5 accounts and 2 keys, tied to this address" && !/primary identity/.test(linked.sub), "the Linked tile of an email case says what it counts: accounts and keys tied to the address");
  ok(/^5 accounts and 2 keys tied to this address, 0 that exist and match, 0 that belong to a different person, and 3 unverified\. Tied to the address means a record says so/.test(b), "and the brief counts the same rows the tiles do");
  ok(tiles().find((t) => t.id === "unverified").value === 3 && investigateTiles({ items: buildEvidence(U.collected, H, "username").items, collected: U.collected, type: "username" }).find((t) => t.id === "linked").sub === "tied to the primary identity", "a username case keeps its wording");
  ok(/Tied to this address by a record/.test(ledgerTiers(E.target, "email").find((t) => t.id === "linked").blurb) && /Tied to the primary identity/.test(ledgerTiers(H, "username").find((t) => t.id === "linked").blurb), "the Linked group says the same in an email case");
  const un = tiles({ partialKeys: ["emailAccounts"] }).find((t) => t.id === "unverified");
  ok(un.atLeast === true && /^at least: /.test(un.sub) && tiles().find((t) => t.id === "unverified").atLeast === false, "when the address lookup answered in part, Unverified is 'at least'");
  const lim = clone(E.collected); lim.emailAccounts.accounts = []; lim.emailAccounts.unattributed = null; lim.emailAccounts.sources.github_commits = { state: "rate_limited", error: "x", error_code: "rate_limited" };
  ok(investigateTiles({ items: buildEvidence({ emailAccounts: lim.emailAccounts }, E.target, "email").items, collected: { emailAccounts: lim.emailAccounts }, type: "email", partialKeys: ["emailAccounts"] }).find((t) => t.id === "unverified").state === "unknown", "and with nothing found it is unknown, never zero");
  ok(row(ev, "acct:github~mara-lind").what === "GitHub (mara-lind)" && row(ev, "acct:github~tidepool-lab").what === "GitHub (tidepool-lab)" && new Set(ev.items.filter((i) => i.key.startsWith("acct:github~")).map((i) => i.what)).size === 2, "two GitHub rows of an email case are told apart by the login in the title");
}

// ---- 17. another person's record: the site and the status, nothing else -----------------------------------------
{
  const ai = aiPayloadFor(U.collected, H, "username"), gl = ai.profile_sources.profiles.find((p) => p.site === "GitLab");
  ok(JSON.stringify(gl) === JSON.stringify({ site: "GitLab", status: "different" }) && !/Petra|Brno/.test(JSON.stringify(ai.profile_sources)), "a record filed as a different person is sent as its site and that status");
  ok(ai.profile_sources.profiles.find((p) => p.site === "Keybase").self_declared.name === "Sam Example" && ai.profile_sources.profiles.find((p) => p.site === "Keybase").url === "https://keybase.io/samexample", "a record of the primary identity keeps what was read on it");
}

// ---- 18. control and bidi characters do not survive a reader ----------------------------------------------------
{
  const evil = "Sam‮ elpmaxE⁦⁩‏\u0007\u009F﻿";
  const d = clone(U.collected.profiles); d.profiles[0].name = evil; d.profiles[0].display_name = evil; d.profiles[0].bio = `bio‮txt`; d.profiles[0].handle = `sam‮example`; d.profiles[0].accounts[0].handle = `x‮y`;
  const s = JSON.stringify(D.readProfileSources(d)), BAD = /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩﻿]/;
  ok(!BAD.test(s) && D.readProfileSources(d).profiles[0].name === "Sam elpmaxE" && D.cleanText("a‮b") === "a b", "a name, a bio and a handle lose characters that reorder or hide text");
  const ea = clone(E.collected.emailAccounts); ea.accounts[0].names = [{ name: `Mara‮ Lind`, commits: 2, own_repo: true }]; ea.keys[0].user_ids[0].name = `K⁧ey`;
  ok(!BAD.test(JSON.stringify(D.readEmailAccounts(ea))), "so do names in commits and on keys");
  ok(!BAD.test(JSON.stringify(C.readTrail([{ target: `sam‮example`, type: "username", via: `the ⁦handle`, source: `Git‏Hub` }]))) && !BAD.test(JSON.stringify(C.readSteps({ "lead:handle:x": { state: "parked", title: `In‮vestigate x` } }))), "and the trail and the parked steps of a stored case");
  ok(D.readProfileSources(clone(U.collected.profiles)).profiles[0].name === "Sam Example" && D.cleanText("Zoë 李小龙 x‍y") === "Zoë 李小龙 x‍y", "ordinary text, other scripts and joiners inside a word are left alone");
}

// ---- 19. a person case says each thing once -------------------------------------------------------------------
{
  const c = { ...U.collected, ...PICK }, b = briefOf(c, H, "username", undefined, { first: an(c).suggestions.top[0].title, incomplete: [] });
  const t = text(b), a = says(c);
  ok(!/You picked|your pick|automatic choice/.test(t) && /^Thin\. Filed around Petra Novak, your pick, not the automatic choice \(Sam Example\)\./.test(a) && /You picked this person/.test(identityHead(buildEvidence(c, H, "username").identity, "")), "the pick is said in the header and as the assessment's headline, not as the brief's first line");
  ok(!/did not answer the profile lookup|blocked the check|could not be asked|source failed/.test(t) && /Could not be asked: Chess\.com \(rate limited\), Codeforces \(failed\), Lobsters \(blocked by site\), Twitch \(blocked the check\)/.test(a), "what could not be asked is in the assessment only");
  ok(!/different people use this handle|Only the first is treated/.test(t) && /7 accounts belong to another person whose name conflicts with Petra Novak/.test(a), "and so are the other people under the handle");
  ok(b.rows.length <= 5 && /^Check first: See archived copies of the GitLab profile\. It is first under "Suggested next steps"\.$/.test(b.rows.at(-1).text), "the brief is short and ends on the one thing to check first");
  const auto = briefOf(U.collected, H, "username", undefined, { first: "Investigate sam_rides" });
  ok(auto.rows.length <= 6 && /^4 linked accounts, 6 that exist and match/.test(auto.rows[0].text) && /Check first: Investigate sam_rides\./.test(auto.rows.at(-1).text), "with the automatic choice it is what was found, then the first step");
  ok(briefOf(E.collected, E.target, "email").rows.every((r) => !/could not be asked|Username tools were not run|are listed under the findings/.test(r.text)), "an email case's brief leaves the gaps and the lead explanations to the two panels");
  // A hash case has no assessment panel, so a failure is still said in its brief.
  ok(/1 source failed \(Hash lookup\)/.test(text(investigateBrief({ type: "hash", target: "x", failed: [{ name: "Hash lookup" }], facts: [], items: [], collected: {} }))), "a case with no assessment panel still names a failed source in its brief");
}

// ---- 22. one record: said for what the record is ------------------------------------------------------------------
{
  const key = { emailAccounts: { email: E.target, cached: false, accounts: [], unattributed: null, keys: [E.collected.emailAccounts.keys[0]], sources: { github_commits: { state: "none" }, github_users: { state: "none" }, openpgp: { state: "ok", count: 1 } } } };
  const k = an(key, E.target, "email").assessment;
  ok(k.strength === "moderate" && /^Moderate\. One OpenPGP key is verified for this address by the key server\. It ties a key to the address, not an account\. A second, independent tie would make this firm\.$/.test(k.headline) && !/ties an account to this address/.test(k.headline), "a single key is not worded as an account");
  const acct = { emailAccounts: { ...key.emailAccounts, keys: [], accounts: [E.collected.emailAccounts.accounts[0]] } };
  ok(/^Moderate\. GitHub's commit attribution ties the account mara-lind to this address\./.test(an(acct, E.target, "email").assessment.headline), "a single commit attribution names the account");
}

// ---- 23. a Recon case file keeps its trail, like an Investigate one -------------------------------------------------
{
  const trail = C.extendTrail({ target: "samexample", type: "username", id: "a1", at: 1700000000000, trail: [] }, { label: "the domain samexample.example", source: "GitHub website field" });
  const f = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: "samexample.example", type: "domain", ran: 1700000000000, collected: { dns: { records: { A: ["192.0.2.1"] } }, trail }, ai: null, deep: null, notes: "", purpose: "" })));
  ok(f.ok && f.entry.type === "RECON" && f.entry.trail?.length === 1 && f.entry.trail[0].target === "samexample" && f.entry.trail[0].file === true && !("trail" in f.entry.results) && !("pick" in f.entry.results), "a Recon case file carries its trail, which lands where a Recon case keeps it");
  ok(/collected: \{ \.\.\.state\.collected, \.\.\.\(readTrail\(state\.trail\)\.length \? \{ trail: readTrail\(state\.trail\) \} : \{\}\) \}/.test(src("recon.js")) && /trail: readTrail\(e\.trail\)/.test(src("recon.js")), "Recon's export writes the trail into the file, and opening one reads it back");
  const g = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: "samexample.example", type: "domain", ran: 1, collected: { dns: { records: { A: ["192.0.2.1"] } }, trail: "x", pick: { members: ["acct:x"] }, nextSteps: { "lead:handle:x": { state: "parked" } } }, ai: null, deep: null, notes: "", purpose: "" })));
  ok(g.ok && !("trail" in g.entry) && Object.keys(g.entry.results).join() === "dns", "an unreadable trail is dropped, and a Recon case has no pick or steps");
}

// ---- 24. a lead known to be a domain opens in Recon ----------------------------------------------------------------
{
  ok(detect("tidepool.example") === "username" && detect("maria.co") === "domain" && detect("word.word") === "username", "typed text is detected as before: a last label that is not a listed TLD is not a domain");
  ok(reconType("tidepool.example", "domain") === "domain" && reconType("tidepool.example") === "username" && reconType("tidepool.example", "ip") === "username", "a value known to be a domain is one, and only then");
  ok(reconType("example.com", "domain") === "domain" && reconType("8.8.8.8", "domain") === "ip" && reconType("AS15169", "domain") === "asn" && reconType("not a domain", "domain") !== "domain" && reconType("jdoe", "domain") === "username" && reconType("a@b.example", "domain") === "email", "what is plainly something else stays that, and the shape of a domain is still required");
  const ee = buildEvidence(E.collected, E.target, "email"), lead = ee.items.find((i) => i.key === "lead:domain:tidepool.example");
  ok(lead.action.pivot === "recon" && lead.action.type === "domain" && /data-pivot="recon"/.test(evSrc(lead)) && /data-pivot-type="domain"/.test(evSrc(lead)), "a domain lead's button says what its value is");
  const s = [...an(E.collected, E.target, "email").suggestions.top, ...an(E.collected, E.target, "email").suggestions.more].find((x) => x.id === "lead:domain:tidepool.example");
  ok(s && s.action.type === "domain", "and so does the suggestion made from it");
  ok(/startRecon\(v, \{ from, via, type: b\.dataset\.pivotType === "domain" \? "domain" : "" \}\)/.test(src("app.js")) && /const type = reconType\(target, opts\.type\);/.test(src("recon.js")) && /type: reconType\(e\.target, e\.kind\)/.test(src("recon.js")) && /type: "RECON", kind: state\.type/.test(src("recon.js")), "the button's type reaches the run, and the case remembers it when it is opened again");
  const f = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: "tidepool.example", type: "domain", ran: 1, collected: { dns: { records: { A: ["192.0.2.1"] } } }, ai: null, deep: null, notes: "", purpose: "" })));
  ok(f.ok && f.entry.kind === "domain" && !parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: "jdoe", type: "domain", ran: 1, collected: { dns: {} }, ai: null, deep: null, notes: "", purpose: "" }))).ok, "its case file opens again, and a file cannot call a handle a domain");
}

console.log(bad ? `${bad} of ${n} case rule checks failed` : `${n}/${n} case rule checks passed`);
if (bad) process.exit(1);
