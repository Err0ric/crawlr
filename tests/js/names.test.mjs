// Name cases. A name search returns candidates, never findings about one person. These checks
// pin the ledger groups and their wording, the three states per directory, the qualifier hits, the
// GitHub "Show profile" merge, the handle suggestions, the outbound searches, what the AI is
// sent, the exports, and what a saved or hostile case file may bring back. No browser, no network.
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };   // ai.js and report.js register delegated listeners on import
const J = "../../static/v2/js/";
const N = await import(J + "names.js");
const L = await import(J + "links.js");
const { sourceTally, sourceCoverage, sourceHasResults, statusForAi, tallyText, detect } = await import(J + "core.js");
const { buildEvidence, ledgerTiers, sourcePlan, accountsFor, avatarImages, collectProfiles, isFinding, factsFor, aiPayloadFor, caseMarkdown, deepDiveUrls, TIER_ORDER } = await import(J + "evidence.js");
const { investigateBrief } = await import(J + "brief.js");
const { evWhat, renderTiers, renderBrief, renderNameKnown, nameNoticesHtml } = await import(J + "workbench.js");
const { sourceCards } = await import(J + "renderers.js");
const { reportHtml } = await import(J + "report.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");
const { makeAdultSwitch } = await import(J + "adult.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const eq = (a, b, name) => { n++; if (JSON.stringify(a) !== JSON.stringify(b)) { bad++; console.log("FAIL", name, "\n   got ", JSON.stringify(a), "\n   want", JSON.stringify(b)); } };
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/names.json", import.meta.url), "utf8"));
const kase = (name) => structuredClone(fx.cases.find((c) => c.name === name));
const ev = (c) => buildEvidence(c.collected, c.target, c.type);
const tierOf = (e, t) => e.items.filter((i) => i.tier === t);
const SRC = { nameResult: N.NAME_SOURCE };
const tally = (c) => sourceTally(c.collected, SRC);
const el = () => ({ innerHTML: "", hidden: false, id: "t" });
const ledgerHtml = (c) => { const e = ev(c), box = el(); renderTiers(box, e.items, N.nameTierView(ledgerTiers(c.target, c.type), e.items), new Set(), "<p>empty</p>"); return box.innerHTML; };
const hrefs = (html) => [...String(html).matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'"));
const brief = (c, failed = []) => { const e = ev(c); return investigateBrief({ collected: c.collected, items: e.items, facts: e.facts, identity: e.identity, failed, type: c.type, target: c.target }); };
const briefText = (c, failed) => brief(c, failed).rows.map((r) => `${r.level}: ${r.text}`).join("\n");
// What "Show profile" stores for a login, from GitHub's recorded answer.
const withProfiles = (c, ...logins) => { c.collected.nameProfiles = { ...(c.collected.nameProfiles || {}), ...Object.fromEntries(logins.map((l) => [l, N.readProfile(fx.githubProfiles[l])])) }; return c; };

const linus = kase("public figure"), dana = kase("qualifiers");

// ---- the plan and the switches ----------------------------------------------------------------
eq(sourcePlan("name", "Linus Torvalds"), ["namesearch"], "a name case runs one source, the name search");
ok(makeAdultSwitch().view("Linus Torvalds", "name").show === false && sourcePlan("name", "Linus Torvalds", { adult: true }).join() === "namesearch", "the adult mode switch is not offered for a name, and never planned");
ok(L.checkPolicy({ type: "name", live: true }).allowed === false && L.pendingChecks(ev(linus).items).length === 0, "the link check is never used for a name case");
ok(detect("Linus Torvalds") === "name" && ev({ collected: linus.collected, target: linus.target }).type === "name" && ev({ collected: { nameResult: linus.collected.nameResult }, target: "x" }).type === "name", "a name case is recognised with or without the type");

// ---- groups: order and wording ------------------------------------------------------------------
{
  const e = ev(linus);
  eq([...new Set(e.items.map((i) => i.tier))], ["notable", "people", "handles", "websearch"], "groups come in order: public figure, people, handles, searches");
  eq(ledgerTiers(linus.target, "name").map((t) => t.title), ["Public figure", "People with this name", "Handles to try", "Search the web"], "the four group titles");
  ok(["notable", "people", "handles", "websearch"].every((t) => TIER_ORDER.includes(t)) && e.items.every((i) => !isFinding(i)), "no row of a name case is a finding");
  const blurb = Object.fromEntries(N.NAME_TIERS.map((t) => [t.id, t.blurb]));
  ok(blurb.handles === "Built from the name. Nothing has been checked: a handle here may not exist, or may belong to someone else.", "the handles blurb");
  ok(blurb.websearch === "These open a search on another site. The name and anything you typed above go to that site.", "the search group says the name goes to that site");
  ok(N.NAME_NOTICE === "A name is shared by many people. Everything below is a candidate to look at, not a finding about one person.", "the caveat line");
  eq(N.nameNotices(linus.collected)[0], { level: "note", text: N.NAME_NOTICE }, "the caveat is the first notice");
  ok(fx.cases.every((c) => N.nameNotices(c.collected)[0].text === N.NAME_NOTICE), "the caveat stands above every name case, with or without results");

  // public figure: one row, Wikipedia and Wikidata as evidence links
  const nb = tierOf(e, "notable");
  ok(nb.length === 1 && nb[0].what === "Linus Torvalds" && nb[0].meta === "Finnish software engineer (born 1969)" && nb[0].source === "Wikidata", "the public figure row carries the name and the description");
  ok(nb[0].link_kind === "evidence" && nb[0].url === "https://en.wikipedia.org/wiki/Linus_Torvalds" && nb[0].link_label === "Wikipedia" && nb[0].more.url === "https://www.wikidata.org/wiki/Q34253" && nb[0].more.label === "Wikidata" && nb[0].more.link_kind === "evidence", "it links to Wikipedia and Wikidata as evidence");
  eq(hrefs(evWhat(nb[0])), ["https://en.wikipedia.org/wiki/Linus_Torvalds", "https://www.wikidata.org/wiki/Q34253"], "both links render, and the name itself is plain text");
  ok(!nb[0].action && !nb[0].fetch, "the public figure row has no action");
  ok(tierOf(ev(dana), "notable").length === 0, "no public figure group when Wikidata has no exact match");

  // people: the server's order, each from its directory
  const people = tierOf(e, "people");
  eq(people.map((i) => i.source), ["Wikidata", "Bluesky", ...Array(8).fill("GitHub")], "candidates keep the server's order");
  eq(people.map((i) => i.what).slice(0, 4), ["Linus Torvalds", "Linus Torvalds", "torvalds", "linus-torvalds-fan"], "a row shows the name, or the handle when the directory gave no name");
  ok(people.every((i) => i.link_kind === "verified_profile" && i.url), "a candidate's link is the record its directory returned");
  ok(people[0].url === "https://www.wikidata.org/wiki/Q34253" && people[1].url === "https://bsky.app/profile/linus-quotes.bsky.social" && people[2].url === "https://github.com/torvalds", "the three URL forms");
  ok(/exact name/.test(people[0].meta) && /all name words/.test(people[2].meta), "each row says how the name matched, in words");
  ok(people[1].meta.startsWith("@linus-quotes.bsky.social · Unofficial. Quotes from mailing list posts. · exact name"), "an account row shows its handle and bio");
  ok(new Set(e.items.map((i) => i.key)).size === e.items.length && people[2].key === "cand:github:torvalds", "row keys are unique and stable");
}
{
  // the words for how a name matched
  eq(N.MATCH_WORD, { exact: "exact name", tokens: "all name words", partial: "family name and initial", none: "name on profile does not match" }, "the match words");
  const people = tierOf(ev(dana), "people");
  ok(/family name and initial/.test(people.find((i) => i.what === "D. Whitfield").meta), "a partial match is worded");
  ok(people.find((i) => i.source === "ORCID").meta.startsWith("ORCID 0000-0002-1825-0097 · Northgate University; Leeds Water Institute · exact name"), "a researcher row shows its affiliation");
  ok(/GB · Northgate University/.test(people.find((i) => i.source === "OpenAlex").meta), "location and affiliation are shown when present");
}

// ---- qualifier hits ---------------------------------------------------------------------------------
{
  const people = tierOf(ev(dana), "people"), by = (s, what) => people.find((i) => i.source === s && (!what || i.what === what));
  ok(/· matches employer · matches keyword$/.test(by("OpenAlex").meta), "a row names the qualifiers it hit");
  ok(/· matches location · matches employer$/.test(by("ORCID").meta) && /· matches location · matches keyword$/.test(by("Bluesky", "Dana Whitfield").meta), "any qualifier may hit in any field");
  ok(!/matches/.test(by("Bluesky", "D. Whitfield").meta), "a row with no hit says nothing");
  const nc = N.nameCase(dana.collected);
  eq(nc.given, ["location", "employer", "keyword"], "the qualifiers in use");
  ok(nc.matchAll === 0, "no row matches all three before a profile is loaded");
  eq(N.qualifierHits({ location: "Leeds", employer: "northgate university", keyword: "Hydro" }, "Leeds, UK", "Northgate University", "Hydrology and open data."), ["location", "employer"], "hits are whole words, whatever the case");
  eq(N.qualifierHits({ location: "São Paulo" }, "Sao Paulo, Brazil"), ["location"], "accents are ignored");
  eq(N.readQualifiers({ location: " Leeds ", employer: "x".repeat(200), keyword: 7, extra: "no" }), { location: "Leeds", employer: "x".repeat(80), keyword: "" }, "qualifiers are trimmed, clipped and limited to the three");
}

// ---- name matching: the server's rule ------------------------------------------------------------
{
  const m = (names, o) => N.matchName("Linus Torvalds", names, o);
  ok(m(["LINUS TORVALDS"]) === "exact" && m(["Linus  Törvalds"]) === "exact", "exact ignores case, spacing and accents");
  ok(m(["Linus Benedict Torvalds"]) === "tokens" && m(["Torvalds, Linus"]) === "tokens", "tokens: every word is there");
  ok(m(["L. Torvalds"]) === "partial" && m(["Torvalds"]) === null && m(["Linus Smith"]) === null && m([""]) === null, "partial needs the family name and the given initial");
  ok(m(["Kernel Fan"], { handle: "LinusTorvalds", fullHandles: ["linustorvalds"] }) === "tokens" && m(["Kernel Fan"], { handle: "ltorvalds", fullHandles: ["linustorvalds"] }) === null, "a handle that spells out both names fits");
  ok(N.matchName("Madonna", ["Madonna"]) === "exact" && N.matchName("Madonna", ["M. Ciccone"]) === null, "a one-word name has no partial match");
  ok(N.fold("Siobhán O’Brien-Müller") === "siobhan obrien muller" && N.fold("Straße Łódź") === "strasse lodz", "folding matches the server's");
  eq(N.parseName("  Mary Ann  Smith "), { given: "Mary", middle: "Ann", family: "Smith", single_token: false }, "first word given, last word family");
}

// ---- GitHub rows: Show profile -----------------------------------------------------------------
{
  const before = tierOf(ev(linus), "people").filter((i) => i.source === "GitHub");
  ok(before.every((i) => i.fetch && i.fetch.label === "Show profile" && i.fetch.login === i.what), "every GitHub row offers Show profile for its own login");
  ok(before.every((i) => /GitHub gives the login only/.test(i.meta)), "an unloaded GitHub row says why it is bare");
  ok(tierOf(ev(linus), "people").filter((i) => i.source !== "GitHub").every((i) => !i.fetch), "no other row has that button");
  const html = ledgerHtml(linus);
  ok((html.match(/data-name-profile="/g) || []).length === 8 && /<button type="button" class="btn btn-sm ev-act" data-name-profile="torvalds" aria-label="Show profile: torvalds">Show profile<\/button>/.test(html), "the button is a real button, named for its login");

  const c = withProfiles(kase("public figure"), "torvalds", "linus-torvalds-fan", "ltorvalds-notes", "linustorvalds", "torvalds-linus-mirror", "linus-t-archive");
  eq(c.collected.nameProfiles.torvalds, { found: true, name: "Linus Torvalds", bio: "", location: "Portland, OR", company: "Linux Foundation" }, "only four text fields are kept from GitHub's answer");
  ok(!JSON.stringify(c.collected.nameProfiles).includes("avatar") && !JSON.stringify(c.collected.nameProfiles).includes("githubusercontent"), "the picture address is never stored");
  const gh = tierOf(ev(c), "people").filter((i) => i.source === "GitHub"), row = (login) => gh.find((i) => i.key === `cand:github:${login}`);
  ok(row("torvalds").what === "Linus Torvalds" && row("torvalds").meta === "@torvalds · Portland, OR · Linux Foundation · exact name", "a loaded row shows name, location and company, and is re-matched as exact");
  ok(!row("torvalds").fetch && row("torvalds").action.value === "torvalds", "a loaded row drops the button and keeps Investigate this");
  ok(/family name and initial/.test(row("ltorvalds-notes").meta) && row("ltorvalds-notes").what === "L. Torvalds", "a looser name is re-matched as partial");
  ok(row("linus-torvalds-fan").what === "Kernel Fan Page" && /name on profile does not match$/.test(row("linus-torvalds-fan").meta) && row("linus-torvalds-fan").gone === true, "a profile whose name does not fit says so");
  ok(row("linustorvalds").what === "linustorvalds" && /all name words · no name on profile$/.test(row("linustorvalds").meta), "a profile with no name keeps the server's match and says there is no name");
  ok(row("torvalds-linus-mirror").meta === "GitHub has no account with this login now" && !row("torvalds-linus-mirror").fetch && !row("torvalds-linus-mirror").action && row("torvalds-linus-mirror").link_kind === "none" && row("torvalds-linus-mirror").url === "", "an account that is gone has no buttons and no link");
  ok(/profile unknown: GitHub rate limited the lookup$/.test(row("linus-t-archive").meta) && row("linus-t-archive").fetch.label === "Try again", "a rate limit is shown on the row as unknown, with Try again");
  eq(gh.slice(-2).map((i) => i.key).sort(), ["cand:github:linus-torvalds-fan", "cand:github:torvalds-linus-mirror"], "rows that do not fit move to the end of the group");
  eq(tierOf(ev(c), "people").slice(0, 3).map((i) => i.key), ["cand:wikidata:q34253", "cand:bluesky:linus-quotes.bsky.social", "cand:github:torvalds"], "and the rest keep their order");
  ok(row("penguin-linus").fetch.label === "Show profile", "rows nobody clicked are untouched");

  // qualifiers are re-read against a loaded profile
  const d = withProfiles(kase("qualifiers"), "danawhitfield", "dwhitfield-maps");
  const dg = tierOf(ev(d), "people").find((i) => i.key === "cand:github:danawhitfield");
  ok(dg.what === "Dána Whitfield" && /exact name · matches location · matches employer · matches keyword$/.test(dg.meta), "a loaded profile is matched and its qualifier hits are found");
  ok(N.nameCase(d.collected).matchAll === 1, "it now matches every qualifier");
  ok(/family name and initial · matches location$/.test(tierOf(ev(d), "people").find((i) => i.key === "cand:github:dwhitfield-maps").meta), "another Whitfield is a partial match, not the same name");
  eq(N.readProfiles({ torvalds: fx.githubProfiles.torvalds, "not a login!": { found: true }, "-bad": { found: true }, okay: "string", half: { found: "yes" } }), { torvalds: c.collected.nameProfiles.torvalds }, "stored profiles are kept only under a GitHub login, in the known shape");
}

// ---- handles to try --------------------------------------------------------------------------------
{
  const e = ev(linus), hs = tierOf(e, "handles");
  eq(hs.map((i) => i.what), ["linustorvalds", "linus.torvalds", "linus_torvalds", "ltorvalds", "linust", "torvaldslinus", "torvalds.linus", "linus-torvalds"], "the suggested handles, in the server's order");
  ok(hs[0].meta === "given name + family name" && hs[3].meta === "given initial + family name" && hs[1].meta === "given name + dot + family name", "each says its pattern in words");
  ok(hs.every((i) => i.link_kind === "none" && i.url === "" && !/<a\b/.test(evWhat(i))), "a suggested handle is never a link: nothing was checked");
  ok(hs.every((i) => i.action.label === "Investigate this" && i.action.pivot === "investigate" && i.action.value === i.what && i.action.type === "username"), "each has Investigate this, as a username");
  ok(/data-pivot="investigate" data-value="linus\.torvalds" data-pivot-type="username" data-confirm-run="1" aria-label="Investigate this: linus\.torvalds"/.test(ledgerHtml(linus)), "the button asks before ending a run, and carries the type so a dotted handle is not read as a domain");
  const view = (c) => N.nameTierView(ledgerTiers(c.target, "name"), ev(c).items).find((t) => t.id === "handles").open;
  ok(view(linus) === false && view(kase("nobody")) === true, "the group is collapsed when there are candidates and open when there are none");
  ok(/<section class="tier\s+collapsed\s*" data-tier="handles">/.test(ledgerHtml(linus)) && !/collapsed[^>]*data-tier="handles"/.test(ledgerHtml(kase("nobody"))), "and renders that way");
  eq(tierOf(ev(kase("one word")), "handles").map((i) => [i.what, i.meta]), [["madonna", "the name as one word"]], "a one-word name suggests one handle");
  // candidate actions
  const people = tierOf(e, "people");
  ok(people.filter((i) => i.source === "GitHub").every((i) => i.action.value === i.what && i.action.type === "username"), "a GitHub row investigates its login");
  ok(people.find((i) => i.source === "Bluesky").action.value === "linus-quotes", "a name.bsky.social row investigates the name part");
  ok(!people.find((i) => i.source === "Wikidata").action, "a public figure row has no action");
  const dp = tierOf(ev(dana), "people");
  ok(!dp.find((i) => i.source === "ORCID").action && !dp.find((i) => i.source === "OpenAlex").action, "a researcher row has no action: its ID is not a username");
  ok(!dp.find((i) => i.key === "cand:bluesky:dana.example.org").action && dp.find((i) => i.key === "cand:bluesky:danaw.bsky.social").action.value === "danaw", "a Bluesky handle on its own domain is not offered as a username");
}

// ---- the three states, per directory and in the tally -----------------------------------------------
{
  ok(N.directoryText(linus.collected.nameResult) === "Wikidata 1 · GitHub 8 · ORCID none · OpenAlex rate limited · Bluesky 1", "the run log line names each directory's outcome");
  ok(N.directoryText(kase("none answered").collected.nameResult) === "Wikidata failed · GitHub rate limited · ORCID failed · OpenAlex rate limited · Bluesky failed", "failed and rate limited are worded apart");
  ok(N.directoryText(kase("one word").collected.nameResult) === "Wikidata 1 · GitHub 1 · Bluesky none", "a directory that was not asked is not listed");

  const t1 = tally(linus);
  eq(sourceCoverage(linus.collected.nameResult), { answered: 4, total: 5, unit: "directories", failedText: "no directory could be asked" }, "a rate limited directory did not answer");
  ok(t1.rows[0].state === "partial" && t1.rows[0].text === "partial: 4 of 5 directories answered" && t1.partial === 1 && t1.failed === 0 && t1.withResults === 1, "one directory down makes the source partial");
  ok(statusForAi(t1.rows[0]) === "partial: 4 of 5 directories answered" && /1 source ran · 1 with results · 1 partial/.test(tallyText(t1)), "and the AI and the header are told so");
  const t2 = tally(dana);
  ok(t2.rows[0].state === "results" && t2.partial === 0, "every directory answered: results");
  const t3 = tally(kase("nobody"));
  ok(t3.rows[0].state === "none" && statusForAi(t3.rows[0]) === "not found", "every directory answered and none had the name: nothing found");
  const t4 = tally(kase("some not asked"));
  ok(t4.rows[0].state === "partial" && t4.rows[0].hasResults === false && statusForAi(t4.rows[0]) !== "not found", "no rows and a directory down is partial, never nothing found");
  const t5 = tally(kase("none answered"));
  ok(t5.rows[0].state === "failed" && t5.rows[0].text === "no directory could be asked" && t5.failed === 1 && /^failed:/.test(statusForAi(t5.rows[0])), "no directory answered: the source failed");
  const t6 = tally(kase("request failed"));
  ok(t6.rows[0].state === "failed" && t6.rows[0].text === "Too many requests. Try again in 30 seconds.", "a request that failed is a failed source");
  ok(tally(kase("old saved case")).ran === 0, "an old case ran no source");
  ok(sourceHasResults(linus.collected.nameResult) && !sourceHasResults(kase("nobody").collected.nameResult), "results means candidates");

  // the notices keep the three states apart
  const second = (c) => N.nameNotices(c.collected)[1];
  ok(N.nameNotices(dana.collected).length === 1, "all answered with rows: only the caveat");
  ok(second(linus).level === "err" && second(linus).title === "1 directory could not be asked." && /OpenAlex \(rate limited\)\. The rows below say nothing about it: unknown, not "nobody there"\./.test(second(linus).text), "rows plus a directory down: says which, and that it is unknown");
  ok(second(kase("nobody")).level === "note" && second(kase("nobody")).title === "No directory had this name." && /Wikidata, GitHub, ORCID, OpenAlex and Bluesky answered, and none lists a person with this name/.test(second(kase("nobody")).text), "all answered, nobody: a clean negative");
  ok(second(kase("some not asked")).level === "err" && second(kase("some not asked")).title === "No one found in the directories that answered." && /GitHub \(rate limited\) and Bluesky \(The source took too long to answer\.\) could not be asked, so this is not a clean negative/.test(second(kase("some not asked")).text), "nobody, with directories down: not a clean negative");
  ok(second(kase("none answered")).level === "err" && second(kase("none answered")).title === "No directory could be asked." && /unknown, not "nobody has this name"/.test(second(kase("none answered")).text), "none answered: unknown");
  ok(N.nameNotices(kase("request failed").collected).length === 1 && N.nameNotices(kase("old saved case").collected).length === 1, "a failed request and an old case show the caveat only; the failed source notice says the rest");
  const nh = nameNoticesHtml(N.nameNotices(kase("some not asked").collected));
  ok(/^<div class="notice " role="note"><span>A name is shared by many people\./.test(nh) && /<div class="notice err" role="note"><strong>No one found in the directories that answered\.<\/strong>/.test(nh), "the notices render with the existing notice classes");
  // the By source card
  const card = sourceCards.nameResult(linus.collected.nameResult);
  ok(/Name search/.test(card) && /10 candidates/.test(card) && /1 not asked/.test(card) && /<dt>GitHub<\/dt><dd>8 kept of 13 the directory returned<\/dd>/.test(card) && /<dt>ORCID<\/dt><dd>answered, no one by this name<\/dd>/.test(card) && /<dt>OpenAlex<\/dt><dd>unknown: rate limited<\/dd>/.test(card), "the card gives one line per directory, three states apart");
  ok(/failed/.test(sourceCards.nameResult(kase("request failed").collected.nameResult)) && /could not be checked/.test(sourceCards.nameResult(kase("request failed").collected.nameResult)), "a failed request gets the failed card");
}

// ---- no candidate becomes a fact, a profile, a cluster member or an account ------------------------
for (const c of [withProfiles(kase("public figure"), "torvalds", "ltorvalds-notes"), withProfiles(kase("qualifiers"), "danawhitfield"), kase("one word")]) {
  const e = ev(c);
  ok(e.facts.length === 0 && e.general.length === 0 && factsFor(e, "anything").length === 0, `${c.name}: no facts`);
  ok(e.identity.views.length === 0 && e.identity.primary === null && e.identity.people === 0 && e.identity.noPrimary === false, `${c.name}: no identity clusters`);
  ok(collectProfiles(c.collected, c.target, c.type).length === 0 && avatarImages(c.collected, c.target, c.type).length === 0, `${c.name}: nothing goes to the avatar comparison`);
  ok(accountsFor(e.items).length === 0 && e.items.every((i) => !String(i.key).startsWith("acct:")), `${c.name}: no account rows`);
  ok(e.items.every((i) => i.tier !== "lead" && i.tier !== "linked" && i.tier !== "matches" && i.tier !== "flag"), `${c.name}: nothing is linked, matched, flagged or a lead`);
  ok(deepDiveUrls(c.collected).length === 0, `${c.name}: nothing for a Deep Dive to read`);
}
{
  const box = el();
  renderNameKnown(box, N.nameKnown(linus.collected));
  ok(box.innerHTML.startsWith('<p class="who-one">No single person is selected. Pick a candidate or a handle to investigate.</p>'), "What we know says no one is selected");
  ok(/A public figure has this name: Linus Torvalds, Finnish software engineer \(born 1969\) \(Wikidata\)\. That does not make them the person you mean\./.test(box.innerHTML), "and carries the notable line");
  const k = N.nameKnown(dana.collected);
  ok(k.lines.length === 1 && k.lines[0] === 'Ranking by location "Leeds", employer or school "Northgate University" and keyword "hydrology". They were compared with what came back and not sent to any directory.', "and the qualifiers in use");
  eq(N.nameKnown(kase("old saved case").collected), { lead: N.NO_ONE_SELECTED, lines: [] }, "an old case says the same and nothing more");
}

// ---- search the web ----------------------------------------------------------------------------------
{
  const s = tierOf(ev(dana), "websearch"), url = (site) => s.find((i) => i.what === site).url;
  eq(s.map((i) => i.what), ["Google", "Bing", "DuckDuckGo", "LinkedIn", "Facebook", "TruePeopleSearch", "FastPeopleSearch", "Spokeo", "BeenVerified", "WhitePages"], "search engines first, then the people-search sites");
  ok(s.every((i) => i.link_kind === "search" && L.LINK_KINDS.includes("search")), "search rows have a link kind of their own");
  ok(url("Google") === "https://www.google.com/search?q=%22Dana%20Whitfield%22%20Leeds%20%22Northgate%20University%22%20hydrology", "the query is the quoted name plus the qualifiers, percent-encoded");
  ok(new URL(url("Google")).searchParams.get("q") === '"Dana Whitfield" Leeds "Northgate University" hydrology' && new URL(url("DuckDuckGo")).searchParams.get("q") === '"Dana Whitfield" Leeds "Northgate University" hydrology', "it decodes to what was typed");
  ok(new URL(url("LinkedIn")).searchParams.get("keywords") === "Dana Whitfield Northgate University" && new URL(url("TruePeopleSearch")).searchParams.get("name") === "Dana Whitfield" && new URL(url("TruePeopleSearch")).searchParams.get("citystatezip") === "Leeds", "people-search sites get the qualifier they have a field for");
  ok(s.find((i) => i.what === "Google").meta === "web search · sends the name and your location, employer and keyword" && s.find((i) => i.what === "Spokeo").meta === "people search · sends the name" && s.find((i) => i.what === "LinkedIn").meta === "people search · sends the name and your employer", "each row says what it sends");
  ok(s.every((i) => { const a = evWhat(i); return /target="_blank"/.test(a) && /rel="noopener noreferrer nofollow"/.test(a) && /data-link-kind="search"/.test(a) && /opens in a new tab/.test(a); }), "they open in a new tab like every other link");
  const plain = tierOf(ev(linus), "websearch");
  ok(plain[0].url === "https://www.google.com/search?q=%22Linus%20Torvalds%22" && plain[0].meta === "web search · sends the name", "with no qualifiers only the name goes");
  // hostile input cannot break out of the query or the href
  const evil = N.searchLinks('Ann "O\'Neil" & <b>', { location: "A&B=1#x", keyword: 'x" onmouseover="1' });
  ok(evil.every((x) => /^https:\/\/[a-z.]+\//.test(x.url) && !/[\s"<>]/.test(x.url)), "every search URL is fully encoded");
  ok(new URL(evil[0].url).searchParams.get("q") === `"Ann O'Neil & <b>" A&B=1#x "x onmouseover= 1"`, "quotes are dropped and everything else is carried as text");
  ok(!/<b>|onmouseover="/.test(evWhat({ tier: "websearch", what: "Google", url: evil[0].url, link_kind: "search", meta: "" })), "and it renders escaped");
  ok(N.searchLinks("", { location: "Leeds" }).length === 0, "no name, no searches");
  // the "no name in a query" rule still holds for everything that is not an outbound search
  for (const c of fx.cases) {
    const name = c.target.toLowerCase();
    const others = ev(c).items.filter((i) => i.tier !== "websearch");
    ok(others.every((i) => i.link_kind !== "search" && [i.url, i.more?.url].filter(Boolean).every((u) => !decodeURIComponent(new URL(u).search).toLowerCase().includes(name))), `${c.name}: no other link carries the name in a query`);
    ok(ev(c).items.filter((i) => i.link_kind === "search").every((i) => i.tier === "websearch" && i.key.startsWith("search:")), `${c.name}: the search kind exists only in the search group`);
  }
  ok(L.classifyLink({ url: "https://example.org/find?q=dana+whitfield", want: "evidence", secrets: ["dana whitfield"] }).link_kind === "evidence" && L.classifyLink({ url: "https://example.org/find?q=jdoe", want: "evidence", secrets: ["jdoe"] }).link_kind === "none", "evidence links still refuse a username in the query");
}

// ---- old saved cases ----------------------------------------------------------------------------------
{
  const c = kase("old saved case"), e = ev(c);
  eq([...new Set(e.items.map((i) => i.tier))], ["websearch"], "an old case (only the typed name) still lists the outbound searches");
  ok(e.items.length === 10 && e.items[5].url === "https://www.truepeoplesearch.com/results?name=Jordan%20Example", "built from the saved name");
  ok(/No directory was searched for this case/.test(briefText(c)), "and its brief says no directory was searched");
  ok(aiPayloadFor(c.collected, c.target, c.type).name_candidates === undefined && aiPayloadFor(c.collected, c.target, c.type).name_search.name === "Jordan Example", "its AI request is what it always was");
  ok(ev({ collected: {}, target: "Not Searched", type: "name" }).items.length === 0, "a name the server refused has no rows at all: nothing is built from the target box");
}

// ---- at a glance ----------------------------------------------------------------------------------------
{
  const t = briefText(linus);
  ok(/info: 10 candidates in 3 of 5 directories \(Wikidata 1, GitHub 8, Bluesky 1\)\. They share the name; they are not one person/.test(t), "how many, across how many directories");
  ok(/info: A public figure has this name: Linus Torvalds, Finnish software engineer \(born 1969\)\. Do not assume the person you mean is this one\./.test(t), "whether a public figure has the name");
  ok(/flag: OpenAlex \(rate limited\) could not be asked, so it is unknown, not "nobody by this name"\./.test(t), "which directories could not be asked");
  ok(/info: Next: pick the person you mean, then investigate their handle\. Nothing is followed until you click\.$/.test(t), "one next step");
  ok(/No location, employer or keyword was given/.test(t), "says no qualifier was given");
  const b = brief(linus).rows.find((r) => /public figure/.test(r.text));
  ok(b.link_kind === "evidence" && b.url === "https://en.wikipedia.org/wiki/Linus_Torvalds" && b.link_label === "Wikipedia", "the public figure line links to Wikipedia as evidence");
  const d = briefText(dana);
  ok(/info: 0 of 6 candidates match location "Leeds", employer or school "Northgate University" and keyword "hydrology"\. 2 GitHub rows have no details to compare until you choose Show profile\./.test(d), "how many match all the qualifiers");
  ok(/ok: 1 of 6 candidates matches location/.test(briefText(withProfiles(kase("qualifiers"), "danawhitfield"))), "and counts a loaded profile");
  ok(/info: Wikidata lists no public figure with exactly this name\./.test(d), "no public figure, when Wikidata answered");
  ok(/info: None of the 5 directories asked lists a person with this name\./.test(briefText(kase("nobody"))), "nobody, all answered");
  ok(/info: Next: try one of the handles built from the name, or open a search\./.test(briefText(kase("nobody"))) && !/pick the person/.test(briefText(kase("nobody"))), "with nobody to pick, the next step is a handle or a search");
  const s = briefText(kase("some not asked"));
  ok(/info: No one by this name in the 3 directories that answered\./.test(s) && /flag: GitHub \(rate limited\) and Bluesky \(The source took too long to answer\.\) could not be asked, so they are unknown/.test(s), "nobody, with directories down");
  ok(/Wikidata could not be asked, so whether a public figure has this name is unknown/.test(briefText(kase("none answered"))), "Wikidata down: a public figure is unknown, not absent");
  ok(/flag: A one-word name matches too many people.*Use a first and last name for a wider search\./.test(briefText(kase("one word"))), "a one-word name gets its own line");
  ok(!/one-word/.test(t), "and a full name does not");
  ok(briefText(kase("request failed"), [{ name: "Name search" }]) === "flag: 1 source failed (Name search), so this picture has gaps. Re-run to fill them.", "a failed request is one line, the failed source");
  ok(brief(linus).actions.length === 0, "the brief follows nothing on its own");
  const one = el(); renderBrief(el(), one, brief(linus));
  ok(/class="brief-list"/.test(one.innerHTML) && !/data-pivot/.test(one.innerHTML), "it renders with the existing brief markup and no pivot button");
}

// ---- what the AI is sent ---------------------------------------------------------------------------------
{
  const c = withProfiles(kase("qualifiers"), "danawhitfield", "dwhitfield-maps");
  const p = aiPayloadFor(c.collected, c.target, c.type, { source_status: { "Name search": "ok" } });
  ok(p.target_type === "name" && p.accounts.length === 0 && p.name_search.name === "Dana Whitfield", "a name request has no accounts");
  eq(Object.keys(p.name_candidates), ["name", "qualifiers", "notable", "candidates"], "the new field");
  eq(Object.keys(p.name_candidates.candidates[0]), ["source", "name", "handle", "description", "location", "affiliation", "name_match", "qualifier_hits"], "each candidate carries the eight text fields and nothing else");
  eq(p.name_candidates.qualifiers, { location: "Leeds", employer: "Northgate University", keyword: "hydrology" }, "the qualifiers travel with it");
  ok(p.name_candidates.notable === null && aiPayloadFor(linus.collected, linus.target, "name").name_candidates.notable.name === "Linus Torvalds", "the notable entry, when there is one");
  const g = p.name_candidates.candidates.find((r) => r.handle === "danawhitfield");
  ok(g.name === "Dána Whitfield" && g.name_match === "exact" && g.qualifier_hits.length === 3 && g.affiliation === "Northgate University", "a loaded GitHub profile is sent as the screen shows it");
  ok(!JSON.stringify(p.name_candidates).includes("http"), "no URL is sent for a candidate");
  ok(aiPayloadFor(kase("request failed").collected, "Dana Whitfield", "name").name_candidates === undefined, "a failed search sends no candidates field");
  ok(aiPayloadFor({ github: { found: true } }, "torvalds", "username").name_candidates === undefined, "no other kind of case sends it");
  ok(aiPayloadFor(kase("nobody").collected, "Zed Quillfeather", "name").name_candidates.candidates.length === 0, "a search that found nobody says so with an empty list");
}

// ---- exports ----------------------------------------------------------------------------------------------
{
  const c = withProfiles(kase("public figure"), "torvalds");
  const md = caseMarkdown({ collected: c.collected, target: c.target, type: c.type, tallyLine: tallyText(tally(c)), now: new Date("2026-11-14T00:00:00Z") });
  ok(md.includes(`> ${N.NAME_NOTICE}`), "Markdown: the caveat line");
  ok(/\*\*1 directory could not be asked\.\*\* OpenAlex \(rate limited\)/.test(md), "Markdown: the directory that could not be asked");
  ok(/## What we know\n- No single person is selected\. Pick a candidate or a handle to investigate\.\n- A public figure has this name: Linus Torvalds/.test(md) && !/Nothing extracted|primary identity/.test(md), "Markdown: what we know, with nobody selected");
  ok(/## Public figure \(1\)\n_Wikidata lists a person[^\n]+_\n- Linus Torvalds · \[Wikipedia\]\(https:\/\/en\.wikipedia\.org\/wiki\/Linus_Torvalds\) · \[Wikidata\]\(https:\/\/www\.wikidata\.org\/wiki\/Q34253\) · Finnish software engineer \(born 1969\) _\(Wikidata\)_/.test(md), "Markdown: the public figure");
  ok(/## People with this name \(10\)/.test(md) && /- \[Linus Torvalds\]\(https:\/\/github\.com\/torvalds\) · @torvalds · Portland, OR · Linux Foundation · exact name _\(GitHub\)_/.test(md), "Markdown: the candidates as the ledger lists them");
  ok(/## Handles to try \(8\)\n_Built from the name\. Nothing has been checked[^\n]+_\n- linustorvalds · given name \+ family name _\(built from the name\)_/.test(md), "Markdown: handles, with their warning");
  ok(/## Search the web \(10\)\n_These open a search on another site\. The name and anything you typed above go to that site\._\n- \[Google\]\(https:\/\/www\.google\.com\/search\?q=%22Linus%20Torvalds%22\)/.test(md), "Markdown: the outbound searches, labelled");
  ok(md.indexOf("## Public figure") < md.indexOf("## People with this name") && md.indexOf("## People with this name") < md.indexOf("## Handles to try") && md.indexOf("## Handles to try") < md.indexOf("## Search the web"), "Markdown: same order as the screen");
  ok(!md.includes(String.fromCharCode(0x2014)), "Markdown: no em dash");

  const e = ev(c);
  const rep = reportHtml({ ai: { summary: "## Case summary\nThree different people.\n\n## People with this name\n- one\n- two" }, target: c.target, items: e.items, facts: e.facts, collected: c.collected, type: "name" });
  ok(rep.startsWith(`<div class="notice" role="note">${N.NAME_NOTICE}</div>`), "report: opens with the caveat");
  ok(!/class="dossier"|class="avatar"|class="fav"|class="tiles"|likely <b>/.test(rep), "report: no dossier, no account tiles, nobody named as the target");
  ok(/<h3>People with this name \(10\)<\/h3>/.test(rep) && /<h3>Public figure \(1\)<\/h3>/.test(rep) && /Three different people\./.test(rep), "report: the model's text, then the candidates");
  ok(reportHtml({ ai: { summary: "plan" }, target: "Jordan Example", items: ev(kase("old saved case")).items, facts: [], collected: {} }).startsWith('<div class="notice"'), "report: a name case is recognised from its rows");
}

// ---- no image anywhere ------------------------------------------------------------------------------------
for (const c of [withProfiles(kase("public figure"), "torvalds", "linus-torvalds-fan"), withProfiles(kase("qualifiers"), "danawhitfield"), kase("one word"), kase("nobody"), kase("old saved case")]) {
  const e = ev(c), facts = el(), b = el();
  renderNameKnown(facts, N.nameKnown(c.collected)); renderBrief(el(), b, brief(c));
  const html = [ledgerHtml(c), nameNoticesHtml(N.nameNotices(c.collected)), facts.innerHTML, b.innerHTML, c.collected.nameResult ? sourceCards.nameResult(c.collected.nameResult) : "",
    reportHtml({ ai: { summary: "## Case summary\ntext" }, target: c.target, items: e.items, facts: e.facts, collected: c.collected, type: "name" })].join("\n");
  ok(!/<img\b|<picture\b|<video\b|<iframe\b|<object\b|<embed\b|background-image|\bsrc=|srcset=/i.test(html), `${c.name}: no image or embedded media in any view`);
  ok(!/avatars\.githubusercontent|icons\.duckduckgo|\.ico\b/.test(html + JSON.stringify(e.items)), `${c.name}: no picture or favicon address anywhere`);
  ok(!/\son[a-z]+\s*=|<script\b|javascript:/i.test(html), `${c.name}: no inline handler or script`);
}

// ---- case files -------------------------------------------------------------------------------------------
{
  const c = withProfiles(kase("qualifiers"), "danawhitfield");
  const file = JSON.stringify(buildCaseFile({ mode: "investigate", target: c.target, type: "name", ran: 1700000000000, collected: c.collected, ai: null, deep: null, notes: "n", purpose: "p" }));
  const r = parseCaseFile(file);
  ok(r.ok && r.entry.kind === "name" && r.entry.type === "INVESTIGATE", "a name case file opens");
  eq(r.entry.results.nameQualifiers, c.collected.nameQualifiers, "the qualifiers round-trip");
  eq(r.entry.results.nameProfiles, c.collected.nameProfiles, "the loaded profiles round-trip");
  eq(r.entry.results.nameResult, N.readNameResult(c.collected.nameResult), "the name result round-trips in its checked shape");
  eq(ev({ collected: r.entry.results, target: r.entry.target, type: r.entry.kind }).items, ev(c).items, "and the opened case builds the same ledger");
  eq(N.readNameResult(N.readNameResult(linus.collected.nameResult)), N.readNameResult(linus.collected.nameResult), "reading is stable: a checked result reads back unchanged");
  eq(N.scrubNames(JSON.parse(JSON.stringify(N.scrubNames(c.collected)))), N.scrubNames(c.collected), "so History keeps what it was given");
  ok(parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "Jordan Example", type: "name", collected: { nameSearch: "Jordan Example" } }))).entry.results.nameSearch === "Jordan Example", "an old name case file still opens");
}
{
  // a hostile case file
  const long = "x".repeat(5000);
  const hostile = {
    nameSearch: "Dana Whitfield",
    nameQualifiers: { location: "<img src=x onerror=alert(1)>", employer: long, keyword: { a: 1 }, __proto__: { polluted: true } },
    nameProfiles: { danawhitfield: { found: true, name: "<script>alert(1)</script>", bio: long, location: "L", company: "C", avatar_url: "https://evil.example/a.png", html: "<b>" }, "../../etc": { found: true }, evil2: { found: true, name: ["x"] } },
    nameResult: {
      name: "Dana Whitfield" + long, parsed: { given: "<script>", single_token: "yes" }, cached: "yes",
      candidates: [
        { source: "GitHub", kind: "account", name: "", handle: "danawhitfield", url: "javascript:alert(1)", description: "<script>alert(1)</script>", location: "", affiliation: "", name_match: "tokens", qualifier_hits: ["keyword", "evil", "location"] },
        { source: "Bluesky", kind: "account", name: "Dana Whitfield", handle: "dana.example.org", url: "https://evil.example/profile/dana.example.org", description: long, location: long, affiliation: long, name_match: "exact", qualifier_hits: "location" },
        { source: "ORCID", kind: "researcher", name: "Dana\u0000 Whitfield\nSecond line", handle: "0000-0002-1825-0097", url: "https://orcid.org/0000-0002-1825-0097", description: "", location: "", affiliation: "", name_match: "exact", qualifier_hits: [] },
        { source: "Evil", kind: "account", name: "x", handle: "x", url: "https://evil.example/x", name_match: "exact" },
        { source: "GitHub", name: "x", handle: "bad handle/../x", url: "https://github.com/bad", name_match: "exact" },
        { source: "GitHub", name: "x", handle: "fine", url: "https://github.com/fine", name_match: "certain" },
        { source: "Wikidata", name: "x", handle: "Q1", url: "https://user:pw@www.wikidata.org/wiki/Q1", name_match: "exact" },
        { source: "GitHub", name: "dupe", handle: "DanaWhitfield", url: "https://github.com/DanaWhitfield", name_match: "exact" },
        "a string", null, 7,
        ...Array.from({ length: 60 }, (_, i) => ({ source: "GitHub", name: "", handle: `filler${i}`, url: `https://github.com/filler${i}`, name_match: "tokens" })),
      ],
      sources: { GitHub: { state: "ok", count: 9999, total: -4 }, Bluesky: { state: "exploded" }, ORCID: { state: "failed", error: "<b>" + long, error_code: "DROP TABLE", error_detail: long }, Evil: { state: "ok", count: 1 }, constructor: { state: "ok" } },
      handles: [{ value: "dana.whitfield", pattern: "given.family" }, { value: "-rf", pattern: "givenfamily" }, { value: "a b", pattern: "givenfamily" }, { value: "x".repeat(65), pattern: "givenfamily" }, { value: "ok", pattern: "<script>" }, "str", ...Array.from({ length: 30 }, (_, i) => ({ value: `h${i}`, pattern: "givenfamily" }))],
      notable: { name: "<img src=x>", description: long, url: "javascript:alert(1)", wikipedia: "https://en.wikipedia.org.evil.example/wiki/X" },
    },
  };
  const r = parseCaseFile(JSON.stringify({ crawlr_case: 1, mode: "investigate", target: "Dana Whitfield", type: "name", ran: 1700000000000, collected: hostile }));
  ok(r.ok, "a hostile name case file still opens, cut down");
  const res = r.entry.results.nameResult;
  ok(res.name.length === 80 && res.parsed.given === "Dana" && res.parsed.single_token === false && res.cached === false, "the name is clipped and the parsed parts are rebuilt, not trusted");
  ok(res.candidates.length === 30, "at most 30 candidates");
  eq(res.candidates.slice(0, 3).map((c) => [c.source, c.handle, c.url]), [["GitHub", "danawhitfield", ""], ["Bluesky", "dana.example.org", ""], ["ORCID", "0000-0002-1825-0097", "https://orcid.org/0000-0002-1825-0097"]], "a javascript: URL or one on another host is dropped; a URL that fits its directory is kept");
  ok(!res.candidates.some((c) => c.source === "Evil" || /bad handle/.test(c.handle) || c.handle === "fine" || c.handle === "DanaWhitfield"), "rows from an unknown directory, with a bad ID, an unknown match word or a repeated login are dropped");
  ok(res.candidates.find((c) => c.handle === "Q1").url === "", "a URL with credentials is dropped");
  ok(res.candidates[1].description.length === 240 && res.candidates[1].location.length === 120 && res.candidates[1].affiliation.length === 200 && res.candidates[1].qualifier_hits.length === 0, "text is clipped to the server's limits, and hits must be a list");
  eq(res.candidates[0].qualifier_hits, ["location", "keyword"], "hits are limited to the three qualifiers, in order");
  ok(res.candidates[2].name === "Dana Whitfield Second line" && res.candidates[2].kind === "researcher", "control characters and line breaks are flattened, and the kind is set from the directory");
  eq(Object.keys(res.sources), ["GitHub", "ORCID"], "only known directories with a known state are kept");
  ok(res.sources.GitHub.count === res.candidates.filter((c) => c.source === "GitHub").length && res.sources.GitHub.total === null, "counts are recounted from the rows that passed");
  ok(res.sources.ORCID.error.length === 200 && res.sources.ORCID.error_code === "unknown" && res.sources.ORCID.error_detail.length === 300, "error text is clipped");
  ok(res.handles.length === 12 && res.handles[0].value === "dana.whitfield" && res.handles.every((h) => /^[A-Za-z0-9._-]{1,64}$/.test(h.value) && !h.value.startsWith("-") && h.pattern in N.PATTERN_WORD), "handles must be valid usernames with a known pattern, 12 at most");
  ok(res.notable.url === "" && res.notable.wikipedia === "" && res.notable.description.length === 240, "the public figure's links must be Wikidata and English Wikipedia");
  eq(r.entry.results.nameQualifiers, { location: "<img src=x onerror=alert(1)>", employer: "x".repeat(80), keyword: "" }, "qualifiers are clipped; text stays text");
  eq(Object.keys(r.entry.results.nameProfiles), ["danawhitfield", "evil2"], "profiles under anything but a login are dropped");
  ok(r.entry.results.nameProfiles.evil2.name === "", "a field that is not text becomes empty");
  eq(Object.keys(r.entry.results.nameProfiles.danawhitfield), ["found", "name", "bio", "location", "company"], "a stored profile keeps four text fields");
  ok(r.entry.results.nameProfiles.danawhitfield.bio.length === 240 && !({}).polluted, "and they are clipped");

  // rendered: everything is text
  const c = { collected: r.entry.results, target: r.entry.target, type: "name" }, e = ev(c), box = el(), known = el();
  renderTiers(box, e.items, N.nameTierView(ledgerTiers(c.target, "name"), e.items), new Set(), "");
  renderNameKnown(known, N.nameKnown(c.collected));
  const html = box.innerHTML + known.innerHTML + nameNoticesHtml(N.nameNotices(c.collected)) + sourceCards.nameResult(res) + reportHtml({ ai: { summary: "x" }, target: c.target, items: e.items, facts: [], collected: c.collected, type: "name" });
  ok(!/<script|<img|<b>x|javascript:/i.test(html) && /&lt;b&gt;x/.test(html) && /&lt;script&gt;alert\(1\)&lt;\/script&gt;/.test(html) && /&lt;img src=x&gt;/.test(html), "a script in a description or a name renders as text");
  ok(hrefs(html).every((u) => /^https:\/\/(www\.wikidata\.org|github\.com|orcid\.org|openalex\.org|bsky\.app|en\.wikipedia\.org|www\.google\.com|www\.bing\.com|duckduckgo\.com|www\.linkedin\.com|www\.facebook\.com|www\.truepeoplesearch\.com|www\.fastpeoplesearch\.com|www\.spokeo\.com|www\.beenverified\.com|www\.whitepages\.com)\//.test(u)), "every link goes to a directory or to a search the investigator opens, and nowhere else");
  const first = e.items.find((i) => i.key === "cand:github:danawhitfield");
  ok(first.what === "<script>alert(1)</script>" && first.link_kind === "none" && !/<a\b/.test(evWhat(first)) && !first.hint, "a candidate whose URL was dropped is plain text");
  ok(e.facts.length === 0 && e.identity.views.length === 0, "and still nothing becomes a fact");
  ok(aiPayloadFor(c.collected, c.target, "name").name_candidates.candidates.every((x) => x.description.length <= 240 && x.name.length <= 120 && x.location.length <= 120 && x.affiliation.length <= 200 && x.handle.length <= 253), "what would go to the AI fits the request model");

  // shapes that are refused outright
  ok(N.readNameResult("x") === null && N.readNameResult([]) === null && N.readNameResult({ candidates: "x", sources: {} }) === null && N.readNameResult({ candidates: [] }) === null, "anything that is not a name result is dropped");
  const junk = parseCaseFile(JSON.stringify({ crawlr_case: 1, mode: "investigate", target: "Dana Whitfield", type: "name", collected: { nameSearch: "Dana Whitfield", nameResult: { junk: true }, nameProfiles: [1], nameQualifiers: "Leeds" } }));
  eq(Object.keys(junk.entry.results), ["nameSearch"], "junk under the three keys is removed and the case opens as an old one");
  eq(N.readNameResult({ error: "<b>" + long, error_code: 5, error_detail: long }), { error: ("<b>" + long).slice(0, 200), error_code: "unknown", error_detail: long.slice(0, 300) }, "a stored failure keeps three clipped strings");
}

console.log(bad ? `${bad} of ${n} name checks failed` : `${n}/${n} name checks passed`);
process.exit(bad ? 1 : 0);
