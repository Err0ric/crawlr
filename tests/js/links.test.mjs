// Link integrity. Builds the ledger, facts, leads, briefs, timeline and recon findings from every
// fixture under tests/js/fixtures and fails if any of them renders a link that claims more than
// the source knew: a bare homepage, a link with no link_kind, an anchor on a row with no public
// URL, or an evidence URL that carries an email address or the username in its query.
// Also checks the link markup, each link check result, and old saved cases. No browser, no network.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };   // ai.js and report.js register delegated listeners on import
const J = "../../static/v2/js/";
const { link, linkOf, sourceTally, sourceCoverage, statusForAi, partialGaps } = await import(J + "core.js");
const L = await import(J + "links.js");
const { buildEvidence, accountsFor, ledgerTiers } = await import(J + "evidence.js");
const { buildFindings } = await import(J + "reconfindings.js");
const { investigateBrief, reconBrief } = await import(J + "brief.js");
const { reconTimeline } = await import(J + "timeline.js");
const { evWhat, renderFacts, renderBrief, renderTiers, patchRow } = await import(J + "workbench.js");
const { sourceCards, profileLink } = await import(J + "renderers.js");
const { reportHtml } = await import(J + "report.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const dir = new URL("./fixtures/", import.meta.url);
const fx = (f) => JSON.parse(fs.readFileSync(new URL(`${f}.json`, dir), "utf8"));

// ---- every fixture becomes one or more cases ----------------------------------------------
// A fixture this function does not understand fails the suite, so a new one cannot be skipped.
const RECON = new Set(["domain", "ip", "asn"]);
function casesOf(name, j) {
  const out = [];
  if (Array.isArray(j.cases)) for (const c of j.cases) out.push({ name: `${name}: ${c.name}`, target: c.target, type: c.type, collected: c.collected });
  if (j.collected && j.target) {
    out.push({ name, target: j.target, type: j.type, collected: j.collected });
    // Newer response shapes recorded beside the old ones.
    const swap = { platformCheckV2: "platformCheck", hibpV2: "hibp", internetdbV2: "shodan", emailPostureV2: "email_posture" };
    const v2 = Object.keys(swap).filter((k) => j[k]);
    if (v2.length) out.push({ name: `${name} (new shapes)`, target: j.target, type: j.type, collected: { ...j.collected, ...Object.fromEntries(v2.map((k) => [swap[k], j[k]])) } });
  }
  for (const [k, v] of Object.entries(j)) if (v && typeof v === "object" && typeof v.hash === "string" && v.verdict) out.push({ name: `${name}: ${k}`, target: v.hash, type: "hash", collected: { hash: v } });
  // Phone answers, new shape and old: each is a phone case of its own.
  for (const [k, v] of Object.entries(j)) if (v && typeof v === "object" && typeof v.input === "string" && ("normalized" in v)) out.push({ name: `${name}: ${k}`, target: v.input, type: "phone", collected: { phone: v } });
  if (j.githubDeep || j.avatarHash) { const t = fx("torvalds"); out.push({ name: `${name} on torvalds`, target: t.target, type: t.type, collected: { ...t.collected, githubDeep: j.githubDeep, avatarHash: j.avatarHash } }); }
  return out;
}
const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
const cases = [];
for (const f of files) { const got = casesOf(f.replace(/\.json$/, ""), fx(f.replace(/\.json$/, ""))); ok(got.length > 0, `fixture ${f} is covered by the link check`); cases.push(...got); }
ok(files.length >= 7 && cases.length >= 12, "every fixture file is read");
// The adult and dating site fixture goes through every invariant below like any other case: its
// rows carry a link kind, never link to a homepage, and mark an unchecked URL as unverified.
ok(cases.some((c) => c.name === "adult" && buildEvidence(c.collected, c.target, c.type).items.filter((i) => i.tier === "adult").length >= 12), "the adult and dating site rows are among the rows checked");

// ---- the rules ------------------------------------------------------------------------------
// The homepage rule is the app's own isBareHome, so this check and the app cannot disagree. What
// differs per row is only the subject: an account row is about the handle and nothing else (a
// site named "Archive.org" does not make https://archive.org/ a profile), a host row is the host.
const EMAIL = /[^\s@/?#&=]+@[^\s@/?#&=]+\.[a-z]{2,}/i;
const hrefs = (html) => [...String(html).matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((m) => m[1].replace(/&amp;/g, "&").replace(/&#39;/g, "'"));
const anchors = (html) => String(html).match(/<a\b[^>]*>[\s\S]*?<\/a>/g) || [];
const personal = (c) => (RECON.has(c.type) || c.type === "hash" ? [] : [c.target, c.target.split("@")[0]].filter((x) => x.length > 2).map((x) => x.toLowerCase()));
const handleOf = (c) => (c.type === "username" ? c.target : "");
// One check per invariant per fixture: every row is looked at, and a failure names the first row.
let looked = 0;
function tracker(c) {
  const seen = new Map();
  const note = (inv, cond, detail = "") => { looked++; const cur = seen.get(inv) || []; if (!cond) cur.push(detail); seen.set(inv, cur); };
  const flush = () => { for (const [inv, fails] of seen) ok(!fails.length, `${c.name}: ${inv}${fails.length ? ` (${fails.length} failed, first: ${fails[0]})` : ""}`); };
  return { note, flush };
}
function checkLink(t, c, where, it, html, subjects) {
  const hs = hrefs(html);
  t.note("every row, fact, lead and finding has a link_kind", L.LINK_KINDS.includes(it.link_kind), where);
  if (it.link_kind === "none") { t.note("kind none renders no href", !hs.length && !it.url, where); return; }
  t.note("a row with a link kind renders its link", hs.length > 0 && !!it.url, where);
  for (const href of hs) {
    t.note("links are http(s) only", /^https?:\/\//.test(href), `${where} ${href}`);
    t.note("no link is a bare homepage", !L.isBareHome(href, subjects), `${where} ${href}`);
    let u; try { u = new URL(href); } catch { continue; }
    if (it.link_kind === "evidence") {
      t.note("no evidence URL holds an email address", !EMAIL.test(decodeURIComponent(href)), `${where} ${href}`);
      t.note("no evidence URL has the username or email in its query", !personal(c).some((p) => decodeURIComponent(u.search).toLowerCase().includes(p)), `${where} ${href}`);
    }
  }
  for (const a of anchors(html)) t.note("every anchor opens in a new tab, says so, and has the icon", /target="_blank"/.test(a) && /rel="noopener noreferrer nofollow"/.test(a) && /<svg class="ext"/.test(a) && /opens in a new tab/.test(a), where);
}
const el = () => ({ innerHTML: "", hidden: false, id: "t" });
const factHtml = (f) => { const e = el(); renderFacts(e, [f]); return e.innerHTML; };
const HOST_ROW = /^(host|sub|tko|redir):/;

let rows = 0, facts = 0, leads = 0, findings = 0;
for (const c of cases) {
  const t = tracker(c);
  if (RECON.has(c.type)) {
    const f = buildFindings(c.collected, c.target, c.type);
    for (const it of f.items) { findings++; checkLink(t, c, `finding ${it.key}`, it, evWhat(it), HOST_ROW.test(it.key) ? [c.target, it.what, L.hostOf(it.what)] : [c.target]); }
    for (const x of f.facts) { facts++; checkLink(t, c, `fact ${x.k}`, x, factHtml(x), [c.target]); }
    for (const k of ["email_posture", "dns_depth"]) for (const x of L.findingsWithEvidence(c.collected[k], c.target)) {
      findings++; checkLink(t, c, `${k} finding "${x.title}"`, x, x.url ? link(x.url, x.link_label, "ev-link", { kind: x.link_kind }) : "", [c.target]);
    }
    const b = reconBrief({ collected: c.collected, items: f.items, failed: [], type: c.type, target: c.target, today: "2026-11-14" });
    for (const r of b.rows) { findings++; const one = el(); renderBrief(el(), one, { rows: [r], actions: [] }); checkLink(t, c, `brief row "${r.text.slice(0, 30)}"`, r, one.innerHTML, [c.target]); }
    for (const e of reconTimeline(c.collected, c.target, "2026-11-14").events) { findings++; checkLink(t, c, `timeline "${e.title}"`, e, link(e.url, e.title, "", { kind: e.link_kind }), [c.target]); }
  } else {
    const ev = buildEvidence(c.collected, c.target, c.type);
    for (const it of ev.items) {
      if (it.tier === "lead") leads++; else rows++;
      const subjects = it.key.startsWith("acct:") ? [handleOf(c)] : it.tier === "lead" ? [it.lead.value] : it.tier === "hosts" ? [it.what] : [handleOf(c)];
      checkLink(t, c, `row ${it.key}`, it, evWhat(it), subjects);
      if (it.link_kind === "none" && it.key.startsWith("acct:")) t.note("an account row with no link says how to check", typeof it.hint === "string" && it.hint.length > 20, it.key);
      if (it.link_kind === "templated_unverified") t.note("an unverified URL is marked for sighted and screen reader users", /class="lk lk-unverified"/.test(evWhat(it)) && /title="unverified URL"/.test(evWhat(it)) && /<span class="lk-flag" aria-hidden="true">unverified URL<\/span>/.test(evWhat(it)) && /\(unverified URL, opens in a new tab\)/.test(evWhat(it)), it.key);
    }
    const all = [...ev.facts, ...ev.general, ...ev.identity.views.flatMap((v) => v.facts)];
    // A fact may link to the site its own value names (a "Website" fact), and to nothing barer.
    for (const x of all) { facts++; checkLink(t, c, `fact ${x.k}`, x, factHtml(x), [handleOf(c), ...(x.k === "Website" ? [x.v, L.hostOf(x.v)] : [])]); }
    const b = investigateBrief({ collected: c.collected, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: c.type, target: c.target });
    for (const r of b.rows) { const one = el(); renderBrief(el(), one, { rows: [r], actions: [] }); checkLink(t, c, `brief row "${r.text.slice(0, 30)}"`, r, one.innerHTML, [handleOf(c)]); }
    // The AI payload and the cards say the same thing about each URL as the ledger does.
    for (const a of accountsFor(ev.items)) t.note("each AI account carries link_kind, and no URL when there is none", L.LINK_KINDS.includes(a.link_kind) && (a.link_kind !== "none" || a.url === ""), a.site);
    for (const id of ["sherlock", "maigret", "platformCheck"]) {
      if (!c.collected[id]) continue;
      for (const a of anchors(sourceCards[id](c.collected[id], c.collected.linkChecks))) {
        t.note("card profile links carry their kind, nofollow and the icon", /data-link-kind="(verified_profile|templated_unverified)"/.test(a) && /rel="noopener noreferrer nofollow"/.test(a) && /<svg class="ext"/.test(a), `${id} ${hrefs(a)[0]}`);
        t.note("no card links to a bare homepage", !L.isBareHome(hrefs(a)[0], [handleOf(c)]), `${id} ${hrefs(a)[0]}`);
      }
    }
  }
  t.flush();
}
ok(rows > 100 && facts > 20 && leads > 3 && findings > 30 && looked > 2000, `the fixtures exercise rows, facts, leads and findings (${rows}, ${facts}, ${leads}, ${findings}; ${looked} row-level looks)`);

// ---- link kinds on the audit targets ---------------------------------------------------------
const er = fx("err0ric"), lf = fx("links"), tv = fx("torvalds"), em = fx("email"), rc = fx("recon"), hs = fx("hash");
const erC = { ...er.collected, platformCheck: er.platformCheckV2 };
const row = (ev, key) => ev.items.find((i) => i.key === key);
{
  const ev = buildEvidence(erC, er.target, er.type);
  const d = row(ev, "acct:discord");
  ok(d && d.link_kind === "none" && d.url === "" && /Discord has no public profile page\./.test(d.hint), "the Discord row is not a link, and says how to check");
  ok(!/<a\b/.test(evWhat(d)) && /How to check/.test(evWhat(d)) && />Discord</.test(`>${evWhat(d)}`), "it renders as plain text with the hint in the row");
  ok(row(ev, "acct:github").link_kind === "verified_profile" && row(ev, "acct:github").url === "https://github.com/Err0ric", "GitHub's API profile URL is a verified profile link, not the templated one Sherlock built");
  ok(row(ev, "acct:youtube").link_kind === "verified_profile" && row(ev, "acct:instagram").link_kind === "verified_profile", "a row the enricher or the platform check read is a verified profile");
  ok(row(ev, "acct:hackerone").link_kind === "templated_unverified" && row(ev, "acct:giphy").link_kind === "templated_unverified", "a Sherlock row nothing read is a templated, unverified URL");
  ok(row(ev, "acct:linkedin").link_kind === "templated_unverified" && row(ev, "acct:facebook").link_kind === "templated_unverified", "a platform check that was blocked or unclear leaves a templated URL");
  ok(row(ev, "acct:cashapp").link_kind === "templated_unverified" && row(ev, "acct:cashapp").url === "https://cash.app/$Err0ric" && row(ev, "acct:cashapp").hint === L.howToCheck("CashApp") && /How to check/.test(evWhat(row(ev, "acct:cashapp"))), "a cash.app/$handle page keeps its link, and its hint, because a server cannot check it");
  ok(L.classifyLink({ url: "https://user:pw@example.org/u/x", want: "templated_unverified" }).link_kind === "none" && !L.pendingChecks([{ key: "acct:x", what: "x", link_kind: "templated_unverified", url: "ftp://example.org/x" }]).length, "a URL with credentials or another scheme is never a link and never sent");
  ok(!L.isBareHome("https://torvalds.substack.com/", ["torvalds"]) && L.isBareHome("https://substack.com/", ["torvalds"]), "a handle that is a host label makes the URL a profile, not a homepage");
  ok(row(ev, "acct:itch.io").link_kind === "templated_unverified", "a profile on its own subdomain is not mistaken for a homepage");
  ok(row(ev, "acct:trakt").tier === "noise" && row(ev, "acct:trakt").link_kind === "templated_unverified", "noisy rows are templated too");
  ok(ev.items.every((i) => L.LINK_KINDS.includes(i.link_kind)), "every row has a link kind");
  ok(ev.facts.every((f) => f.link_kind === "evidence" && f.url === "https://github.com/Err0ric"), "GitHub facts link to the profile they came from, as evidence");
}
{
  const c = lf.cases[1], ev = buildEvidence(c.collected, c.target, c.type);
  for (const s of ["discord", "whatsapp", "signal", "skype", "cashapp"]) ok(row(ev, `acct:${s}`).link_kind === "none" && row(ev, `acct:${s}`).hint === L.howToCheck(s) && L.howToCheck(s).length > 30, `${s} has no public username URL: no link, and its own hint`);
  ok(row(ev, "acct:example forum").link_kind === "none" && row(ev, "acct:example forum").hint === L.GENERIC_HINT, "any other homepage URL becomes text with the general hint");
  ok(row(ev, "acct:example pages").link_kind === "templated_unverified", "handle.site.tld is a profile URL");
  ok(L.pendingChecks(ev.items).length === 1, "rows with no link are never sent to the link check");
  // 6. a site whose name is also its hostname: the homepage is still a homepage
  for (const s of ["archive.org", "last.fm", "itch.io"]) ok(row(ev, `acct:${s}`).link_kind === "none" && row(ev, `acct:${s}`).url === "" && !/<a\b/.test(evWhat(row(ev, `acct:${s}`))) && row(ev, `acct:${s}`).hint === L.GENERIC_HINT, `the ${s} homepage is not a profile link, whatever the site is called`);
  ok(L.isBareHome("https://archive.org/", ["jdoe_example"]) && L.isBareHome("https://www.last.fm/", ["jdoe_example"]) && L.isBareHome("https://itch.io/", ["jdoe_example"]) && !L.isBareHome("https://jdoe_example.itch.io/", ["jdoe_example"]), "the check uses the app's own homepage rule");
}
ok(L.isBareHome("https://discord.com") && L.isBareHome("https://discord.com/") && L.isBareHome("https://www.site.com/?ref=home", ["jdoe"]) && !L.isBareHome("https://site.com/jdoe") && !L.isBareHome("https://site.com/?user=jdoe", ["jdoe"]) && !L.isBareHome("https://github.com/github", ["github"]) && L.isBareHome("https://github.com", ["github"]), "the homepage rule");
ok(L.classifyLink({ url: "javascript:alert(1)", want: "verified_profile" }).link_kind === "none" && L.classifyLink({ url: "discord.com/x", want: "templated_unverified" }).link_kind === "none" && L.classifyLink({ url: "", want: "evidence" }).link_kind === "none", "only absolute http(s) URLs are links");
ok(L.classifyLink({ url: "https://example.org/find?q=jdoe@example.org", want: "evidence", secrets: ["jdoe@example.org"] }).link_kind === "none" && L.classifyLink({ url: "https://example.org/find?u=JDoe_Old", want: "evidence", secrets: ["jdoe_old"] }).link_kind === "none", "an evidence link never carries the email or the username in its query");

// ---- link markup ------------------------------------------------------------------------------
{
  const a = link("https://example.org/u/x", "Example");
  ok(/^<a href="https:\/\/example\.org\/u\/x" target="_blank" rel="noopener noreferrer nofollow" class="lk">Example<svg class="ext"[^>]*aria-hidden="true"/.test(a) && /<span class="sr-only"> \(opens in a new tab\)<\/span><\/a>$/.test(a), "a link opens in a new tab with noopener, noreferrer and nofollow, an icon and words for a screen reader");
  const u = link("https://example.org/u/x", "Example", "", { kind: "templated_unverified" });
  ok(/class="lk lk-unverified"/.test(u) && /data-link-kind="templated_unverified"/.test(u) && /title="unverified URL"/.test(u) && /\(unverified URL, opens in a new tab\)/.test(u) && /<\/a><span class="lk-flag" aria-hidden="true">unverified URL<\/span>$/.test(u), "an unverified URL is dashed by class, titled, read out, and says so in visible text");
  ok(!/tabindex/.test(u) && /^<a href=/.test(u), "an unverified link stays a real, focusable anchor");
  ok(link("https://example.org/u/x", "Example", "", { kind: "none" }) === "Example" && link("", "Example") === "Example" && link("javascript:alert(1)", "x") === "x" && linkOf({ url: "https://example.org/u/x", link_kind: "none", what: "Example" }) === "Example", "kind none, a blank URL and a non-http URL are plain text");
  ok(link("https://example.org/?a=1&b=<2>", "<b>x</b>").includes("&lt;b&gt;x&lt;/b&gt;") && !link("https://example.org/\"onmouseover=\"x", "y").includes('"onmouseover="x"'), "text and URLs are escaped");
  ok(/class="lk btn btn-sm"/.test(link("https://example.org/a", "Open", "btn btn-sm")), "a class can be added");
  const labelled = evWhat({ what: "445/tcp", url: "https://internetdb.shodan.io/1.2.3.4", link_kind: "evidence", link_label: "InternetDB record", meta: "" });
  ok(/^<span class="ev-title">445\/tcp <a href="https:\/\/internetdb\.shodan\.io\/1\.2\.3\.4"[^>]*class="lk ev-link"[^>]*>InternetDB record/.test(labelled), "an evidence link is a labelled anchor after the text");
}

// ---- the link check: each state ----------------------------------------------------------------
{
  const base = buildEvidence(erC, er.target, er.type);
  const sent = L.pendingChecks(base.items);
  ok(sent.length > 10 && sent.every((r) => /^acct:/.test(r.id) && r.site && /^https?:/.test(r.url)) && !sent.some((r) => ["acct:github", "acct:discord", "acct:youtube"].includes(r.id)), "only templated account rows are sent: never a read profile or a row with no link");
  ok(L.pendingChecks(base.items, "noise").length === 1 && L.pendingChecks(base.items, "unverified").length === sent.length - 1, "rows are sent per group");
  const many = Array.from({ length: 60 }, (_, i) => ({ id: `acct:s${i}`, site: `s${i}`, url: `https://example.org/u/${i}` }));
  ok(L.batches(many).map((b) => b.length).join() === "25,25,10" && L.CHECK_BATCH === 25 && L.CHECK_PARALLEL === 2, "batches of 25, two in flight");
  const checks = L.mergeChecks(null, sent, lf.verify.results);
  ok(!checks["acct:notsent"] && !checks["acct:openstreetmap"] && Object.keys(checks).length === 6, "a result for a row that was not sent, or with an unknown state, is dropped");
  const ev = buildEvidence({ ...erC, linkChecks: checks }, er.target, er.type);
  const v = row(ev, "acct:hackerone");
  ok(v.link_kind === "verified_profile" && v.url === "https://hackerone.com/err0ric?type=user" && v.check === "verified" && /class="lk"/.test(evWhat(v)) && !/unverified URL/.test(evWhat(v)) && /<span class="lk-state ok">page checked<\/span>/.test(evWhat(v)), "verified: a solid link to final_url, and the row says page checked");
  const nf = row(ev, "acct:giphy");
  ok(nf.link_kind === "none" && nf.url === "" && nf.gone === true && !/<a\b/.test(evWhat(nf)) && /page not found \(The site answered 404: there is no page at this address\)/.test(evWhat(nf)), "not_found: the link is removed and the row says page not found");
  const unv = ev.items.filter((i) => i.tier === "unverified");
  ok(unv.length === base.items.filter((i) => i.tier === "unverified").length && unv[unv.length - 1].key === "acct:giphy" && unv.filter((i) => i.gone).length === 1, "it moves to the end of its group and is never deleted");
  const bl = row(ev, "acct:librarything");
  ok(bl.link_kind === "templated_unverified" && /lk-unverified/.test(evWhat(bl)) && /<span class="lk-state warn">Blocked by site \(The site asks visitors to sign in[^<]*\)<\/span>/.test(evWhat(bl)), "blocked: says Blocked by site and keeps the dashed link");
  const un = row(ev, "acct:houzz");
  ok(un.link_kind === "templated_unverified" && /lk-unverified/.test(evWhat(un)) && /could not be checked \(The site took too long to answer\)/.test(evWhat(un)), "unknown: keeps the dashed link and says it could not be checked");
  const np = row(ev, "acct:virustotal");
  ok(np.link_kind === "none" && !/<a\b/.test(evWhat(np)) && /VirusTotal user pages need a sign-in/.test(evWhat(np)) && /no public page/.test(evWhat(np)), "no_public_url: no link, and the hint from the verifier");
  const home = row(ev, "acct:7cups");
  ok(home.link_kind === "verified_profile" && home.url === "https://www.7cups.com/@Err0ric", "a final_url that is a homepage is not used");
  ok(base.items.every((i) => row(ev, i.key)?.tier === i.tier), "the link check never moves a row to another tier");
  ok(L.pendingChecks(ev.items).length === sent.length - 6, "a row that was checked is not sent again");
  // a stale or hostile stored check
  const stale = buildEvidence({ ...erC, linkChecks: { "acct:hackerone": { state: "not_found", url: "https://hackerone.com/someone-else" }, "acct:github": { state: "not_found", url: "https://github.com/Err0ric" }, "acct:giphy": { state: "verified", url: "https://giphy.com/Err0ric", final_url: "javascript:alert(1)" }, "acct:f3.cool": { state: "not_found" }, "lead:x": { state: "verified" }, "acct:houzz": "verified" } }, er.target, er.type);
  ok(row(stale, "acct:hackerone").link_kind === "templated_unverified" && !row(stale, "acct:hackerone").check, "a check of a different URL is ignored");
  ok(row(stale, "acct:github").link_kind === "verified_profile" && !row(stale, "acct:github").gone, "a stored check never takes a read profile's link away");
  ok(row(stale, "acct:giphy").url === "https://giphy.com/Err0ric" && row(stale, "acct:giphy").link_kind === "verified_profile" && !row(stale, "acct:houzz").check && !row(stale, "acct:f3.cool").check && row(stale, "acct:f3.cool").link_kind === "templated_unverified", "a final_url that is not http(s), a malformed entry, and a check that does not say which URL it checked, are ignored");
  // exports and the AI payload
  const acc = accountsFor(ev.items);
  const a = (s) => acc.find((x) => x.site === s);
  ok(a("HackerOne").link_kind === "verified_profile" && a("HackerOne").link_check === "verified" && a("Giphy").link_kind === "none" && a("Giphy").url === "" && a("Giphy").link_check === "not_found" && a("Discord").link_kind === "none" && a("Houzz").link_kind === "templated_unverified" && a("GitHub").link_kind === "verified_profile" && !("link_check" in a("GitHub")), "the AI payload's accounts carry link_kind and the check result");
  ok(L.mdLink(un) === "[Houzz](https://houzz.com/user/Err0ric) (unverified URL)" && L.mdLink(nf) === "Giphy" && L.mdLink(row(ev, "acct:discord")) === "Discord" && L.mdLink(v) === "[HackerOne](https://hackerone.com/err0ric?type=user)", "Markdown marks an unverified URL and prints a row with no URL without a link");
  ok(/page not found/.test(L.mdNote(nf)) && /how to check: Discord has no public/.test(L.mdNote(row(ev, "acct:discord"))), "the Markdown note carries the check result and the hint");
  const cards = sourceCards.sherlock(erC.sherlock, checks);
  ok(/Discord(?!<svg)/.test(cards) && !/href="https:\/\/discord\.com\/?"/.test(cards) && /data-link-kind="verified_profile"[^>]*>7Cups/.test(cards) && /data-link-kind="templated_unverified"[^>]*>GitHub/.test(cards) && /^Giphy <span class="dim small">page not found<\/span>$/.test(profileLink("Giphy", "https://giphy.com/Err0ric", "templated_unverified", "Err0ric", checks)), "the Sherlock card follows the same link kinds and check results as the ledger");
  ok(profileLink("Discord", "https://discord.com", "templated_unverified", "Err0ric") === "Discord", "a card never links a homepage");
  // the report
  const html = reportHtml({ ai: { summary: "## Case summary\nx\n## Platform footprint\ny", profile: {} }, target: er.target, items: ev.items, facts: ev.facts, collected: erC });
  ok(/<div class="tile [^"]*"[^>]*>(?:(?!<\/div>).)*Discord/s.test(html) && !/href="https:\/\/discord\.com/.test(html) && !/href="#"/.test(html), "the report shows a row with no URL as a tile that is not a link");
  ok(/class="tile [^"]*unv[^"]*" href="https:\/\/houzz\.com\/user\/Err0ric"[^>]*data-link-kind="templated_unverified"/.test(html) && /\(unverified URL\)/.test(html) && /rel="noopener noreferrer nofollow"/.test(html), "the report marks an unverified URL");
  // the link check as a source
  const src = L.linkCheckSource({ linkChecks: checks });
  const t = sourceTally({ linkCheck: src }, { linkCheck: "Link check" });
  ok(src.link_check === true && src.results.length === 6 && sourceCoverage(src).answered === 4 && t.rows[0].state === "partial" && /4 of 6 links checked/.test(t.rows[0].text), "the link check is a source: blocked and unclear links make it partial");
  ok(t.rows[0].listed === true && partialGaps(t.rows).length === 0, "blocked links are rows of their own, so a partial link check does not make the tiles read at least");
  const failed = L.linkCheckSource({ linkChecks: checks, linkCheck: { error: "Too many requests.", error_code: "rate_limited", error_detail: "429" } });
  const tf = sourceTally({ linkCheck: failed }, { linkCheck: "Link check" });
  ok(tf.failed === 1 && tf.rows[0].state === "failed" && /^failed: Too many requests/.test(statusForAi(tf.rows[0])), "a verifier failure is a failed source, through the same tally as every other source");
  const afterFail = buildEvidence({ ...erC, linkCheck: { error: "x", error_code: "network" } }, er.target, er.type);
  ok(afterFail.items.every((i) => !i.gone && !i.check) && row(afterFail, "acct:giphy").link_kind === "templated_unverified", "a verifier failure never changes a row to not found");
  const allBlocked = sourceTally({ linkCheck: L.linkCheckSource({ linkChecks: { "acct:a": { state: "blocked" }, "acct:b": { state: "unknown" } } }) }, { linkCheck: "Link check" });
  ok(allBlocked.rows[0].state === "failed" && allBlocked.rows[0].text === "no link could be checked", "when no link could be checked the source is failed, not empty");
  ok(L.linkCheckSource({}) === null && sourceTally({ linkCheck: null }, { linkCheck: "Link check" }).ran === 0, "a case with no link check has no such source");
  ok(/4 of 6 pages exist|2 of 6 pages exist/.test(sourceCards.linkCheck(src)) && /hackerone/.test(sourceCards.linkCheck(src)), "the link check has a card");
  // a case file keeps the results
  const file = JSON.stringify(buildCaseFile({ mode: "investigate", target: er.target, type: er.type, ran: Date.now() - 1000, collected: { ...erC, linkChecks: checks } }));
  const back = parseCaseFile(file);
  ok(back.ok && JSON.stringify(back.entry.results.linkChecks) === JSON.stringify(checks) && row(buildEvidence(back.entry.results, back.entry.target, back.entry.kind), "acct:giphy").gone === true, "a case file carries the link checks and they apply when it is opened");
}

// ---- evidence links -------------------------------------------------------------------------------
{
  const E = L.evidenceUrl;
  ok(E.internetdb("216.198.79.1") === "https://internetdb.shodan.io/216.198.79.1" && E.shodanHost("216.198.79.1") === "https://www.shodan.io/host/216.198.79.1", "ports and CVEs: the InternetDB or Shodan page for that address");
  ok(E.dns("darkwire.tech", "MX") === "https://dns.google/query?name=darkwire.tech&type=MX" && E.crtsh("darkwire.tech") === "https://crt.sh/?q=darkwire.tech" && E.rdap("darkwire.tech") === "https://rdap.org/domain/darkwire.tech" && E.wayback("darkwire.tech") === "https://web.archive.org/web/*/darkwire.tech", "DNS, certificate, RDAP and Wayback templates");
  ok(E.virustotal(hs.eicarNew.hash) === `https://www.virustotal.com/gui/file/${hs.eicarNew.hash}` && E.otx(hs.eicarNew.hash) === `https://otx.alienvault.com/indicator/file/${hs.eicarNew.hash}`, "hash templates");
  ok(E.dns("x y", "TXT") === "" && E.dns("a.example", "ANY") === "" && E.internetdb("not an ip") === "" && E.rdap("jdoe@example.org") === "" && E.crtsh("torvalds") === "" && E.virustotal("abc") === "" && E.rdap("example.org/?q=jdoe") === "", "nothing but a domain, an IP or a hash goes into an evidence URL");
  const d = (t, data) => L.dnsFindingEvidence(t, "example.org", data)?.url || "";
  ok(d("No DMARC record") === "https://dns.google/query?name=_dmarc.example.org&type=TXT" && d("DMARC is monitor-only (p=none)") === d("No DMARC record") && d("Subdomains are not protected (sp=none)") === d("No DMARC record"), "DMARC findings look up _dmarc TXT");
  ok(d("No SPF record") === "https://dns.google/query?name=example.org&type=TXT" && d("SPF ends in +all") === d("No SPF record"), "SPF findings look up the domain's TXT");
  ok(d("DKIM key published (google, selector1)") === "https://dns.google/query?name=google._domainkey.example.org&type=TXT" && d("No DKIM key at common selectors") === "", "a DKIM finding looks up its selector, and has no link without one");
  ok(d("No MX records") === "https://dns.google/query?name=example.org&type=MX" && d("No MTA-STS") === "https://dns.google/query?name=_mta-sts.example.org&type=TXT" && d("TLS reporting enabled") === "https://dns.google/query?name=_smtp._tls.example.org&type=TXT" && d("BIMI record published") === "https://dns.google/query?name=default._bimi.example.org&type=TXT", "MX, MTA-STS, TLS-RPT and BIMI");
  ok(d("No CAA record") === "https://dns.google/query?name=example.org&type=CAA" && d("DNSSEC is not enabled") === "https://dns.google/query?name=example.org&type=DNSKEY" && d("DNSSEC keys with no DS record") === "https://dns.google/query?name=example.org&type=DS" && d("Wildcard DNS: any subdomain resolves (1.2.3.4)") === "", "CAA and DNSSEC, and no link for a wildcard");
  const c = { ...rc.collected, shodan: { ...rc.internetdbV2, ports: [22, 445, 443], vulns: ["CVE-2024-0001"] }, email_posture: { ...rc.collected.email_posture, mail_enabled: true, findings: [{ level: "flag", title: "No DMARC record", detail: "x" }, { level: "flag", title: "No SPF record", detail: "y" }] }, lookalikes: { results: [{ domain: "darkwlre.tech", technique: "homoglyph", mail: true, ips: [] }] }, portscan: { ip: "216.198.79.1", results: [{ port: 8080, open: true, service: "http-alt" }] } };
  const f = buildFindings(c, rc.target, "domain");
  const it = (k) => f.items.find((i) => i.key === k);
  const idb = "https://internetdb.shodan.io/216.198.79.1";
  ok(it("port:445").tier === "flag" && it("port:445").url === idb && it("port:445").link_label === "InternetDB record" && it("port:22").url === idb && it("port:443").url === idb, "every indexed port, flagged or not, links to the InternetDB record and is not deduplicated away");
  ok(it("port:8080").link_kind === "none" && it("port:8080").url === "", "a port from the live scan has no public page");
  ok(it("cve:CVE-2024-0001").url === "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" && it("cve:CVE-2024-0001").more.url === idb && hrefs(evWhat(it("cve:CVE-2024-0001"))).join() === `https://nvd.nist.gov/vuln/detail/CVE-2024-0001,${idb}`, "a CVE links to its NVD entry and to the record that reported it");
  ok(it("mail:No DMARC record").url === "https://dns.google/query?name=_dmarc.darkwire.tech&type=TXT" && it("mail:No SPF record").url === "https://dns.google/query?name=darkwire.tech&type=TXT" && it("mail:No DMARC record").link_label === "DNS lookup", "email flags link to the lookup for their record");
  ok(it("look:darkwlre.tech").url === "https://rdap.org/domain/darkwlre.tech", "a lookalike links to its registration record");
  const sh = buildFindings({ ...c, shodan: { ...c.shodan, source: "shodan" } }, rc.target, "domain");
  ok(sh.items.find((i) => i.key === "port:22").url === "https://www.shodan.io/host/216.198.79.1" && sh.items.find((i) => i.key === "port:22").link_label === "Shodan record", "Shodan rows link to the Shodan host page");
  ok(f.facts.find((x) => x.k === "Registrar").url === "https://rdap.org/domain/darkwire.tech" && f.facts.find((x) => x.k === "TLS issuer").url === "https://crt.sh/?q=darkwire.tech" && f.facts.find((x) => x.k === "Certificates").url === "https://crt.sh/?q=darkwire.tech", "WHOIS facts link to RDAP and certificate facts to the logs");
  const ip = buildFindings({ shodan: { ...c.shodan, target: "216.198.79.1" }, ssl: rc.collected.ssl }, "216.198.79.1", "ip");
  ok(ip.items.find((i) => i.key === "port:22").url === idb && ip.facts.every((x) => !/crt\.sh|rdap\.org|dns\.google/.test(x.url)), "an IP case builds no domain lookups");
  // breaches and hashes
  const b2 = buildEvidence({ hibp: em.hibpV2 }, em.target, "email");
  ok(b2.items.filter((i) => i.tier === "flag").every((i) => i.link_kind === "evidence" && /^https:\/\/xposedornot\.com\/xposed\/#/.test(i.url)), "a breach row links to its own reference page");
  const b1 = buildEvidence({ hibp: { breaches: ["ExampleBreach"] } }, em.target, "email");
  ok(b1.items[0].link_kind === "none" && b1.items[0].hint === L.BREACH_HINT && !/<a\b/.test(evWhat(b1.items[0])) && /xposedornot\.com/.test(evWhat(b1.items[0])), "a breach with no page names xposedornot.com as plain text, never as a homepage link");
  const h = buildEvidence({ hash: hs.malicious }, hs.malicious.hash, "hash");
  const hv = h.items.find((i) => i.key === "hash:verdict");
  ok(hv.link_kind === "evidence" && hv.url === E.virustotal(hs.malicious.hash) && hv.link_label === "VirusTotal", "a hash verdict links to its VirusTotal page");
  const h2 = buildEvidence({ hash: hs.eicarNew }, hs.eicarNew.hash, "hash").items.find((i) => i.key === "hash:verdict");
  ok(h2.more?.url === E.otx(hs.eicarNew.hash) && h2.more.label === "OTX" && hrefs(evWhat(h2)).length === 2, "and to the OTX indicator page when OTX answered");
  // timeline and brief
  const tl = reconTimeline(rc.collected, rc.target, "2026-11-14").events;
  ok(tl.find((e) => e.title === "Domain registered").url === "https://rdap.org/domain/darkwire.tech" && tl.filter((e) => e.source === "Certificate logs").every((e) => /^https:\/\/crt\.sh\/\?q=/.test(e.url)) && tl.every((e) => L.LINK_KINDS.includes(e.link_kind)), "timeline rows link to where the date can be checked");
  const br = reconBrief({ collected: c, items: f.items, failed: [], type: "domain", target: rc.target, today: "2026-11-14" }).rows;
  ok(br.some((r) => /spoofed|Email spoofing/.test(r.text) && r.url === "https://dns.google/query?name=_dmarc.darkwire.tech&type=TXT") && br.every((r) => L.LINK_KINDS.includes(r.link_kind)), "brief rows carry their evidence link where one exists");
}

// ---- old saved cases ------------------------------------------------------------------------------
{
  const c = lf.cases[2], ev = buildEvidence(c.collected, c.target, c.type);
  ok(row(ev, "acct:discord").link_kind === "none" && row(ev, "acct:reddit").link_kind === "verified_profile" && row(ev, "acct:reddit").url === "https://www.reddit.com/user/jdoe_old/" && row(ev, "acct:github").link_kind === "templated_unverified", "an old username case gets link kinds through the same code");
  ok(row(ev, "acct:instagram").link_kind === "templated_unverified" && /profile URL answered, check by hand/.test(row(ev, "acct:instagram").meta), "an old platform check hit was a bare response, so its URL is unverified");
  const card = sourceCards.platformCheck(c.collected.platformCheck);
  ok(anchors(card).length === 1 && anchors(card).every((a) => /data-link-kind="templated_unverified"/.test(a)) && !/OnlyFans|check by hand/.test(card), "the old platform check card marks its URLs unverified, and no longer lists the old manual OnlyFans row");
  const e = lf.cases[3], ee = buildEvidence(e.collected, e.target, e.type);
  ok(row(ee, "acct:spotify").link_kind === "none" && row(ee, "acct:spotify").hint === L.REGISTERED_HINT && row(ee, "acct:discord").link_kind === "none" && row(ee, "acct:gravatar").link_kind === "verified_profile", "an old email case: a registration check has no page to link, Gravatar's record does");
  ok(ee.items.filter((i) => /^breach:/.test(i.key)).every((i) => i.link_kind === "none"), "old breach rows (names only) have no link");
  const old = buildEvidence(tv.collected, tv.target, tv.type);
  ok(old.items.every((i) => L.LINK_KINDS.includes(i.link_kind)) && old.items.filter((i) => i.tier === "unverified" && i.url).every((i) => i.link_kind === "templated_unverified"), "a case saved before link kinds existed is classified when it is opened");
  ok(ledgerTiers(tv.target, tv.type).length === 11, "the link check adds no tier");
}

// ---- 1. a case that was opened, not run, never starts fetches on its own ---------------------------
{
  const P = L.checkPolicy;
  ok(P({ live: true }).auto === true && P({ live: true }).confirm === false, "a run started in this session may start the link check on its own");
  ok(P({ live: false }).auto === false && P({ live: false }).allowed === true && P({ live: false }).confirm === false, "a case opened from History is never checked on its own: it waits for the button");
  ok(P({ live: false, imported: true }).auto === false && P({ live: true, imported: true }).auto === false && P({ imported: true }).confirm === true, "a case file is never checked on its own, and asks first");
  ok(!P({ live: true, on: false }).allowed && !P({ live: true, running: true }).allowed && !P({ live: true, type: "email" }).allowed && !P({ live: true, handleOk: false }).auto, "switch off, a run in flight, or a non-username case: no check at all");
  ok(/come from the case file you opened/.test(L.checkConfirmText(17)) && /17 addresses/.test(L.checkConfirmText(17)) && /1 address /.test(L.checkConfirmText(1)), "the confirm for a case file says the links come from the file");
  const ev = buildEvidence(erC, er.target, er.type);
  const box = el(), tiers = ledgerTiers(er.target, er.type);
  renderTiers(box, ev.items, tiers, new Set(), "", { check: (tier) => L.pendingChecks(ev.items, tier).length });
  const btns = [...box.innerHTML.matchAll(/<button type="button" class="btn btn-sm tier-check" data-check-tier="(\w+)" data-count="(\d+)">Check these links \((\d+)\)<\/button>/g)].map((m) => `${m[1]}:${m[3]}`);
  ok(btns.join() === `unverified:${L.pendingChecks(ev.items, "unverified").length},noise:1`, "a group with unchecked links has a Check these links button with the count in its header");
  ok(/<\/button><button type="button" class="btn btn-sm tier-check"[^>]*>[^<]*<\/button><\/h2>/.test(box.innerHTML), "the button sits in the group header, beside the toggle and not inside it");
  const none = el(); renderTiers(none, ev.items, tiers, new Set(), "", { check: () => 0 });
  const plain = el(); renderTiers(plain, ev.items, tiers, new Set(), "");
  ok(!/tier-check/.test(none.innerHTML) && !/tier-check/.test(plain.innerHTML), "no button when there is nothing to check or the check is off");
  const src = fs.readFileSync(new URL(J + "linkcheck.js", import.meta.url), "utf8");
  ok(/if \(!allowed\(\) \|\| !auto\(\) \|\| halted \|\| queue\.failed\) return;/.test(src) && /else if \(allowed\(\) && auto\(\) && !halted\) start\(e\.detail\.tier\)/.test(src), "the checker only starts by itself behind the auto rule");
}

// ---- 2. pacing, 429 and retry -------------------------------------------------------------------
{
  const flush = async () => { for (let i = 0; i < 8; i++) await new Promise((r) => setImmediate(r)); };
  // A virtual clock: sleep() resolves only when the test advances time.
  function rig(sendImpl, opts = {}) {
    const st = { t: 0, timers: [], calls: [], maxFlying: 0, flying: 0, batches: [], fails: [], pauses: [], idles: [], cancels: [], answered: [] };
    st.q = L.makeCheckQueue({
      now: () => st.t, sleep: (ms) => new Promise((r) => st.timers.push({ at: st.t + ms, r })), ...opts,
      send: async (rws, signal) => { st.calls.push({ at: st.t, n: rws.length }); st.flying++; st.maxFlying = Math.max(st.maxFlying, st.flying); try { return await sendImpl(rws, st.calls.length, signal, st); } finally { st.flying--; } },
      onBatch: (rws, res) => { st.batches.push(rws.length); st.answered.push(...rws.map((r) => r.id)); }, onFail: (e, dropped) => st.fails.push({ e, dropped: dropped.length }),
      onPause: (p) => st.pauses.push(p), onIdle: (i) => st.idles.push(i), onCancel: (rws) => st.cancels.push(rws.length),
    });
    st.advance = async (to) => { st.t = to; const due = st.timers.filter((x) => x.at <= to); st.timers = st.timers.filter((x) => x.at > to); for (const x of due) x.r(); await flush(); };
    return st;
  }
  const mk = (nRows, p = "s") => Array.from({ length: nRows }, (_, i) => ({ id: `acct:${p}${i}`, site: `${p}${i}`, url: `https://example.org/u/${p}${i}` }));
  const okSend = async (rws) => rws.map((r) => ({ id: r.id, state: "unknown" }));
  {
    // two groups of 200 rows: 16 batches
    const st = rig(okSend);
    st.q.add("unverified", mk(200, "a")); st.q.add("noise", mk(200, "b"));
    await flush();
    ok(st.calls.length === 10 && L.CHECK_PER_MINUTE === 10 && st.maxFlying <= 2, "at most 10 calls go out in a minute across every group, two at a time");
    ok(st.pauses.length === 1 && st.pauses[0].reason === "pace" && st.pauses[0].until === 60000 && !st.fails.length && st.q.paused, "the 11th batch waits for the window instead of being sent into a 429");
    await st.advance(59000);
    ok(st.calls.length === 10, "nothing more goes out before the window clears");
    await st.advance(60000);
    ok(st.calls.length === 16 && st.answered.length === 400 && new Set(st.answered).size === 400 && st.idles.length === 1 && !st.idles[0].stopped && !st.fails.length, "then the rest go, every row is answered once, and no source is marked failed");
  }
  {
    // the server says 429 with Retry-After
    const st = rig(async (rws, nth) => { if (nth === 2) throw Object.assign(new Error("slow down"), { status: 429, retryAfter: 7 }); return okSend(rws); });
    st.q.add("unverified", mk(60));
    await flush();
    ok(!st.fails.length && !st.q.failed && st.pauses.at(-1).reason === "rate_limited" && st.pauses.at(-1).until === 7000 && st.calls.length === 2, "a 429 pauses the check for Retry-After seconds and does not fail the source");
    await st.advance(7000);
    ok(st.answered.length === 60 && new Set(st.answered).size === 60 && st.idles.length === 1 && !st.fails.length, "after the wait the same batch is sent again and the check finishes");
  }
  {
    // 429 with no Retry-After: wait until the minute window clears
    const st = rig(async (rws, nth, _s, s2) => { if (nth === 2 && s2.t === 0) throw Object.assign(new Error("slow down"), { status: 429 }); return okSend(rws); });
    st.q.add("unverified", mk(50));
    await flush();
    ok(st.pauses.at(-1).reason === "rate_limited" && st.pauses.at(-1).until === 60000 && !st.fails.length, "without Retry-After it waits until the minute window clears");
    const waiting = st.q.stop();
    await flush();
    ok(waiting.length === 25 && st.idles.length === 1 && st.idles[0].stopped === true && !st.q.paused && st.answered.length === 25, "Stop works while paused: the waiting rows come back and nothing more is sent");
    await st.advance(60000);
    ok(st.calls.length === 2, "and the old timer starts nothing");
  }
  {
    // a 429 that never clears is, in the end, a failure
    const st = rig(async () => { throw Object.assign(new Error("slow down"), { status: 429, retryAfter: 1 }); });
    st.q.add("unverified", mk(5));
    for (let i = 1; i <= 8; i++) { await flush(); await st.advance(i * 1000); }
    ok(st.fails.length === 1 && st.calls.length === L.CHECK_RATE_WAITS + 1, "rate limiting that never clears stops after a bounded number of waits");
  }
  {
    // a real failure, then Try again
    let broken = true;
    const st = rig(async (rws) => { if (broken) throw Object.assign(new Error("boom"), { status: 500, code: "server" }); return okSend(rws); });
    st.q.add("unverified", mk(60));
    await flush();
    ok(st.fails.length === 1 && st.fails[0].dropped === 60 && st.q.failed && !st.answered.length && !st.idles.length, "a real failure fails the source once and hands back every row that was not answered");
    st.q.add("unverified", mk(60));
    await flush();
    ok(st.calls.length === 2, "nothing is sent while it is failed");
    broken = false; st.q.clearFailure(); st.q.add("unverified", mk(60));
    await flush();
    ok(!st.q.failed && st.answered.length === 60 && st.idles.length === 1, "Try again clears the failure and the same rows are checked, with no need to reopen the case");
  }
  {
    // closing a group cancels only that group's batches
    const hold = [];
    const st = rig((rws, _n, signal) => new Promise((res, rej) => { hold.push(() => res(rws.map((r) => ({ id: r.id, state: "unknown" })))); signal.addEventListener("abort", () => rej(Object.assign(new Error("Cancelled"), { code: "cancelled" }))); }));
    st.q.add("unverified", mk(25, "a")); st.q.add("noise", mk(50, "b"));
    await flush();
    const back = st.q.stop("noise");
    await flush();
    ok(back.length === 25 && st.cancels.join() === "25" && !st.fails.length, "closing a group cancels its batch in flight and returns its waiting rows, and that is not a failure");
    hold[0](); await flush();
    ok(st.answered.length === 25 && st.answered[0] === "acct:a0" && st.idles.length === 1 && st.idles[0].stopped, "the other group's batch still lands");
  }
  // core.js: a 429 reaches the caller with its status and Retry-After
  const { post } = await import(J + "core.js");
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 429, statusText: "Too Many Requests", headers: { get: (k) => (k === "Retry-After" ? "23" : null) }, json: async () => ({ detail: "Too many requests." }) });
  const err = await post("/api/recon/verify-links", {}).catch((e) => e);
  globalThis.fetch = realFetch;
  ok(err.status === 429 && err.retryAfter === 23 && err.code === "rate_limited", "post() reports a 429 with the server's Retry-After");
}

// ---- 3. a stored check cannot point a row somewhere else --------------------------------------------
{
  const only = lf.cases[0];   // Sherlock rows only: GitHub is a templated, unverified URL here
  const gh = "https://www.github.com/Err0ric";
  const withCheck = (check, key = "acct:github") => row(buildEvidence({ ...only.collected, linkChecks: { [key]: check } }, only.target, only.type), key);
  const evil = withCheck({ state: "verified", url: gh, final_url: "https://evil.example/login" });
  ok(evil.link_kind === "verified_profile" && evil.url === gh && !/evil\.example/.test(evWhat(evil)), "a final_url on another host is ignored: the row keeps the URL that was checked");
  ok(withCheck({ state: "verified", url: gh, final_url: "https://github.com/err0ric" }).url === "https://github.com/err0ric" && withCheck({ state: "verified", url: gh, final_url: "https://gist.github.com/err0ric" }).url === "https://gist.github.com/err0ric", "a final_url on the same registrable host is used");
  ok(withCheck({ state: "verified", url: gh, final_url: "https://github.com.evil.example/Err0ric" }).url === gh && withCheck({ state: "verified", url: gh, final_url: "https://user:pw@github.com/Err0ric" }).url === gh && withCheck({ state: "verified", url: gh, final_url: "//evil.example/x" }).url === gh && withCheck({ state: "verified", url: gh, final_url: "https://notgithub.com/Err0ric" }).url === gh, "lookalike hosts, credentials and scheme-relative addresses are refused");
  ok(L.safeFinalUrl("https://x.com/jdoe", "https://twitter.com/jdoe") === "https://x.com/jdoe" && L.safeFinalUrl("https://www.threads.com/@jdoe", "https://www.threads.net/@jdoe") === "https://www.threads.com/@jdoe" && L.safeFinalUrl("https://x.com/jdoe", "https://threads.net/jdoe") === "", "the known aliases twitter.com/x.com and threads.net/threads.com count as the same site");
  ok(L.regHost("https://a.b.example.co.uk/x") === "example.co.uk" && L.regHost("https://www.github.com/x") === "github.com" && L.safeFinalUrl("https://other.co.uk/u", "https://example.co.uk/u") === "", "the registrable host is compared, not a suffix");
  const lied = withCheck({ state: "not_found", url: gh, evidence: "Call 555 0100 to restore this account <b>now</b>", hint: "Sign in at https://evil.example to see it" });
  ok(lied.check === "not_found" && !lied.check_evidence && /<span class="lk-state ">page not found<\/span>/.test(evWhat(lied)) && !/555|evil/.test(evWhat(lied)), "evidence text from a stored check is dropped unless it is one of the verifier's own sentences");
  const known = withCheck({ state: "unknown", url: gh, evidence: "The site took too long to answer." });
  ok(known.check_evidence === "The site took too long to answer." && /could not be checked \(The site took too long to answer\)/.test(evWhat(known)) && /lk-unverified/.test(evWhat(known)), "a known sentence is kept, and unknown keeps the dashed link");
  const np = withCheck({ state: "no_public_url", url: gh, hint: "Sign in at https://evil.example to see it" });
  ok(np.link_kind === "none" && np.hint === L.NO_PAGE_HINT, "a hint from a stored check is never shown: the row gets CrawlR's own");
  const dz = withCheck({ state: "no_public_url", url: "https://discord.com", hint: "evil" }, "acct:discord");
  ok(dz.hint === L.howToCheck("Discord"), "and a named site keeps the hint from the client table");
  ok(L.readCheck({ state: "deleted" }) === null && L.readCheck({ state: "verified", url: 5, final_url: {}, evidence: [], hint: 1 }).final_url === "" && Object.keys(L.readChecks({ "acct:x": { state: "verified" }, "__proto__x": { state: "verified" }, ["acct:" + "y".repeat(90)]: { state: "verified" } })).join() === "acct:x", "state, types and ids are validated again on every read");
  // the live answer is shown as the server gave it; the same text read back from a file is not
  const sent = [{ id: "acct:github", url: gh, site: "GitHub" }];
  const liveChecks = L.mergeChecks(null, sent, [{ id: "acct:github", state: "unknown", evidence: "Not checked this time: the site is being asked too often.", final_url: "", cached: false }]);
  const liveRow = row(buildEvidence({ ...only.collected, linkChecks: liveChecks }, only.target, only.type), "acct:github");
  const fileRow = row(buildEvidence({ ...only.collected, linkChecks: JSON.parse(JSON.stringify(liveChecks)) }, only.target, only.type), "acct:github");
  ok(/could not be checked \(Not checked this time: the site is being asked too often\)/.test(evWhat(liveRow)) && liveRow.link_kind === "templated_unverified" && fileRow.check === "unknown" && !fileRow.check_evidence && /<span class="lk-state ">could not be checked<\/span>/.test(evWhat(fileRow)), "a new server sentence shows in the live session; once stored it must be on the known list");
  const fileHint = row(buildEvidence({ ...erC, linkChecks: JSON.parse(JSON.stringify(L.mergeChecks(null, L.pendingChecks(buildEvidence(erC, er.target, er.type).items), lf.verify.results))) }, er.target, er.type), "acct:virustotal");
  ok(fileHint.link_kind === "none" && fileHint.hint === L.NO_PAGE_HINT && fileHint.check_evidence === undefined, "after a reload the verifier's hint for an unnamed site becomes the generic one");
}

// ---- 4. an address the verifier would refuse is not sent, and says so ---------------------------------
{
  const long = `https://example.org/u/jdoe_long?${"x".repeat(700)}`, edge = `https://example.org/e/${"y".repeat(600 - 22)}`;
  const c = { sherlock: { username: "jdoe_long", results: [{ site: "LongSite", url: long }, { site: "EdgeSite", url: edge }, { site: "Short", url: "https://example.org/u/jdoe_long" }] } };
  const ev = buildEvidence(c, "jdoe_long", "username");
  const sent = L.pendingChecks(ev.items);
  ok(edge.length === 600 && sent.map((r) => r.site).sort().join() === "EdgeSite,Short" && sent.every((r) => r.url === row(ev, r.id).url), "a URL over the verifier's limit is not sent, and a sent URL is never cut short");
  const lr = row(ev, "acct:longsite");
  ok(lr.check === "unknown" && lr.link_kind === "templated_unverified" && /could not be checked \(address too long\)/.test(evWhat(lr)) && /lk-unverified/.test(evWhat(lr)) && /address too long/.test(L.mdNote(lr)), "the row says it could not be checked because the address is too long");
  const merged = L.mergeChecks(null, sent, sent.map((r) => ({ id: r.id, state: "verified", final_url: "" })));
  ok(buildEvidence({ ...c, linkChecks: merged }, "jdoe_long", "username").items.filter((i) => i.check === "verified").length === 2, "every row that was sent matches its answer");
}

// ---- the verifier's contract: ports, "not checked this time", and its sentence list ---------------------
{
  const c = { sherlock: { username: "jdoe_port", results: [{ site: "PortSite", url: "https://example.org:8443/u/jdoe_port" }, { site: "Tls", url: "https://example.org:443/t/jdoe_port" }, { site: "Plain", url: "http://example.org:80/p/jdoe_port" }, { site: "Fine", url: "https://example.org/u/jdoe_port" }, { site: "Six", url: "https://[2001:db8::1]/u/jdoe_port" }] } };
  const ev = buildEvidence(c, "jdoe_port", "username");
  ok(L.pendingChecks(ev.items).map((r) => r.site).sort().join() === "Fine,Six", "a URL with an explicit port, the default ones included, is never sent");
  ok(["portsite", "tls", "plain"].every((k) => row(ev, `acct:${k}`).check === "unknown" && /could not be checked \(address names a port\)/.test(evWhat(row(ev, `acct:${k}`))) && /lk-unverified/.test(evWhat(row(ev, `acct:${k}`)))), "those rows say they could not be checked, and keep the dashed link");
  ok(L.hasPort("https://a.example:443/x") && L.hasPort("https://u:p@a.example:1/") && L.hasPort("https://[::1]:80/x") && !L.hasPort("https://[::1]/x") && !L.hasPort("https://a.example/x:80") && !L.hasPort("https://a.example/?q=:80"), "the port test reads the raw address");
  const sent = [{ id: "acct:fine", url: "https://example.org/u/jdoe_port", site: "Fine" }, { id: "acct:six", url: "https://[2001:db8::1]/u/jdoe_port", site: "Six" }];
  const merged = L.mergeChecks(null, sent, [{ id: "acct:fine", state: "unknown", evidence: L.THROTTLED_EVIDENCE }, { id: "acct:six", state: "unknown", evidence: "The site took too long to answer." }]);
  ok(!merged["acct:fine"] && merged["acct:six"].state === "unknown" && L.pendingChecks(buildEvidence({ ...c, linkChecks: merged }, "jdoe_port", "username").items).map((r) => r.id).join() === "acct:fine", "a link that was not checked this time is not stored, so it can be checked later");
  const srcPy = fs.readFileSync(new URL("../../modules/link_verify.py", import.meta.url), "utf8");
  const dict = srcPy.slice(srcPy.indexOf("EVIDENCE = {"), srcPy.indexOf("\n}", srcPy.indexOf("EVIDENCE = {")));
  const server = [...dict.matchAll(/"\w+":\s*"((?:[^"\\]|\\.)*)"/g)].map((m) => JSON.parse(`"${m[1]}"`));
  ok(server.length >= 30 && JSON.stringify(server) === JSON.stringify(L.KNOWN_EVIDENCE), `the client's list of verifier sentences matches EVIDENCE in modules/link_verify.py (${server.length} server, ${L.KNOWN_EVIDENCE.length} client)`);
  ok(server.includes(L.THROTTLED_EVIDENCE), "the throttled sentence is one of them");
  const glue = fs.readFileSync(new URL(J + "linkcheck.js", import.meta.url), "utf8");
  ok(/isTransient\(r\)[^\n]*asked\.delete\(r\.id\); deferred\.add\(r\.id\)/.test(glue) && /waitingIn\(sec\.dataset\.tier, false\)/.test(glue), "the checker reopens a throttled row for the button only, never for an automatic start");
}

// ---- 5. a result landing does not take keyboard focus away ----------------------------------------------
{
  // A small stand-in for the two rows the ledger would hold.
  function fakeLedger(keys) {
    const doc = { activeElement: null };
    const body = { rows: [], querySelectorAll: () => body.rows };
    const mkEl = (name) => ({ name, focus() { doc.activeElement = this; } });
    for (const key of keys) {
      const linkEl = mkEl(`link:${key}`), box = mkEl(`box:${key}`);
      const what = { html: `<a class="lk lk-unverified" href="#">x</a>`, set innerHTML(v) { this.html = v; if (doc.activeElement === linkEl) doc.activeElement = null; this.link = /<a\b[^>]*class="lk[ "]/.test(v) ? mkEl(`newlink:${key}`) : null; }, get innerHTML() { return this.html; }, link: linkEl, contains: (x) => !!x && x === what.link, querySelector: (s) => (s === "a.lk" ? what.link : null) };
      const cls = new Set();
      const r = { dataset: { row: key }, what, box, parentElement: body, classList: { add: (c) => cls.add(c), contains: (c) => cls.has(c) }, querySelector: (s) => (s === ".what" ? what : s === "input[type=checkbox]" ? box : null),
        after(other) { body.rows = body.rows.filter((x) => x !== other); body.rows.splice(body.rows.indexOf(r) + 1, 0, other); if (doc.activeElement === other.box || doc.activeElement === other.what.link) doc.activeElement = null; } };
      body.rows.push(r);
    }
    return { doc, body, el: { querySelectorAll: () => body.rows }, row: (k) => body.rows.find((r) => r.dataset.row === k) };
  }
  const item = (key, over) => ({ key, what: key.slice(5), url: `https://example.org/u/${key.slice(5)}`, link_kind: "templated_unverified", meta: "", ...over });
  let f = fakeLedger(["acct:a", "acct:b", "acct:c"]);
  f.doc.activeElement = f.row("acct:a").what.link;
  patchRow(f.el, item("acct:a", { link_kind: "verified_profile", check: "verified" }), f.doc);
  ok(f.doc.activeElement && f.doc.activeElement.name === "newlink:acct:a", "focus on a row's link moves to the patched link");
  f = fakeLedger(["acct:a", "acct:b", "acct:c"]);
  f.doc.activeElement = f.row("acct:a").what.link;
  patchRow(f.el, item("acct:a", { link_kind: "none", url: "", check: "not_found", gone: true }), f.doc);
  ok(f.doc.activeElement && f.doc.activeElement.name === "box:acct:a" && f.body.rows.map((r) => r.dataset.row).join() === "acct:b,acct:c,acct:a", "when the link became plain text and the row moved, focus goes to that row's checkbox");
  f = fakeLedger(["acct:a", "acct:b", "acct:c"]);
  f.doc.activeElement = f.row("acct:a").box;
  patchRow(f.el, item("acct:a", { link_kind: "none", url: "", check: "not_found", gone: true }), f.doc);
  ok(f.doc.activeElement && f.doc.activeElement.name === "box:acct:a", "focus on the checkbox survives the move to the end of the group");
  f = fakeLedger(["acct:a", "acct:b", "acct:c"]);
  const elsewhere = f.row("acct:b").what.link; f.doc.activeElement = elsewhere;
  patchRow(f.el, item("acct:a", { link_kind: "none", url: "", check: "not_found", gone: true }), f.doc);
  patchRow(f.el, item("acct:c", { link_kind: "verified_profile", check: "verified" }), f.doc);
  ok(f.doc.activeElement === elsewhere, "focus anywhere else is left alone");
  f = fakeLedger(["acct:a"]); f.doc.activeElement = null;
  patchRow(f.el, item("acct:a", { link_kind: "verified_profile", check: "verified" }), f.doc);
  ok(f.doc.activeElement === null && patchRow(f.el, item("acct:zzz"), f.doc) === false, "and nothing is focused when nothing was");
}

console.log(bad ? `${bad} of ${n} link checks failed` : `${n}/${n} link checks passed`);
if (bad) process.exit(1);
