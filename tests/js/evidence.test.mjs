// The ledger, leads, breach and hash rows, recon findings and the source tally, checked against
// trimmed copies of responses recorded for the audit targets (tests/js/fixtures). No browser, no network.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
const { caseAnalysis, buildEvidence, accountsFor, breachList, breachMeta, hashView, hashCoverage, collectProfiles, sourcePlan, isFreeMail, ledgerTiers, TIERS, isFinding, factsFor, avatarImages, tierCounts } = await import("../../static/v2/js/evidence.js");
const { investigateBrief, reconBrief, resolvedHosts, mailState, noMailOpen } = await import("../../static/v2/js/brief.js");
const { buildFindings, takeoverForAi, TIERS: RECON_TIERS } = await import("../../static/v2/js/reconfindings.js");
const { sourceTally, tallyText, sourceCoverage, statusForAi } = await import("../../static/v2/js/core.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = (f) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${f}.json`, import.meta.url), "utf8"));
const row = (ev, key) => ev.items.find((i) => i.key === key);
const tier = (ev, t) => ev.items.filter((i) => i.tier === t);
const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");

// ---- B. tiers ---------------------------------------------------------------------
ok(TIERS.map((t) => t.id).join() === "flag,info,linked,matches,different,unverified,adult,lead,similar,hosts,noise", "tier order");
ok(TIERS.filter((t) => ["linked", "matches", "different", "unverified", "noise"].includes(t.id)).map((t) => t.title).join("|") === "Linked|Exists (matches)|Exists (different person)|Unverified|Known noisy sites", "tier titles");
ok(TIERS.find((t) => t.id === "different").open === false, "different people are collapsed by default");
const tv = fx("torvalds"), er = fx("err0ric"), em = fx("email"), hs = fx("hash"), rc = fx("recon"), extra = fx("identity-extras");
{
  const ev = buildEvidence(tv.collected, tv.target, tv.type);
  ok(row(ev, "acct:github").tier === "linked" && /GitHub's own record for this handle/.test(row(ev, "acct:github").meta), "GitHub's API answer for the searched handle is linked");
  ok(tier(ev, "linked").length === 1, "nothing else is linked without a strong signal");
  ok(row(ev, "acct:snapchat").tier === "matches" && /name on profile: Linus Torvalds/.test(row(ev, "acct:snapchat").meta) && /same name/.test(row(ev, "acct:snapchat").meta), "Snapchat (same name) exists and matches, and says why");
  ok(row(ev, "acct:medium").tier === "different" && /name on profile: Patricia Torvalds/.test(row(ev, "acct:medium").meta), "Medium is a different person and the row says whose name is on it");
  ok(row(ev, "acct:pinterest").tier === "different" && row(ev, "acct:threads").tier === "different" && row(ev, "acct:pinterest").person === "Marco Migozzi", "Pinterest and Threads are a different person");
  ok(row(ev, "acct:x").tier === "matches" && /no name on profile/.test(row(ev, "acct:x").meta), "a read profile with no real name carries no conflict");
  ok(row(ev, "acct:paypal").tier === "unverified" && row(ev, "acct:tumblr").tier === "unverified", "a reported handle that was never read is unverified");
  ok(row(ev, "acct:disqus").tier === "noise" && !ev.identity.views.some((v) => v.sites.includes("Disqus")), "noisy sites stay noise and are kept out of clustering");
  ok(!ev.items.some((i) => i.tier === "confirmed" || i.tier === "possible"), "the old tiers are gone");
  // C. what we know: the primary cluster only
  ok(ev.facts.some((f) => f.k === "Name" && f.v === "Linus Torvalds" && f.source === "GitHub") && ev.facts.some((f) => f.k === "Location" && f.v === "Portland, OR"), "facts come from the primary cluster and name their source");
  ok(!ev.facts.some((f) => /Patricia|Marco|GamerNine|Pavel|Nikolai/.test(f.v)), "no other person's name is among the facts");
  ok(!ev.identity.views.flatMap((v) => v.facts).some((f) => /streams live on Twitch|Watch awesome|on Patreon|is on Facebook|is on Snapchat/.test(f.v)), "boilerplate bios never become facts");
  const marco = ev.identity.views.find((v) => v.label === "Marco Migozzi");
  ok(marco && !marco.primary && factsFor(ev, marco.id).some((f) => f.v === "Marco Migozzi" && f.source === "Pinterest") && !factsFor(ev, marco.id).some((f) => f.v === "Linus Torvalds"), "another cluster's facts can be viewed, and hold only that cluster");
  ok(ev.identity.views[0].primary && /GitHub's own record/.test(ev.identity.views[0].why), "the primary view says why it is primary");
  // brief
  const b = text(investigateBrief({ collected: tv.collected, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "username", target: tv.target }));
  // Other people under the handle are said once, in the assessment, and counted as people.
  const says = caseAnalysis(ev, { collected: tv.collected, target: tv.target, type: "username" }).assessment.lines.map((l) => `${l.level}: ${l.text}`).join("\n");
  ok(/flag: \d+ accounts belong to \d+ other people whose name conflicts with Linus Torvalds/.test(says) && !/different people use this handle/.test(b), "the assessment counts people, not names, and the brief does not repeat it");
  ok(Number(says.match(/belong to (\d+) other people/)[1]) === ev.identity.views.filter((v) => v.different).length && ev.identity.views.filter((v) => v.different).length === new Set(tier(ev, "different").map((i) => i.person)).size, "it counts exactly the people the ledger calls different");
  ok(row(ev, "acct:steam").tier === "matches" && /name does not conflict/.test(row(ev, "acct:steam").meta) && !/GamerNine/.test(b), "a single nickname is not counted as another person");
  ok(/1 linked account, \d+ that exist and match, \d+ that belong to a different person, and \d+ unverified/.test(b), "the brief uses the tier vocabulary");
  ok(/2 profiles carry the name "Linus Torvalds"/.test(b), "the brief says which profiles support the primary identity");
  // AI payload
  const acc = accountsFor(ev.items);
  ok(acc.find((a) => a.site === "GitHub").status === "linked" && acc.find((a) => a.site === "Medium").status === "different" && /Patricia Torvalds/.test(acc.find((a) => a.site === "Medium").note), "accountsFor sends the tier and whose name is on a different-person row");
  ok(acc.every((a) => ["linked", "matches", "different", "unverified"].includes(a.status)) && !acc.some((a) => /deadspace/.test(a.site)), "only account rows go to the AI, never leads");
  ok(JSON.stringify(tierCounts(ev.items)) === JSON.stringify({ linked: 1, matches: tier(ev, "matches").length, different: tier(ev, "different").length, unverified: tier(ev, "unverified").length }), "tier counts cover account rows only");
  // F. a lead from a profile outside the primary cluster says so
  const lead = row(ev, "lead:domain:deadspace.wtf");
  ok(lead && lead.tier === "lead" && lead.action.label === "Open in Recon" && lead.action.pivot === "recon" && /Bluesky bio/.test(lead.meta) && /not tied to the target/.test(lead.meta), "a URL in a Bluesky bio becomes a domain lead that names its origin");
  ok(!isFinding(lead) && isFinding(row(ev, "acct:github")), "leads are not findings");
}
{
  // D + E: avatar hashes and the GitHub deep pull feed clustering, facts and leads
  const c = { ...tv.collected, githubDeep: extra.githubDeep, avatarHash: extra.avatarHash };
  const ev = buildEvidence(c, tv.target, tv.type);
  ok(row(ev, "acct:keybase").tier === "linked" && /same avatar/.test(row(ev, "acct:keybase").meta), "the same avatar as GitHub makes Keybase linked");
  ok(row(ev, "acct:x").tier === "matches" && row(ev, "acct:duolingo").tier === "matches", "two default avatars never link (X and Duolingo stay unlinked)");
  ok(ev.facts.some((f) => f.k === "Organisations" && f.v === "example-org") && ev.facts.some((f) => f.k === "Languages" && f.v === "C, Shell") && ev.facts.some((f) => f.k === "Commit email" && f.v === "committer@example.org" && f.source === "GitHub details"), "GitHub details add Organisations, Languages and Commit email facts");
  const mail = row(ev, "lead:email:committer@example.org");
  ok(mail && mail.action.label === "Investigate this" && mail.action.pivot === "investigate" && /GitHub commit in torvalds\/linux/.test(mail.meta), "a commit email is a lead with Investigate this");
  ok(!row(ev, "lead:domain:social.example.org") && row(ev, "lead:url:https://social.example.org/@torvalds")?.action === null, "a social account on a multi-user host is a plain link, not a domain to recon");
  ok(avatarImages(tv.collected, tv.target, tv.type).length === 1 && avatarImages(tv.collected, tv.target, tv.type)[0].id === "acct:github", "avatar images come from read profiles with an https image");
  const failedAv = buildEvidence({ ...tv.collected, avatarHash: { error: "timeout", error_code: "timeout" } }, tv.target, tv.type);
  ok(row(failedAv, "acct:github").tier === "linked" && row(failedAv, "acct:snapchat").tier === "matches", "a failed avatar comparison leaves clusters to the other signals");
  const failedGh = buildEvidence({ ...tv.collected, github: { found: null, error: "rate limited", error_code: "rate_limited" } }, tv.target, tv.type);
  ok(!row(failedGh, "acct:github") || row(failedGh, "acct:github").tier !== "linked", "a failed GitHub lookup links nothing");
}
{
  const ev = buildEvidence(er.collected, er.target, er.type);
  ok(row(ev, "acct:github").tier === "linked", "Err0ric: GitHub is linked");
  ok(row(ev, "acct:youtube").tier === "matches" && row(ev, "acct:threads").tier === "matches" && tier(ev, "different").length === 0, "Eric and Eric Henderson are not different people");
  const view = ev.identity.views.find((v) => v.label === "Eric Henderson");
  ok(view && view.sites.includes("YouTube") && view.sites.includes("Threads"), "they are one cluster");
  const b = text(investigateBrief({ collected: er.collected, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "username", target: er.target }));
  ok(!/different (person|people) use this handle/.test(b) && !/Eric on YouTube.*Eric Henderson on/.test(b), "the brief does not call Eric and Eric Henderson a conflict");
  // old platform check shape: a bare 200 is unverified
  ok(row(ev, "acct:instagram").tier === "unverified" && /check by hand/.test(row(ev, "acct:instagram").meta), "old platform check: a URL that answered is unverified");
  // platform check v2
  const v2 = buildEvidence({ ...er.collected, platformCheck: er.platformCheckV2 }, er.target, er.type);
  ok(row(v2, "acct:instagram").tier === "matches" && /profile read/.test(row(v2, "acct:instagram").meta) && /profile page names @err0ric/.test(row(v2, "acct:instagram").meta), "platform check v2: state found is a read profile, not a lead to check by hand");
  ok(row(v2, "acct:linkedin").tier === "unverified" && /^Blocked by site \(login wall\)/.test(row(v2, "acct:linkedin").meta), "state blocked is unverified and labelled Blocked by site");
  ok(row(v2, "acct:facebook").tier === "unverified" && /^Could not tell/.test(row(v2, "acct:facebook").meta), "state unknown is unverified");
  ok(!row(v2, "acct:tiktok"), "not_found adds nothing");
  // An older platform check listed OnlyFans as "check by hand". It is an adult site: without the
  // adult mode on the case it shows nowhere, and with it on it is a row of that group only.
  ok(er.platformCheckV2.results.some((r) => r.platform === "OnlyFans") && !v2.items.some((i) => /onlyfans/i.test(i.key + i.what + i.url)), "an old manual OnlyFans row shows nowhere in a case without the adult mode");
  const v2a = buildEvidence({ ...er.collected, platformCheck: er.platformCheckV2, adultMode: true }, er.target, er.type);
  ok(v2a.items.filter((i) => /onlyfans/i.test(i.key + i.what)).map((i) => `${i.key}:${i.tier}`).join() === "adult:onlyfans:adult" && /could not be checked/.test(row(v2a, "adult:onlyfans").meta), "with the mode on it is an adult row that could not be checked");
  const b2 = text(investigateBrief({ collected: { ...er.collected, platformCheck: er.platformCheckV2 }, items: v2.items, facts: v2.facts, identity: v2.identity, failed: [], type: "username", target: er.target }));
  ok(/Could not be asked: .*LinkedIn \(blocked the check\).* Each is unknown, not absent\./.test(caseAnalysis(v2, { collected: { ...er.collected, platformCheck: er.platformCheckV2 }, target: er.target, type: "username" }).assessment.lines.map((l) => l.text).join("\n")) && !/blocked the check/.test(b2), "the assessment says a blocked site is unknown, once");
  const dead = buildEvidence({ ...er.collected, maigret: { error: "timeout", error_code: "timeout", results: er.collected.maigret.results } }, er.target, er.type);
  ok(!dead.identity.views.some((v) => v.label === "Eric Henderson") && row(dead, "acct:threads").tier === "unverified", "a failed source contributes nothing, even if it carries rows");
}

// ---- G. email flow -------------------------------------------------------------------
ok(sourcePlan("email", "torvalds@linux-foundation.org").join() === "holehe,hibp,gravatar,emailaccounts,harvester,hunter", "an email runs no username tools");
ok(!sourcePlan("email", "someone@gmail.com").includes("harvester") && !sourcePlan("email", "a@GMX.de").includes("harvester"), "the domain harvest is skipped for mail providers");
ok(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "gmx.net", "aol.com", "live.com", "me.com", "mail.com", "yandex.ru"].every(isFreeMail) && !isFreeMail("linux-foundation.org") && !isFreeMail("notgmail.com"), "free-mail list");
ok(sourcePlan("username", "jdoe").join() === "sherlock,maigret,github,platform,profiles" && sourcePlan("hash", "x").join() === "hash", "other types keep their sources");
{
  const ev = buildEvidence(em.collected, em.target, em.type);
  const h = row(ev, "lead:handle:torvalds");
  ok(h && h.what === "torvalds" && /the part before the @/.test(h.meta) && h.action.label === "Investigate this" && h.action.value === "torvalds", "the local part is a handle lead with Investigate this");
  ok(buildEvidence({}, "j.doe+news@example.org", "email").items.find((i) => i.key === "lead:handle:j.doe"), "a +tag is dropped from the handle lead");
  ok(row(ev, "lead:handle:reallylinustorvalds") && row(ev, "lead:domain:linux-foundation.org").action.label === "Open in Recon", "the Gravatar username and the email's domain are leads too");
  ok(!buildEvidence({}, "someone@gmail.com", "email").items.some((i) => i.key === "lead:domain:gmail.com"), "a mail provider is not offered for recon");
  ok(tier(ev, "hosts").length === 8 && tier(ev, "hosts")[0].source === "Domain harvest" && /CertSpotter/.test(tier(ev, "hosts")[0].meta), "harvested hosts get their own group, each with its sources");
  ok(ledgerTiers(em.target, "email").find((t) => t.id === "hosts").title === "Hosts on linux-foundation.org" && ledgerTiers(em.target, "email").find((t) => t.id === "hosts").open === false, "the host group is named after the domain and collapsed");
  ok(ev.items.filter(isFinding).length === ev.items.length - 8 - tier(ev, "lead").length - tier(ev, "similar").length && tier(ev, "similar").length > 0, "hosts, leads and similar handles are not counted as findings");
  ok(row(ev, "acct:spotify").tier === "linked" && /registered with this email/.test(row(ev, "acct:spotify").meta) && row(ev, "acct:gravatar").tier === "linked", "registrations for the searched email are linked");
  ok(!ev.items.some((i) => i.source === "Sherlock" || i.source === "Maigret"), "no username rows in an email case");
  // H. breaches, old shape
  ok(tier(ev, "flag").length === 10 && row(ev, "breach:linkedin").meta === "credential exposure", "old breach shape (a list of names) still renders");
  const v2 = buildEvidence({ ...em.collected, hibp: em.hibpV2 }, em.target, em.type);
  ok(row(v2, "breach:linkedin").meta === "2012 · Email addresses, Passwords" && row(v2, "breach:linkedin").url.includes("xposedornot.com"), "new breach shape: year and data classes in the row");
  ok(tier(v2, "flag").map((i) => i.what).join("|") === "Breach: LinkedInScrape-2021|Breach: LinkedIn|Breach: AntiPublicCombo", "breach rows are newest first, undated last");
  const b = text(investigateBrief({ collected: { ...em.collected, hibp: em.hibpV2 }, items: v2.items, facts: v2.facts, identity: v2.identity, failed: [], type: "email", target: em.target }));
  ok(/3 known breaches \(LinkedInScrape-2021 2021, LinkedIn 2012, AntiPublicCombo\)/.test(b) && /8 hosts on linux-foundation.org/.test(b) && !/Username tools were not run/.test(b) && caseAnalysis(v2, { collected: { ...em.collected, hibp: em.hibpV2 }, target: em.target, type: "email" }).suggestions.top.concat(caseAnalysis(v2, { collected: { ...em.collected, hibp: em.hibpV2 }, target: em.target, type: "email" }).suggestions.more).some((x) => x.id === "lead:handle:torvalds" && /It is a guess at a handle, not a finding/.test(x.reason)), "the email brief names breaches with years and the host inventory; the unsearched handle is a suggested step that says it is a guess");
}
{
  const l = breachList({ breaches: ["B", { name: "A", date: "2019-01-01", data_classes: ["Email addresses", "Passwords", "Names", "Phones", "IPs", "DOB"], records: 5 }, { name: "" }, null, { name: "C", year: 2021 }] });
  ok(l.map((b) => b.name).join() === "C,A,B" && l[0].year === 2021 && l[2].year === null, "breachList mixes both shapes, drops junk, sorts newest first");
  ok(breachMeta(l[1]) === "2019 · Email addresses, Passwords, Names, Phones and 2 more" && breachMeta(l[2]) === "credential exposure", "breach meta clips long class lists and falls back");
  ok(breachList({}).length === 0 && breachList(null).length === 0, "no breaches is an empty list");
}

// ---- I. hash --------------------------------------------------------------------------
for (const [name, d] of [["old shape", hs.eicarOld], ["new shape", hs.eicarNew]]) {
  const ev = buildEvidence({ hash: d }, d.hash, "hash");
  const v = row(ev, "hash:verdict");
  ok(v.tier === "info" && v.what === "EICAR antivirus test file: harmless by design, every scanner flags it", `EICAR (${name}) is an info row`);
  ok(!ev.items.some((i) => i.tier === "flag") && !/malware|TrojanSpy/i.test(v.what) && v.meta === "not malware", `EICAR (${name}) is never called known malware`);
  const b = text(investigateBrief({ collected: { hash: d }, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "hash", target: d.hash }));
  ok(/^ok: EICAR antivirus test file: harmless by design/.test(b) && !/Known malware/.test(b), `EICAR (${name}) brief`);
  ok(ev.facts.some((f) => f.k === "Detection" && f.v === "no detection ratio from keyless sources") && ev.facts.some((f) => f.k === "File name" && f.v === "eicar.com"), `EICAR (${name}) facts say there is no detection ratio`);
}
{
  const v = hashView(hs.eicarNew);
  ok(v.verdict === "TEST_FILE" && v.family === "" && v.tags.join() === "TrojanSpy,Mitre Attack,ET", "community tags are kept apart from the family");
  ok(hashView(hs.eicarOld).family === "" && hashView(hs.eicarOld).tags.length === 3, "old free-text families are treated as unverified tags");
  const ev = buildEvidence({ hash: hs.malicious }, hs.malicious.hash, "hash");
  const m = row(ev, "hash:verdict");
  ok(m.tier === "flag" && m.what === "Malicious SHA-256: Emotet" && /family named by MalwareBazaar, ThreatFox/.test(m.meta) && !/free text tag/.test(m.what + m.meta), "a malicious headline uses the family only");
  ok(ev.facts.some((f) => f.k === "Detection" && f.v === "60 of 70 engines (example)") && ev.facts.some((f) => f.k === "File type" && f.v === "exe") && ev.facts.some((f) => f.k === "First seen" && f.v === "2024-01-02") && ev.facts.some((f) => f.k === "File size" && f.v === "204,800 bytes"), "detection ratio, type, size and dates are shown when present");
  const unk = buildEvidence({ hash: { hash: "a".repeat(32), hash_type: "MD5", verdict: "UNKNOWN" } }, "a".repeat(32), "hash");
  ok(row(unk, "hash:verdict").tier === "info" && /not seen by any source/.test(row(unk, "hash:verdict").what), "an unknown hash is a lookup result, not a noisy site");
  ok(buildEvidence({ hash: { error: "timeout", error_code: "timeout", verdict: "MALICIOUS" } }, "x", "hash").items.length === 0, "a failed hash lookup gives no verdict");
}

// ---- K. recon ---------------------------------------------------------------------------
{
  const old = buildFindings(rc.collected, rc.target, "domain");
  ok(old.items.some((i) => i.key === "host:nail-ao.com" && i.tier === "surface"), "old exposure shape: hostnames render as before");
  const c2 = { ...rc.collected, shodan: rc.internetdbV2, email_posture: rc.emailPostureV2 };
  const f = buildFindings(c2, rc.target, "domain");
  const shared = f.items.find((i) => i.key === "host:shared");
  ok(shared && shared.tier === "surface" && shared.what === "Shared Vercel address: 1 other site answers on this IP", "a shared host gets one info row");
  ok(!f.items.some((i) => i.key === "host:nail-ao.com") && f.items.find((i) => i.key === "nbr:nail-ao.com")?.tier === "neighbor", "neighbours are not surface rows; they sit in their own group");
  ok(RECON_TIERS.find((t) => t.id === "neighbor").open === false && /Unrelated neighbours/.test(RECON_TIERS.find((t) => t.id === "neighbor").title), "the neighbour group is collapsed and labelled unrelated");
  ok(f.items.filter((i) => i.key.startsWith("port:")).every((i) => /shared Vercel edge/.test(i.meta)), "ports_note is attached to port rows");
  ok(!old.items.filter((i) => i.key.startsWith("port:")).some((i) => i.meta), "no note on ports when the host is not shared");
  // email posture
  ok(mailState(rc.emailPostureV2) === "none" && mailState(rc.collected.email_posture) === "none" && mailState({ mail_enabled: null }) === "unknown" && mailState({ mx: ["mx.example.org"], spf: {} }) === "yes", "mail state: new field, old shape and unknown");
  ok(!f.items.some((i) => i.key.startsWith("mail:")) && !old.items.some((i) => /^mail:No (SPF|DMARC)/.test(i.key)), "a no-mail domain gets no SPF or DMARC flag, in new or old data");
  ok(f.facts.find((x) => x.k === "Email security").v === "No mail: no MX records, not graded" && old.facts.find((x) => x.k === "Email security").v === "No mail: no MX records, not graded", "the fact says no mail instead of a grade");
  for (const [name, c] of [["new", c2], ["old", rc.collected]]) {
    const b = text(reconBrief({ collected: c, items: buildFindings(c, rc.target, "domain").items, failed: [], type: "domain", target: rc.target, today: "2026-11-14" }));
    ok(/info: This domain has no MX records/.test(b) && /v=spf1 -all and v=DMARC1; p=reject;/.test(b) && !/can be spoofed|grade F|Mail from this domain/.test(b), `the brief does not call a no-mail domain spoofable (${name} shape)`);
    ok(!/no longer resolve/.test(b), `the brief never says the target no longer resolves when DNS answered (${name} shape)`);
  }
  ok(/shared Vercel/.test(text(reconBrief({ collected: c2, items: f.items, failed: [], type: "domain", target: rc.target, today: "2026-11-14" }))), "the brief says the address is shared");
  // resolution guard and takeover
  ok(resolvedHosts(rc.collected, rc.target).has("darkwire.tech") && resolvedHosts(rc.collected, rc.target).has("www.darkwire.tech"), "hosts this run resolved are known");
  const tk = { found: true, checked: 3, dangling: 2, unknown: 1, unchecked: ["x.darkwire.tech"], candidates: [
    { host: "www.darkwire.tech", cname: "gone.example.net", service: "Heroku", status: "dangling" },
    { host: "old.darkwire.tech", cname: "gone.example.net", service: "Heroku", status: "dangling" },
    { host: "maybe.darkwire.tech", cname: "x.example.net", service: "Heroku", status: "unknown" }] };
  const t = buildFindings({ ...rc.collected, takeover: tk }, rc.target, "domain");
  const www = t.items.find((i) => i.key === "tko:www.darkwire.tech"), gone = t.items.find((i) => i.key === "tko:old.darkwire.tech"), maybe = t.items.find((i) => i.key === "tko:maybe.darkwire.tech");
  ok(www.tier === "surface" && /this run resolved the host/.test(www.meta) && !/no longer resolves/.test(www.what + www.meta), "a dangling row for a host the run resolved is suppressed, with a note");
  ok(gone.tier === "flag" && /no longer resolves/.test(gone.meta), "a dangling row for a host that did not resolve is a flag");
  ok(maybe.tier === "surface" && /could not be completed/.test(maybe.meta), "status unknown is never a flag");
  const tb = text(reconBrief({ collected: { ...rc.collected, takeover: tk }, items: t.items, failed: [], type: "domain", target: rc.target, today: "2026-11-14" }));
  ok(/flag: 1 subdomain points at a cloud resource that no longer exists \(old.darkwire.tech\)/.test(tb) && /2 hosts could not be checked for takeover/.test(tb), "the brief counts only real dangling hosts and mentions the unchecked ones");
  const cs = { ...rc.collected, subdomains: { ...rc.collected.subdomains, ct_summary: { ...rc.collected.subdomains.ct_summary, not_resolving: ["darkwire.tech", "retired.darkwire.tech"], resolution_unknown: ["flaky.darkwire.tech"] } } };
  const sb = text(reconBrief({ collected: cs, items: [], failed: [], type: "domain", target: rc.target, today: "2026-11-14" }));
  ok(/1 name in certificate logs no longer resolves \(retired.darkwire.tech\)/.test(sb) && /1 name in certificate logs could not be checked \(flaky.darkwire.tech\)/.test(sb), "not resolving and could-not-be-checked are told apart");
}

// ---- L. one tally -----------------------------------------------------------------------
{
  const names = { sherlock: "Sherlock", github: "GitHub", githubDeep: "GitHub details", avatarHash: "Avatar comparison", enricher: "Profile enrichment", harvester: "Domain harvest", hibp: "Breaches", whois: "WHOIS" };
  const c = {
    sherlock: { total: 3, results: [{ site: "a" }] }, github: { found: false }, githubDeep: { found: null, error: "rate limited", error_code: "rate_limited" },
    avatarHash: { results: [{ id: "a", hash: "00" }] }, enricher: { total: 0, profiles: [] }, harvester: { skipped: true, message: "mail provider" }, hibp: { breaches: [] },
    whois: { error: "No match", error_code: "not_found" }, nameSearch: "J Doe", reverseImage: "https://example.org/a.png", ipAsn: { "1.1.1.1": {} }, maigret: null,
  };
  const t = sourceTally(c, names);
  ok(t.ran === 7 && t.answered === 6 && t.withResults === 2 && t.failed === 1 && t.skipped === 1, "ran, answered, with results, failed and skipped");
  ok(t.rows.find((r) => r.key === "githubDeep").state === "failed" && t.rows.find((r) => r.key === "github").state === "none" && t.rows.find((r) => r.key === "whois").state === "none", "failed, not found and a registry's 'no such record' stay apart");
  ok(t.rows.some((r) => r.name === "GitHub details") && t.rows.some((r) => r.name === "Avatar comparison") && t.rows.some((r) => r.name === "Profile enrichment"), "follow-up lookups are counted as sources");
  ok(!t.rows.some((r) => ["nameSearch", "reverseImage", "ipAsn", "maigret"].includes(r.key)), "browser-made values and sources that never answered are not counted");
  ok(tallyText(t) === "7 sources ran · 2 with results · 1 failed · 1 skipped", "one sentence for the header and the run log");
  ok(sourceTally({}, names).ran === 0 && tallyText(sourceTally({}, names)) === "0 sources ran", "nothing ran");
  ok(sourceTally({ hash: hs.eicarNew }, { hash: "Hash lookup" }).withResults === 1 && sourceTally({ hash: { verdict: "UNKNOWN" } }, { hash: "Hash lookup" }).withResults === 0, "a verdict is a result, unknown is not");
}

// ---- review fixes ------------------------------------------------------------------------
{
  // 1. README links are leads only: they never tie another profile to the GitHub record
  const c = { github: { found: true, name: "Linus Torvalds", profile_url: "https://github.com/torvalds", blog: "" },
    githubDeep: { found: true, state: "ok", readme_links: ["https://kernel.org/doc", "https://keybase.io/someoneelse"], sections: { readme_links: "ok" } },
    maigret: { results: [{ site: "Keybase", url: "https://keybase.io/torvalds", verified: true, profile: { name: "Kay Unrelated", bio: "docs at https://kernel.org/doc" } }] } };
  const ev = buildEvidence(c, "torvalds", "username");
  ok(!collectProfiles(c, "torvalds", "username").find((p) => p.id === "acct:github").links.some((l) => /kernel\.org/.test(l)), "README links are not among the anchor's links");
  ok(row(ev, "acct:keybase").tier === "different" && row(ev, "lead:url:https://kernel.org/doc"), "a README link to kernel.org/doc does not link an unrelated Keybase profile, and is still a lead");
  // 3. a profile that merely links to the GitHub profile is support, never linked
  const fan = buildEvidence({ github: c.github, maigret: { results: [{ site: "Keybase", url: "https://keybase.io/torvalds", verified: true, profile: { bio: "see https://github.com/torvalds" } }] } }, "torvalds", "username");
  ok(row(fan, "acct:keybase").tier === "matches" && /Keybase links to the GitHub profile, not confirmed from the other side/.test(row(fan, "acct:keybase").meta), "a one-way link to the anchor lands in matches and says so");
  const vouched = buildEvidence({ github: { ...c.github, twitter_username: "torvalds" }, maigret: { results: [{ site: "Twitter", url: "https://twitter.com/torvalds", verified: true, profile: { name: "Someone Else Entirely" } }] } }, "torvalds", "username");
  ok(row(vouched, "acct:x").tier === "linked" && /GitHub links to X/.test(row(vouched, "acct:x").meta), "a link from the anchor itself is linked");
  // 4. names the owner might use
  for (const name of ["torvalds official", "L. Torvalds", "LinusTorvalds", "Линус Торвальдс", "Linux kernel dev"]) {
    const e = buildEvidence({ github: c.github, maigret: { results: [{ site: "Medium", url: "https://medium.com/@torvalds", verified: true, profile: { name } }] } }, "torvalds", "username");
    ok(row(e, "acct:medium").tier === "matches" && tier(e, "different").length === 0, `"${name}" is matches, not a different person`);
  }
}
{
  // 5. no anchor, no strong signal: no primary, no "different", and every surface says the same
  const c = { maigret: { results: [{ site: "Medium", url: "https://medium.com/@jdoe", verified: true, profile: { name: "Bob Arnold", location: "Leeds" } }, { site: "Steam", url: "https://steamcommunity.com/id/jdoe", verified: true, profile: { name: "Carol Baker" } }, { site: "Paypal", url: "https://paypal.me/jdoe", verified: false }] } };
  const ev = buildEvidence(c, "jdoe", "username");
  ok(ev.identity.noPrimary && ev.identity.primary === null && ev.identity.views.length === 2 && !ev.identity.views.some((v) => v.primary), "no primary identity is chosen");
  ok(tier(ev, "different").length === 0 && tier(ev, "linked").length === 0 && tier(ev, "matches").length === 2, "all read profiles are matches, none different, none linked");
  ok(/name on profile: Bob Arnold · Leeds · exists, nothing ties it to the target/.test(row(ev, "acct:medium").meta) && /exists, nothing ties it to the target/.test(row(ev, "acct:steam").meta), "each row says nothing ties it to the target");
  ok(ev.facts.length === 0 && factsFor(ev, ev.identity.views[0].id).some((f) => f.v === "Bob Arnold"), "no one's facts are shown as the target's, but a cluster can still be viewed");
  const acc = accountsFor(ev.items);
  ok(acc.filter((a) => a.status === "matches").every((a) => /nothing ties it to the target/.test(a.note)) && !acc.some((a) => a.status === "different" || a.status === "linked"), "the AI payload carries the same statuses and the same words");
  const b = text(investigateBrief({ collected: c, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "username", target: "jdoe" }));
  ok(/Each read profile exists, and nothing ties it to the target/.test(b) && !/different person|Only the first/.test(b) && /^None\. No identity is established/.test(caseAnalysis(ev, { collected: c, target: "jdoe", type: "username" }).assessment.headline), "the brief and the assessment say the same");
}
{
  // 7 + 11. a source whose parts did not answer is failed or partial, never "nothing found"
  const names = { platformCheck: "Platform check", avatarHash: "Avatar comparison", hash: "Hash lookup", githubDeep: "GitHub details" };
  const blockedRows = [{ platform: "LinkedIn", state: "blocked", found: null, evidence: "login wall" }, { platform: "Facebook", state: "unknown", found: null }, { platform: "OnlyFans", state: "manual", found: null, manual: true }];
  const allBlocked = { platformCheck: { total: 0, results: blockedRows }, avatarHash: { results: [{ id: "acct:a", error: "too large", error_code: "too_large" }, { id: "acct:b", error: "timeout", error_code: "timeout" }] },
    hash: { hash: "a".repeat(32), hash_type: "MD5", verdict: "UNKNOWN", verdict_basis: "No source that could be asked has seen this hash.", failed_sources: ["MalwareBazaar", "ThreatFox", "CIRCL", "AlienVault OTX"], malware_bazaar: { found: null, error_code: "auth" }, threatfox: { found: null, error_code: "auth" }, circl: { found: null, error_code: "timeout" }, alienvault: { found: null, error_code: "timeout" } } };
  const t = sourceTally(allBlocked, names);
  const st = (k) => t.rows.find((r) => r.key === k);
  ok(st("platformCheck").state === "failed" && st("platformCheck").text === "blocked by every site checked", "platform check blocked everywhere is failed, not nothing found");
  ok(st("avatarHash").state === "failed" && st("avatarHash").text === "no image could be read", "an avatar comparison where every image errored is failed");
  ok(st("hash").state === "failed" && /no source could be asked \(MalwareBazaar, ThreatFox, CIRCL, AlienVault OTX\)/.test(st("hash").text), "a hash lookup where no source answered is failed");
  ok(t.failed === 3 && t.withResults === 0 && t.answered === 0 && tallyText(t) === "3 sources ran · 0 with results · 3 failed", "the tally counts them as failed");
  ok(statusForAi(st("platformCheck")) === "blocked: blocked by every site checked" && /^failed: no image/.test(statusForAi(st("avatarHash"))) && t.rows.every((r) => statusForAi(r) !== "not found"), "the AI is told blocked or failed, never not found");
  const part = { platformCheck: { total: 1, results: [...blockedRows, { platform: "Instagram", state: "found", found: true }, { platform: "X", state: "not_found", found: false }] },
    avatarHash: { results: [{ id: "acct:a", hash: "c3c3e7e7ffff0f0f", default: false }, { id: "acct:b", error: "timeout", error_code: "timeout" }] },
    hash: { hash: "a".repeat(32), hash_type: "MD5", verdict: "UNKNOWN", verdict_basis: "Two of four sources answered and neither has seen it.", failed_sources: ["MalwareBazaar", "ThreatFox"], malware_bazaar: { found: null, error_code: "auth" }, threatfox: { found: null, error_code: "auth" }, circl: { found: false }, alienvault: { found: false } },
    githubDeep: { found: true, state: "partial", orgs: [], sections: { orgs: "ok", top_repos: "rate_limited", ssh_keys: "rate_limited" } } };
  const tp = sourceTally(part, names), sp = (k) => tp.rows.find((r) => r.key === k);
  ok(sp("platformCheck").state === "partial" && sp("platformCheck").text === "partial: 2 of 4 sites answered" && sp("platformCheck").hasResults, "some sites blocked is partial, and its results still count");
  ok(sp("hash").state === "partial" && statusForAi(sp("hash")) === "partial: 2 of 4 sources answered" && !sp("hash").hasResults, "a hash with failed sources is partial: 2 of 4 sources answered, never not found");
  ok(sp("avatarHash").state === "partial" && sp("githubDeep").state === "partial" && sp("githubDeep").text === "partial: 1 of 3 sections read", "avatar comparison and GitHub details report partial too");
  ok(tp.partial === 4 && tp.failed === 0 && tp.answered === 4 && tallyText(tp) === "4 sources ran · 3 with results · 4 partial", "partial sources are counted apart from failed ones");
  ok(sourceCoverage({ results: [{ platform: "Instagram", found: true }] }) === null && sourceCoverage({ breaches: [] }) === null, "old shapes and single-part sources have no coverage to report");
  // the ledger row for an unknown hash says who answered
  const some = row(buildEvidence({ hash: part.hash }, part.hash.hash, "hash"), "hash:verdict");
  ok(some.what === "MD5 not seen by the 2 sources that answered; 2 could not be asked (MalwareBazaar, ThreatFox)" && some.meta === "Two of four sources answered and neither has seen it.", "unknown hash: says how many answered and renders verdict_basis");
  const nobody = row(buildEvidence({ hash: allBlocked.hash }, allBlocked.hash.hash, "hash"), "hash:verdict");
  ok(/^MD5 could not be checked: no source could be asked/.test(nobody.what) && !/not seen/.test(nobody.what), "unknown hash with no answers is not called not seen");
  ok(row(buildEvidence({ hash: { hash: "b".repeat(32), hash_type: "MD5", verdict: "UNKNOWN" } }, "b".repeat(32), "hash"), "hash:verdict").what === "MD5 not seen by any source", "with every source answering the old wording stands");
  const hb = (h) => text(investigateBrief({ collected: { hash: h }, items: [], facts: [], identity: { views: [] }, failed: [], type: "hash", target: h.hash }));
  ok(/None of the 2 sources that answered has seen this hash/.test(hb(part.hash)) && /No source could be asked about this hash/.test(hb(allBlocked.hash)) && !/No source has seen/.test(hb(part.hash) + hb(allBlocked.hash)), "the hash brief speaks only for the sources that answered");
  ok(JSON.stringify(hashCoverage(part.hash)) === JSON.stringify({ answered: 2, failed: ["MalwareBazaar", "ThreatFox"], total: 4 }), "hash coverage counts answered and failed sources");
  ok(sourceTally({ hash: { verdict: "UNKNOWN", circl: { found: false } } }, names).rows[0].state === "none", "an unknown verdict with every source answering is still nothing found");
}
{
  // 8. the AI payload withholds what the screen withholds
  const tk = { found: true, checked: 3, dangling: 2, candidates: [
    { host: "www.darkwire.tech", cname: "gone.example.net", service: "Heroku", status: "dangling" },
    { host: "old.darkwire.tech", cname: "gone.example.net", service: "Heroku", status: "dangling" },
    { host: "api.darkwire.tech", cname: "x.example.net", service: "Heroku", status: "pointing" }] };
  const sent = takeoverForAi({ ...rc.collected, takeover: tk }, rc.target);
  ok(sent.candidates.map((x) => x.host).join() === "old.darkwire.tech,api.darkwire.tech" && sent.dangling === 1 && sent.withheld_resolved_in_this_run === 1, "a dangling candidate this run resolved is not sent to the AI");
  ok(tk.candidates.length === 3 && tk.dangling === 2, "the collected data itself is left as it was");
  ok(takeoverForAi({ takeover: { error: "timeout", error_code: "timeout" } }, rc.target).error === "timeout" && takeoverForAi({}, rc.target) === null, "a failed or missing takeover check passes through unchanged");
  const md = buildFindings({ ...rc.collected, takeover: tk }, rc.target, "domain").items.filter((i) => i.key.startsWith("tko:"));
  ok(md.filter((i) => i.tier === "flag").map((i) => i.key).join() === "tko:old.darkwire.tech" && !/no longer resolves/.test(md.find((i) => i.key === "tko:www.darkwire.tech").meta), "the export, built from the same rows, withholds it too");
}
{
  // 9. a no-mail domain that already publishes the null records is locked, not "publishes no policy"
  const locked = { found: true, grade: "A", spoofable: "no", mail_enabled: false, mx: [], suggested_records: [], spf: { record: "v=spf1 -all" }, dmarc: { record: "v=DMARC1; p=reject;" }, findings: [] };
  ok(!noMailOpen(locked) && noMailOpen(rc.emailPostureV2) && noMailOpen(rc.collected.email_posture), "open only when spoofable or when records are suggested");
  const b = text(reconBrief({ collected: { ...rc.collected, email_posture: locked }, items: [], failed: [], type: "domain", target: rc.target, today: "2026-11-14" }));
  ok(/ok: This domain has no MX records, so it does not receive mail, and its SPF and DMARC records tell receivers to reject/.test(b) && /locked against spoofing/.test(b) && !/publishes no policy|would close that/.test(b), "the brief says a locked no-mail domain is locked");
  ok(buildFindings({ ...rc.collected, email_posture: locked }, rc.target, "domain").facts.find((x) => x.k === "Email security").v === "No mail, and locked against spoofing", "and so does the fact");
}
{
  // 10. breaches are told apart by name, never by a shared reference URL
  const shared = { breaches: [{ name: "Combo A", date: "2020-01-01", url: "https://xposedornot.com/xposed" }, { name: "Combo B", date: "2019-01-01", url: "https://xposedornot.com/xposed" }, { name: "combo a", date: "2018-01-01", url: "https://other.example/x" }] };
  const ev = buildEvidence({ hibp: shared }, "a@example.org", "email");
  ok(tier(ev, "flag").map((i) => i.what).join("|") === "Breach: Combo A|Breach: Combo B", "two breaches sharing a URL are two rows; the same name twice is one");
  const b = text(investigateBrief({ collected: { hibp: shared }, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "email", target: "a@example.org" }));
  ok(/3 known breaches/.test(b) === false && /2 known breaches/.test(b), "the brief counts the same number the ledger shows");
}

// ---- 11. the people-depth lookups: rows, commit emails, post activity, archive diff -------------
// Built on the invented case in fixtures/deep.json (Sam Example). No network.
{
  const E = await import("../../static/v2/js/evidence.js");
  const D = await import("../../static/v2/js/deep.js");
  const { rowCertainty } = await import("../../static/v2/js/present.js");
  const { personTimeline } = await import("../../static/v2/js/timeline.js");
  const { setSelfAudit } = await import("../../static/v2/js/casework.js");
  const U = fx("deep").cases[0], H = U.target;
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const prof = (source, site, url, x = {}) => ({ site, source, handle: H, url, state: "found", display_name: "", name: "", bio: "", location: "", company: "", website: "", links: [], emails: [], created: "", last_active: "", accounts: [], stats: {}, followers: null, items: [], note: "", avatar_hash: "", avatar_default: false, thumb: "", avatar_state: "none", ...x });
  const NEW = [
    prof("mastodon_fosstodon_org", "Mastodon (fosstodon.org)", `https://fosstodon.org/@${H}`, { display_name: "Sam Example", note: "moved", created: "2019-02-03T00:00:00Z" }),
    prof("mastodon_mastodon_online", "Mastodon (mastodon.online)", `https://mastodon.online/@${H}`),
    prof("launchpad", "Launchpad", `https://launchpad.net/~${H}`, { display_name: "Sam Example", bio: "Maps.", note: "not an active account", created: "2011-05-26T10:29:24Z", links: ["https://unclaimed.example/page"], emails: ["nobody@unclaimed.example"] }),
    prof("codeberg", "Codeberg", `https://codeberg.org/${H}`, { display_name: "Sam Example" }),
    prof("gitea", "Gitea.com", `https://gitea.com/${H}`, { note: "organization" }),
    prof("lobsters", "Lobsters", `https://lobste.rs/~${H}`),
  ];
  const base = (more = {}) => {
    const c = clone(U.collected);
    c.profiles.profiles.push(...clone(NEW));
    for (const p of NEW) c.profiles.sources[p.source] = { site: p.site, state: "found" };
    c.sherlock.results.push({ site: "Fosstodon", url: `https://fosstodon.org/@${H}`, confidence: "normal" }, { site: "Gitea", url: `https://gitea.com/${H}`, confidence: "normal" }, { site: "Launchpad", url: `https://launchpad.net/~${H}`, confidence: "normal" });
    c.maigret.results.push({ site: "mastodon.online", url: `https://mastodon.online/@${H}`, confidence: "normal", category: "social" }, { site: "Launchpad", url: `https://launchpad.net/~${H}`, confidence: "normal", verified: true, profile: { name: "Sam Example", bio: "Maps." } });
    return { ...c, ...more };
  };
  const tiersOf = (ev) => JSON.stringify(ev.items.filter((i) => i.key?.startsWith("acct:")).map((i) => [i.key, i.tier, !!i.inPrimary]));
  const clusters = (ev) => JSON.stringify(ev.identity.views.map((v) => [v.id, v.primary, v.members]));
  const an = (c, ev = buildEvidence(c, H, "username")) => caseAnalysis(ev, { collected: c, target: H, type: "username" });
  const steps = (c) => { const s = an(c).suggestions; return [...s.top, ...s.more]; };
  const md = (c, more = {}) => E.caseMarkdown({ collected: c, target: H, type: "username", ...more });

  // -- A. one site is one row, and each Mastodon instance is its own --
  ok(E.canonSite("Mastodon (fosstodon.org)") === "fosstodon.org" && E.canonSite("Fosstodon") === "fosstodon.org" && E.canonSite("Mastodon") === "mastodon.social" && E.canonSite("Mastodon (mastodon.social)") === "mastodon.social" && E.canonSite("mastodon.social") === "mastodon.social" && E.canonSite("Mstdn.social") === "mstdn.social" && E.canonSite("Mastodon (mstdn.social)") === "mstdn.social", "each Mastodon instance has its own canonical name, the host, and mastodon.social keeps the one older cases use");
  ok(E.canonSite("Gitea") === "gitea" && E.canonSite("Gitea.com") === "gitea" && E.canonSite("Launchpad") === "launchpad" && E.canonSite("launchpad.net") === "launchpad" && E.canonSite("HackerNews") === E.canonSite("Hacker News") && E.canonSite("codeberg.org") === E.canonSite("Codeberg") && E.canonSite("Steam (community)") === "steam" && E.canonSite("X (Twitter)") === "x", "the tools' names for Gitea.com, Launchpad and the rest are the same site, and another trailing remark is still dropped");
  const c0 = base(), ev0 = buildEvidence(c0, H, "username");
  const fo = row(ev0, "acct:fosstodon.org"), ms = row(ev0, "acct:mastodon.social"), mo = row(ev0, "acct:mastodon.online"), gt = row(ev0, "acct:gitea"), lp = row(ev0, "acct:launchpad"), cb = row(ev0, "acct:codeberg");
  ok(fo && ms && mo && fo.what === "Mastodon (fosstodon.org)" && ms.what === "Mastodon" && mo.what === "Mastodon (mastodon.online)" && ev0.items.filter((i) => /^Mastodon/.test(i.what)).length === 3 && fo.sources.join() === "Profile sources,Sherlock" && mo.sources.join() === "Profile sources,Maigret" && fo.url === `https://fosstodon.org/@${H}`, "three instances are three rows, each with the tools that named it");
  ok(gt.what === "Gitea.com" && gt.sources.join() === "Profile sources,Sherlock" && ev0.items.filter((i) => /gitea/i.test(i.key || "")).length === 1 && ev0.items.filter((i) => /launchpad/i.test(i.key || "")).length === 1, "Gitea.com and Launchpad are one row each, whoever reported them");
  ok(mo.tier === "matches" && !mo.inPrimary && ms.inPrimary === true && !ev0.identity.views.find((v) => v.primary).members.includes("acct:mastodon.online"), "the same handle on another instance is not tied to the identity by its spelling");
  ok(fo.siteNote === "moved" && fo.card.note.includes(D.PROFILE_NOTE_TEXT.moved) && !/notes: moved/.test(fo.card.note) && gt.siteNote === "organization" && gt.card.note.includes("An organization, not a person."), "moved and organization are said in the page's own sentence");
  // a Launchpad record nobody claimed
  ok(lp.tier === "unverified" && lp.unclaimed === true && lp.nofind === true && !E.isFinding(lp) && lp.meta === E.UNCLAIMED_META && lp.card.basis === E.UNCLAIMED_TEXT && /^Launchpad makes such a record by itself/.test(E.UNCLAIMED_TEXT) && lp.card.facts.length === 0 && !lp.card.bio && !lp.detail && !lp.archive && !lp.canCommitEmails && !lp.canPostActivity && !lp.thumb, "an unclaimed Launchpad record is an Unverified row that shows nothing from the record");
  ok(rowCertainty(lp).word === "Not a claimed account" && rowCertainty(lp).line === "dashed" && lp.link_kind === "verified_profile" && lp.url === `https://launchpad.net/~${H}`, "it has its own pill word, dashed, and links to the record that was read");
  ok(!E.collectProfiles(c0, H, "username").some((p) => p.id === "acct:launchpad") && !ev0.identity.views.some((v) => v.members.includes("acct:launchpad") || v.sites.includes("Launchpad")) && !ev0.identity.views.flatMap((v) => v.facts).some((f) => /Launchpad/.test(f.source)) && !ev0.items.some((i) => i.tier === "lead" && /unclaimed\.example/.test(i.what)) && !personTimeline(c0, H, "username").events.some((e) => /Launchpad/.test(e.title)), "and it is no profile: no cluster, no fact, no lead and no timeline entry, even when a tool parsed its page");
  const claimed = base(); claimed.profiles.profiles.find((p) => p.source === "launchpad").note = "team";
  ok(row(buildEvidence(claimed, H, "username"), "acct:launchpad").tier !== "unverified" && row(buildEvidence(claimed, H, "username"), "acct:launchpad").card.note.includes("A team on Launchpad, not a person.") && !row(buildEvidence(claimed, H, "username"), "acct:launchpad").unclaimed, "a Launchpad team is a read profile, labelled as a team");
  const b0 = text(investigateBrief({ collected: c0, items: ev0.items, facts: ev0.facts, identity: ev0.identity, failed: [], type: "username", target: H }));
  ok(/info: Launchpad holds a record under this handle that is not a claimed account\./.test(b0) && /12 profiles were read from the site's own record, of \d+ sites asked/.test(b0) && !/were read[^\n]*Launchpad/.test(b0.split("\n").find((l) => /profiles were read/.test(l))), "the brief says so once and does not count it among the profiles read");
  const a0 = an(c0, ev0);
  ok(a0.assessment.lines.some((l) => l.level === "info" && /Launchpad holds a record under this handle that is not a claimed account/.test(l.text)) && !steps(c0).some((s) => /launchpad/i.test(s.id)), "the assessment names it as nobody's account, and nothing is suggested for it");
  const ai0 = E.aiPayloadFor(c0, H, "username");
  ok(!ai0.profile_sources.profiles.some((p) => p.site === "Launchpad") && ai0.profile_sources.notes.some((x) => /^Launchpad: a record exists under this handle that is not a claimed account/.test(x)) && ai0.accounts.find((x) => x.site === "Launchpad").note === E.UNCLAIMED_NOTE && ai0.accounts.find((x) => x.site === "Launchpad").status === "unverified" && ai0.profile_sources.profiles.length === 12, "the model is told it is not a claimed account, and gets nothing that was read on it");
  ok(/- \[Launchpad\]\(https:\/\/launchpad\.net\/~samexample\) · not a claimed account: Launchpad made this record by itself/.test(md(c0)) && /## Unverified \(\d+\)/.test(md(c0)), "the export lists it under Unverified with its own words");

  // -- B. commit emails --
  const CE = (site, x = {}) => ({ site, site_name: D.COMMIT_EMAIL_SITES[site][0], username: H, state: "found", cached: false, handle: H, profile_url: `https://${D.COMMIT_EMAIL_SITES[site][1]}/${H}`, display_name: "Sam Example",
    emails: [{ email: "sam@example.org", name: "Sam Example", how: "forge_attributed", self_declared: true, commits: 3, first_commit: "2026-01-15T09:00:00Z", last_commit: "2026-10-30T09:00:00Z", repos: [`${H}/maps`] },
      { email: "sam.old@example.com", name: "Sam Example", how: "author_line_match", self_declared: true, commits: 1, first_commit: "2025-10-10T08:00:00Z", last_commit: "2025-10-10T08:00:00Z", repos: [`${H}/maps`] }],
    emails_state: "found", complete: true, sections: { account: "found", repos: "ok" }, repos: [{ name: `${H}/maps`, url: `https://${D.COMMIT_EMAIL_SITES[site][1]}/${H}/maps`, fork: false, state: "ok", commits_seen: 6 }],
    counts: { repos_listed: 1, repos_read: 1, commits_seen: 6, own: 4, noreply: 0, other_authors: 2 }, requests: 3, ...x });
  const one = (email) => [{ email, name: "N", how: "author_line_match", self_declared: true, commits: 1, repos: [] }];
  ok(JSON.stringify(cb.canCommitEmails) === JSON.stringify({ site: "codeberg", username: H }) && JSON.stringify(gt.canCommitEmails) === JSON.stringify({ site: "gitea", username: H }) && row(ev0, "acct:gitlab").canCommitEmails.site === "gitlab" && !row(ev0, "acct:github").canCommitEmails && !ms.canCommitEmails && !cb.commitEmails, "the button belongs on a read GitLab, Codeberg or Gitea.com row and nowhere else");
  const cB = base({ commitEmails: { "acct:codeberg": CE("codeberg"), "acct:gitlab": CE("gitlab", { emails: one("petra@example.org") }), "acct:gitea": CE("gitea", { emails: one("org@example.net") }) } }), evB = buildEvidence(cB, H, "username");
  const lead = (ev, v) => ev.items.find((i) => i.tier === "lead" && i.lead?.value === v);
  ok(row(evB, "acct:codeberg").commitEmails.state === "found" && row(evB, "acct:codeberg").commitEmails.rows.length === 2 && row(evB, "acct:codeberg").commitEmails.rows[0].strong === true && row(evB, "acct:gitlab").commitEmails.rows[0].email === "petra@example.org", "an answer is shown on the row it belongs to, the stronger tie first");
  ok(lead(evB, "sam@example.org").tied === true && /Codeberg ties to this account/.test(lead(evB, "sam@example.org").meta) && /self-declared/.test(lead(evB, "sam@example.org").meta) && lead(evB, "sam@example.org").source === "Commit emails" && lead(evB, "sam@example.org").action.pivot === "investigate", "an address the forge ties to the account is a lead, and says it is self-declared");
  ok(lead(evB, "sam.old@example.com").tied === true && /the weaker tie/.test(lead(evB, "sam.old@example.com").meta) && /self-declared/.test(lead(evB, "sam.old@example.com").meta), "an author-line match says it is the weaker tie");
  ok(lead(evB, "org@example.net").tied === false && / · on a profile not tied to the target$/.test(lead(evB, "org@example.net").meta) && !lead(evB, "petra@example.org"), "an address on an untied row is a weaker lead, and a row filed as a different person gives none");
  const cf = evB.facts.filter((f) => f.k === "Commit email");
  ok(cf.some((f) => f.v === "sam@example.org" && f.source === "Codeberg commits" && f.how.prov === "self-declared") && cf.some((f) => f.v === "sam.old@example.com" && f.source === "Codeberg commits (author line only)") && !evB.identity.views.flatMap((v) => v.facts).some((f) => /petra@example\.org|org@example\.net/.test(f.v)), "a commit email is a fact only for a profile of the primary identity, marked self-declared");
  ok(tiersOf(evB) === tiersOf(ev0) && clusters(evB) === clusters(ev0), "and it moves no row and no profile");
  const sB = steps(cB), s0 = steps(c0);
  ok(s0.find((s) => s.id === "commits:acct:codeberg")?.action.kind === "commit-emails" && s0.find((s) => s.id === "commits:acct:codeberg").action.key === "acct:codeberg" && s0.find((s) => s.id === "commits:acct:codeberg").title === "Read the commit emails of the Codeberg account" && /self-declared and a lead to check/.test(s0.find((s) => s.id === "commits:acct:codeberg").reason) && !s0.some((s) => s.id === "commits:acct:gitlab" || s.id === "commits:acct:gitea") && !sB.some((s) => /^commits:/.test(s.id)), "commit emails are suggested for a forge account of the identity with no answer yet, never for another person's or an untied one");
  ok(sB.find((s) => s.id === "lead:email:sam@example.org").score > sB.find((s) => s.id === "lead:email:sam.old@example.com").score && sB.find((s) => s.id === "lead:email:sam.old@example.com").score > sB.find((s) => s.id === "lead:email:org@example.net").score, "the forge's own tie ranks above an author-line match, and an untied row's address last");
  const wrong = buildEvidence(base({ commitEmails: { "acct:codeberg": CE("codeberg", { username: "someoneelse" }), "acct:gitea": CE("gitlab") } }), H, "username");
  ok(!row(wrong, "acct:codeberg").commitEmails && !row(wrong, "acct:gitea").commitEmails && !lead(wrong, "sam@example.org"), "an answer about another account or another site is not put on the row");
  const down = buildEvidence(base({ commitEmails: { "acct:codeberg": { site: "codeberg", username: H, error: "The source took too long to answer.", error_code: "timeout" } } }), H, "username");
  ok(row(down, "acct:codeberg").commitEmails.state === "failed" && row(down, "acct:codeberg").commitEmails.retry === true && !/no address/i.test(row(down, "acct:codeberg").commitEmails.text) && !down.items.some((i) => i.tier === "lead" && i.source === "Commit emails"), "a failed reading is unknown, with a retry, and gives no lead");
  const mB = md(cB);
  ok(/  - Commit emails: 2 addresses of this account on the 6 commits read\. _\(Commit emails · self-declared\)_\n    - sam@example\.org/.test(mB) && /\*\*Commit email:\*\* \[sam@example\.org\]\(https:\/\/codeberg\.org\/samexample\/maps\) _\(Codeberg commits · self-declared · typed into a commit by its author/.test(mB) && !/\u2014/.test(mB), "the export has the addresses under the row and the fact with its provenance");

  // -- C. post activity --
  const hours = (peak) => Array.from({ length: 24 }, (_, i) => ((i - peak + 24) % 24 < 12 ? 6 : 0));
  const PA = (site, offs, x = {}) => ({ site, site_name: D.POST_ACTIVITY_SITES[site].name, username: H, found: true, state: "ok", cached: false, complete: true, pages: 1, unit: D.POST_ACTIVITY_SITES[site].unit, window_days_max: 365, bot: false, events: 72,
    window: { first: "2025-12-01T08:04:43Z", last: "2026-11-16T11:05:27Z", days: 350, active_days: 60 }, hours_utc: hours(8), weekdays_utc: [12, 12, 12, 12, 12, 6, 6], types: [{ type: site === "mastodon" ? "post" : site === "lobsters" ? "story" : "comment", count: 72 }],
    estimate: offs ? { utc_offset_from: offs[0], utc_offset_to: offs.at(-1), utc_offsets: offs, quiet_start_hour: 20, quiet_end_hour: 8, quiet_events: 0 } : null, estimate_reason: offs ? null : { code: "too_few_days", text: "x" },
    read: { posts: 80, outside_window: 8, capped: false, available: 80 }, ...x });
  ok(JSON.stringify(row(ev0, "acct:hackernews").canPostActivity) === JSON.stringify({ site: "hackernews", username: H }) && JSON.stringify(fo.canPostActivity) === JSON.stringify({ site: "mastodon", username: H, instance: "fosstodon.org" }) && ms.canPostActivity.instance === "mastodon.social" && row(ev0, "acct:lobsters").canPostActivity.site === "lobsters" && !cb.canPostActivity && !row(ev0, "acct:github").canPostActivity, "post activity can be asked on a read Hacker News, Mastodon or Lobsters row, with the row's own instance");
  const agree = { "acct:hackernews": PA("hackernews", [0, 1, 2, 3]), "acct:mastodon.social": PA("mastodon", [1, 2], { instance: "mastodon.social" }), "acct:lobsters": PA("lobsters", [-8, -7]), "acct:mastodon.online": PA("mastodon", [9, 10], { instance: "mastodon.online" }) };
  const cC = base({ postActivity: agree }), evC = buildEvidence(cC, H, "username"), rd = E.activityReadings(evC), cmp = E.offsetComparison(evC);
  ok(row(evC, "acct:hackernews").postActivity.state === "ok" && row(evC, "acct:hackernews").postActivity.label === "Hacker News" && row(evC, "acct:hackernews").postActivity.hours.length === 24 && row(evC, "acct:mastodon.online").postActivity.label === "Mastodon (mastodon.online)", "a reading is shown on its row as a view the activity renderer can draw");
  ok(rd.own.map((x) => x.label).join() === "GitHub,Hacker News,Mastodon" && rd.own.every((x) => x.own && x.note === "" && x.view && x.answer) && rd.own[0].kind === "github" && rd.own[0].heading === "GitHub activity" && rd.own[1].heading === "Hacker News post activity" && rd.own[1].key === "acct:hackernews", "the primary identity's readings are GitHub's and the post activity of its rows");
  ok(rd.other.map((x) => x.label).join() === "Lobsters,Mastodon (mastodon.online)" && rd.other.every((x) => !x.own && x.standing.own === false && / post activity \(not the person this case is about\)$/.test(x.heading)) && rd.other[0].note === "This is the post activity of the Lobsters account. Nothing ties that account to Sam Example, so it is not read as theirs.", "a reading of a row that is not the identity's says whose it is");
  ok(cmp.verdict === "agree" && cmp.compared === 3 && cmp.label === "UTC+1 to UTC+2" && cmp.text === "GitHub, Hacker News and Mastodon fit the same range (UTC+1 to UTC+2)." && cmp.labels.join() === "GitHub,Hacker News,Mastodon", "only the identity's own readings are compared: an untied row's range takes no part");
  const aC = an(cC, evC).assessment, lineC = aC.lines.find((l) => /UTC offset ranges estimated/.test(l.text));
  ok(lineC.level === "info" && /^Supporting, not proof\. /.test(lineC.text) && lineC.text.includes(cmp.text) && lineC.text.includes(D.OFFSETS_AGREE_NOTE) && lineC.text.includes(D.OFFSETS_NOT_A_PLACE) && aC.strength === a0.assessment.strength && aC.headline === a0.assessment.headline, "agreeing ranges are a supporting line that says it is not proof, and the strength does not move");
  const cD = base({ postActivity: { ...agree, "acct:hackernews": PA("hackernews", [-9, -8, -7]) } }), evD = buildEvidence(cD, H, "username"), lineD = an(cD, evD).assessment.lines.find((l) => /UTC offset ranges estimated/.test(l.text));
  ok(E.offsetComparison(evD).verdict === "disagree" && lineD.level === "flag" && lineD.text.includes("GitHub, Hacker News and Mastodon do not fit one range.") && lineD.text.includes(D.OFFSETS_DISAGREE_NOTE) && lineD.text.includes(D.OFFSETS_NOT_A_PLACE) && /\*\*Check:\*\* The UTC offset ranges/.test(md(cD)), "ranges that do not fit are a Check line with the caution, never a conclusion");
  ok(tiersOf(evD) === tiersOf(ev0) && clusters(evD) === clusters(ev0) && an(cD, evD).assessment.strength === a0.assessment.strength && tiersOf(evC) === tiersOf(ev0), "neither verdict changes a tier, a cluster or the strength");
  ok(E.offsetComparison(ev0).verdict === "not_enough_data" && !a0.assessment.lines.some((l) => /UTC offset ranges/.test(l.text)) && E.activityReadings(ev0).own.length === 1 && E.activityReadings(null).own.length === 0 && E.offsetComparison(null).verdict === "not_enough_data", "one reading is nothing to compare, and nothing is said");
  const lineOf = (c) => an(c).assessment.lines.filter((l) => /UTC offset/.test(l.text)).map((l) => l.text).join(" ") + (md(c).split("## Do the activity readings fit together")[1] || "").split("\n## ")[0] + JSON.stringify(E.aiPayloadFor(c, H, "username").offset_comparison || "");
  ok(lineOf(cC).length > 300 && lineOf(cD).length > 300 && !/\b(city|country|located|based in|lives in [A-Z]|time zone|Europe|America|Asia|Berlin|London)\b/.test(lineOf(cC) + lineOf(cD)), "no line turns a range of offsets into a place");
  const caseHN = buildEvidence(base({ postActivity: { "acct:hackernews": PA("hackernews", [0, 1], { username: "SamExample" }), "acct:mastodon.social": PA("mastodon", [0, 1], { instance: "fosstodon.org" }) } }), H, "username");
  ok(!row(caseHN, "acct:hackernews").postActivity && !row(caseHN, "acct:mastodon.social").postActivity && E.activityReadings(caseHN).own.length === 1, "an answer about another spelling of a Hacker News name, or another instance, is not this row's");
  const pk = base({ postActivity: agree, pick: { members: ["acct:gitlab"], at: 1 } }), evP = buildEvidence(pk, H, "username");
  ok(E.activityReadings(evP).own.length === 0 && E.activityReadings(evP).other.some((x) => x.kind === "github" && !x.own) && E.activityReadings(evP).other.find((x) => x.key === "acct:hackernews").note === "This is the post activity of the Hacker News account, which the findings file as a different person (Sam Example). It is that account's, not Petra Novak's." && E.offsetComparison(evP).verdict === "not_enough_data" && !("post_activity" in E.aiPayloadFor(pk, H, "username")), "after a pick of somebody else the readings are that other person's: labelled, not compared, not sent");
  const tl = personTimeline(cC, H, "username").events;
  ok(tl.some((e) => e.date === "2025-12-01" && e.title === "Oldest counted public post on Hacker News" && e.basis_text === "site record" && e.source === "Post activity" && /72 public posts counted, from the 365 days before the newest one\./.test(e.detail)) && tl.some((e) => e.date === "2026-11-16" && e.title === "Latest public post on Mastodon") && tl.some((e) => e.title === "Oldest counted submitted story on Lobsters" && /Consistent with the primary identity, not proven/.test(e.detail)) && !personTimeline(pk, H, "username").events.some((e) => / on Hacker News$/.test(e.title)), "the first and last counted post of a reading are on the timeline as site records, for Linked and matching rows only");
  const mC = md(cC);
  ok(/## Hacker News post activity\n- 72 public posts from 2025-12-01 to 2026-11-16/.test(mC) && /## Lobsters post activity \(not the person this case is about\)\n_This is the post activity of the Lobsters account\./.test(mC) && /## Do the activity readings fit together\n- GitHub, Hacker News and Mastodon fit the same range \(UTC\+1 to UTC\+2\)\. This supports one person/.test(mC) && !/## Do the activity readings/.test(md(c0)), "the export has a section per reading, each under a heading that says whose it is, and the comparison");
  const sC = steps(c0);
  ok(sC.find((s) => s.id === "posts:acct:hackernews")?.action.kind === "post-activity" && sC.find((s) => s.id === "posts:acct:hackernews").title === "Read when the Hacker News account posts" && /a hint and never a place/.test(sC.find((s) => s.id === "posts:acct:hackernews").reason) && sC.some((s) => s.id === "posts:acct:fosstodon.org" || s.id === "posts:acct:mastodon.social") && !sC.some((s) => s.id === "posts:acct:lobsters" || s.id === "posts:acct:mastodon.online") && !steps(cC).some((s) => s.id === "posts:acct:hackernews"), "post activity is suggested for an account of the identity with no reading yet");

  // -- D. archive diff --
  const KURL = `https://keybase.io/${H}`, GURL = `https://gitlab.com/${H}`;
  const ARCH = (url) => D.readArchive({ state: "ok", count: 3, first: "2019-03-04T05:06:07Z", last: "2024-01-02T03:04:05Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }, { timestamp: "2021-06-01T00:00:00Z" }, { timestamp: "2024-01-02T03:04:05Z" }], distinct_versions: 3 }, url);
  const cap = (ts, title) => ({ state: "ok", timestamp: ts, asked: ts, exact: true, bytes: 100, truncated: false, title, text_lines: 9, links: 4 });
  const DIFF = (url, x = {}) => ({ url, state: "ok", from: cap("2021-06-01T00:00:00Z", "samexample on Keybase"), to: cap("2024-01-02T03:04:05Z", "samexample on Keybase"),
    removed: { text: ["Night shift cartographer at Example Maps.", "Lisbon"], text_total: 2, links: [{ url: "https://social.example.net/@samold", external: true }, { url: "https://old-site.example.org", external: true }, { url: "https://sam-notes.example.net/about", external: true }, { url: "https://twitter.com/", external: true }, { url: "https://www.pornhub.com/users/x", external: true }, { url: `${url}/sub`, external: false }], links_total: 6 },
    added: { text: ["S E"], text_total: 1, links: [{ url: "https://added.example.com/page", external: true }], links_total: 1 }, complete: true, swapped: false, cached: false, ...x });
  const cA = base({ archives: { "acct:keybase": ARCH(KURL), "acct:gitlab": ARCH(GURL), "acct:npm": D.readArchive({ state: "none" }, `https://www.npmjs.com/~${H}`) } }), evA = buildEvidence(cA, H, "username");
  ok(row(evA, "acct:keybase").archiveDiffPairs.length === 3 && row(evA, "acct:keybase").archiveDiffPairs[0].default === true && row(evA, "acct:keybase").archiveDiffPairs[0].from === "2021-06-01T00:00:00Z" && !row(evA, "acct:npm").archiveDiffPairs && !row(evA, "acct:mastodon.social").archiveDiffPairs && !row(evA, "acct:keybase").archiveDiff, "two copies can be compared only where the archive listed two or more captures");
  const sA = steps(cA).find((s) => s.id === "diff:acct:keybase");
  ok(sA && sA.action.kind === "archive-diff" && sA.action.key === "acct:keybase" && sA.action.from === "2021-06-01T00:00:00Z" && sA.action.to === "2024-01-02T03:04:05Z" && sA.title === "Compare two archived copies of the Keybase profile" && /copies from 3 days/.test(sA.reason) && !steps(cA).some((s) => s.id === "diff:acct:gitlab"), "comparing the two newest copies is suggested for a profile of the identity, never for another person's");
  const cX = { ...cA, archiveDiffs: { "acct:keybase": DIFF(KURL), "acct:gitlab": DIFF(GURL, { removed: { text: ["Petra"], text_total: 1, links: [{ url: "https://petra.example.org/cv", external: true }], links_total: 1 } }) } }, evX = buildEvidence(cX, H, "username");
  const dv = row(evX, "acct:keybase").archiveDiff;
  ok(dv.state === "ok" && dv.removed.text.join("|") === "Night shift cartographer at Example Maps.|Lisbon" && dv.from.label === "2021-06-01" && dv.removed.links.every((l) => !/pornhub/.test(l.label)) && row(evX, "acct:gitlab").archiveDiff.state === "ok" && !steps(cX).some((s) => /^diff:/.test(s.id)), "the answer is shown on its row, and is not suggested again");
  const L = (k) => evX.items.find((i) => i.key === k);
  ok(L("lead:url:https://social.example.net/@samold")?.tied === true && !L("lead:domain:social.example.net") && L("lead:url:https://social.example.net/@samold").meta === "link · removed from the archived Keybase profile between 2021-06-01 and 2024-01-02" && L("lead:url:https://social.example.net/@samold").source === "Internet Archive", "a removed link to a page on a platform is a link lead, and says where it came from");
  ok(L("lead:domain:old-site.example.org")?.action.pivot === "recon" && !L("lead:url:https://old-site.example.org") && L("lead:domain:sam-notes.example.net")?.tied === true && L("lead:url:https://sam-notes.example.net/about") && !evX.items.some((i) => i.tier === "lead" && /twitter\.com|pornhub|added\.example|keybase\.io\/samexample\/sub|petra\.example/.test(i.what)), "a bare personal domain is a domain lead; a platform's front page, an adult site, an added link, a link on the profile's own site and a different person's row give nothing");
  const mX = md(cX);
  ok(/  - Archive diff: Between the captures of 2021-06-01 and 2024-01-02: 2 lines and 6 links removed, 1 line and 1 link added\./.test(mX) && /    - Removed text: "Night shift cartographer at Example Maps\."; "Lisbon"/.test(mX), "the export has the comparison under the row");
  const aiX = JSON.stringify(E.aiPayloadFor(cX, H, "username"));
  ok(!/Night shift cartographer|samold|old-site\.example\.org"|archive_diff/.test(aiX.replace(/"accounts":\[.*?\]/, "")) && !/Night shift cartographer/.test(aiX), "the text of an archive diff is not sent to the model");
  ok(tiersOf(evX) === tiersOf(ev0) && clusters(evX) === clusters(ev0), "and it moves no row and no profile");
  const other = buildEvidence({ ...cA, archiveDiffs: { "acct:keybase": DIFF(GURL) } }, H, "username");
  ok(!row(other, "acct:keybase").archiveDiff && !buildEvidence(base({ archiveDiffs: { "acct:keybase": DIFF(KURL) } }), H, "username").items.some((i) => i.archiveDiff || (i.tier === "lead" && i.source === "Internet Archive")), "a comparison of another address, or one with no capture list behind it, is not shown and leads nowhere");
  // the minor guard reads the same text as the server records
  const pt = E.profileTexts(cX), ia = pt.filter((e) => e.source === "Internet Archive");
  ok(ia.length === 2 && JSON.stringify(ia[0]) === JSON.stringify({ source: "Internet Archive", url: `https://web.archive.org/web/20210601000000/${KURL}`, name: "", bio: "samexample on Keybase\nNight shift cartographer at Example Maps.\nLisbon\nS E", text: "" }) && pt.indexOf(ia[0]) > pt.findIndex((e) => e.source === "Lobsters") && JSON.stringify(E.profileTexts({ ...cX, archiveDiffs: D.readArchiveDiffs(cX.archiveDiffs) })) === JSON.stringify(pt), "the content check reads the titles and the lines of an archive diff, after the profile sources, the same from a stored case");
  const cBX = { ...cB, archiveDiffs: cX.archiveDiffs };
  ok(JSON.stringify(E.profileTexts({ ...cBX, commitEmails: D.readCommitEmails(cBX.commitEmails) })) === JSON.stringify(E.profileTexts(cBX)) && E.profileTexts(cBX).findIndex((e) => e.source === "Internet Archive") > E.profileTexts(cBX).findIndex((e) => e.source === "Gitea.com") && JSON.stringify(E.profileTexts(E.storedCase(cBX))) === JSON.stringify(E.profileTexts(cBX)), "commit names read from a stored case are the same text as the live answer, and the archive text comes after them");

  // -- G. what the model is told --
  const cG = base({ postActivity: agree, commitEmails: cB.commitEmails, archives: cA.archives, archiveDiffs: cX.archiveDiffs }), aiG = E.aiPayloadFor(cG, H, "username");
  ok(aiG.post_activity.length === 2 && aiG.post_activity.map((x) => x.site).join() === "Hacker News,Mastodon" && aiG.post_activity[0].hours_utc.length === 24 && aiG.post_activity[0].utc_offset_estimate.range === "UTC to UTC+3" && !JSON.stringify(aiG.post_activity).includes("Lobsters"), "post activity is sent for the identity's own rows only");
  ok(aiG.offset_comparison.verdict === "agree" && aiG.offset_comparison.accounts.join() === "GitHub,Hacker News,Mastodon" && aiG.offset_comparison.shared_range === "UTC+1 to UTC+2" && /never a place/.test(aiG.offset_comparison.caution), "the comparison is sent as a verdict, the accounts and the shared range, with the caution");
  ok(aiG.commit_emails.length === 1 && aiG.commit_emails[0].site === "Codeberg" && aiG.commit_emails[0].addresses.length === 2 && aiG.commit_emails[0].addresses.every((x) => x.self_declared === true && ["forge_attributed", "author_line_match"].includes(x.tie)) && !/petra@example\.org|org@example\.net/.test(JSON.stringify(aiG)), "commit addresses are sent for the identity's own rows only, each with its tie and marked self-declared");
  const many = base({ postActivity: { ...agree, "acct:fosstodon.org": PA("mastodon", [1, 2], { instance: "fosstodon.org" }), "acct:lobsters": PA("lobsters", [1, 2]) } }); many.profiles.profiles.find((p) => p.source === "lobsters").display_name = "Sam Example";
  ok(E.activityReadings(buildEvidence(many, H, "username")).own.length === 5 && E.aiPayloadFor(many, H, "username").post_activity.length === 3, "at most three readings are sent");
  ok(E.aiSignature(cG, H, "username") !== E.aiSignature(c0, H, "username") && E.aiSignature(c0, H, "username") === E.aiSignature(base(), H, "username") && !("post_activity" in ai0) && !("offset_comparison" in ai0) && !("commit_emails" in ai0), "a new reading changes what a report was written from; a case without one sends no new key");

  // -- E. the self-audit in the export, and its pointer among the next steps --
  const me = setSelfAudit(cB, true, 1700000000000), mM = md(me);
  ok(/## Reduce your footprint\n_The investigator marked this case as being about themselves \("This is me"\)\. That is their own statement, not a finding of the tool\._\n/.test(mM) && (mM.match(/## Reduce your footprint/g) || []).length === 1 && /\n1\. \*\*/.test(mM.split("## Reduce your footprint")[1]) && !/## Reduce your footprint/.test(mB) && !/## Reduce your footprint/.test(E.caseMarkdown({ collected: { hash: hs.malicious, selfAudit: { on: true, at: 1 } }, target: hs.malicious.hash, type: "hash" })), "the export has the self-audit only for a person case marked This is me, as the investigator's own statement");
  const sM = steps(me);
  ok(sM.find((s) => s.id === "audit:footprint")?.action.kind === "focus" && sM.find((s) => s.id === "audit:footprint").action.where === "footprint" && !sM.some((s) => s.id === "audit:commit-email" || s.id === "audit:breaches") && sB.some((s) => s.id === "audit:commit-email" && s.tag === "self-audit" && /On GitLab, Codeberg or Gitea\.com/.test(s.reason)) && !sB.some((s) => s.id === "audit:footprint"), "a case marked This is me points to its view once; otherwise the self-audit hints stay");
  // adult and dating site rows are built apart: none of the lookups is ever offered on one
  const ad = fx("adult"), evAd = buildEvidence({ ...ad.collected, commitEmails: { "acct:pornhub": CE("gitlab") }, postActivity: { "acct:pornhub": PA("hackernews", [0, 1]) } }, ad.target, ad.type);
  ok(tier(evAd, "adult").length > 0 && evAd.items.filter((i) => i.tier === "adult" || /pornhub|onlyfans|fansly|tinder/i.test(`${i.key} ${i.url}`)).every((i) => !i.canCommitEmails && !i.canPostActivity && !i.archiveDiffPairs && !i.commitEmails && !i.postActivity && !i.archiveDiff && !i.archive) && !caseAnalysis(evAd, { collected: ad.collected, target: ad.target, type: ad.type }).suggestions.top.concat(caseAnalysis(evAd, { collected: ad.collected, target: ad.target, type: ad.type }).suggestions.more).some((s) => /^(commits|posts|diff):/.test(s.id) && evAd.items.find((i) => i.key === s.action.key)?.tier === "adult"), "no lookup is offered or suggested for an adult or dating site row");
  // a case the minor guard stopped suggests nothing
  const stopped = an({ ...cA, adultBlock: { kind: "age", source: "Reddit", snippet: "x", url: "" } }).suggestions;
  ok(stopped.top.length === 0 && /sign of a minor/.test(stopped.note), "nothing is suggested for a case the minor guard stopped");
}

// ---- the archive comparison needs a handle the server takes --------------------------------------
// POST /api/recon/archive-diff refuses a request without a username, so a row offers the
// comparison only with one: the case's handle in a username case, the row's own in an email case.
{
  const D = await import("../../static/v2/js/deep.js");
  const ARCH = (u) => D.readArchive({ state: "ok", count: 3, first: "2019-03-04T05:06:07Z", last: "2024-01-02T03:04:05Z", snapshots: [{ timestamp: "2019-03-04T05:06:07Z" }, { timestamp: "2021-06-01T00:00:00Z" }, { timestamp: "2024-01-02T03:04:05Z" }], distinct_versions: 3 }, u);
  const G = "https://gravatar.com/maralind";
  const grav = (x) => ({ gravatar: { found: true, profile_url: G, display_name: "maralind", name: "Mara Lind", avatar_url: "", ...x }, archives: { "acct:gravatar": ARCH(G) } });
  const e1 = row(buildEvidence(grav(), "mara@tidepool.example", "email"), "acct:gravatar");
  ok(e1.archiveDiffPairs.length === 3 && e1.archiveDiffUser === "maralind", "in an email case the comparison is sent with the row's own handle");
  const K = "https://keybase.io/samexample", kb = { profiles: { username: "samexample", profiles: [{ site: "Keybase", source: "keybase", handle: "samexample", url: K, state: "found", display_name: "Sam Example" }], sources: { keybase: { site: "Keybase", state: "found" } } }, archives: { "acct:keybase": ARCH(K) } };
  const u1 = row(buildEvidence(kb, "@samexample", "username"), "acct:keybase");
  ok(u1.archiveDiffPairs.length === 3 && u1.archiveDiffUser === "samexample", "in a username case it is sent with the case's handle, without the @");
  const u2 = row(buildEvidence(kb, "sam example!", "username"), "acct:keybase");
  ok(u2 && u2.archive?.view?.state === "ok" && !u2.archiveDiffPairs && !u2.archiveDiffUser && !caseAnalysis(buildEvidence(kb, "sam example!", "username"), { collected: kb, target: "sam example!", type: "username", failed: [] }).suggestions.top.some((x) => x.id.startsWith("diff:")), "with no handle the server would take, the comparison is not offered and not suggested");
}

console.log(`${n - bad}/${n} evidence checks passed`);
process.exit(bad ? 1 : 0);
