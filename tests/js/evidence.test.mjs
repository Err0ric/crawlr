// The ledger, leads, breach and hash rows, recon findings and the source tally, checked against
// trimmed copies of responses recorded for the audit targets (tests/js/fixtures). No browser, no network.
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
const { buildEvidence, accountsFor, breachList, breachMeta, hashView, hashCoverage, collectProfiles, sourcePlan, isFreeMail, ledgerTiers, TIERS, isFinding, factsFor, avatarImages, tierCounts } = await import("../../static/v2/js/evidence.js");
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
ok(TIERS.map((t) => t.id).join() === "flag,info,linked,matches,different,unverified,lead,hosts,noise", "tier order");
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
  ok(/flag: \d+ different people use this handle: Linus Torvalds on GitHub, Snapchat/.test(b), "the brief counts people, not names");
  ok(Number(b.match(/flag: (\d+) different people/)[1]) === 1 + ev.identity.views.filter((v) => v.different).length && ev.identity.views.filter((v) => v.different).length === new Set(tier(ev, "different").map((i) => i.person)).size, "it counts exactly the people the ledger calls different, plus the primary");
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
  ok(!row(v2, "acct:tiktok") && !row(v2, "acct:onlyfans"), "not_found and manual add nothing");
  const b2 = text(investigateBrief({ collected: { ...er.collected, platformCheck: er.platformCheckV2 }, items: v2.items, facts: v2.facts, identity: v2.identity, failed: [], type: "username", target: er.target }));
  ok(/LinkedIn blocked the check, so that account is unknown, not absent/.test(b2), "the brief says a blocked site is unknown");
  const dead = buildEvidence({ ...er.collected, maigret: { error: "timeout", error_code: "timeout", results: er.collected.maigret.results } }, er.target, er.type);
  ok(!dead.identity.views.some((v) => v.label === "Eric Henderson") && row(dead, "acct:threads").tier === "unverified", "a failed source contributes nothing, even if it carries rows");
}

// ---- G. email flow -------------------------------------------------------------------
ok(sourcePlan("email", "torvalds@linux-foundation.org").join() === "holehe,hibp,gravatar,harvester,hunter", "an email runs no username tools");
ok(!sourcePlan("email", "someone@gmail.com").includes("harvester") && !sourcePlan("email", "a@GMX.de").includes("harvester"), "the domain harvest is skipped for mail providers");
ok(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "gmx.net", "aol.com", "live.com", "me.com", "mail.com", "yandex.ru"].every(isFreeMail) && !isFreeMail("linux-foundation.org") && !isFreeMail("notgmail.com"), "free-mail list");
ok(sourcePlan("username", "jdoe").join() === "sherlock,maigret,github,platform" && sourcePlan("hash", "x").join() === "hash", "other types keep their sources");
{
  const ev = buildEvidence(em.collected, em.target, em.type);
  const h = row(ev, "lead:handle:torvalds");
  ok(h && h.what === "torvalds" && /the part before the @/.test(h.meta) && h.action.label === "Investigate this" && h.action.value === "torvalds", "the local part is a handle lead with Investigate this");
  ok(buildEvidence({}, "j.doe+news@example.org", "email").items.find((i) => i.key === "lead:handle:j.doe"), "a +tag is dropped from the handle lead");
  ok(row(ev, "lead:handle:reallylinustorvalds") && row(ev, "lead:domain:linux-foundation.org").action.label === "Open in Recon", "the Gravatar username and the email's domain are leads too");
  ok(!buildEvidence({}, "someone@gmail.com", "email").items.some((i) => i.key === "lead:domain:gmail.com"), "a mail provider is not offered for recon");
  ok(tier(ev, "hosts").length === 8 && tier(ev, "hosts")[0].source === "Domain harvest" && /CertSpotter/.test(tier(ev, "hosts")[0].meta), "harvested hosts get their own group, each with its sources");
  ok(ledgerTiers(em.target, "email").find((t) => t.id === "hosts").title === "Hosts on linux-foundation.org" && ledgerTiers(em.target, "email").find((t) => t.id === "hosts").open === false, "the host group is named after the domain and collapsed");
  ok(ev.items.filter(isFinding).length === ev.items.length - 8 - tier(ev, "lead").length, "hosts and leads are not counted as findings");
  ok(row(ev, "acct:spotify").tier === "linked" && /registered with this email/.test(row(ev, "acct:spotify").meta) && row(ev, "acct:gravatar").tier === "linked", "registrations for the searched email are linked");
  ok(!ev.items.some((i) => i.source === "Sherlock" || i.source === "Maigret"), "no username rows in an email case");
  // H. breaches, old shape
  ok(tier(ev, "flag").length === 10 && row(ev, "breach:linkedin").meta === "credential exposure", "old breach shape (a list of names) still renders");
  const v2 = buildEvidence({ ...em.collected, hibp: em.hibpV2 }, em.target, em.type);
  ok(row(v2, "breach:linkedin").meta === "2012 · Email addresses, Passwords" && row(v2, "breach:linkedin").url.includes("xposedornot.com"), "new breach shape: year and data classes in the row");
  ok(tier(v2, "flag").map((i) => i.what).join("|") === "Breach: LinkedInScrape-2021|Breach: LinkedIn|Breach: AntiPublicCombo", "breach rows are newest first, undated last");
  const b = text(investigateBrief({ collected: { ...em.collected, hibp: em.hibpV2 }, items: v2.items, facts: v2.facts, identity: v2.identity, failed: [], type: "email", target: em.target }));
  ok(/3 known breaches \(LinkedInScrape-2021 2021, LinkedIn 2012, AntiPublicCombo\)/.test(b) && /Username tools were not run on "torvalds"/.test(b) && /8 hosts on linux-foundation.org/.test(b), "the email brief names breaches with years, the unsearched handle and the host inventory");
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
  ok(/2 different names appear under this handle .* none is tied to the target/.test(b) && !/different person|Only the first/.test(b), "the brief says the same");
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

console.log(`${n - bad}/${n} evidence checks passed`);
process.exit(bad ? 1 : 0);
