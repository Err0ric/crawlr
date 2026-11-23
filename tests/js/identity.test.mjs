// Identity clusters are rules, so every join and every refusal to join can be checked exactly.
// Data: trimmed copies of responses recorded for the audit targets (tests/js/fixtures).
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
import { clusterIdentities, compareNames, meaningfulName, nameTokens, hamming, popcount, lowInformation, standing, linkParts, looksBoilerplate, NO_PRIMARY } from "../../static/v2/js/identity.js";
import { collectProfiles } from "../../static/v2/js/evidence.js";

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = (f) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${f}.json`, import.meta.url), "utf8"));
const clusterOf = (res, id) => res.clusters.find((c) => c.members.includes(id));
const P = (id, o = {}) => ({ id: `acct:${id}`, site: id, url: `https://${id}.example/u/jdoe`, handle: "jdoe", name: "", location: "", links: [], bio: "", ...o });

// ---- names ---------------------------------------------------------------------
ok(nameTokens("Éric  HENDERSON-Smith!").join(" ") === "eric henderson smith", "case, accents and punctuation are folded");
ok(meaningfulName("torvalds", "torvalds") === null && meaningfulName("ToRvaLDs", "torvalds") === null && meaningfulName("Torvalds Torvalds", "torvalds") === null, "a name that only repeats the handle is no name");
ok(meaningfulName("Err0ric", "Err0ric") === null && meaningfulName("", "x") === null && meaningfulName("💎", "x") === null, "empty and symbol-only names are no name");
ok(meaningfulName("Patricia Torvalds", "torvalds")?.join(" ") === "patricia torvalds", "a name that contains the handle and more is a name");
const t = (s) => meaningfulName(s, "zz");
ok(compareNames(t("Linus Torvalds"), t("linus  TORVALDS")) === "same", "same name");
ok(compareNames(t("LinusTorvalds"), t("Linus Torvalds")) === "same", "the same name with the space removed");
ok(compareNames(t("Eric"), t("Eric Henderson")) === "subset" && compareNames(t("Linus"), t("Linus Torvalds")) === "subset", "a single name inside a full name is a match, never a conflict");
ok(compareNames(t("Eric Henderson"), t("Mary Okafor")) === "conflict", "two personal names that share no word conflict");
ok(compareNames(t("Patricia Torvalds"), t("Linus Torvalds"), ["torvalds"]) === "conflict", "sharing only the searched handle is not sharing a word");
ok(compareNames(t("Eric Henderson"), t("Eric Smith")) === "neutral" && compareNames(t("Patricia Torvalds"), t("Linus Torvalds")) === "neutral", "a shared word is neither a match nor a conflict");
// 4. the right person is not called different
for (const name of ["torvalds official", "L. Torvalds", "LinusTorvalds", "Линус Торвальдс", "Linux kernel dev", "linus", "NaraKa"]) {
  const tk = meaningfulName(name, "torvalds");
  ok(tk && compareNames(tk, meaningfulName("Linus Torvalds", "torvalds"), ["torvalds"]) !== "conflict", `"${name}" does not conflict with Linus Torvalds`);
}

// ---- avatars and links ------------------------------------------------------------
ok(hamming("ffffffffffffffff", "ffffffffffffffff") === 0 && hamming("ffffffffffffffff", "fffffffffffffffe") === 1 && hamming("0000000000000000", "ffffffffffffffff") === 64, "hamming distance on 64-bit hex");
ok(hamming("xyz", "ffffffffffffffff") === null, "a malformed hash compares as unknown");
ok(popcount("00000000000000ff") === 8 && lowInformation("000000000000007f") && !lowInformation("00000000000000ff") && lowInformation("ffffffffffffff7f") && !lowInformation("ffffffffffffff00") && lowInformation("zz"), "a hash with under 8 or over 56 set bits is low information");
ok(linkParts("https://www.Twitter.com/JDoe/").key === "x.com/jdoe" && linkParts("javascript:alert(1)") === null && linkParts("jdoe.dev").host === "jdoe.dev", "links are normalized and only http(s) counts");
ok(linkParts("https://fosstodon.org/@alice").platform && linkParts("https://social.example.org/@a").platform && !linkParts("https://jdoe.dev").platform, "multi-user services are recognized");
ok(looksBoilerplate("torvalds streams live on Twitch! Check out their videos") && !looksBoilerplate("Kernel hacker"), "old boilerplate bios are recognized");

const HASH = "c3c3e7e7ffff0f0f", NEAR = "c3c3e7e7ffff0f0d";
const tierOf = (res, p) => standing(p, res, { handle: "jdoe" });
const sig = (res, a, b) => [...res.clusters.flatMap((c) => c.links), ...res.supports].find((l) => (l.a === a && l.b === b) || (l.a === b && l.b === a))?.signals.map((s) => s.type).join(",") || "";

// ---- strong signals -----------------------------------------------------------------
{
  const ps = [
    P("github", { anchor: "github", name: "J Doe", links: ["https://twitter.com/jdoe"], websites: ["https://jdoe.dev"], avatarHash: HASH }),
    P("x", { url: "https://x.com/jdoe", name: "someone else entirely" }),
    P("keybase", { avatarHash: NEAR }),
    P("blog", { name: "Night Owl", websites: ["https://www.jdoe.dev/"] }),
    P("about", { name: "Other Writer", bio: "more at https://jdoe.dev/about", links: ["https://jdoe.dev/about"] }),
    P("forum", { name: "Unrelated Person" }),
  ];
  const res = clusterIdentities(ps, { handle: "jdoe" });
  const c = clusterOf(res, "acct:github");
  ok(c.primary && ["acct:x", "acct:keybase", "acct:blog"].every((id) => c.members.includes(id)) && !c.members.includes("acct:forum"), "a link from the anchor, the same avatar and a shared website each join, whatever the names say");
  ok(sig(res, "acct:github", "acct:x") === "cross-link" && sig(res, "acct:github", "acct:keybase") === "avatar" && sig(res, "acct:github", "acct:blog") === "shared-link", "each pair records the signal that joined it");
  ok(tierOf(res, ps[2]).tier === "linked" && /same avatar/.test(tierOf(res, ps[2]).why), "a strong signal makes a profile linked and says why");
  ok(tierOf(res, ps[5]).tier === "different", "a conflicting personal name is a different person");
  ok(!c.members.includes("acct:about") && sig(res, "acct:blog", "acct:about") === "", "a page on a site does not tie its author to the site's owner");
}
{
  // 1. shared links need host plus path; a bare site joins only as both profiles' website
  const fedi = clusterIdentities([P("a", { name: "Alice Stone", links: ["https://fosstodon.org/@alice"] }), P("b", { name: "Bob Reed", links: ["https://fosstodon.org/@bob"] })], { handle: "jdoe" });
  ok(clusterOf(fedi, "acct:a") !== clusterOf(fedi, "acct:b") && sig(fedi, "acct:a", "acct:b") === "", "two accounts on one fediverse host are not one person");
  const acme = clusterIdentities([P("gh", { anchor: "github", name: "Alice Stone", links: ["https://acme.com"] }), P("b", { name: "Bob Reed", links: ["https://acme.com/"] })], { handle: "jdoe" });
  ok(clusterOf(acme, "acct:b") !== clusterOf(acme, "acct:gh") && sig(acme, "acct:gh", "acct:b") === "shared-site", "both mentioning acme.com is support, never a join");
  ok(tierOf(acme, P("b", { name: "Bob Reed" })).tier === "different", "and it does not rescue a conflicting name");
  const site = clusterIdentities([P("a", { name: "Alice Stone", websites: ["https://alice.example"] }), P("b", { name: "A Stone Writes", websites: ["alice.example"] })], { handle: "jdoe" });
  ok(clusterOf(site, "acct:a") === clusterOf(site, "acct:b") && sig(site, "acct:a", "acct:b").includes("shared-link"), "the same personal site in both website fields joins");
  const svc = clusterIdentities([P("a", { name: "Alice Stone", websites: ["https://fosstodon.org"] }), P("b", { name: "Bob Reed", websites: ["https://fosstodon.org"] })], { handle: "jdoe" });
  ok(clusterOf(svc, "acct:a") !== clusterOf(svc, "acct:b"), "a multi-user service is never a personal site, even in a website field");
  const page = clusterIdentities([P("a", { name: "Alice Stone", links: ["https://alice.example/about"] }), P("b", { name: "Bob Reed", links: ["https://alice.example/about/"] })], { handle: "jdoe" });
  ok(clusterOf(page, "acct:a") === clusterOf(page, "acct:b"), "the same page on a personal site joins");
  const repo = clusterIdentities([P("a", { name: "Alice Stone", links: ["https://github.com/torvalds/linux"] }), P("b", { name: "Bob Reed", links: ["https://github.com/torvalds/linux"] }), P("c", { name: "Cy Vale", links: ["https://kernel.org/doc"] }), P("d", { name: "Di Wren", links: ["https://kernel.org/doc"] })], { handle: "jdoe" });
  ok(repo.clusters.every((c) => c.members.length === 1), "two people linking the same repository or documentation page are not one person");
}
{
  // 2. default and low-information avatars never link
  const res = clusterIdentities([
    P("a", { avatarHash: HASH, avatarDefault: true, links: ["https://github.com"] }), P("b", { avatarHash: HASH, avatarDefault: true, links: ["https://github.com/"] }),
    P("c", { avatarHash: "0000000000000000" }), P("d", { avatarHash: "0000000000000000" }), P("e", { avatarHash: "ffffffffffffffff" }), P("f", { avatarHash: "fffffffffffffffe" }),
    P("g", { avatarHash: "0000000000000013" }), P("h", { avatarHash: "0000000000000013" }),
  ], { handle: "jdoe" });
  ok(res.clusters.length === 0 && res.unassigned.length === 8, "default avatars, near-blank hashes and platform homepages never link profiles");
  const far = clusterIdentities([P("a", { avatarHash: "ffffffff00000000" }), P("b", { avatarHash: "ffffffffffff0000" })], { handle: "jdoe" });
  ok(far.clusters.length === 0, "avatars more than 6 bits apart do not link");
  const near = clusterIdentities([P("a", { avatarHash: HASH }), P("b", { avatarHash: NEAR })], { handle: "jdoe" });
  ok(near.clusters.length === 1 && near.clusters[0].primary, "two real avatars 1 bit apart link, and make the only strong group primary");
}
{
  // 3. cross-links: first path segment, and one-way only from the anchor's side
  const gh = P("github", { anchor: "github", url: "https://github.com/torvalds", handle: "torvalds", name: "Linus Torvalds" });
  const repoLink = clusterIdentities([gh, P("blog", { handle: "torvalds", name: "Mallory Vance", links: ["https://github.com/mallory/torvalds"] })], { handle: "torvalds" });
  ok(sig(repoLink, "acct:github", "acct:blog") === "", "github.com/mallory/torvalds is not a link to torvalds");
  const fan = P("fan", { handle: "torvalds", name: "", links: ["https://github.com/torvalds"] });
  const oneWay = clusterIdentities([gh, fan], { handle: "torvalds" });
  ok(clusterOf(oneWay, "acct:fan") === undefined && sig(oneWay, "acct:github", "acct:fan") === "one-way-link", "an unrelated profile that links to the anchor is support only");
  const st = standing(fan, oneWay, { handle: "torvalds" });
  ok(st.tier === "matches" && /links to the github profile, not confirmed from the other side/.test(st.why), "it lands in matches and says the link is not confirmed");
  const impostor = P("imp", { handle: "torvalds", name: "Mallory Vance", links: ["https://github.com/torvalds"] });
  ok(standing(impostor, clusterIdentities([gh, impostor], { handle: "torvalds" }), { handle: "torvalds" }).tier !== "linked", "a conflicting profile that links to the anchor is never linked");
  const mutual = clusterIdentities([P("a", { name: "Ann Lee", url: "https://a.example/u/jdoe", links: ["https://b.example/u/jdoe"] }), P("b", { name: "Zed Other", url: "https://b.example/u/jdoe", links: ["https://a.example/u/jdoe"] })], { handle: "jdoe" });
  ok(clusterOf(mutual, "acct:a") === clusterOf(mutual, "acct:b") && sig(mutual, "acct:a", "acct:b") === "cross-link", "a mutual link is strong without an anchor");
  const chain = clusterIdentities([gh, P("x", { handle: "torvalds", url: "https://x.com/torvalds", links: ["https://keybase.io/torvalds"] }), P("keybase", { handle: "torvalds", url: "https://keybase.io/torvalds" }), { ...gh, links: ["https://x.com/torvalds"] }].slice(1), { handle: "torvalds" });
  ok(clusterOf(chain, "acct:github").members.length === 3 && sig(chain, "acct:x", "acct:keybase") === "cross-link", "a link from a profile the anchor already vouches for is strong too");
}
{
  // 4. names the anchor's owner might use are matches, not different people
  const gh = P("github", { anchor: "github", handle: "torvalds", name: "Linus Torvalds" });
  for (const name of ["torvalds official", "L. Torvalds", "LinusTorvalds", "Линус Торвальдс", "Linux kernel dev"]) {
    const p = P("other", { handle: "torvalds", name });
    const res = clusterIdentities([gh, p], { handle: "torvalds" });
    ok(standing(p, res, { handle: "torvalds" }).tier === "matches", `"${name}" beside Linus Torvalds is matches, not different`);
  }
  const pat = P("medium", { handle: "torvalds", name: "Patricia Torvalds" });
  ok(standing(pat, clusterIdentities([gh, pat], { handle: "torvalds" }), { handle: "torvalds" }).tier === "different", "Patricia Torvalds is still a different person");
}
{
  // 5. no anchor and no strong signal: nobody is picked and nobody is called different
  const ps = [P("a", { name: "Bob Arnold" }), P("b", { name: "Carol Baker" }), P("c", { name: "Carol Baker" })];
  const res = clusterIdentities(ps, { handle: "jdoe" });
  ok(res.primary === null && res.clusters.length === 2 && !res.clusters.some((c) => c.primary), "no anchor and no strong signal means no primary identity");
  ok(ps.every((p) => standing(p, res, { handle: "jdoe" }).tier === "matches" && standing(p, res, { handle: "jdoe" }).why === NO_PRIMARY), "every read profile is matches: exists, nothing ties it to the target");
  const tie = clusterIdentities([P("a", { name: "Ann Lee", avatarHash: HASH }), P("b", { avatarHash: NEAR }), P("c", { name: "Zed Other", avatarHash: "0f0f0f0f33335555" }), P("d", { avatarHash: "0f0f0f0f33335557" })], { handle: "jdoe" });
  ok(tie.primary === null, "two equally strong groups with no anchor: still nobody is picked");
}
{
  // 6. a single name joins only when exactly one cluster fits, whatever the order
  const base = [P("a", { name: "Priya" }), P("b", { name: "Priya Sharma" }), P("c", { name: "Priya Patel" }), P("d", { name: "Eric" }), P("e", { name: "Eric Henderson" }), P("f", { name: "Zed Other" })];
  const shape = (r) => JSON.stringify(r.clusters.map((c) => [...c.members].sort()).sort());
  const want = shape(clusterIdentities(base, { handle: "jdoe" }));
  const first = clusterIdentities(base, { handle: "jdoe" });
  ok(clusterOf(first, "acct:a").members.length === 1 && clusterOf(first, "acct:b") !== clusterOf(first, "acct:c"), "Priya joins neither Priya Sharma nor Priya Patel");
  ok(clusterOf(first, "acct:d") === clusterOf(first, "acct:e") && sig(first, "acct:d", "acct:e") === "weak-name", "Eric joins the one Eric Henderson, recorded as a weak name match");
  let same = true, seed = 7;
  for (let n = 0; n < 40; n++) { const sh = base.map((p) => [p, (seed = (seed * 1103515245 + 12345) % 2147483648)]).sort((x, y) => x[1] - y[1]).map((x) => x[0]); if (shape(clusterIdentities(sh, { handle: "jdoe" })) !== want) same = false; }
  ok(same, "40 shuffles of the input give the same clusters");
  const loc = clusterIdentities([P("a", { name: "J Doe", location: "Portland, OR" }), P("b", { name: "j doe", location: "portland or" })], { handle: "zz" });
  ok(loc.clusters[0].links[0].signals.some((s) => s.type === "location"), "a matching location is recorded as support");
}
{
  // primary: GitHub anchor, then Gravatar anchor, then the one strongly tied group
  const ps = [P("a", { name: "Big Group" }), P("b", { name: "Big Group" }), P("c", { name: "Big Group" }), P("d", { name: "Small One", links: ["https://small.example/me"] }), P("e", { name: "Other Name", links: ["https://small.example/me"] })];
  ok(clusterOf(clusterIdentities(ps), "acct:d").primary, "a strongly tied group outranks a larger one joined by name");
  ok(clusterIdentities(ps.slice(0, 3).concat(P("z", { name: "Lone Wolf" }))).primary === null, "size alone never makes a primary");
  ok(clusterIdentities([...ps, P("gr", { anchor: "gravatar" })]).clusters[0].anchor === "gravatar", "a Gravatar anchor outranks both");
  ok(clusterIdentities([...ps, P("gr", { anchor: "gravatar" }), P("gh", { anchor: "github" })]).clusters[0].anchor === "github", "the GitHub anchor outranks everything");
  ok(clusterIdentities([P("gh", { anchor: "github", name: "jdoe" })], { handle: "jdoe" }).clusters[0].label === "jdoe", "an anchor with no name still gets a cluster, labelled with the handle");
}

// ---- torvalds: many people, one handle --------------------------------------------------
{
  const f = fx("torvalds");
  const profiles = collectProfiles(f.collected, f.target, f.type);
  const res = clusterIdentities(profiles, { handle: f.target });
  const primary = res.clusters[0];
  ok(primary.primary && primary.label === "Linus Torvalds" && primary.anchor === "github", "Linus Torvalds is the primary cluster, anchored on GitHub");
  ok(primary.members.includes("acct:github") && primary.members.includes("acct:snapchat") && primary.members.length === 2, "GitHub and Snapchat (both Linus Torvalds) are together, and nothing else is");
  const marco = clusterOf(res, "acct:pinterest"), pat = clusterOf(res, "acct:medium");
  ok(marco.label === "Marco Migozzi" && marco.members.includes("acct:threads") && !marco.primary, "Pinterest and Threads (Marco Migozzi) are one other person");
  ok(pat.label === "Patricia Torvalds" && pat.members.length === 1 && !pat.primary && pat !== marco, "Patricia Torvalds on Medium is a third person");
  ok(["acct:x", "acct:telegram", "acct:soundcloud", "acct:tiktok"].every((id) => res.unassigned.includes(id)), "profiles whose name only repeats the handle stay unassigned");
  ok(!profiles.some((p) => /Join Facebook|is on Snapchat/.test(p.bio)), "boilerplate bios from the old run are dropped");
  const again = clusterIdentities(collectProfiles(f.collected, f.target, f.type), { handle: f.target });
  const shuffled = clusterIdentities([...profiles].reverse(), { handle: f.target });
  ok(JSON.stringify(res) === JSON.stringify(again), "the same input gives the same clusters");
  const shape = (r) => JSON.stringify(r.clusters.map((c) => [c.label, c.primary, [...c.members].sort()]).sort());
  ok(shape(res) === shape(shuffled) && shuffled.clusters[0].label === "Linus Torvalds", "input order does not change who is clustered with whom or which is primary");
}

// ---- Err0ric: a first name and a full name are not a conflict ---------------------------
{
  const f = fx("err0ric");
  const profiles = collectProfiles(f.collected, f.target, f.type);
  const res = clusterIdentities(profiles, { handle: f.target });
  const eric = clusterOf(res, "acct:youtube");
  ok(eric && eric.members.includes("acct:threads") && eric.label === "Eric Henderson", "Eric on YouTube and Eric Henderson on Threads are one cluster");
  ok(eric.links.some((l) => l.signals.some((s) => s.type === "weak-name")), "and the join is recorded as a weak name match");
  const noGh = clusterIdentities(profiles.filter((p) => p.id !== "acct:github"), { handle: f.target });
  ok(noGh.primary === null, "without the GitHub record nobody is picked as primary");
  ok(res.clusters[0].anchor === "github" && !res.clusters[0].named, "the GitHub record (name equals the handle) is primary and carries no name");
  ok(standing(profiles.find((p) => p.id === "acct:youtube"), res, { handle: f.target }).tier === "matches", "with no name on the primary record, a named profile is not called a different person");
}

console.log(`${n - bad}/${n} identity checks passed`);
process.exit(bad ? 1 : 0);
