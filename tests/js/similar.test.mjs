// Similar handles and the "taken" state: the variant generator, the line-up rules, the stored
// checks as outside data, how an added profile enters and leaves the ledger, and what the AI is
// told. No browser, no network. Names of people here are invented.
// Run: node tests/js/similar.test.mjs
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document ??= { addEventListener() {} };
const S = await import("../../static/v2/js/similar.js");
const { handleVariants, nameVariants, similarHandles, similarBase, readProbe, readSimilar, asProfile, lineUp, evaluateSimilar, addedProfiles, variantOutcome, variantSummary, sourceStates, similarBrief, similarItems, similarBlurb, profileId, MAX_VARIANTS, MAX_STORED, SIMILAR_BLURB } = S;
const { buildEvidence, accountsFor, aiPayloadFor, aiSignature, collectProfiles, isFinding, ledgerTiers, tierCounts, caseMarkdown, deepDiveUrls, avatarImages } = await import("../../static/v2/js/evidence.js");
const { handlePatterns, parseName } = await import("../../static/v2/js/names.js");
const { investigateBrief } = await import("../../static/v2/js/brief.js");
const { investigateTiles, rowCertainty, withoutThumbs, safeThumb } = await import("../../static/v2/js/present.js");
const { parseCaseFile, buildCaseFile } = await import("../../static/v2/js/casefile.js");
const { renderTiers, evWhat, evSrc, pillOf } = await import("../../static/v2/js/workbench.js");
const { sourceTally, sourceCoverage, sourceHasResults } = await import("../../static/v2/js/core.js");
const { sourceCards } = await import("../../static/v2/js/renderers.js");
const L = await import("../../static/v2/js/links.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const fx = (f) => JSON.parse(fs.readFileSync(new URL(`./fixtures/${f}.json`, import.meta.url), "utf8"));
const values = (h, o) => similarHandles(h, o).map((x) => x.value);
const VALID = /^[A-Za-z0-9._-]{1,64}$/;
const THUMB = fx("identity-extras").avatarHash.results.find((r) => r.thumb).thumb;

// ---- variants ------------------------------------------------------------------------------
{
  const samples = ["torvalds", "Err0ric", "john_smith99", "x_alice_x", "ab", "12345", "JohnSmith", "l33tHax0r", "TheRealSam_Official", "user2015", "heyyy", "4lice", "a.b-c_d", "x".repeat(64), "_under_", "h1dden"];
  for (const h of samples) {
    const v = similarHandles(h, { name: "Sam Example" });
    ok(v.length <= MAX_VARIANTS && v.every((x) => VALID.test(x.value) && !x.value.startsWith("-") && x.value.length >= 2), `${h}: every variant passes the server's username pattern, at most ${MAX_VARIANTS}`);
    ok(v.every((x) => x.value.toLowerCase() !== h.toLowerCase()) && new Set(v.map((x) => x.value)).size === v.length, `${h}: never the handle itself, no duplicates`);
    ok(v.every((x) => typeof x.reason === "string" && x.reason.length > 5 && !/undefined|null/.test(x.reason) && !x.reason.includes(String.fromCharCode(0x2014))), `${h}: every variant says why in plain words`);
    ok(JSON.stringify(similarHandles(h, { name: "Sam Example" })) === JSON.stringify(v), `${h}: the same input gives the same list`);
  }
  // torvalds: a plain word. Nothing to take off, so the name comes first, then things put on.
  const tv = similarHandles("torvalds", { name: "Linus Torvalds" });
  ok(tv.map((x) => x.value).join() === "linustorvalds,linus.torvalds,linus_torvalds,ltorvalds,linust,torvaldslinus,torvalds_,_torvalds,t0rvalds,torv4lds,t0rv4ld5,realtorvalds,thetorvalds,torvaldsofficial", "torvalds with the name Linus Torvalds");
  ok(tv[0].reason === "built from the name on the primary profile (given name + family name)" && tv.find((x) => x.value === "t0rvalds").reason === "the letter o written as 0", "a name variant and a letter variant say what they are");
  ok(values("torvalds").join() === "torvalds_,_torvalds,t0rvalds,torv4lds,t0rv4ld5,realtorvalds,thetorvalds,torvaldsofficial", "torvalds with no name on the primary profile");
  // Err0ric: the digit read as a letter is the likeliest variant.
  const er = similarHandles("Err0ric", { name: "Eric Henderson" });
  ok(er[0].value === "erroric" && er[0].reason === "the 0 read as the letter o", "Err0ric gives erroric first");
  ok(er.map((x) => x.value).join() === "erroric,erichenderson,eric.henderson,eric_henderson,ehenderson,erich,hendersoneric,err0ric_,_err0ric,er0ric", "Err0ric with the name Eric Henderson");
  ok(!values("Err0ric").some((v) => /^(real|the)/.test(v) || /official$/.test(v) || /err0r1c/.test(v)), "a handle with a digit in it gets no decorations and no more digits");
  // john_smith99: the number goes, the separator goes or changes.
  ok(values("john_smith99").join() === "john_smith,johnsmith99,john.smith99,john-smith99,johnsmith,john_smith99_,_john_smith99", "john_smith99");
  ok(values("x_alice_x")[0] === "alice" && values("x_alice_x").includes("xalicex") && values("x_alice_x").includes("x.alice.x"), "x_alice_x loses its decoration first");
  ok(values("ab").join() === "ab_,_ab", "a 2 character handle gets the two underscore variants and nothing shorter");
  ok(values("12345").join() === "12345_,_12345", "an all-digit handle is never stripped to nothing or read as letters");
  // each rule in both directions
  ok(values("l33tHax0r")[0] === "leethaxor" && values("4lice")[0] === "alice" && values("h1dden").slice(0, 2).join() === "hidden,hldden", "digits to letters: all at once, at the start of a word, and both readings of 1");
  ok(values("hidden").includes("h1dden") && values("alice").includes("4lice") === false && values("alice").includes("al1ce"), "letters to digits, never the first character");
  ok(values("john.smith").includes("johnsmith") && values("john.smith").includes("john_smith") && values("JohnSmith").slice(0, 2).join() === "john_smith,john.smith" && values("user2015").includes("user_2015"), "separators: removed, swapped, and put in at a case change or before trailing digits");
  ok(!values("johnsmith").some((v) => /[._-]/.test(v.replace(/^_|_$/g, ""))), "no separator is put into a handle with no detectable word boundary");
  ok(handleVariants("user2015")[0].reason === "without the year at the end" && values("2cool").includes("cool") && values("sam7")[0] === "sam", "a number at the end or the start is taken off");
  ok(values("_under_")[0] === "under" && values("sam").includes("sam_") && values("sam").includes("_sam") && !values("sam_").includes("sam__"), "an underscore at either end is added or removed");
  ok(values("heyyy").includes("hey") && values("heyyy").includes("heyyyy") && values("Err0ric").includes("er0ric") && !values("torvalds").includes("torvaldss") && !values("sam").includes("samm"), "a doubled letter is written once; one is only added where the handle repeats a letter at its end");
  ok(values("TheRealSam_Official").slice(0, 3).join() === "sam_official,therealsam,sam" && values("xx_sam_xx")[0] === "sam" && values("sam_official")[0] === "sam" && values("its_sam")[0] === "sam" && values("ItsSam")[0] === "sam", "decorations are taken off");
  ok(!values("theodore").includes("odore") && !values("imogen").includes("ogen") && !values("xerox").includes("ero") && !values("realtor").includes("tor"), "a word that only starts like a decoration is left alone");
  ok(values("sam").filter((v) => /real|the|official/.test(v)).join() === "realsam,thesam,samofficial", "a few decorations are put on a plain word, and only a few");
  // the name
  ok(nameVariants("Cher").length === 0 && nameVariants("").length === 0 && nameVariants("山田 太郎").length === 0, "one word, no name, or a name with no ASCII form builds nothing");
  ok(similarHandles("samexample", { name: "Sam Example" }).every((x) => x.value !== "samexample") && similarHandles("x", { name: "Sam Example" }).filter((x) => /built from the name/.test(x.reason)).length === 6, "name variants never repeat the handle, and at most six are offered");
  ok(handleVariants("").length === 0 && handleVariants("a b").length === 0 && handleVariants("-rf").length === 0 && handleVariants("x".repeat(65)).length === 0 && handleVariants(null).length === 0, "something that is not a handle builds nothing");
  ok(!JSON.stringify(similarHandles("sam", { name: "Sam Example" })).includes("example.org") && similarBase("sam.example+news@corp.example.org", "email") === "sam.example" && similarBase("sam@corp.example.org", "email") === "sam", "an email case builds from the part before the @, never from the domain");
  ok(similarBase("@Sam", "username") === "Sam" && similarBase("sam", "hash") === "" && similarBase("Sam Example", "name") === "" && similarBase("-x", "username") === "", "only a username or an email case has similar handles");
  // the JS copy of the server's handle patterns
  for (const c of JSON.parse(fs.readFileSync(new URL("../fixtures/handle_patterns.json", import.meta.url), "utf8"))) {
    ok(JSON.stringify(handlePatterns(parseName(c.name))) === JSON.stringify(c.handles), `handle patterns for "${c.name}" are the server's`);
  }
}

// ---- reading a probe -------------------------------------------------------------------------
const prof = (site, o = {}) => ({ site, url: "https://evil.example.org/x", state: "found", name: "", bio: "", location: "", created: "", followers: null, note: "", links: [], avatar_hash: "", avatar_default: false, thumb: "", ...o });
const probeOf = (profiles, sources = {}) => ({ username: "x", cached: false, sources: { GitHub: "not_found", Facebook: "unknown", Instagram: "not_found", X: "not_found", Threads: "blocked", TikTok: "not_found", Reddit: "blocked", Discord: "taken", Bluesky: "not_found", ...Object.fromEntries(profiles.filter((p) => p && p.site).map((p) => [p.site, "found"])), ...sources }, profiles });
{
  const p = readProbe(probeOf([prof("GitHub", { name: "  Sam\n Example  ", bio: "b".repeat(900), followers: 3.7, links: ["https://sam.example.org", "javascript:alert(1)", "https://u:p@example.org/", 7, "https://x.com/sam_example"], avatar_hash: "C3C3E7E7FFFF0F0F", thumb: THUMB, note: "suspended", extra: "<script>" }),
    prof("Discord", { name: "nobody" }), prof("OnlyFans", { name: "x" }), prof("GitHub", { name: "second" }), prof("X", { state: "taken" }), prof("Bluesky", { avatar_hash: "zz", thumb: THUMB }), "junk", null]), "Sam_Example");
  ok(p.profiles.map((x) => x.site).join() === "GitHub,Bluesky", "only a known site, once, and only a profile that was read");
  const g = p.profiles[0];
  ok(g.url === "https://github.com/Sam_Example" && p.profiles[1].url === "https://bsky.app/profile/sam_example.bsky.social", "the address is rebuilt from the site and the handle, never taken from the answer");
  ok(g.name === "Sam Example" && g.bio.length === 300 && g.followers === 3 && g.note === "suspended" && !("extra" in g), "text is on one line and clipped, numbers are whole, unknown fields are dropped");
  ok(g.links.join() === "https://sam.example.org,https://x.com/sam_example", "links: http and https only, no credentials");
  ok(g.avatar_hash === "c3c3e7e7ffff0f0f" && g.thumb === THUMB && p.profiles[1].avatar_hash === "" && p.profiles[1].thumb === "", "a thumbnail is kept only with a well-formed hash");
  ok(readProbe(probeOf([prof("GitHub", { avatar_hash: "c3c3e7e7ffff0f0f", avatar_default: true, thumb: THUMB })]), "sam").profiles[0].thumb === "" && readProbe(probeOf([prof("GitHub", { avatar_hash: "c3c3e7e7ffff0f0f", thumb: "https://evil.example.org/a.png" })]), "sam").profiles[0].thumb === "", "no thumbnail for a placeholder, and never a remote picture");
  ok(p.sources.Discord === "unknown" && p.sources.TikTok === "not_found" && p.sources.Reddit === "blocked" && p.sources.GitHub === "found" && p.sources.X === "unknown" && !("OnlyFans" in p.sources), "sources keep their own states, for known sites only");
  ok(readProbe({ sources: { GitHub: "found", X: "exploded", Reddit: "blocked" }, profiles: [] }, "sam").sources.GitHub === "unknown" && !("X" in readProbe({ sources: { X: "exploded" }, profiles: [] }, "sam").sources), "a 'found' with no profile behind it is unknown, and an unknown state is dropped");
  ok(readProbe(null, "sam") === null && readProbe({}, "a b") === null && readProbe([], "sam") === null, "something that is not a probe is refused");
}

// ---- does it line up? ------------------------------------------------------------------------
const H1 = "c3c3e7e7ffff0f0f", H2 = "c3c3e7e7ffff0f0d", FAR = "0f0f0f0ff0f0f0f0", FLAT = "0000000000000001";
const base = (o = {}) => [
  { id: "acct:github", site: "GitHub", url: "https://github.com/sam", handle: "sam", name: "Sam Example", location: "Lisbon", bio: "", links: [], websites: ["https://sam.example.org"], anchor: "github", avatarHash: H1, avatarDefault: false, ...o },
  { id: "acct:threads", site: "Threads", url: "https://www.threads.com/@sam", handle: "sam", name: "Sam Example", location: "", bio: "", links: [], websites: [] },
  { id: "acct:forum", site: "Forum", url: "https://forum.example.net/u/sam", handle: "sam", name: "Riley Otherperson", location: "", bio: "", links: [], websites: [] },
];
const pp = (site, variant, o = {}) => asProfile(variant, readProbe(probeOf([prof(site, o)]), variant).profiles[0]);
const lu = (p, b = base()) => lineUp(p, b, { handle: "sam" });
{
  const pic = lu(pp("GitHub", "sam_", { avatar_hash: H2 }));
  ok(pic.outcome === "picture" && pic.strength === "strong" && pic.canAdd && pic.tier === "linked" && pic.text === "Same picture as the GitHub profile" && lu(pp("GitHub", "sam_", { name: "Sam Example", avatar_hash: H2 })).outcome === "picture", "the same picture is a strong signal, and it says which profile it matches");
  // the same picture under another name is its own outcome, and it says both names
  const pcf = lu(pp("GitHub", "sam_", { name: "Jordan Unrelated", avatar_hash: H2 }));
  ok(pcf.outcome === "picture_conflict" && pcf.canAdd && pcf.tier === "linked" && pcf.text === "Same picture, but the name on it differs (Jordan Unrelated, against Sam Example)" && pcf.reason === "same picture as the GitHub profile, but the name on it differs (Jordan Unrelated, against Sam Example)", "the same picture with a conflicting name says so in those words");
  ok(lu(pp("GitHub", "sam_", { name: "Riley Otherperson", avatar_hash: H2 })).outcome === "picture_conflict", "also when that name is one another person under the handle carries");
  ok(lu(pp("GitHub", "sam_", { avatar_hash: FAR, name: "" })).outcome === "nothing" && lu(pp("GitHub", "sam_", { avatar_hash: H2, avatar_default: true })).outcome === "nothing", "a different picture, or a placeholder with the same hash, never matches");
  ok(lineUp(pp("GitHub", "sam_", { avatar_hash: FLAT }), base({ avatarHash: FLAT }), { handle: "sam" }).outcome === "nothing" && lineUp(pp("GitHub", "sam_", { avatar_hash: H1 }), base({ avatarDefault: true }), { handle: "sam" }).outcome === "nothing", "a near-blank picture or a default on the case's side never matches either");
  const link = lineUp(pp("X", "sam_ex"), base({ links: ["https://x.com/sam_ex"] }), { handle: "sam" });
  ok(link.outcome === "link" && link.strength === "strong" && link.canAdd && /GitHub links to X/.test(link.text), "a link from the target's own record to the profile is the cross-link rule");
  ok(lu(pp("GitHub", "sam_", { links: ["https://sam.example.org"] })).outcome === "link" && /sam\.example\.org/.test(lu(pp("GitHub", "sam_", { links: ["https://sam.example.org"] })).text), "the same personal site on both is the shared-link rule");
  ok(lu(pp("GitHub", "sam_", { links: ["https://github.com/sam"] })).outcome === "nothing", "a link from the profile to the target alone is its own claim, not a tie");
  const nm = lu(pp("Instagram", "sam.example", { name: "Sam Example" }));
  ok(nm.outcome === "name" && nm.strength === "supporting" && nm.canAdd && nm.tier === "matches" && /^Name on profile: Sam Example, the same full name as on (GitHub|Threads)$/.test(nm.text) && nm.reason === "same full name. A name alone is supporting, not proof", "the same full name on both sides is supporting, lands in Exists (matches), and says it is not proof");
  // a name alone is offered only for the same full name, and never under a handle built from that name
  const builtNm = lineUp(pp("Instagram", "samexample", { name: "Sam Example" }), base(), { handle: "sam", fromName: true });
  ok(builtNm.outcome === "name_built" && !builtNm.canAdd && /this handle was built from the name on the primary profile, so the match proves nothing$/.test(builtNm.text), "the same name under a handle built from that name proves nothing and is not offered");
  ok(lineUp(pp("GitHub", "samexample", { name: "Jordan Unrelated", avatar_hash: H2 }), base(), { handle: "sam", fromName: true }).canAdd && /this handle was built from the name on the primary profile$/.test(lineUp(pp("GitHub", "samexample", { avatar_hash: H2 }), base(), { handle: "sam", fromName: true }).reason), "a picture still counts under a name-built handle, and the note says how the handle was built");
  const one = lineUp(pp("Instagram", "sam.example", { name: "Sam" }), base().slice(0, 2), { handle: "x" });
  ok(one.outcome === "name_weak" && !one.canAdd && /a single word is shared by many people/.test(one.text), "a single word that fits a full name is not enough to add");
  const longer = lineUp(pp("Instagram", "eric_", { name: "Eric Smith" }), [{ id: "acct:github", site: "GitHub", url: "https://github.com/eric", handle: "ericx", name: "Eric", links: [], websites: [], anchor: "github" }], { handle: "ericx" });
  ok(longer.outcome === "name_weak" && !longer.canAdd && /not the same full name/.test(longer.text), "a full name against a one word primary name is not enough to add");
  ok(lu(pp("Instagram", "sam_", { name: "SamExample" })).outcome === "name_weak" && lu(pp("Instagram", "sam.example", { name: "Example Sam" })).outcome === "name" && lu(pp("Instagram", "sam.example", { name: "Sam J Example" })).canAdd === false, "the same words in another order are the same full name; run together or with a word more they are not");
  const sub = lineUp(pp("Instagram", "sam.example", { name: "Sam" }), base().slice(0, 2), { handle: "x" });
  ok(sub.outcome === "name_weak" && !sub.canAdd && /which fits the name on/.test(sub.text), "a name contained in the primary's name fits, and is not enough to add");
  const cf = lu(pp("Instagram", "sam.example", { name: "Jordan Unrelated" }));
  ok(cf.outcome === "conflict" && !cf.canAdd && cf.text === "Name on profile: Jordan Unrelated, which conflicts with Sam Example", "a conflicting name is a different person and is never offered for adding");
  ok(lu(pp("Instagram", "sam.example", { name: "Riley Otherperson" })).canAdd === false, "a name that matches someone else under the handle does not line up with the primary identity");
  const none = lu(pp("Bluesky", "samexample", { name: "samexample" }));
  ok(none.outcome === "nothing" && none.why === "profile_empty" && /this profile carries no name and no picture/.test(none.text) && !none.canAdd, "a profile with no name and no picture: nothing to compare, and it says which side");
  const bare = lineUp(pp("Instagram", "sam.example", { name: "Sam Example" }), [{ id: "acct:github", site: "GitHub", url: "https://github.com/sam", handle: "sam", name: "sam", links: [], websites: [], anchor: "github" }], { handle: "sam" });
  ok(bare.outcome === "nothing" && /primary identity carries no name/.test(bare.text) && !bare.canAdd, "a primary identity with no name and no picture: nothing to compare");
  ok(lu(pp("Instagram", "sam.example", { name: "Lisbon Maps Club" })).why === "no_tie" && /neither matches nor conflicts with Sam Example/.test(lu(pp("Instagram", "sam.example", { name: "Lisbon Maps Club" })).text), "a name that neither fits nor conflicts is not offered");
  const np = lineUp(pp("Instagram", "sam.example", { name: "Sam Example", avatar_hash: H1 }), base().slice(1), { handle: "sam" });
  ok(np.outcome === "nothing" && np.why === "no_primary" && /no primary identity/.test(np.text) && !np.canAdd, "a case with no primary identity has nothing to compare against");
  ok(lineUp(pp("Instagram", "sam.example", { name: "Sam Example" }), [], { handle: "sam" }).why === "no_primary" && lineUp(null, base()).canAdd === false, "no profiles, or no profile, is never a match");
  // a probed profile never becomes the primary identity or re-picks it
  const strongOnly = [{ id: "acct:a", site: "A", url: "https://a.example/u/sam", handle: "sam", name: "", links: [], websites: [], avatarHash: H1 }, { id: "acct:b", site: "B", url: "https://b.example/u/sam", handle: "sam", name: "", links: [], websites: [], avatarHash: H2 }];
  ok(lineUp(pp("GitHub", "sam_", { avatar_hash: H1 }), strongOnly, { handle: "sam" }).outcome === "picture", "with a primary held together by a strong signal, the same picture still lines up");
  // other added profiles are not part of what a profile is compared with
  const withAdded = [...base(), { ...pp("X", "samx", { name: "Jordan Unrelated" }), similar: { variant: "samx" } }];
  ok(lu(pp("Instagram", "sam.example", { name: "Jordan Unrelated" }), withAdded).outcome === "conflict", "a profile is compared with the case's own profiles, never with ones added from another similar handle");
}

// ---- the stored checks are outside data -------------------------------------------------------
const entry = (variant, profiles, added = [], sources = {}) => ({ variant, checked_at: 1700000000000, probe: probeOf(profiles, sources), added });
{
  const hostile = {
    "sam_": entry("sam_", [prof("GitHub", { name: "Jordan Unrelated", url: "javascript:alert(1)", thumb: "https://evil.example.org/p.png", avatar_hash: FAR, bio: "<img src=x onerror=alert(1)>" })], ["acct:github~sam_", "acct:github~other", "acct:onlyfans~sam_", 7]),
    "SAM.EX": entry("SAM.EX", [prof("X")]),
    "bad key": entry("bad key", [prof("X")]),
    "../../etc": entry("../../etc", [prof("X")]),
    "sam": entry("sam", [prof("X", { name: "Sam Example" })], ["acct:x~sam"]),
    "mismatch": entry("other", [prof("X")]),
    "__proto__": entry("__proto__", [prof("X")]),
    "ok_err": { variant: "ok_err", checked_at: "soon", error: { error: "x".repeat(500), error_code: "rate_limited", extra: 1 } },
    "empty": { variant: "empty" },
    "arr": [1, 2],
  };
  const r = readSimilar(hostile, "sam");
  ok(Object.keys(r).sort().join() === "ok_err,sam_", "a handle that fails the pattern, a key that is not its handle, and the case's own handle are dropped");
  ok(r["sam_"].probe.profiles[0].url === "https://github.com/sam_" && r["sam_"].probe.profiles[0].thumb === "" && r["sam_"].added.join() === "acct:github~sam_", "addresses are rebuilt, a remote picture is dropped, and 'added' is kept only for a profile the entry holds");
  ok(r.ok_err.error.error.length === 200 && r.ok_err.checked_at === 0 && r.ok_err.added.length === 0 && !("extra" in r.ok_err.error), "a failed check keeps a clipped message and nothing else");
  ok(Object.keys(readSimilar(Object.fromEntries(Array.from({ length: 80 }, (_, i) => [`h${i}x`, entry(`h${i}x`, [])])), "sam")).length === MAX_STORED, `at most ${MAX_STORED} checked handles are kept`);
  const many = readSimilar(Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`t${i}x`, entry(`t${i}x`, [prof("GitHub", { avatar_hash: H1, thumb: THUMB }), prof("Bluesky", { avatar_hash: H1, thumb: THUMB })])])), "sam");
  ok(Object.values(many).flatMap((e) => e.probe.profiles).filter((p) => p.thumb).length === 30, "at most 30 thumbnails across the checks");
  ok(JSON.stringify(readSimilar(null)) === "{}" && JSON.stringify(readSimilar("x")) === "{}" && JSON.stringify(readSimilar([1])) === "{}", "anything that is not a map is nothing");

  // through a case file
  const collected = { github: { found: true, username: "sam", name: "Sam Example", profile_url: "https://github.com/sam", avatar_url: "", public_repos: 1, followers: 1 }, similar: hostile };
  const file = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "sam", type: "username", collected })));
  ok(file.ok && Object.keys(file.entry.results.similar).join() === "sam_" && file.entry.results.similar["sam_"].from_file === true && file.entry.results.similar["sam_"].added.length === 0, "a case file keeps only handles the case would offer itself, marked as from the file, with nothing added");
  const ev = buildEvidence(file.entry.results, "sam", "username");
  // sam_ holds a GitHub profile whose name conflicts: the file says "added", the rules say no
  ok(!ev.items.some((i) => /~/.test(i.key)) && ev.items.find((i) => i.key === "similar:sam_").sim.profiles[0].added === false && ev.items.find((i) => i.key === "similar:sam_").sim.state === "file", "nothing from a file is in the ledger: its rows wait to be checked here");
  // a stored (not imported) case with a conflicting profile marked added: the rules say no
  const local = buildEvidence({ ...collected, similar: readSimilar(hostile, "sam") }, "sam", "username");
  ok(!local.items.some((i) => /~/.test(i.key)) && local.items.find((i) => i.key === "similar:sam_").sim.profiles[0].lineup.outcome === "conflict", "a stored case cannot add a profile that does not line up: it is evaluated again and stays out of the ledger");
  ok(!/onerror=alert|javascript:/.test(JSON.stringify(ev.items.map((i) => [i.url, i.sim?.profiles.map((p) => p.url)]))) && !evWhat(ev.items.find((i) => i.key === "similar:sam_")).includes("<img src=x"), "nothing from the file becomes an address or markup");
  ok(!("similar" in parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "44d88612fea8a8f36de82e1278abb02f", type: "hash", collected: { hash: { found: false }, similar: hostile } }))).entry.results), "a case that is not a username or an email keeps no similar handles");
  ok(!("similar" in parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "sam", type: "username", collected: { github: { found: false }, similar: "x" } }))).entry.results), "a similar field that is not a map is dropped");
}

// ---- the ledger: a row per variant, an added profile, and taking it out again ---------------------
const e0 = fx("err0ric");
const PC = { username: "Err0ric", total: 2, checked: 8, results: [
  ...e0.platformCheckV2.results.filter((r) => !["Reddit", "Discord"].includes(r.platform)),
  { platform: "Reddit", url: "https://www.reddit.com/user/Err0ric", state: "blocked", found: null, evidence: "Reddit refuses requests from servers, so this could not be checked automatically.", display_name: "", public_url: true, hint: "<b>from the server</b>" },
  { platform: "Discord", url: "", state: "taken", found: null, evidence: "<i>anything a file might say</i>", display_name: "", public_url: false, hint: "x" }] };
const caseOf = (similar, extra = {}) => ({ ...e0.collected, platformCheck: PC, avatarHash: { results: [{ id: "acct:github", hash: H1, default: false, thumb: THUMB }] }, ...(similar ? { similar } : {}), ...extra });
const T = e0.target;
const erroric = (added = []) => ({ erroric: entry("erroric", [prof("GitHub", { name: "Sam Example", location: "Lisbon", bio: "Maps and bread", created: "2019-04-02T00:00:00Z", followers: 4, avatar_hash: H2, thumb: THUMB }), prof("Instagram", { name: "Jordan Unrelated" }), prof("Bluesky")], added, { Discord: "not_found" }) });
{
  const plain = buildEvidence(caseOf(null), T, "username");
  const sim = plain.items.filter((i) => i.tier === "similar");
  ok(sim.length > 0 && sim[0].what === "erroric" && sim.every((i) => i.sim.state === "new" && i.link_kind === "none" && !i.url && i.action.label === "Investigate this" && i.action.pivot === "investigate" && i.action.type === "username"), "a username case offers its similar handles, unchecked, each with Investigate this");
  ok(sim.every((i) => !isFinding(i)) && plain.items.filter((i) => i.tier === "lead").every((i) => !/^similar:/.test(i.key)) && plain.similarLine === "", "a similar handle is not a finding and not a lead, and the brief says nothing before a check");
  const tiles = (ev, c) => investigateTiles({ items: ev.items, collected: c, type: "username" });
  const leadTile = (ev, c) => tiles(ev, c).find((t) => t.id === "lead").value;
  ok(leadTile(plain, caseOf(null)) === plain.items.filter((i) => i.tier === "lead").length, "the Leads tile does not count similar handles");
  const tiersList = ledgerTiers(T, "username").map((t) => t.id);
  ok(tiersList.indexOf("similar") === tiersList.indexOf("lead") + 1 && ledgerTiers(T, "username").find((t) => t.id === "similar").open === false && ledgerTiers(T, "username").find((t) => t.id === "similar").blurb === SIMILAR_BLURB, "the group sits after Leads from profiles, collapsed, with its blurb");
  ok(/^Handles close to this one\. Nothing has been checked\. Check one to see whether its name or picture lines up with this case\./.test(SIMILAR_BLURB) && similarBlurb(plain.items) === SIMILAR_BLURB, "the blurb says nothing has been checked while that is true");
  ok(evSrc(sim[0]).includes('data-sim-check="erroric"') && />Check</.test(evSrc(sim[0])) && evSrc(sim[0]).includes('data-pivot="investigate"') && !evWhat(sim[0]).includes("sim-res"), "an unchecked row has Check and Investigate this, and no result");
  ok(buildEvidence({ hash: { found: false } }, "44d88612fea8a8f36de82e1278abb02f", "hash").items.every((i) => i.tier !== "similar") && buildEvidence({ nameSearch: "Sam Example" }, "Sam Example", "name").items.every((i) => i.tier !== "similar"), "a hash or a name case has no similar handles");
  const em = buildEvidence({ gravatar: { found: false } }, "err0ric+x@corp.example.org", "email").items.filter((i) => i.tier === "similar");
  ok(em.length > 0 && em[0].what === "erroric" && !em.some((i) => /corp|example/.test(i.what)), "an email case builds them from the part before the @");

  // checked, nothing added
  const c1 = caseOf(erroric());
  const ev1 = buildEvidence(c1, T, "username");
  const r1 = ev1.items.find((i) => i.key === "similar:erroric");
  ok(r1.sim.state === "checked" && r1.sim.profiles.map((p) => `${p.site}:${p.lineup.outcome}:${p.added}`).join() === "GitHub:picture:false,Instagram:nothing:false,Bluesky:nothing:false", "a checked handle lists each read profile with how it lines up");
  ok(r1.sim.summary === "3 profiles read: 1 lines up with this case, 2 could not be compared." && ev1.similarLine === "1 similar handle checked: 1 lines up and is not added.", "the row and the brief say what the check found");
  ok(r1.sim.sources.map((g) => `${g.word}=${g.sites.join("+")}`).join("; ") === "Not found=X (Twitter)+TikTok+Discord; Blocked by site=Threads+Reddit; Could not tell=Facebook", "every source that read nothing is named with its own state");
  ok(!ev1.items.some((i) => /~/.test(i.key)) && JSON.stringify(accountsFor(ev1.items)) === JSON.stringify(accountsFor(plain.items)) && aiSignature(c1, T, "username") === aiSignature(caseOf(null), T, "username"), "a checked handle that was not added changes nothing in the ledger or in what the AI is told");
  ok(ev1.items.filter(isFinding).length === plain.items.filter(isFinding).length && JSON.stringify(ev1.facts) === JSON.stringify(plain.facts) && JSON.stringify(ev1.identity) === JSON.stringify(plain.identity), "nor in the findings, the facts or the identities");
  const html1 = evWhat(r1);
  ok(html1.includes('data-sim-add="acct:github~erroric"') && (html1.match(/data-sim-add=/g) || []).length === 1 && !html1.includes("data-sim-remove") && html1.includes(">Same picture</span>") && html1.includes(">Nothing to compare</span>"), "only the profile that lines up gets Add to this case");
  ok(html1.includes('class="sim-card tone-linked"') && !/line-dashed/.test(html1) && html1.includes('class="mark-thumb"') && !/duckduckgo|mark-fav/.test(html1) && html1.includes('href="https://github.com/erroric"'), "a read profile is a solid card with the server's thumbnail or initials, never a site icon");
  ok(!evSrc(r1).includes("data-sim-check") && evSrc(r1).includes('data-pivot="investigate"'), "a checked row keeps Investigate this and loses Check");
  ok(similarBlurb(ev1.items).startsWith("Handles close to this one. 1 handle checked so far") && !/Nothing has been checked/.test(similarBlurb(ev1.items)), "the blurb stops saying nothing has been checked");
  const sc = sourceTally(c1, { github: "GitHub", sherlock: "Sherlock", maigret: "Maigret", platformCheck: "Platform check", enricher: "Profile enrichment", avatarHash: "Avatar comparison" });
  ok(JSON.stringify(sc) === JSON.stringify(sourceTally(caseOf(null), { github: "GitHub", sherlock: "Sherlock", maigret: "Maigret", platformCheck: "Platform check", enricher: "Profile enrichment", avatarHash: "Avatar comparison" })), "a handle probe does not change how many sources ran");
  ok(leadTile(ev1, c1) === leadTile(plain, caseOf(null)) && JSON.stringify(tierCounts(ev1.items)) === JSON.stringify(tierCounts(plain.items)), "tiles and counts are unchanged by a check");

  // added
  const c2 = caseOf(erroric(["acct:github~erroric", "acct:instagram~erroric", "acct:bluesky~erroric"]));
  const ev2 = buildEvidence(c2, T, "username");
  const addedRows = ev2.items.filter((i) => /~/.test(i.key));
  ok(addedRows.length === 1 && addedRows[0].key === "acct:github~erroric", "only the profile that lines up enters the ledger, whatever 'added' lists");
  const a = addedRows[0];
  ok(a.tier === "linked" && a.what === "GitHub" && a.url === "https://github.com/erroric" && a.link_kind === "verified_profile" && a.card.handle === "erroric" && a.thumb === THUMB, "it sits in the tier the identity rules give it, under its own handle and link");
  ok(a.card.note === "Added from the similar handle erroric: same picture as the GitHub profile." && /^under the handle erroric, added from a similar handle check \(same picture as the GitHub profile\)/.test(a.meta) && a.source === "Similar handle check", "the row says where it came from and why it was added");
  ok(evSrc(a).includes('data-sim-remove="acct:github~erroric"') && evSrc(a).includes("Remove from this case") && evWhat(ev2.items.find((i) => i.key === "similar:erroric")).includes('data-sim-remove="acct:github~erroric"') && evWhat(ev2.items.find((i) => i.key === "similar:erroric")).includes(">Added</span>"), "it can be removed from its row and from the similar handle");
  ok(ev2.items.find((i) => i.key === "acct:github").tier === "linked" && ev2.items.find((i) => i.key === "acct:github").url === "https://github.com/Err0ric", "the target's own GitHub row is untouched");
  const primary = ev2.identity.views.find((v) => v.primary);
  ok(JSON.stringify(ev2.identity) === JSON.stringify(plain.identity) && JSON.stringify(ev2.facts) === JSON.stringify(plain.facts), "an added profile is a row, never part of the identity: label, members, signals, picture and facts are unchanged");
  ok(ev2.added.length === 1 && ev2.added[0].label === "GitHub (erroric)" && ev2.added[0].facts.some((f) => f.k === "Name" && f.v === "Sam Example" && f.source === "GitHub (erroric)" && f.url === "https://github.com/erroric") && plain.added.length === 0, "its facts are kept apart, each naming the site and the handle");
  ok(JSON.stringify(ev2.items.filter((i) => !/~/.test(i.key) && i.tier !== "similar")) === JSON.stringify(plain.items.filter((i) => i.tier !== "similar")), "every other row is exactly as it was: tier, text, link and order");
  ok(ev2.items.filter(isFinding).length === plain.items.filter(isFinding).length + 1 && leadTile(ev2, c2) === leadTile(plain, caseOf(null)) && ev2.items.filter((i) => i.tier === "lead").length === plain.items.filter((i) => i.tier === "lead").length, "it is one more finding, and it starts no leads");
  ok(ev2.similarLine === "1 similar handle checked: 1 added." && ev2.items.find((i) => i.key === "similar:erroric").sim.summary === "3 profiles read: 1 added to this case, 2 could not be compared.", "the brief line and the row count it as added");
  ok(avatarImages(c2, T, "username").every((i) => !/~/.test(i.id)) && deepDiveUrls(c2).every((u) => !/erroric/.test(u.url)), "an added profile is not sent to the avatar comparison or to a Deep Dive");
  ok(!collectProfiles(c2, T, "username").some((p) => p.similar || /~/.test(p.id)), "collectProfiles holds the case's own profiles only");
  // the AI payload
  const ai = aiPayloadFor(c2, T, "username");
  const acc = ai.accounts.find((x) => x.handle === "erroric");
  ok(acc && acc.site === "GitHub" && acc.status === "linked" && acc.url === "https://github.com/erroric" && /added from a similar handle check \(same picture as the GitHub profile\)/.test(acc.note) && ai.accounts.filter((x) => x.handle).length === 1, "the AI gets the added account with the handle it is under and why it was added");
  ok(!("similar" in ai) && !JSON.stringify(ai).includes("Jordan Unrelated") && aiSignature(c2, T, "username") !== aiSignature(c1, T, "username"), "nothing else from the checks is sent, and an added profile changes the report signature");
  const md = caseMarkdown({ collected: c2, target: T, type: "username" });
  ok(md.includes("## Similar handles (") && /\[GitHub\]\(https:\/\/github\.com\/erroric\) · under the handle erroric, added from a similar handle check/.test(md) && md.includes("- erroric · the 0 read as the letter o · 3 profiles read: 1 added to this case, 2 could not be compared."), "the Markdown export has the added row and the similar handles with their results");
  // through a case file and back
  const back = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: T, type: "username", collected: c2 }))).entry.results;
  ok(!buildEvidence(back, T, "username").items.some((i) => /~/.test(i.key)) && back.similar.erroric.added.length === 0 && back.similar.erroric.from_file === true, "a case file carries the check, never the add: the investigator checks and adds again here");
  // removal
  const c3 = caseOf(erroric([]));
  ok(JSON.stringify(buildEvidence(c3, T, "username").items.map((i) => i.key)) === JSON.stringify(ev1.items.map((i) => i.key)) && JSON.stringify(buildEvidence(c3, T, "username").identity) === JSON.stringify(plain.identity), "removing it puts the ledger and the identities back as they were");
  // adding never forces a link the rules do not support
  const noPic = caseOf(erroric(["acct:github~erroric"]), { avatarHash: { results: [] } });
  ok(!buildEvidence(noPic, T, "username").items.some((i) => /~/.test(i.key)) && buildEvidence(noPic, T, "username").items.find((i) => i.key === "similar:erroric").sim.profiles[0].added === false, "when the signal it was added on is gone, the profile is no longer part of the case");
  // a name-only match lands in Exists (matches)
  const tv = fx("torvalds");
  const named = { ...tv.collected, similar: { "torvalds_": entry("torvalds_", [prof("GitHub", { name: "Linus Torvalds" }), prof("X", { name: "Jordan Unrelated" })], ["acct:github~torvalds_", "acct:x~torvalds_"]) } };
  const evn = buildEvidence(named, tv.target, "username");
  const nrow = evn.items.find((i) => i.key === "acct:github~torvalds_");
  ok(nrow && nrow.tier === "matches" && nrow.card.note === "Added from the similar handle torvalds_: same full name. A name alone is supporting, not proof." && nrow.card.why === "" && !evn.items.some((i) => i.key === "acct:x~torvalds_") && evn.similarLine === "1 similar handle checked: 1 added.", "a full-name match is added to Exists (matches) with the caveat in its note, and a conflicting profile beside it is not");
  const tvPlain = buildEvidence(tv.collected, tv.target, "username");
  ok(JSON.stringify(evn.identity) === JSON.stringify(tvPlain.identity) && JSON.stringify(evn.facts) === JSON.stringify(tvPlain.facts) && JSON.stringify(evn.items.filter((i) => !/~/.test(i.key) && i.tier !== "similar")) === JSON.stringify(tvPlain.items.filter((i) => i.tier !== "similar")), "a name add changes nothing else either");
  // the handle built from the primary's name: a stranger with that name is never offered
  const builtCase = buildEvidence({ ...tv.collected, similar: { linustorvalds: entry("linustorvalds", [prof("GitHub", { name: "Linus Torvalds" })], ["acct:github~linustorvalds"]) } }, tv.target, "username");
  const builtRow = builtCase.items.find((i) => i.key === "similar:linustorvalds");
  ok(builtRow.sim.profiles[0].lineup.outcome === "name_built" && !builtRow.sim.profiles[0].added && !builtCase.items.some((i) => /~/.test(i.key)) && !evWhat(builtRow).includes("data-sim-add") && evWhat(builtRow).includes(">Same name, proves nothing</span>") && evSrc(builtRow).includes('data-pivot="investigate"'), "a name match under a handle built from that name has no Add, says why, and keeps Investigate this");
  ok(evn.items.find((i) => i.key === "similar:torvalds_").sim.profiles.find((p) => p.site === "X (Twitter)").lineup.outcome === "conflict" && /A name alone is supporting, not proof\./.test(evWhat(evn.items.find((i) => i.key === "similar:torvalds_"))), "the conflicting profile says so, and a name match says it is not proof");
  ok(buildEvidence(tv.collected, tv.target, "username").items.filter((i) => i.tier === "similar").slice(0, 3).map((i) => i.source).join() === "built from the name,built from the name,built from the name", "with a name on the primary profile, the handles built from it come first");
  // a handle checked earlier stays listed even when it is no longer generated
  const gone = buildEvidence(caseOf({ zzcustom: entry("zzcustom", []) }), T, "username").items.find((i) => i.key === "similar:zzcustom");
  ok(gone && gone.sim.state === "checked" && gone.sim.reason === "checked earlier in this case" && gone.sim.summary === "No profile was read. 3 sites could not be checked, so those are unknown, not absent.", "a blocked site is never read as absent");
  ok(variantSummary({ profiles: [], sources: { GitHub: "not_found", Discord: "taken" } }) === "No profile under this handle on the sites checked." && variantOutcome({ profiles: [], sources: {} }) === "none", "nothing found anywhere is said as that");
  // a failed check
  const failed = buildEvidence(caseOf({ erroric: { variant: "erroric", checked_at: 1, error: { error: "Too many requests. Try again in 30 seconds.", error_code: "rate_limited" } } }), T, "username");
  const fr = failed.items.find((i) => i.key === "similar:erroric");
  ok(fr.sim.state === "failed" && fr.sim.summary === "Could not be checked: Too many requests. Try again in 30 seconds." && />Try again</.test(evSrc(fr)) && failed.similarLine === "", "a check that failed says so, offers Try again, and is not counted as checked");
  // the brief
  const three = { a_one: entry("a_one", [prof("GitHub", { name: "Sam Example", avatar_hash: H2 })], ["acct:github~a_one"]), b_two: entry("b_two", [prof("X", { name: "Jordan Unrelated" })]), c_three: entry("c_three", [prof("Bluesky")]) };
  const sb = similarBrief(evaluateSimilar(three, base(), { handle: "sam" }));
  ok(sb === "3 similar handles checked: 1 added, 1 belongs to someone else, 1 could not be compared.", "the brief line for three checks");
  const brief = investigateBrief({ collected: c2, items: ev2.items, facts: ev2.facts, identity: ev2.identity, failed: [], type: "username", target: T, similarLine: ev2.similarLine });
  ok(brief.rows.filter((r) => /similar handle/.test(r.text)).length === 1 && !investigateBrief({ collected: caseOf(null), items: plain.items, facts: plain.facts, identity: plain.identity, failed: [], type: "username", target: T, similarLine: plain.similarLine }).rows.some((r) => /similar handle/.test(r.text)), "at most one line in the brief, and only after a check");
  // the page
  const box = { innerHTML: "", id: "t" };
  renderTiers(box, ev2.items, ledgerTiers(T, "username"), new Set(), "");
  ok(/<section class="tier\s+collapsed\s*" data-tier="similar">/.test(box.innerHTML.replace(/\s+/g, " ")) && box.innerHTML.includes('aria-label="Profiles read for the handle erroric"'), "the group is drawn collapsed, and the read profiles are a named list");
  renderTiers(box, ev2.items, ledgerTiers(T, "username"), new Set(), "", { open: new Map([["similar", true], ["linked", false]]) });
  ok(/<section class="tier\s*" data-tier="similar">/.test(box.innerHTML.replace(/\s+/g, " ")) && /<section class="tier confirmed collapsed\s*" data-tier="linked">/.test(box.innerHTML.replace(/\s+/g, " ")), "a redraw after adding keeps every group open or closed as it was");
  renderTiers(box, plain.items.filter((i) => i.tier === "similar"), ledgerTiers(T, "username"), new Set(), "<p>Nothing found</p>");
  ok(box.innerHTML.startsWith("<p>Nothing found</p>") && box.innerHTML.includes('data-tier="similar"'), "with no findings the page still says so above the similar handles");
  ok(!/<img[^>]+src="(?!data:image\/(webp|png);base64,)/.test(box.innerHTML) && !/placeholder=|<input(?![^>]*type="checkbox")/.test(box.innerHTML), "the group loads no remote image and adds no text input");
  // thumbnails go first when storage is full
  const stripped = withoutThumbs([{ id: "a", results: c2 }], "");
  ok(stripped[0].results.similar.erroric.probe.profiles.every((p) => p.thumb === "") && c2.similar.erroric.probe.profiles[0].thumb === THUMB && withoutThumbs([{ id: "a", results: c2 }], "a")[0].results.similar.erroric.probe.profiles[0].thumb === THUMB, "thumbnails of similar handles are dropped with the others when storage is full, never from the run being saved first");
}

// ---- "taken" is never a read profile -----------------------------------------------------------
{
  const c = caseOf(null), ev = buildEvidence(c, T, "username");
  const d = ev.items.find((i) => i.key === "acct:discord"), r = ev.items.find((i) => i.key === "acct:reddit");
  ok(d && d.tier === "unverified" && d.taken === true && d.url === "" && d.link_kind === "none" && d.meta === L.TAKEN_TEXT.discord && /^Discord has no public profile page/.test(d.hint), "Discord's taken handle is one Unverified row with no link, CrawlR's own sentence and the how-to-check hint");
  ok(!JSON.stringify(d).includes("anything a file might say") && !JSON.stringify(r).includes("from the server"), "the row's sentence and hint are CrawlR's, never text from the stored answer");
  const cert = rowCertainty(d);
  ok(cert.word === "Handle taken" && cert.line === "dashed" && cert.tone === "unverified" && pillOf(d).includes("line-dashed") && pillOf(d).includes(">Handle taken<"), "the pill reads Handle taken with the dashed line: reported, nothing read");
  ok(d.card.basis === L.TAKEN_TEXT.discord && d.card.facts.length === 0 && !d.card.bio && !d.thumb && evWhat(d).includes("How to check") && !evWhat(d).includes("<a "), "the card says what the sign-up check said and links nowhere");
  ok(d.sources.join() === "Platform check,Sherlock,Maigret" && ev.items.filter((i) => /discord/i.test(i.key)).length === 1 && !JSON.stringify(d).includes("https://discord.com"), "Sherlock's and Maigret's Discord rows merge into it, and their homepage URL is dropped");
  ok(!/reported by \d+ tools/.test(d.meta), "it does not claim that tools reported a profile");
  ok(!collectProfiles(c, T, "username").some((p) => /discord/i.test(p.id)) && !ev.identity.views.some((v) => v.sites.includes("Discord")) && !ev.facts.some((f) => /discord/i.test(f.source)), "it is not a profile: no identity, no facts");
  const acc = accountsFor(ev.items).find((a) => a.site === "Discord");
  ok(acc.status === "unverified" && acc.note === "handle taken, owner unknown" && acc.url === "" && acc.link_kind === "none", "the AI is told: taken, owner unknown");
  const tiles = investigateTiles({ items: ev.items, collected: c, type: "username" });
  const without = buildEvidence({ ...c, platformCheck: { ...PC, results: PC.results.filter((x) => x.platform !== "Discord") }, sherlock: { ...c.sherlock, results: c.sherlock.results.filter((x) => x.site !== "Discord") }, maigret: { ...c.maigret, results: c.maigret.results.filter((x) => x.site !== "Discord") } }, T, "username");
  const tw = investigateTiles({ items: without.items, collected: c, type: "username" });
  ok(tiles.find((t) => t.id === "linked").value === tw.find((t) => t.id === "linked").value && tiles.find((t) => t.id === "exists").value === tw.find((t) => t.id === "exists").value && tiles.find((t) => t.id === "unverified").value === tw.find((t) => t.id === "unverified").value + 1, "on the tiles it counts as Unverified, never as Linked or Exists");
  const brief = investigateBrief({ collected: c, items: ev.items, facts: ev.facts, identity: ev.identity, failed: [], type: "username", target: T });
  ok(brief.rows.some((x) => x.text === "The handle is taken on Discord according to the site's sign-up check. Nothing was read there, so who holds it is unknown.") && brief.rows.some((x) => /Reddit blocked the check|LinkedIn, Reddit blocked the check/.test(x.text)), "the brief says the handle is taken and nothing was read, and that Reddit blocked the check");
  ok(deepDiveUrls({ platformCheck: PC }).every((u) => !/discord/i.test(u.site)) && avatarImages(c, T, "username").every((i) => !/discord/.test(i.id)), "the taken row gives a Deep Dive nothing to read and has no picture");
  // the source as a whole
  const cv = sourceCoverage(PC);
  ok(cv.answered === PC.results.filter((x) => ["found", "not_found", "taken"].includes(x.state)).length && cv.answered < cv.total && !sourceHasResults({ results: [{ platform: "Discord", state: "taken" }] }) && !sourceHasResults({ results: [{ platform: "Discord", state: "taken" }, { platform: "Reddit", state: "blocked" }] }), "Discord answered, so it is not a part that failed; a taken handle is still not a result, and blocked rows make the source partial");
  const card = sourceCards.platformCheck(PC, {});
  ok(/Discord<\/?[^>]*>?\s*<span class="tag ">handle taken<\/span>|Discord <span class="tag ">handle taken<\/span>/.test(card) && card.includes("1 handle taken") && />Reddit<svg/.test(card) && card.includes("Blocked by site") && !/<a[^>]*>Discord</.test(card), "the Platform check card lists Reddit and Discord with their states, and Discord has no link");
  // Reddit
  ok(r && r.tier === "unverified" && r.url === "https://www.reddit.com/user/Err0ric" && r.link_kind === "templated_unverified" && r.hint === L.REDDIT_HINT && /^Blocked by site \(Reddit refuses requests from servers, so this could not be checked automatically\)$/.test(r.meta), "Reddit blocked: an unverified link, the reason, and how to check by hand");
  ok(r.card.basis === "Nothing was read." && /^Blocked by site/.test(r.card.note), "the Reddit card does not say the platform check reported a profile");
  // a tool's report is replaced by the platform check's answer
  const withTool = { ...c, sherlock: { ...c.sherlock, results: [...c.sherlock.results, { site: "Reddit", url: "https://www.reddit.com/user/Err0ric", verified: false }] } };
  const rt = buildEvidence(withTool, T, "username").items.filter((i) => i.key === "acct:reddit");
  ok(rt.length === 1 && rt[0].sources.join() === "Platform check,Sherlock" && rt[0].card.basis === "Reported by Sherlock. Nothing was read." && /^Blocked by site/.test(rt[0].meta) && !/reported by 2 tools/.test(rt[0].meta), "a tool that also lists Reddit is named on the one row, and the platform check's state stands");
  const freePc = { ...PC, results: PC.results.map((x) => (x.platform === "Discord" ? { ...x, state: "not_found", found: false } : x.platform === "Reddit" ? { ...x, state: "not_found", found: false } : x)) };
  const free = buildEvidence({ ...withTool, platformCheck: freePc }, T, "username");
  ok(!free.items.some((i) => i.key === "acct:discord" || i.key === "acct:reddit"), "when the platform check says the handle is not there, the tools' rows for that site are dropped");
  const noPc = buildEvidence({ ...withTool, platformCheck: undefined }, T, "username");
  ok(noPc.items.some((i) => i.key === "acct:discord" && !i.taken) && noPc.items.some((i) => i.key === "acct:reddit" && i.sources.join() === "Sherlock"), "without a platform check the tools' rows stand as before");
  // Reddit read through the API
  const found = { ...PC, results: PC.results.map((x) => (x.platform === "Reddit" ? { platform: "Reddit", url: "https://www.reddit.com/user/Err0ric", state: "found", found: true, evidence: "Reddit's own record for this handle", display_name: "Sam Example", bio: "Maps and bread", created: "2015-01-01", karma: 1354, avatar_url: "https://styles.redditmedia.com/t5_abc/styles/profileIcon_x.jpg?width=256", note: "suspended", public_url: true } : x)) };
  const fc = { ...c, platformCheck: found }, fe = buildEvidence(fc, T, "username"), fr = fe.items.find((i) => i.key === "acct:reddit");
  ok(fr.link_kind === "verified_profile" && ["linked", "matches", "different"].includes(fr.tier) && fr.card.facts.includes("Sam Example") && fr.card.facts.includes("1,354 karma") && fr.card.facts.includes("joined 2015") && fr.card.bio === "Maps and bread" && fr.card.note === "The site marks this account as suspended.", "a Reddit profile read through the API shows its name, bio, year, karma and the suspended note");
  ok(avatarImages(fc, T, "username").some((i) => i.id === "acct:reddit" && /^https:\/\/styles\.redditmedia\.com\//.test(i.url)) && !JSON.stringify(fe.items).includes("redditmedia"), "its picture goes to the server's avatar comparison and is never an image address on the page");
}

// ---- review fixes: an added profile is a row, never part of the identity ----------------------
{
  const { addedFactsHtml, ADDED_FACTS } = await import("../../static/v2/js/workbench.js");
  const { fromFile, FROM_FILE, LINEUP_PILL } = S;
  const tv = fx("torvalds"), extra = fx("identity-extras");
  const tvCase = (similar) => ({ ...tv.collected, avatarHash: extra.avatarHash, ...(similar ? { similar } : {}) });
  const before = buildEvidence(tvCase(null), tv.target, "username");
  const rest = (ev) => JSON.stringify(ev.items.filter((i) => !/~/.test(i.key) && i.tier !== "similar"));
  const same = (ev) => JSON.stringify(ev.identity) === JSON.stringify(before.identity) && JSON.stringify(ev.facts) === JSON.stringify(before.facts) && rest(ev) === rest(before);
  const main = (ev) => ev.identity.views.find((v) => v.primary);
  // the same picture under a conflicting name: offered, said in words, and nothing else moves
  const pcf = buildEvidence(tvCase({ "torvalds_": entry("torvalds_", [prof("GitHub", { name: "Jordan Unrelated", location: "Elsewhere", bio: "Not the kernel", avatar_hash: H2, thumb: THUMB })], ["acct:github~torvalds_"]) }), tv.target, "username");
  const prow = pcf.items.find((i) => i.key === "acct:github~torvalds_");
  ok(prow && prow.tier === "linked" && prow.card.note === "Added from the similar handle torvalds_: same picture as the GitHub profile, but the name on it differs (Jordan Unrelated, against Linus Torvalds)." && pillOf(prow).includes(">Linked<"), "same picture, conflicting name: the row lands in Linked with the difference in its note");
  ok(same(pcf) && main(pcf).label === "Linus Torvalds" && main(pcf).thumb === main(before).thumb && !JSON.stringify(pcf.identity).includes("Jordan") && !pcf.facts.some((f) => /Jordan|Elsewhere|Not the kernel/.test(f.v)), "and the primary's label, picture, members and facts, and every other row, are as they were");
  ok(pcf.added[0].facts.map((f) => `${f.k}=${f.v}`).join() === "Name=Jordan Unrelated,Location=Elsewhere,Bio=Not the kernel" && pcf.added[0].facts.every((f) => f.source === "GitHub (torvalds_)"), "its name and facts are only in the block for added profiles");
  const card = evWhat(pcf.items.find((i) => i.key === "similar:torvalds_"));
  ok(card.includes("Same picture, but the name on it differs (Jordan Unrelated, against Linus Torvalds).") && card.includes(">Same picture, name differs</span>") && card.includes("data-sim-remove"), "the card says so before and after the add");
  // a nameless primary never takes the added profile's name as its label
  ok(main(buildEvidence(caseOf(erroric(["acct:github~erroric"])), T, "username")).label === main(buildEvidence(caseOf(null), T, "username")).label && main(buildEvidence(caseOf(null), T, "username")).label !== "Sam Example", "a primary with no name keeps its label when a named profile is added");
  // the block in "What we know", and in the Markdown export
  const block = addedFactsHtml(pcf.added);
  ok(ADDED_FACTS === "From profiles you added (under a different handle)" && block.includes(`>${ADDED_FACTS}</h3>`) && block.includes("Jordan Unrelated") && block.includes("GitHub (torvalds_)") && addedFactsHtml([]) === "" && addedFactsHtml(before.added) === "", "What we know gets a separate, labelled block for added profiles, and only when there is one");
  const md = caseMarkdown({ collected: tvCase({ "torvalds_": entry("torvalds_", [prof("GitHub", { name: "Jordan Unrelated", avatar_hash: H2 })], ["acct:github~torvalds_"]) }), target: tv.target, type: "username" });
  ok(md.includes(`## ${ADDED_FACTS}`) && md.indexOf("Jordan Unrelated") > md.indexOf(`## ${ADDED_FACTS}`) && !md.slice(0, md.indexOf(`## ${ADDED_FACTS}`)).includes("Jordan Unrelated"), "the Markdown export keeps the same separation");
  const briefRows = investigateBrief({ collected: {}, items: pcf.items, facts: pcf.facts, identity: pcf.identity, failed: [], type: "username", target: tv.target }).rows.map((r) => r.text).join("\n");
  const briefBefore = investigateBrief({ collected: {}, items: before.items, facts: before.facts, identity: before.identity, failed: [], type: "username", target: tv.target }).rows.map((r) => r.text).join("\n");
  ok(briefRows === briefBefore, "the brief's account counts do not include an added profile");
  // name-only adds
  const strangers = buildEvidence(tvCase({ linustorvalds: entry("linustorvalds", [prof("X", { name: "Linus Torvalds" })], ["acct:x~linustorvalds"]), "torvalds_": entry("torvalds_", [prof("X", { name: "Linus" }), prof("Instagram", { name: "Linus B Torvalds" })], ["acct:x~torvalds_", "acct:instagram~torvalds_"]) }), tv.target, "username");
  ok(!strangers.items.some((i) => /~/.test(i.key)) && same(strangers), "a name under a handle built from that name, one word of the name, or a longer name: none is added, whatever the stored case says");
  const outcomes = (ev, v) => ev.items.find((i) => i.key === `similar:${v}`).sim.profiles.map((p) => `${p.lineup.outcome}:${p.pill.word}`).join("|");
  ok(outcomes(strangers, "linustorvalds") === "name_built:Same name, proves nothing" && outcomes(strangers, "torvalds_") === "name_weak:Same name, not enough to add|name_weak:Same name, not enough to add", "each says in its pill why it is not offered");
  ok(strangers.items.find((i) => i.key === "similar:torvalds_").sim.summary === "2 profiles read: 2 share a name, which is not enough to add." && !evWhat(strangers.items.find((i) => i.key === "similar:torvalds_")).includes("data-sim-add") && /Use Investigate this to look at the handle as a case of its own\./.test(evWhat(strangers.items.find((i) => i.key === "similar:torvalds_"))), "the row counts them apart and points at Investigate this");
  ok(Object.keys(LINEUP_PILL).join() === "picture,picture_conflict,link,name,name_weak,name_built,conflict,nothing", "the outcome list");
  const nameAdd = aiPayloadFor(tvCase({ "torvalds_": entry("torvalds_", [prof("GitHub", { name: "Linus Torvalds" })], ["acct:github~torvalds_"]) }), tv.target, "username").accounts.find((a) => a.handle === "torvalds_");
  ok(nameAdd.status === "matches" && /same full name\. A name alone is supporting, not proof/.test(nameAdd.note), "the AI gets a name add as Exists (matches), with the caveat");
  const builtAdd = aiPayloadFor(tvCase({ linustorvalds: entry("linustorvalds", [prof("GitHub", { avatar_hash: H2 })], ["acct:github~linustorvalds"]) }), tv.target, "username").accounts.find((a) => a.handle === "linustorvalds");
  ok(builtAdd.status === "linked" && /this handle was built from the name on the primary profile/.test(builtAdd.note), "and is told when the handle was built from the name");

  // a picture that could not be read is not "no picture"
  const lost = readProbe(probeOf([{ ...prof("GitHub"), avatar_state: "failed" }]), "sam_").profiles[0];
  ok(lost.avatar_state === "failed" && readProbe(probeOf([prof("GitHub")]), "sam_").profiles[0].avatar_state === "none" && readProbe(probeOf([prof("GitHub", { avatar_hash: H1, avatar_state: "failed" })]), "sam_").profiles[0].avatar_state === "ok" && readProbe(probeOf([{ ...prof("GitHub"), avatar_state: "<b>" }]), "sam_").profiles[0].avatar_state === "none", "the picture's state is read as one of four words");
  const lt = lineUp(asProfile("sam_", lost), base(), { handle: "sam" });
  ok(lt.why === "picture_failed" && lt.text === "Read, but nothing to compare: this profile carries no name, and the picture could not be compared." && /The picture could not be compared, and no link ties it/.test(lineUp(asProfile("sam_", { ...lost, name: "Lisbon Maps Club" }), base(), { handle: "sam" }).text), "the card says the picture could not be compared, never that there is none");

  // a case file cannot attach a handle
  const gates = { billgates: entry("billgates", [prof("X", { name: "Sam Example" })], ["acct:x~billgates"]), "sam_": entry("sam_", [prof("GitHub", { name: "Sam Example", avatar_hash: H2, thumb: THUMB })], ["acct:github~sam_"]), samexample: entry("samexample", [prof("X", { name: "Sam Example" })], ["acct:x~samexample"]) };
  const own = { github: { found: true, username: "sam", name: "Sam Example", profile_url: "https://github.com/sam", avatar_url: "", public_repos: 1, followers: 1 }, avatarHash: { results: [{ id: "acct:github", hash: H1, default: false }] } };
  const localEv = buildEvidence({ ...own, similar: gates }, "sam", "username");
  ok(localEv.items.some((i) => i.key === "acct:x~billgates") && localEv.items.some((i) => i.key === "acct:github~sam_"), "(in a case checked in this browser both would be rows)");
  const imp = parseCaseFile(JSON.stringify(buildCaseFile({ mode: "investigate", target: "sam", type: "username", collected: { ...own, similar: gates } }))).entry.results;
  ok(Object.keys(imp.similar).sort().join() === "sam_,samexample" && Object.values(imp.similar).every((e) => e.from_file === true && e.added.length === 0), "from a file: a handle the case would not offer is dropped, and nothing stays added");
  const impEv = buildEvidence(imp, "sam", "username");
  ok(!impEv.items.some((i) => /~/.test(i.key)) && !JSON.stringify(impEv.items).includes("billgates") && impEv.similarLine === "" && impEv.added.length === 0, "nothing from the file is in the ledger, the brief or What we know");
  const frow = impEv.items.find((i) => i.key === "similar:sam_"), fhtml = evWhat(frow);
  ok(frow.sim.state === "file" && frow.sim.summary.startsWith(FROM_FILE) && frow.sim.profiles[0].link_kind === "templated_unverified" && frow.sim.profiles[0].thumb === "" && !frow.sim.profiles[0].lineup.canAdd, "a kept answer is marked as from the file, not checked here");
  ok(fhtml.includes("lk-unverified") && fhtml.includes(">From the file</span>") && /class="cp tone-unverified line-dashed"/.test(fhtml) && /class="sim-card tone-unverified line-dashed"/.test(fhtml) && !fhtml.includes("data-sim-add") && !fhtml.includes("mark-thumb") && />Check here</.test(evSrc(frow)), "its links are unverified, its card is dashed, it has no Add, and the row offers Check here");
  ok(JSON.stringify(fromFile(gates, "sam", [])) === "{}" && Object.keys(fromFile({ ...gates, bad: { variant: "bad", error: { error: "x" } } }, "sam", ["sam_", "bad"])).join() === "sam_" && readSimilar({ "sam_": { ...gates["sam_"], from_file: true } }, "sam")["sam_"].added.length === 0, "fromFile keeps only allowed handles with an answer, and from_file never carries an add");
  // checking it here replaces the file's answer
  const rechecked = buildEvidence({ ...imp, similar: { ...imp.similar, "sam_": { variant: "sam_", checked_at: 5, probe: gates["sam_"].probe, added: ["acct:github~sam_"] } } }, "sam", "username");
  ok(rechecked.items.some((i) => i.key === "acct:github~sam_" && i.tier === "linked") && rechecked.items.find((i) => i.key === "similar:sam_").sim.state === "checked", "once checked here it can be added like any other");

  // a check in flight shows in every redraw
  const busyRow = { ...before.items.find((i) => i.tier === "similar"), sim: { ...before.items.find((i) => i.tier === "similar").sim, busy: true } };
  const box = { innerHTML: "", id: "t" };
  renderTiers(box, [busyRow], ledgerTiers(tv.target, "username"), new Set(), "");
  ok(/aria-disabled="true">Checking…/.test(evSrc(busyRow)) && /data-row="similar:[^"]+" aria-busy="true"/.test(box.innerHTML) && !/aria-busy|aria-disabled/.test(evSrc(before.items.find((i) => i.tier === "similar"))), "a handle being checked is drawn busy with a disabled button, whoever redraws the ledger");

  // counts: a handle with nothing anywhere has no findings
  const blockedPc = { username: "zqnobody", total: 0, checked: 2, results: PC.results.filter((x) => ["Reddit", "Discord"].includes(x.platform)) };
  const empty = { sherlock: { results: [{ site: "Discord", url: "https://discord.com" }] }, maigret: { results: [] }, github: { found: false }, platformCheck: blockedPc };
  const ee = buildEvidence(empty, "zqnobody", "username");
  ok(ee.items.filter(isFinding).length === 0 && ee.items.filter((i) => i.tier === "unverified").length === 2 && investigateTiles({ items: ee.items, collected: empty, type: "username" }).find((t) => t.id === "unverified").value === 2, "a blocked Reddit row and a taken Discord handle are not findings; they count on the Unverified tile only");
  const tl = sourceTally(empty, { sherlock: "Sherlock", platformCheck: "Platform check", github: "GitHub" });
  ok(tl.rows.find((r) => r.key === "platformCheck").hasResults === false && tl.rows.find((r) => r.key === "platformCheck").state === "partial", "and the platform check is not counted as a source with results");
  const withReddit = buildEvidence({ ...empty, sherlock: { results: [{ site: "Reddit", url: "https://www.reddit.com/user/zqnobody" }] } }, "zqnobody", "username");
  ok(withReddit.items.filter(isFinding).map((i) => i.key).join() === "acct:reddit" && withReddit.items.find((i) => i.key === "acct:reddit").tools === 1, "a tool's own report of Reddit is still a finding, by one tool");
  // Reddit's API not-found keeps a tool's report
  const hiddenPc = { ...blockedPc, results: [{ platform: "Reddit", url: "https://www.reddit.com/user/zqnobody", state: "not_found", found: false, evidence: "x", hidden_possible: true }] };
  const hid = buildEvidence({ ...empty, sherlock: { results: [{ site: "Reddit", url: "https://reddit.com/" }] }, platformCheck: hiddenPc }, "zqnobody", "username").items.find((i) => i.key === "acct:reddit");
  ok(hid && hid.tier === "unverified" && hid.url === "https://www.reddit.com/user/zqnobody" && hid.meta === L.REDDIT_HIDDEN && hid.card.note === `${L.REDDIT_HIDDEN}.` && hid.sources.join() === "Sherlock", "when Reddit's API finds no visible account, a tool's Reddit row stays, unverified, with that said");
  ok(!buildEvidence({ ...empty, platformCheck: hiddenPc }, "zqnobody", "username").items.some((i) => i.key === "acct:reddit") && !buildEvidence({ ...empty, sherlock: { results: [{ site: "Reddit", url: "https://reddit.com/" }] }, platformCheck: { ...hiddenPc, results: [{ ...hiddenPc.results[0], hidden_possible: undefined }] } }, "zqnobody", "username").items.some((i) => i.key === "acct:reddit"), "with no tool report there is no row, and the keyless not-found still drops one");

  // variants: nothing absurd
  ok(!values("realestate").includes("estate") && !values("realtor_jane").includes("tor_jane") && !values("TheRapist").includes("rapist") && !values("the_rapist").includes("rapist") && !values("theory_x").includes("ory_x") && !values("official").some((v) => v.length < 3), "a decoration is not taken off an ordinary word that starts with it");
  ok(!values("realsam").includes("sam") && !values("therealsam").includes("sam") && values("real_sam")[0] === "sam" && values("RealSam")[0] === "sam" && values("the_real_sam")[0] === "sam" && values("SamOfficial")[0] === "sam", "and only at a separator or a change of case");
  ok(!values("im_x").includes("x") && !values("its_ab").includes("ab"), "never when fewer than 3 characters would be left");
  for (const h of [".eric", "_eric_", "a..b", "x_", "-", "._", "sam.", "__init__"]) ok(similarHandles(h).every((x) => !/^[._-]{2}|[._-]{2}$/.test(x.value)), `${h}: no variant begins or ends with two separators`);
  ok(similarBase("info@", "email") === "" && similarBase("@", "email") === "" && similarBase("info@", "username") === "" && buildEvidence({}, "info@", "email").items.every((i) => i.tier !== "similar") && handleVariants("info@").length === 0, "something that is not a whole address or a valid handle builds nothing");
  ok(nameVariants("Linux Kernel Dev").length === 0 && nameVariants("Dr Eric").length === 0 && nameVariants("Example Security Labs").length === 0 && nameVariants("Sam Example 2").length === 0 && nameVariants("A B C D").length === 0, "no handles are built from a label that is not a person's name");
  ok(nameVariants("Dr. Sam Example")[0].value === "samexample" && nameVariants("Prof Sam Q Example").some((x) => x.value === "samqexample") && nameVariants("Sam Example").length > 0, "a title is dropped, and a name of two or three words builds");
}

console.log(bad ? `${bad} of ${n} similar handle checks failed` : `${n}/${n} similar handle checks passed`);
if (bad) process.exit(1);
