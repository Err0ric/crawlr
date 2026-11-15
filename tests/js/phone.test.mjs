// Phone cases: detection, the checked reading of an answer, the ledger, facts, tiles, brief, the
// source tally, exports, the AI field and case files. The fixture (tests/js/fixtures/phone.json)
// is what modules/phone_lookup.py returns for each number, with the NPA-NXX answers recorded on
// 2026-11-14, plus two answers in the shape the endpoint had before. No browser, no network.
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
const { detect, looksLikePhone, sourceTally, sourceCoverage, sourceHasResults, statusForAi } = await import("../../static/v2/js/core.js");
const P = await import("../../static/v2/js/phone.js");
const { buildEvidence, ledgerTiers, isFinding, aiPayloadFor, caseMarkdown, sourcePlan } = await import("../../static/v2/js/evidence.js");
const { investigateBrief } = await import("../../static/v2/js/brief.js");
const { investigateTiles } = await import("../../static/v2/js/present.js");
const { sourceCards } = await import("../../static/v2/js/renderers.js");
const { evWhat } = await import("../../static/v2/js/workbench.js");
const { buildCaseFile, parseCaseFile } = await import("../../static/v2/js/casefile.js");
const L = await import("../../static/v2/js/links.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const eq = (a, b, name) => ok(JSON.stringify(a) === JSON.stringify(b), `${name}\n   got  ${JSON.stringify(a)}\n   want ${JSON.stringify(b)}`);
const fx = JSON.parse(fs.readFileSync(new URL("./fixtures/phone.json", import.meta.url), "utf8"));
const T = "+1 202 456 1111";
const ev = (k, target = T) => buildEvidence({ phone: fx[k] }, target, "phone");
const tier = (e, t) => e.items.filter((i) => i.tier === t);
const fact = (e, k) => e.facts.find((f) => f.k === k);
const tally = (k) => sourceTally({ phone: fx[k] }, { phone: "Phone lookup" });
const brief = (k) => { const e = ev(k); const t = tally(k); return investigateBrief({ collected: { phone: fx[k] }, items: e.items, facts: e.facts, identity: e.identity, failed: t.rows.filter((r) => r.state === "failed"), incomplete: [], type: "phone", target: T }); };
const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");
const tiles = (k) => { const t = tally(k); const st = (s) => t.rows.filter((r) => r.state === s).map((r) => r.key); return investigateTiles({ items: ev(k).items, collected: { phone: fx[k] }, type: "phone", failedKeys: st("failed"), partialKeys: st("partial"), extra: P.phoneTileExtra(fx[k]) }); };
const show = (ts) => ts.map((t) => `${t.label}=${t.value}`).join("|");
const BROKERS = /spokeo|whitepages|beenverified|truecaller|numverify|calleridtest|intelius|peoplefinder/i;

// ---- detection: both directions -------------------------------------------------------------------
{
  const phones = ["+1 202 456 1111", "+12024561111", "202-456-1111", "(202) 456-1111", "202.456.1111", "202 456 1111", "2024561111", "1 202 456 1111", "12024561111", "1-202-456-1111",
    "+44 20 7946 0958", "+44 (0)20 7946 0958", "0044 20 7946 0958", "00 44 20 7946 0958", "020 7946 0958", "07400 123456", "07400123456", "+49 1512 3456789", "+91 98765 43210", "+55 (11) 91234-5678", "0412 345 678",
    "1-800-FLOWERS", "1 (800) MY-APPLE", "800-GO-FEDEX", "+1 800 356 9377", "+1 202 456 1111 ext. 22", "202-456-1111 x22", "253 555 0100", "+1 253 555 0100", "555-1234", "+33 9 12 34 56 78", "030/123456"];
  for (const p of phones) ok(detect(p) === "phone", `"${p}" is a phone number (got ${detect(p)})`);
  const not = { "44d88612fea8a8f36de82e1278abb02f": "hash", "12345678901234567890123456789012": "hash", "8.8.8.8": "ip", "192.168.100.200": "ip", "AS15169": "asn", "as64496": "asn",
    "2024-01-15": "username", "15/01/2024": "username", "01.15.2024": "username", "2024/1/5": "username", "1999-12-31": "username", "2020-2021": "username", "3.14159265": "username", "1.2.3": "username",
    "12345678": "username", "123456": "username", "20240115": "username", "9876543210123": "username", "007": "username", "1800flowers": "username", "user1234567": "username", "404-not-found": "username",
    "911": "username", "jdoe": "username", "a@b.com": "email", "example.com": "domain", "Jane Doe": "name", "+": "username", "++1 202 456 1111": "username", "202--456--1111": "username", "1-800-": "username" };
  for (const [k, want] of Object.entries(not)) ok(detect(k) === want, `"${k}" is ${want}, not a phone number (got ${detect(k)})`);
  ok(!looksLikePhone("") && !looksLikePhone(null) && !looksLikePhone("1".repeat(41)), "empty and oversized input is not a phone number");
}

// ---- reading an answer ------------------------------------------------------------------------------
{
  const r = P.readPhone(fx.us);
  ok(r && !r.legacy && r.number.e164 === "+12024561111" && r.number.national === "(202) 456-1111" && r.valid === true && r.kind === "number", "a new answer is read");
  eq(Object.keys(r.sources), ["numbering_plan", "npa_nxx"], "a source that was not asked has no entry");
  ok(r.assignment.evidence_url === "https://localcallingguide.com/lca_prefix.php?npa=202&nxx=456" && r.assignment.rate_centre === "Washington Zone 1" && r.assignment.block_assigned === true, "the block record is kept");
  eq(P.readPhone(r), r, "reading is idempotent");
  ok(!("owner_note" in r) && !JSON.stringify(r).includes("rc-lat"), "nothing but the known fields is kept");
  // A hostile answer or case file.
  const evil = JSON.parse(JSON.stringify(fx.us));
  evil.number.e164 = "+1202<script>"; evil.number.international = "x".repeat(500); evil.number.line_type = "<b>"; evil.number.time_zones = ["America/New_York", "<img>", 3, "a".repeat(80)];
  evil.assignment.evidence_url = "https://evil.example/lca_prefix.php?npa=202&nxx=456"; evil.assignment.prefix = "202-456";
  evil.findings = [{ level: "flag", code: "x y", title: `T${String.fromCharCode(0x2028)}itle\nsecond`, detail: "d".repeat(900) }, { level: "critical", title: "no" }, { level: "ok" }, ...Array(40).fill({ level: "info", code: "note", title: "n", detail: "" })];
  evil.search_links = [{ site: "Google", url: "https://evil.example/search?q=1" }, { site: "Spokeo", url: "https://www.spokeo.com/1" }, { site: "Bing", url: "http://www.bing.com/search?q=1" }, { site: "DuckDuckGo", url: "https://user:pw@duckduckgo.com/?q=1" },
    { site: "800notes", url: "javascript:alert(1)" }, { site: "WhoCallsMe", url: "https://whocallsme.com/Phone-Number.aspx/2024561111", label: "<i>x</i>", group: "weird" }, { site: "WhoCallsMe", url: "https://whocallsme.com/again" }];
  evil.sources.npa_nxx.state = "maybe"; evil.sources.numlookup = { state: "ok", carrier: "C".repeat(300), line_type: 7 }; evil.sources.extra = { state: "ok" };
  const e = P.readPhone(evil);
  ok(e.number.e164 === "" && e.number.international.length === 30 && e.number.line_type === "unknown" && e.number.line_type_text === "Unknown", "bad number fields are dropped or clipped");
  eq(e.number.time_zones, ["America/New_York"], "a time zone must look like one");
  ok(e.findings.length === 20 && e.findings[0].code === "note" && e.findings[0].title === "T itle second" && e.findings[0].detail.length === 400, "findings are bounded, one line each, with a known level");
  eq(e.search_links.map((l) => [l.site, l.url, l.group, l.kind]), [["WhoCallsMe", "https://whocallsme.com/Phone-Number.aspx/2024561111", "search engine", "search"]], "a search link must be https and point at the site it names");
  ok(!e.sources.npa_nxx && !e.sources.extra && e.sources.numlookup.carrier.length === 80 && e.sources.numlookup.line_type === "", "sources keep known keys and states");
  ok(e.assignment.evidence_url === "" && e.assignment.rate_centre === "" && e.assignment.block_assigned === null, "with no answered block source there is no block record, and the evidence link is never taken from the file");
  ok(P.blockPage("202-456") === "https://localcallingguide.com/lca_prefix.php?npa=202&nxx=456" && P.blockPage("202-000") === "" && P.blockPage("202-456&x=1") === "" && P.blockPage(null) === "", "the block page is built from a checked prefix only");
  ok(P.readPhone(null) === null && P.readPhone("x") === null && P.readPhone([]) === null, "not an answer");
  eq(P.readPhone({ error: "Boom", error_code: "timeout", error_detail: "x", number: {} }), { error: "Boom", error_code: "timeout", error_detail: "x" }, "a failure keeps its three fields");
}

// ---- a United States number --------------------------------------------------------------------
{
  const e = ev("us");
  eq(ledgerTiers(T, "phone").map((t) => t.title), ["Flags", "About this number", "Search the web"], "a phone case has three groups");
  ok(ledgerTiers(T, "phone")[2].blurb === "These open a search on another site. The number goes to that site.", "the search group says the number goes to that site");
  eq([...new Set(e.items.map((i) => i.tier))], ["info", "websearch"], "no flags: what the data says, then the searches");
  eq(tier(e, "info").map((i) => i.key), ["phone:valid", "phone:block"], "the validity row and the block row");
  const block = e.items.find((i) => i.key === "phone:block");
  ok(block.what === "The 202-456 block is assigned to Washington Zone 1, DC" && /not the place of the phone or the person/.test(block.meta) && /First assigned to VERIZON WASHINGTON DC, INC\. Numbers are ported/.test(block.meta), "the block row says what it is and what it is not");
  ok(block.link_kind === "evidence" && block.link_label === "Block record" && block.url === "https://localcallingguide.com/lca_prefix.php?npa=202&nxx=456" && block.source === "Local Calling Guide", "it links to the public page for the prefix, as evidence");
  ok(!/1111/.test(block.url), "the evidence link carries the area code and exchange, never the number");
  ok(/data-link-kind="evidence"/.test(evWhat(block)) && />Block record</.test(evWhat(block)), "and is drawn as a labelled evidence link");
  eq(e.facts.map((f) => f.k), ["Number", "National format", "E.164", "Validity", "Country", "Line type", "Range assigned in", "Rate centre", "Range first assigned to", "Time zone of the range", "Who uses it"], "What we know, in order");
  ok(fact(e, "Number").v === "+1 202-456-1111" && fact(e, "E.164").v === "+12024561111" && fact(e, "Country").v === "United States (+1)", "formats and country");
  ok(fact(e, "Line type").v === "Fixed line or mobile (the numbering plan cannot tell which)", "the line type says the plan cannot tell which");
  ok(fact(e, "Range assigned in").v === "Washington D.C. (the range, not the phone or the person using it)", "the area is labelled as the range's, not the phone's");
  ok(fact(e, "Range first assigned to").v === "VERIZON WASHINGTON DC, INC. (numbers are ported, so this may not be the current carrier)" && fact(e, "Range first assigned to").source === "Local Calling Guide", "the first assignee carries the porting caveat");
  ok(fact(e, "Rate centre").link_kind === "evidence" && fact(e, "Number").link_kind === "none" && fact(e, "Number").source === "Numbering plan", "facts name their source, and only the block facts link");
  ok(fact(e, "Who uses it").v === "Not something open numbering data shows.", "What we know says what cannot be known");
  ok(!e.facts.some((f) => /^(Owner|Name|Address|Subscriber)$/.test(f.k)) && e.identity.views.length === 0, "nothing about a person");
  ok(e.items.filter(isFinding).length === 2, "the searches are not findings");
  eq(show(tiles("us")), "Valid=Valid|Line type=Fixed line or mobile|Assigned in=Washington Zone 1, DC|Flags=0", "tiles: Valid, Line type, Assigned in, Flags");
  const ts = tiles("us");
  ok(ts[0].tone === "linked" && ts.slice(0, 3).every((t) => t.line === "solid" && t.state === "word") && ts[2].sub === "the range, not the phone" && ts[1].sub === "the plan cannot tell which" && ts[3].state === "zero", "read from the numbering plan, so solid, each with what it means");
  const b = text(brief("us"));
  ok(/^ok: \+1 202-456-1111 is a valid United States number: fixed line or mobile \(the numbering plan cannot tell which\)\. Valid means the digits fit a number range\. It does not show the number is in service\./.test(b), "the brief says what the number is");
  ok(/info: Its number range is assigned in Washington Zone 1, DC\. That is where the range is assigned, not where the phone or the person using it is\. The range was first assigned to VERIZON WASHINGTON DC, INC\. Numbers are ported/.test(b), "and where its range is assigned, with both caveats");
  ok(b.endsWith("info: Who uses this number is not something open numbering data shows."), "and what cannot be known");
  ok(brief("us").rows.find((r) => /range is assigned in/.test(r.text)).link_kind === "evidence", "the brief line links to the block record");
  ok(!/NumLookup|key/.test(b), "nothing asks for a key");
  const t = tally("us");
  ok(t.rows[0].state === "results" && t.withResults === 1 && t.failed === 0 && t.partial === 0 && sourceHasResults(fx.us), "the lookup counts as a source with results, with no key");
}

// ---- search links ------------------------------------------------------------------------------------
{
  const s = tier(ev("us"), "websearch");
  eq(s.map((i) => i.what), ["Google", "Bing", "DuckDuckGo", "800notes", "Should I Answer", "WhoCallsMe"], "three search engines and three free report sites for a +1 number");
  ok(s.every((i) => i.link_kind === "search" && L.LINK_KINDS.includes("search") && i.key.startsWith("search:") && i.source === "opens on that site" && !isFinding(i)), "every one has the search kind and is not a finding");
  const q = new URL(s[0].url).searchParams.get("q");
  ok(q === '"(202) 456-1111" OR "202-456-1111" OR "+1 202-456-1111" OR "+12024561111"', "the query is the number in its written forms, quoted");
  ok(s[0].url.includes("%22%28202%29+456-1111%22") && s[0].url.includes("%2B12024561111") && !/[ "<>]/.test(s[0].url), "and it is percent-encoded");
  ok(s.every((i) => { const a = evWhat(i); return /target="_blank"/.test(a) && /rel="noopener noreferrer nofollow"/.test(a) && /data-link-kind="search"/.test(a); }), "they open in a new tab like every other link");
  ok(!s.some((i) => BROKERS.test(i.url + i.what)), "no data broker and no paid people-search site");
  eq(tier(ev("uk_mobile", "+44 7400 123456"), "websearch").map((i) => i.what), ["Google", "Bing", "DuckDuckGo"], "outside +1 only the search engines");
  ok(tier(ev("too_short"), "websearch").length === 0 && tier(ev("emergency", "911"), "websearch").length === 0, "digits that cannot be a number, and services, get no search links");
  for (const k of Object.keys(fx)) ok(ev(k).items.filter((i) => i.link_kind === "search").every((i) => i.tier === "websearch") && ev(k).items.filter((i) => i.tier !== "websearch").every((i) => ![i.url, i.more?.url].some((u) => u && /\d{7}/.test(u.replace(/\D/g, "")))), `${k}: no other link carries the number`);
}

// ---- flags and special ranges --------------------------------------------------------------------------
{
  const f = ev("fiction", "+1 202 555 0143");
  eq(tier(f, "flag").map((i) => [i.key, i.what, i.source]), [["phone:fiction", "Reserved for fiction", "Numbering plan"]], "a fiction number is flagged");
  ok(/reserved for fiction and is not in use/.test(tier(f, "flag")[0].meta), "with one plain sentence");
  ok(tier(f, "info").some((i) => i.key === "phone:unassigned_block" && i.link_kind === "evidence"), "its empty block is a note, with the block record");
  eq(show(tiles("fiction")), "Valid=Valid|Line type=Fixed line or mobile|Assigned in=Washington D.C.|Flags=1", "fiction tiles");
  ok(tiles("fiction")[0].sub === "but reserved for fiction" && tiles("fiction")[0].tone === "" && tiles("fiction")[3].tone === "flag", "the Valid tile says it is reserved for fiction");
  ok(/^flag: Reserved for fiction\. In North America 555-0100 to 555-0199/.test(text(brief("fiction"))) && !/^ok:/m.test(text(brief("fiction"))), "the brief leads with what the flag means, and nothing is tagged Good");

  const u = ev("unassigned", "+1 202 555 1234");
  ok(tier(u, "flag").some((i) => i.key === "phone:unassigned_block" && i.source === "Local Calling Guide" && i.link_label === "Block record"), "a block no carrier holds is a flag from the source that said so");
  const d = ev("uk_drama", "+44 7700 900123");
  ok(tier(d, "flag").length === 1 && /Ofcom/.test(tier(d, "flag")[0].meta), "a UK drama number is flagged once");
  eq(show(tiles("uk_drama")), "Valid=Not valid|Line type=unknown|Assigned in=unknown|Flags=1", "an invalid number: Not valid, and no line type");
  ok(tiles("uk_drama")[1].line === "dashed" && tiles("uk_drama")[1].sub === "not a valid number" && tiles("uk_drama")[0].tone === "flag" && tiles("uk_drama")[2].line === "dashed", "what cannot be known is dashed and says why");
  ok(tier(ev("premium"), "flag").some((i) => /charged at a premium/.test(i.meta)) && tier(ev("voip"), "flag").some((i) => i.what === "VoIP number" && /easy to get and discard/.test(i.meta)), "premium rate and VoIP are flagged with their sentence");
  ok(tier(ev("toll_free"), "flag").length === 0 && tier(ev("toll_free"), "info").some((i) => i.key === "phone:toll_free") && tier(ev("toll_free"), "info").some((i) => i.key === "phone:vanity"), "toll free is a note, and so is the vanity spelling");
  eq(show(tiles("toll_free")), "Valid=Valid|Line type=Toll free|Assigned in=North America|Flags=0", "a toll-free number belongs to the shared plan");

  const i = ev("invalid", "+1 555 555 1234");
  eq(tier(i, "flag").map((x) => x.key), ["phone:invalid"], "an invalid number is a flag");
  ok(/no number range in its plan starts with these digits/.test(fact(i, "Validity").v) && !fact(i, "Line type") && !fact(i, "Rate centre"), "it says why, and claims no line type or place");
  ok(/flag: Not a valid number for /.test(text(brief("invalid"))) && !/is a valid/.test(text(brief("invalid"))), "the brief says it is not valid");
  ok(/too|area code/.test(fact(ev("too_short"), "Validity").v) && tiles("too_short")[0].value === "Not valid", "too short says so");

  const em = ev("emergency", "911");
  eq(tier(em, "flag").map((x) => x.what), ["Emergency number"], "an emergency number is named as one");
  eq(em.facts.map((x) => x.k), ["Kind of number", "Country", "Who uses it"], "and is not treated as a subscriber number");
  eq(show(tiles("emergency")), "Valid=Emergency number|Line type=Emergency number|Assigned in=United States|Flags=1", "emergency tiles");
  ok(/It is a service, not a subscriber number/.test(text(brief("emergency"))) && !/Who uses this number/.test(text(brief("emergency"))), "the brief says what it is");
  ok(tier(ev("short_code", "46645"), "info").some((x) => x.what === "Short code") && tiles("short_code")[0].value === "Short code", "a short code is named as one");
  ok(/No country code given, read as a United States number\. Add the country code/.test(text(brief("assumed"))) && tier(ev("assumed"), "info").some((x) => x.what === "No country code given, read as a United States number"), "an assumed country is stated on screen");
}

// ---- other countries --------------------------------------------------------------------------------
{
  const m = ev("uk_mobile", "+44 7400 123456");
  eq(show(tiles("uk_mobile")), "Valid=Valid|Line type=Mobile|Assigned in=United Kingdom|Flags=0", "a UK mobile");
  ok(fact(m, "Range first assigned to").v === "Three (numbers are ported, so this may not be the current carrier)" && fact(m, "Range first assigned to").source === "Numbering plan" && fact(m, "Range first assigned to").link_kind === "none", "the library's carrier is the range's first assignee, with the caveat and no link");
  ok(!fact(m, "Rate centre") && !fact(m, "Range assigned in") && !m.items.some((i) => i.key === "phone:block"), "no place finer than the country is claimed for a mobile range");
  ok(/The range was first assigned to Three\. Numbers are ported/.test(text(brief("uk_mobile"))) && /valid United Kingdom number: mobile\./.test(text(brief("uk_mobile"))), "the brief says so");
  ok(fact(ev("uk_landline"), "Range assigned in").v.startsWith("Birmingham (") && tiles("uk_landline")[2].value === "Birmingham", "a UK landline has an area");
  ok(tiles("canada")[2].value === "Vancouver, BC" && fact(ev("canada"), "Range first assigned to").v.startsWith("TELUS"), "a Canadian block");
  ok(fact(ev("de_mobile"), "Range first assigned to").v.startsWith("T-Mobile ("), "a German mobile");
}

// ---- NumLookup and failures: three states, never merged --------------------------------------------------
{
  const k = ev("us_numlookup");
  ok(fact(k, "Current carrier").v === "Verizon Communications" && fact(k, "Current carrier").source === "NumLookup" && fact(k, "Line type from NumLookup").v === "landline", "NumLookup's carrier is shown as NumLookup's");
  ok(fact(k, "Line type").source === "Numbering plan" && k.items.some((i) => i.key === "phone:numlookup" && i.source === "NumLookup" && /asked with your key/.test(i.meta)), "beside the offline facts, not over them");
  ok(/NumLookup, asked with your key, reports the current carrier as Verizon Communications and the line type as landline\./.test(text(brief("us_numlookup"))), "the brief says where it came from");
  ok(tally("us_numlookup").rows[0].state === "results" && sourceCoverage(fx.us_numlookup).total === 3, "three sources answered");

  const nf = ev("us_numlookup_failed");
  ok(fact(nf, "Rate centre") && fact(nf, "Validity") && !fact(nf, "Current carrier"), "a rejected key does not blank the offline facts");
  const tn = tally("us_numlookup_failed").rows[0];
  ok(tn.state === "partial" && tn.text === "partial: 2 of 3 sources answered" && statusForAi(tn) === "partial: 2 of 3 sources answered", "the lookup is partial, said the same way everywhere");
  ok(/NumLookup could not be asked \(NumLookup rejected the key\. Update or clear it in Settings\), so the current carrier is unknown/.test(text(brief("us_numlookup_failed"))), "the brief names the source that failed");

  const bf = ev("us_block_failed");
  ok(!bf.items.some((i) => /block/.test(i.key)) && !fact(bf, "Rate centre") && fact(bf, "Range assigned in"), "a failed block lookup claims nothing about the block");
  ok(/Local Calling Guide could not be asked about the 202-456 block, so whether it is assigned is unknown, not "unassigned"\./.test(text(brief("us_block_failed"))), "and the brief says unknown, not unassigned");
  ok(tally("us_block_failed").rows[0].state === "partial" && tiles("us_block_failed")[2].value === "Washington D.C.", "partial, and the tile falls back to the plan's own area");
  const hot = JSON.parse(JSON.stringify(fx.unassigned)); hot.sources.npa_nxx = { state: "failed", error: "The source took too long to answer.", error_code: "timeout" };
  const tf = sourceTally({ phone: hot }, { phone: "Phone lookup" }), stf = (s) => tf.rows.filter((r) => r.state === s).map((r) => r.key);
  const ft = investigateTiles({ items: buildEvidence({ phone: hot }, T, "phone").items, collected: { phone: hot }, type: "phone", failedKeys: stf("failed"), partialKeys: stf("partial"), extra: P.phoneTileExtra(hot) });
  ok(ft[3].atLeast === true && /at least/.test(ft[3].sub), "with a source down, a flag count is a lower bound");

  const dead = { phone: fx.failed };
  const ef = buildEvidence(dead, T, "phone");
  ok(ef.items.length === 0 && ef.facts.length === 0, "a failed lookup contributes nothing");
  const td = sourceTally(dead, { phone: "Phone lookup" });
  ok(td.rows[0].state === "failed" && td.failed === 1, "and is counted as failed, not as not found");
  const dt = investigateTiles({ items: [], collected: dead, type: "phone", failedKeys: ["phone"], extra: P.phoneTileExtra(fx.failed) });
  ok(dt.every((t) => t.state === "unknown" && t.line === "dashed" && t.value === "unknown") && dt[0].sub === "the lookup failed", "every tile reads unknown, dashed");
  ok(/failed card|failed/.test(sourceCards.phone(fx.failed)) && /could not be checked/.test(sourceCards.phone(fx.failed)), "its card is the failed card");
}

// ---- By source card -----------------------------------------------------------------------------------
{
  const c = sourceCards.phone(fx.us);
  ok(/>Phone lookup</.test(c) && />valid</.test(c) && /Washington Zone 1, DC/.test(c) && /data-link-kind="evidence"/.test(c), "the card shows the number and the block record");
  ok(/Numbering plan/.test(c) && /read offline from libphonenumber 9\.0\.43\. Nothing left the server\./.test(c) && /answered: the 202-456 block is assigned/.test(c) && /not asked: no key in Settings\. It is optional/.test(c), "and each source's state");
  ok(/Who uses this number is not something open numbering data shows\./.test(c) && !/links only|Add a NumLookup key/.test(c), "it never says it needs a key");
  ok(/unknown: The source took too long to answer\./.test(sourceCards.phone(fx.us_block_failed)) && /1 not asked/.test(sourceCards.phone(fx.us_block_failed)), "a failed source is unknown on the card");
  ok(/unknown: NumLookup rejected the key/.test(sourceCards.phone(fx.us_numlookup_failed)) && /from NumLookup/.test(sourceCards.phone(fx.us_numlookup)), "NumLookup's state and its carrier");
  ok(/not asked: it lists United States and Canadian geographic blocks only/.test(sourceCards.phone(fx.uk_mobile)), "outside North America the block source is not asked, and says why");
  const evil = JSON.parse(JSON.stringify(fx.us)); evil.assignment.company = '<img src=x onerror=1>'; evil.number.international = '"><script>1</script>';
  ok(!/<img src=x|<script>/.test(sourceCards.phone(evil)) && !/<img src=x/.test(JSON.stringify(buildEvidence({ phone: evil }, T, "phone").items.map(evWhat))), "source text is escaped everywhere");
}

// ---- a case saved before this change ---------------------------------------------------------------------
{
  const o = ev("old_keyed", "+1 202 555 0143");
  eq(o.facts.map((f) => [f.k, f.v, f.source]), [["Carrier", "Example Mobile", "NumLookup"], ["Line type", "voip", "NumLookup"], ["Location", "Washington, United States", "NumLookup"]], "an old case keeps its three facts");
  eq(o.items.map((i) => [i.tier, i.key]), [["flag", "phone:voip"]], "and its flag, under the same key");
  ok(!JSON.stringify(o).match(BROKERS) && !BROKERS.test(sourceCards.phone(fx.old_keyed)), "the people-search links it was saved with are not shown");
  eq(show(tiles("old_keyed")), "Valid=Valid|Line type=voip|Assigned in=Washington, United States|Flags=1", "old case tiles");
  ok(/Run this number again/.test(sourceCards.phone(fx.old_keyed)) && /saved before CrawlR read open numbering data/.test(text(brief("old_keyed"))), "it says how to get the new data");
  const e = ev("old_empty");
  ok(e.items.length === 0 && e.facts.length === 0 && tiles("old_empty").slice(0, 3).every((t) => t.state === "unknown"), "an old case that learned nothing renders, with unknown tiles");
  ok(sourceCards.phone(fx.old_empty).includes("saved by an older version") && /Run it again/.test(text(brief("old_empty"))), "and its card and brief say why");
  ok(P.phoneForAi(fx.old_keyed).legacy === true && P.phoneForAi(fx.old_keyed).carrier === "Example Mobile" && !("lookup_links" in P.phoneForAi(fx.old_keyed)), "the AI gets its old keys and no links");
}

// ---- AI field, Markdown and case files ---------------------------------------------------------------------
{
  const p = aiPayloadFor({ phone: fx.us_numlookup }, T, "phone", { source_status: { "Phone lookup": "ok" } });
  ok(p.target_type === "phone" && p.phone.number.e164 === "+12024561111" && p.phone.assignment.rate_centre === "Washington Zone 1" && p.phone.findings.length === 1 && p.phone.sources.numlookup.carrier === "Verizon Communications", "the AI gets the structured facts");
  ok(!("search_links" in p.phone) && !("input" in p.phone) && p.accounts.length === 0, "and no outbound links");
  ok(aiPayloadFor({ phone: fx.failed }, T, "phone").phone.error_code === "network" && aiPayloadFor({}, T, "phone").phone === null, "a failed lookup travels as a failure");
  eq(sourcePlan("phone", T), ["phone"], "one source in the plan");

  const md = caseMarkdown({ collected: { phone: fx.fiction }, target: "+1 202 555 0143", type: "phone", now: new Date("2026-11-14T00:00:00Z") });
  ok(/## What we know/.test(md) && /- \*\*Validity:\*\* Valid: the digits fit/.test(md) && /- \*\*Who uses it:\*\* Not something open numbering data shows\. _\(Numbering plan\)_/.test(md), "Markdown has the facts");
  ok(/## Flags \(1\)\n- Reserved for fiction · In North America/.test(md) && /## About this number \(\d\)/.test(md), "the flags and the notes");
  ok(/## Search the web \(6\)\n_These open a search on another site\. The number goes to that site\._\n- \[Google\]\(https:\/\/www\.google\.com\/search\?q=/.test(md), "and the searches, under their own heading with the warning");
  ok(/Block record\]\(https:\/\/localcallingguide\.com\/lca_prefix\.php\?npa=202&nxx=555\)/.test(md), "with the block record as a link");

  const file = (collected) => JSON.stringify(buildCaseFile({ mode: "investigate", target: T, type: "phone", ran: 1700000000000, collected, ai: null, deep: null, notes: "", purpose: "" }));
  const r = parseCaseFile(file({ phone: fx.us_numlookup }));
  ok(r.ok && r.entry.kind === "phone" && r.entry.results.phone.number.e164 === "+12024561111", "a phone case file opens");
  eq(r.entry.results.phone, P.readPhone(fx.us_numlookup), "holding exactly the checked shape");
  const evil = JSON.parse(JSON.stringify(fx.us));
  evil.search_links.push({ site: "Spokeo", url: "https://www.spokeo.com/phone-lookup/2024561111" }); evil.search_links[0].url = "https://evil.example/?q=1"; evil.lookup_links = { Spokeo: "https://www.spokeo.com/x" };
  evil.assignment.evidence_url = "https://evil.example/"; evil.findings.push({ level: "flag", code: "owner", title: "x".repeat(900), detail: "y".repeat(5000) }); evil.owner = { name: "Jane Doe" };
  const re = parseCaseFile(file({ phone: evil })).entry.results.phone;
  ok(!JSON.stringify(re).match(/evil\.example|spokeo|Jane Doe/i) && re.search_links.length === 5 && re.findings[1].title.length === 120 && re.findings[1].detail.length === 400, "a case file's phone answer is bounded: unknown fields, foreign links and long text are dropped");
  ok(re.assignment.evidence_url === "https://localcallingguide.com/lca_prefix.php?npa=202&nxx=456", "and its evidence link is rebuilt, not read");
  const old = parseCaseFile(file({ phone: fx.old_keyed }));
  ok(old.ok && old.entry.results.phone.legacy === true && !JSON.stringify(old.entry.results.phone).match(BROKERS), "an old case file opens without its people-search links");
  ok(parseCaseFile(file({ phone: "x", hash: { found: false } })).entry.results.phone === undefined, "a phone field that is not an answer is dropped");
  ok(detect(T) === "phone" && parseCaseFile(JSON.stringify({ ...JSON.parse(file({ phone: fx.us })), type: undefined })).entry.kind === "phone", "a case file with no type is still read as a phone case");
}

// ---- wording rules ----------------------------------------------------------------------------------
{
  const src = ["phone.js"].map((f) => fs.readFileSync(new URL(`../../static/v2/js/${f}`, import.meta.url), "utf8")).join("\n");
  const EM = String.fromCharCode(0x2014);
  ok(!src.includes(EM) && !JSON.stringify(fx).includes(EM), "no em dashes in the copy or in what the server says");
  const inv = fs.readFileSync(new URL("../../static/v2/js/investigate.js", import.meta.url), "utf8");
  ok(!/links only without a key/.test(inv) && !/Phone lookup \(links only\)/.test(inv) && /desc: PHONE_SOURCE_DESC/.test(inv), "the source list no longer says links only");
  ok(P.PHONE_SOURCE_DESC === "validity, country, line type and where the number range is assigned, from open numbering data; your NumLookup key adds the current carrier", "the source is described truthfully");
  const all = Object.keys(fx).filter((k) => k !== "failed").map((k) => text(brief(k)) + JSON.stringify(ev(k).facts) + JSON.stringify(ev(k).items.map((i) => [i.what, i.meta]))).join("\n");
  ok(!/\b(owner is|owned by|belongs to [A-Z]|lives|home address|registered to [A-Z])/i.test(all), "nothing asserts who has the number");
}

console.log(`${n - bad}/${n} phone checks passed`);
process.exit(bad ? 1 : 0);
