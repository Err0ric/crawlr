// Case files are outside data. These checks pin what is accepted, what is dropped and what is refused.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
globalThis.location = { origin: "https://crawlr.lol" };
const { buildCaseFile, parseCaseFile, MAX_CASE_BYTES } = await import("../../static/v2/js/casefile.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const file = (o) => JSON.stringify(o);
const recon = () => buildCaseFile({ mode: "recon", target: "example.com", type: "domain", ran: 1700000000000, collected: { dns: { records: { A: ["93.184.216.34"] } }, whois: { found: true }, ipAsn: { "93.184.216.34": { asn: "AS15133" } } }, ai: { summary: "# Report", short_summary: ["one"], model: "m" }, deep: null, notes: "my notes", purpose: "Authorized test for the owner" });

// ---- "This is me" never arrives in a file ---------------------------------------
{
  const inv = (collected) => parseCaseFile(file(buildCaseFile({ mode: "investigate", target: "samexample", type: "username", ran: 1700000000000, collected })));
  const r = inv({ github: { found: true, profile_url: "https://github.com/samexample" }, selfAudit: { on: true, at: 1700000000000 } });
  ok(r.ok && !("selfAudit" in r.entry.results) && r.entry.results.github.found === true, "a case file's selfAudit is dropped: the statement is the person's at the browser");
  ok(!inv({ selfAudit: { on: true, at: 1 } }).ok, "and it is not a result");
  const rc = parseCaseFile(file({ ...recon(), collected: { ...recon().collected, selfAudit: { on: true, at: 1 } } }));
  ok(rc.ok && !("selfAudit" in rc.entry.results), "a recon case never carries one either");
}

// ---- round trip --------------------------------------------------------------
{
  const r = parseCaseFile(file(recon()));
  ok(r.ok, "a recon case file opens");
  const e = r.entry;
  ok(e.type === "RECON" && e.kind === "domain" && e.target === "example.com" && e.v2 === true, "it becomes a recon History entry");
  ok(e.timestamp === 1700000000000 && typeof e.imported === "number", "keeps when it was collected and marks it as imported");
  ok(e.notes === "my notes" && e.purpose === "Authorized test for the owner", "notes and purpose travel with it");
  ok(e.results.dns.records.A[0] === "93.184.216.34" && e.results.ipAsn["93.184.216.34"].asn === "AS15133", "results are kept as they were");
  ok(e.ai.summary === "# Report" && e.aiSummary === "# Report" && e.deep === null, "the AI report is kept");
  ok(/^\d+_[a-z0-9]+$/.test(e.id), "gets a fresh id, never the file's");
}
{
  const f = buildCaseFile({ mode: "investigate", target: "jdoe", type: "username", ran: 1700000000000, collected: { github: { found: true }, nameSearch: "J Doe", reverseImage: "https://example.org/a.png", profileScrape: { results: [] } }, ai: { summary: "x", profile: { name: "J" }, ai_source: "pasted", tokens: 12, evil: "<script>" }, deep: { summary: "deep" } });
  const r = parseCaseFile(file(f));
  ok(r.ok && r.entry.type === "INVESTIGATE" && r.entry.kind === "username", "an investigate case file opens");
  ok(r.entry.results.nameSearch === "J Doe" && r.entry.results.reverseImage === "https://example.org/a.png", "the two text values are kept");
  ok(r.entry.deepDive.summary === "deep" && !("deep" in r.entry), "the deep report lands where Investigate reads it");
  ok(r.entry.ai.profile.name === "J" && r.entry.ai.ai_source === "pasted" && r.entry.ai.tokens === 12 && !("evil" in r.entry.ai), "AI reports keep known fields only");
}
{
  // a name that looks like a domain can still be an Investigate case when the file says so
  const r = parseCaseFile(file({ ...buildCaseFile({ mode: "investigate", target: "john.dev", type: "username", collected: { sherlock: { results: [] } } }) }));
  ok(r.ok && r.entry.kind === "username", "the stated Investigate type is respected");
}

// ---- refused ------------------------------------------------------------------
const refuse = (text, re, name) => { const r = parseCaseFile(text); ok(!r.ok && re.test(r.error), name); };
refuse("", /empty/, "empty file");
refuse("{not json", /not valid JSON/, "broken JSON");
refuse("[1,2]", /not a CrawlR case/, "an array");
refuse(file({ target: "example.com", collected: {} }), /not a CrawlR case/, "JSON that is not a case file");
refuse(file({ ...recon(), crawlr_case: 2 }), /newer version/, "a newer format");
refuse(file({ ...recon(), target: "" }), /no usable target/, "no target");
refuse(file({ ...recon(), target: "a".repeat(300) }), /no usable target/, "an overlong target");
refuse(file({ ...recon(), target: "exa\nmple.com" }), /no usable target/, "control characters in the target");
refuse(file({ ...recon(), target: { toString: 1 } }), /no usable target/, "a target that is not text");
refuse(file({ ...recon(), mode: "other" }), /which workbench/, "an unknown workbench");
refuse(file({ ...recon(), target: "jdoe" }), /not a domain, IP address or ASN/, "a username in a recon file");
refuse(file({ ...recon(), mode: "investigate", type: "domain", target: "example.com" }), /not a username/, "a domain in an investigate file");
refuse(file({ ...recon(), collected: [] }), /no results/, "results that are a list");
refuse(file({ ...recon(), collected: {} }), /no results/, "no results at all");
refuse(file({ ...recon(), collected: Object.fromEntries(Array.from({ length: 61 }, (_, i) => [`s${i}`, {}])) }), /more sources/, "too many sources");
refuse(" ".repeat(MAX_CASE_BYTES) + file(recon()), /too large/, "an oversized file");

// ---- cleaned, not trusted --------------------------------------------------------
{
  const raw = `{"crawlr_case":1,"mode":"recon","target":" example.com ","ran":"soon","notes":{"a":1},"purpose":"  two\\n  lines  ","collected":{"dns":{"ok":true},"__proto__":{"polluted":true},"constructor":{"x":1},"bad key":{},"whois":"a string","9lives":{},"ssl":null},"ai":{"summary":""},"deep":"nope","id":"evil","imported":1}`;
  const r = parseCaseFile(raw);
  ok(r.ok, "a messy file still opens");
  const e = r.entry;
  ok(e.target === "example.com", "target is trimmed");
  ok(JSON.stringify(Object.keys(e.results).sort()) === '["dns","ssl"]', "only well-named object results survive");
  ok(({}).polluted === undefined && !Object.prototype.hasOwnProperty.call(e.results, "__proto__"), "no prototype pollution");
  ok(e.notes === "" && e.purpose === "two lines", "non-text notes are dropped and the purpose is one line");
  ok(e.ai === null && e.deep === null && e.aiSummary === null, "empty or malformed AI reports are dropped");
  ok(e.id !== "evil" && e.imported !== 1 && Math.abs(e.timestamp - Date.now()) < 5000, "id, import time and a bad date come from this browser");
}
{
  const r = parseCaseFile(file({ ...recon(), notes: "n".repeat(30000), purpose: "p".repeat(500), ran: Date.now() + 10 * 86400000 }));
  ok(r.ok && r.entry.notes.length === 20000 && r.entry.purpose.length === 300, "long text is clipped");
  ok(r.entry.timestamp <= Date.now(), "a date in the future is not believed");
}

console.log(`${n - bad}/${n} case file checks passed`);
process.exit(bad ? 1 : 0);
