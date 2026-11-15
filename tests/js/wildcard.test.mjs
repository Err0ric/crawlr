// Wildcard DNS in Recon: a zone that answers for every name must not fill the page with
// names the wordlist guessed. One row, one graph node, one brief line, and counts of real names.
import { readFileSync } from "node:fs";
import { buildFindings, takeoverInput, takeoverForAi, TIERS, VIA_WILDCARD } from "../../static/v2/js/reconfindings.js";
import { reconBrief } from "../../static/v2/js/brief.js";
import { reconTiles, wildcardOf, wildcardText } from "../../static/v2/js/present.js";
import { reconTimeline } from "../../static/v2/js/timeline.js";
import { topologySubdomains, MAX_GRAPH_SUBDOMAINS } from "../../static/v2/js/graph.js";
import { parseCaseFile, buildCaseFile } from "../../static/v2/js/casefile.js";

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");
const T = "crawlr.lol";
const PIXIE = "pixie.porkbun.com", IPS = ["207.207.210.107", "207.207.210.229"];
const WORDS = ["pop", "imap", "webmail", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "relay", "api", "app"];
const GUESSED = WORDS.map((w) => `${w}.${T}`);
const run = (c, target = T) => { const f = buildFindings(c, target, "domain"); return { ...f, tiles: Object.fromEntries(reconTiles({ items: f.items, collected: c, type: "domain" }).map((t) => [t.id, t])), brief: text(reconBrief({ collected: c, items: f.items, failed: [], type: "domain", target, today: "2026-11-15" })) }; };
const inv = (f) => f.items.filter((i) => i.tier === "inventory");

// ---- what the page showed before the fix: every guess as a subdomain ---------------------
const before = { subdomains: { domain: T, total: GUESSED.length, checked: 92, ct_found: 0, ct_entries: [], ct_summary: null, subdomains: GUESSED.map((s) => ({ subdomain: s, ips: IPS, source: "DNS" })) } };
{
  const r = run(before);
  ok(inv(r).length === GUESSED.length && r.tiles.subdomains.value === GUESSED.length, "a case saved before the fix still renders, as it was saved");
  ok(wildcardOf(before).state === "" && !/ildcard/.test(r.brief) && !r.items.some((i) => /^wild:/.test(i.key)), "and nothing is claimed about a wildcard it never checked");
  ok(topologySubdomains(before, T).length === GUESSED.length && topologySubdomains(before, T).every((x) => x.type === "subdomain"), "its topology is unchanged too");
  ok(takeoverInput(before, T).hosts.length === GUESSED.length && takeoverInput(before, T).wildcard_cnames.length === 0, "and its takeover input");
}

// ---- the crawlr.lol shape after the fix ----------------------------------------------------
const wildcard = { state: "yes", name: `*.${T}`, cnames: [PIXIE], ips: IPS, probes: 3, matched: 3, failed: 0, suppressed: 92, suppressed_names: GUESSED, parents: [],
  provider: { name: "Porkbun", kind: "parking or forwarding service", basis: "cname" }, service: "", target_state: "resolves", attest_failed: [], note: "x" };
const finding = { level: "info", title: `Wildcard DNS: any name under ${T} resolves to ${PIXIE}`, detail: "So a name that resolves is not proof a host exists. 92 guessed names were left out because they only matched the wildcard." };
const after = { subdomains: { domain: T, total: 0, checked: 92, ct_found: 0, ct_entries: [], ct_summary: null, subdomains: [], wildcard, findings: [finding] } };
{
  const r = run(after);
  const rows = inv(r);
  ok(rows.length === 1 && rows[0].what === `*.${T}` && rows[0].key === `wild:*.${T}` && !rows[0].url, "the wildcard is one row, and it is not a link to a host");
  ok(rows[0].meta === `Wildcard DNS: any name under ${T} resolves to ${PIXIE} (Porkbun, a third-party parking or forwarding service). So a name that resolves is not proof a host exists. 92 guessed names were left out because they only matched the wildcard. Addresses: ${IPS.join(", ")}.`, "the row says what it resolves to, why it matters and how many guesses were left out");
  ok(!r.items.some((i) => GUESSED.includes(i.what)), "no guessed name is a row");
  ok(!r.items.some((i) => i.tier === "flag"), "a wildcard is a configuration fact, not a flag");
  ok(r.tiles.subdomains.value === 0 && r.tiles.subdomains.state === "zero" && r.tiles.subdomains.sub === "wildcard DNS: 92 guesses left out", "the Subdomains tile counts real names only, and says why it is zero");
  ok(r.tiles.flags.value === 0, "the Flags tile is not inflated");
  ok(r.brief.includes(`info: Wildcard DNS: any name under ${T} resolves to ${PIXIE} (Porkbun, a third-party parking or forwarding service). So a name that resolves is not proof a host exists. 92 guessed names were left out because they only matched the wildcard.`), "the brief has one line for the wildcard");
  ok((r.brief.match(/Wildcard DNS/g) || []).length === 1, "and only one");
  ok(r.facts.find((f) => f.k === "Wildcard DNS")?.v === `*.${T} resolves to ${PIXIE} (Porkbun)`, "What we know names the wildcard");
  ok(!(r.brief + rows[0].meta + wildcardText(wildcardOf(after))).includes(String.fromCharCode(0x2014)), "no em dash in the copy");
  ok(TIERS.find((t) => t.id === "inventory").title === "Subdomains", "the row sits in the Subdomains group");
}

// ---- topology: one node for the wildcard --------------------------------------------------
{
  const g = topologySubdomains(after, T);
  ok(g.length === 1 && g[0].type === "wildcard" && g[0].label === `*.${T}` && g[0].id === `wild_*.${T}`, "the graph has one wildcard node");
  ok(g[0].cnames.join() === PIXIE && g[0].ips.join() === IPS.join() && /resolves to pixie\.porkbun\.com\. 92 guessed names left out/.test(g[0].note), "with its target, its addresses and the count");
  const real = { subdomains: { ...after.subdomains, subdomains: [{ subdomain: `api.${T}`, ips: ["198.51.100.7"], source: "DNS" }, { subdomain: `www.${T}`, ips: IPS, source: "CT", via_wildcard: true }] } };
  const g2 = topologySubdomains(real, T);
  ok(g2.map((x) => `${x.type}:${x.label}`).join() === `wildcard:*.${T},subdomain:api.${T},subdomain:www.${T}`, "real names follow the wildcard node");
  ok(g2[1].ips.join() === "198.51.100.7" && g2[2].ips.length === 0 && g2[2].note === "resolves through the wildcard", "a name that resolves through the wildcard does not repeat the wildcard's addresses");
  ok(g2.filter((x) => x.type === "wildcard").length === 1, "still exactly one wildcard node");
  const many = { subdomains: { ...after.subdomains, subdomains: Array.from({ length: 60 }, (_, i) => ({ subdomain: `h${i}.${T}`, ips: ["198.51.100.7"], source: "CT" })) } };
  ok(topologySubdomains(many, T).length === MAX_GRAPH_SUBDOMAINS + 1, "the cap on drawn names does not drop the wildcard node");
  ok(topologySubdomains({}, T).length === 0 && topologySubdomains({ subdomains: { error: "x", wildcard, subdomains: [{ subdomain: "a.b" }] } }, T).length === 0, "nothing is drawn for a failed check");
}

// ---- real and attested names in a wildcard zone ---------------------------------------------
{
  const c = { subdomains: { ...after.subdomains, subdomains: [
    { subdomain: `api.${T}`, ips: ["198.51.100.7"], source: "DNS" },
    { subdomain: `www.${T}`, ips: IPS, source: "DNS+CT", via_wildcard: true },
    { subdomain: `mail.${T}`, ips: IPS, source: "DNS", via_wildcard: true, attested: ["MX"] }], wildcard: { ...wildcard, suppressed: 89, suppressed_names: GUESSED.filter((x) => x !== `api.${T}`) } },
    harvest: { hosts: [`pop.${T}`, `docs.${T}`, `www.${T}`], host_sources: { [`pop.${T}`]: ["RapidDNS"], [`docs.${T}`]: ["URLScan"] } } };
  const r = run(c);
  const row = (k) => r.items.find((i) => i.key === k);
  ok(row(`sub:api.${T}`).meta === "198.51.100.7 · DNS", "a host with its own address is listed as before");
  ok(row(`sub:www.${T}`).meta === `${IPS.join(", ")} · DNS+CT · ${VIA_WILDCARD}`, "a certified name that resolves through the wildcard is kept, keeps its source, and is marked");
  ok(row(`sub:mail.${T}`).meta.endsWith(`${VIA_WILDCARD} · named in the domain's MX record`), "a name the MX record points at is kept and says why");
  ok(row(`sub:pop.${T}`)?.source === "Passive discovery" && row(`sub:pop.${T}`).meta === `RapidDNS · ${VIA_WILDCARD}`, "a guessed name a passive source attests is never dropped: it keeps its source and is marked");
  ok(row(`sub:docs.${T}`).meta === "URLScan", "a passive host the wordlist never guessed is unaffected");
  ok(r.tiles.subdomains.value === 5 && inv(r).length === 6, "the tile counts the five names, not the wildcard row");
  // takeover: only names that exist on their own are asked about
  const tk = takeoverInput(c, T);
  ok(tk.hosts.join() === `api.${T},docs.${T}` && tk.wildcard_cnames.join() === PIXIE, "the takeover input leaves out every name that only resolves through the wildcard");
  ok(takeoverInput(after, T).hosts.length === 0, "and is empty when the wildcard is all there is");
  ok(JSON.stringify(takeoverInput({ subdomains: { subdomains: [{ subdomain: "a.example.com", ips: [], source: "CT" }] }, harvest: { hosts: ["a.example.com", "b.example.com"] } }, "example.com")) === JSON.stringify({ hosts: ["a.example.com", "b.example.com"], wildcard_cnames: [] }), "without a wildcard the takeover input is what it always was");
}

// ---- a dangling wildcard target is one flag -------------------------------------------------
{
  const flag = { level: "flag", title: "Wildcard DNS points at gone-app.herokuapp.com (Heroku), which no longer resolves", detail: "Every name under example.com follows this record. From DNS only: verify by hand before reporting a takeover." };
  const c = { subdomains: { domain: "example.com", subdomains: [], wildcard: { state: "yes", cnames: ["gone-app.herokuapp.com"], ips: [], suppressed: 0, suppressed_names: [], service: "Heroku", target_state: "absent" }, findings: [{ level: "info", title: "Wildcard DNS: any name under example.com resolves to gone-app.herokuapp.com", detail: "x" }, flag] },
    takeover: { found: true, checked: 0, dangling: 0, unknown: 0, unchecked: [], via_wildcard: 0, candidates: [] } };
  const r = run(c, "example.com");
  const flags = r.items.filter((i) => i.tier === "flag");
  ok(flags.length === 1 && flags[0].what === flag.title && flags[0].source === "Subdomains" && r.tiles.flags.value === 1, "a dangling wildcard target is exactly one flag, about the wildcard");
  ok(!r.items.some((i) => /^tko:/.test(i.key)) && takeoverForAi(c, "example.com").candidates.length === 0, "and no takeover candidate per name");
  ok(/No guessed name was left out\./.test(r.brief), "zero left out is said plainly");
}

// ---- unknown, no wildcard, second level ------------------------------------------------------
{
  const unknown = { subdomains: { ...before.subdomains, wildcard: { state: "unknown", cnames: [], ips: [], probes: 3, matched: 0, failed: 3, suppressed: 0, suppressed_names: [] }, findings: [{ level: "info", title: `Wildcard DNS could not be checked for ${T}`, detail: "x" }] } };
  const r = run(unknown);
  ok(inv(r).length === GUESSED.length + 1 && r.tiles.subdomains.value === GUESSED.length, "probes that failed: nothing is left out");
  ok(/info: Wildcard DNS could not be checked: the test lookups failed, so a guessed name that resolves may not be a real host\./.test(r.brief) && r.tiles.subdomains.sub === "wildcard DNS not checked: guesses may not be hosts", "and the page says the check is unknown, not that there is no wildcard");
  ok(topologySubdomains(unknown, T).every((x) => x.type === "subdomain"), "an unknown wildcard draws no wildcard node");

  const none = { subdomains: { ...before.subdomains, wildcard: { state: "no", cnames: [], ips: [], probes: 3, matched: 0, suppressed: 0, suppressed_names: [], parents: [], note: "" }, findings: [] } };
  const a = run(none), b = run(before);
  ok(JSON.stringify(a.items) === JSON.stringify(b.items) && a.brief === b.brief && JSON.stringify(a.tiles) === JSON.stringify(b.tiles), "a zone without a wildcard reads exactly as before");

  const second = { subdomains: { domain: "example.com", subdomains: ["a", "b", "c"].map((x) => ({ subdomain: `${x}.dev.example.com`, ips: ["203.0.113.9"], source: "CT", via_wildcard: true })),
    wildcard: { state: "no", cnames: [], ips: [], suppressed: 0, suppressed_names: [], parents: [{ parent: "dev.example.com", name: "*.dev.example.com", cnames: [], ips: ["203.0.113.9"] }] } } };
  const s = run(second, "example.com");
  ok(inv(s)[0].what === "*.dev.example.com" && /any name under dev\.example\.com resolves to 203\.0\.113\.9/.test(inv(s)[0].meta) && s.tiles.subdomains.value === 3, "a wildcard one level down is one row, and its certified names stay");
  ok(/Wildcard DNS one level down: any name under dev\.example\.com/.test(s.brief), "and one brief line");
  const g = topologySubdomains(second, "example.com");
  ok(g[0].type === "wildcard" && g[0].label === "*.dev.example.com" && g.filter((x) => x.type === "wildcard").length === 1 && g.slice(1).every((x) => x.ips.length === 0), "and one graph node");
}

// ---- outside data: a case file, or junk -------------------------------------------------------
{
  const junk = [{ wildcard: "yes" }, { wildcard: { state: "maybe" } }, { wildcard: { state: "yes", cnames: "x", ips: [1, null, { a: 1 }], suppressed: "lots", suppressed_names: [3, "<img src=x>"], parents: "no", provider: "p" } }, { wildcard: null }, { error: "x", wildcard }];
  for (const j of junk) {
    let threw = false;
    try { run({ subdomains: { subdomains: [], ...j } }); topologySubdomains({ subdomains: { subdomains: [], ...j } }, T); takeoverInput({ subdomains: j }, T); } catch { threw = true; }
    ok(!threw, `malformed wildcard data never throws (${JSON.stringify(j).slice(0, 40)})`);
  }
  ok(wildcardOf({ subdomains: { error: "timeout", wildcard } }).state === "", "a failed subdomain check says nothing about a wildcard");
  const w = wildcardOf({ subdomains: { domain: "Example.COM.", wildcard: { state: "yes", cnames: ["LB.Example.NET."], ips: ["192.0.2.1"], suppressed_names: ["A.example.com"] } } });
  ok(w.name === "*.example.com" && w.cnames[0] === "lb.example.net" && w.suppressed === 1 && w.suppressedNames[0] === "a.example.com", "names are normalised, and a missing count falls back to the list");
  // a case file round trip keeps the wildcard, and an old file without it opens
  const file = (collected) => parseCaseFile(JSON.stringify(buildCaseFile({ mode: "recon", target: T, type: "domain", ran: Date.parse("2026-11-15T10:00:00Z"), collected, ai: null, deep: null, notes: "", purpose: "" })));
  const opened = file(after), old = file(before);
  ok(opened.ok && wildcardOf(opened.entry.results, T).state === "yes" && run(opened.entry.results).tiles.subdomains.value === 0, "a case file keeps the wildcard through parseCaseFile");
  ok(old.ok && run(old.entry.results).tiles.subdomains.value === GUESSED.length, "a case file from before the fix still opens");
}

// ---- the timeline reads certificate dates, never guessed names ----------------------------------
{
  const c = { subdomains: { ...after.subdomains, ct_summary: { first_issued: "2026-10-01", first_seen: [{ name: T, date: "2026-10-01" }] } } };
  const names = reconTimeline(c, T, "2026-11-15").events.map((e) => `${e.title} ${e.detail}`).join("\n");
  ok(/First certificate for crawlr\.lol/.test(names) && !GUESSED.some((g) => names.includes(g)), "the timeline has no guessed name");
}

// ---- the page code uses the shared helpers -------------------------------------------------------
{
  const src = readFileSync(new URL("../../static/v2/js/recon.js", import.meta.url), "utf8");
  ok(/takeoverInput\(state\.collected, target\)/.test(src) && /wildcard_cnames/.test(src), "the run sends the takeover check the filtered hosts and the wildcard targets");
  ok(/Guessed names left out/.test(src) && /wildcardOf\(\{ subdomains: d \}/.test(src), "the By source card shows the wildcard state and the names left out");
  const g = readFileSync(new URL("../../static/v2/js/graph.js", import.meta.url), "utf8");
  ok(/const subNodes = topologySubdomains\(d, target\)/.test(g), "the graph draws the rows topologySubdomains returns");
}

console.log(bad ? `${bad} of ${n} wildcard checks FAILED` : `${n}/${n} wildcard checks passed`);
process.exit(bad ? 1 : 0);
