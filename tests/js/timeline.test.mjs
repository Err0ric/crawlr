// The recon timeline is built from dated facts only, so every row can be checked exactly.
import { toDay, span, daysBetween, reconTimeline, domainAgeDays } from "../../static/v2/js/timeline.js";
import { reconBrief } from "../../static/v2/js/brief.js";

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const TODAY = "2026-11-14";

// ---- dates ------------------------------------------------------------------
ok(toDay("1995-08-14 04:00:00") === "1995-08-14", "WHOIS date with a time");
ok(toDay("2026-09-26T22:10:00+00:00") === "2026-09-26", "ISO date");
ok(toDay("Sep 26 22:10:00 2026 GMT") === "2026-09-26", "TLS date");
ok(toDay("Jan  5 00:00:00 2027 GMT") === "2027-01-05", "TLS date with a padded day");
ok(toDay("20140102030405") === "2014-01-02", "Wayback timestamp");
ok(toDay(["2001-02-03", "2009-01-01"]) === "2001-02-03", "first of a list");
ok(toDay("") === "" && toDay(null) === "" && toDay("not a date") === "" && toDay("0000-00-00") === "" && toDay("None") === "", "junk gives no date");
ok(daysBetween("2026-11-14", "2026-11-24") === 10 && daysBetween("2026-11-14", "2026-11-04") === -10, "day arithmetic");
ok(span(0) === "today" && span(-1) === "1 day ago" && span(12) === "in 12 days" && span(-90) === "3 months ago" && span(-365 * 31) === "31 years ago", "spans read naturally");

// ---- a full domain case -----------------------------------------------------
const full = {
  whois: { found: true, registrar: "Example Registrar", creation_date: "1995-08-14 04:00:00", updated_date: "2026-08-14 07:01:38", expiration_date: "2027-08-13 04:00:00" },
  ssl: { found: true, issuer: "Example CA", not_before: "Sep 26 22:10:00 2026 GMT", not_after: "Dec 25 22:09:59 2026 GMT" },
  subdomains: { ct_entries: [{ subdomain: "ignored.example.com", date: "2030-01-01" }], ct_summary: { first_issued: "2013-03-01", first_seen: [{ name: "example.com", date: "2013-03-01" }, { name: "a.example.com", date: "2020-05-05" }, { name: "b.example.com", date: "2020-05-05" }, { name: "shop.example.com", date: "2024-02-02" }] } },
  wayback: { found: true, snapshot_history: [{ date: "2002-01-20", url: "https://web.archive.org/web/20020120000000/example.com" }, { date: "1998-12-02", url: "https://web.archive.org/web/19981202000000/example.com" }], most_recent_snapshot: { timestamp: "20261101120000", url: "https://web.archive.org/web/20261101120000/example.com" } },
  wellknown: { found: true, security_txt: { expires: ["2027-01-01T00:00:00Z"] } },
};
{
  const { events, today } = reconTimeline(full, "example.com", TODAY);
  const t = events.map((e) => `${e.date} ${e.title}`);
  ok(today === TODAY, "reports the day it was built for");
  ok(t[0] === "1995-08-14 Domain registered", "oldest fact first");
  ok(t.join("|") === [...t].sort((a, b) => a.slice(0, 10).localeCompare(b.slice(0, 10))).join("|"), "rows are in date order");
  ok(t.includes("1998-12-02 Earliest archived copy found") && !t.includes("2002-01-20 Earliest archived copy found"), "earliest archive copy is the oldest in the sample, whatever order it arrived in");
  ok(t.includes("2013-03-01 First certificate in public logs") && t.includes("2013-03-01 First certificate for example.com"), "certificate logging start and the first name");
  const pair = events.find((e) => e.title === "First certificates for 2 names");
  ok(pair && pair.date === "2020-05-05" && pair.detail === "a.example.com, b.example.com", "names first certified on one day share a row");
  ok(!t.some((x) => /ignored/.test(x)), "the server's first-seen list wins over the capped entry list");
  ok(t.includes("2026-09-26 Current TLS certificate issued") && t.includes("2026-12-25 Current TLS certificate expires"), "TLS dates");
  const fut = events.filter((e) => e.future).map((e) => e.title);
  ok(fut.join("|") === "Current TLS certificate expires|security.txt expires|Domain registration expires", "future rows are flagged and ordered");
  ok(events.find((e) => e.title === "Domain registered").when === "31 years ago" && events.find((e) => e.title === "Current TLS certificate expires").when === "in 41 days", "each row says how long ago or how soon");
  ok(events.find((e) => e.title === "Latest archived copy").url.startsWith("https://web.archive.org/"), "archive rows link to the snapshot");
  ok(domainAgeDays(full, TODAY) > 11000, "domain age in days");
}

// ---- failed sources leave gaps, never dates ----------------------------------
{
  const c = { whois: { found: false, error: "timed out", error_code: "timeout", creation_date: "2026-11-01" }, ssl: { error: "refused", error_code: "connect", not_after: "2026-12-01" }, subdomains: { error: "crt.sh is down" }, wayback: { found: false } };
  ok(reconTimeline(c, "example.com", TODAY).events.length === 0, "nothing is dated from a failed source");
  ok(domainAgeDays(c, TODAY) === null, "a failed WHOIS is not a new domain");
  ok(reconTimeline({}, "example.com", TODAY).events.length === 0, "an empty case has an empty timeline");
}
{
  // expired things say so
  const { events } = reconTimeline({ whois: { found: true, creation_date: "2020-01-01", expiration_date: "2026-01-01" }, ssl: { found: true, not_before: "2025-01-01", not_after: "2025-04-01" } }, "example.com", TODAY);
  ok(events.some((e) => e.title === "Domain registration expired" && !e.future) && events.some((e) => e.title === "Current TLS certificate expired"), "past expiries are worded as expired");
}
{
  // old saved cases: use the entry list only when it was not cut short
  const small = reconTimeline({ subdomains: { ct_entries: [{ subdomain: "x.example.com", date: "2021-01-01" }, { subdomain: "x.example.com", date: "2019-06-06" }], ct_summary: { first_issued: "2019-06-06" } } }, "example.com", TODAY).events;
  ok(small.some((e) => e.title === "First certificate for x.example.com" && e.date === "2019-06-06"), "falls back to the entry list for older saved cases");
  const cut = reconTimeline({ subdomains: { ct_entries: Array.from({ length: 400 }, (_, i) => ({ subdomain: `h${i}.example.com`, date: "2025-01-01" })), ct_summary: { first_issued: "2015-01-01" } } }, "example.com", TODAY).events;
  ok(cut.length === 1 && cut[0].title === "First certificate in public logs", "does not guess first-seen dates from a truncated list");
}
{
  const { events } = reconTimeline({ asn_detail: { found: true, date_registered: "2000-03-30", rir: "ARIN" } }, "AS15169", TODAY);
  ok(events.length === 1 && events[0].title === "Network number registered" && events[0].detail === "Registry: ARIN", "ASN cases get their registration date");
}

// ---- the brief uses the registration age ---------------------------------------
{
  const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");
  const young = reconBrief({ type: "domain", target: "new.example", failed: [], items: [], today: TODAY, collected: { whois: { found: true, creation_date: "2026-11-02" } } });
  ok(/flag: Registered 12 days ago/.test(text(young)), "a domain under 90 days old is called out");
  const old = reconBrief({ type: "domain", target: "example.com", failed: [], items: [], today: TODAY, collected: full });
  ok(!/Registered \d+ days? ago/.test(text(old)), "an old domain is not");
  ok(old.actions.some((a) => a.tab === "timeline"), "offers the timeline when there is one");
  const unknown = reconBrief({ type: "domain", target: "example.com", failed: [{ name: "WHOIS" }], items: [], today: TODAY, collected: { whois: { error: "timeout", error_code: "timeout" } } });
  ok(!/Registered/.test(text(unknown)), "no age claim when WHOIS failed");
}

console.log(`${n - bad}/${n} timeline checks passed`);
process.exit(bad ? 1 : 0);
