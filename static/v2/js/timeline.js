// Timeline for a recon case: every dated fact the sources already returned, in order.
// No new collection and no model. Infrastructure targets only (domain, IP, ASN): a dated
// history of a person's accounts would be a profile, and is deliberately not built.
// Kept free of DOM code so the rules can be tested with plain node.

import { sealLink, evidenceUrl, isDomain } from "./links.js";

const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const pad = (n) => String(n).padStart(2, "0");
const valid = (y, m, d) => y >= 1970 && y <= 2200 && m >= 1 && m <= 12 && d >= 1 && d <= 31;

// Sources disagree on date formats. Read the calendar day without going through local time,
// so a date never shifts by one depending on where the browser is.
export function toDay(v) {
  const s = String(Array.isArray(v) ? v[0] ?? "" : v ?? "").trim();
  if (!s) return "";
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);                                    // 2026-09-26, ISO, "2026-09-26 22:10:00"
  if (m) return valid(+m[1], +m[2], +m[3]) ? `${m[1]}-${m[2]}-${m[3]}` : "";
  m = s.match(/^(\d{4})(\d{2})(\d{2})(\d{6})?$/);                                 // Wayback: 20260926221000
  if (m) return valid(+m[1], +m[2], +m[3]) ? `${m[1]}-${m[2]}-${m[3]}` : "";
  m = s.match(/^([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})/);                   // TLS: "Sep 26 22:10:00 2026 GMT"
  if (m && MONTHS[m[1].toLowerCase()]) return valid(+m[3], MONTHS[m[1].toLowerCase()], +m[2]) ? `${m[3]}-${pad(MONTHS[m[1].toLowerCase()])}-${pad(+m[2])}` : "";
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "";
}

const DAY = 86400000;
export const daysBetween = (a, b) => Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / DAY);
// A source that failed says nothing. "not_found" is an answer, with no dates in it.
const usable = (d) => !!d && typeof d === "object" && !((d.error_code || d.error) && d.error_code !== "not_found");

// How long ago, or how far ahead, in the largest unit that reads naturally.
export function span(days) {
  const n = Math.abs(days);
  if (n === 0) return "today";
  const unit = n < 60 ? [n, "day"] : n < 730 ? [Math.round(n / 30.44), "month"] : [Math.round(n / 365.25), "year"];
  const text = `${unit[0]} ${unit[1]}${unit[0] === 1 ? "" : "s"}`;
  return days < 0 ? `${text} ago` : `in ${text}`;
}

// Returns { events, today }. Each event: { date, title, detail, source, url, link_kind, future }.
// url is where the date can be checked: the RDAP record, the certificate logs, the snapshot.
export function reconTimeline(c, target, today = new Date().toISOString().slice(0, 10)) {
  const events = [];
  const add = (raw, title, source, detail = "", url = "") => {
    const date = toDay(raw);
    if (date) events.push({ date, title, detail, source, url, future: date > today });
  };
  const domain = isDomain(target) ? String(target).trim().toLowerCase() : "";
  const rdap = evidenceUrl.rdap(domain), crt = evidenceUrl.crtsh(domain);

  const wh = c.whois;
  if (usable(wh) && wh.found !== false) {
    add(wh.creation_date, "Domain registered", "WHOIS", wh.registrar ? `Current registrar: ${wh.registrar}` : "", rdap);
    add(wh.updated_date, "Registration record last changed", "WHOIS", "A renewal, a transfer or a change of name servers. WHOIS does not say which.", rdap);
    add(wh.expiration_date, toDay(wh.expiration_date) > today ? "Domain registration expires" : "Domain registration expired", "WHOIS", "", rdap);
  }

  // Certificate transparency: the first time each name was certified says when it appeared.
  const sub = c.subdomains;
  if (usable(sub)) {
    // The server works this out over every logged certificate. Cases saved before it did
    // carry only the most recent entries, which is enough when the list was not cut short.
    const first = new Map();
    const rows = sub.ct_summary?.first_seen || ((sub.ct_entries || []).length < 400 ? (sub.ct_entries || []).map((e) => ({ name: e.subdomain, date: e.date })) : []);
    for (const e of rows) {
      const d = toDay(e.date), name = String(e.name || "").toLowerCase();
      if (!d || !name) continue;
      if (!first.has(name) || d < first.get(name)) first.set(name, d);
    }
    const byDay = new Map();
    for (const [name, d] of first) { if (!byDay.has(d)) byDay.set(d, []); byDay.get(d).push(name); }
    const firstLogged = toDay(sub.ct_summary?.first_issued);
    if (firstLogged) add(firstLogged, "First certificate in public logs", "Certificate logs", "The earliest certificate logged for this domain or a subdomain. Logging only became universal around 2018, so older sites can predate it.", crt);
    for (const [d, names] of byDay) {
      names.sort();
      const shown = names.slice(0, 4).join(", ") + (names.length > 4 ? ` and ${names.length - 4} more` : "");
      add(d, names.length === 1 ? `First certificate for ${names[0]}` : `First certificates for ${names.length} names`, "Certificate logs", names.length === 1 ? "" : shown, names.length === 1 ? evidenceUrl.crtsh(names[0]) || crt : crt);
    }
  }

  const ssl = c.ssl;
  if (usable(ssl) && ssl.found) {
    add(ssl.not_before, "Current TLS certificate issued", "TLS certificate", ssl.issuer ? `Issued by ${ssl.issuer}` : "", crt);
    add(ssl.not_after, toDay(ssl.not_after) > today ? "Current TLS certificate expires" : "Current TLS certificate expired", "TLS certificate", "", crt);
  }

  const wb = c.wayback;
  if (usable(wb) && wb.found) {
    const hist = (wb.snapshot_history || []).filter((s) => toDay(s?.date)).sort((a, b) => toDay(a.date).localeCompare(toDay(b.date)));
    if (hist.length) add(hist[0].date, "Earliest archived copy found", "Wayback Machine", "The oldest snapshot in the sample CrawlR fetched. The archive may hold older ones.", hist[0].url || evidenceUrl.wayback(domain));
    add(wb.most_recent_snapshot?.timestamp, "Latest archived copy", "Wayback Machine", "", wb.most_recent_snapshot?.url || evidenceUrl.wayback(domain));
  }

  const st = c.wellknown?.security_txt;
  if (usable(c.wellknown) && st) add([].concat(st.expires || [])[0], toDay([].concat(st.expires || [])[0]) > today ? "security.txt expires" : "security.txt expired", "Published files", "After this date the published security contact should be treated as stale.");

  const ad = c.asn_detail;
  if (usable(ad) && ad.found) add(ad.date_registered, "Network number registered", "ASN detail", ad.rir ? `Registry: ${ad.rir}` : "", evidenceUrl.asn(ad.asn || target));

  // Oldest first. On the same day, keep the order the facts were added in.
  const seen = new Set();
  const out = events.map((e, i) => ({ ...e, i })).sort((a, b) => a.date.localeCompare(b.date) || a.i - b.i)
    .filter((e) => { const k = `${e.date}|${e.title}`; if (seen.has(k)) return false; seen.add(k); return true; })
    .map(({ i, ...e }) => sealLink({ ...e, when: span(daysBetween(today, e.date)) }, { subjects: [target] }));
  return { events: out, today };
}

// Age of the registration in days, or null when WHOIS did not answer. A failed lookup is not "new".
export function domainAgeDays(c, today = new Date().toISOString().slice(0, 10)) {
  const wh = c.whois;
  if (!usable(wh) || wh.found === false) return null;
  const d = toDay(wh.creation_date);
  if (!d || d > today) return null;
  return daysBetween(d, today);
}
