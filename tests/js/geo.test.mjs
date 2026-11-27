// The coordinate converter (static/v2/js/geo.js) and the one map link (mapLink in links.js).
import fs from "node:fs";
const { parseCoords, coordForms, fmtDd, fmtDms, fmtDdm, validPosition } = await import("../../static/v2/js/geo.js");
const { mapLink, LINK_KINDS, parseUrl } = await import("../../static/v2/js/links.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const near = (a, b, eps = 1e-5) => Math.abs(a - b) < eps;
const reads = (text, lat, lon, format) => { const r = parseCoords(text); ok(r.ok && near(r.lat, lat) && near(r.lon, lon) && (!format || r.format === format), `reads ${JSON.stringify(text)}${r.ok ? "" : `: ${r.error}`}`); };
const refuses = (text, re) => { const r = parseCoords(text); ok(!r.ok && re.test(r.error), `refuses ${JSON.stringify(text)}${r.ok ? "" : `: ${r.error}`}`); };

// ---- decimal degrees ------------------------------------------------------------------------------
reads("48.85837, 2.294481", 48.85837, 2.294481, "dd");
reads("48.85837 2.294481", 48.85837, 2.294481, "dd");
reads("-33.856784, 151.215297", -33.856784, 151.215297, "dd");
reads("-33.856784 -70.5", -33.856784, -70.5, "dd");
reads("48.85837N 2.294481E", 48.85837, 2.294481, "dd");
reads("N 48.85837, W 2.294481", 48.85837, -2.294481, "dd");
reads("33.856784° S, 151.215297° E", -33.856784, 151.215297, "dd");
reads("2.294481E 48.85837N", 48.85837, 2.294481, "dd");       // longitude first, said by its letter
reads("0, 0", 0, 0, "dd");
reads("90, 180", 90, 180);
reads("48,85837; 2,294481".replace(/,(\d)/g, ".$1"), 48.85837, 2.294481);
// ---- degrees, minutes, seconds ------------------------------------------------------------------------
reads("48°51'30.13\"N 2°17'40.13\"E", 48.858369, 2.294481, "dms");
reads("48 51 30.13 N, 2 17 40.13 E", 48.858369, 2.294481, "dms");
reads("48° 51′ 30.13″ N 2° 17′ 40.13″ E", 48.858369, 2.294481, "dms");
reads("S 33°51'24.4\" E 151°12'55.1\"", -33.856778, 151.215306, "dms");
reads("48 51 30.13 2 17 40.13", 48.858369, 2.294481, "dms");
reads("-33 51 24.4, 151 12 55.1", -33.856778, 151.215306, "dms");
reads("48°51''N 2°17''E".replace(/''/g, "'"), 48.85, 2.283333, "ddm");
// ---- degrees and decimal minutes ----------------------------------------------------------------------
reads("48°51.5022'N 2°17.6689'E", 48.85837, 2.294482, "ddm");
reads("N 48 51.5022 E 2 17.6689", 48.85837, 2.294482, "ddm");
reads("48 51.5022, -2 17.6689", 48.85837, -2.294482, "ddm");
// ---- what is refused, and why ---------------------------------------------------------------------------
refuses("", /Type a position/);
refuses("   ", /Type a position/);
refuses(null, /Type a position/);
refuses("91, 10", /Latitude must be between/);
refuses("10, 181", /Longitude must be between/);
refuses("-90.0001 0", /Latitude/);
refuses("48 61 0 N, 2 0 0 E", /Minutes must be under 60/);
refuses("48 51 60 N, 2 0 0 E", /Seconds must be under 60/);
refuses("48.5 30 N, 2 0 E", /whole number/);
refuses("48 51.5 30 N, 2 17 40 E", /Minutes must be a whole number/);
refuses("48N 2N", /Both halves are latitudes/);
refuses("48E 2W", /Both halves are longitudes/);
refuses("-48N 2E", /sign or a hemisphere letter/);
refuses("48.85837", /latitude and a longitude/);
refuses("1 2 3", /latitude and a longitude/);
refuses("1, 2, 3", /latitude and a longitude/);
refuses("48 51 30 12 N, 2 E", /at most degrees, minutes and seconds/);
refuses("paris, france", /something other than numbers/);
refuses("48.85837, 2.294481 <script>", /something other than numbers/);
refuses("4".repeat(200), /too long/);
refuses("1e3, 2", /before or after the numbers/);
refuses("N, E", /number is missing/);
refuses("48 -51 30, 2 17 40", /Only the degrees may carry a sign/);
// 100 E is a longitude wherever it stands, and 100 as a latitude is refused.
reads("100E 10N", 10, 100);
refuses("100 10", /Latitude/);

// ---- writing a position back ----------------------------------------------------------------------------
{
  ok(fmtDd(48.858369444, 2.294480556) === "48.858369, 2.294481", "decimal degrees keep six places");
  ok(fmtDms(48.858369444, 2.294480556) === "48°51'30.13\"N 2°17'40.13\"E", "degrees, minutes and seconds");
  ok(fmtDdm(48.858369444, 2.294480556) === "48°51.5022'N 2°17.6688'E", "degrees and decimal minutes");
  ok(fmtDms(-33.856784, -151.215297) === "33°51'24.42\"S 151°12'55.07\"W", "south and west are letters, never a sign");
  ok(fmtDms(9.9999999, 0) === "10°00'00.00\"N 0°00'00.00\"E" && fmtDdm(9.99999999, 0) === "10°00.0000'N 0°00.0000'E", "rounding carries into the degrees and never prints 60");
  const f = coordForms(48.85837, 2.294481);
  ok(f && f.dd && f.dms && f.ddm && coordForms(91, 0) === null && coordForms(NaN, 0) === null && coordForms("48", 2) === null, "all three forms, or nothing for a value that is not a position");
  // Round trip: each written form reads back to the same place.
  let drift = 0;
  for (const [la, lo] of [[48.85837, 2.294481], [-33.856784, 151.215297], [0, 0], [-0.000001, -179.999999], [89.999999, 180], [12.5, -45.25]]) {
    const w = coordForms(la, lo);
    for (const k of ["dd", "dms", "ddm"]) { const r = parseCoords(w[k]); if (!r.ok || !near(r.lat, la, 2e-5) || !near(r.lon, lo, 2e-5)) drift++; }
  }
  ok(drift === 0, "every written form reads back to the same position");
  ok(validPosition(90, -180) && !validPosition(90.1, 0) && !validPosition(0, Infinity), "the range check");
}
// ---- the map link ---------------------------------------------------------------------------------------------
{
  const m = mapLink(48.85837, 2.294481);
  const u = parseUrl(m.url);
  ok(m.link_kind === "map" && LINK_KINDS.includes("map") && m.label === "Open in OpenStreetMap", "the map link has a kind of its own");
  ok(u.protocol === "https:" && u.hostname === "www.openstreetmap.org" && u.searchParams.get("mlat") === "48.858370" && u.searchParams.get("mlon") === "2.294481" && u.hash === "#map=15/48.858370/2.294481" && [...u.searchParams.keys()].length === 2, "it goes to OpenStreetMap and carries two numbers and nothing else");
  ok(mapLink(91, 0) === null && mapLink(0, 181) === null && mapLink("48.8", 2.2) === null && mapLink(NaN, 0) === null && mapLink(undefined, undefined) === null, "no link for anything that is not a position in range");
  ok(/^https:\/\/www\.openstreetmap\.org\/\?mlat=-?\d+\.\d{6}&mlon=-?\d+\.\d{6}#map=15\/-?\d+\.\d{6}\/-?\d+\.\d{6}$/.test(mapLink(-33.856784, -151.215297).url), "the address is built from fixed-point numbers only");
  // The only places that write a map address are mapLink and its callers.
  const dir = new URL("../../static/v2/js/", import.meta.url);
  const hits = fs.readdirSync(dir).filter((f) => f.endsWith(".js")).filter((f) => /openstreetmap\.org|google\.[a-z.]+\/maps|maps\.apple/.test(fs.readFileSync(new URL(f, dir), "utf8")));
  ok(hits.length === 1 && hits[0] === "links.js", "a map address is written in links.js and nowhere else: " + hits.join(", "));
  const geo = fs.readFileSync(new URL("geo.js", dir), "utf8");
  ok(!/\bfetch\(|document\.|innerHTML|import\s/.test(geo.replace(/\/\/.*$/gm, "")), "geo.js has no DOM, no network and no imports");
}

console.log(bad ? `${bad} of ${n} coordinate checks failed` : `all ${n} coordinate checks pass`);
if (bad) process.exit(1);
