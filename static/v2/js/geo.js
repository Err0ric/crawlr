// Coordinates: reading a position written as decimal degrees, degrees-minutes-seconds or
// degrees and decimal minutes, checking its ranges, and writing it back in all three forms.
// Pure: no DOM, no network. Used by the coordinate converter under Decoders and by the image
// metadata reader. A position never leaves the browser unless the investigator opens the map link.

const MAX_TEXT = 120;
const fail = (error) => ({ ok: false, error });
const AXIS = { N: "lat", S: "lat", E: "lon", W: "lon" };

export const validLat = (v) => typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= 90;
export const validLon = (v) => typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= 180;
export const validPosition = (lat, lon) => validLat(lat) && validLon(lon);

// One half of a position: up to three numbers and an optional hemisphere letter.
function readHalf(text) {
  const letters = text.match(/[NSEW]/g) || [];
  if (letters.length > 1) return fail("Each half takes one hemisphere letter.");
  const hemi = letters[0] || "";
  if (/\d[\s°'"]*[NSEW][\s°'"]*[+-]?\d/.test(text)) return fail("A hemisphere letter goes before or after the numbers, not between them.");
  const body = text.replace(/[NSEW]/g, " ").trim();
  // What is left may only be numbers and the marks people put after them.
  if (/[^0-9+\-.\s°'"]/.test(body)) return fail("That holds something other than numbers, degree marks and N, S, E or W.");
  const nums = body.match(/[+-]?\d+(?:\.\d+)?/g) || [];
  if (body.replace(/[+-]?\d+(?:\.\d+)?/g, "").replace(/[\s°'"]/g, "")) return fail("A number in that could not be read.");
  if (!nums.length || nums.length > 3) return fail(nums.length ? "A coordinate has at most degrees, minutes and seconds." : "A number is missing.");
  const signed = /^[+-]/.test(nums[0]);
  if (nums.slice(1).some((n) => /^[+-]/.test(n))) return fail("Only the degrees may carry a sign.");
  if (signed && hemi) return fail("Use a sign or a hemisphere letter, not both.");
  const [d, m = 0, s = 0] = nums.map((n) => Math.abs(Number(n)));
  if (nums.length > 1 && !Number.isInteger(d)) return fail("Degrees must be a whole number when minutes follow.");
  if (nums.length > 2 && !Number.isInteger(m)) return fail("Minutes must be a whole number when seconds follow.");
  if (m >= 60) return fail("Minutes must be under 60.");
  if (s >= 60) return fail("Seconds must be under 60.");
  const neg = nums[0].startsWith("-") || hemi === "S" || hemi === "W";
  const value = (d + m / 60 + s / 3600) * (neg ? -1 : 1);
  return { ok: true, value, hemi, parts: nums.length };
}

// Splits the text into its two halves: at a comma or semicolon, else around the hemisphere
// letters, else by the count of numbers (2, 4 or 6).
function halves(t) {
  const bySep = t.split(/[,;]/);
  if (bySep.length === 2) return bySep;
  if (bySep.length > 2) return null;
  const letters = [...t.matchAll(/[NSEW]/g)];
  if (letters.length === 2) {
    // "48 51 30 N 2 17 40 E": a letter closes its half. "N 48 51 30 E 2 17 40": it opens it.
    const leading = !/\d/.test(t.slice(0, letters[0].index));
    const cut = leading ? letters[1].index : letters[0].index + 1;
    return [t.slice(0, cut), t.slice(cut)];
  }
  if (letters.length) return null;
  const nums = [...t.matchAll(/[+-]?\d+(?:\.\d+)?/g)];
  if (![2, 4, 6].includes(nums.length)) return null;
  const cut = nums[nums.length / 2].index;
  return [t.slice(0, cut), t.slice(cut)];
}

// { ok: true, lat, lon, format: "dd" | "ddm" | "dms" } or { ok: false, error }.
// Without hemisphere letters the first value is the latitude.
export function parseCoords(input) {
  if (typeof input !== "string" || !input.trim()) return fail("Type a position, for example 48.85837, 2.294481.");
  if (input.length > MAX_TEXT) return fail("That is too long to be a position.");
  const t = input.normalize("NFKC").toUpperCase()
    .replace(/[\u00ba\u02da]/g, "°").replace(/[\u2032\u2019\u2018\u02b9\u00b4`]/g, "'").replace(/[\u2033\u201d\u201c]/g, '"').replace(/''/g, '"')
    .replace(/[\u2212\u2013\u2014]/g, "-").replace(/\s+/g, " ").trim();
  const parts = halves(t);
  if (!parts) return fail("Give a latitude and a longitude, for example 48.85837, 2.294481 or 48°51'30\"N 2°17'40\"E.");
  const a = readHalf(parts[0].trim()), b = readHalf(parts[1].trim());
  if (!a.ok) return a;
  if (!b.ok) return b;
  const ax = AXIS[a.hemi] || "", bx = AXIS[b.hemi] || "";
  if (ax && bx && ax === bx) return fail(ax === "lat" ? "Both halves are latitudes (N or S)." : "Both halves are longitudes (E or W).");
  // A half marked E or W is the longitude wherever it stands.
  const swap = ax === "lon" || bx === "lat";
  const lat = swap ? b.value : a.value, lon = swap ? a.value : b.value;
  if (!validLat(lat)) return fail("Latitude must be between -90 and 90.");
  if (!validLon(lon)) return fail("Longitude must be between -180 and 180.");
  const n = Math.max(a.parts, b.parts);
  return { ok: true, lat, lon, format: n === 1 ? "dd" : n === 2 ? "ddm" : "dms" };
}

// One axis as whole degrees, whole minutes and seconds, rounded as one number so 59.999" never prints as 60.
function dmsOf(value, places) {
  const unit = 10 ** places;
  const total = Math.round(Math.abs(value) * 3600 * unit);
  const d = Math.floor(total / (3600 * unit)), m = Math.floor((total - d * 3600 * unit) / (60 * unit));
  const s = (total - d * 3600 * unit - m * 60 * unit) / unit;
  return { d, m, s };
}
function ddmOf(value, places) {
  const unit = 10 ** places;
  const total = Math.round(Math.abs(value) * 60 * unit);
  const d = Math.floor(total / (60 * unit));
  return { d, m: (total - d * 60 * unit) / unit };
}
const hemiOf = (value, axis) => (axis === "lat" ? (value < 0 ? "S" : "N") : value < 0 ? "W" : "E");

export const fmtDd = (lat, lon) => `${lat.toFixed(6)}, ${lon.toFixed(6)}`;
export function fmtDms(lat, lon) {
  const one = (v, axis) => { const { d, m, s } = dmsOf(v, 2); return `${d}°${String(m).padStart(2, "0")}'${s.toFixed(2).padStart(5, "0")}"${hemiOf(v, axis)}`; };
  return `${one(lat, "lat")} ${one(lon, "lon")}`;
}
export function fmtDdm(lat, lon) {
  const one = (v, axis) => { const { d, m } = ddmOf(v, 4); return `${d}°${m.toFixed(4).padStart(7, "0")}'${hemiOf(v, axis)}`; };
  return `${one(lat, "lat")} ${one(lon, "lon")}`;
}
// The three written forms of one position, or null when it is not a position.
export function coordForms(lat, lon) {
  if (!validPosition(lat, lon)) return null;
  return { dd: fmtDd(lat, lon), dms: fmtDms(lat, lon), ddm: fmtDdm(lat, lon) };
}
