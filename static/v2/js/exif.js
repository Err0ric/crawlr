// Image metadata, read in the browser. The image metadata tool hands this module the bytes of a
// file the investigator picked; nothing here touches the DOM or the network, and the file is
// never uploaded.
//
// Read: the Exif block of a JPEG (APP1), a PNG (eXIf), a WebP (EXIF chunk) or a TIFF file: the
// first image directory, its Exif directory and its GPS directory, in either byte order. Also a
// JPEG comment and a PNG's text chunks. Not read: maker notes, XMP and IPTC (their presence is
// said), and the embedded preview image, which is never followed or shown.
//
// The file is outside data and may be built to mislead or to stall a parser. Every offset is
// checked against the block it must sit in, a directory is visited once, counts are capped, and
// the work done is bounded by the constants below. A block that breaks a rule is reported as
// "could not be read"; nothing throws and nothing loops.
//
//   readImageMeta(bytes) -> {
//     state    "ok" | "none" | "unreadable" | "unsupported"
//     format   "jpeg" | "png" | "webp" | "tiff" | ""
//     width, height            pixels from the image's own header, or null
//     meta     { make, model, software, lens, owner, serial, artist, copyright, description, comment,
//                dateOriginal, offsetOriginal, dateDigitized, offsetDigitized, dateModified, offsetModified,
//                orientation, orientationText, exifWidth, exifHeight }   only the keys that were found
//     gps      null | { lat, lon, altitude, time, direction, datum }     lat and lon are always in range
//     text     [{ k, v }]      PNG text chunks
//     problems [sentence]      each says which block could not be read
//     notes    [sentence]      what else the file carries that this reader does not parse
//   }

export const MAX_IMAGE_BYTES = 64 * 1024 * 1024;   // the tool refuses a larger file before reading it
const MAX_SEGMENTS = 400;       // JPEG segments walked before the image data
const MAX_CHUNKS = 200000;      // PNG or RIFF chunks walked (a large PNG has thousands of IDAT chunks)
const MAX_ENTRIES = 512;        // entries in one directory
const MAX_ASCII = 1024;         // bytes of one text value that are looked at
const MAX_TEXT = 300;           // characters of one text value that are kept
const MAX_TEXT_CHUNKS = 40;

class Unreadable extends Error {}
const bad = (why) => { throw new Unreadable(why); };

const ORIENTATION = {
  1: "Normal", 2: "Mirrored left to right", 3: "Rotated 180°", 4: "Mirrored top to bottom",
  5: "Mirrored and rotated 90° counter-clockwise", 6: "Rotated 90° clockwise", 7: "Mirrored and rotated 90° clockwise", 8: "Rotated 90° counter-clockwise",
};
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

// Text from a file: control characters and the characters that reorder or hide text are removed.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const tidy = (s) => Array.from(String(s).replace(UNSAFE, " ").replace(/\s+/g, " ").trim()).slice(0, MAX_TEXT).join("");
function decodeText(bytes) {
  let end = bytes.indexOf(0); if (end < 0) end = bytes.length;
  const cut = bytes.subarray(0, Math.min(end, MAX_ASCII));
  try { return tidy(new TextDecoder("utf-8", { fatal: true }).decode(cut)); } catch { return tidy(Array.from(cut, (b) => String.fromCharCode(b)).join("")); }
}
const latin1 = (bytes) => Array.from(bytes.subarray(0, MAX_ASCII), (b) => String.fromCharCode(b)).join("");

// "2024:05:01 12:33:20" as 2024-05-01 12:33:20. Anything else is not a date and is dropped.
const exifDate = (s) => { const m = /^(\d{4})[:-](\d{2})[:-](\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/.exec(String(s).trim()); return m && +m[2] >= 1 && +m[2] <= 12 && +m[3] >= 1 && +m[3] <= 31 && +m[4] < 24 && +m[5] < 60 && +m[6] < 61 ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}` : ""; };
const exifOffset = (s) => (/^[+-]\d{2}:\d{2}$/.test(String(s).trim()) ? String(s).trim() : "");

// ---- TIFF: the structure Exif is written in ------------------------------------------------------
// `t` is the TIFF block alone, so every offset is checked against its length.
function tiffReader(t) {
  if (t.length < 8) bad("header");
  const le = t[0] === 0x49 && t[1] === 0x49 ? true : t[0] === 0x4d && t[1] === 0x4d ? false : bad("byte order");
  const dv = new DataView(t.buffer, t.byteOffset, t.byteLength);
  const u16 = (o) => (o + 2 <= t.length ? dv.getUint16(o, le) : bad("offset"));
  const u32 = (o) => (o + 4 <= t.length ? dv.getUint32(o, le) : bad("offset"));
  const i32 = (o) => (o + 4 <= t.length ? dv.getInt32(o, le) : bad("offset"));
  if (u16(2) !== 42) bad("magic");
  const visited = new Set();
  // One directory: Map of tag -> { type, count, at } for the value's bytes. A directory is read
  // once: a second visit is a loop. The pointer to the next directory is never followed.
  function dir(offset) {
    if (visited.has(offset)) bad("loop");
    visited.add(offset);
    if (offset < 8 || offset + 2 > t.length) bad("directory offset");
    const n = u16(offset);
    if (n > MAX_ENTRIES) bad("entry count");
    if (offset + 2 + n * 12 > t.length) bad("truncated directory");
    const out = new Map();
    for (let i = 0; i < n; i++) {
      const e = offset + 2 + i * 12, tag = u16(e), type = u16(e + 2), count = u32(e + 4), size = TYPE_SIZE[type];
      if (!size || out.has(tag)) continue;
      const total = size * count;
      out.set(tag, { type, count, total, at: total <= 4 ? e + 8 : u32(e + 8) });
    }
    return out;
  }
  // A value of a tag this reader wants. Its bytes must lie inside the block.
  const span = (v, max) => { if (v.count > max) bad("value count"); if (v.at + v.total > t.length) bad("value offset"); return t.subarray(v.at, v.at + v.total); };
  const ascii = (d, tag) => { const v = d.get(tag); return v && (v.type === 2 || v.type === 7 || v.type === 1) ? decodeText(span(v, 65536)) : ""; };
  const int = (d, tag) => { const v = d.get(tag); if (!v || v.count < 1) return null; span(v, 65536); return v.type === 3 ? u16(v.at) : v.type === 4 ? u32(v.at) : v.type === 1 ? t[v.at] : v.type === 9 ? i32(v.at) : null; };
  const rationals = (d, tag, want) => {
    const v = d.get(tag);
    if (!v || (v.type !== 5 && v.type !== 10) || v.count < want) return null;
    span(v, 16);
    const out = [];
    for (let i = 0; i < want; i++) {
      const num = v.type === 5 ? u32(v.at + i * 8) : i32(v.at + i * 8), den = v.type === 5 ? u32(v.at + i * 8 + 4) : i32(v.at + i * 8 + 4);
      if (den === 0) return null;
      out.push(num / den);
    }
    return out;
  };
  // Exif "UserComment": eight bytes that name the character set, then the text.
  const comment = (d, tag) => {
    const v = d.get(tag);
    if (!v || v.total < 9) return "";
    const b = span(v, 65536), code = latin1(b.subarray(0, 8)).replace(/\0+$/, "");
    const body = b.subarray(8, 8 + MAX_ASCII);
    if (code === "ASCII") return decodeText(body);
    if (code === "UNICODE") { try { return tidy(new TextDecoder(le ? "utf-16le" : "utf-16be").decode(body).replace(/\0+$/, "")); } catch { return ""; } }
    return "";
  };
  return { dir, ifd0: u32(4), ascii, int, rationals, comment };
}

function readGps(r, g) {
  const lat = r.rationals(g, 2, 3), lon = r.rationals(g, 4, 3);
  const latRef = r.ascii(g, 1).toUpperCase().slice(0, 1), lonRef = r.ascii(g, 3).toUpperCase().slice(0, 1);
  const out = { lat: null, lon: null, altitude: null, time: "", direction: null, datum: "" };
  if (g.has(2) || g.has(4)) {
    if (!lat || !lon || !"NS".includes(latRef || "?") || !"EW".includes(lonRef || "?")) bad("position");
    const deg = ([d, m, s]) => (d >= 0 && m >= 0 && m < 60 && s >= 0 && s < 60 ? d + m / 60 + s / 3600 : NaN);
    const la = deg(lat) * (latRef === "S" ? -1 : 1), lo = deg(lon) * (lonRef === "W" ? -1 : 1);
    if (!Number.isFinite(la) || !Number.isFinite(lo) || Math.abs(la) > 90 || Math.abs(lo) > 180) bad("position range");
    out.lat = la; out.lon = lo;
  }
  const alt = r.rationals(g, 6, 1);
  if (alt && Number.isFinite(alt[0]) && Math.abs(alt[0]) < 100000) out.altitude = Math.round(alt[0] * (r.int(g, 5) === 1 ? -1 : 1) * 10) / 10;
  const hms = r.rationals(g, 7, 3), date = /^(\d{4}):(\d{2}):(\d{2})$/.exec(r.ascii(g, 0x1d));
  if (hms && hms[0] < 24 && hms[1] < 60 && hms[2] < 61 && hms.every((x) => x >= 0)) {
    const p = (x) => String(Math.floor(x)).padStart(2, "0");
    out.time = `${date ? `${date[1]}-${date[2]}-${date[3]} ` : ""}${p(hms[0])}:${p(hms[1])}:${p(hms[2])} UTC`;
  } else if (date) out.time = `${date[1]}-${date[2]}-${date[3]} UTC`;
  const dir = r.rationals(g, 0x11, 1);
  if (dir && dir[0] >= 0 && dir[0] < 360) out.direction = { degrees: Math.round(dir[0] * 10) / 10, ref: r.ascii(g, 0x10).toUpperCase().startsWith("M") ? "magnetic north" : "true north" };
  out.datum = r.ascii(g, 0x12);
  return out;
}

// Reads one TIFF block into `res`. A broken first directory makes the whole block unreadable;
// a broken Exif or GPS directory is said by itself, and what was read before it is kept.
function readTiff(t, res, { own = false } = {}) {
  let r, d0;
  try { r = tiffReader(t); d0 = r.dir(r.ifd0); } catch (e) { if (!(e instanceof Unreadable)) throw e; res.problems.push("The Exif block could not be read: its structure is damaged or cut short."); return false; }
  const m = res.meta;
  const put = (k, v) => { if (v !== "" && v !== null && v !== undefined) m[k] = v; };
  const block = (name, fn) => { try { fn(); } catch (e) { if (!(e instanceof Unreadable)) throw e; res.problems.push(`${name} could not be read: it points outside the file, loops or is cut short.`); } };
  block("Part of the camera block", () => {
    put("make", r.ascii(d0, 0x010f)); put("model", r.ascii(d0, 0x0110)); put("software", r.ascii(d0, 0x0131));
    put("artist", r.ascii(d0, 0x013b)); put("copyright", r.ascii(d0, 0x8298)); put("description", r.ascii(d0, 0x010e));
    put("dateModified", exifDate(r.ascii(d0, 0x0132)));
    const o = r.int(d0, 0x0112);
    if (ORIENTATION[o]) { m.orientation = o; m.orientationText = ORIENTATION[o]; }
    if (own) { const w = r.int(d0, 0x0100), h = r.int(d0, 0x0101); if (w > 0 && h > 0 && w < 1e6 && h < 1e6) { res.width = w; res.height = h; } }
  });
  const exifAt = (() => { try { return r.int(d0, 0x8769); } catch { return null; } })();
  if (exifAt !== null) block("The Exif details block", () => {
    const x = r.dir(exifAt);
    put("dateOriginal", exifDate(r.ascii(x, 0x9003))); put("dateDigitized", exifDate(r.ascii(x, 0x9004)));
    put("offsetModified", exifOffset(r.ascii(x, 0x9010))); put("offsetOriginal", exifOffset(r.ascii(x, 0x9011))); put("offsetDigitized", exifOffset(r.ascii(x, 0x9012)));
    put("lens", [r.ascii(x, 0xa433), r.ascii(x, 0xa434)].filter(Boolean).join(" ")); put("owner", r.ascii(x, 0xa430)); put("serial", r.ascii(x, 0xa431));
    put("comment", r.comment(x, 0x9286));
    const w = r.int(x, 0xa002), h = r.int(x, 0xa003);
    if (w > 0 && h > 0 && w < 1e6 && h < 1e6) { m.exifWidth = w; m.exifHeight = h; }
    if (x.has(0x927c)) res.notes.push("The file carries a maker note (the camera maker's own block), which this reader does not parse.");
  });
  const gpsAt = (() => { try { return r.int(d0, 0x8825); } catch { return null; } })();
  if (gpsAt !== null) block("The GPS block", () => {
    const g = readGps(r, r.dir(gpsAt));
    if (g.lat !== null) res.gps = g;
    else if (g.time || g.altitude !== null) res.notes.push(`The GPS block holds no position${g.time ? `, only a time (${g.time})` : ""}.`);
    else res.notes.push("The GPS block is present and holds no position.");
  });
  return true;
}

// ---- containers ------------------------------------------------------------------------------------
const startsWith = (b, at, sig) => at + sig.length <= b.length && sig.every((c, i) => b[at + i] === c);
const str = (s) => Array.from(s, (c) => c.charCodeAt(0));
const be16 = (b, o) => (b[o] << 8) | b[o + 1];
const be32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const le32 = (b, o) => ((b[o + 3] << 24) | (b[o + 2] << 16) | (b[o + 1] << 8) | b[o]) >>> 0;
const le24 = (b, o) => (b[o + 2] << 16) | (b[o + 1] << 8) | b[o];
const EXIF_HEAD = str("Exif\0\0"), XMP_HEAD = str("http://ns.adobe.com/xap/1.0/\0");
const XMP_NOTE = "The file also carries an XMP packet, which this reader does not parse.";

function readJpeg(b, res) {
  let pos = 2, exif = false;
  for (let i = 0; i < MAX_SEGMENTS; i++) {
    if (pos + 4 > b.length) { if (!exif && res.width === null) bad("truncated"); break; }
    if (b[pos] !== 0xff) bad("marker");
    let marker = b[pos + 1];
    while (marker === 0xff && pos + 2 < b.length) { pos++; marker = b[pos + 1]; }      // fill bytes
    if (pos + 4 > b.length) bad("truncated");
    if (marker === 0xd9 || marker === 0xda) break;                                      // end, or the image data starts
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) { pos += 2; continue; }  // markers with no length
    const len = be16(b, pos + 2);
    if (len < 2) bad("segment length");
    const start = pos + 4, end = pos + 2 + len;
    if (end > b.length) { res.problems.push("The file ends in the middle of a block. What came before it was read."); break; }
    if (marker === 0xe1 && !exif && startsWith(b, start, EXIF_HEAD)) { exif = true; readTiff(b.subarray(start + 6, end), res); }
    else if (marker === 0xe1 && startsWith(b, start, XMP_HEAD)) { if (!res.notes.includes(XMP_NOTE)) res.notes.push(XMP_NOTE); }
    else if (marker === 0xed) { const n = "The file also carries an IPTC or Photoshop block, which this reader does not parse."; if (!res.notes.includes(n)) res.notes.push(n); }
    else if (marker === 0xfe && !res.meta.fileComment) { const c = decodeText(b.subarray(start, end)); if (c) res.meta.fileComment = c; }
    else if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc && len >= 7) { res.height = be16(b, start + 1); res.width = be16(b, start + 3); }
    pos = end;
  }
}

function readPng(b, res) {
  let pos = 8;
  for (let i = 0; i < MAX_CHUNKS && pos + 8 <= b.length; i++) {
    const len = be32(b, pos), type = latin1(b.subarray(pos + 4, pos + 8)), start = pos + 8, end = start + len;
    if (i === 0 && type !== "IHDR") bad("first chunk");
    if (end + 4 > b.length) { if (i === 0) bad("truncated"); res.problems.push("The file ends in the middle of a chunk. What came before it was read."); break; }
    const data = b.subarray(start, end);
    if (type === "IHDR" && len >= 8) { res.width = be32(data, 0); res.height = be32(data, 4); }
    else if (type === "eXIf" && !res.exifSeen) { res.exifSeen = true; readTiff(data, res); }
    else if ((type === "tEXt" || type === "iTXt") && res.text.length < MAX_TEXT_CHUNKS) {
      const z = data.indexOf(0);
      if (z > 0 && z <= 79) {
        const k = tidy(latin1(data.subarray(0, z)));
        let body = null;
        if (type === "tEXt") body = tidy(latin1(data.subarray(z + 1)));
        else if (data[z + 1] === 0) {                    // iTXt, not compressed: language tag, translated keyword, then UTF-8 text
          const lang = data.indexOf(0, z + 3), tr = lang < 0 ? -1 : data.indexOf(0, lang + 1);
          if (tr > 0) body = decodeText(data.subarray(tr + 1));
        } else res.zipped = true;
        if (k && body) { if (/^XML:com\.adobe\.xmp$/i.test(k)) { if (!res.notes.includes(XMP_NOTE)) res.notes.push(XMP_NOTE); } else res.text.push({ k, v: body }); }
      }
    } else if (type === "zTXt") res.zipped = true;
    else if (type === "IEND") break;
    pos = end + 4;
  }
  if (res.zipped) res.notes.push("The file carries compressed text chunks, which this reader does not unpack.");
}

function readWebp(b, res) {
  let pos = 12;
  for (let i = 0; i < MAX_CHUNKS && pos + 8 <= b.length; i++) {
    const type = latin1(b.subarray(pos, pos + 4)), len = le32(b, pos + 4), start = pos + 8, end = start + len;
    if (end > b.length) { if (i === 0) bad("truncated"); res.problems.push("The file ends in the middle of a chunk. What came before it was read."); break; }
    const d = b.subarray(start, end);
    if (type === "VP8X" && len >= 10) { res.width = le24(d, 4) + 1; res.height = le24(d, 7) + 1; }
    else if (type === "VP8 " && len >= 10 && d[3] === 0x9d && d[4] === 0x01 && d[5] === 0x2a && res.width === null) { res.width = (d[6] | (d[7] << 8)) & 0x3fff; res.height = (d[8] | (d[9] << 8)) & 0x3fff; }
    else if (type === "VP8L" && len >= 5 && d[0] === 0x2f && res.width === null) { res.width = 1 + (d[1] | ((d[2] & 0x3f) << 8)); res.height = 1 + ((d[2] >> 6) | (d[3] << 2) | ((d[4] & 0x0f) << 10)); }
    else if (type === "EXIF" && !res.exifSeen) { res.exifSeen = true; readTiff(startsWith(d, 0, EXIF_HEAD) ? d.subarray(6) : d, res); }
    else if (type === "XMP ") { if (!res.notes.includes(XMP_NOTE)) res.notes.push(XMP_NOTE); }
    pos = end + (len & 1);
  }
}

export function sniffFormat(b) {
  if (!(b instanceof Uint8Array) || b.length < 12) return "";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg";
  if (startsWith(b, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (startsWith(b, 0, str("RIFF")) && startsWith(b, 8, str("WEBP"))) return "webp";
  if (startsWith(b, 0, [0x49, 0x49, 0x2a, 0x00]) || startsWith(b, 0, [0x4d, 0x4d, 0x00, 0x2a])) return "tiff";
  return "";
}

const META_KEYS = ["make", "model", "software", "lens", "owner", "serial", "artist", "copyright", "description", "comment", "fileComment", "dateOriginal", "dateDigitized", "dateModified", "orientation"];

export function readImageMeta(bytes) {
  const res = { state: "unsupported", format: "", width: null, height: null, meta: {}, gps: null, text: [], problems: [], notes: [] };
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_IMAGE_BYTES) return res;
  res.format = sniffFormat(bytes);
  if (!res.format) return res;
  try {
    if (res.format === "jpeg") readJpeg(bytes, res);
    else if (res.format === "png") readPng(bytes, res);
    else if (res.format === "webp") readWebp(bytes, res);
    else if (!readTiff(bytes, res, { own: true })) { res.state = "unreadable"; delete res.exifSeen; delete res.zipped; return res; }
  } catch (e) {
    // The container itself is damaged. Nothing that was half read is shown.
    return { state: "unreadable", format: res.format, width: null, height: null, meta: {}, gps: null, text: [], problems: ["The file could not be read: it is damaged or cut short."], notes: [] };
  }
  delete res.exifSeen; delete res.zipped;
  if (!(res.width > 0 && res.height > 0 && res.width < 1e6 && res.height < 1e6)) { res.width = null; res.height = null; }
  const has = META_KEYS.some((k) => k in res.meta) || !!res.gps || res.text.length > 0;
  res.state = has ? "ok" : res.problems.length ? "unreadable" : "none";
  return res;
}
