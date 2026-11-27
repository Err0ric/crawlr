// The image metadata reader (static/v2/js/exif.js). Every file here is built in the test from
// bytes: no image is stored in the repository and nothing is fetched. The camera and the place are invented.
import fs from "node:fs";
const { readImageMeta, sniffFormat, MAX_IMAGE_BYTES } = await import("../../static/v2/js/exif.js");
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {}, querySelector: () => null, querySelectorAll: () => [], createElement: () => ({ innerHTML: "" }) };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const { renderImage } = await import("../../static/v2/js/imagemeta.js");
const shown = (meta) => renderImage({ name: "picture.jpg", size: 1234, lastModified: 0 }, meta).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };

// ---- a small TIFF writer ------------------------------------------------------------------------
// dirs: { ifd0: [entry], exif: [entry], gps: [entry] }, entry: [tag, type, values]
//   type 2 ASCII (a string), 3 SHORT, 4 LONG, 5 RATIONAL ([[num, den], ...]), 7 UNDEFINED (bytes), 1 BYTE
const SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1 };
function tiff({ ifd0 = [], exif = null, gps = null, le = true, patch = null } = {}) {
  const w16 = (a, v) => (le ? a.push(v & 255, (v >> 8) & 255) : a.push((v >> 8) & 255, v & 255));
  const w32 = (a, v) => (le ? a.push(v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255) : a.push((v >>> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255));
  const enc = (type, values) => {
    const a = [];
    if (type === 2) { for (const c of values) a.push(c.charCodeAt(0)); a.push(0); }
    else if (type === 7 || type === 1) a.push(...values);
    else if (type === 3) for (const v of [].concat(values)) w16(a, v);
    else if (type === 4) for (const v of [].concat(values)) w32(a, v);
    else if (type === 5) for (const [x, y] of values) { w32(a, x); w32(a, y); }
    return a;
  };
  const sizeOf = (entries) => 2 + entries.length * 12 + 4;
  const dirs = [["ifd0", [...ifd0]], ["exif", exif], ["gps", gps]].filter(([, e]) => e);
  // Layout: header (8), each directory, then the values that do not fit in four bytes.
  const at = {}; let pos = 8;
  if (exif) dirs[0][1].push([0x8769, 4, [0]]);
  if (gps) dirs[0][1].push([0x8825, 4, [0]]);
  for (const [name, entries] of dirs) { at[name] = pos; pos += sizeOf(entries); }
  for (const e of dirs[0][1]) { if (e[0] === 0x8769) e[2] = [at.exif]; if (e[0] === 0x8825) e[2] = [at.gps]; }
  const head = []; if (le) head.push(0x49, 0x49); else head.push(0x4d, 0x4d);
  w16(head, 42); w32(head, 8);
  const body = [], tail = [];
  for (const [, entries] of dirs) {
    w16(body, entries.length);
    for (const [tag, type, values] of entries) {
      const data = enc(type, values), count = data.length / SIZE[type];
      w16(body, tag); w16(body, type); w32(body, count);
      if (data.length <= 4) { body.push(...data, ...Array(4 - data.length).fill(0)); }
      else { w32(body, pos + tail.length); tail.push(...data); }
    }
    w32(body, 0);
  }
  const out = Uint8Array.from([...head, ...body, ...tail]);
  if (patch) patch(out, at, { w16, w32, le });
  return out;
}
const jpeg = (tiffBytes, { extra = [], sof = true, comment = "" } = {}) => {
  const seg = (marker, data) => [0xff, marker, ((data.length + 2) >> 8) & 255, (data.length + 2) & 255, ...data];
  const out = [0xff, 0xd8];
  if (tiffBytes) out.push(...seg(0xe1, [0x45, 0x78, 0x69, 0x66, 0, 0, ...tiffBytes]));
  for (const e of extra) out.push(...e);
  if (comment) out.push(...seg(0xfe, [...comment].map((c) => c.charCodeAt(0))));
  if (sof) out.push(...seg(0xc0, [8, 0x03, 0x00, 0x04, 0x00, 3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]));   // 768 high, 1024 wide
  out.push(0xff, 0xda, 0, 2, 0xff, 0xd9);
  return Uint8Array.from(out);
};
const GPS = (lat = [[48, 1], [51, 1], [3013, 100]], lon = [[2, 1], [17, 1], [4013, 100]], latRef = "N", lonRef = "E") => [
  [1, 2, latRef], [2, 5, lat], [3, 2, lonRef], [4, 5, lon], [5, 1, [0]], [6, 5, [[357, 10]]], [7, 5, [[12, 1], [33, 1], [20, 1]]], [0x1d, 2, "2024:05:01"], [0x10, 2, "T"], [0x11, 5, [[2715, 10]]],
];
const FULL = (le) => tiff({
  le,
  ifd0: [[0x010f, 2, "Halvorsen Optics"], [0x0110, 2, "Tern 40"], [0x0112, 3, [6]], [0x0131, 2, "TernOS 2.1"], [0x0132, 2, "2024:05:02 09:00:00"], [0x013b, 2, "Odalys Brandtmoor"]],
  exif: [[0x9003, 2, "2024:05:01 14:33:20"], [0x9011, 2, "+02:00"], [0xa002, 4, [4000]], [0xa003, 4, [3000]], [0xa434, 2, "Tern 24mm f/2"], [0x9286, 7, [0x41, 0x53, 0x43, 0x49, 0x49, 0, 0, 0, ...[..."flag{left-in-the-comment}"].map((c) => c.charCodeAt(0))]]],
  gps: GPS(),
});

// ---- a JPEG with everything, in both byte orders ------------------------------------------------------
for (const le of [true, false]) {
  const name = le ? "little-endian" : "big-endian";
  const r = readImageMeta(jpeg(FULL(le)));
  ok(r.state === "ok" && r.format === "jpeg" && r.width === 1024 && r.height === 768, `${name}: a JPEG with Exif is read, with its pixel size from the image header`);
  ok(r.meta.make === "Halvorsen Optics" && r.meta.model === "Tern 40" && r.meta.software === "TernOS 2.1" && r.meta.artist === "Odalys Brandtmoor" && r.meta.lens === "Tern 24mm f/2", `${name}: make, model, software, artist and lens`);
  ok(r.meta.dateOriginal === "2024-05-01 14:33:20" && r.meta.offsetOriginal === "+02:00" && r.meta.dateModified === "2024-05-02 09:00:00" && !("offsetModified" in r.meta), `${name}: the original date with its offset tag, and no offset where the file has none`);
  ok(r.meta.orientation === 6 && r.meta.orientationText === "Rotated 90° clockwise" && r.meta.exifWidth === 4000 && r.meta.exifHeight === 3000, `${name}: orientation in words and the Exif pixel size`);
  ok(r.meta.comment === "flag{left-in-the-comment}", `${name}: an ASCII user comment`);
  const g = r.gps;
  ok(g && Math.abs(g.lat - 48.858369) < 1e-5 && Math.abs(g.lon - 2.294481) < 1e-5 && g.altitude === 35.7 && g.time === "2024-05-01 12:33:20 UTC" && g.direction.degrees === 271.5 && g.direction.ref === "true north", `${name}: GPS position, altitude, timestamp and direction`);
  ok(r.problems.length === 0, `${name}: nothing is reported as unreadable`);
}
{
  const r = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: [...GPS(undefined, undefined, "S", "W").filter((e) => e[0] !== 5), [5, 1, [1]]] })));
  ok(r.gps.lat < 0 && r.gps.lon < 0 && r.gps.altitude === -35.7, "south, west and below sea level are negative");
}
// ---- no metadata is an answer of its own ----------------------------------------------------------------
{
  const r = readImageMeta(jpeg(null));
  ok(r.state === "none" && r.format === "jpeg" && r.width === 1024 && r.gps === null && !Object.keys(r.meta).length && !r.problems.length, "a JPEG with no Exif block answers none, not unreadable");
  const c = readImageMeta(jpeg(null, { comment: "made with a tool" }));
  ok(c.state === "ok" && c.meta.fileComment === "made with a tool", "a JPEG comment is metadata");
  const x = readImageMeta(jpeg(null, { extra: [[0xff, 0xe1, 0, 2 + 29 + 4, ...[..."http://ns.adobe.com/xap/1.0/\0"].map((ch) => ch.charCodeAt(0)), 60, 120, 62, 32]] }));
  ok(x.state === "unparsed" && x.notes.some((s) => /XMP packet/.test(s)), "an XMP packet is named and not parsed, and a file that holds only that is not called empty");
}
// ---- malformed files end in "could not be read" ------------------------------------------------------------
const unread = (r) => r.problems.some((p) => /could not be read/.test(p));
{
  // The first directory points outside the block.
  const far = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], patch: (b, at, { w32 }) => { const a = []; w32(a, 0x7fffffff); b.set(a, 4); } })));
  ok(far.state === "unreadable" && unread(far) && !Object.keys(far.meta).length, "a first directory outside the file: could not be read");
  // A directory that claims 60000 entries.
  const huge = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], patch: (b, at, { w16 }) => { const a = []; w16(a, 60000); b.set(a, 8); } })));
  ok(huge.state === "unreadable" && unread(huge), "a directory with a huge entry count: could not be read");
  // The Exif pointer points back at the first directory: a loop.
  const loop = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], exif: [[0x9003, 2, "2024:05:01 14:33:20"]], patch: (b, at, { w32 }) => { const a = []; w32(a, 8); b.set(a, at.ifd0 + 2 + 1 * 12 + 8); } })));
  ok(loop.state === "ok" && loop.meta.make === "Halvorsen Optics" && !loop.meta.dateOriginal && loop.problems.some((p) => /Exif details block could not be read/.test(p)), "a directory loop is cut, said, and what came before is kept");
  // The GPS pointer points past the end.
  const gone = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: GPS(), patch: (b, at, { w32 }) => { const a = []; w32(a, 0x00ffffff); b.set(a, at.ifd0 + 2 + 1 * 12 + 8); } })));
  ok(gone.gps === null && gone.problems.some((p) => /GPS block could not be read/.test(p)), "a GPS block outside the file: could not be read, and no position is invented");
  // A text value with a count of four billion.
  const count = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"], [0x0110, 2, "Tern 40"]], patch: (b, at, { w32 }) => { const a = []; w32(a, 0xfffffff0); b.set(a, at.ifd0 + 2 + 4); } })));
  ok(unread(count) && !count.meta.make, "a value with a huge count: could not be read");
  // A zero denominator, a latitude over 90, a missing hemisphere letter.
  for (const [what, g] of [["a zero denominator", GPS([[48, 0], [51, 1], [30, 1]])], ["a latitude over 90", GPS([[98, 1], [0, 1], [0, 1]])], ["an unknown hemisphere", GPS(undefined, undefined, "X", "E")], ["minutes over 60", GPS([[48, 1], [75, 1], [0, 1]])]]) {
    const r = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: g })));
    ok(r.gps === null && r.problems.some((p) => /GPS block could not be read/.test(p)) && r.meta.make === "Halvorsen Optics", `${what}: the GPS block could not be read`);
  }
  // Truncation at every length never throws and never hangs.
  const whole = jpeg(FULL(true));
  let threw = 0, states = new Set();
  for (let i = 0; i <= whole.length; i++) { try { states.add(readImageMeta(whole.slice(0, i)).state); } catch { threw++; } }
  ok(threw === 0 && [...states].every((s) => ["ok", "none", "unparsed", "unreadable", "unsupported"].includes(s)) && states.has("unreadable"), "a file cut at any byte gives a state, never an exception");
  // Every single-byte change of the Exif block gives a state too, and a position, when given, is in range.
  let wild = 0;
  for (let i = 12; i < 12 + 400 && i < whole.length; i++) for (const v of [0x00, 0xff, 0x7f]) {
    const c = whole.slice(); c[i] = v;
    try { const r = readImageMeta(c); if (r.gps && !(Math.abs(r.gps.lat) <= 90 && Math.abs(r.gps.lon) <= 180)) wild++; } catch { wild++; }
  }
  ok(wild === 0, "a corrupted byte anywhere in the block never throws and never gives a position out of range");
  // A file made only of marker fill bytes, and one with a zero segment length.
  ok(readImageMeta(Uint8Array.from([0xff, 0xd8, ...Array(5000).fill(0xff)])).state === "unreadable", "marker fill to the end of the file: could not be read");
  ok(readImageMeta(Uint8Array.from([0xff, 0xd8, 0xff, 0xe1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])).state === "unreadable", "a segment length of zero: could not be read");
}
// ---- what is not an image this reader knows ---------------------------------------------------------------
{
  ok(readImageMeta(new TextEncoder().encode("GIF89a not one of ours")).state === "unsupported" && sniffFormat(new Uint8Array(4)) === "", "another kind of file is unsupported");
  ok(readImageMeta("not bytes").state === "unsupported" && readImageMeta(null).state === "unsupported", "anything but bytes is unsupported");
  ok(MAX_IMAGE_BYTES === 64 * 1024 * 1024, "the size cap is 64 MB");
}
// ---- PNG ---------------------------------------------------------------------------------------------------------
{
  const chunk = (type, data) => { const len = data.length; return [(len >>> 24) & 255, (len >> 16) & 255, (len >> 8) & 255, len & 255, ...[...type].map((c) => c.charCodeAt(0)), ...data, 0, 0, 0, 0]; };
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const ihdr = chunk("IHDR", [0, 0, 2, 128, 0, 0, 1, 224, 8, 2, 0, 0, 0]);      // 640 by 480
  const text = (k, v) => chunk("tEXt", [...k].map((c) => c.charCodeAt(0)).concat(0, [...v].map((c) => c.charCodeAt(0))));
  const png = Uint8Array.from([...sig, ...ihdr, ...text("Software", "Quillwriter 7.2"), ...text("Comment", "<b>not markup</b>"), ...chunk("eXIf", [...tiff({ le: false, ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: GPS() })]), ...chunk("zTXt", [65, 0, 0, 1, 2]), ...chunk("IEND", [])]);
  const r = readImageMeta(png);
  ok(r.state === "ok" && r.format === "png" && r.width === 640 && r.height === 480, "a PNG is read, with its size");
  ok(r.text.length === 2 && r.text[0].k === "Software" && r.text[0].v === "Quillwriter 7.2" && r.text[1].v === "<b>not markup</b>", "its text chunks are returned as text");
  ok(r.meta.make === "Halvorsen Optics" && r.gps && Math.abs(r.gps.lat - 48.858369) < 1e-5, "its eXIf chunk is read like any Exif block");
  ok(r.notes.some((s) => /compressed text chunks/.test(s)), "a compressed text chunk is named and not unpacked");
  const bare = readImageMeta(Uint8Array.from([...sig, ...ihdr, ...chunk("IEND", [])]));
  ok(bare.state === "none" && bare.width === 640, "a PNG with no metadata answers none");
  const cut = readImageMeta(png.slice(0, sig.length + ihdr.length + 20));
  ok(cut.problems.some((p) => /ends in the middle of a chunk/.test(p)) && cut.width === 640, "a PNG cut in a chunk says so and keeps what was read");
  ok(readImageMeta(Uint8Array.from([...sig, ...chunk("tEXt", [65, 0, 66])])).state === "unreadable", "a PNG that does not start with its header chunk: could not be read");
  let threw = 0; for (let i = 0; i <= png.length; i++) { try { readImageMeta(png.slice(0, i)); } catch { threw++; } }
  ok(threw === 0, "a PNG cut at any byte never throws");
}
// ---- WebP and TIFF ---------------------------------------------------------------------------------------------
{
  const s4 = (s) => [...s].map((c) => c.charCodeAt(0));
  const chunk = (type, data) => [...s4(type), data.length & 255, (data.length >> 8) & 255, (data.length >> 16) & 255, 0, ...data, ...(data.length & 1 ? [0] : [])];
  const vp8x = chunk("VP8X", [0x08, 0, 0, 0, 0x1f, 0x03, 0, 0x57, 0x02, 0]);      // 800 by 600
  const body = [...s4("WEBP"), ...vp8x, ...chunk("VP8 ", [0, 0, 0]), ...chunk("EXIF", [...tiff({ ifd0: [[0x0110, 2, "Tern 40"]], gps: GPS() })]), ...chunk("XMP ", [60, 62])];
  const webp = Uint8Array.from([...s4("RIFF"), body.length & 255, (body.length >> 8) & 255, 0, 0, ...body]);
  const r = readImageMeta(webp);
  ok(r.state === "ok" && r.format === "webp" && r.width === 800 && r.height === 600 && r.meta.model === "Tern 40" && r.gps && r.notes.some((x) => /XMP/.test(x)), "a WebP with an EXIF chunk is read, and its XMP chunk is named");
  let threw = 0; for (let i = 0; i <= webp.length; i++) { try { readImageMeta(webp.slice(0, i)); } catch { threw++; } }
  ok(threw === 0, "a WebP cut at any byte never throws");
  const t = readImageMeta(tiff({ le: false, ifd0: [[0x0100, 4, [320]], [0x0101, 4, [200]], [0x010f, 2, "Halvorsen Optics"], [0x0131, 2, "TernOS 2.1"]] }));
  ok(t.state === "ok" && t.format === "tiff" && t.width === 320 && t.height === 200 && t.meta.software === "TernOS 2.1", "a TIFF file is read from its own first directory");
  ok(readImageMeta(Uint8Array.from([0x49, 0x49, 0x2a, 0, 0xff, 0xff, 0xff, 0x7f, 0, 0, 0, 0])).state === "unreadable", "a TIFF whose directory is outside the file: could not be read");
}
// ---- text from a file is cleaned and bounded --------------------------------------------------------------------
{
  const r = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halv\u0007orsen\u0001 Optics"], [0x0110, 7, [...new TextEncoder().encode("Tern\u202e 40 \u00e9"), 0]], [0x013b, 2, "x".repeat(900)]] })));
  ok(r.meta.make === "Halv orsen Optics" && r.meta.model === "Tern 40 \u00e9" && r.meta.artist.length === 300, "control and direction characters are removed, UTF-8 is read and a value is clipped");
}
// ---- what was not read is never called absent ---------------------------------------------------------------------
{
  const seg = (marker, data) => [0xff, marker, ((data.length + 2) >> 8) & 255, (data.length + 2) & 255, ...data];
  const XMP = seg(0xe1, [...[..."http://ns.adobe.com/xap/1.0/\0"].map((ch) => ch.charCodeAt(0)), 60, 120, 62, 32]), IPTC = seg(0xed, [80, 104, 111, 116, 111]);
  // A file whose only metadata is in a block this tool does not parse.
  for (const [what, r] of [["an XMP packet", readImageMeta(jpeg(null, { extra: [XMP] }))], ["an IPTC block", readImageMeta(jpeg(null, { extra: [IPTC] }))], ["a maker note", readImageMeta(jpeg(tiff({ exif: [[0x927c, 7, [1, 2, 3, 4, 5, 6]]] })))]]) {
    ok(r.state === "unparsed" && r.notes.length === 1 && !r.problems.length, `a file with only ${what} has the state "unparsed", not "none"`);
    ok(!/No metadata in this file/.test(shown(r)) && /Metadata this tool does not read/.test(shown(r)) && /not the same as a file with no metadata/.test(shown(r)) && /Also in the file/.test(shown(r)), `and the tool does not say "No metadata" above the card that names ${what}`);
  }
  ok(readImageMeta(jpeg(null)).position === "none" && /No metadata in this file/.test(shown(readImageMeta(jpeg(null)))), "a file with nothing in it is still called empty");
  // The position, in four words: found, none, unknown, unparsed.
  const full = readImageMeta(jpeg(FULL(true)));
  ok(full.position === "found" && /Metadata found, with a position/.test(shown(full)), "a position that was read is found");
  const plain = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]] })));
  ok(plain.state === "ok" && plain.position === "none" && /The file carries no GPS position\./.test(shown(plain)), "an Exif block that was read whole and has no GPS block: no position");
  const gone = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: GPS(), patch: (b, at, { w32 }) => { const a = []; w32(a, 0x00ffffff); b.set(a, at.ifd0 + 2 + 1 * 12 + 8); } })));
  ok(gone.state === "ok" && gone.position === "unknown" && !/carries no GPS position/.test(shown(gone)) && /Whether the file carries a GPS position is unknown/.test(shown(gone)), "a GPS block that could not be read: the position is unknown, never absent");
  const badPos = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: GPS([[98, 1], [0, 1], [0, 1]]) })));
  ok(badPos.position === "unknown" && !/carries no GPS position/.test(shown(badPos)), "a position out of range is unknown too");
  const withXmp = readImageMeta(jpeg(tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]] }), { extra: [XMP] }));
  ok(withXmp.state === "ok" && withXmp.position === "unparsed" && !/The file carries no GPS position/.test(shown(withXmp)) && /XMP packet, which this tool does not parse and which can hold one/.test(shown(withXmp)), "no position in the Exif block and an XMP packet beside it: the tool says which part it read");
  const timeOnly = readImageMeta(jpeg(tiff({ gps: [[7, 5, [[12, 1], [33, 1], [20, 1]]], [0x1d, 2, "2024:05:01"]] })));
  ok(timeOnly.state === "ok" && timeOnly.position === "none" && timeOnly.notes.some((x) => /only a time \(2024-05-01 12:33:20 UTC\)/.test(x)) && !/No metadata in this file/.test(shown(timeOnly)), "a GPS block with a time and no position is metadata, with no position");
  // A walk that ends on its cap says so.
  const many = (count) => { const pre = []; for (let i = 0; i < count; i++) pre.push(0xff, 0xe0, 0, 2); return Uint8Array.from([0xff, 0xd8, ...pre, ...jpeg(FULL(true)).slice(2)]); };
  const under = readImageMeta(many(300)), over = readImageMeta(many(400));
  ok(under.state === "ok" && under.gps && !under.problems.length, "a file with many blocks, under the cap, is read whole");
  ok(over.state === "unreadable" && over.position === "unknown" && over.problems.some((p) => /more blocks than this tool walks/.test(p)) && !/No metadata in this file/.test(shown(over)) && /could not be read/.test(shown(over)), "a file with more blocks than the tool walks: could not be read fully, never 'no metadata'");
  const pchunk = (type, data) => { const len = data.length; return [(len >>> 24) & 255, (len >> 16) & 255, (len >> 8) & 255, len & 255, ...[...type].map((c) => c.charCodeAt(0)), ...data, 0, 0, 0, 0]; };
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], ihdr = pchunk("IHDR", [0, 0, 2, 128, 0, 0, 1, 224, 8, 2, 0, 0, 0]);
  const junk = Uint8Array.from(pchunk("juNk", [])), tailPng = Uint8Array.from([...pchunk("eXIf", [...tiff({ ifd0: [[0x010f, 2, "Halvorsen Optics"]], gps: GPS() })]), ...pchunk("IEND", [])]);
  const bigPng = new Uint8Array(sig.length + ihdr.length + junk.length * 200000 + tailPng.length);
  bigPng.set([...sig, ...ihdr], 0); for (let i = 0; i < 200000; i++) bigPng.set(junk, sig.length + ihdr.length + i * junk.length); bigPng.set(tailPng, bigPng.length - tailPng.length);
  const capped = readImageMeta(bigPng);
  ok(capped.state === "unreadable" && capped.position === "unknown" && capped.problems.some((p) => /more chunks than this tool walks/.test(p)), "a PNG with more chunks than the tool walks: could not be read fully");
  const s4 = (x) => [...x].map((c) => c.charCodeAt(0)), wj = Uint8Array.from([...s4("JUNK"), 0, 0, 0, 0]);
  const bigWebp = new Uint8Array(12 + wj.length * 200000 + 8); bigWebp.set([...s4("RIFF"), 0, 0, 0, 0, ...s4("WEBP")], 0); for (let i = 0; i < 200000; i++) bigWebp.set(wj, 12 + i * wj.length); bigWebp.set([...s4("XMP "), 0, 0, 0, 0], bigWebp.length - 8);
  ok(readImageMeta(bigWebp).problems.some((p) => /more chunks than this tool walks/.test(p)) && readImageMeta(bigWebp).state === "unreadable", "and so does a WebP");
  // More text chunks than are kept: the rest is counted and said.
  const text = (k, v) => pchunk("tEXt", [...k].map((c) => c.charCodeAt(0)).concat(0, [...v].map((c) => c.charCodeAt(0))));
  const wordy = readImageMeta(Uint8Array.from([...sig, ...ihdr, ...Array.from({ length: 47 }, (_, i) => text(`Key${i}`, `value ${i}`)).flat(), ...pchunk("IEND", [])]));
  ok(wordy.text.length === 40 && wordy.textMore === 7 && /and 7 more text chunks that are not shown/i.test(shown(wordy)), "text chunks past the 40 that are kept are counted and said");
  ok(readImageMeta(Uint8Array.from([...sig, ...ihdr, ...text("Software", "Quillwriter 7.2"), ...pchunk("IEND", [])])).textMore === 0, "and nothing is said when all were kept");
  // Seconds the file leaves unset do not cost the whole position, and the tool says how exact it is.
  const coarse = readImageMeta(jpeg(tiff({ gps: GPS([[48, 1], [51, 1], [0, 0]], [[2, 1], [17, 1], [0, 0]]) })));
  ok(coarse.gps && Math.abs(coarse.gps.lat - (48 + 51 / 60)) < 1e-9 && Math.abs(coarse.gps.lon - (2 + 17 / 60)) < 1e-9 && coarse.gps.coarse === true && /seconds of the position unset/.test(shown(coarse)) && /exact only to the minute/.test(shown(coarse)), "a position whose seconds are unset is read to the minute, and marked as that");
  ok(!readImageMeta(jpeg(FULL(true))).gps.coarse && readImageMeta(jpeg(tiff({ gps: GPS([[48, 1], [0, 0], [30, 1]]) }))).gps === null && readImageMeta(jpeg(tiff({ gps: GPS([[48, 1], [51, 1], [7, 0]]) }))).gps === null, "unset minutes, or seconds with a number over zero, are still unreadable");
  // 0, 0 is what a device writes with no fix.
  const zero = readImageMeta(jpeg(tiff({ gps: GPS([[0, 1], [0, 1], [0, 1]], [[0, 1], [0, 1], [0, 1]]) })));
  ok(zero.gps && zero.gps.lat === 0 && zero.gps.lon === 0 && zero.gps.placeholder === true && /Metadata found, with a position of 0, 0/.test(shown(zero)) && /probably a placeholder and not a place/.test(shown(zero)) && !/The file names where it was taken/.test(shown(zero)), "a position of 0, 0 is shown with a note that it is a common placeholder");
  ok(!readImageMeta(jpeg(FULL(true))).gps.placeholder && !/placeholder/.test(shown(readImageMeta(jpeg(FULL(true))))), "and no other position carries that note");
}
// ---- the module keeps its promises -------------------------------------------------------------------------------
{
  const src = fs.readFileSync(new URL("../../static/v2/js/exif.js", import.meta.url), "utf8");
  ok(!/\bfetch\(|XMLHttpRequest|document\.|innerHTML|import\s/.test(src.replace(/\/\/.*$/gm, "")), "exif.js has no DOM, no network and no imports");
  ok(!/0x0201|0x0202|JPEGInterchangeFormat|thumbnail/i.test(src.replace(/\/\/.*$/gm, "")), "it never reads the embedded preview");
  const tool = fs.readFileSync(new URL("../../static/v2/js/imagemeta.js", import.meta.url), "utf8");
  ok(!/\bfetch\(|post\(|XMLHttpRequest|sendBeacon|FormData|createObjectURL/.test(tool), "the image tool makes no request and builds no object URL for the file");
}

console.log(bad ? `${bad} of ${n} image metadata checks failed` : `all ${n} image metadata checks pass`);
if (bad) process.exit(1);
