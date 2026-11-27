// The image metadata tool: the investigator picks or drops an image and the page reads the
// metadata inside it (exif.js). Everything happens in this browser. The file is never uploaded,
// this module makes no request of any kind, the picture is never drawn, and nothing is stored.
// Every value from the file, its name included, reaches the page through h, esc or link.
import { $, h, raw, link, fmtNum } from "./core.js";
import { readImageMeta, MAX_IMAGE_BYTES, COARSE_NOTE, PLACEHOLDER_NOTE } from "./exif.js";
import { coordForms } from "./geo.js";
import { mapLink } from "./links.js";

// One position in its three written forms, each with a Copy button, and the one map link.
// Used here and by the coordinate converter under Decoders.
export function positionHtml(lat, lon) {
  const f = coordForms(lat, lon), m = mapLink(lat, lon);
  if (!f || !m) return "";
  const row = (k, v) => h`<div class="dec-row pos-row"><span class="k">${k}</span><div class="dec-out"><code>${v}</code><button class="btn btn-sm" type="button" data-copy="${v}" aria-label="Copy ${k}">Copy</button></div></div>`;
  return row("Decimal", f.dd) + row("DMS", f.dms) + row("DDM", f.ddm)
    + h`<p class="pos-map">${raw(link(m.url, m.label, "", { kind: m.link_kind }))}<span class="dim">Opening the map sends this position to ${m.host}. Nothing is sent until you do.</span></p>`;
}

const FORMAT = { jpeg: "JPEG", png: "PNG", webp: "WebP", tiff: "TIFF" };
const fmtSize = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${fmtNum(n)} bytes`);
const card = (title, badge, body) => `<article class="card"><div class="card-head"><h2 class="card-title">${title}</h2>${badge}</div><div class="card-body">${body}</div></article>`;
const kv = (pairs) => { const rows = pairs.filter(([, v]) => v !== undefined && v !== null && v !== ""); return rows.length ? `<dl class="kv">${rows.map(([k, v]) => h`<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>` : ""; };
const tag = (t, cls = "") => h`<span class="tag ${cls}">${t}</span>`;
const verdict = (title, text, cls = "") => h`<div class="verdict ${cls}"><div class="v">${title}</div><p>${text}</p></div>`;
const NONE_TEXT = "The file is readable and carries no camera, software, date or position. Most social sites and chat apps remove metadata when an image is uploaded, so an empty file has usually passed through one. That is itself a finding: this is probably not the camera's original file.";
const UNPARSED_TEXT = "The file carries metadata in a form this tool does not parse; \"Also in the file\" below names it. That is not the same as a file with no metadata: a tool that reads XMP, IPTC or maker notes may show a camera, a date or a position.";
// Why there is no position card. Only a file whose Exif block was read whole "carries none".
const POSITION_TEXT = {
  none: "The file carries no GPS position. What it does carry is below.",
  unknown: "Whether the file carries a GPS position is unknown: part of it could not be read. What was read is below.",
  unparsed: "The Exif block carries no GPS position. The file also holds an XMP packet, which this tool does not parse and which can hold one. What was read is below.",
};
const date = (d, off) => (d ? `${d}${off ? ` ${off}` : " (no time zone in the file)"}` : "");

// file: { name, size, lastModified }. meta: readImageMeta's answer. sha: hex, or "".
export function renderImage(file, meta, sha = "") {
  const m = meta.meta, kind = FORMAT[meta.format] || "";
  const sized = meta.width && meta.height ? `${fmtNum(meta.width)} by ${fmtNum(meta.height)} pixels` : "";
  const fileCard = card("File", kind ? tag(kind) : "", kv([["Name", file.name], ["Size", fmtSize(file.size)], ["Kind", kind ? `${kind}, by its first bytes` : "Not recognised"], ["Dimensions", sized],
    ["Date on your disk", Number.isFinite(file.lastModified) && file.lastModified > 0 ? `${new Date(file.lastModified).toISOString().slice(0, 16).replace("T", " ")} UTC` : ""]])
    + (sha ? h`<div class="dec-row pos-row"><span class="k">SHA-256</span><div class="dec-out"><code>${sha}</code><button class="btn btn-sm" type="button" data-copy="${sha}" aria-label="Copy SHA-256">Copy</button></div></div>` : "")
    + `<p class="muted small">The date on your disk is your computer's date for the file, not a date from inside it. The hash was worked out in this browser.</p>`);
  if (meta.state === "unsupported") return verdict("Not an image this tool reads", "The file does not start like a JPEG, PNG, WebP or TIFF file, so nothing was read from it. HEIC, RAW and video files are not read here.", "warn") + fileCard;
  const problems = meta.problems.length ? card("Could not be read", tag(String(meta.problems.length), "warn"), `<ul class="img-list">${meta.problems.map((p) => h`<li>${p}</li>`).join("")}</ul><p class="muted small">A block that breaks the format's rules is not guessed at. What is shown above it was read from the parts that hold together.</p>`) : "";
  if (meta.state === "unreadable") return verdict("The metadata could not be read", "The file is damaged, cut short or built in a way that breaks the format's rules. Nothing from the broken part is shown. That is not the same as a file with no metadata.", "warn") + fileCard + problems;
  const head = meta.state === "none" ? verdict("No metadata in this file", NONE_TEXT)
    : meta.state === "unparsed" ? verdict("Metadata this tool does not read", UNPARSED_TEXT, "warn")
      : meta.gps?.placeholder ? verdict("Metadata found, with a position of 0, 0", "Many devices write 0, 0 when they have no fix. Treat it as a placeholder, not as where the picture was taken.")
        : verdict(meta.gps ? "Metadata found, with a position" : "Metadata found", meta.gps ? "The file names where it was taken. A position is what the file says: it can be edited, and a phone may write its last known fix." : POSITION_TEXT[meta.position] || POSITION_TEXT.unknown, meta.gps ? "ok" : "");
  const camera = kv([["Make", m.make], ["Model", m.model], ["Lens", m.lens], ["Software", m.software], ["Owner name", m.owner], ["Serial number", m.serial], ["Artist", m.artist], ["Copyright", m.copyright], ["Description", m.description], ["Comment", m.comment], ["Comment in the file", m.fileComment]]);
  const dates = kv([["Taken", date(m.dateOriginal, m.offsetOriginal)], ["Digitized", date(m.dateDigitized, m.offsetDigitized)], ["Modified", date(m.dateModified, m.offsetModified)]]);
  const resized = m.exifWidth && meta.width && (m.exifWidth !== meta.width || m.exifHeight !== meta.height);
  const shape = kv([["Orientation", m.orientation ? `${m.orientationText} (value ${m.orientation})` : ""], ["Size in the Exif block", m.exifWidth ? `${fmtNum(m.exifWidth)} by ${fmtNum(m.exifHeight)} pixels` : ""]]);
  const g = meta.gps;
  const place = g ? (g.placeholder ? h`<p class="muted small">${PLACEHOLDER_NOTE}</p>` : "") + positionHtml(g.lat, g.lon) + (g.coarse ? h`<p class="muted small">${COARSE_NOTE}</p>` : "") + kv([["Altitude", g.altitude !== null ? `${g.altitude} m ${g.altitude < 0 ? "below" : "above"} sea level` : ""], ["GPS time", g.time], ["Facing", g.direction ? `${g.direction.degrees}° from ${g.direction.ref}` : ""], ["Datum", g.datum]])
    + `<p class="muted small">GPS time is the satellite clock, in UTC. It can differ from the camera's own date above, which is the camera's local clock.</p>` : "";
  return head + fileCard
    + (place ? card("Position", tag("GPS", "ok"), place) : "")
    + (camera ? card("Camera and software", "", camera) : "")
    + (dates ? card("Dates", "", dates + `<p class="muted small">These are the clock of the camera or of the software that saved the file. A date with no time zone is local time wherever the clock was set.</p>`) : "")
    + (shape ? card("Orientation and size", resized ? tag("resized") : "", shape + (resized ? h`<p class="muted small">The Exif block and the image disagree about the size, so the image was resized or cropped after it was taken.</p>` : "")) : "")
    + (meta.text.length ? card("Text in the file", tag(String(meta.text.length)), `<dl class="kv">${meta.text.map((t) => h`<dt>${t.k}</dt><dd>${t.v}</dd>`).join("")}</dl>` + (meta.textMore > 0 ? h`<p class="muted small">And ${fmtNum(meta.textMore)} more text ${meta.textMore === 1 ? "chunk that is" : "chunks that are"} not shown.</p>` : "")) : "")
    + problems
    + (meta.notes.length ? card("Also in the file", "", `<ul class="img-list">${meta.notes.map((p) => h`<li>${p}</li>`).join("")}</ul>`) : "");
}

// ---- the page ---------------------------------------------------------------------------------------
const outBox = () => $("#imgOut");
let seq = 0;
async function readFile(file) {
  if (!file) return;
  const mine = ++seq, out = outBox();
  const about = { name: String(file.name || "file"), size: Number(file.size) || 0, lastModified: file.lastModified };
  if (about.size > MAX_IMAGE_BYTES) { out.innerHTML = verdict("That file is too large to read here", `The limit is 64 MB and this file is ${fmtSize(about.size)}. It was not read.`, "warn"); return; }
  out.innerHTML = `<p class="dec-wait" role="status">Reading the file in this browser…</p>`;
  let bytes;
  try { bytes = new Uint8Array(await file.arrayBuffer()); } catch { if (mine === seq) out.innerHTML = verdict("The browser could not read that file", "Nothing was read. Pick the file again.", "warn"); return; }
  if (mine !== seq) return;
  const meta = readImageMeta(bytes);
  let sha = "";
  try { sha = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((b) => b.toString(16).padStart(2, "0")).join(""); } catch { /* no hash on an insecure origin */ }
  if (mine !== seq) return;
  out.innerHTML = renderImage(about, meta, sha);
}
if (globalThis.document && $("#imgFile")) {
  const input = $("#imgFile"), drop = $("#imgDrop"), page = $("#imagemeta");
  // The value is cleared so that picking the same file again reads it again.
  input.addEventListener("change", () => { const f = input.files?.[0]; input.value = ""; readFile(f); });
  // A file dropped anywhere on the tool is read here. Without this the browser would open it.
  page.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  page.addEventListener("dragleave", (e) => { if (!page.contains(e.relatedTarget)) drop.classList.remove("over"); });
  page.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); readFile(e.dataTransfer?.files?.[0]); });
  $("#imgClear").addEventListener("click", () => { seq++; input.value = ""; outBox().innerHTML = $("#imgEmptyTpl").innerHTML; input.focus(); });
}
