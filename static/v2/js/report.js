// Investigation report: dossier card on top, then one scrolling report.
// Everything the model says is escaped through markdown()/inline(); account tiles and
// avatars come from collected data, never from the model.
import { h, raw, esc, safeUrl, link, mark } from "./core.js";
import { UNVERIFIED_TEXT, checkText } from "./links.js";
import { markdown, splitSections, inline } from "./ai.js";
import { adultListHtml, splitAdultProse, ADULT_SECTION, adultHost } from "./adult.js";
import { rowCertainty, certaintyOf, mayFavicon } from "./present.js";
import { NAME_NOTICE } from "./names.js";
import { evWhat } from "./workbench.js";

const SECTION = {
  "case summary": "summary", "identity assessment": "identity", "platform footprint": "footprint",
  "exposure and risk": "exposure", "investigative leads": "leads", "gaps and next pivots": "gaps", "active techniques": "active",
};
// safeUrl("") resolves to the site root, so blank stays blank.
const su = (u) => (u ? safeUrl(u) : "");
const kind = (t) => SECTION[String(t).toLowerCase().trim()] || "other";
const host = (u) => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; } };
const short = (u) => String(u).replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, "");
const initials = (s) => (String(s).replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).map((w) => w[0]).join("").slice(0, 2) || "?").toUpperCase();
const normSite = (s) => String(s).toLowerCase().replace(/\(.*?\)/g, "").replace(/[^a-z0-9]/g, "");

// Favicon with a letter fallback: the one site mark helper in core.js.
// Asked for by registrable domain only, never for a case opened from a case file (see present.js).
let iconOpts = { imported: false, handle: "" };
const icon = (a, url = a?.url) => mark(a.what, { url: a.link_kind === "none" ? "" : url, handle: iconOpts.handle, favicon: mayFavicon(a, iconOpts) && !adultHost(url), cls: "fav" });

// "| a | b |" markdown table -> rows of cells (header first), or null.
function parseTable(md) {
  const rows = String(md).split("\n").map((l) => l.trim()).filter((l) => l.startsWith("|") && !/^\|?\s*:?-{2,}/.test(l))
    .map((l) => l.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
  return rows.length > 1 ? rows : null;
}
const notTable = (md) => String(md).split("\n").filter((l) => !l.trim().startsWith("|")).join("\n");
const confKey = (c) => (String(c).trim().toLowerCase().match(/^(high|medium|low)/) || [])[1] || "";
const conf = (c) => { const k = confKey(c); return k ? `<span class="conf ${k}">${esc(k[0].toUpperCase() + k.slice(1))}</span>` : ""; };

function identityFields(md) {
  const t = parseTable(md);
  if (!t) return markdown(md);
  const [, ...rows] = t;
  return `<div class="idfs">${rows.map(([k = "", v = "", c = "", e = ""]) => `<div class="idf"><div class="k">${inline(k)}${conf(c)}</div><div class="v">${inline(v)}</div>${e ? `<div class="e">${inline(e)}</div>` : ""}</div>`).join("")}</div>` + markdown(notTable(md));
}

const RANK = { linked: 0, matches: 1, unverified: 2, different: 3 };
const TIER_WORD = { linked: "Linked", matches: "Exists (matches)", different: "Exists (different person)", unverified: "Unverified" };
// Account tiles from evidence; the AI footprint table only adds the "why it matters" note.
function accountTiles(accounts, footprintMd) {
  const why = new Map();
  for (const [p = "", , , w = ""] of (parseTable(footprintMd) || []).slice(1)) why.set(normSite(p), w);
  const keyed = (a) => why.get(normSite(a.what)) || why.get(normSite(a.key.slice(5)));
  const sorted = [...accounts].sort((a, b) => (!!keyed(b) - !!keyed(a)) || RANK[a.tier] - RANK[b.tier]);
  const tiles = sorted.map((a) => {
    // A profile added from a similar handle is not the row the model's table is about.
    const w = a.similar ? "" : keyed(a);
    // A tile for another person's account says whose name is on it, whatever the model wrote. One
    // under another handle says which, and a taken handle says that nothing was read.
    const sub = a.tier === "different" ? `different person: ${a.person || "another name"}` : a.similar ? `under the handle ${a.similar.variant}` : a.taken ? "handle taken, owner unknown" : w || (a.sources || [a.source]).join(", ");
    // A tile is a link only when the row has a usable URL. An unchecked URL says so on the tile.
    const href = a.link_kind === "none" ? "" : su(a.url);
    const unv = a.link_kind === "templated_unverified";
    // The same grammar as the ledger: tier color on the edge, dashed when nothing read or checked it.
    const cert = rowCertainty(a);
    const cls = `tile${cert.tone ? ` tone-${cert.tone}` : ""}${cert.line === "dashed" ? " line-dashed" : ""}${w && a.tier !== "different" ? " key" : ""}${a.gone ? " gone" : ""}`;
    const inner = h`${raw(icon(a, a.url || a.checked_url))}<span class="n">${a.what}</span><span class="s">${sub}</span>${unv ? raw(`<span class="s lk-flag">(${UNVERIFIED_TEXT})</span>`) : ""}${checkText(a) ? raw(h`<span class="s">${checkText(a)}</span>`) : ""}`;
    if (!href) return h`<div class="${cls}" title="${TIER_WORD[a.tier]} · no public page · ${(a.sources || [a.source]).join(", ")}">${raw(inner)}</div>`;
    return h`<a class="${cls}" href="${href}" target="_blank" rel="noopener noreferrer nofollow" data-link-kind="${a.link_kind || ""}" title="${TIER_WORD[a.tier]} · ${short(a.url)} · ${(a.sources || [a.source]).join(", ")}">${raw(inner)}<span class="sr-only"> (opens in a new tab)</span></a>`;
  }).join("");
  const n = (t) => accounts.filter((a) => a.tier === t).length;
  const legend = ["linked", "matches", "different", "unverified"].filter((t) => n(t)).map((t) => { const c = certaintyOf(t); return `<span class="cp tone-${c.tone}${c.line === "dashed" ? " line-dashed" : ""}">${esc(c.word)} ${n(t)}</span>`; }).join("");
  return `<div class="grid-legend">${legend}${why.size ? `<span class="lg-note">Key accounts first</span>` : ""}</div><div class="tiles">${tiles}</div>`
    + (footprintMd ? markdown(notTable(footprintMd)) : "");
}

// Leads: one card per line, with a pivot button when the line names something CrawlR can run.
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/;
const DOMAIN = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i;
const PLATFORM_HOSTS = /(github|gitlab|twitter|x|instagram|facebook|youtube|reddit|tiktok|twitch|steam(community)?|linkedin|hackerone|bsky|threads|discord|medium|google|bing|duckduckgo|archive|web\.archive|huggingface|itch|keybase)\.(com|net|tv|app|io|org|co|gg|in)$/i;
function pivotFor(text) {
  const q = (text.match(/`([^`]+)`/) || [])[1];
  const email = (text.match(EMAIL) || [])[0];
  if (email) return { label: "Run in Investigate", mode: "investigate", value: email, primary: true };
  const url = (text.match(/https?:\/\/[^\s)`]+/) || [])[0];
  if (q && !/^https?:/.test(q)) {
    const bare = q.replace(/^@/, "");
    if (/^[\w.-]{3,40}$/.test(bare) && !bare.includes(".")) return { label: "Run in Investigate", mode: "investigate", value: bare, primary: true, copy: q };
    if (DOMAIN.test(bare) && /^[\w.-]+$/.test(bare) && !PLATFORM_HOSTS.test(bare)) return { label: "Run in Recon", mode: "recon", value: bare, primary: true };
    return { label: "Search Google", href: `https://www.google.com/search?q=${encodeURIComponent(q)}`, copy: q };
  }
  if (url) { const d = host(url); if (d && !PLATFORM_HOSTS.test(d)) return { label: "Run in Recon", mode: "recon", value: d, primary: true, secondary: { label: "Open", href: url } }; return { label: "Open", href: url }; }
  return null;
}
function leadCards(md) {
  const items = String(md).split("\n").map((l) => l.trim()).map((l) => (l.match(/^(?:[-*•]\s+|→\s*|\d+[.)]\s+)(.+)/) || [])[1]).filter(Boolean);
  if (!items.length) return markdown(md);
  return `<ol class="pivots">${items.map((t, i) => {
    const p = pivotFor(t);
    const btn = (b, primary) => b.href ? link(b.href, b.label, `btn btn-sm${primary ? " btn-primary" : ""}`)
      : `<button type="button" class="btn btn-sm${primary ? " btn-primary" : ""}" data-pivot="${esc(b.mode)}" data-value="${esc(b.value)}">${esc(b.label)}</button>`;
    const acts = p ? [btn(p, p.primary), p.secondary ? btn(p.secondary) : "", p.copy ? `<button type="button" class="btn btn-sm btn-ghost" data-copy="${esc(p.copy)}">Copy</button>` : ""].join("") : "";
    return `<li class="pivot"><span class="rank">${i + 1}</span><div class="t">${inline(t)}</div>${acts ? `<div class="acts">${acts}</div>` : ""}</li>`;
  }).join("")}</ol>`;
}

function dossier({ target, profile = {}, facts, accounts, collected }) {
  const fact = (k) => facts.find((f) => f.k === k)?.v || "";
  const name = profile.name || fact("Name");
  const loc = profile.location || fact("Location");
  const gh = collected.github?.found && !collected.github.error ? collected.github : null;
  const since = gh?.created_at ? String(gh.created_at).slice(0, 10) : "";
  const line = [name ? `likely <b>${esc(name)}</b>` : "", loc ? esc(loc) : "", since ? `on GitHub since ${esc(since)}` : ""].filter(Boolean).join(" · ");
  const tags = profile.interests || [];
  const exp = profile.exposure;
  const lvl = { Low: 1, Medium: 2, High: 3 }[exp] || 0;
  // Only accounts tied to the primary identity, or consistent with it, sit beside its name.
  // A profile added from a similar handle is a row of the case, never part of the identity shown here.
  const confirmed = accounts.filter((a) => (a.tier === "linked" || a.tier === "matches") && !a.similar);
  // Linked and matching accounts were read, so their URLs came from the source. One with no public page is not a link.
  const chips = confirmed.slice(0, 14).map((a) => (a.link_kind !== "none" && su(a.url) ? `<a class="chip" href="${esc(su(a.url))}" target="_blank" rel="noopener noreferrer nofollow" title="${esc(a.what)}">${icon(a)}<span class="sr-only">${esc(a.what)} (opens in a new tab)</span></a>` : `<span class="chip" title="${esc(a.what)}">${icon(a, "")}<span class="sr-only">${esc(a.what)}</span></span>`)).join("");
  // The picture is the server-made thumbnail of a linked account, or initials. Never a remote image.
  // Never the picture of a profile added from a similar handle: that one is under another handle.
  const thumb = accounts.find((a) => a.tier === "linked" && a.thumb && !a.similar)?.thumb || "";
  return `<div class="dossier">
    ${mark(name || target, { thumb, cls: "avatar" })}
    <div class="who">
      <div class="handle">${esc(target)}</div>
      ${line ? `<div class="line">${line}</div>` : `<div class="line muted">No name or location in the collected data</div>`}
      ${tags.length ? `<div class="tags">${tags.map((t) => `<span class="tag">${esc(t)}</span>`).join("")}</div>` : ""}
    </div>
    ${lvl ? `<div class="opsec ${exp.toLowerCase()}">
      <div class="k">OPSEC exposure</div>
      <div class="meter" role="img" aria-label="${esc(exp)} exposure">${[1, 2, 3].map((i) => `<span class="${i <= lvl ? "on" : ""}"></span>`).join("")}</div>
      <div class="v">${esc(exp)}</div>
      ${profile.exposure_reason ? `<div class="why">${esc(profile.exposure_reason)}</div>` : ""}
    </div>` : ""}
    ${accounts.length ? `<div class="seen"><span class="k">Seen on</span>${chips}${accounts.length > Math.min(confirmed.length, 14) ? `<a class="more" href="#rs-accounts" data-jump>+${accounts.length - Math.min(confirmed.length, 14)} more</a>` : ""}</div>` : ""}
  </div>`;
}

const TITLE = { identity: "Identity", accounts: "Accounts", leads: "Next moves", exposure: "Exposure and risk", gaps: "Gaps", active: "Active techniques", adult: ADULT_SECTION };

// A name case has no dossier: nobody is selected, so there is no name, picture or account grid.
// The caveat comes first, then what the model wrote, then the candidates as the ledger lists them.
function nameReport({ ai, items }) {
  const rows = (tier) => items.filter((i) => i.tier === tier);
  const sec = (id, title, list) => (list.length ? `<section class="rsec" id="rs-${id}"><h3>${esc(title)} (${list.length})</h3><ul>${list.map((i) => h`<li>${raw(evWhat(i))} <span class="dim small">${i.source}</span></li>`).join("")}</ul></section>` : "");
  return h`<div class="notice" role="note">${NAME_NOTICE}</div>`
    + `<div class="report-scroll">${markdown(splitAdultProse(ai.summary).rest)}${sec("notable", "Public figure", rows("notable"))}${sec("people", "People with this name", rows("people"))}</div>`;
}

export function reportHtml({ ai, target, items, facts, collected, type = "", imported = false }) {
  iconOpts = { imported: !!imported, handle: type === "username" ? String(target || "").replace(/^@/, "") : "" };
  if (type === "name" || items.some((i) => i.tier === "people" || i.tier === "websearch")) return nameReport({ ai, items });
  // Every account row, with or without a URL: a row with no public page is a tile, not a link.
  const accounts = items.filter((i) => i.key?.startsWith("acct:") && i.tier in RANK);
  // Adult and dating site rows are in the items only when the case had that mode on. They get
  // their own last section, as text: no tile, no favicon, no picture.
  const adult = items.filter((i) => i.tier === "adult");
  const adultHtml = adultListHtml(adult);
  // Every section of the report that is about adult or dating sites, however its heading is
  // worded and however many there are, is taken out before anything is rendered. What is left of
  // them (lines with no address and no markup) is shown only in the one section below, and only
  // for a case that has adult rows: with the mode off nothing of them is shown at all.
  const { rest, prose } = splitAdultProse(ai.summary);
  const parts = splitSections(rest);
  if (parts.length < 2) return dossier({ target, profile: ai.profile, facts, accounts, collected }) + `<div class="report-scroll">${markdown(rest)}${adultHtml ? `<section class="rsec adult" id="rs-adult"><h3>${esc(ADULT_SECTION)}</h3>${adultHtml}${prose ? markdown(prose) : ""}</section>` : ""}</div>`;
  const by = {}; const other = [];
  for (const p of parts) { const k = kind(p.title); if (k === "other" || by[k]) other.push(p); else by[k] = p.md; }

  const secs = [];
  const sec = (id, inner, title = TITLE[id]) => inner && secs.push({ id, title, html: `<section class="rsec ${id}" id="rs-${id}"><h3>${esc(title)}</h3>${inner}</section>` });
  sec("identity", by.identity && identityFields(by.identity));
  sec("accounts", accounts.length ? accountTiles(accounts, by.footprint) : by.footprint && markdown(by.footprint), `Accounts (${accounts.length})`);
  sec("leads", by.leads && leadCards(by.leads));
  sec("exposure", by.exposure && markdown(by.exposure));
  sec("gaps", by.gaps && markdown(by.gaps));
  sec("active", by.active && markdown(by.active));
  other.forEach((p, i) => sec(`x${i}`, markdown(p.md), p.title || "Notes"));
  sec("adult", adult.length ? adultHtml + (prose ? markdown(prose) : "") : "");

  const jump = `<nav class="jump" aria-label="Report sections"><span>Jump to</span>${secs.map((s) => `<a href="#rs-${s.id}" data-jump>${esc(s.title.replace(/ \(\d+\)$/, ""))}</a>`).join("")}</nav>`;
  return dossier({ target, profile: ai.profile, facts, accounts, collected })
    + `<div class="report-scroll">${jump}${by.summary ? `<div class="report-lead">${markdown(by.summary)}</div>` : ""}${secs.map((s) => s.html).join("")}</div>`;
}

// In-page jump links (the page uses hash routing, so don't touch location.hash).
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-jump]"); if (!a) return;
  e.preventDefault(); document.querySelector(a.getAttribute("href"))?.scrollIntoView({ behavior: "smooth", block: "start" });
});
