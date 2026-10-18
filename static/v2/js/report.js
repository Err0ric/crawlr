// Investigation report: dossier card on top, then one scrolling report.
// Everything the model says is escaped through markdown()/inline(); account tiles and
// avatars come from collected data, never from the model.
import { h, raw, esc, safeUrl } from "./core.js";
import { markdown, splitSections, inline } from "./ai.js";

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

// Favicon with a letter fallback (the <img> is removed on error by the delegated handler below).
const icon = (name, url) => {
  const d = host(url);
  return `<span class="ic" aria-hidden="true"><span class="ic-l">${esc(initials(name))}</span>${d ? `<img src="https://icons.duckduckgo.com/ip3/${esc(d)}.ico" alt="" loading="lazy" referrerpolicy="no-referrer">` : ""}</span>`;
};
document.addEventListener("error", (e) => { if (e.target?.matches?.(".ic img, .dossier .avatar img")) e.target.remove(); }, true);

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
  return `<div class="fields">${rows.map(([k = "", v = "", c = "", e = ""]) => `<div class="field"><div class="k">${inline(k)}${conf(c)}</div><div class="v">${inline(v)}</div>${e ? `<div class="e">${inline(e)}</div>` : ""}</div>`).join("")}</div>` + markdown(notTable(md));
}

// Account tiles from evidence; the AI footprint table only adds the "why it matters" note.
function accountTiles(accounts, footprintMd) {
  const why = new Map();
  for (const [p = "", , , w = ""] of (parseTable(footprintMd) || []).slice(1)) why.set(normSite(p), w);
  const keyed = (a) => why.get(normSite(a.what)) || why.get(normSite(a.key.slice(5)));
  const sorted = [...accounts].sort((a, b) => (!!keyed(b) - !!keyed(a)) || (a.tier === "confirmed" ? -1 : 1) - (b.tier === "confirmed" ? -1 : 1));
  const tiles = sorted.map((a) => {
    const w = keyed(a);
    return h`<a class="tile ${a.tier === "confirmed" ? "c" : "l"}${w ? " key" : ""}" href="${su(a.url) || "#"}" target="_blank" rel="noopener noreferrer" title="${short(a.url)} · ${(a.sources || [a.source]).join(", ")}">${raw(icon(a.what, a.url))}<span class="n">${a.what}</span><span class="s">${w || (a.sources || [a.source]).join(", ")}</span></a>`;
  }).join("");
  const nC = accounts.filter((a) => a.tier === "confirmed").length;
  return `<div class="grid-legend"><span class="c">Confirmed ${nC}</span><span class="l">Likely ${accounts.length - nC}</span>${why.size ? `<span class="k">Key accounts first</span>` : ""}</div><div class="tiles">${tiles}</div>`
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
    const btn = (b, primary) => b.href ? `<a class="btn btn-sm${primary ? " btn-primary" : ""}" href="${esc(su(b.href) || "#")}" target="_blank" rel="noopener noreferrer">${esc(b.label)}</a>`
      : `<button type="button" class="btn btn-sm${primary ? " btn-primary" : ""}" data-pivot="${esc(b.mode)}" data-value="${esc(b.value)}">${esc(b.label)}</button>`;
    const acts = p ? [btn(p, p.primary), p.secondary ? btn(p.secondary) : "", p.copy ? `<button type="button" class="btn btn-sm btn-ghost" data-copy="${esc(p.copy)}">Copy</button>` : ""].join("") : "";
    return `<li class="pivot"><span class="rank">${i + 1}</span><div class="t">${inline(t)}</div>${acts ? `<div class="acts">${acts}</div>` : ""}</li>`;
  }).join("")}</ol>`;
}

function dossier({ target, profile = {}, facts, accounts, collected }) {
  const fact = (k) => facts.find((f) => f.k === k)?.v || "";
  const name = profile.name || fact("Name");
  const loc = profile.location || fact("Location");
  const gh = collected.github?.found ? collected.github : null;
  const avatar = su(gh?.avatar_url || (collected.gravatar?.found && collected.gravatar.avatar_url) || "");
  const since = gh?.created_at ? String(gh.created_at).slice(0, 10) : "";
  const line = [name ? `likely <b>${esc(name)}</b>` : "", loc ? esc(loc) : "", since ? `on GitHub since ${esc(since)}` : ""].filter(Boolean).join(" · ");
  const tags = profile.interests || [];
  const exp = profile.exposure;
  const lvl = { Low: 1, Medium: 2, High: 3 }[exp] || 0;
  const confirmed = accounts.filter((a) => a.tier === "confirmed");
  const chips = confirmed.slice(0, 14).map((a) => `<a class="chip" href="${esc(su(a.url) || "#")}" target="_blank" rel="noopener noreferrer" title="${esc(a.what)}">${icon(a.what, a.url)}</a>`).join("");
  return `<div class="dossier">
    <div class="avatar">${avatar ? `<img src="${esc(avatar)}" alt="" referrerpolicy="no-referrer">` : ""}<span>${esc(initials(name || target))}</span></div>
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

const TITLE = { identity: "Identity", accounts: "Accounts", leads: "Next moves", exposure: "Exposure and risk", gaps: "Gaps", active: "Active techniques" };

export function reportHtml({ ai, target, items, facts, collected }) {
  const accounts = items.filter((i) => i.url && i.key?.startsWith("acct:") && (i.tier === "confirmed" || i.tier === "likely"));
  const parts = splitSections(ai.summary);
  if (parts.length < 2) return dossier({ target, profile: ai.profile, facts, accounts, collected }) + `<div class="report-scroll">${markdown(ai.summary)}</div>`;
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

  const jump = `<nav class="jump" aria-label="Report sections"><span>Jump to</span>${secs.map((s) => `<a href="#rs-${s.id}" data-jump>${esc(s.title.replace(/ \(\d+\)$/, ""))}</a>`).join("")}</nav>`;
  return dossier({ target, profile: ai.profile, facts, accounts, collected })
    + `<div class="report-scroll">${jump}${by.summary ? `<div class="report-lead">${markdown(by.summary)}</div>` : ""}${secs.map((s) => s.html).join("")}</div>`;
}

// In-page jump links (the page uses hash routing, so don't touch location.hash).
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-jump]"); if (!a) return;
  e.preventDefault(); document.querySelector(a.getAttribute("href"))?.scrollIntoView({ behavior: "smooth", block: "start" });
});
