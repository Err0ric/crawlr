// AI responses: normalization (the backend sometimes returns fenced JSON in
// `summary`) and a single small markdown renderer used for every report.
import { h, raw, esc, link } from "./core.js";

export function normalizeAi(data) {
  let summary = String(data?.summary ?? data?.full_report ?? "");
  let bullets = Array.isArray(data?.short_summary) ? data.short_summary : [];
  const fenced = summary.match(/```(?:json)?\s*([\s\S]*?)```/);
  const body = (fenced ? fenced[1] : summary).trim();
  if (body.startsWith("{")) {
    try {
      const j = JSON.parse(body);
      if (Array.isArray(j.short_summary)) bullets = j.short_summary;
      summary = String(j.full_report ?? j.summary ?? summary);
    } catch { /* leave as text */ }
  }
  return { ...data, summary: summary.replace(/```(?:json|markdown)?/g, "").trim(), short_summary: bullets.map(String) };
}

const inline = (s) =>
  esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/(?<![\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, "<em>$1</em>")
    .replace(/\bhttps?:\/\/[^\s)<]+/g, (u) => link(u, u));

const confClass = (cell) => { const t = cell.toLowerCase(); return t.includes("high") ? "conf-high" : t.includes("medium") ? "conf-medium" : t.includes("low") ? "conf-low" : ""; };

// Supports: ## / ### / **Heading** lines, bullets (- * • →), pipe tables, paragraphs,
// and "search query" lead lines (→ or lines inside the "ready-to-use" section) rendered with a copy button.
export function markdown(md) {
  const lines = String(md || "").replace(/\r/g, "").split("\n");
  const out = [];
  let para = [], ul = [], table = [], inLeads = false;
  const flushP = () => { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } };
  const flushUl = () => { if (ul.length) { out.push(`<ul>${ul.map((x) => `<li>${x}</li>`).join("")}</ul>`); ul = []; } };
  const flushTable = () => {
    if (!table.length) return;
    const rows = table.filter((r) => !/^\s*\|?\s*:?-{2,}/.test(r)).map((r) => r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim()));
    const [head, ...body] = rows;
    out.push(`<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead><tbody>${body.map((r) => `<tr>${r.map((c) => `<td class="${confClass(c)}">${inline(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`);
    table = [];
  };
  const flushAll = () => { flushP(); flushUl(); flushTable(); };

  for (let raw0 of lines) {
    const t = raw0.trim();
    if (!t) { flushAll(); continue; }
    let m;
    if ((m = t.match(/^#{1,4}\s+(.+)/)) || (m = t.match(/^\*\*([^*]{3,60})\*\*:?$/))) {
      flushAll();
      const title = m[1].replace(/\*\*/g, "").replace(/:$/, "");
      inLeads = /search|quer|dork|lead/i.test(title);
      out.push(`<h3>${esc(title)}</h3>`);
      continue;
    }
    if (/^\|/.test(t)) { flushP(); flushUl(); table.push(t); continue; }
    flushTable();
    if ((m = t.match(/^(?:[-*•]|→|\d+[.)])\s+(.+)/))) {
      flushP();
      const body = m[1];
      if (inLeads || /^→/.test(t) || /^`[^`]+`$/.test(body)) {
        const q = body.replace(/^`|`$/g, "");
        ul.push(`<div class="lead"><code>${esc(q)}</code><button class="btn btn-sm" type="button" data-copy="${esc(q)}">Copy</button></div>`);
      } else ul.push(inline(body));
      continue;
    }
    flushUl();
    para.push(t);
  }
  flushAll();
  return out.join("");
}

export function summaryBlock(ai, opts = {}) {
  const bullets = ai.short_summary?.length ? ai.short_summary : [];
  const meta = [ai.model, ai.tokens ? `${Number(ai.tokens).toLocaleString()} tokens` : "", ai.elapsed ? `${Number(ai.elapsed).toFixed(1)}s` : "", ai.cached ? "cached" : "", ai.ai_source === "house" ? "free tier" : ""].filter(Boolean).join(" · ");
  return h`
    <div class="ai-summary card">
      ${bullets.length ? raw(`<ul>${bullets.map((b) => `<li>${inline(b)}</li>`).join("")}</ul>`) : raw(`<div class="report">${markdown(ai.summary).slice(0, 2000)}</div>`)}
      <div class="ai-meta">${meta}</div>
      ${opts.reportId ? raw(h`<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn btn-sm" type="button" data-open-report="${opts.reportId}">Full report</button>${opts.deepDive ? raw(opts.deepDive) : ""}</div>`) : ""}
    </div>`;
}

// Delegated handler for copy buttons inside rendered reports.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500); });
});
