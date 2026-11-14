// AI responses: normalization (the backend sometimes returns fenced JSON in
// `summary`) and a single small markdown renderer used for every report.
import { h, raw, esc, link, post, toast, userAiKey, freeLeft, aiAvailable, aiCost } from "./core.js";
import { openModal, closeModal } from "./ui.js";

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

export const inline = (s) =>
  esc(s)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/(?<![\w*])\*(?!\s)([^*]+?)\*(?!\w)/g, "<em>$1</em>")
    .replace(/\bhttps?:\/\/[^\s)<]+/g, (u) => link(u, u));

// Only color cells that ARE a confidence value ("High", "medium-high", "Low (unverified)"),
// not any cell that happens to contain the letters ("followers", "highlights").
const confClass = (cell) => {
  const m = String(cell).trim().toLowerCase().match(/^(high|medium|low)\b/);
  return m ? `conf-${m[1]}` : "";
};

// Supports: ## / ### / **Heading** lines, bullets (- * • →), pipe tables, paragraphs,
// and "search query" lead lines (→ or lines inside the "ready-to-use" section) rendered with a copy button.
export function markdown(md) {
  const lines = String(md || "").replace(/\r/g, "").split("\n");
  const out = [];
  let para = [], ul = [], table = [];
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
      out.push(`<h3>${esc(title)}</h3>`);
      continue;
    }
    if (/^\|/.test(t)) { flushP(); flushUl(); table.push(t); continue; }
    flushTable();
    if ((m = t.match(/^(?:[-*•]\s+|→\s*|\d+[.)]\s+)(.+)/))) {
      flushP();
      const body = m[1];
      if (/^`[^`]+`$/.test(body)) {
        // a bare query on its own line: show it as a copyable block
        const q = body.replace(/^`|`$/g, "");
        ul.push(`<div class="lead"><code>${esc(q)}</code><button class="btn btn-sm" type="button" data-copy="${esc(q)}">Copy</button></div>`);
      } else {
        // prose lead: render normally, and add a copy button for the first query in backticks
        const q = body.match(/`([^`]+)`/);
        ul.push(inline(body) + (q ? ` <button class="btn btn-sm lead-copy" type="button" data-copy="${esc(q[1])}">Copy query</button>` : ""));
      }
      continue;
    }
    flushUl();
    para.push(t);
  }
  flushAll();
  return out.join("");
}

// Split a "## Heading" markdown report into [{title, md}] for tabbed display.
export function splitSections(md) {
  const out = [];
  let cur = null;
  for (const line of String(md || "").split("\n")) {
    const m = line.match(/^#{1,3}\s+(.+)/);
    if (m) { cur = { title: m[1].replace(/\*\*/g, "").trim(), md: "" }; out.push(cur); }
    else if (cur) cur.md += line + "\n";
    else if (line.trim()) { cur = { title: "", md: line + "\n" }; out.push(cur); }
  }
  return out;
}

export function summaryBlock(ai, opts = {}) {
  const bullets = ai.short_summary?.length ? ai.short_summary : [];
  const meta = [ai.model, ai.tokens ? `${Number(ai.tokens).toLocaleString()} tokens` : "", ai.elapsed ? `${Number(ai.elapsed).toFixed(1)}s` : "", ai.cached ? "cached" : "", ai.ai_source === "house" ? "free tier" : ""].filter(Boolean).join(" · ");
  return h`
    <div class="ai-summary card">
      ${bullets.length ? raw(`<ul>${bullets.map((b) => `<li>${inline(b)}</li>`).join("")}</ul>`) : raw(`<div class="report">${markdown(ai.summary).slice(0, 2000)}</div>`)}
      <div class="ai-meta">${meta}</div>
      ${opts.reportId ? raw(`<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap"><button class="btn btn-sm" type="button" ${opts.attr || "data-open-report"}="${esc(opts.reportId)}">Full report</button>${opts.deepDive || ""}</div>`) : ""}
    </div>`;
}

// Delegated handler for copy buttons inside rendered reports.
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-copy]");
  if (!b) return;
  navigator.clipboard?.writeText(b.dataset.copy).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1500); });
});

// ---- the AI panel before a report exists ------------------------------------------------
// Two ways to get a written report, neither automatic:
//   1. "Analyze with AI": one click, uses a free credit or the user's key, cost stated first.
//   2. "Copy prompt": no key at all. The prompt (instructions plus the collected findings) is
//      copied for the user to paste into an assistant they already use, and the reply can be
//      pasted back to get the same formatted report.
// idp prefixes the element ids so Investigate and Recon can both have a panel.
export function aiStartHtml(idp, pitch) {
  const can = aiAvailable();
  const out = can && !userAiKey() && freeLeft() <= 0;
  return h`<p class="ai-pitch">${pitch}</p>
    ${raw(can ? h`<button class="btn btn-primary btn-block" type="button" id="${idp}AiRun" ${out ? "disabled" : ""}>Analyze with AI</button><p class="ai-cost">${aiCost()}</p>` : "")}
    <div class="keyless">
      <p class="keyless-h">${can ? "Or use your own assistant" : "Use your own assistant, no key needed"}</p>
      <button class="btn btn-block" type="button" id="${idp}AiCopy">Copy prompt</button>
      <p class="ai-cost">Paste it into Claude, ChatGPT, Gemini or any assistant you already use. The prompt contains the findings on this page.</p>
      <details class="more"><summary>Paste the reply back to format it</summary>
        <label class="sr-only" for="${idp}AiPaste">Reply from your assistant</label>
        <textarea class="textarea" id="${idp}AiPaste" name="ai-reply" rows="5" placeholder="Paste the assistant's reply here" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other"></textarea>
        <button class="btn btn-sm mt" type="button" id="${idp}AiPasteGo">Format reply</button>
      </details>
    </div>
    ${raw(can ? "" : `<p class="ai-cost">For one-click analysis, <button class="linklike" type="button" data-open-settings>add a key in Settings</button>.</p>`)}`;
}

// Fetch the prompt and put it on the clipboard. If the browser refuses (some block clipboard
// writes after a network round trip), show it in a dialog to copy by hand.
export async function copyPrompt(url, payload) {
  let prompt;
  try { prompt = (await post(url, payload)).prompt; }
  catch (err) { toast(err.detail || err.message, 5000); return false; }
  try { await navigator.clipboard.writeText(prompt); toast("Prompt copied. Paste it into your assistant.", 4000); return true; }
  catch {
    openModal({ title: "Copy this prompt", wide: true,
      body: h`<p class="modal-p">Your browser blocked automatic copying. Select all of this and copy it.</p><label class="sr-only" for="promptText">Prompt</label><textarea class="textarea mono" id="promptText" name="ai-prompt" rows="14" readonly autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" data-1p-ignore data-lpignore="true" data-bwignore data-form-type="other">${prompt}</textarea>`,
      focus: "#promptText",
      actions: [{ label: "Close", primary: true, onClick: closeModal }] });
    document.getElementById("promptText")?.select();
    return true;
  }
}
export async function parseReply(text) {
  if (!String(text || "").trim()) { toast("Paste the assistant's reply first."); return null; }
  try { return normalizeAi(await post("/api/analyze/parse", { text })); }
  catch (err) { toast(err.detail || err.message, 5000); return null; }
}
