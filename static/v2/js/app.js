// Entry point: navigation, landing, settings, history drawer, AI pill, terms.
import { $, $$, h, raw, esc, store, toast, looksLikeHeaders, refreshQuota, quota, aiLabel, aiAvailable, KEYS, getKey, setKey, getProvider, setProvider, detect, TYPE_LABEL, INVESTIGATE_TYPES, RECON_TYPES } from "./core.js";
import { openModal, closeModal, openDrawer, closeDrawer } from "./ui.js";
import { run, renderSources, loadHistory, getHistory, clearCase, exportCase, state } from "./investigate.js";
import * as recon from "./recon.js";
import * as tools from "./tools.js";

// ---- views ---------------------------------------------------------------------
const BENCHES = ["investigate", "recon"];
const TOOLS = ["headers", "dorks", "decoders"];
const VIEWS = [...BENCHES, ...TOOLS];
function show(view) {
  $("#landing").hidden = view !== "landing";
  VIEWS.forEach((b) => ($(`#${b}`).hidden = view !== b));
  $("#railToggle").hidden = !BENCHES.includes(view);
  $$(".nav a").forEach((a) => a.removeAttribute("aria-current"));
  $(`.nav a[data-mode="${view}"]`)?.setAttribute("aria-current", "page");
  if (view === "landing") setTimeout(() => $("#landingInput").focus(), 50);
  if (VIEWS.includes(view) && location.hash !== `#${view}`) history.replaceState(null, "", `${location.pathname}#${view}`);
  if (view === "headers") setTimeout(() => $("#hdrInput").focus(), 50);
  if (view === "dorks") setTimeout(() => $("#dkName").focus(), 50);
}
window.addEventListener("hashchange", () => { const v = location.hash.slice(1); if (VIEWS.includes(v)) show(v); });
document.addEventListener("click", (e) => { const g = e.target.closest("[data-goto]"); if (g) { e.preventDefault(); show(g.dataset.goto); } });
$("#brand").addEventListener("click", (e) => { e.preventDefault(); clearCase(); recon.clearCase(); show("landing"); history.replaceState(null, "", location.pathname); });
$$(".nav a[data-mode]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); show(a.dataset.mode); }));

// ---- landing -------------------------------------------------------------------
const detectBox = $("#landingDetect");
function describe(type) {
  if (!type) return "";
  if (type === "headers") return "Email headers. Will check SPF, DKIM and DMARC and trace the route.";
  if (type === "multi") return "Multiple targets. Run them one at a time for now.";
  if (RECON_TYPES.includes(type)) return `${TYPE_LABEL[type]}. Will run ${{ domain: "DNS, WHOIS, TLS, headers, subdomains, exposure and a port scan", ip: "TLS, headers, network owner, exposure and a port scan", asn: "registry, prefix and peering lookups" }[type]}.`;
  return `${TYPE_LABEL[type]}. Will run ${{ username: "Sherlock, Maigret, GitHub and platform checks", email: "Holehe, breaches, Gravatar, Sherlock and Maigret", hash: "MalwareBazaar, CIRCL, OTX and ThreatFox", phone: "carrier lookup", name: "people-search links" }[type]}.`;
}
$("#landingInput").addEventListener("input", (e) => { const t = detect(e.target.value); detectBox.innerHTML = t ? h`<span class="pill ${INVESTIGATE_TYPES.includes(t) || RECON_TYPES.includes(t) ? "violet" : ""}">${TYPE_LABEL[t]}</span><span>${describe(t).split(". ").slice(1).join(". ")}</span>` : ""; });
$("#landingForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#landingInput").value.trim(); if (!v) return;
  const t = detect(v);
  if (t === "headers") { show("headers"); tools.prefillHeaders(v); return; }
  if (t === "multi") { toast("One target at a time for now."); return; }
  if (RECON_TYPES.includes(t)) { show("recon"); recon.run(v); return; }
  $("#targetInput").value = v; onTargetInput();
  show("investigate");
  run(v);
});
// Pasted email headers lose their newlines in a one-line input, so catch the paste itself.
["#landingInput", "#targetInput"].forEach((sel) => $(sel).addEventListener("paste", (e) => {
  const text = e.clipboardData?.getData("text") || "";
  if (!looksLikeHeaders(text)) return;
  e.preventDefault();
  show("headers"); tools.prefillHeaders(text); toast("Those look like email headers. Analyzing them here.");
}));
$$(".ex").forEach((b) => b.addEventListener("click", () => { $("#landingInput").value = b.dataset.example; $("#landingForm").requestSubmit(); }));

// ---- rail (target + sources + run) ----------------------------------------------
let typeOverride = "";
function onTargetInput() {
  const v = $("#targetInput").value.trim();
  const detected = detect(v);
  const t = typeOverride || detected;
  renderSources(INVESTIGATE_TYPES.includes(t) ? t : "");
  const box = $("#targetDetected");
  if (!v) { box.innerHTML = ""; return; }
  const looksRecon = !typeOverride && RECON_TYPES.includes(detected);
  // Always offer the Investigate types so an ambiguous target ("john.dev") can be searched as a username.
  box.innerHTML = h`<span>${looksRecon ? `Looks like a ${TYPE_LABEL[detected].toLowerCase()}. Search it as:` : typeOverride ? "Treating as" : "Detected"}</span>
    <span class="seg" role="group" aria-label="Target type">${raw(INVESTIGATE_TYPES.map((o) => h`<button type="button" data-type="${o}" aria-pressed="${o === t}">${TYPE_LABEL[o]}</button>`).join(""))}</span>
    ${looksRecon ? raw(h`<span>or run it in <a href="#recon" data-goto="recon" data-carry="1">Recon</a></span>`) : ""}`;
}
$("#targetInput").addEventListener("input", () => { typeOverride = ""; onTargetInput(); });
$("#targetInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#runBtn").click(); });
$("#targetDetected").addEventListener("click", (e) => { const b = e.target.closest("[data-type]"); if (!b) return; typeOverride = b.dataset.type === detect($("#targetInput").value.trim()) ? "" : b.dataset.type; onTargetInput(); });
$("#runBtn").addEventListener("click", () => { $("#rail").classList.remove("open"); run($("#targetInput").value, typeOverride || undefined); });
$("#clearBtn").addEventListener("click", () => { clearCase(); typeOverride = ""; });
$("#exportBtn").addEventListener("click", exportCase);
$("#railToggle").addEventListener("click", () => $(".bench:not([hidden]) .rail")?.classList.toggle("open"));
// carry a domain/IP typed into Investigate over to Recon
document.addEventListener("click", (e) => { if (e.target.closest("[data-carry]")) { const v = $("#targetInput").value.trim(); $("#rTargetInput").value = v; $("#rTargetInput").dispatchEvent(new Event("input")); } });

// ---- AI pill + settings ----------------------------------------------------------------
function paintPill() {
  const { text, cls } = aiLabel();
  const pill = $("#aiPill"); pill.className = `pill ${cls}`; $("#aiPillText").textContent = text;
}
quota.listeners.add(paintPill);
$("#aiPill").addEventListener("click", openSettings);
$("#settingsBtn").addEventListener("click", openSettings);

function openSettings() {
  const prov = getProvider();
  const el = openDrawer({
    title: "Settings",
    body: h`
      <section>
        <h3 style="font-size:var(--fs-2);margin-bottom:6px">AI provider</h3>
        <p style="color:var(--ink-3);font-size:var(--fs-1);margin-bottom:10px">${quota.state.house_ai ? `Without your own key, analysis runs on the free tier (${quota.state.remaining?.analysis ?? 0} analyses and ${quota.state.remaining?.deepdive ?? 0} Deep Dive left today for you). Your own key removes the limits.` : "Add a Claude or Gemini key to turn on AI analysis and Deep Dive."}</p>
        <div class="seg" role="group" aria-label="Provider"><button type="button" data-prov="anthropic" aria-pressed="${prov === "anthropic"}">Claude</button><button type="button" data-prov="gemini" aria-pressed="${prov === "gemini"}">Gemini</button></div>
      </section>
      <section>
        <h3 style="font-size:var(--fs-2);margin-bottom:2px">Your keys</h3>
        <p style="color:var(--ink-3);font-size:var(--fs-0);margin-bottom:6px">Stored only in this browser. Each key is sent only to the service it belongs to.</p>
        ${raw(KEYS.map((k) => h`
          <div class="keyrow">
            <div class="top"><span class="name">${k.label}</span>${getKey(k.id) ? raw('<span class="tag ok">set</span>') : ""}<a href="${k.url}" target="_blank" rel="noopener noreferrer">${k.help}</a></div>
            <div style="display:flex;gap:6px"><input class="input mono" type="password" data-key="${k.id}" placeholder="${getKey(k.id) ? "••••••••••••" : k.placeholder}" autocomplete="off"><button class="btn btn-sm" type="button" data-clear="${k.id}" ${getKey(k.id) ? "" : "disabled"}>Clear</button></div>
          </div>`).join(""))}
      </section>
      <section>
        <h3 style="font-size:var(--fs-2);margin-bottom:6px">Interface</h3>
        <p style="color:var(--ink-3);font-size:var(--fs-1)">The <a href="/classic">classic interface</a> is still available for a few weeks if you need something from it.</p>
      </section>`,
  });
  el.addEventListener("click", (e) => {
    const p = e.target.closest("[data-prov]"); if (p) { setProvider(p.dataset.prov); $$("[data-prov]", el).forEach((b) => b.setAttribute("aria-pressed", b === p)); paintPill(); }
    const c = e.target.closest("[data-clear]"); if (c) { setKey(c.dataset.clear, ""); toast(`${KEYS.find((k) => k.id === c.dataset.clear).label} key removed`); closeDrawer(); openSettings(); }
  });
  el.addEventListener("change", (e) => {
    const k = e.target.dataset.key; if (!k || !e.target.value.trim()) return;
    setKey(k, e.target.value); e.target.value = ""; e.target.placeholder = "••••••••••••";
    e.target.closest(".keyrow").querySelector("[data-clear]").disabled = false;
    toast(`${KEYS.find((x) => x.id === k).label} key saved`); paintPill();
  });
}

// ---- history drawer ---------------------------------------------------------------------
$("#historyBtn").addEventListener("click", openHistory);
function openHistory() {
  const list = getHistory();
  const el = openDrawer({
    title: "History",
    body: list.length ? h`
      <div class="hist">${raw(list.map((e) => h`
        <div class="hist-row" role="button" tabindex="0" data-id="${e.id}">
          <div><div class="t">${e.target}</div><div class="m">${(e.type || "").toLowerCase()} · ${new Date(e.timestamp).toLocaleString()}${e.v2 ? "" : " · classic"}</div></div>
          <button class="btn btn-ghost btn-sm" type="button" data-del="${e.id}" aria-label="Delete">✕</button>
        </div>`).join(""))}</div>
      <button class="btn btn-sm" type="button" id="histClear" style="align-self:flex-start">Clear all history</button>`
      : `<p class="empty" style="padding:0">No cases yet. History is kept in this browser only.</p>`,
  });
  el.addEventListener("click", (e) => {
    const d = e.target.closest("[data-del]");
    if (d) { store.set("crawlr_history", getHistory().filter((x) => x.id !== d.dataset.del)); closeDrawer(); openHistory(); return; }
    if (e.target.id === "histClear") { openModal({ title: "Clear all history?", body: `<p style="font-size:var(--fs-1)">Removes every saved case and its notes from this browser.</p>`, actions: [{ label: "Keep", onClick: closeModal }, { label: "Clear all", primary: true, onClick: () => { store.del("crawlr_history"); closeModal(); closeDrawer(); toast("History cleared"); } }] }); return; }
    const r = e.target.closest(".hist-row");
    if (r) {
      closeDrawer();
      const entry = getHistory().find((x) => x.id === r.dataset.id);
      if (!entry) return;
      if (entry.type === "RECON") { recon.loadHistory(entry); show("recon"); }
      else if (entry.type === "INVESTIGATE") { loadHistory(entry.id); show("investigate"); }
      else if (entry.type === "email_headers") { show("headers"); tools.loadHeaderHistory(entry); }
    }
  });
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.classList.contains("hist-row")) e.target.click(); });
}

// ---- terms ---------------------------------------------------------------------------------
function termsIfNeeded() {
  if (store.get("crawlr_terms_v1")) return;
  openModal({
    title: "Before you start",
    body: `<div style="font-size:var(--fs-1);color:var(--ink-2);display:flex;flex-direction:column;gap:8px">
      <p>CrawlR queries public sources about the target you enter. Use it only for lawful purposes: your own accounts, authorized assessments, research, or investigations you're entitled to run.</p>
      <p>Results come from third parties and can be wrong. Treat "unverified" findings as leads, not facts.</p>
      <p>Active techniques (profile scraping for Deep Dive) fetch the target's pages and may be logged by those sites.</p>
      <label style="display:flex;gap:8px;align-items:flex-start;margin-top:6px"><input type="checkbox" id="termsOk" style="accent-color:var(--violet-2);margin-top:3px"> I understand and will use CrawlR responsibly.</label>
    </div>`,
    actions: [{ label: "Continue", primary: true, onClick: (el) => { if (!el.querySelector("#termsOk").checked) { toast("Tick the box to continue."); return; } store.set("crawlr_terms_v1", Date.now()); closeModal(); } }],
  });
}

// ---- boot -------------------------------------------------------------------------------------
(async function boot() {
  renderSources("");
  await refreshQuota();
  paintPill();
  termsIfNeeded();
  const v = location.hash.slice(1);
  show(VIEWS.includes(v) ? v : "landing");
})();
