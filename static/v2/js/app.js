// Entry point: navigation, landing, settings, history drawer, AI pill, theme, terms.
import { $, $$, h, raw, esc, store, toast, looksLikeHeaders, refreshQuota, quota, aiLabel, KEYS, getKey, setKey, getProvider, setProvider, detect, TYPE_LABEL, INVESTIGATE_TYPES, RECON_TYPES, roving } from "./core.js";
import { openModal, closeModal, openDrawer, closeDrawer } from "./ui.js";
import { run, cancel, renderSources, loadHistory, getHistory, clearCase, exportCase, state } from "./investigate.js";
import * as recon from "./recon.js";
import * as tools from "./tools.js";

// ---- theme ---------------------------------------------------------------------
// The stylesheet follows the system setting on its own. This only applies an explicit choice.
const THEME_KEY = "crawlr_theme";
function applyTheme() {
  const t = store.str(THEME_KEY, "");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
}
applyTheme();

// Password managers (Chrome, Safari/iCloud Keychain, 1Password, Bitwarden, LastPass) treat any
// text box mentioning "username" or "email" as a login field and pop up saved logins.
// None of CrawlR's inputs are logins, so opt every one of them out, including ones added later.
const QUIET = { autocomplete: "off", "data-1p-ignore": "", "data-lpignore": "true", "data-bwignore": "", "data-form-type": "other" };
function quietAutofill(root) {
  for (const el of root.querySelectorAll?.("input:not([type=checkbox]):not([type=radio]):not([type=file]), textarea") || []) {
    if (el.dataset.quiet) continue;
    el.dataset.quiet = "1";
    for (const [k, v] of Object.entries(QUIET)) el.setAttribute(k, v);
    // A password-type box always triggers "save password"; mask API keys with CSS instead.
    if (el.type === "password") { el.type = "text"; el.classList.add("masked"); }
    // Browsers skip autofill on search boxes, which is what these are.
    if (el.tagName === "INPUT" && el.type === "text") el.type = "search";
  }
}
quietAutofill(document);
new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach((n) => n.nodeType === 1 && quietAutofill(n.parentNode || n)))).observe(document.body, { childList: true, subtree: true });


// ---- views ---------------------------------------------------------------------
const BENCHES = ["investigate", "recon"];
const TOOLS = ["headers", "dorks", "decoders"];
const VIEWS = [...BENCHES, ...TOOLS];
const TITLES = { landing: "CrawlR: OSINT investigation in your browser", investigate: "Investigate · CrawlR", recon: "Recon · CrawlR", headers: "Email headers · CrawlR", dorks: "Search query builder · CrawlR", decoders: "Decoders · CrawlR" };
const FOCUS = { landing: "#landingInput", headers: "#hdrInput", dorks: "#dkName", decoders: "#b64In" };
let current = "";
function show(view, { focus = true } = {}) {
  current = view;
  $("#landing").hidden = view !== "landing";
  VIEWS.forEach((b) => ($(`#${b}`).hidden = view !== b));
  closeRail(); measureCasebar();
  $$("[data-mode]").forEach((a) => a.removeAttribute("aria-current"));
  $$(`[data-mode="${view}"]`).forEach((a) => a.setAttribute("aria-current", "page"));
  document.title = TITLES[view] || TITLES.landing;
  if (VIEWS.includes(view) && location.hash !== `#${view}`) history.replaceState(null, "", `${location.pathname}#${view}`);
  if (!focus) return;
  // Move focus to the natural starting point of the view (wide screens: the first field).
  // an empty workbench starts in its target field; one with a case open starts at the results
  const idleBench = BENCHES.includes(view) && !(view === "recon" ? recon.state.target : state.target);
  const sel = FOCUS[view] || (idleBench ? `#${view} .casebar .target` : "");
  setTimeout(() => { if ($("#overlays").children.length) return; (sel && $(sel)?.offsetParent ? $(sel) : $("#content")).focus({ preventScroll: true }); }, 50);
}
window.addEventListener("hashchange", () => { const v = location.hash.slice(1); if (VIEWS.includes(v)) show(v); });
document.addEventListener("click", (e) => { const g = e.target.closest("[data-goto]"); if (g) { e.preventDefault(); show(g.dataset.goto); } });
$("#brand").addEventListener("click", (e) => { e.preventDefault(); clearCase(); recon.clearCase(); syncIdle(); show("landing"); history.replaceState(null, "", location.pathname); });
$$("[data-mode]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); show(a.dataset.mode); }));
$(".skip").addEventListener("click", (e) => { e.preventDefault(); $("#content").focus(); });

// The Sources panel drops from the case bar (a sheet on phones). It is a plain disclosure:
// the button says whether it is open, Escape and a click outside close it.
const railBtn = () => $(".bench:not([hidden]) .sources-btn");
function openRail() {
  const rail = $(".bench:not([hidden]) .rail"); if (!rail) return;
  rail.hidden = false; rail.classList.add("open"); document.body.classList.add("rail-open");
  railBtn()?.setAttribute("aria-expanded", "true");
  (rail.querySelector("[data-toggle]") || rail.querySelector("button"))?.focus();
}
function closeRail({ refocus = false } = {}) {
  const open = $$(".rail.open");
  open.forEach((r) => { r.classList.remove("open"); r.hidden = true; });
  document.body.classList.remove("rail-open");
  $$(".sources-btn").forEach((b) => b.setAttribute("aria-expanded", "false"));
  if (refocus && open.length) railBtn()?.focus();
}
// Sticky things below the case bar (result tabs, the summary column) need its height.
function measureCasebar() {
  const c = $(".bench:not([hidden]) .casebar");
  const sticky = c && getComputedStyle(c).position === "sticky";
  document.documentElement.style.setProperty("--casebar-h", `${sticky ? c.offsetHeight : 0}px`);
}
const casebarWatch = new ResizeObserver(measureCasebar);
$$(".casebar").forEach((c) => casebarWatch.observe(c));
window.addEventListener("resize", measureCasebar);
const syncIdle = () => {};   // kept for callers; the layout no longer depends on whether a case is open
$$(".sources-btn").forEach((b) => b.addEventListener("click", () => ($(".rail.open") ? closeRail({ refocus: true }) : openRail())));
document.addEventListener("click", (e) => {
  if (e.target.closest("[data-close-rail]")) { closeRail({ refocus: true }); return; }
  if ($(".rail.open") && !e.target.closest(".rail, .sources-btn")) closeRail();
});
// preventDefault matters: the target field is type=search, and browsers clear a search field on Escape.
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $(".rail.open") && !$("#overlays").children.length) { e.preventDefault(); closeRail({ refocus: true }); } });
document.addEventListener("crawlr:close-rail", () => closeRail());

// ---- landing -------------------------------------------------------------------
const detectBox = $("#landingDetect");
const WILL_RUN = {
  domain: "Runs in Recon: DNS, WHOIS, TLS, headers, subdomains, exposure and a port scan.",
  ip: "Runs in Recon: TLS, headers, network owner, exposure and a port scan.",
  asn: "Runs in Recon: registry, prefix and peering lookups.",
  username: "Runs in Investigate: Sherlock, Maigret, GitHub and platform checks.",
  email: "Runs in Investigate: Holehe, breaches, Gravatar and a handle search.",
  hash: "Runs in Investigate: MalwareBazaar, CIRCL, OTX and ThreatFox.",
  phone: "Runs in Investigate: carrier lookup and search links.",
  name: "Runs in Investigate: people-search links to open by hand.",
  headers: "Opens the email header analyzer.",
  multi: "One target at a time for now.",
};
$("#landingInput").addEventListener("input", (e) => { const t = detect(e.target.value); detectBox.innerHTML = t ? h`<span class="pill ${INVESTIGATE_TYPES.includes(t) || RECON_TYPES.includes(t) ? "violet" : ""}">${TYPE_LABEL[t]}</span><span>${WILL_RUN[t] || ""}</span>` : ""; });
function startInvestigate(v) { $("#targetInput").value = v; typeOverride = ""; onTargetInput(); show("investigate", { focus: false }); run(v).then(syncIdle); syncIdle(); $("#content").focus({ preventScroll: true }); }
function startRecon(v) { show("recon", { focus: false }); recon.run(v).then(syncIdle); syncIdle(); $("#content").focus({ preventScroll: true }); }
$("#landingForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const v = $("#landingInput").value.trim(); if (!v) return;
  const t = detect(v);
  if (t === "headers") { show("headers"); tools.prefillHeaders(v); return; }
  if (t === "multi") { toast("One target at a time for now."); return; }
  if (RECON_TYPES.includes(t)) startRecon(v); else startInvestigate(v);
});
// Pivot buttons in the investigation report ("Run in Investigate" / "Run in Recon").
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-pivot]"); if (!b) return;
  const v = b.dataset.value; if (!v) return;
  if (state.running || recon.state.running) { toast("A run is in progress. Cancel it or wait for it to finish."); return; }
  window.scrollTo({ top: 0, behavior: "smooth" });
  if (b.dataset.pivot === "recon") startRecon(v); else startInvestigate(v);
});
// Pasted email headers lose their newlines in a one-line input, so catch the paste itself.
["#landingInput", "#targetInput"].forEach((sel) => $(sel).addEventListener("paste", (e) => {
  const text = e.clipboardData?.getData("text") || "";
  if (!looksLikeHeaders(text)) return;
  e.preventDefault();
  show("headers"); tools.prefillHeaders(text); toast("Those look like email headers. Analyzing them here.");
}));
// An example fills the box and runs the open sources. It never spends an AI credit.
$$(".ex").forEach((b) => b.addEventListener("click", () => { $("#landingInput").value = b.dataset.example; $("#landingForm").requestSubmit(); }));

// ---- rail (target + sources + run) ----------------------------------------------
let typeOverride = "";
const syncType = roving($("#targetDetected"), "[role=radio]", (el) => el.click());
function onTargetInput() {
  const v = $("#targetInput").value.trim();
  const detected = detect(v);
  const t = typeOverride || detected;
  renderSources(INVESTIGATE_TYPES.includes(t) ? t : "");
  const box = $("#targetDetected");
  if (!v) { box.innerHTML = ""; return; }
  const hadFocus = box.contains(document.activeElement);
  const looksRecon = !typeOverride && RECON_TYPES.includes(detected);
  // Always offer the Investigate types so an ambiguous target ("john.dev") can be searched as a username.
  const lead = looksRecon ? `Looks like a ${TYPE_LABEL[detected].toLowerCase()}. Search it as:` : typeOverride ? "Treating as" : "Detected";
  box.innerHTML = h`<span id="typeLead">${lead}</span>
    <span class="seg" role="radiogroup" aria-labelledby="typeLead">${raw(INVESTIGATE_TYPES.map((o) => h`<button type="button" role="radio" data-type="${o}" aria-checked="${o === t}">${TYPE_LABEL[o]}</button>`).join(""))}</span>
    ${looksRecon ? raw(h`<span>or run it in <a href="#recon" data-goto="recon" data-carry="1">Recon</a></span>`) : ""}`;
  syncType();
  if (hadFocus) (box.querySelector('[aria-checked="true"]') || box.querySelector("[role=radio]"))?.focus();
}
$("#targetInput").addEventListener("input", () => { typeOverride = ""; onTargetInput(); });
$("#targetInput").addEventListener("keydown", (e) => { if (e.key === "Enter" && !state.running) $("#runBtn").click(); });
$("#targetDetected").addEventListener("click", (e) => { const b = e.target.closest("[data-type]"); if (!b) return; typeOverride = b.dataset.type === detect($("#targetInput").value.trim()) ? "" : b.dataset.type; onTargetInput(); });
$("#runBtn").addEventListener("click", () => {
  if (state.running) { cancel(); return; }
  closeRail();
  const v = $("#targetInput").value.trim();
  // Any target can be typed in either workbench: a domain, IP or ASN typed here opens in Recon
  // unless the investigator chose to search it as a handle.
  if (v && !typeOverride && RECON_TYPES.includes(detect(v))) { toast(`${TYPE_LABEL[detect(v)]}: opened in Recon.`); startRecon(v); return; }
  run(v, typeOverride || undefined);
});
// The same in the other direction: a username or email typed into Recon opens in Investigate.
$("#rRunBtn").addEventListener("click", (e) => {
  if (recon.state.running) return;
  const v = $("#rTargetInput").value.trim(), t = detect(v);
  if (v && INVESTIGATE_TYPES.includes(t)) { e.stopImmediatePropagation(); toast(`${TYPE_LABEL[t]}: opened in Investigate.`); startInvestigate(v); }
}, true);
$("#clearBtn").addEventListener("click", () => { clearCase(); typeOverride = ""; syncIdle(); $("#targetInput").focus(); });
$("#rClearBtn").addEventListener("click", () => { syncIdle(); $("#rTargetInput").focus(); });
$("#exportBtn").addEventListener("click", exportCase);
// carry a domain/IP typed into Investigate over to Recon
document.addEventListener("click", (e) => { if (e.target.closest("[data-carry]")) { const v = $("#targetInput").value.trim(); $("#rTargetInput").value = v; $("#rTargetInput").dispatchEvent(new Event("input")); } });

// ---- AI pill + settings ----------------------------------------------------------------
function paintPill() {
  const { text, long, cls } = aiLabel();
  const pill = $("#aiPill"); pill.className = `pill ${cls}`; $("#aiPillText").textContent = text;
  pill.title = long; pill.setAttribute("aria-label", long);
}
quota.listeners.add(paintPill);
$("#aiPill").addEventListener("click", openSettings);
$("#settingsBtn").addEventListener("click", openSettings);
document.addEventListener("click", (e) => { if (e.target.closest("[data-open-settings]")) openSettings(); });

const radios = (name, label, options, value) => h`<span class="seg" role="radiogroup" aria-label="${label}">${raw(options.map(([v, text]) => h`<button type="button" role="radio" data-${name}="${v}" aria-checked="${v === value}">${text}</button>`).join(""))}</span>`;
function openSettings() {
  const prov = getProvider();
  const theme = store.str(THEME_KEY, "") || "system";
  const q = quota.state;
  const el = openDrawer({
    title: "Settings",
    body: h`
      <section>
        <h3 class="set-h">AI provider</h3>
        <p class="set-p">${q.house_ai ? `Without your own key, analysis uses the free tier: ${q.remaining?.analysis ?? 0} analyses and ${q.remaining?.deepdive ?? 0} Deep Dive left today. A cached answer or a repeat of the same result does not use a credit. Your own key removes the limits.` : "Add a Claude or Gemini key to turn on AI analysis and Deep Dive."} AI never runs on its own.</p>
        ${raw(radios("prov", "AI provider for your own key", [["anthropic", "Claude"], ["gemini", "Gemini"]], prov))}
      </section>
      <section>
        <h3 class="set-h">Your keys</h3>
        <p class="set-p">Stored only in this browser. A key is sent with a request to CrawlR's server, which passes it to that service and does not store it.</p>
        ${raw(KEYS.map((k) => h`
          <div class="keyrow">
            <div class="top"><label class="name" for="key-${k.id}">${k.label} key</label>${getKey(k.id) ? raw('<span class="tag ok">set</span>') : ""}<a href="${k.url}" target="_blank" rel="noopener noreferrer">${k.help}</a></div>
            <div class="inline-form"><input class="input mono" type="password" id="key-${k.id}" data-key="${k.id}" placeholder="${getKey(k.id) ? "••••••••••••" : k.placeholder}" autocomplete="off"><button class="btn btn-sm" type="button" data-clear="${k.id}" aria-label="Clear ${k.label} key" ${getKey(k.id) ? "" : "disabled"}>Clear</button></div>
          </div>`).join(""))}
      </section>
      <section>
        <h3 class="set-h">Appearance</h3>
        ${raw(radios("theme", "Color theme", [["system", "System"], ["dark", "Dark"], ["light", "Light"]], theme))}
      </section>
      <section>
        <h3 class="set-h">Your data</h3>
        <p class="set-p">Cases, notes and keys live in this browser's storage and nowhere else. CrawlR has no accounts. Clear saved cases from History.</p>
      </section>
      <section>
        <h3 class="set-h">Responsible use</h3>
        <p class="set-p">What CrawlR is for, what it must not be used for, and what it does and does not record.</p>
        <button class="btn btn-sm" type="button" data-open-use>Read the acceptable-use statement</button>
      </section>`,
  });
  roving(el, "[role=radio]", (b) => b.click());
  el.addEventListener("click", (e) => {
    const p = e.target.closest("[data-prov]"); if (p) { setProvider(p.dataset.prov); $$("[data-prov]", el).forEach((b) => { b.setAttribute("aria-checked", b === p); b.tabIndex = b === p ? 0 : -1; }); paintPill(); }
    const t = e.target.closest("[data-theme]"); if (t) { store.setStr(THEME_KEY, t.dataset.theme === "system" ? "" : t.dataset.theme); applyTheme(); $$("[data-theme]", el).forEach((b) => { b.setAttribute("aria-checked", b === t); b.tabIndex = b === t ? 0 : -1; }); }
    const c = e.target.closest("[data-clear]"); if (c) { setKey(c.dataset.clear, ""); toast(`${KEYS.find((k) => k.id === c.dataset.clear).label} key removed`); closeDrawer({ restore: false }); openSettings(); paintPill(); }
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
const KIND = { INVESTIGATE: "investigate", RECON: "recon", email_headers: "email headers" };
function openHistory() {
  const list = getHistory();
  const el = openDrawer({
    title: "History",
    body: list.length ? h`
      <p class="set-p">Kept in this browser only, newest first. Up to 50 cases.</p>
      <ul class="hist">${raw(list.map((e) => h`
        <li class="hist-row">
          <button type="button" class="hist-open" data-id="${e.id}"><span class="t">${e.target}</span><span class="m">${KIND[e.type] || String(e.type || "").toLowerCase()} · ${new Date(e.timestamp).toLocaleString()}${e.v2 ? "" : " · saved by the old interface"}</span></button>
          <button class="btn btn-ghost btn-icon" type="button" data-del="${e.id}" aria-label="Delete case ${e.target}">✕</button>
        </li>`).join(""))}</ul>
      <button class="btn btn-sm hist-clear" type="button" id="histClear">Clear all history</button>`
      : `<p class="empty flat">No cases yet. History is kept in this browser only.</p>`,
  });
  el.addEventListener("click", (e) => {
    const d = e.target.closest("[data-del]");
    if (d) { store.set("crawlr_history", getHistory().filter((x) => x.id !== d.dataset.del)); closeDrawer({ restore: false }); openHistory(); return; }
    if (e.target.id === "histClear") { openModal({ title: "Clear all history?", body: `<p class="modal-p">Removes every saved case and its notes from this browser. This can't be undone.</p>`, actions: [{ label: "Keep", onClick: closeModal }, { label: "Clear all", primary: true, onClick: () => { store.del("crawlr_history"); closeModal({ restore: false }); toast("History cleared"); } }] }); return; }
    const r = e.target.closest(".hist-open");
    if (r) {
      if (state.running || recon.state.running) { toast("A run is in progress. Cancel it or wait for it to finish."); return; }
      closeDrawer({ restore: false });
      const entry = getHistory().find((x) => x.id === r.dataset.id);
      if (!entry) return;
      if (entry.type === "RECON") { recon.loadHistory(entry); syncIdle(); show("recon", { focus: false }); }
      else if (entry.type === "INVESTIGATE") { loadHistory(entry.id); syncIdle(); show("investigate", { focus: false }); }
      else if (entry.type === "email_headers") { show("headers", { focus: false }); tools.loadHeaderHistory(entry); }
      $("#content").focus({ preventScroll: true });
    }
  });
}

// ---- acceptable use -----------------------------------------------------------------------
// The same commitments as the first-run gate, in full, reachable at any time.
const USE_HTML = `<div class="terms">
  <p><b>CrawlR is for</b> security work on systems you own or are authorized to test, checking your own exposure, research, journalism, incident response and training exercises such as CTFs.</p>
  <p><b>Do not use it to</b> harass, stalk, dox or locate a private individual, to scan or probe systems without permission, or to try credentials found in breaches. CrawlR never logs in to anything, never triggers a password reset and never contacts a person.</p>
  <p><b>Passive by default.</b> Most sources ask third parties what they already know. The two active techniques (the port scan and profile scraping for Deep Dive) connect to the target's own systems, are labelled, and stay off until you turn them on.</p>
  <p><b>Leads, not proof.</b> Results come from third parties and can be wrong or out of date. "Confirmed" means an account exists, not who owns it. "Possible" means a tool reported it and nothing verified it. A source that failed says nothing either way.</p>
  <p><b>What is kept.</b> Your cases, notes and keys stay in this browser. The server does not write the targets you look up to its logs and has no database. AI reports are only requested when you ask, and are sent to the provider you chose.</p>
  <p><b>Collect only what your purpose needs.</b> Public does not mean harmless: separate public facts can identify someone once combined. You are responsible for how you use what you find, under the law where you are and where the target is.</p>
  <p>CrawlR is not a people-search service. Name and phone lookups only open links for you to search by hand.</p>
</div>`;
function openUse() { openModal({ title: "Acceptable use", wide: true, body: USE_HTML, actions: [{ label: "Close", primary: true, onClick: closeModal }] }); }
document.addEventListener("click", (e) => { if (e.target.closest("[data-open-use]")) { closeDrawer({ restore: false }); openUse(); } });

// ---- terms ---------------------------------------------------------------------------------
// The gate cannot be dismissed with Escape, the backdrop or a close button: the only way
// through is to tick the box and continue.
function termsIfNeeded() {
  if (store.get("crawlr_terms_v1")) return false;
  const el = openModal({
    title: "Before you start",
    required: true,
    focus: "#termsOk",
    body: `<div class="terms">
      <p>CrawlR queries public sources about the target you enter. Use it only for lawful purposes: your own accounts, authorized assessments, research, or investigations you're entitled to run.</p>
      <p>Results come from third parties and can be wrong. "Possible" findings are leads to check, not facts, and a confirmed account shows that a handle exists, not who owns it.</p>
      <p>Active techniques (the port scan in Recon, profile scraping for Deep Dive) connect to the target's own systems and may be logged there. They are labelled and stay off until you turn them on. Only scan hosts you own or are authorized to test.</p>
      <p>Your cases and notes stay in this browser. Don't collect more about a person than your purpose needs.</p>
      <p>The full acceptable-use statement is always under Settings.</p>
      <label class="terms-ok"><input type="checkbox" id="termsOk"> I understand and will use CrawlR responsibly.</label>
    </div>`,
    actions: [{ label: "Continue", primary: true, disabled: true, onClick: (m) => { if (!m.querySelector("#termsOk").checked) return; store.set("crawlr_terms_v1", Date.now()); closeModal({ restore: false }); show(current || "landing"); } }],
  });
  el.querySelector("#termsOk").addEventListener("change", (e) => { el.querySelector("[data-action]").disabled = !e.target.checked; });
  return true;
}

// ---- boot -------------------------------------------------------------------------------------
(async function boot() {
  renderSources("");
  const v = location.hash.slice(1);
  show(VIEWS.includes(v) ? v : "landing", { focus: false });
  const gated = termsIfNeeded();
  await refreshQuota();
  paintPill();
  if (!gated) show(current);
})();
