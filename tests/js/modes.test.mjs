// Session modes: "Adult sites" and "Active techniques" (static/v2/js/modes.js).
// Off on every page load, on for the page session once switched on, never stored, asked about
// once, and honest per case: not used for the wrong kind of target, suspended for a handle that
// suggests a minor. No browser, no network.
// Run: node tests/js/modes.test.mjs
import fs from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
// Every storage call during this suite is recorded. An older version left these preferences behind.
const calls = { local: [], session: [] };
const LEGACY = { crawlr_v2_sources: JSON.stringify({ active: true, "maigret.nsfw": true, adult: true, sherlock: false }), crawlr_v2_recon_sources: JSON.stringify({ portscan: true, wayback: false }) };
const mem = { ...LEGACY };
const recorder = (log, data) => ({
  getItem: (k) => { log.push(["get", k]); return k in data ? data[k] : null; },
  setItem: (k, v) => { log.push(["set", k, String(v)]); data[k] = String(v); },
  removeItem: (k) => { log.push(["remove", k]); delete data[k]; },
  clear: () => { log.push(["clear"]); }, key: () => null, get length() { return Object.keys(data).length; },
});
globalThis.localStorage = recorder(calls.local, mem);
globalThis.sessionStorage = recorder(calls.session, {});
const writes = () => [...calls.local, ...calls.session].filter((c) => c[0] !== "get");

const J = "../../static/v2/js/";
const M = await import(J + "modes.js");
const A = await import(J + "adult.js");
const { store } = await import(J + "core.js");
const { sourcePlan, aiPayloadFor, buildEvidence } = await import(J + "evidence.js");
const { parseCaseFile, buildCaseFile } = await import(J + "casefile.js");

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const read = (p) => fs.readFileSync(new URL(p, import.meta.url), "utf8");
const code = (f) => read(J + f).replace(/\/\/.*$/gm, "");
const fx = JSON.parse(read("./fixtures/adult.json"));
const T = fx.target, C = fx.collected;
const yes = ({ accept }) => accept(), no = ({ cancel }) => cancel();
const never = () => { throw new Error("asked when it must not be"); };

// What a run would ask for, built from the same functions investigate.js calls: the session, the
// per-case view, the plan and the Sherlock and Maigret bodies.
function runWould(s, target, type, refusals) {
  const av = M.adultCase(s.on("adult"), target, type, refusals);
  const adult = A.adultOn(type, target, av.applies);
  const plan = sourcePlan(type, target, { adult });
  return { adult, nsfw: type === "username" ? A.usernameBody(A.handleOf(target), adult).nsfw : undefined, adultCheck: plan.includes("adult"), view: av };
}

// ---- 1. off on load, in memory only ------------------------------------------------------------
{
  ok(M.MODE_IDS.join() === "adult,active", "there are two session modes");
  ok(!M.session.on("adult") && !M.session.on("active"), "both are off when the module loads");
  const fresh = M.makeSessionModes();
  ok(!fresh.on("adult") && !fresh.on("active") && !fresh.accepted("adult") && !fresh.accepted("active") && !fresh.on("nope") && !fresh.on(undefined), "a new session starts with both off and nothing accepted");
  ok(runWould(fresh, T, "username").nsfw === false && !runWould(fresh, T, "username").adultCheck, "off: a run sends nsfw false and plans no adult site check");
  // the stored leftovers turn nothing on
  ok(JSON.parse(mem.crawlr_v2_sources).active === true && !M.session.on("active") && !M.session.on("adult"), "a stored legacy preference turns nothing on");
}

// ---- 2. the first-use confirmation: once per session, per mode -----------------------------------
{
  const s = M.makeSessionModes();
  let asked = 0;
  const count = (answer) => (x) => { asked++; answer(x); };
  ok(s.request("adult", true, count(no)) === "asked" && !s.on("adult") && asked === 1 && !s.accepted("adult"), "cancelling leaves the mode off");
  ok(s.request("adult", true, count(yes)) === "on" && s.on("adult") && asked === 2 && s.accepted("adult"), "a cancelled confirmation is asked again, and confirming turns the mode on");
  ok(s.request("adult", false, never) === "off" && !s.on("adult"), "switching off never asks");
  ok(s.request("adult", true, never) === "on" && s.on("adult"), "switching on again in the same session does not ask again");
  ok(s.request("adult", true, never) === "on", "nor does asking for what is already on");
  ok(!s.on("active") && !s.accepted("active"), "accepting one mode accepts nothing about the other");
  let activeAsked = 0;
  s.request("active", true, (x) => { activeAsked++; x.accept(); });
  s.request("active", false); s.request("active", true, never); s.request("active", false); s.request("active", true, never);
  ok(activeAsked === 1 && s.on("active") && s.on("adult"), "the other mode is asked about once, on its own first use");
  // only the literal true, and only through ask
  const t = M.makeSessionModes();
  for (const v of ["true", 1, {}, [true], "on"]) t.request("adult", v, yes);
  ok(!t.on("adult"), "only the literal true switches a mode on");
  ok(t.request("adult", true) === "off" && t.request("adult", true, null) === "off" && !t.on("adult"), "with nothing to ask, a mode that was never accepted stays off");
  ok(t.request("everything", true, yes) === "off" && !t.on("everything"), "an unknown mode is never on");
  // a confirmation answers once
  let handle = null;
  t.request("active", true, (x) => { handle = x; });
  ok(!t.on("active"), "while the confirmation is open the mode is off");
  handle.cancel(); handle.accept();
  ok(!t.on("active") && !t.accepted("active"), "a dialog that was cancelled cannot be accepted afterwards");
  ok(M.MODE.adult.confirm.join(" ").match(/existence checks only/i) && /text/i.test(M.MODE.adult.confirm.join(" ")) && /never run for a handle that suggests a minor/.test(M.MODE.adult.confirm.join(" ")) && /lawful purposes/.test(M.MODE.adult.confirm.join(" ")), "the adult confirmation says: existence checks only, text only, never for a minor, lawful purposes");
  ok(/fetch the target's own profile pages/.test(M.MODE.active.confirm.join(" ")) && /scan 20 common ports on the target host/.test(M.MODE.active.confirm.join(" ")) && /the target's services may log/.test(M.MODE.active.confirm.join(" ")), "the active confirmation says what is fetched or scanned, and that the target may log it");
  for (const id of M.MODE_IDS) ok(M.confirmHtml(id).includes("It stays on for every case until you switch it off or reload the page.") && /never saved/.test(M.confirmHtml(id)) && !/<(?!\/?p\b)/.test(M.confirmHtml(id).replace(/<p class="modal-p">/g, "<p>")), `the ${id} confirmation says how long it lasts, as plain paragraphs`);
}

// ---- 3. the mode survives every change of case ---------------------------------------------------
{
  const s = M.makeSessionModes(), refusals = M.makeRefusals();
  s.request("adult", true, yes); s.request("active", true, yes);
  const first = runWould(s, T, "username", refusals);
  ok(first.adult && first.nsfw === true && first.adultCheck, "on: the run sends nsfw true and plans the adult site check");
  // another handle, a similar handle's "Investigate this", a lead pivot: each is run(target) again
  for (const [what, handle] of [["a different handle", "someone_else"], ["a similar handle", "jdoe_examp1e"], ["a lead pivot", "@other.person"], ["a name candidate's handle", "jordan-doe"], ["a re-run", T]]) {
    const r = runWould(s, handle, "username", refusals);
    ok(r.adult && r.nsfw === true && r.adultCheck && s.on("adult") && s.on("active"), `${what} runs with the mode on, with no extra click`);
  }
  // The session has no way to be switched off except request(id, false): there is nothing a new
  // case, Clear or a case opened from History could call.
  ok(Object.keys(s).sort().join() === "accepted,on,request,subscribe", "the session has no reset: only a request can change it");
  const inv = code("investigate.js"), rec = code("recon.js"), app = code("app.js");
  const fn = (src, name) => { const a = src.indexOf(`export function ${name}(`); return src.slice(a, src.indexOf("\n}\n", a)); };
  for (const [name, body] of [["Investigate clearCase", fn(inv, "clearCase")], ["Investigate loadHistory", fn(inv, "loadHistory")], ["Recon clearCase", fn(rec, "clearCase")], ["Recon loadHistory", fn(rec, "loadHistory")]]) ok(body.length > 100 && !/session\.|refusals|\.request\(|adultSwitch|\.reset\(\)(?<!checker\.reset\(\))/.test(body), `${name} does not touch a session mode`);
  ok(!/session\.request|\.request\(/.test(inv) && !/session\.request|\.request\(/.test(rec) && !/session\.request|\.request\(/.test(app), "no workbench code switches a mode: Investigate, Recon and the entry point never call request");
  const ui = code("modeui.js");
  ok((ui.match(/session\.request\(/g) || []).length === 2 && /session\.request\(id, e\.target\.checked === true, ask\(id\)\)/.test(ui) && /session\.request\(id, false\)/.test(ui), "a mode changes in two places only: the switch's own change event, and Turn off");
  ok(/const av = adultView\(type, target\);\s*\n\s*const adult = adultOn\(type, target, av\.applies\);/.test(read(J + "investigate.js")) && /adultMode: adult, adultBlocked: av\.state === "suspended" \? av\.reason : ""/.test(inv), "every run reads the session through the per-case view");
  ok(/const adultView = \(type, target = \$\("#targetInput"\)\.value\) => adultCase\(session\.on\("adult"\), target, type, refusals\);/.test(inv), "and that view is the tested one");
  ok(/function startInvestigate\(v, type = ""\) \{[^\n]*run\(v, typeOverride \|\| undefined\)/.test(app) && !/startInvestigate[\s\S]{0,300}session/.test(app.slice(app.indexOf("function startInvestigate"), app.indexOf("function startRecon"))), "a pivot, a lead and a similar handle start a run through the same run(): nothing about the modes is passed or reset");
}

// ---- 4. applicability stays honest per case ------------------------------------------------------
{
  const s = M.makeSessionModes(), refusals = M.makeRefusals();
  s.request("adult", true, yes);
  for (const [type, target] of [["email", "jdoe_example@example.org"], ["hash", "44d88612fea8a8f36de82e1278abb02f"], ["phone", "+1 202 555 0100"], ["name", "Jordan Doe"]]) {
    const r = runWould(s, target, type, refusals);
    ok(s.on("adult") && r.view.on && r.view.state === "unused" && r.view.note === "Not used for this kind of target." && !r.view.applies && !r.adult && !r.adultCheck && !sourcePlan(type, target, { adult: r.adult }).includes("adult"), `a ${type} case: the mode stays on, says it is not used, and nothing adult is requested`);
  }
  ok(runWould(s, T, "username", refusals).nsfw === true, "and it applies again on the next username");
  // the minor guard suspends, with the reason, and has no override
  const young = runWould(s, "anna15", "username", refusals);
  ok(s.on("adult") && young.view.on && young.view.state === "suspended" && !young.view.applies && young.nsfw === false && !young.adultCheck, "a handle that suggests a minor: the mode stays on for the session and is suspended for that case");
  ok(young.view.reason === "Adult and dating sites are not checked for this handle: it suggests a minor (the handle starts or ends with a number from 10 to 17)." && young.view.note === M.MINOR_SHORT, "with the reason shown");
  ok(!A.adultOn("username", "anna15", true) && !sourcePlan("username", "anna15", { adult: true }).includes("adult") && A.usernameBody("anna15", A.adultOn("username", "anna15", true)).nsfw === false, "and there is no override: even a literal true asks for nothing adult");
  const next = runWould(s, "someone_else", "username", refusals);
  ok(s.on("adult") && next.view.state === "applies" && next.nsfw === true && next.adultCheck, "the next handle that passes runs with it on");
  // the server's own guard refused a handle the client's copy passed
  refusals.add("@Odd_Handle", "The handle contains a word that suggests a minor.");
  const refused = runWould(s, "odd_handle", "username", refusals);
  ok(s.on("adult") && refused.view.state === "suspended" && refused.nsfw === false && !refused.adultCheck && /it suggests a minor \(the handle contains a word that suggests a minor\)\.$/.test(refused.view.reason), "a refusal from the server suspends the mode for that handle, with its reason, and leaves the session on");
  ok(runWould(s, T, "username", refusals).nsfw === true, "and only for that handle");
  refusals.add("blank", "");
  ok(/it suggests a minor \(/.test(runWould(s, "blank", "username", refusals).view.reason), "a refusal with no reason still suspends it");
  const cap = M.makeRefusals(3); for (const h of ["a1x", "b2x", "c3x", "d4x"]) cap.add(h, "r");
  ok(!cap.has("a1x") && cap.has("d4x"), "the refusal list is bounded");
  const inv = read(J + "investigate.js");
  ok(/err\.code === "minor_guard"\) \{ adultRefused\(err\.reason\)/.test(inv) && /refusals\.add\(state\.target, why\);/.test(inv) && /d === GUARDED \? runSource\(label, url, usernameBody\(handle, false\)/.test(inv), "the run handles the server's refusal as before: the tool is asked again without the adult part");
  // off, the views say the same things about the case without claiming the mode is on
  const off = M.adultCase(false, "anna15", "username");
  ok(off.state === "off" && !off.on && !off.applies && off.note === M.MINOR_SHORT && M.adultCase(false, T, "email").note === M.NOT_USED && M.adultCase(false, T, "username").note === "" && M.adultCase(true, "", "").state === "idle" && M.adultCase("true", T, "username").on === false, "off is off whatever the case, and only the literal true is on");
  // Active techniques
  ok(M.activeCase(true, "username").applies && M.activeCase(true, "domain", "recon").applies && M.activeCase(true, "ip", "recon").applies, "Active techniques applies to a username case in Investigate, and to a domain or an IP address in Recon");
  for (const [t, b] of [["email", "investigate"], ["hash", "investigate"], ["phone", "investigate"], ["name", "investigate"], ["asn", "recon"]]) ok(M.activeCase(true, t, b).state === "unused" && M.activeCase(true, t, b).on && M.activeCase(true, t, b).note === M.NOT_USED, `and says it is not used for ${t} in ${b}`);
  ok(M.activeCase(true, "", "recon").state === "idle" && M.activeCase(false, "domain", "recon").state === "off" && !M.activeCase(1, "domain", "recon").on, "with no target it is idle, and off is off");
}

// ---- 5. a case cannot turn a mode on --------------------------------------------------------------
{
  const before = [M.session.on("adult"), M.session.on("active")].join();
  // A History entry and a case file that recorded the adult mode, plus fields a hostile file might add.
  const stored = A.scrubCollected(C, T, "username");
  ok(stored.adultMode === true && A.adultAllowed(stored, T, "username") && buildEvidence(stored, T, "username").items.some((i) => i.tier === "adult"), "a stored case that recorded the mode still shows its adult rows");
  const file = JSON.stringify({ ...JSON.parse(JSON.stringify(buildCaseFile({ mode: "investigate", target: T, type: "username", ran: 1700000000000, collected: stored, ai: null, deep: null, notes: "", purpose: "" }))), session: { adult: true, active: true }, modes: ["adult", "active"], adultMode: true, active: true, sources: { active: true, portscan: true } });
  const back = parseCaseFile(file);
  ok(back.ok && back.entry.results.adultMode === true && !("session" in back.entry) && !("modes" in back.entry) && !("active" in back.entry) && !("sources" in back.entry), "a case file keeps the record that the run had the mode on, and nothing else about modes");
  aiPayloadFor(back.entry.results, T, "username", { source_status: {}, active: M.session.on("active") });
  ok([M.session.on("adult"), M.session.on("active")].join() === before && before === "false,false", "reading, scrubbing, drawing and exporting such a case switches nothing on");
  const off = A.scrubCollected({ ...C, adultMode: undefined }, T, "username");
  ok(!buildEvidence(off, T, "username").items.some((i) => i.tier === "adult"), "and a stored case that did not record the mode shows no adult row, whatever the session says");
  const inv = code("investigate.js");
  ok(!/adultMode\s*[)&|?]|collected\.adultMode|results\.adultMode/.test(inv.replace(/state\.adultMode|adultMode: (?:adult|false|true)/g, "")) && !/session\.on\([^)]*\)\s*\|\|/.test(inv), "investigate.js never reads a case's record of the mode as the mode");
  ok(/Object\.assign\(state, \{ live: false, imported: !!e\.imported, target: e\.target, type: kind, adultMode: false, adultBlocked: ""/.test(inv), "a case opened from History is not a run: it has no mode of its own, only what it recorded");
  const modes = code("modes.js");
  ok(!/collected|results|historyId|parseCaseFile|location\.|URLSearchParams|history\./.test(modes), "modes.js knows nothing of cases, History, case files or the URL");
}

// ---- 6. nothing is stored -------------------------------------------------------------------------
{
  for (const f of ["modes.js", "modeui.js"]) ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|\bstore\b|location\.(?:hash|search)|pushState|replaceState/.test(code(f)), `${f} never touches storage, cookies or the URL`);
  ok(!/localStorage|sessionStorage|indexedDB|document\.cookie|\bstore\b/.test(code("adult.js")), "adult.js never touches storage");
  // Every operation so far, on the shared session too, wrote nothing.
  const s = M.session;
  const mark = writes().length;
  s.request("adult", true, yes); s.request("active", true, yes);
  for (const h of [T, "someone_else", "anna15", "jdoe_example@example.org"]) runWould(s, h, h.includes("@") ? "email" : "username", M.makeRefusals());
  M.barSwitchHtml("adult", M.adultCase(true, T, "username")); M.sheetRowHtml("active", M.activeCase(true, "username")); M.statusHtml([{ id: "adult", view: M.adultCase(true, T, "username") }]);
  s.request("adult", false); s.request("active", false);
  ok(writes().length === mark && mark === 0 && calls.session.length === 0, "switching on, running, changing case, drawing and switching off wrote nothing to localStorage or sessionStorage");
  ok(!s.on("adult") && !s.on("active"), "(the shared session is off again for the rest of this suite)");

  // The legacy preferences: ignored, and removed by the one cleanup write each workbench makes on load.
  const inv = M.cleanPrefs(store.get("crawlr_v2_sources", {}));
  ok(inv.dirty && JSON.stringify(inv.prefs) === JSON.stringify({ sherlock: false }), "a stored active, adult or maigret.nsfw preference is dropped and the ordinary ones are kept");
  const rec = M.cleanPrefs(store.get("crawlr_v2_recon_sources", {}));
  ok(rec.dirty && JSON.stringify(rec.prefs) === JSON.stringify({ wayback: false }), "Recon's stored port scan preference is dropped the same way");
  if (inv.dirty) store.set("crawlr_v2_sources", inv.prefs);
  if (rec.dirty) store.set("crawlr_v2_recon_sources", rec.prefs);
  const w = writes();
  ok(w.length === 2 && w.every((c) => c[0] === "set") && !/active|nsfw|adult|portscan/.test(JSON.stringify(w)) && mem.crawlr_v2_sources === '{"sherlock":false}' && mem.crawlr_v2_recon_sources === '{"wayback":false}', "the only writes are the two that remove them, and neither holds a mode");
  ok(!M.cleanPrefs(store.get("crawlr_v2_sources", {})).dirty && !M.cleanPrefs({}).dirty && !M.cleanPrefs(null).dirty && M.cleanPrefs("x").dirty && JSON.stringify(M.cleanPrefs([1]).prefs) === "{}", "clean preferences need no write, and a value that is not an object is replaced");
  for (const id of ["active", "adult", "maigret.nsfw", "portscan", null, 7]) ok(!M.mayStore(id), `${JSON.stringify(id)} is never stored as a preference`);
  ok(M.mayStore("sherlock") && M.mayStore("wayback"), "ordinary sources are");
  const invSrc = code("investigate.js"), recSrc = code("recon.js");
  ok(/const \{ prefs: srcState, dirty: srcDirty \} = cleanPrefs\(store\.get\("crawlr_v2_sources", \{\}\)\);\s*\nconst saveSrc = \(\) => store\.set\("crawlr_v2_sources", srcState\);\s*\nif \(srcDirty\) saveSrc\(\);/.test(invSrc) && (invSrc.match(/crawlr_v2_sources/g) || []).length === 2, "Investigate reads its preferences through that cleanup and writes them in one place");
  ok(/const setSrc = \(id, v\) => \{ if \(!mayStore\(id\)\) return; srcState\[id\] = v; saveSrc\(\); \};/.test(invSrc), "and refuses to store a mode");
  ok(/const \{ prefs: srcState, dirty: srcDirty \} = cleanPrefs\(store\.get\("crawlr_v2_recon_sources", \{\}\)\);\s*\nconst saveSrc = \(\) => store\.set\("crawlr_v2_recon_sources", srcState\);\s*\nif \(srcDirty\) saveSrc\(\);/.test(recSrc) && /if \(!t \|\| !mayStore\(t\)\) return;\s*\n\s*srcState\[t\] = e\.target\.checked; saveSrc\(\);/.test(recSrc) && (recSrc.match(/crawlr_v2_recon_sources/g) || []).length === 2, "Recon does the same");
  ok(!/\{ id: "active", how:/.test(invSrc) && !/srcOn\("active"\)/.test(invSrc) && (invSrc.match(/session\.on\("active"\)/g) || []).length === 4, "Active techniques is no longer a stored source in Investigate: Deep Dive and the AI payload read the session");
  const core = code("core.js");
  ok(!/sessionStorage/.test(["investigate.js", "recon.js", "app.js", "core.js", "ui.js"].map(code).join("")) && /localStorage/.test(core), "nothing in the workbenches uses sessionStorage at all");
}

// ---- 7. Recon's port scan follows the Active mode -------------------------------------------------
{
  const rec = code("recon.js");
  ok(/id: "portscan"[^\n]*on: false, warn: "active", mode: "active" \}/.test(rec), "the port scan is marked as the Active techniques mode, and off by default");
  ok(/const modeOf = \(id\) => SOURCES\.find\(\(s\) => s\.id === id\)\?\.mode \|\| "";\s*\nexport const srcOn = \(id\) => \(modeOf\(id\) \? session\.on\(modeOf\(id\)\) : id in srcState/.test(rec), "a source with a mode is on exactly when the session mode is: its stored preference is never read");
  ok(/if \(on\("portscan"\) && !state\.cancelled\) late\.push\(source\("Port scan", "\/api\/infra\/portscan", T, "portscan"\)\);/.test(rec) && (rec.match(/\/api\/infra\/portscan/g) || []).length === 1 && /const on = srcOn;/.test(rec), "the run asks for a port scan in one place, behind that switch");
  ok(/s\.mode \? sheetRowHtml\(s\.mode, activeView\(\), \{ prefix: "r", name: s\.name, desc: PORTSCAN_DESC, tag: s\.warn \}\)/.test(rec) && !/data-toggle="portscan"/.test(rec), "its row in Recon's sheet is the mirrored mode switch, not a stored toggle");
  ok(/paintBar\(\$\("#rModes"\), \$\("#rModeStatus"\), \[\{ id: "active", view: v, desc: MODE\.active\.reconDesc, prefix: "r" \}\]\);/.test(rec) && M.MODE.active.reconDesc === "Port scan of the target host. May notify the target.", "Recon's case bar carries the Active techniques switch, worded for Recon");
  ok(/In Recon this is the port scan/.test(M.MODE.active.sheet) && /Deep Dive/.test(M.MODE.active.sheet) && /Deep Dive/.test(M.MODE.active.desc), "the one mode says what it covers in each workbench");
}

// ---- 8. the controls: one state, two places --------------------------------------------------------
{
  const s = M.makeSessionModes();
  const input = (id) => ({ dataset: { sessionMode: id }, checked: false });
  const bar = [input("adult"), input("active")], sheet = [input("adult"), input("active")], other = { dataset: { toggle: "sherlock" }, checked: true }, stray = { dataset: { sessionMode: "nope" }, checked: true };
  const all = [...bar, ...sheet, other, stray, null];
  let told = [];
  s.subscribe((id) => { told.push(id); M.syncSwitches(all, s); });
  s.request("adult", true, yes);
  ok(bar[0].checked && sheet[0].checked && !bar[1].checked && !sheet[1].checked && told.join() === "adult", "switching a mode on checks both copies of its switch and no other");
  // the investigator moved the sheet's copy of the other switch, then cancelled the confirmation
  sheet[1].checked = true;
  s.request("active", sheet[1].checked, no);
  ok(!sheet[1].checked && !bar[1].checked && !s.on("active"), "a switch that was moved and then cancelled goes back to off, in both places");
  s.request("active", true, yes); s.request("adult", false);
  ok(!bar[0].checked && !sheet[0].checked && bar[1].checked && sheet[1].checked, "Turn off unchecks both copies");
  ok(other.checked === true && stray.checked === true, "an ordinary source switch is never touched");
  const unsub = s.subscribe(() => {}); ok(typeof unsub === "function", "subscribe returns its own undo");

  // markup: the same attribute on both, a real switch, labelled and described
  const on = M.adultCase(true, T, "username"), offV = M.adultCase(false, T, "username");
  const b = M.barSwitchHtml("adult", on), sh = M.sheetRowHtml("adult", on);
  ok(/<input type="checkbox" role="switch" id="mode-adult" data-session-mode="adult" checked aria-labelledby="mode-adult-l" aria-describedby="mode-adult-d">/.test(b) && /<label class="mode-label" for="mode-adult" id="mode-adult-l">Adult sites<\/label>/.test(b) && /<span class="mode-desc" id="mode-adult-d">Existence checks on adult and dating sites\.<\/span>/.test(b), "the bar switch is a labelled role=switch with its one-line description as visible text");
  ok(/<input type="checkbox" role="switch" data-session-mode="adult" checked aria-labelledby="sheet-adult-l" aria-describedby="sheet-adult-d">/.test(sh) && /It stays on for every case until you switch it off or reload the page\./.test(sh), "the sheet's row is the same control, and says how long it lasts");
  ok(!/ checked/.test(M.barSwitchHtml("adult", offV)) && !/ checked/.test(M.sheetRowHtml("adult", offV)) && /class="mode off"/.test(M.barSwitchHtml("adult", offV)), "both are drawn off from the same view");
  const act = M.barSwitchHtml("active", M.activeCase(true, "username"));
  ok(/Active techniques <span class="tag warn">caution<\/span>/.test(act) && /<span class="tag warn">caution<\/span>/.test(M.sheetRowHtml("active", M.activeCase(true, "username"))) && !/tag warn/.test(b), "the caution tag stays on Active techniques, in both places");
  ok(/id="rmode-active"/.test(M.barSwitchHtml("active", M.activeCase(true, "domain", "recon"), { prefix: "r", desc: M.MODE.active.reconDesc })) && /Port scan of the target host/.test(M.barSwitchHtml("active", M.activeCase(true, "domain", "recon"), { prefix: "r", desc: M.MODE.active.reconDesc })), "Recon's copy has its own ids and wording");
  // per-case notes replace the description
  ok(/id="mode-adult-d">Not used for this kind of target\.</.test(M.barSwitchHtml("adult", M.adultCase(true, "a@b.org", "email"))) && /id="mode-adult-d">Not checked for this handle: it suggests a minor\.</.test(M.barSwitchHtml("adult", M.adultCase(true, "anna15", "username"))), "under the switch the description gives way to what is true for this case");
  ok(/sheet-adult-n">Adult and dating sites are not checked for this handle: it suggests a minor \(/.test(M.sheetRowHtml("adult", M.adultCase(true, "anna15", "username"))) && /aria-describedby="sheet-adult-d sheet-adult-n"/.test(M.sheetRowHtml("adult", M.adultCase(true, "anna15", "username"))), "and the sheet's row gives the full reason, as part of the switch's description");
  // no control looks like a login to a password manager
  const every = [b, sh, act, M.sheetRowHtml("active", M.activeCase(true, "username")), M.barSwitchHtml("active", M.activeCase(true, "ip", "recon"), { prefix: "r" }), M.statusHtml([{ id: "adult", view: on }, { id: "active", view: M.activeCase(true, "username") }])].join("");
  const attrs = [...every.matchAll(/\b(?:id|name|for|placeholder|aria-label)="([^"]*)"/g)].map((m) => m[1]).concat(Object.values(M.MODE).flatMap((m) => [m.label, m.off]));
  ok(attrs.length > 12 && !attrs.some((v) => /user|e-?mail|login|account|passw/i.test(v)), "no switch carries user, email, login or account in its label, id or name");
}

// ---- 9. the status line ----------------------------------------------------------------------------
{
  const rows = (a, b) => [{ id: "adult", view: a }, { id: "active", view: b }];
  ok(M.statusHtml(rows(M.adultCase(false, T, "username"), M.activeCase(false, "username"))) === "", "with both modes off there is no status line");
  const both = M.statusHtml(rows(M.adultCase(true, T, "username"), M.activeCase(true, "username")));
  ok(/<p class="mode-line" data-mode-line="adult"><span>Adult sites on for this session\.<\/span> <button type="button" class="linklike" data-mode-off="adult" aria-label="Turn off adult sites">Turn off<\/button><\/p>/.test(both), "Adult sites on for this session, with a one-click Turn off");
  ok(/<span>Active techniques on for this session\. May notify the target\.<\/span> <button type="button" class="linklike" data-mode-off="active" aria-label="Turn off active techniques">Turn off<\/button>/.test(both), "Active techniques on for this session, with the warning and its own Turn off");
  ok(/Adult sites on for this session\. Not used for this kind of target\./.test(M.statusHtml(rows(M.adultCase(true, "a@b.org", "email"), M.activeCase(false, "email")))) && !/Active techniques/.test(M.statusHtml(rows(M.adultCase(true, "a@b.org", "email"), M.activeCase(false, "email")))), "on a case it is not used for, the line says so and the mode stays on");
  ok(/Adult sites on for this session\. Adult and dating sites are not checked for this handle: it suggests a minor \(the handle starts or ends with a number from 10 to 17\)\./.test(M.statusHtml(rows(M.adultCase(true, "anna15", "username"), M.activeCase(false, "username")))), "for a handle that suggests a minor the line gives the reason");
  ok(!/<img|<a\b|style=|onclick/i.test(both) && M.statusHtml(rows(M.adultCase(true, '<img src=x onerror=1>"', "username"), M.activeCase(false, ""))).indexOf("<img") === -1, "the line is text and one button, and holds no part of the target");
  const html = read("../../static/v2/index.html");
  ok(/<div class="casebar-sub">\s*<div class="detected" id="targetDetected" aria-live="polite"><\/div>\s*<div class="modes" id="modes" role="group" aria-label="Session modes"><\/div>\s*<\/div>\s*<div class="mode-status" id="modeStatus" aria-live="polite" hidden><\/div>/.test(html), "Investigate's case bar: the switches sit beside the detected-type chips, the status line under them");
  ok(/<div class="detected" id="rTargetDetected" aria-live="polite"><\/div>\s*<div class="modes" id="rModes" role="group" aria-label="Session modes"><\/div>\s*<\/div>\s*<div class="mode-status" id="rModeStatus" aria-live="polite" hidden><\/div>/.test(html), "Recon's case bar has the same row");
  ok(html.indexOf('id="modes"') < html.indexOf('id="rail"') && html.indexOf('id="rModes"') < html.indexOf('id="rRail"'), "both are outside the Sources sheet");
  const inv = code("investigate.js");
  ok(/box\.insertAdjacentHTML\("beforeend", sheetRowHtml\("adult", adultView\(sourcesType\)\) \+ sheetRowHtml\("active", activeView\(sourcesType\)\)\);/.test(inv), "and the sheet still lists both, as the same control");
}

// ---- 10. the styles follow the design record --------------------------------------------------------
{
  const css = read("../../static/v2/css/app.css");
  const a = css.indexOf("/* session modes:"), part = css.slice(a, css.indexOf(".switch input:disabled", a));
  ok(a > 0 && part.length > 400 && !/#[0-9a-f]{3,8}\b/i.test(part) && !/url\(/.test(part), "the mode styles add no color and no image");
  ok((part.match(/var\(--violet\)/g) || []).length === 1 && /\.mode-line \.linklike:focus-visible \{ outline: 2px solid var\(--violet\)/.test(part) && !/btn-primary|--violet-2|--on-violet/.test(part), "purple appears only as the focus ring: the switches are ink");
  ok(/\.switch input:checked \+ span \{ background: var\(--switch-on\)/.test(css) && !/\.mode[^{]*\.switch[^{]*\{[^}]*background/.test(part), "they use the existing switch primitive unchanged");
  const srcs = ["modes.js", "modeui.js", "investigate.js", "recon.js", "app.js", "adult.js"].map((f) => read(J + f)).join("\n") + read("../../static/v2/index.html") + css + read("../../static/v2/DESIGN.md") + read("../../docs/ARCHITECTURE.md") + read("../../CLAUDE.md") + read("./modes.test.mjs");
  ok(!srcs.includes(String.fromCharCode(8212)), "no em dash in anything this change touched");
}

console.log(bad ? `${bad} of ${n} mode checks failed` : `${n}/${n} mode checks passed`);
process.exit(bad ? 1 : 0);
