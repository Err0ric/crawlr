// Session modes: "Adult sites" and "Active techniques" in Investigate, "Port scan" in Recon
// (static/v2/js/modes.js). Three separate modes: none switches another on.
// Off on every page load, on for the page session once switched on, never stored, asked about
// once, and honest per case: not used for the wrong kind of target, suspended for a handle that
// suggests a minor. No browser, no network.
// Run: node tests/js/modes.test.mjs
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
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

// One case after another, the way investigate.js starts them. run() calls M.startAdult() once when
// a run starts and keeps the answer; a pivot button passes the standing of the case it was on as
// `from`. Everything asserted about a run below is what that real function returned. adultCheck is
// the plan built from its answer by the function run() uses (is an adult pass planned?), and nsfw
// is the body of the ordinary run's own Sherlock and Maigret requests, which is false whatever
// the mode: adult sites are asked in a pass of their own, after the profile check.
function makeBench(s) {
  const suspended = M.makeSuspended();
  let minor = null;
  const start = (target, type, { pivot = false } = {}) => {
    const d = M.startAdult({ on: s.on("adult"), type, target, from: pivot && minor ? { minor } : null, suspended });
    minor = d.minor;
    const adult = A.adultOn(type, target, d.adult);
    return { ...d, nsfw: type === "username" ? A.usernameBody(A.handleOf(target), false).nsfw : undefined, adultCheck: sourcePlan(type, target, { adult }).includes("adult") };
  };
  return { start, suspended, open: (target, type) => start(target, type), refuse: (target, why) => { suspended.add(target, { server: true, detail: why }); minor = M.minorFor({ type: "username", target, suspended }); } };
}

// ---- 1. off on load, in memory only ------------------------------------------------------------
{
  ok(M.MODE_IDS.join() === "adult,active,portscan" && !M.session.on("portscan"), "there are three session modes, and the port scan is off on load too");
  ok(!M.session.on("adult") && !M.session.on("active"), "both are off when the module loads");
  const fresh = M.makeSessionModes();
  ok(!fresh.on("adult") && !fresh.on("active") && !fresh.accepted("adult") && !fresh.accepted("active") && !fresh.on("nope") && !fresh.on(undefined), "a new session starts with both off and nothing accepted");
  const cold = makeBench(fresh).start(T, "username");
  ok(cold.adult === false && cold.nsfw === false && !cold.adultCheck && cold.minor === null, "off: a run sends nsfw false and plans no adult site check");
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
  ok(M.MODE.adult.confirm.join(" ").match(/existence checks only/i) && /text/i.test(M.MODE.adult.confirm.join(" ")) && /not run for a handle that states an age under 18, and not when a profile found for the handle suggests a minor\. There is no way around that\./.test(M.MODE.adult.confirm.join(" ")) && /once the ordinary sources have run and the profiles they found have been checked/.test(M.MODE.adult.confirm.join(" ")) && /lawful purposes/.test(M.MODE.adult.confirm.join(" ")), "the adult confirmation says: after the ordinary sources, existence checks only, text only, not for a minor, lawful purposes");
  ok(/fetch the target's own profile pages/.test(M.MODE.active.confirm.join(" ")) && /may log the visit/.test(M.MODE.active.confirm.join(" ")) && !/port|scan|Recon/i.test(M.MODE.active.confirm.join(" ") + M.MODE.active.desc + M.MODE.active.sheet + M.MODE.active.status), "the active confirmation says what is fetched and that it may be logged, and says nothing about Recon or a port scan");
  ok(/scan 20 common ports on the target host on every Recon run/.test(M.MODE.portscan.confirm.join(" ")) && /the target's services may log/.test(M.MODE.portscan.confirm.join(" ")) && /own or are authorized to test/.test(M.MODE.portscan.confirm.join(" ")) && !/Deep Dive|profile|Investigate/i.test(M.MODE.portscan.confirm.join(" ") + M.MODE.portscan.desc + M.MODE.portscan.sheet + M.MODE.portscan.status), "the port scan confirmation says what is scanned and that it may be logged, and says nothing about Investigate or Deep Dive");
  ok(/May notify the target\./.test(M.MODE.active.desc) && /May notify the target\./.test(M.MODE.portscan.desc) && /May notify the target\./.test(M.MODE.active.status) && /May notify the target\./.test(M.MODE.portscan.status) && M.CAUTIONED.join() === "active,portscan", "both keep the warning and the caution tag");
  for (const id of M.MODE_IDS) ok(M.confirmHtml(id).includes("It stays on for every case until you switch it off or reload the page.") && /never saved/.test(M.confirmHtml(id)) && !/<(?!\/?p\b)/.test(M.confirmHtml(id).replace(/<p class="modal-p">/g, "<p>")), `the ${id} confirmation says how long it lasts, as plain paragraphs`);
}

// ---- 3. the mode survives every change of case ---------------------------------------------------
{
  const s = M.makeSessionModes(), b = makeBench(s);
  s.request("adult", true, yes); s.request("active", true, yes);
  const first = b.start(T, "username");
  ok(first.adult === true && first.nsfw === false && first.adultCheck, "on: the run plans the adult pass, and its ordinary requests still send nsfw false");
  // another handle typed, and the pivots: a similar handle's "Investigate this", a lead, a name candidate
  for (const [what, handle, pivot] of [["a different handle", "someone_else", false], ["a similar handle", "jdoe_examp1e", true], ["a lead pivot", "@other.person", true], ["a name candidate's handle", "jordan-doe", true], ["a re-run", T, false]]) {
    const r = b.start(handle, "username", { pivot });
    ok(r.adult === true && r.nsfw === false && r.adultCheck && s.on("adult") && s.on("active"), `${what} runs with the mode on, with no extra click`);
  }
  // The session has no way to be switched off except request(id, false): there is nothing a new
  // case, Clear or a case opened from History could call.
  ok(Object.keys(s).sort().join() === "accepted,blocked,on,request,subscribe", "the session has no reset: only a request can change it");
  const inv = code("investigate.js"), rec = code("recon.js"), app = code("app.js");
  const fn = (src, name) => { const a = src.indexOf(`export function ${name}(`); return src.slice(a, src.indexOf("\n}\n", a)); };
  for (const [name, body] of [["Investigate clearCase", fn(inv, "clearCase")], ["Investigate loadHistory", fn(inv, "loadHistory")], ["Recon clearCase", fn(rec, "clearCase")], ["Recon loadHistory", fn(rec, "loadHistory")]]) ok(body.length > 100 && !/session\.request|\.request\(|adultSwitch|suspended\.(?!add)/.test(body.replace(/startAdult\(\{[^}]*\}\)/, "")), `${name} does not change a session mode`);
  ok(!/session\.request|\.request\(/.test(inv) && !/session\.request|\.request\(/.test(rec) && !/session\.request|\.request\(/.test(app), "no workbench code switches a mode: Investigate, Recon and the entry point never call request");
  const ui = code("modeui.js");
  ok((ui.match(/session\.request\(/g) || []).length === 2 && /session\.request\(id, e\.target\.checked === true, ask\(id\)\)/.test(ui) && /session\.request\(id, false\)/.test(ui), "a mode changes in two places only: the switch's own change event, and Turn off");
  // Backstop: run() really calls the tested functions, once, and keeps what they said.
  ok(/const from = opts\.pivot === true && opts\.from === "case" && state\.minor \? \{ minor: state\.minor \} : null;\s*\n\s*const mode = startAdult\(\{ on: session\.on\("adult"\), type, target, from, suspended \}\);\s*\n\s*const av = mode\.view;/.test(inv) && /const adult = adultOn\(type, target, mode\.adult\);/.test(inv), "run() asks startAdult once, with the pivot's origin, and takes its answer");
  ok(/adultMode: false, adultBlocked: "", minor: mode\.minor \}\);/.test(inv) && (inv.match(/startAdult\(/g) || []).length === 2 && /const plan = new Set\(sourcePlan\(type, target, \{ adult \}\)\);/.test(inv) && /c\.adultMode = true; state\.adultMode = true;/.test(inv) && (inv.match(/adultMode = true/g) || []).length === 2, "the answer is kept for the whole run: the plan reads it, not the switch, and the case is marked as an adult case only once its profile check came back clean");
  ok(/const adultView = \(type, target = \$\("#targetInput"\)\.value\) => adultFor\(\{ on: session\.on\("adult"\), type, target, suspended \}\)\.view;/.test(inv), "the switch's own view is drawn by the same function");
  ok(/const from = current === "investigate" \? "case" : "other";/.test(app) && /startInvestigate\(v, b\.dataset\.pivotType \|\| "", \{ pivot: true, from \}\)/.test(app) && /run\(v, typeOverride \|\| undefined, opts\)/.test(app) && (app.match(/pivot: true/g) || []).length === 1, "every pivot button starts its run as a pivot, through one handler; a typed target does not");
}

// ---- 4. applicability stays honest per case ------------------------------------------------------
{
  const s = M.makeSessionModes(), b = makeBench(s);
  s.request("adult", true, yes);
  for (const [type, target] of [["email", "jdoe_example@example.org"], ["hash", "44d88612fea8a8f36de82e1278abb02f"], ["phone", "+1 202 555 0100"], ["name", "Jordan Doe"]]) {
    const r = b.start(target, type);
    ok(s.on("adult") && r.view.on && r.view.state === "unused" && r.view.note === "Not used for this kind of target." && !r.view.applies && r.adult === false && !r.adultCheck, `a ${type} case: the mode stays on, says it is not used, and nothing adult is requested`);
  }
  ok(b.start(T, "username").adultCheck === true, "and it applies again on the next username");
  // the minor guard suspends, with the reason, and has no override
  const young = b.start("anna_15yo", "username");
  ok(s.on("adult") && young.view.on && young.view.state === "suspended" && !young.view.applies && young.adult === false && young.nsfw === false && !young.adultCheck && young.minor.kind === "guard" && young.minor.via === "handle" && young.minor.block.kind === "handle", "a handle that states an age under 18: the mode stays on for the session and is suspended for that case");
  ok(young.view.reason === "Adult and dating sites are not checked for this handle: the handle states an age under 18." && young.view.note === M.MINOR_SHORT.handle && M.MINOR_SHORT.handle === "Not checked for this handle: it states an age under 18.", "with the reason shown");
  const worded = b.start("preteen_sam", "username");
  ok(worded.view.state === "suspended" && worded.minor.block.kind === "word" && worded.view.note === M.MINOR_SHORT.word && worded.view.reason === "Adult and dating sites are not checked for this handle: the handle contains a word that marks it as a minor's.", "one of the three words suspends it too, and says so");
  ok(!A.adultOn("username", "anna_15yo", true) && !sourcePlan("username", "anna_15yo", { adult: true }).includes("adult") && A.usernameBody("anna_15yo", A.adultOn("username", "anna_15yo", true)).nsfw === false, "and there is no override: even a literal true asks for nothing adult");
  for (const extra of [{ force: true }, { override: true }, { adult: true }, { minor: null }, { from: { minor: null } }]) ok(M.startAdult({ on: true, type: "username", target: "anna_15yo", suspended: M.makeSuspended(), ...extra }).adult === false, `no argument overrides the guard (${Object.keys(extra)[0]})`);
  // The owner's list: a bare number in the handle plans the adult pass like any other handle.
  for (const h of ["gamer13", "sk8r_15", "10outof10", "err0ric17", "mike1999", "mike2010", "anna15", "emma2012", "apollo13"]) { const r = b.start(h, "username"); ok(r.view.state === "applies" && r.adult === true && r.adultCheck && r.minor === null, `${h} is not suspended by its handle`); }
  const next = b.start("someone_else", "username");
  ok(s.on("adult") && next.view.state === "applies" && next.adult === true && next.adultCheck, "the next handle that passes runs with it on");
  ok(next.nsfw === false && young.nsfw === false, "and the ordinary run's own requests carry nsfw false either way: adult sites are a pass of their own");
  // the server's own guard refused a handle the page passed
  b.refuse("@Odd_Handle", "The handle contains a word that marks it as a minor's.");
  const refused = b.start("odd_handle", "username");
  ok(s.on("adult") && refused.view.state === "suspended" && refused.adult === false && refused.nsfw === false && !refused.adultCheck && refused.minor.kind === "server" && refused.view.reason === "Adult and dating sites are not checked for this handle: the handle contains a word that marks it as a minor's." && refused.view.note === M.MINOR_SHORT.server, "a refusal from the server suspends the mode for that handle, with its reason, and leaves the session on");
  ok(b.start(T, "username").adult === true, "and not for an unrelated handle");
  b.refuse("blank", "");
  ok(b.start("blank", "username").view.reason === "Adult and dating sites are not checked for this handle: the server refused this handle.", "a refusal with no reason still suspends it");
  const cap = M.makeSuspended(3); for (const h of ["qqa", "qqb", "qqc", "qqd"]) cap.add(h, { server: true });
  ok(cap.size === 3 && !cap.get("qqa") && cap.get("qqd") && cap.get("qqd").server === true, "the suspended list is bounded, and the newest handle is the one kept");
  const inv = read(J + "investigate.js");
  ok(/err\.code === "minor_guard"\) \{ adultRefused\(err\);/.test(inv) && /suspended\.add\(state\.target, \{ server: true, detail: err\.reason \|\| "" \}\);/.test(inv) && /state\.minor = suspendContent\(suspended, state\.target, block\);/.test(inv), "the run handles the server's refusal: the handle is suspended, by its handle or by what its profiles said");
  // off, the views say the same things about the case without claiming the mode is on
  const off = M.adultCase(false, "anna_15yo", "username");
  ok(off.state === "off" && !off.on && !off.applies && off.note === M.MINOR_SHORT.handle && M.adultCase(false, T, "email").note === M.NOT_USED && M.adultCase(false, T, "username").note === "" && M.adultCase(true, "", "").state === "idle" && M.adultCase("true", T, "username").on === false, "off is off whatever the case, and only the literal true is on");
  // Active techniques and the port scan
  ok(M.activeCase(true, "username").applies && M.portscanCase(true, "domain").applies && M.portscanCase(true, "ip").applies, "Active techniques applies to a username case in Investigate, and the port scan to a domain or an IP address in Recon");
  for (const t of ["email", "hash", "phone", "name", "domain"]) ok(M.activeCase(true, t).state === "unused" && M.activeCase(true, t).on && M.activeCase(true, t).note === M.NOT_USED, `Active techniques says it is not used for ${t}`);
  for (const t of ["asn", "username"]) ok(M.portscanCase(true, t).state === "unused" && M.portscanCase(true, t).on && M.portscanCase(true, t).note === M.NOT_USED, `the port scan says it is not used for ${t}`);
  ok(M.portscanCase(true, "").state === "idle" && M.portscanCase(false, "domain").state === "off" && !M.portscanCase(1, "domain").on && M.activeCase(true, "").state === "idle", "with no target they are idle, and off is off");
}

// ---- 4b. what a suspension covers: the handle, a pivot from it, and nothing else ----------------------
{
  const PIVOT = "Adult and dating sites are not checked here: this case was opened from emma_15yo, whose handle states an age under 18.";
  const BLOCK = { kind: "age", source: "Instagram", snippet: "16 | junior in high school", url: "https://www.instagram.com/river_stone/" };
  // Adult sites on, run emma_15yo, then "Investigate this" on a handle found on that case
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    const a = b.start("emma_15yo", "username");
    ok(a.adult === false && a.nsfw === false && !a.adultCheck && a.minor.kind === "guard" && a.minor.origin === "emma_15yo", "emma_15yo is suspended by its handle");
    const e = b.start("emma", "username", { pivot: true });
    ok(e.adult === false && e.nsfw === false && !e.adultCheck && e.view.state === "suspended" && e.minor.kind === "pivot" && e.minor.via === "handle" && e.view.reason === PIVOT && e.view.note === M.MINOR_TIED && s.on("adult"), "\"Investigate this\" on emma from emma_15yo: no adult pass, and the reason says where the case was opened from");
    ok(JSON.stringify(e.minor.block) === JSON.stringify({ kind: "pivot", source: "emma_15yo", via: "handle" }), "and that is what the case records");
    // it chains: a pivot from the suspended emma case is suspended too, whatever the handle
    const c = b.start("emma_w", "username", { pivot: true });
    ok(c.adult === false && !c.adultCheck && c.minor.kind === "pivot" && c.minor.origin === "emma_15yo" && c.view.reason === PIVOT, "the suspension chains: a pivot from that case is suspended, with the same origin");
    const c2 = b.start("unrelated_name", "username", { pivot: true });
    ok(c2.adult === false && c2.minor.kind === "pivot", "and so is the next pivot down the chain");
    // typed by hand afterwards: the handles reached by pivots stay suspended for the session
    for (const h of ["emma", "Emma", "@emma", "e.m.m.a", "emma_w", "unrelated_name"]) { const r = b.start(h, "username"); ok(r.adult === false && !r.adultCheck && r.view.state === "suspended" && r.minor.kind === "pivot", `typing ${h} by hand afterwards is still suspended`); }
    ok(b.start("someone_else", "username").adult === true, "a handle that was never tied to it runs with the mode on");
  }
  // a variant of a suspended handle is NOT suspended: it gets its own check of its own profiles
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    b.start("emma_15yo", "username");
    const { handleVariants } = await import(J + "similar.js");
    const variants = handleVariants("emma_15yo").map((v) => v.value).filter((v) => !A.minorGuard(v).blocked);
    ok(b.start("emma", "username").adult === true && b.start("emma15", "username").adult === true, "emma and emma15, typed by hand after emma_15yo, are judged on their own");
    for (const v of variants) { const r = b.start(v, "username"); ok(r.adult === true && r.adultCheck && r.minor === null && r.view.state === "applies", `the variant ${v}, typed by hand, is judged on its own`); }
    ok(!("variantText" in M) && !/handleVariants/.test(code("modes.js")), "the rule that suspended every variant is gone");
    ok(M.adultFor({ on: true, type: "username", target: "EMMA_15YO", suspended: b.suspended }).view.state === "suspended" && M.adultFor({ on: true, type: "username", target: "emmanuel", suspended: b.suspended }).adult === true, "the handle itself stays suspended however it is written, and a different handle is not caught");
  }
  // the content check stopped a run: that handle is suspended for the session, with what was found
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    ok(b.start("river_stone", "username").adult === true, "a clean handle starts with the adult pass planned");
    const kept = M.suspendContent(b.suspended, "river_stone", BLOCK);
    ok(kept.kind === "content" && kept.via === "content" && kept.origin === "river_stone" && kept.block.snippet === BLOCK.snippet, "suspendContent returns what the case keeps");
    const again = b.start("River.Stone", "username");
    ok(again.adult === false && !again.adultCheck && again.view.state === "suspended" && again.minor.kind === "content" && again.view.note === M.MINOR_SHORT.content, "the same handle, run again in this session, plans no adult pass");
    ok(again.view.reason === 'Adult and dating sites are not checked for this handle: a profile found for this handle states an age under 18 (Instagram: "16 | junior in high school").', "and the switch says which profile, with the quoted text");
    ok(JSON.stringify(again.minor.block) === JSON.stringify({ kind: "age", source: "Instagram", snippet: "16 | junior in high school", url: "https://www.instagram.com/river_stone/" }), "the case records the same block");
    const p = b.start("river", "username", { pivot: true });
    ok(p.adult === false && p.minor.kind === "pivot" && p.minor.via === "content" && p.view.reason === "Adult and dating sites are not checked here: this case was opened from river_stone, where a profile suggested a minor.", "a case opened from it by a pivot inherits the block, worded for a profile");
    ok(b.start("river", "username").minor?.kind === "pivot" && b.start("stone_river", "username").adult === true, "the pivoted handle stays tied, and an unrelated handle runs");
    ok(M.suspendContent(M.makeSuspended(), "x", { kind: "nope" }).block === null && M.makeSuspended().get("x") === null, "a block that cannot be read suspends nothing by itself");
    // Remote text in a block is bounded before it is kept.
    const big = M.suspendContent(M.makeSuspended(), "y", { kind: "age", source: "S".repeat(500), snippet: "x".repeat(500), url: "javascript:alert(1)" });
    ok(big.block.source.length === 80 && big.block.snippet.length === 60 && big.block.url === "", "the source, the snippet and the address of a block are bounded and checked");
  }
  // the same from an email case whose local part fails the handle check
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    const m = b.start("emma_15yo@example.org", "email");
    ok(m.adult === false && m.view.state === "unused" && m.minor && m.minor.kind === "guard" && m.minor.origin === "emma_15yo", "an email case whose local part states an age under 18 is marked, though the mode is not used for an email");
    const lead = b.start("emma", "username", { pivot: true });
    ok(lead.adult === false && !lead.adultCheck && lead.minor.kind === "pivot" && lead.view.reason === PIVOT, "\"Investigate this\" on emma from emma_15yo@example.org is suspended");
    ok(b.start("emma2012@example.org", "email").minor === null, "an email whose local part only carries a number is not marked");
  }
  // a refusal from the server spreads the same way
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    b.start("odd_handle9", "username");
    b.refuse("odd_handle9", "The handle contains a word that marks it as a minor's.");
    const p = b.start("odd_handle", "username", { pivot: true });
    ok(p.adult === false && p.minor.kind === "pivot" && /opened from odd_handle9, whose handle states an age under 18\.$/.test(p.view.reason), "a pivot from a handle the server refused is suspended");
    ok(b.start("oddhandle9", "username").adult === false && b.start("odd_handle9", "username").minor.kind === "server", "and the refused handle stays refused, however it is written");
  }
  // a case opened from History is a case too: it is judged without a run
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    b.open("emma_15yo", "username");
    ok(b.start("emma", "username", { pivot: true }).adult === false && b.start("emma", "username").adult === false, "a pivot from a case opened from History is suspended, and stays so when typed");
  }
  // the mode being off changes nothing about who is remembered
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    b.start("emma_15yo", "username"); b.start("emma", "username", { pivot: true });
    s.request("adult", true, yes);
    ok(b.start("emma", "username").adult === false && b.start("emma_15yo", "username").adult === false, "handles seen while the mode was off are suspended once it is switched on");
  }
  // not a pivot: a case that only follows a suspended one in time inherits nothing
  {
    const s = M.makeSessionModes(), b = makeBench(s);
    s.request("adult", true, yes);
    b.start("emma_15yo", "username");
    ok(b.start("torvalds", "username").adult === true, "a new handle typed after a suspended case runs with the mode on");
    ok(M.minorFor({ type: "username", target: "torvalds", from: { minor: null } }) === null && M.minorFor({ type: "name", target: "Jordan Doe", from: { minor: { origin: "emma_15yo" } } }).kind === "pivot", "inheritance needs a suspended origin, and then covers any kind of case");
  }
  ok(M.normHandle("@Em.Ma_20-12") === "emma2012" && M.caseHandle("email", "emma2012+x@example.org") === "emma2012" && M.caseHandle("username", "@emma") === "emma" && M.caseHandle("hash", "abc") === "", "handles are compared without case, a leading @ or separators");
  ok(M.statusHtml([{ id: "adult", view: M.adultFor({ on: true, type: "username", target: "x", from: { minor: { origin: '<img src=x onerror=1>' } } }).view }]).indexOf("<img") === -1 && M.pivotText("a".repeat(200)).length < 200, "the origin handle is clipped, and escaped where it is shown");
  { // the quoted profile text is remote: it is escaped wherever the switch shows it
    const sus = M.makeSuspended(); M.suspendContent(sus, "z", { kind: "age", source: "Git<b>Hub", snippet: 'i am 15 <img src=x onerror=1> "q"', url: "https://github.com/z" });
    const v = M.adultFor({ on: true, type: "username", target: "z", suspended: sus }).view;
    const html = M.statusHtml([{ id: "adult", view: v }]) + M.sheetRowHtml("adult", v);
    ok(!/<img|<b>/.test(html) && html.includes("&lt;img src=x onerror=1&gt;") && v.reason.includes('(GitbHub: "i am 15 <img'), "a snippet with markup is shown as text in the status line and the sheet");
  }
  // Without the minor rules the adult mode cannot be switched on, and says why.
  {
    const scan = await import(J + "minorscan.js");
    const { RULES } = await import("./rules.mjs");
    ok(scan.setRules({ version: 99 }) === false && !scan.rulesReady() && scan.rulesError() !== "", "a rules file with another version is refused");
    const s = M.makeSessionModes();
    let asked = 0;
    ok(s.request("adult", true, () => { asked++; }) === "off" && asked === 0 && !s.on("adult") && s.blocked("adult") === A.RULES_UNAVAILABLE && s.blocked("active") === "", "the switch stays off, nothing is asked, and it says the rules could not be loaded");
    ok(s.request("active", true, yes) === "on" && s.on("active"), "the other modes are not affected");
    const v = M.adultFor({ on: true, type: "username", target: "torvalds" });
    ok(v.adult === false && v.view.state === "suspended" && v.view.note === M.MINOR_SHORT.rules && A.minorGuard("torvalds").kind === "rules" && A.adultRequests("torvalds", { blocked: false }).length === 0, "every handle is refused, and no adult request can be built");
    ok(scan.scanProfiles([], "torvalds").blocked === true && scan.softBirthYear("mike2010") === null, "the content check fails closed too");
    for (const bad of [null, {}, "x", { ...RULES, handle: undefined }, { ...RULES, content: { ...RULES.content, rules: [{ id: "x", kind: "age", strength: "strong", fields: ["bio"], value: "none", pattern: "(" }] } }]) ok(scan.setRules(bad) === false && !scan.rulesReady(), "a rules file that does not validate leaves the guard closed");
    let fetched = 0;
    ok(await scan.loadRules(async () => { fetched++; return { ok: false, status: 404 }; }) === false && !scan.rulesReady() && await scan.loadRules(async () => { throw new Error("offline"); }) === false && !scan.rulesReady(), "a failed fetch leaves it closed");
    // A session that was on goes dark when the rules go away, and back when they are in again.
    scan.setRules(RULES);
    const s2 = M.makeSessionModes(); s2.request("adult", true, yes);
    scan.setRules(null);
    ok(!s2.on("adult"), "a mode that was on is off while the rules are missing");
    ok(await scan.loadRules(async (url) => { ok(String(url).endsWith("/data/minor-rules.json"), "the page fetches the one rules file, next to its scripts"); return { ok: true, status: 200, json: async () => RULES }; }) === true && scan.rulesReady() && s2.on("adult"), "and the rules load through one fetch at startup");
    ok(/loadRules\(\)\.then\(refreshModes\);/.test(code("app.js")) && !/import [^;]*\.json/.test(code("minorscan.js")) && !/with \{ type: "json" \}/.test(code("minorscan.js")), "app.js loads them at boot with a fetch, not a JSON module import");
  }
  const inv = code("investigate.js");
  ok(/const suspended = makeSuspended\(\);/.test(inv) && !/localStorage|sessionStorage/.test(code("modes.js")) && /minor: startAdult\(\{ on: session\.on\("adult"\), type: kind, target: e\.target, suspended \}\)\.minor \|\| storedMinor,/.test(inv) && /adultBlocked: "", minor: null, target: ""/.test(inv), "the list lives in memory, a case opened from History is judged by the same function, and Clear forgets the case, not the list");
  ok(!/suspended\.(add|tie)\(/.test(inv.slice(inv.indexOf("export function loadHistory("), inv.indexOf("export function clearCase("))), "opening a saved case that was stopped does not suspend its handle for the session: running it again checks again");
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
  const bq = makeBench(s);
  for (const h of [T, "someone_else", "anna15", "emma2012", "emma", "jdoe_example@example.org"]) bq.start(h, h.includes("@") ? "email" : "username", { pivot: h === "emma" });
  M.portscanFor({ on: s.on("portscan"), type: "domain", startedBy: "run" }); M.deepDiveFor({ on: s.on("active") });
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
  ok(!/\{ id: "active", how:/.test(invSrc) && !/srcOn\("active"\)/.test(invSrc) && (invSrc.match(/session\.on\("active"\)/g) || []).length === 5, "Active techniques is no longer a stored source in Investigate: Deep Dive and the AI payload read the session");
  const core = code("core.js");
  ok(!/sessionStorage/.test(["investigate.js", "recon.js", "app.js", "core.js", "ui.js"].map(code).join("")) && /localStorage/.test(core), "nothing in the workbenches uses sessionStorage at all");
}

// ---- 7. Recon's port scan is its own mode, apart from Investigate's Active techniques -----------------
{
  const rec = code("recon.js"), inv = code("investigate.js"), app0 = code("app.js");
  // What each workbench would do, read the way its code reads the session.
  const deepDive = (s) => s.on("active");            // investigate.js: canDeep = session.on("active") && ...
  const portScan = (s) => s.on("portscan");          // recon.js: srcOn("portscan") = session.on(modeOf("portscan"))
  const a = M.makeSessionModes();
  let asked = [];
  const yesTo = (id) => (x) => { asked.push(id); x.accept(); };
  a.request("active", true, yesTo("active"));
  ok(deepDive(a) && !portScan(a) && !a.on("portscan") && !a.accepted("portscan") && asked.join() === "active", "switching Active techniques on in Investigate leaves Recon's port scan off: a Recon run would make no /api/infra/portscan call");
  a.request("portscan", true, yesTo("portscan"));
  ok(asked.join() === "active,portscan" && portScan(a), "the port scan has its own first-use confirmation, even after Active techniques was accepted");
  a.request("active", false);
  ok(!deepDive(a) && portScan(a), "switching Active techniques off leaves the port scan on");
  const b2 = M.makeSessionModes();
  b2.request("portscan", true, yes);
  ok(portScan(b2) && !deepDive(b2) && !b2.on("active") && !b2.accepted("active") && !b2.on("adult"), "and the reverse: switching the port scan on in Recon leaves Active techniques off, so Deep Dive is not offered and no profile page is fetched");
  b2.request("portscan", false); b2.request("portscan", true, never);
  ok(portScan(b2) && !deepDive(b2), "it survives being switched off and on in its own workbench, without asking again");
  // the wiring: each workbench reads only its own mode
  ok(/id: "portscan"[^\n]*on: false, warn: "caution", mode: "portscan" \}/.test(rec), "the port scan source is marked with its own mode, and off by default");
  ok(/const modeOf = \(id\) => SOURCES\.find\(\(s\) => s\.id === id\)\?\.mode \|\| "";\s*\nexport const srcOn = \(id\) => \(modeOf\(id\) \? session\.on\(modeOf\(id\)\) : id in srcState/.test(rec), "a source with a mode is on exactly when that session mode is: its stored preference is never read");
  ok(/if \(scan\.scan && !state\.cancelled\) late\.push\(source\("Port scan", "\/api\/infra\/portscan", T, "portscan"\)\);/.test(rec) && (rec.match(/\/api\/infra\/portscan/g) || []).length === 1 && !/[^.]on\("portscan"\)/.test(rec), "the run asks for a port scan in one place, behind the decision made when it started");

  // Who started the run decides. portscanFor() is the function recon.js calls, once, at the start.
  const P = (startedBy, on = true, type = "domain") => M.portscanFor({ on, type, startedBy });
  ok(P("run").scan === true && P("run").note === "" && P("run", true, "ip").scan === true, "Port scan on, Run recon pressed in Recon's own box: the scan runs");
  for (const how of ["pivot", "lead", "brief", "node", "landing", "history", "investigate", undefined, null, "", "RUN", true, 1]) ok(P(how).scan === false && P(how).note === "Port scan not run: this case was opened from a link. Press Run recon to scan this host.", `started by ${JSON.stringify(how)}: no scan, and the note says how to run one`);
  ok(P("run", false).scan === false && P("run", false).note === "" && P("pivot", false).note === "" && P("run", true, "asn").scan === false && P("pivot", true, "asn").note === "" && P("run", "true").scan === false && P("run", 1).scan === false, "with the mode off, or for an ASN, nothing is scanned and there is nothing to say");
  ok(Object.keys(P("run")).join() === "scan,note" && M.portscanFor().scan === false, "the decision is those two values and nothing else");
  ok(/const scan = portscanFor\(\{ on: session\.on\("portscan"\), type, startedBy: opts\.startedBy === "run" \? "run" : "pivot" \}\);\s*\n\s*state\.scanNote = scan\.note;/.test(rec) && (rec.match(/portscanFor\(/g) || []).length === 1, "run() asks it once when the run starts and keeps the answer: a switch moved mid-run changes the next run");
  ok(/export async function run\(raw0, opts = \{\}\)/.test(rec) && (rec.match(/startedBy: "run"/g) || []).length === 1 && /\$\("#rRunBtn"\)\.addEventListener\("click", \(\) => \{[^\n]*run\(\$\("#rTargetInput"\)\.value, \{ startedBy: "run" \}\); \}\);/.test(rec) && /if \(e\.key === "Enter" && !state\.running\) \$\("#rRunBtn"\)\.click\(\);/.test(rec), "only the Run recon button (and Enter in Recon's box, which presses it) starts a run as \"run\"");
  ok(/run\(b\.dataset\.runNode\);/.test(rec) && /function startRecon\(v\) \{ show\("recon", \{ focus: false \}\); recon\.run\(v\)\.then/.test(app0) && !/startedBy/.test(app0), "a topology node, a lead, a brief action, the landing form and the other workbench all start it with no claim to be a run");
  ok(/if \(scan\.note\) log\.add\(scan\.note, "skip"\);/.test(rec) && /state\.scanNote \? h`<div class="notice" role="note" id="rScanNote">\$\{state\.scanNote\}<\/div>` : ""/.test(rec) && (rec.match(/scanNote: ""/g) || []).length === 4, "the note goes in the run log and above the findings, and is cleared with the case");
  // Deep Dive asks again at the moment it would fetch
  ok(M.deepDiveFor({ on: true }).fetch === true && M.deepDiveFor({ on: false }).fetch === false && M.deepDiveFor({ on: "true" }).fetch === false && M.deepDiveFor().fetch === false && M.deepDiveFor({ on: false }).note === "Active techniques was switched off, so no profile page was fetched.", "a Deep Dive may fetch only while Active techniques is on");
  ok(/async function runDeepDive\(urls\) \{\s*\n[^\n]*\n\s*const may = deepDiveFor\(\{ on: session\.on\("active"\) \}\);\s*\n\s*if \(!may\.fetch\) \{ toast\(may\.note, 5000\); renderAiPanel\(\); return; \}/.test(read(J + "investigate.js")) && code("investigate.js").indexOf("const may = deepDiveFor") < code("investigate.js").indexOf('post("/api/recon/scrape-profiles"'), "runDeepDive checks it before the request that fetches the pages");
  const noStatus = (src) => src.replace(/paintStatus\([^\n]*\n/g, "").replace(/^import [^\n]*$/gm, "");
  ok(!/"active"|"adult"|activeCase|adultCase/.test(noStatus(rec)) && (noStatus(rec).match(/session\.on\(/g) || []).length === 3 && /session\.on\("portscan"\)/.test(rec), "recon.js reads Investigate's modes only to name them in the status line");
  ok(!/portscan|portscanCase/.test(noStatus(inv)) && !/session\.on\((?!"adult"\)|"active"\))/.test(noStatus(inv)), "investigate.js reads Recon's mode only to name it in the status line");
  ok(/s\.mode \? sheetRowHtml\(s\.mode, scanView\(\), \{ prefix: "r" \}\)/.test(rec) && !/data-toggle="portscan"/.test(rec), "its row in Recon's sheet is the mirrored mode switch, not a stored toggle");
  ok(/paintBar\(\$\("#rModes"\), \[\{ id: "portscan", view: v, desc: MODE\.portscan\.desc, prefix: "r" \}\]\);/.test(rec) && M.MODE.portscan.desc === "Connects to 20 common ports. May notify the target." && M.MODE.portscan.label === "Port scan", "Recon's case bar carries the Port scan switch and nothing else");
  const st = M.statusHtml([{ id: "portscan", view: M.portscanCase(true, "domain") }]);
  ok(/<span>Port scan on for this session\. May notify the target\.<\/span> <button type="button" class="linklike" data-mode-off="portscan" aria-label="Turn off the port scan">Turn off<\/button>/.test(st) && !/Active techniques/.test(st), "Recon's status line is the port scan's own");
  const app = read(J + "app.js");
  ok(/domain: "Runs in Recon: DNS, WHOIS, TLS, headers, subdomains and exposure\. A port scan runs only if you switch Port scan on\."/.test(app) && /ip: "Runs in Recon: TLS, headers, network owner and exposure\. A port scan runs only if you switch Port scan on\."/.test(app) && !/exposure and a port scan/.test(app), "the landing page no longer says a port scan runs by default");
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
  ok(/<input type="checkbox" role="switch" id="mode-adult" data-session-mode="adult" checked aria-label="Adult sites" aria-labelledby="mode-adult-l" aria-describedby="mode-adult-d">/.test(b) && /<label class="mode-label" for="mode-adult" id="mode-adult-l">Adult sites<\/label>/.test(b) && /<span class="mode-desc" id="mode-adult-d">Existence checks on adult and dating sites\.<\/span>/.test(b), "the bar switch is a labelled role=switch with its one-line description as visible text");
  ok(/<input type="checkbox" role="switch" data-session-mode="adult" checked aria-label="Adult sites" aria-labelledby="sheet-adult-l" aria-describedby="sheet-adult-d">/.test(sh) && /aria-label="Port scan" aria-labelledby="rsheet-portscan-l"/.test(M.sheetRowHtml("portscan", M.portscanCase(true, "domain"), { prefix: "r" })) && /It stays on for every case until you switch it off or reload the page\./.test(sh), "the sheet's row is the same control, and says how long it lasts");
  ok(!/ checked/.test(M.barSwitchHtml("adult", offV)) && !/ checked/.test(M.sheetRowHtml("adult", offV)) && /class="mode off"/.test(M.barSwitchHtml("adult", offV)), "both are drawn off from the same view");
  const act = M.barSwitchHtml("active", M.activeCase(true, "username"));
  ok(/Active techniques <span class="tag warn">caution<\/span>/.test(act) && /<span class="tag warn">caution<\/span>/.test(M.sheetRowHtml("active", M.activeCase(true, "username"))) && !/tag warn/.test(b), "the caution tag stays on Active techniques, in both places");
  const scan = M.barSwitchHtml("portscan", M.portscanCase(true, "domain"), { prefix: "r" });
  ok(/id="rmode-portscan" data-session-mode="portscan" checked/.test(scan) && /Port scan <span class="tag warn">caution<\/span>/.test(scan) && /Connects to 20 common ports\. May notify the target\./.test(scan) && /Port scan <span class="tag warn">caution<\/span>/.test(M.sheetRowHtml("portscan", M.portscanCase(true, "domain"), { prefix: "r" })), "Recon's switch has its own ids, wording and caution tag, in both places");
  // per-case notes replace the description
  ok(/id="mode-adult-d">Not used for this kind of target\.</.test(M.barSwitchHtml("adult", M.adultCase(true, "a@b.org", "email"))) && /id="mode-adult-d">Not checked for this handle: it states an age under 18\.</.test(M.barSwitchHtml("adult", M.adultCase(true, "anna_15yo", "username"))) && /id="mode-adult-d">Existence checks on adult and dating sites\.</.test(M.barSwitchHtml("adult", M.adultCase(true, "anna15", "username"))), "under the switch the description gives way to what is true for this case");
  ok(/sheet-adult-n">Adult and dating sites are not checked for this handle: the handle states an age under 18\.</.test(M.sheetRowHtml("adult", M.adultCase(true, "anna_15yo", "username"))) && /aria-describedby="sheet-adult-d sheet-adult-n"/.test(M.sheetRowHtml("adult", M.adultCase(true, "anna_15yo", "username"))), "and the sheet's row gives the full reason, as part of the switch's description");
  // no control looks like a login to a password manager
  const every = [b, sh, act, M.sheetRowHtml("active", M.activeCase(true, "username")), scan, M.sheetRowHtml("portscan", M.portscanCase(true, "ip"), { prefix: "r" }), M.statusHtml([{ id: "adult", view: on }, { id: "active", view: M.activeCase(true, "username") }])].join("");
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
  ok(/Adult sites on for this session\. Adult and dating sites are not checked for this handle: the handle states an age under 18\.</.test(M.statusHtml(rows(M.adultCase(true, "anna_15yo", "username"), M.activeCase(false, "username")))) && !/not checked/.test(M.statusHtml(rows(M.adultCase(true, "anna15", "username"), M.activeCase(false, "username")))), "for a handle that states an age under 18 the line gives the reason, and a bare number gives none");
  ok(!/<img|<a\b|style=|onclick/i.test(both) && M.statusHtml(rows(M.adultCase(true, '<img src=x onerror=1>"', "username"), M.activeCase(false, ""))).indexOf("<img") === -1, "the line is text and one button, and holds no part of the target");
  // the other workbench's mode is named too, and a run in flight says when a change applies
  const foreign = M.statusHtml([{ id: "adult", view: M.adultCase(false, "", "") }, { id: "portscan", view: M.portscanCase(true, ""), foreign: "Recon" }]);
  ok(/<span>Port scan on \(Recon\)\.<\/span> <button type="button" class="linklike" data-mode-off="portscan" aria-label="Turn off the port scan">Turn off<\/button>/.test(foreign) && !/Not used|May notify/.test(foreign), "Investigate says \"Port scan on (Recon).\" while Recon's mode is on, with its Turn off");
  const back = M.statusHtml([{ id: "portscan", view: M.portscanCase(false, "") }, { id: "adult", view: M.adultCase(true, "", ""), foreign: "Investigate" }, { id: "active", view: M.activeCase(true, ""), foreign: "Investigate" }]);
  ok(/Adult sites on \(Investigate\)\./.test(back) && /Active techniques on \(Investigate\)\./.test(back) && (back.match(/data-mode-off=/g) || []).length === 2, "and Recon names Investigate's modes the same way");
  ok(/Port scan on for this session\. May notify the target\. Port scan not run: this case was opened from a link\. Press Run recon to scan this host\./.test(M.statusHtml([{ id: "portscan", view: { ...M.portscanCase(true, "domain"), state: "suspended", reason: M.PORTSCAN_PIVOT_NOTE } }])) && /const line = v\.on && state\.scanNote \? \{ \.\.\.v, state: "suspended", reason: state\.scanNote \} : v;/.test(code("recon.js")), "a Recon case opened by a pivot says in the status line that the scan did not run");
  const busy = M.statusHtml(rows(M.adultCase(true, T, "username"), M.activeCase(false, "username")), { running: true });
  ok(/<p class="mode-line mode-wait">A run is in progress: a change applies from the next run\.<\/p>$/.test(busy) && M.statusHtml(rows(M.adultCase(false, T, "username"), M.activeCase(false, "username")), { running: true }) === "" && !/mode-wait/.test(both), "while a run is in flight the line says a change applies from the next run, and only then");
  const html = read("../../static/v2/index.html");
  ok(/<div class="casebar-sub">\s*<div class="detected" id="targetDetected" aria-live="polite"><\/div>\s*<div class="modes" id="modes" role="group" aria-label="Session modes"><\/div>\s*<\/div>/.test(html) && /<div class="detected" id="rTargetDetected" aria-live="polite"><\/div>\s*<div class="modes" id="rModes" role="group" aria-label="Session modes"><\/div>\s*<\/div>/.test(html), "the switches sit beside the detected-type chips in both case bars");
  ok(html.indexOf('id="modes"') < html.indexOf('id="rail"') && html.indexOf('id="rModes"') < html.indexOf('id="rRail"'), "both are outside the Sources sheet");
  // the on-state stays in view at every width: a sticky strip outside the case bar, never [hidden]
  ok(/<div class="modestrip mode-status" id="modeStatus" aria-live="polite"><\/div>\s*<div class="workspace">/.test(html) && /<div class="modestrip mode-status" id="rModeStatus" aria-live="polite"><\/div>\s*<div class="workspace">/.test(html) && !/id="r?[mM]odeStatus"[^>]*hidden/.test(html), "the status line is a strip between the case bar and the results in both workbenches, rendered always");
  ok(/<aside class="aside" id="aside" aria-label="Case summary">\s*<div class="mode-status mode-echo" id="modeEcho"><\/div>/.test(html) && /<aside class="aside" id="rAside" aria-label="Case summary">\s*<div class="mode-status mode-echo" id="rModeEcho"><\/div>/.test(html) && !/id="r?[mM]odeEcho"[^>]*aria-live/.test(html), "and it is repeated at the top of the summary column, which is what the Case details drawer shows");
  const css = read("../../static/v2/css/app.css");
  ok(/\.modestrip \{ position: sticky; top: calc\(var\(--topbar-h\) \+ var\(--casebar-own, 0px\)\);/.test(css) && /\.mode-status:empty \{ display: none; \}/.test(css) && !/\.mode-status\[hidden\]/.test(css) && /\.mode-echo \{ display: none; \}\s*\n#sheet \.mode-echo:not\(:empty\) \{ display: flex;/.test(css), "the strip is sticky under the top bar at every width, is hidden only by being empty, and its copy shows only in the drawer");
  const inv = code("investigate.js"), rec = code("recon.js"), ui = code("modeui.js"), app = code("app.js");
  ok(/paintStatus\(\[\$\("#modeStatus"\), \$\("#modeEcho"\)\], \[\.\.\.rows, \{ id: "portscan", view: portscanCase\(session\.on\("portscan"\), ""\), foreign: "Recon" \}\], \{ running: state\.running \}\);/.test(inv) && /paintStatus\(\[\$\("#rModeStatus"\), \$\("#rModeEcho"\)\], \[\{ id: "portscan", view: line \}, \{ id: "adult", [^\n]*foreign: "Investigate" \}, \{ id: "active", [^\n]*foreign: "Investigate" \}\], \{ running: state\.running \}\);/.test(rec), "each workbench draws its own modes and names the other's, in the strip and in the drawer");
  ok(!/\.hidden\s*=/.test(ui) && /box\.innerHTML = html;/.test(ui), "the strip is emptied, never hidden, so it stays a live region");
  ok(/\$\("#main"\)\.setAttribute\("aria-busy", on\);\s*\n\s*paintModes\(\);/.test(inv) && /\$\("#rMain"\)\.setAttribute\("aria-busy", on\);\s*\n\s*paintModes\(\);/.test(rec), "the line is redrawn when a run starts and when it ends");
  ok(/const own = c && getComputedStyle\(c\)\.position === "sticky" \? c\.offsetHeight : 0;/.test(app) && /"--casebar-h", `\$\{own \+ \(strip \? strip\.offsetHeight : 0\)\}px`/.test(app) && /\$\$\("\.casebar, \.modestrip"\)\.forEach\(\(c\) => casebarWatch\.observe\(c\)\);/.test(app), "what is sticky below it (the result tabs, the summary column) is offset by the strip's height");
  ok(/sheet \? sheet\.querySelector\("\[data-close\]"\) :/.test(ui), "Turn off inside the drawer keeps focus in the drawer");
  // a dialog button is already detached when the click reaches the document
  ok(/if \(!e\.target\.isConnected\) return;\s*\n\s*if \(\$\("\.rail\.open"\) && !e\.target\.closest\("\.rail, \.sources-btn, #overlays"\)\) closeRail\(\);/.test(app), "confirming or cancelling a dialog opened from the Sources sheet does not close the sheet");
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
