// The engine for the minor guard's rules. Pure: no DOM, no storage, and no network apart from
// loadRules(), which the page calls once at startup.
//
// Every pattern and threshold lives in one file, static/v2/data/minor-rules.json, which the server
// reads too (core/minor_rules.py is the same engine in Python). Nothing in this module is a rule:
// it checks the file and applies it. tests/test_minor_parity.py runs the same fixtures through
// both engines and fails on any difference.
//
//   handleToken(handle)             "age" or "word" when the handle itself carries an explicit age
//                                   under 18 or one of three words, else ""
//   softBirthYear(handle, today)    a four-digit year in the handle that would make the person 6
//                                   to 18 today, else null. It never blocks on its own
//   scanProfiles(profiles, handle, today)
//                                   reads the names and bios of the profiles found for a handle:
//                                   { blocked, kind, signal, signals, soft, read }
//
// Fail closed: until setRules() has accepted a rules file, rulesReady() is false, handleToken()
// answers "rules" and scanProfiles() answers blocked. The adult mode cannot be switched on then.
// English only. Text is normalised before any pattern sees it (see `normalize` in the rules
// file), and both engines work on code points, so a snippet is the same string on both sides.

export const RULES_VERSION = 1;
export const RULES_URL = new URL("../data/minor-rules.json", import.meta.url);
const SOURCE_MAX = 80, URL_MAX = 600, FIELD_MAX = 40;
const cps = (v) => Array.from(String(v ?? ""));
const clip = (v, n) => cps(v).slice(0, n).join("");
const int = (v) => { const n = Number(v); if (!Number.isInteger(n)) throw new Error("number"); return n; };
const str = (v) => { if (typeof v !== "string") throw new Error("text"); return v; };
const inRange = (ranges, cp) => ranges.some(([a, b]) => a <= cp && cp <= b);

// today: a Date, "YYYY-MM-DD" or [y, m, d].
export function ymd(today = new Date()) {
  if (today instanceof Date) return [today.getFullYear(), today.getMonth() + 1, today.getDate()];
  if (typeof today === "string") return today.split("-").map(Number);
  return today.map(Number);
}

// Builds an engine from a parsed rules file. Throws when the file does not validate.
export function makeEngine(doc) {
  if (!doc || typeof doc !== "object" || doc.version !== RULES_VERSION) throw new Error("version");
  const n = doc.normalize, macros = Object.entries(doc.macros).map(([k, v]) => [`{{${k}}}`, str(v)]);
  const rx = (pattern, flags = "") => {
    let text = str(pattern);
    for (let i = 0; i < 5; i++) for (const [k, v] of macros) text = text.split(k).join(v);
    if (text.includes("{{")) throw new Error("macro");
    return new RegExp(text, flags);
  };
  const ws = n.whitespace.map(([a, b]) => [int(a), int(b)]), breaks = new Set(n.line_break.map(int)), drop = new Set(n.drop.map(int));
  const map = new Map(Object.entries(n.map).map(([k, v]) => [k, str(v)])), sepRanges = n.separator_ranges.map(([a, b]) => [int(a), int(b)]);
  const SEP = str(n.separator), OTHER = str(n.other), MAX_CHARS = int(n.max_chars);
  const delimSet = new Set(str(doc.clause.delimiters)), periodWord = int(doc.clause.period_needs_word);
  const snippetMax = int(doc.snippet_max), signalsMax = int(doc.signals_max), adultAge = int(doc.adult_age);
  const h = doc.handle, strip = str(h.strip), handleSeps = new Set(str(h.separators));
  const ageMin = int(h.age.min), ageMax = int(h.age.max), ageRx = Object.values(h.age.patterns).map((p) => rx(p, "g"));
  const wordsRx = rx(h.words.pattern), leet = h.words.leet.map((t) => new Map(Object.entries(t).map(([k, v]) => [k, str(v)])));
  const softRx = rx(h.soft_year.pattern, "g"), softMin = int(h.soft_year.min_age), softMax = int(h.soft_year.max_age);
  const c = doc.content, birth = c.birth, cls = c.class_year;
  const birthRx = rx(birth.field_pattern), ageFieldRx = rx(birth.age_field_pattern);
  for (const k of ["min_age", "year_only_max_age", "two_digit_base", "age_min", "age_max"]) int(birth[k]);
  for (const k of ["max_ahead", "strong_ahead", "this_year_until_month", "two_digit_base"]) int(cls[k]);
  const ctx = new Map(Object.entries(c.contexts).map(([name, x]) => [name, { rx: rx(x.pattern), cased: x.cased === true }]));
  const rules = c.rules.map((r) => {
    if (!["age", "school", "birth"].includes(r.kind) || !["strong", "weak", "by_value"].includes(r.strength) || !["none", "age", "birth_year", "class_year"].includes(r.value)) throw new Error(`rule ${r.id}`);
    for (const key of ["unless", "needs", "strong_if"]) for (const [name, scope] of r[key] || []) if (!ctx.has(name) || !["clause", "text"].includes(scope)) throw new Error(`rule ${r.id}`);
    if (!Array.isArray(r.fields)) throw new Error(`rule ${r.id}`);
    return { ...r, rx: rx(r.pattern, "g") };
  });

  // { orig, low, cased }: one entry per kept code point in all three.
  function normalize(text) {
    const orig = [], low = [], cased = [];
    let pending = false, brk = false;
    for (const ch of cps(text).slice(0, MAX_CHARS)) {
      const cp = ch.codePointAt(0);
      if (drop.has(cp)) continue;
      if (inRange(ws, cp)) { pending = true; brk = brk || breaks.has(cp); continue; }
      if (pending && orig.length) { orig.push(" "); low.push(brk ? SEP : " "); cased.push(brk ? SEP : " "); }
      pending = false; brk = false;
      let lo, up;
      if (cp < 128) {
        if (cp < 32 || cp === 127) lo = up = OTHER;
        else if (cp >= 65 && cp <= 90) { lo = String.fromCharCode(cp + 32); up = ch; }
        else lo = up = ch;
      } else if (map.has(ch)) lo = up = map.get(ch);
      else if (inRange(sepRanges, cp)) lo = up = SEP;
      else lo = up = OTHER;
      orig.push(ch); low.push(lo); cased.push(up);
    }
    return { orig, low: low.join(""), cased: cased.join("") };
  }
  const handleOf = (handle) => { let t = normalize(handle).low; while (t && strip.includes(t[0])) t = t.slice(1); return t; };

  function handleToken(handle) {
    const raw = handleOf(handle);
    if (!raw) return "";
    for (const r of ageRx) for (const m of raw.matchAll(r)) { const v = parseInt(m[1], 10); if (ageMin <= v && v <= ageMax) return "age"; }
    const joined = [...raw].filter((ch) => !handleSeps.has(ch)).join("");
    for (const table of [null, ...leet]) if (wordsRx.test(table ? [...joined].map((ch) => table.get(ch) ?? ch).join("") : joined)) return "word";
    return "";
  }
  function softBirthYear(handle, today) {
    const year = ymd(today)[0];
    for (const m of handleOf(handle).matchAll(softRx)) { const y = parseInt(m[1], 10); if (softMin <= year - y && year - y <= softMax) return y; }
    return null;
  }

  function delimsOf(low) {
    const out = [];
    for (let i = 0; i < low.length; i++) {
      const ch = low[i];
      if (delimSet.has(ch)) out.push(i);
      else if (ch === "." && (i + 1 === low.length || low[i + 1] === " ") && i >= periodWord && /^[a-z0-9]+$/.test(low.slice(i - periodWord, i))) out.push(i);
    }
    return out;
  }
  function clauseOf(delims, s, e, len) {
    let a = 0, b = len;
    for (const d of delims) { if (d < s) a = d + 1; else if (d >= e) { b = d; break; } }
    return [a, b];
  }
  function snippet(orig, s, e) {
    const len = orig.length, mx = snippetMax;
    let a, b;
    if (e - s >= mx) { a = s; b = s + mx; } else {
      const pad = Math.floor((mx - (e - s)) / 2);
      a = Math.max(0, s - pad); b = Math.min(len, a + mx); a = Math.max(0, b - mx);
      if (a > 0 && orig[a - 1] !== " ") { let j = a; while (j < s && orig[j] !== " ") j++; if (j < s) a = j + 1; }
      if (b < len && orig[b] !== " ") { let j = b - 1; while (j >= e && orig[j] !== " ") j--; if (j >= e) b = j; }
    }
    return orig.slice(a, b).join("").replace(/^ +| +$/g, "");
  }
  const ctxHit = (pairs, low, cased, span) => (pairs || []).some(([name, scope]) => { const x = ctx.get(name), text = x.cased ? cased : low; return x.rx.test(scope === "text" ? text : text.slice(span[0], span[1])); });
  const yearOf = (digits, base, year, future) => { let y = parseInt(digits, 10); if (digits.length === 2) { y += base; if (!future && y > year) y -= 100; } return y; };

  function fieldSignals(field, text, [year, month]) {
    const { orig, low, cased } = normalize(text);
    if (!low) return [];
    const delims = delimsOf(low), out = [];
    for (const r of rules) {
      if (!r.fields.includes(field)) continue;
      for (const m of low.matchAll(r.rx)) {
        const groups = m.slice(1).filter((g) => g !== undefined);
        let strength = r.strength, ahead = 0;
        if (r.value === "age") { if (!groups.length) continue; const v = parseInt(groups[0], 10); if (!(int(r.min) <= v && v <= int(r.max))) continue; }
        else if (r.value === "birth_year") {
          const g = r.year_group ? m[int(r.year_group)] : groups[0];
          if (g === undefined) continue;
          const age = year - yearOf(g, int(birth.two_digit_base), year, false);
          if (!(int(birth.min_age) <= age && age <= int(birth.year_only_max_age))) continue;
        } else if (r.value === "class_year") {
          if (!groups.length) continue;
          ahead = yearOf(groups[0], int(cls.two_digit_base), year, true) - year;
          if (ahead < 0 || ahead > int(cls.max_ahead)) continue;
          if (ahead === 0 && month > int(cls.this_year_until_month)) continue;
        }
        const s = m.index, e = m.index + m[0].length, span = clauseOf(delims, s, e, low.length);
        if (r.needs && !ctxHit(r.needs, low, cased, span)) continue;
        if (ctxHit(r.unless, low, cased, span)) continue;
        if (strength === "by_value") strength = ahead >= int(cls.strong_ahead) || ctxHit(r.strong_if, low, cased, span) ? "strong" : "weak";
        out.push({ strength, kind: r.kind, rule: r.id, snippet: snippet(orig, s, e) });
      }
    }
    return out;
  }
  function birthFields(p, [year, month, day]) {
    const out = [];
    for (const key of birth.field_keys) {
      const { orig, low } = normalize(p[key]);
      const m = low.match(birthRx);
      if (!m) continue;
      const y = parseInt(m[1], 10);
      let hit;
      if (m[2] && m[3]) { const mo = parseInt(m[2], 10), d = parseInt(m[3], 10); const age = year - y - (month < mo || (month === mo && day < d) ? 1 : 0); hit = int(birth.min_age) <= age && age < adultAge; }
      else hit = int(birth.min_age) <= year - y && year - y <= int(birth.year_only_max_age);
      if (hit) out.push({ strength: "strong", kind: "birth", rule: "birth_field", snippet: clip(`${key}: ${orig.slice(0, FIELD_MAX).join("")}`, snippetMax) });
    }
    for (const key of birth.age_field_keys) {
      const { orig, low } = normalize(p[key]);
      const m = low.match(ageFieldRx);
      if (m && int(birth.age_min) <= parseInt(m[1], 10) && parseInt(m[1], 10) <= int(birth.age_max)) out.push({ strength: "strong", kind: "age", rule: "age_field", snippet: clip(`${key}: ${orig.slice(0, FIELD_MAX).join("")}`, snippetMax) });
    }
    return out;
  }
  // A strong signal blocks alone; a weak one blocks only together with a soft birth year in the handle.
  function scanProfiles(profiles, handle, today) {
    const t = ymd(today), soft = softBirthYear(handle, t);
    const signals = [], seen = new Set(), read = new Set();
    const keys = ["name", "bio", ...birth.field_keys, ...birth.age_field_keys];
    for (const p of Array.isArray(profiles) ? profiles : []) {
      if (!p || typeof p !== "object" || Array.isArray(p)) continue;
      const source = clip(p.source || "", SOURCE_MAX), url = clip(p.url || "", URL_MAX);
      const found = [...fieldSignals("name", p.name, t), ...fieldSignals("bio", p.bio, t), ...birthFields(p, t)];
      if (keys.some((k) => normalize(p[k]).low)) read.add(source);
      for (const s of found) {
        const key = JSON.stringify([s.strength, s.kind, source, s.snippet]);
        if (seen.has(key) || signals.length >= signalsMax) continue;
        seen.add(key);
        signals.push({ ...s, source, url });
      }
    }
    const strong = signals.find((s) => s.strength === "strong") || null;
    const weak = soft !== null ? signals.find((s) => s.strength === "weak") || null : null;
    const shown = strong || weak;
    return { blocked: !!shown, kind: strong ? strong.kind : weak ? "soft" : "", signal: shown, signals, soft, read: read.size };
  }
  return { normalize, handleToken, softBirthYear, scanProfiles, snippetMax };
}

// ---- the rules this page runs on ------------------------------------------------------------
let engine = null, loadError = "not loaded";
// Accepts a parsed rules file. Returns true when it validates; otherwise nothing changes hands
// and the guard stays closed.
export function setRules(doc) {
  try { engine = makeEngine(doc); loadError = ""; return true; } catch (e) { engine = null; loadError = String(e?.message || "invalid").slice(0, 80); return false; }
}
export const rulesReady = () => engine !== null;
export const rulesError = () => loadError;
// The page's one fetch of the rules, at startup. A failure leaves the guard closed.
export async function loadRules(fetchFn = globalThis.fetch, url = RULES_URL) {
  try {
    const r = await fetchFn(url, { headers: { Accept: "application/json" } });
    if (!r.ok) { engine = null; loadError = `HTTP ${r.status}`; return false; }
    return setRules(await r.json());
  } catch (e) { engine = null; loadError = "could not be fetched"; return false; }
}
// "age", "word", "" or, with no rules loaded, "rules".
export const handleToken = (handle) => (engine ? engine.handleToken(handle) : "rules");
export const softBirthYear = (handle, today = new Date()) => (engine ? engine.softBirthYear(handle, today) : null);
export const scanProfiles = (profiles, handle, today = new Date()) => (engine ? engine.scanProfiles(profiles, handle, today)
  : { blocked: true, kind: "rules", signal: null, signals: [], soft: null, read: 0 });
export const snippetMax = () => (engine ? engine.snippetMax : 60);
