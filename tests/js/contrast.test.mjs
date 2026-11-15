// WCAG 2.2 AA contrast check for the design tokens in static/v2/css/app.css.
// Text tokens must reach 4.5:1 on every surface they are used on, in both themes;
// state colors must also hold on their own tinted backgrounds; UI borders need 3:1.
import fs from "node:fs";

const css = fs.readFileSync(new URL("../../static/v2/css/app.css", import.meta.url), "utf8");
const block = (re) => { const m = css.match(re); if (!m) throw new Error("token block not found: " + re); return Object.fromEntries([...m[1].matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{3,8})/g)].map((x) => [x[1], x[2]])); };
const dark = block(/:root\s*{([^}]*)}/);
const light = { ...dark, ...block(/:root\[data-theme="light"\]\s*{([^}]*)}/) };
const lightAuto = { ...dark, ...block(/:root:not\(\[data-theme="dark"\]\)\s*{([^}]*)}/) };

const rgb = (hex) => { let h = hex.slice(1); if (h.length === 3) h = [...h].map((c) => c + c).join(""); return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)).concat(h.length === 8 ? parseInt(h.slice(6, 8), 16) / 255 : 1); };
const over = (fg, bg) => { const [r, g, b, a] = rgb(fg), [R, G, B] = rgb(bg); return [r * a + R * (1 - a), g * a + G * (1 - a), b * a + B * (1 - a)]; };
const lum = ([r, g, b]) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b); };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

let bad = 0, checked = 0;
function check(theme, name, fg, bg, min) {
  const r = ratio(fg, bg); checked++;
  if (r < min) { bad++; console.log(`FAIL ${theme} ${name}: ${r.toFixed(2)}:1 (needs ${min})`); }
}
for (const [theme, t] of [["dark", dark], ["light", light], ["light(auto)", lightAuto]]) {
  const surfaces = ["bg", "bg-raised", "bg-sunken", "bg-hover"];
  const solid = (k) => rgb(t[k]).slice(0, 3);
  for (const s of surfaces) {
    for (const ink of ["ink", "ink-2", "ink-3", "ink-4", "violet", "ok", "warn", "bad", "flag", "linked", "match", "different", "unverified"]) check(theme, `--${ink} on --${s}`, solid(ink), solid(s), 4.5);
    check(theme, `--line-strong on --${s} (UI border)`, solid("line-strong"), solid(s), 3);
  }
  // tinted chips: the state color on its own translucent background, over raised and hover surfaces
  for (const [fg, tint] of [["ok", "ok-bg"], ["warn", "warn-bg"], ["bad", "bad-bg"], ["violet", "violet-bg"], ["ink", "violet-bg"]])
    for (const s of ["bg-raised", "bg-hover", "bg"]) check(theme, `--${fg} on --${tint} over --${s}`, solid(fg), over(t[tint], t[s]), 4.5);
  check(theme, "--on-violet on --violet-2 (primary button)", solid("on-violet"), solid("violet-2"), 4.5);
  check(theme, "--on-violet on --violet-3 (primary hover)", solid("on-violet"), solid("violet-3"), 4.5);
  // certainty pills: the tier color on its own tint, over every surface a card or tile sits on
  for (const [fg, tint] of [["flag", "flag-bg"], ["linked", "linked-bg"], ["match", "match-bg"]])
    for (const s of ["bg-raised", "bg-hover", "bg-sunken", "bg"]) check(theme, `--${fg} on --${tint} over --${s}`, solid(fg), over(t[tint], t[s]), 4.5);
  // the edge of a card or tile is a UI mark: 3:1 against the surface beside it
  for (const edge of ["flag", "linked", "match", "different", "unverified"]) for (const s of ["bg", "bg-raised", "bg-sunken", "bg-hover"]) check(theme, `--${edge} edge on --${s}`, solid(edge), solid(s), 3);
  // selected segments, pressed chips and the shown identity: page color on ink
  check(theme, "--bg on --ink (selected segment)", solid("bg"), solid("ink"), 4.5);
  // the ghost Cancel button: ink text and a visible line on the page
  check(theme, "--ink on --bg (cancel button)", solid("ink"), solid("bg"), 4.5);
  check(theme, "--line-strong on --bg (cancel button border)", solid("line-strong"), solid("bg"), 3);
  check(theme, "--bg-raised knob on --switch-on", solid("bg-raised"), solid("switch-on"), 3);
  check(theme, "--violet focus ring on --bg", solid("violet"), solid("bg"), 3);
  check(theme, "--switch-on on --bg-raised", solid("switch-on"), solid("bg-raised"), 3);
  check(theme, "--switch-on on --bg", solid("switch-on"), solid("bg"), 3);
}
// Linked (green) and Matches (teal) must stay apart in hue, in both themes: they sit side by side.
const hue = (hex) => { const [r, g, b] = rgb(hex).slice(0, 3).map((v) => v / 255); const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn; if (!d) return 0; const h = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; return (h * 60 + 360) % 360; };
for (const [theme, t] of [["dark", dark], ["light", light]]) { checked++; const d = Math.abs(hue(t.linked) - hue(t.match)); if (Math.min(d, 360 - d) < 40) { bad++; console.log(`FAIL ${theme} --linked and --match are ${Math.min(d, 360 - d).toFixed(0)} degrees of hue apart (needs 40)`); } }
if (JSON.stringify(light) !== JSON.stringify(lightAuto)) { bad++; console.log("FAIL light tokens differ between prefers-color-scheme and data-theme"); }
console.log(bad ? `${bad} of ${checked} contrast checks failed` : `all ${checked} contrast checks pass`);
if (bad) process.exit(1);
