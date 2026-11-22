// Runs the JavaScript engine of the minor guard over JSON read from stdin and prints the answers
// as JSON. tests/test_minor_parity.py calls this and compares each answer with the Python
// engine's. Input: { today, handles: [..], scans: [{ handle, profiles }] }.
import { readFileSync } from "node:fs";
import { makeEngine } from "../../static/v2/js/minorscan.js";

const rules = JSON.parse(readFileSync(new URL("../../static/v2/data/minor-rules.json", import.meta.url), "utf8"));
const engine = makeEngine(rules);
const input = JSON.parse(readFileSync(0, "utf8"));
const out = {
  handles: (input.handles || []).map((h) => ({ token: engine.handleToken(h) || null, soft: engine.softBirthYear(h, input.today) })),
  scans: (input.scans || []).map((s) => engine.scanProfiles(s.profiles, s.handle, s.today || input.today)),
};
process.stdout.write(JSON.stringify(out));
