// Prints, as JSON, the profile text the page's content check reads from a case given on stdin
// (profileTexts in static/v2/js/evidence.js). tests/test_minor_parity.py compares it with what
// the server keeps for the same answers (entries_of in core/profile_record.py).
import "./rules.mjs";
import { readFileSync } from "node:fs";
globalThis.location = { origin: "https://crawlr.lol" };
globalThis.document = { addEventListener() {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const { profileTexts } = await import("../../static/v2/js/evidence.js");
process.stdout.write(JSON.stringify(profileTexts(JSON.parse(readFileSync(0, "utf8")))));
