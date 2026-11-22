// Loads the minor guard's rules for a node test, as the page does at startup with a fetch.
// Import this before anything that asks the guard: without rules the guard refuses everything.
import { readFileSync } from "node:fs";
import { setRules } from "../../static/v2/js/minorscan.js";

export const RULES = JSON.parse(readFileSync(new URL("../../static/v2/data/minor-rules.json", import.meta.url), "utf8"));
if (!setRules(RULES)) throw new Error("static/v2/data/minor-rules.json does not validate");
