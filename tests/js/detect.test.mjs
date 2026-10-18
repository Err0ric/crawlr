globalThis.location = { origin: "https://crawlr.lol" };
const { detect } = await import("../../static/v2/js/core.js");
const cases = { "word.word": "username", "john.smith": "username", "jdoe": "username", "example.com": "domain", "sub.example.co.uk": "domain",
  "crawlr.lol": "domain", "john.dev": "domain", "a@b.com": "email", "8.8.8.8": "ip", "AS15169": "asn", "44d88612fea8a8f36de82e1278abb02f": "hash",
  "+1 253 555 0100": "phone", "Jane Doe": "name", "first.last.name": "domain", "user.name.here": "username" };
let bad = 0;
for (const [k, v] of Object.entries(cases)) { const got = detect(k); if (got !== v) { bad++; console.log("FAIL", k, "->", got, "expected", v); } }
console.log(bad ? `${bad} failed` : `all ${Object.keys(cases).length} pass`);
if (bad) process.exit(1);
