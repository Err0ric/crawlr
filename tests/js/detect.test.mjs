globalThis.location = { origin: "https://crawlr.lol" };
const { detect } = await import("../../static/v2/js/core.js");
const cases = { "word.word": "username", "john.smith": "username", "jdoe": "username", "example.com": "domain", "sub.example.co.uk": "domain",
  "crawlr.lol": "domain", "john.dev": "domain", "a@b.com": "email", "8.8.8.8": "ip", "AS15169": "asn", "44d88612fea8a8f36de82e1278abb02f": "hash",
  "+1 253 555 0100": "phone", "Jane Doe": "name", "first.last.name": "domain", "user.name.here": "username",
  // A name of two or more words is a name in any script, with hyphens, apostrophes, periods or a middle dot.
  "José García": "name", "Jean-Luc Picard": "name", "O'Brien Smith": "name", "J. R. R. Tolkien": "name", "王 伟": "name", "Лев Толстой": "name", "Gil·les Martí": "name", "john smith2": "name",
  // And nothing else is taken for one: a single word, a dotted handle, an address, a number.
  "Madonna": "username", "José": "username", "李小龙": "username", "john.smith jones": "username", "jose@example.com": "email", "josé.com": "username", "253 555 0100": "phone",
  "d41d8cd98f00b204e9800998ecf8427e": "hash", "José, García": "multi", "www.example.com now": "username", "-x y": "username" };
let bad = 0;
for (const [k, v] of Object.entries(cases)) { const got = detect(k); if (got !== v) { bad++; console.log("FAIL", k, "->", got, "expected", v); } }
console.log(bad ? `${bad} failed` : `all ${Object.keys(cases).length} pass`);
if (bad) process.exit(1);
