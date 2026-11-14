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

// Password managers read an input's placeholder, label, id and name. None may look like a login.
{
  const fs = await import("node:fs");
  const html = fs.readFileSync(new URL("../../static/v2/index.html", import.meta.url), "utf8");
  const bad = /user|e-?mail|login|account|passw/i;
  const inputs = [...html.matchAll(/<(?:input|textarea)\b[^>]*>/g)].map((m) => m[0]).filter((t) => !/type="(checkbox|radio|file|hidden)"/.test(t));
  const attr = (t, a) => (t.match(new RegExp(`\\b${a}="([^"]*)"`)) || [])[1] || "";
  const hits = [];
  for (const t of inputs) {
    const id = attr(t, "id");
    const label = (html.match(new RegExp(`<label[^>]*for="${id}"[^>]*>([^<]*)</label>`)) || [])[1] || "";
    for (const [k, v] of [["id", id], ["name", attr(t, "name")], ["placeholder", attr(t, "placeholder").replace(/\S+@\S+/g, "")], ["aria-label", attr(t, "aria-label")], ["label", label]]) if (bad.test(v)) hits.push(`${id || t.slice(0, 40)} ${k}: ${v}`);
    if (/type="(text|password)"/.test(t)) hits.push(`${id} is type text or password, not search`);
  }
  if (hits.length) { console.error("FAIL inputs that look like a login to a password manager:\n  " + hits.join("\n  ")); process.exit(1); }
  console.log(`no input looks like a login (${inputs.length} checked)`);
}
