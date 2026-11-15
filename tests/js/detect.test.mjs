globalThis.location = { origin: "https://crawlr.lol" };
const { detect } = await import("../../static/v2/js/core.js");
const cases = { "word.word": "username", "john.smith": "username", "jdoe": "username", "example.com": "domain", "sub.example.co.uk": "domain",
  "crawlr.lol": "domain", "john.dev": "domain", "a@b.com": "email", "8.8.8.8": "ip", "AS15169": "asn", "44d88612fea8a8f36de82e1278abb02f": "hash",
  "+1 253 555 0100": "phone", "Jane Doe": "name", "first.last.name": "domain", "user.name.here": "username",
  // A name of two or more words is a name in any script, with hyphens, apostrophes, periods or a middle dot.
  "José García": "name", "Jean-Luc Picard": "name", "O'Brien Smith": "name", "J. R. R. Tolkien": "name", "王 伟": "name", "Лев Толстой": "name", "Gil·les Martí": "name", "john smith2": "name",
  // And nothing else is taken for one: a single word, a dotted handle, an address, a number.
  "Madonna": "username", "José": "username", "李小龙": "username", "john.smith jones": "username", "jose@example.com": "email", "josé.com": "username", "253 555 0100": "phone",
  "d41d8cd98f00b204e9800998ecf8427e": "hash", "José, García": "multi", "www.example.com now": "username", "-x y": "username",
  // A phone number as people write it: with or without a +, spaces, dashes, dots, parentheses, a leading 00, an extension, vanity letters.
  "+12024561111": "phone", "(202) 456-1111": "phone", "202-456-1111": "phone", "202.456.1111": "phone", "2024561111": "phone", "1-202-456-1111": "phone", "+44 20 7946 0958": "phone",
  "0044 20 7946 0958": "phone", "+44 (0)20 7946 0958": "phone", "07400 123456": "phone", "+49 1512 3456789": "phone", "1-800-FLOWERS": "phone", "800-GO-FEDEX": "phone", "+1 202 456 1111 ext. 22": "phone",
  // And what a phone number must not take: a hash, an address, an ASN, a date, a year range, a decimal, an all-digit handle.
  "12345678901234567890123456789012": "hash", "192.168.100.200": "ip", "as64496": "asn", "2024-01-15": "username", "15/01/2024": "username", "01.15.2024": "username", "2020-2021": "username",
  "3.14159265": "username", "12345678": "username", "20240115": "username", "9876543210123": "username", "1800flowers": "username", "404-not-found": "username", "007": "username" };
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
