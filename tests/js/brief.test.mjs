// The "At a glance" brief is built from rules, so its statements can be checked exactly.
import { investigateBrief, reconBrief } from "../../static/v2/js/brief.js";

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");
const acct = (site, tier, sources = ["Maigret"]) => ({ key: `acct:${site.toLowerCase()}`, what: site, tier, sources });

// ---- investigate ------------------------------------------------------------
{
  const b = investigateBrief({
    type: "username", target: "jdoe", failed: [{ name: "GitHub" }], facts: [{ k: "Email", v: "j@example.org" }, { k: "Website", v: "https://jdoe.dev" }],
    items: [acct("Bluesky", "confirmed"), acct("Medium", "confirmed"), acct("Facebook", "possible", ["Sherlock", "Maigret"]), acct("Paypal", "possible")],
    collected: { sherlock: { results: [] }, maigret: { results: [{ site: "Bluesky", verified: true, profile: { name: "J Doe" } }, { site: "Medium", verified: true, profile: { name: "Someone Else" } }, { site: "Paypal", verified: false, profile: { name: "Ignored" } }] } },
  });
  const t = text(b);
  ok(/2 confirmed accounts and 2 possible accounts/.test(t), "counts accounts");
  ok(/flag: Profiles under this handle show 2 different names/.test(t) && /may belong to different people/.test(t), "warns when names differ");
  ok(!/Ignored/.test(t), "ignores names from unverified hits");
  ok(/1 possible account was reported by two tools/.test(t), "notes two-tool agreement without calling it verified");
  ok(/flag: 1 source failed \(GitHub\)/.test(t), "lists failed sources");
  ok(b.actions.some((a) => a.pivot === "investigate" && a.value === "j@example.org") && b.actions.some((a) => a.pivot === "recon" && a.value === "jdoe.dev"), "offers pivots from extracted facts");
}
{
  const b = investigateBrief({ type: "username", target: "jdoe", failed: [], facts: [], items: [acct("GitHub", "confirmed"), acct("Bluesky", "confirmed")],
    collected: { github: { found: true, name: "J Doe" }, maigret: { results: [{ site: "Bluesky", verified: true, profile: { name: "j doe" } }] } } });
  ok(/ok: The name "J Doe" appears on 2 profiles/.test(text(b)), "one name on several profiles is reported as support");
}
{
  const b = investigateBrief({ type: "username", target: "jdoe", failed: [], facts: [], items: [], collected: { github: { found: true, name: "J Doe", error: "rate limited" }, sherlock: { results: [] } } });
  ok(!/J Doe/.test(text(b)), "a failed source contributes no name");
  ok(/No source found anything/.test(text(b)), "says so when nothing was found");
}
{
  const b = investigateBrief({ type: "email", target: "j@example.org", failed: [], facts: [], items: [], collected: { hibp: { breaches: ["Adobe", "LinkedIn"] }, holehe: { results: [{ site: "spotify" }] } } });
  const t = text(b);
  ok(/flag: This address is in 2 known breaches \(Adobe, LinkedIn\)/.test(t) && /Registered on 1 service/.test(t), "breaches and registrations");
  ok(b.actions.some((a) => a.pivot === "recon" && a.value === "example.org"), "offers recon on the email's domain");
  const clean = investigateBrief({ type: "email", target: "j@example.org", failed: [], facts: [], items: [], collected: { hibp: { breaches: [] } } });
  ok(/ok: Not in any breach/.test(text(clean)), "clean breach result");
  const failed = investigateBrief({ type: "email", target: "j@example.org", failed: [{ name: "Breaches" }], facts: [], items: [], collected: { hibp: { breaches: [], error: "timeout" } } });
  ok(!/Not in any breach/.test(text(failed)), "a failed breach check is never reported as clean");
}
{
  const mal = investigateBrief({ type: "hash", target: "x", failed: [], facts: [], items: [], collected: { hash: { verdict: "MALICIOUS", malware_families: ["Emotet"] } } });
  ok(/flag: Known malware \(Emotet\)/.test(text(mal)), "malicious hash");
  const unk = investigateBrief({ type: "hash", target: "x", failed: [], facts: [], items: [], collected: { hash: { verdict: "UNKNOWN" } } });
  ok(/not a clean bill of health/.test(text(unk)), "unknown hash is not called clean");
}

// ---- recon -------------------------------------------------------------------
{
  const b = reconBrief({
    type: "domain", target: "example.org", failed: [{ name: "WHOIS" }],
    items: [{ tier: "flag", what: "No DMARC record" }, { tier: "flag", what: "Redis open on 6379" }],
    collected: {
      dns: { cloudflare_proxied: true },
      email_posture: { grade: "F", spoofable: "yes" },
      takeover: { dangling: 1, candidates: [{ host: "old.example.org", status: "dangling" }, { host: "www.example.org", status: "pointing" }] },
      lookalikes: { registered: 3, with_mail: 2 },
      wellknown: { found: true, security_txt: null, favicon: { shodan_query: "http.favicon.hash:1" } },
      wayback: { interesting_paths: { A: ["x/admin"], B: ["x/.env", "x/b.sql"] } },
      ssl: { found: true, days_left: 60 },
      shodan: { found: true, ports: [80] },
      subdomains: { ct_summary: { not_resolving: ["gone.example.org"] }, subdomains: [
        { subdomain: "a.example.org", ips: ["1.1.1.1"] }, { subdomain: "b.example.org", ips: ["1.1.1.2"] }, { subdomain: "c.example.org", ips: ["1.1.1.3"] }, { subdomain: "odd.example.org", ips: ["9.9.9.9"] }] },
      ipAsn: { "1.1.1.1": { asn: "AS1", org: "Main" }, "1.1.1.2": { asn: "AS1", org: "Main" }, "1.1.1.3": { asn: "AS1", org: "Main" }, "9.9.9.9": { asn: "AS9", org: "Other" } },
    },
  });
  const t = text(b);
  ok(/flag: 2 flags: No DMARC record, Redis open on 6379\./.test(t), "summarizes flags");
  ok(/Behind Cloudflare/.test(t), "cloudflare caveat");
  ok(/flag: Mail from this domain can be spoofed/.test(t), "spoofable mail");
  ok(/1 subdomain points at a cloud resource that no longer exists \(old\.example\.org\)/.test(t), "dangling takeover candidate only");
  ok(/Most hosts sit in AS1 \(Main\)\. 1 host sits elsewhere \(odd\.example\.org in AS9\)/.test(t), "outlier network");
  ok(/1 name in certificate logs no longer resolves \(gone\.example\.org\)/.test(t), "certificate names that do not resolve");
  ok(/flag: 3 lookalike domains are registered, 2 of them able to receive mail/.test(t) && /does not mean malicious/.test(t), "lookalikes with the caveat");
  ok(/No security\.txt/.test(t) && /3 archived paths look sensitive/.test(t), "published files and archived paths");
  ok(/passive index, not a live scan/.test(t), "says ports are passive when no scan ran");
  ok(/flag: 1 check failed \(WHOIS\)/.test(t), "failed checks");
  ok(b.actions.some((a) => a.tab === "topology") && b.actions.some((a) => /shodan/.test(a.href || "")), "actions");
}
{
  const b = reconBrief({ type: "domain", target: "example.org", failed: [], items: [], collected: { email_posture: { grade: "A", spoofable: "no" }, lookalikes: { error: "timeout", registered: 9 } } });
  const t = text(b);
  ok(/ok: No flags/.test(t) && /ok: Email spoofing is rejected \(grade A\)/.test(t), "clean run");
  ok(!/lookalike/.test(t), "a failed check contributes nothing");
  const gaps = reconBrief({ type: "domain", target: "example.org", failed: [{ name: "HTTP headers" }], items: [], collected: {} });
  ok(!/No flags/.test(text(gaps)), "never says 'no flags' when checks failed");
}

console.log(bad ? `${bad} of ${n} brief checks failed` : `all ${n} brief checks pass`);
if (bad) process.exit(1);
