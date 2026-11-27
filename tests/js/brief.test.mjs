// The "At a glance" brief is built from rules, so its statements can be checked exactly.
import "./rules.mjs";   // the minor guard refuses everything until its rules are loaded
import { investigateBrief, reconBrief } from "../../static/v2/js/brief.js";
import { buildEvidence, caseAnalysis } from "../../static/v2/js/evidence.js";

let bad = 0, n = 0;
const ok = (cond, name) => { n++; if (!cond) { bad++; console.log("FAIL", name); } };
const text = (b) => b.rows.map((r) => `${r.level}: ${r.text}`).join("\n");
const acct = (site, tier, sources = ["Maigret"]) => ({ key: `acct:${site.toLowerCase()}`, what: site, tier, sources });

// ---- investigate ------------------------------------------------------------
// The brief reads the ledger and the identity clusters that buildEvidence produced.
const run = (collected, target, type, failed = []) => { const ev = buildEvidence(collected, target, type); return investigateBrief({ collected, items: ev.items, facts: ev.facts, identity: ev.identity, failed, type, target }); };
// A person case says three things in "What the evidence says" and "Suggested next steps", once,
// and not again in the brief: who else uses the handle, what could not be asked, and what to check.
const panel = (collected, target, type, failed = []) => { const a = caseAnalysis(buildEvidence(collected, target, type), { collected, target, type, failed: failed.map((f) => f.name) }); return { says: [a.assessment.headline, ...a.assessment.lines.map((l) => `${l.level}: ${l.text}`)].join("\n"), next: [...a.suggestions.top, ...a.suggestions.more] }; };
{
  const col = { sherlock: { results: [{ site: "Facebook", url: "https://facebook.com/jdoe" }, { site: "Paypal", url: "https://paypal.me/jdoe" }] }, github: { found: true, name: "J Doe", email: "j@example.org", blog: "https://jdoe.dev", profile_url: "https://github.com/jdoe" },
    maigret: { results: [{ site: "Bluesky", url: "https://bsky.app/profile/jdoe", verified: true, profile: { name: "J Doe" } }, { site: "Medium", url: "https://medium.com/@jdoe", verified: true, profile: { name: "Someone Else" } }, { site: "Facebook", url: "https://facebook.com/jdoe", verified: false }, { site: "Paypal", url: "https://paypal.me/jdoe", verified: false, profile: { name: "Ignored" } }] } };
  const b = run(col, "jdoe", "username", [{ name: "Holehe" }]), p = panel(col, "jdoe", "username", [{ name: "Holehe" }]);
  const t = text(b);
  ok(/1 linked account, 1 that exist and match, 1 that belong to a different person, and 2 unverified/.test(t), "counts accounts by tier");
  ok(/flag: 1 account belongs to another person whose name conflicts with J Doe: Someone Else \(Medium\)\. Nothing is removed\./.test(p.says) && !/different (person|people)s? use this handle|Someone Else/.test(t), "another person under the handle is said in the assessment, once, and not again in the brief");
  ok(!/Ignored/.test(t), "ignores names from unverified hits");
  ok(p.next.some((x) => x.id === "check:two" && /^Check the 2 accounts two tools agree on$/.test(x.title) && /nothing was read/.test(x.reason)) && !/reported by two tools/.test(t), "two-tool agreement is a suggested step, not called verified, and not repeated in the brief");
  ok(/info: Could not be asked: Holehe \(failed\)\. Each is unknown, not absent\./.test(p.says) && !/source failed/.test(t), "a failed source is named in the assessment, once, and not again in the brief");
  ok(b.rows.length <= 4 && /^ok: 1 linked account/.test(t), "the brief of a person case is short: what was found");
  // The platform check asking Reddit or Discord itself is not a second tool: a blocked Reddit row
  // or a taken Discord handle that one tool also listed is not "reported by two tools".
  const pc = { results: [{ platform: "Reddit", url: "https://www.reddit.com/user/jdoe", state: "blocked", found: null, evidence: "Reddit refuses requests from servers, so this could not be checked automatically." }, { platform: "Discord", url: "", state: "taken", found: null }] };
  const one = panel({ sherlock: { results: [{ site: "Reddit", url: "https://www.reddit.com/user/jdoe" }, { site: "Discord", url: "https://discord.com" }] }, platformCheck: pc }, "jdoe", "username");
  ok(!one.next.some((x) => x.id === "check:two"), "a blocked Reddit row or a taken Discord row plus one tool is not two-tool agreement");
  const two = panel({ sherlock: { results: [{ site: "Reddit", url: "https://www.reddit.com/user/jdoe" }, { site: "Discord", url: "https://discord.com" }] }, maigret: { results: [{ site: "Reddit", url: "https://www.reddit.com/user/jdoe", verified: false }, { site: "Discord", url: "https://discord.com", verified: false }] }, platformCheck: pc }, "jdoe", "username");
  ok(two.next.some((x) => x.id === "check:two" && x.title === "Check the account two tools agree on"), "two tools that both list Reddit are two tools; a taken handle never is");
  ok(/Reddit \(blocked the check\)/.test(two.says), "and the site that blocked the check is among what could not be asked");
  ok(b.actions.some((a) => a.pivot === "investigate" && a.value === "j@example.org") && b.actions.some((a) => a.pivot === "recon" && a.value === "jdoe.dev"), "offers pivots from extracted facts");
}
{
  const b = run({ github: { found: true, name: "J Doe" }, maigret: { results: [{ site: "Bluesky", verified: true, profile: { name: "j doe" } }] } }, "jdoe", "username");
  ok(/ok: 2 profiles carry the name "J Doe" or are tied to it \(GitHub, Bluesky\)/.test(text(b)), "one name on several profiles is reported as support");
}
{
  const c = { maigret: { results: [{ site: "YouTube", verified: true, profile: { name: "Eric" } }, { site: "Threads", verified: true, profile: { name: "Eric Henderson" } }] } };
  const t = text(run({ ...c, github: { found: true, name: "err0ric", profile_url: "https://github.com/err0ric" } }, "err0ric", "username"));
  ok(!/different (name|person|people)s? (appear|use)/.test(t) && /One name appears on other profiles \(Eric Henderson on Threads, YouTube\)/.test(t), "a first name and a full name are one person, not a conflict");
  // no anchor record and no strong signal: nobody is picked
  const nc = { maigret: { results: [{ site: "Medium", verified: true, profile: { name: "Bob Arnold" } }, { site: "Steam", verified: true, profile: { name: "Carol Baker" } }, { site: "Paypal", verified: false }] } };
  const none = text(run(nc, "jdoe", "username")), np = panel(nc, "jdoe", "username");
  ok(/^None\. No identity is established: profiles were read, and nothing ties any of them to the target\./.test(np.says) && np.next.some((x) => x.id === "pick:none" && /2 names appear under this handle \(Bob Arnold, Carol Baker\) and nothing ties any of them to the target, so nobody was chosen/.test(x.reason)), "with no anchor the assessment says nobody is tied to the target, and the first step is to choose");
  ok(/info: 2 profiles were read and 1 account is unverified. Each read profile exists, and nothing ties it to the target/.test(none) && !/belong to a different person|linked account|Only the first is treated/.test(none), "and it issues no linked or different-person counts");
  const one = panel(c, "err0ric", "username");
  ok(one.next.some((x) => x.id === "pick:none" && /One name appears under this handle \(Eric Henderson\) and nothing ties it to the target, so nobody was chosen/.test(x.reason)) && !/Eric Henderson/.test(text(run(c, "err0ric", "username")).split("\n").filter((l) => /^(ok|flag)/.test(l)).join()), "one unanchored name is reported without picking it");
}
{
  const b = run({ github: { found: true, name: "J Doe", error: "rate limited" }, sherlock: { results: [] } }, "jdoe", "username");
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
  const mal = investigateBrief({ type: "hash", target: "x", failed: [], facts: [], items: [], collected: { hash: { verdict: "MALICIOUS", family: "Emotet", malware_families: ["Emotet"], community_tags: ["Some Pulse Name"] } } });
  ok(/flag: Known malware \(Emotet\)/.test(text(mal)) && !/Some Pulse Name/.test(text(mal)), "malicious hash names the family only");
  const old = investigateBrief({ type: "hash", target: "x", failed: [], facts: [], items: [], collected: { hash: { verdict: "MALICIOUS", malware_families: ["Free Text Pulse"] } } });
  ok(/flag: Known malware\. Do not run/.test(text(old)) && !/Free Text Pulse/.test(text(old)), "an old response's free-text families stay out of the headline");
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
