// Turns raw module responses into ranked evidence and extracted facts.
//
// An evidence item: { tier, what, url, meta, source, key }
//   tier: "flag" | "confirmed" | "possible" | "noise"
//     flag       - something that changes the risk picture (breach, malware verdict, VOIP number)
//     confirmed  - an account or record verified by profile data or an API: Maigret parsed a
//                  real profile, GitHub's API returned the user, a registration check passed
//     possible   - a tool says the handle exists but nothing verified it. Many sites answer
//                  "yes" to any name, so these are leads to check, not facts.
//     noise      - sites known to answer yes to everything, collapsed by default
//   A source that FAILED contributes nothing here; failures are reported separately so an
//   error is never read as "not found".
//   key: stable id used for the checkbox state, e.g. "sherlock:GitHub"
//
// A fact: { k, v, source, url? }  (name, location, employer…), shown in "What we know".

const norm = (s) => String(s ?? "").trim().toLowerCase();

// Different tools name the same site differently ("Twitter" vs "X", "Steam Community" vs "Steam").
// Accounts are merged on the canonical name so one site is one row, with every source that saw it.
const SITE_ALIAS = {
  "twitter": "x", "x (twitter)": "x", "x / twitter": "x", "x/twitter": "x", "twitter.com": "x", "x.com": "x",
  "steam community": "steam", "steamcommunity": "steam", "threads.net": "threads", "instagram.com": "instagram",
  "facebook.com": "facebook", "youtube channel": "youtube", "reddit.com": "reddit", "github.com": "github",
  "tiktok.com": "tiktok", "twitch.tv": "twitch", "bsky": "bluesky", "bsky.app": "bluesky", "hugging face": "huggingface",
};
const SITE_DISPLAY = { x: "X (Twitter)", steam: "Steam", huggingface: "Hugging Face" };
const canonSite = (s) => { const n = norm(s).replace(/\s*\((?!twitter).*\)$/, ""); return SITE_ALIAS[n] || n; };
const TIER_RANK = { flag: 0, confirmed: 1, possible: 2, noise: 3 };
const failed = (d) => !!(d && (d.error || d.error_code));

export function buildEvidence(collected, target) {
  const items = [];
  const facts = [];
  const seen = new Set();
  const add = (it) => {
    const dedupe = it.url ? norm(it.url) : `${it.source}:${norm(it.what)}`;
    if (seen.has(dedupe)) return;
    seen.add(dedupe);
    items.push(it);
  };
  // One row per site across Sherlock, Maigret, Holehe and Platform check.
  const accounts = new Map();
  const addAccount = (site, it) => {
    const c = canonSite(site);
    if (!c) return;
    const prev = accounts.get(c);
    if (prev) {
      if (!prev.sources.includes(it.source)) prev.sources.push(it.source);
      if (TIER_RANK[it.tier] < TIER_RANK[prev.tier]) prev.tier = it.tier;
      if (!prev.url && it.url) prev.url = it.url;
      if (it.tier === "confirmed" && it.meta) prev.meta = it.meta; else if (!prev.meta && it.meta) prev.meta = it.meta;
      return;
    }
    const row = { ...it, what: SITE_DISPLAY[c] || site, key: `acct:${c}`, sources: [it.source] };
    accounts.set(c, row);
    items.push(row);
  };
  const fact = (k, v, source, url) => {
    if (!v) return;
    const dup = facts.find((f) => f.k === k && norm(f.v) === norm(v));
    if (!dup) facts.push({ k, v: String(v), source, url });
  };

  // --- username enumeration: sherlock + maigret (merged by url) ----------
  const accountRows = [];
  for (const r of collected.sherlock?.results || []) accountRows.push({ ...r, _src: "Sherlock" });
  for (const r of collected.maigret?.results || []) accountRows.push({ ...r, _src: "Maigret" });
  for (const r of accountRows) {
    const site = r.site || r.name || "";
    // Confirmed needs a verified profile signal. A well-known site name is not one:
    // Facebook and PayPal answer 200 for names that do not exist.
    let tier = "possible", meta = r.category || "";
    if (r.confidence === "false_positive") tier = "noise";
    else if (r.verified) {
      tier = "confirmed";
      const p = r.profile || {};
      meta = ["profile read", p.name && `name on profile: ${p.name}`, p.location].filter(Boolean).join(" · ");
    }
    addAccount(site, { tier, url: r.url, meta, source: r._src });
  }

  // --- email registration checks: holehe + platform check -----------------
  for (const r of collected.holehe?.results || []) {
    addAccount(r.site || r.domain, { tier: "confirmed", url: r.domain ? `https://${r.domain}` : "", meta: "account registered", source: "Holehe" });
  }
  for (const r of collected.platformCheck?.results || []) {
    // A 200 on the profile URL is weak: these platforms often answer 200 for any name.
    if (r.found) addAccount(r.platform, { tier: "possible", url: r.url, meta: "profile URL answered, check by hand", source: "Platform check" });
  }

  // --- breaches -------------------------------------------------------------
  for (const b of collected.hibp?.breaches || []) {
    add({ tier: "flag", what: `Breach: ${b}`, url: "", meta: "credential exposure", source: "HIBP", key: `breach:${norm(b)}` });
  }

  // --- github ----------------------------------------------------------------
  const gh = collected.github;
  if (gh?.found && !failed(gh)) {
    addAccount("GitHub", { tier: "confirmed", url: gh.profile_url, meta: `${gh.public_repos ?? 0} repos · ${gh.followers ?? 0} followers`, source: "GitHub" });
    fact("Name", gh.name, "GitHub", gh.profile_url);
    fact("Location", gh.location, "GitHub", gh.profile_url);
    fact("Employer", gh.company, "GitHub", gh.profile_url);
    fact("Email", gh.email, "GitHub", gh.profile_url);
    fact("Website", gh.blog, "GitHub", gh.blog);
    fact("Bio", gh.bio, "GitHub", gh.profile_url);
    fact("Active since", gh.created_at ? String(gh.created_at).slice(0, 10) : "", "GitHub", gh.profile_url);
  }

  // --- gravatar ----------------------------------------------------------------
  const gr = collected.gravatar;
  if (gr?.found && !failed(gr)) {
    add({ tier: "confirmed", what: "Gravatar profile", url: gr.profile_url, meta: gr.display_name || gr.name || "", source: "Gravatar", key: "acct:gravatar" });
    fact("Name", gr.name || gr.display_name, "Gravatar", gr.profile_url);
    fact("Location", gr.location, "Gravatar", gr.profile_url);
  }

  // --- enricher + profile scrape (bios, display names) --------------------------
  for (const p of collected.enricher?.profiles || []) {
    // The enricher read a display name or bio from the page, which verifies the account exists.
    if (p.platform && (p.display_name || p.bio)) addAccount(p.platform, { tier: "confirmed", url: p.url, meta: ["profile read", p.display_name && `name on profile: ${p.display_name}`].filter(Boolean).join(" · "), source: "Profile enrichment" });
    fact("Display name", p.display_name, p.platform || "Profile", p.url);
    if (p.bio) fact("Bio", p.bio.slice(0, 160), p.platform || "Profile", p.url);
  }
  for (const p of (collected.profileScrape?.results || []).filter((r) => !r.error)) {
    fact("Display name", p.display_name, p.site || "Profile", p.url);
    fact("Location", p.location, p.site || "Profile", p.url);
    for (const e of p.emails || []) fact("Email", e, p.site || "Profile", p.url);
  }

  // --- hunter ----------------------------------------------------------------------
  const hu = collected.hunter;
  if (hu && !hu.error) {
    if (hu.pattern) fact("Email pattern", hu.pattern, "Hunter.io");
    for (const e of (hu.emails || []).slice(0, 25)) {
      add({ tier: Number(e.confidence) >= 80 ? "confirmed" : "possible", what: e.email, url: "", meta: [e.first_name, e.last_name].filter(Boolean).join(" ") + (e.position ? ` · ${e.position}` : ""), source: "Hunter.io", key: `email:${norm(e.email)}` });
    }
  }

  // --- harvester ---------------------------------------------------------------------
  // Domain harvest: only addresses matter for a person; hostnames stay in the source card.
  const hv = collected.harvester;
  if (hv && !hv.error && !hv.skipped) {
    for (const e of hv.emails || []) if (norm(e) !== norm(target)) add({ tier: "possible", what: e, url: "", meta: "same domain, seen in public archives", source: "Domain harvest", key: `email:${norm(e)}` });
  }

  // --- hash --------------------------------------------------------------------------
  const hs = collected.hash;
  if (hs && !failed(hs)) {
    const v = String(hs.verdict || "").toUpperCase();
    if (v === "MALICIOUS") add({ tier: "flag", what: `Malicious ${hs.hash_type || "hash"}${hs.malware_families?.length ? `: ${hs.malware_families.join(", ")}` : ""}`, url: hs.virustotal_url, meta: "known malware", source: "Hash lookup", key: "hash:verdict" });
    else if (v === "CLEAN") add({ tier: "confirmed", what: `Known clean ${hs.hash_type || "hash"}`, url: hs.virustotal_url, meta: "CIRCL hashlookup", source: "Hash lookup", key: "hash:verdict" });
    else add({ tier: "noise", what: `${hs.hash_type || "Hash"} not seen by any source`, url: hs.virustotal_url, meta: "", source: "Hash lookup", key: "hash:verdict" });
    if (hs.malware_bazaar?.found) fact("File name", hs.malware_bazaar.file_name, "MalwareBazaar");
    if (hs.malware_bazaar?.signature) fact("Signature", hs.malware_bazaar.signature, "MalwareBazaar");
  }

  // --- phone ----------------------------------------------------------------------------
  const ph = collected.phone;
  if (ph) {
    if (ph.carrier) fact("Carrier", ph.carrier, "NumLookup");
    if (ph.line_type) fact("Line type", ph.line_type, "NumLookup");
    if (ph.location || ph.country) fact("Location", [ph.location, ph.country].filter(Boolean).join(", "), "NumLookup");
    if (norm(ph.line_type).includes("voip")) add({ tier: "flag", what: "VOIP number", url: "", meta: "often disposable or burner", source: "NumLookup", key: "phone:voip" });
    if (ph.valid === false) add({ tier: "flag", what: "Number reported invalid", url: "", meta: "", source: "NumLookup", key: "phone:invalid" });
  }

  // tier ordering inside the ledger
  for (const it of items) if (it.sources) {
    it.source = it.sources.join(", ");
    // Two tools agreeing is worth saying, but it is still not verification.
    if (it.tier === "possible" && it.sources.length > 1 && !/tools$/.test(it.meta || "")) it.meta = [it.meta, `reported by ${it.sources.length} tools`].filter(Boolean).join(" · ");
  }
  items.sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || (b.sources?.length || 1) - (a.sources?.length || 1) || a.what.localeCompare(b.what));
  return { items, facts };
}

export const TIERS = [
  { id: "flag",      title: "Flags",     cls: "flag",      open: true,  blurb: "Breaches, malware, disposable numbers. Read these first." },
  { id: "confirmed", title: "Confirmed", cls: "confirmed", open: true,  blurb: "Verified to exist: a profile was read or a registration check passed. This shows the account exists, not who owns it." },
  { id: "possible",  title: "Possible",  cls: "possible",  open: true,  blurb: "A tool reported the handle, but nothing verified it. Many sites answer yes to any name. Open and check before relying on one." },
  { id: "noise",     title: "Known noisy sites", cls: "", open: false, limit: 40, blurb: "Sites that answer yes to any username. Kept for completeness." },
];

// The account rows the AI prompt and the report use, so they match the screen exactly.
export const accountsFor = (items) => items.filter((i) => i.key?.startsWith("acct:") && (i.tier === "confirmed" || i.tier === "possible"))
  .map((i) => ({ site: String(i.what).slice(0, 120), url: String(i.url || "").slice(0, 600), status: i.tier, sources: (i.sources || [i.source]).slice(0, 8).map(String), note: i.tier === "confirmed" ? String(i.meta || "").slice(0, 200) : "" }));
