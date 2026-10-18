// Turns raw module responses into ranked evidence and extracted facts.
//
// An evidence item: { tier, what, url, meta, source, key }
//   tier: "confirmed" | "flag" | "likely" | "unverified"
//     confirmed  - an account or record that definitely exists for this target
//     flag       - something that changes the risk picture (breach, malware verdict, VOIP number)
//     likely     - probable but from a source with known false positives
//     unverified - kept for completeness, collapsed by default
//   key: stable id used for the checkbox state, e.g. "sherlock:GitHub"
//
// A fact: { k, v, source, url? }  (name, location, employer…), shown in "What we know".

const SITE_RANK = new Set(["github", "reddit", "steam", "tiktok", "linkedin", "twitter", "x", "instagram", "youtube", "twitch", "keybase", "gitlab", "hackerone", "bugcrowd", "mastodon", "telegram", "discord", "spotify", "soundcloud", "pinterest", "medium", "dev.to", "stack overflow", "stackoverflow"]);

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
const TIER_RANK = { flag: 0, confirmed: 1, likely: 2, unverified: 3 };

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
      if (!prev.meta && it.meta) prev.meta = it.meta;
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
    const conf = r.confidence || "";
    let tier = "likely";
    if (conf === "false_positive") tier = "unverified";
    else if (conf === "high_confidence" || SITE_RANK.has(canonSite(site))) tier = "confirmed";
    addAccount(site, { tier, url: r.url, meta: r.category || "", source: r._src });
  }

  // --- email registration checks: holehe + platform check -----------------
  for (const r of collected.holehe?.results || []) {
    addAccount(r.site || r.domain, { tier: "confirmed", url: r.domain ? `https://${r.domain}` : "", meta: "account registered", source: "Holehe" });
  }
  for (const r of collected.platformCheck?.results || []) {
    if (r.found) addAccount(r.platform, { tier: r.manual ? "likely" : "confirmed", url: r.url, meta: r.manual ? "needs manual check" : "account registered", source: "Platform check" });
  }

  // --- breaches -------------------------------------------------------------
  for (const b of collected.hibp?.breaches || []) {
    add({ tier: "flag", what: `Breach: ${b}`, url: "", meta: "credential exposure", source: "HIBP", key: `breach:${norm(b)}` });
  }

  // --- github ----------------------------------------------------------------
  const gh = collected.github;
  if (gh?.found) {
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
  if (gr?.found) {
    add({ tier: "confirmed", what: "Gravatar profile", url: gr.profile_url, meta: gr.display_name || gr.name || "", source: "Gravatar", key: "acct:gravatar" });
    fact("Name", gr.name || gr.display_name, "Gravatar", gr.profile_url);
    fact("Location", gr.location, "Gravatar", gr.profile_url);
  }

  // --- enricher + profile scrape (bios, display names) --------------------------
  for (const p of collected.enricher?.profiles || []) {
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
      add({ tier: Number(e.confidence) >= 80 ? "confirmed" : "likely", what: e.email, url: "", meta: [e.first_name, e.last_name].filter(Boolean).join(" ") + (e.position ? ` · ${e.position}` : ""), source: "Hunter.io", key: `email:${norm(e.email)}` });
    }
  }

  // --- harvester ---------------------------------------------------------------------
  // Domain harvest: only addresses matter for a person; hostnames stay in the source card.
  const hv = collected.harvester;
  if (hv && !hv.error && !hv.skipped) {
    for (const e of hv.emails || []) if (norm(e) !== norm(target)) add({ tier: "likely", what: e, url: "", meta: "same domain, seen in public archives", source: "Domain harvest", key: `email:${norm(e)}` });
  }

  // --- hash --------------------------------------------------------------------------
  const hs = collected.hash;
  if (hs) {
    const v = String(hs.verdict || "").toUpperCase();
    if (v === "MALICIOUS") add({ tier: "flag", what: `Malicious ${hs.hash_type || "hash"}${hs.malware_families?.length ? `: ${hs.malware_families.join(", ")}` : ""}`, url: hs.virustotal_url, meta: "known malware", source: "Hash lookup", key: "hash:verdict" });
    else if (v === "CLEAN") add({ tier: "confirmed", what: `Known clean ${hs.hash_type || "hash"}`, url: hs.virustotal_url, meta: "CIRCL hashlookup", source: "Hash lookup", key: "hash:verdict" });
    else add({ tier: "unverified", what: `${hs.hash_type || "Hash"} not seen by any source`, url: hs.virustotal_url, meta: "", source: "Hash lookup", key: "hash:verdict" });
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
  const order = { flag: 0, confirmed: 1, likely: 2, unverified: 3 };
  for (const it of items) if (it.sources) it.source = it.sources.join(", ");
  items.sort((a, b) => order[a.tier] - order[b.tier] || a.what.localeCompare(b.what));
  return { items, facts };
}

export const TIERS = [
  { id: "flag",       title: "Flags",               cls: "flag",      open: true,  blurb: "Breaches, malware, disposable numbers. Read these first." },
  { id: "confirmed",  title: "Confirmed",           cls: "confirmed", open: true,  blurb: "Accounts and records that exist for this target." },
  { id: "likely",     title: "Likely",              cls: "likely",    open: true,  blurb: "Probable, but from a source that sometimes guesses." },
  { id: "unverified", title: "Unverified",          cls: "",          open: false, limit: 40, blurb: "Sites that answer yes to any username. Kept for completeness." },
];
