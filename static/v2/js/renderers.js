// Per-source cards for the "By source" section. Every value goes through h`` / esc.
import { h, raw, esc, link, fmtNum, plural, sourceOutcome } from "./core.js";
import { breachList, hashView, detectionText, TEST_FILE_TEXT, canonSite } from "./evidence.js";
import { classifyLink, applyCheck, evidenceUrl, CHECK_TEXT } from "./links.js";
import { readNameResult, DIRECTORIES, NAME_NOTICE, NAME_SOURCE } from "./names.js";
import { isAdultRow, adultListHtml, adultCounts, adultCheckText, ADULT_SOURCE } from "./adult.js";

// A profile link in a card carries the same link kind as its ledger row: a URL the source read
// is solid, a templated one is marked unverified, a homepage is plain text. `checks` is the
// link check's stored answers, so a card and the ledger never disagree about a URL.
export function profileLink(site, url, want, handle, checks) {
  const row = { key: `acct:${canonSite(site)}`, what: site, ...classifyLink({ url, want, site, subjects: [handle] }) };
  applyCheck(row, checks?.[row.key]);
  return link(row.url, site || url, "", { kind: row.link_kind }) + (row.check && row.check !== "verified" ? h` <span class="dim small">${CHECK_TEXT[row.check]}</span>` : "");
}
const ev = (url, text) => link(url, text, "", { kind: "evidence" });
const read = (url, text) => link(url, text, "", { kind: classifyLink({ url, want: "verified_profile" }).link_kind });

const card = (title, badge, body) => h`
  <article class="card">
    <div class="card-head"><h3 class="card-title">${title}</h3>${raw(badge)}</div>
    <div class="card-body">${raw(body)}</div>
  </article>`;
const tag = (text, cls = "") => h`<span class="tag ${cls}">${text}</span>`;
const list = (rows) => `<ul style="margin:0;padding-left:18px;font-size:var(--fs-1)">${rows.join("")}</ul>`;
const li = (inner) => `<li>${inner}</li>`;
const kv = (pairs) => `<dl class="kv">${pairs.filter(([, v]) => v).map(([k, v]) => h`<dt>${k}</dt><dd>${raw(v)}</dd>`).join("")}</dl>`;
const more = (n) => (n > 0 ? h`<div style="color:var(--ink-4);font-size:var(--fs-0);margin-top:6px">+${fmtNum(n)} more in the ledger above</div>` : "");

// A failed source gets its own card state. It is never rendered as "not found".
export function errorCard(title, d) {
  const o = sourceOutcome(d);
  return card(title, tag("failed", "bad"), h`<p class="muted">${o.text}</p><p class="muted small">This source could not be checked, so it says nothing either way.</p>${o.detail ? raw(h`<details class="lg-detail"><summary>details</summary><code>${o.detail}</code></details>`) : ""}`);
}
const none = (text) => h`<p class="muted">${text}</p>`;

function accountCard(title, data, checks, limit = 8) {
  // Adult and dating site rows are never listed here: they have their own group and card.
  const all = (data?.results || []).filter((r) => !isAdultRow(r));
  const ok = all.filter((r) => r.confidence !== "false_positive");
  const verified = ok.filter((r) => r.verified);
  const rows = ok.slice(0, limit).map((r) => li(h`${raw(profileLink(r.site || r.name, r.url, r.verified ? "verified_profile" : "templated_unverified", data?.username, checks))}${r.verified ? raw(' <span class="tag">profile read</span>') : ""}${r.profile?.name ? h` ${r.profile.name}` : ""}`));
  const badge = (verified.length ? tag(`${fmtNum(verified.length)} read`) + " " : "") + tag(`${fmtNum(ok.length - verified.length)} unverified`) + (all.length - ok.length ? " " + tag(`${fmtNum(all.length - ok.length)} noisy`) : "");
  return card(title, badge, (rows.length ? list(rows) : none("Answered, nothing found: no accounts reported.")) + more(ok.length - limit)
    + (verified.length ? h`<p class="muted small">A profile that was read exists. Whether it belongs to the same person is decided in the ledger, by name, avatar and links.</p>` : ""));
}

// Shared by Investigate (email domain) and Recon (target domain).
export function harvestCard(d) {
  if (d?.skipped) return card("Domain harvest", tag("skipped"), h`<p style="color:var(--ink-3);font-size:var(--fs-1)">${d.message}</p>`);
  if (d?.error) return errorCard("Domain harvest", d);
  const em = d?.emails || [], ho = d?.hosts || [], hs = d?.host_sources || {};
  const srcRows = Object.entries(d?.sources || {}).map(([n, r]) => h`<span class="tag ${r.error ? "" : "ok"}" title="${r.error || `${r.hosts ?? 0} hosts${r.emails ? `, ${r.emails} emails` : ""}`}">${n}${r.error ? " ✕" : ` ${r.hosts ?? 0}`}</span>`).join(" ");
  return card("Domain harvest", tag(`${fmtNum(d?.total_hosts ?? ho.length)} hosts · ${fmtNum(em.length)} emails`, em.length ? "ok" : ""),
    (srcRows ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">${srcRows}</div>` : "")
    + (em.length ? `<div class="mono" style="font-size:var(--fs-0);margin-bottom:8px">${em.map(esc).join("<br>")}</div>` : "")
    + (ho.length ? `<details style="font-size:var(--fs-0)"><summary style="cursor:pointer;color:var(--ink-3)">Hostnames (${fmtNum(ho.length)})</summary><div class="mono" style="margin-top:6px;max-height:260px;overflow:auto">${ho.slice(0, 300).map((x) => `${esc(x)} <span style="color:var(--ink-4)">${esc((hs[x] || []).join(", "))}</span>`).join("<br>")}</div></details>` : "")
    + (!em.length && !ho.length ? h`<p class="muted">Answered, nothing found: no public source returned anything for this domain.</p>` : ""));
}

const CARDS = {
  sherlock: (d, checks) => accountCard("Sherlock", d, checks),
  maigret: (d, checks) => accountCard("Maigret", d, checks),
  holehe: (d) => {
    const rows = (d?.results || []).map((r) => li(h`${r.site || r.domain}`));
    return card("Holehe", tag(`${fmtNum(rows.length)} registered`, rows.length ? "ok" : ""), rows.length ? list(rows) : h`<p class="muted">Answered, nothing found: no registrations detected.</p>`);
  },
  platformCheck: (d, checks) => {
    // An adult site (older cases list OnlyFans as "check by hand") is never part of this card.
    const all = (d?.results || []).filter((r) => !isAdultRow(r));
    // Only "found" read the page. A blocked or unclear check leaves a templated URL; a page the
    // site says does not exist is not linked at all.
    const WANT = { found: "verified_profile", not_found: "", blocked: "templated_unverified", unknown: "templated_unverified" };
    const pl = (r, want) => (want ? profileLink(r.platform, r.url, want, d?.username, checks) : esc(r.platform));
    // New shape: each result carries a state and the reason for it.
    if (all.some((r) => r.state)) {
      const WORD = { found: ["profile read", "ok"], not_found: ["not found", ""], blocked: ["Blocked by site", "warn"], unknown: ["could not tell", ""] };
      const n = (st) => all.filter((r) => r.state === st).length;
      const rows = all.map((r) => li(h`${raw(pl(r, WANT[r.state] ?? "templated_unverified"))} <span class="tag ${(WORD[r.state] || ["", ""])[1]}">${(WORD[r.state] || [r.state])[0]}</span>${r.display_name ? ` ${r.display_name}` : ""}${r.evidence ? raw(h`<div class="dim small">${r.evidence}</div>`) : ""}`));
      return card("Platform check", tag(`${fmtNum(n("found"))} read`, n("found") ? "ok" : "") + (n("blocked") ? " " + tag(`${fmtNum(n("blocked"))} blocked`, "warn") : ""),
        (rows.length ? list(rows) : none("No platforms were checked.")) + h`<p class="muted small">"Profile read" means a marker on the page matched, never a bare response. "Blocked by site" means the site refused or walled the check, so it is unknown, not absent.</p>`);
    }
    const found = all.filter((r) => r.found);
    const rows = found.map((r) => li(pl(r, "templated_unverified")));
    return card("Platform check", tag(`${fmtNum(found.length)} unverified`), (rows.length ? list(rows) : none("Answered, nothing found: no profile URLs answered.")) + h`<p class="muted small">A profile URL that answers is a weak signal. These sites often answer for any name.</p>`);
  },
  // rows: the ledger's adult group (adultRows), so the card and the group say the same thing.
  // Text and links only: no picture, no favicon, no preview.
  adultCheck: (d, rows) => {
    const mine = (rows || []).filter((r) => (r.sources || []).includes(ADULT_SOURCE));
    const c = adultCounts(mine);
    return card(ADULT_SOURCE, tag(`${fmtNum(c.read)} read`, c.read ? "ok" : "") + (c.blocked ? " " + tag(`${fmtNum(c.blocked)} blocked`, "warn") : "") + " " + tag("existence only"),
      h`<p class="muted">${adultCheckText(d)}.</p>` + (mine.length ? adultListHtml(mine) : none("No adult or dating site was checked."))
      + h`<p class="muted small">"Profile read" means a marker on the page matched. "Blocked by site" and "could not be checked" are unknown, not absent. Nothing here says who owns an account.</p>`);
  },
  hibp: (d) => {
    const b = breachList(d);
    const rows = b.map((x) => li(h`${raw(ev(x.url, x.name))}${x.date || x.year ? raw(h` <span class="dim">${x.date || x.year}</span>`) : ""}${x.verified === true ? raw(' <span class="tag">verified</span>') : x.verified === false ? raw(' <span class="tag warn">unverified</span>') : ""}${x.sensitive ? raw(' <span class="tag warn">sensitive</span>') : ""}${x.data_classes.length || x.records ? raw(h`<div class="dim small">${[x.data_classes.join(", "), x.records ? `${fmtNum(x.records)} records` : ""].filter(Boolean).join(" · ")}</div>`) : ""}`));
    return card("Breaches", tag(plural(b.length, "breach", "breaches"), b.length ? "warn" : "ok"),
      (rows.length ? list(rows) : h`<p class="muted">Answered, nothing found: not in any breach known to this source.</p>`)
      + (d?.details === "unavailable" ? h`<p class="muted small">Dates and data classes could not be loaded, so only the names are shown.</p>` : "")
      + (b.length ? h`<p class="muted small">Newest first${d?.source ? `. Source: ${d.source}` : ""}.</p>` : ""));
  },
  // deep: the follow-up "GitHub details" response, when it ran.
  github: (d, deep) => {
    if (!d?.found) return card("GitHub", tag("not found"), none("Answered, nothing found: GitHub has no account with this username."));
    const base = kv([
      ["Profile", read(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Bio", esc(d.bio)], ["Company", esc(d.company)],
      ["Location", esc(d.location)], ["Email", esc(d.email)], ["Website", ev(/^https?:\/\//i.test(String(d.blog || "")) || !d.blog ? d.blog : `https://${d.blog}`, d.blog)], ["Twitter", esc(d.twitter_username)],
      ["Repos", esc(d.public_repos)], ["Followers", esc(d.followers)], ["Since", esc(String(d.created_at || "").slice(0, 10))],
    ]);
    return card("GitHub", tag("found", "ok") + (deep?.state === "partial" ? " " + tag("details partial", "warn") : ""), base + githubDeepBody(deep));
  },
  // Shown as its own card only when the follow-up failed or found nothing; otherwise it is part of the GitHub card.
  githubDeep: (d, gh) => (gh?.found && d?.found !== false ? "" : card("GitHub details", tag("not found"), none("Answered, nothing found: GitHub returned no details for this username."))),
  avatarHash: (d) => {
    const r = d?.results || [], ok = r.filter((x) => x.hash && !x.error), dflt = ok.filter((x) => x.default), bad = r.filter((x) => x.error);
    const name = (id) => String(id).replace(/^acct:/, "");
    return card("Avatar comparison", tag(`${fmtNum(ok.length)} of ${fmtNum(r.length)} compared`, ok.length ? "ok" : ""),
      h`<p class="muted">Profile pictures were fetched from public image hosts and reduced to a 64-bit fingerprint. Two profiles with nearly the same picture are tied together in the ledger.</p>`
      + kv([["Compared", esc(ok.filter((x) => !x.default).map((x) => name(x.id)).join(", "))], ["Default or placeholder", esc(dflt.map((x) => name(x.id)).join(", "))], ["Could not be read", bad.map((x) => h`${name(x.id)} <span class="dim">${x.error}</span>`).join("<br>")]])
      + h`<p class="muted small">A default or placeholder picture never ties two profiles together. A picture that could not be read is unknown, not different.</p>`);
  },
  gravatar: (d) => {
    if (!d?.found) return card("Gravatar", tag("not found"), h`<p class="muted">Answered, nothing found: no Gravatar for this address.</p>`);
    return card("Gravatar", tag("found", "ok"), kv([["Profile", read(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Display name", esc(d.display_name)], ["Location", esc(d.location)]]));
  },
  enricher: (d) => {
    const p = d?.profiles || [];
    const rows = p.slice(0, 10).map((x) => li(h`${raw(read(x.url, x.platform || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.bio && !x.bio_boilerplate ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 150)}</div>`) : ""}`));
    return card("Profile enrichment", tag(`${fmtNum(p.length)} profiles`), rows.length ? list(rows) : h`<p class="muted">Answered, nothing found: no profile page gave a name or a bio.</p>`);
  },
  profileScrape: (d) => {
    const p = (d?.results || []).filter((r) => !r.error);
    const rows = p.map((x) => li(h`${raw(read(x.url, x.site || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.location ? h` · ${x.location}` : ""}${x.emails?.length ? raw(h`<div class="mono" style="font-size:var(--fs-0)">${x.emails.join(", ")}</div>`) : ""}${x.bio ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 200)}</div>`) : ""}`));
    return card("Scraped profiles", tag(`${fmtNum(p.length)} scraped`), rows.length ? list(rows) : h`<p class="muted">No profile pages could be read.</p>`);
  },
  harvester: (d) => harvestCard(d),
  // d is linkCheckSource(collected): one row per link the check looked at.
  linkCheck: (d) => {
    const r = d?.results || [], n = (st) => r.filter((x) => x.state === st).length;
    const name = (id) => String(id).replace(/^acct:/, "");
    const names = (st) => esc(r.filter((x) => x.state === st).map((x) => name(x.id)).join(", "));
    return card("Link check", tag(`${fmtNum(n("verified"))} of ${fmtNum(r.length)} pages exist`, n("verified") ? "ok" : "") + (n("blocked") ? " " + tag(`${fmtNum(n("blocked"))} blocked`, "warn") : ""),
      h`<p class="muted">Each reported profile URL was requested once to see whether the page exists. It is the same passive check the username tools make.</p>`
      + kv([["Page exists", names("verified")], ["Page not found", names("not_found")], ["Blocked by site", names("blocked")], ["Could not be checked", names("unknown")], ["No public page", names("no_public_url")]])
      + h`<p class="muted small">A page that exists shows the handle is taken there. It does not show who owns it. Blocked and unchecked links are unknown, not absent.</p>`);
  },
  hunter: (d) => {
    if (!d) return "";
    const em = d.emails || [];
    const rows = em.slice(0, 15).map((e) => li(h`<span class="mono">${e.email}</span>${e.confidence != null ? raw(h` <span class="tag ${Number(e.confidence) >= 80 ? "ok" : ""}">${e.confidence}%</span>`) : ""}${e.position ? h` · ${e.position}` : ""}`));
    return card("Hunter.io", tag(`${fmtNum(em.length)} emails`, em.length ? "ok" : ""), (d.pattern ? h`<p style="font-size:var(--fs-1);margin-bottom:6px">Pattern <span class="mono">${d.pattern}</span></p>` : "") + (rows.length ? list(rows) : h`<p class="muted">Answered, nothing found: no addresses on this domain.</p>`));
  },
  hash: (d) => {
    const v = hashView(d) || { verdict: "UNKNOWN", tags: [], families: [], familySources: [] };
    const cls = v.verdict === "MALICIOUS" ? "warn" : v.verdict === "CLEAN" || v.verdict === "TEST_FILE" ? "ok" : "";
    const word = { TEST_FILE: "test file", MALICIOUS: "malicious", CLEAN: "known clean", UNKNOWN: "unknown" }[v.verdict];
    const src = [];
    if (d?.malware_bazaar?.found) src.push(["MalwareBazaar", esc([d.malware_bazaar.file_name, d.malware_bazaar.file_type, d.malware_bazaar.signature, d.malware_bazaar.first_seen].filter(Boolean).join(" · "))]);
    if (d?.circl?.found) src.push(["CIRCL", esc([d.circl.file_name, d.circl.known_malicious ? "listed as malicious" : "known file"].filter(Boolean).join(" · "))]);
    if (d?.alienvault?.found) src.push(["AlienVault OTX", esc(`${d.alienvault.pulse_count ?? 0} pulses`)]);
    if (d?.threatfox?.found) src.push(["ThreatFox", esc(`${d.threatfox.count ?? 0} IOCs` + (d.threatfox.malware_names?.length ? ` · ${d.threatfox.malware_names.join(", ")}` : ""))]);
    return card("Hash lookup", tag(word, cls),
      (v.testFile ? h`<p class="card-lead">${v.testFile.name}: ${TEST_FILE_TEXT}.${v.testFile.note ? ` ${v.testFile.note}` : ""}</p>` : "")
      + kv([["Type", esc(d?.hash_type)], ["Hash", h`<span class="mono">${d?.hash}</span>`],
        ["Family", esc(v.family ? `${v.family}${v.familySources.length ? ` (${v.familySources.join(", ")})` : ""}` : "")], ["Other families", esc(v.families.filter((f) => f !== v.family).join(", "))],
        ["Detection", esc(detectionText(v))], ["File type", esc(v.fileType)], ["File name", esc(v.fileName)], ["File size", esc(v.fileSize != null && v.fileSize !== "" ? `${fmtNum(v.fileSize)} bytes` : "")],
        ["First seen", esc(v.firstSeen)], ["Last seen", esc(v.lastSeen)], ...src,
        ["Verdict basis", esc(d?.verdict_basis)], ["Could not be asked", esc((d?.failed_sources || []).join(", "))],
        ["Community tags (unverified)", esc(v.tags.join(", "))], ["Check", [(evidenceUrl.virustotal(d?.hash) || d?.virustotal_url) && ev(evidenceUrl.virustotal(d?.hash) || d?.virustotal_url, "VirusTotal"), d?.alienvault && !d.alienvault.error && !d.alienvault.error_code && evidenceUrl.otx(d?.hash) ? ev(evidenceUrl.otx(d?.hash), "OTX") : ""].filter(Boolean).join(" · ")]])
      + ((d?.failed_sources || []).length ? h`<p class="muted small">A source that could not be asked is unknown. It did not say "not found".</p>` : "")
      + (v.tags.length ? h`<p class="muted small">Community tags are free text written by whoever submitted a report. They are not a family name and are never used in a headline.</p>` : ""));
  },
  phone: (d) => {
    const links = Object.entries(d?.lookup_links || {}).map(([n, u]) => link(u, n)).join(" · ");
    const noData = !d?.carrier && !d?.line_type;
    const badge = d?.api_error ? tag("key problem", "warn") : noData ? tag("links only") : tag(d?.valid === false ? "invalid" : "valid", d?.valid === false ? "warn" : "ok");
    const note = d?.api_error ? d.api_error : noData ? "Add a NumLookup key in Settings for carrier and line type." : "";
    return card("Phone lookup", badge, kv([["Number", h`<span class="mono">${d?.normalized || d?.input}</span>`], ["Carrier", esc(d?.carrier)], ["Line type", esc(d?.line_type)], ["Location", esc([d?.location, d?.country].filter(Boolean).join(", "))], ["Lookups", links]]) + (note ? h`<p style="color:var(--ink-3);font-size:var(--fs-0);margin-top:8px">${note}</p>` : ""));
  },
  // One line per directory: how many rows it gave, that it had no one, or that it is unknown.
  // The outbound searches are no longer a card: they are the "Search the web" group in the ledger.
  nameResult: (d) => {
    const r = readNameResult(d);
    if (!r || r.error) return "";
    const asked = DIRECTORIES.filter((k) => r.sources[k]);
    const down = asked.filter((k) => r.sources[k].state === "failed" || r.sources[k].state === "rate_limited");
    const word = (s) => (s.state === "ok" ? `${fmtNum(s.count)} found${s.shown < s.count ? `, ${fmtNum(s.shown)} shown` : ""}${s.total != null && s.total > s.count ? ` (the directory returned ${fmtNum(s.total)})` : ""}`
      : s.state === "none" ? "answered, no one by this name" : s.state === "rate_limited" ? "unknown: rate limited" : `unknown: ${s.error || "failed"}`);
    return card(NAME_SOURCE, tag(plural(r.candidates.length, "candidate"), r.candidates.length ? "ok" : "") + (down.length ? " " + tag(`${fmtNum(down.length)} not asked`, "warn") : ""),
      h`<p class="muted">${NAME_NOTICE}</p>` + kv(asked.map((k) => [k, esc(word(r.sources[k]))]))
      + h`<p class="muted small">Only rows whose name fits are counted, and the list holds 30 in all, taken from every directory in turn. A directory that could not be asked is unknown, not "nobody by this name". The location, employer and keyword are compared here and never sent to a directory.</p>`);
  },
  reverseImage: (url) => {
    const q = encodeURIComponent(url);
    return card("Reverse image", tag("manual"), list([li(link(`https://lens.google.com/uploadbyurl?url=${q}`, "Google Lens")), li(link(`https://tineye.com/search?url=${q}`, "TinEye")), li(link(`https://yandex.com/images/search?rpt=imageview&url=${q}`, "Yandex"))]));
  },
};

// The extra sections the GitHub details call adds to the GitHub card. A section GitHub
// rate limited or failed is shown as unknown, never as an empty list.
function githubDeepBody(dp) {
  if (!dp) return "";
  if (sourceOutcome(dp).state === "error") return "";   // its own failed card says so
  if (dp.found === false) return "";
  const st = (k) => dp.sections?.[k] || "ok";
  const unknown = (k) => (st(k) === "rate_limited" ? '<span class="dim">unknown: GitHub rate limited this lookup</span>' : st(k) === "failed" ? '<span class="dim">unknown: this lookup failed</span>' : "");
  const val = (k, html, empty = '<span class="dim">none</span>') => unknown(k) || html || empty;
  const repos = (dp.top_repos || []).slice(0, 6).map((r) => h`${raw(ev(r.url, r.name))} <span class="dim">${[r.language, `${fmtNum(r.stars)} stars`, r.fork ? "fork" : ""].filter(Boolean).join(" · ")}</span>`).join("<br>");
  const keys = [...(dp.keys?.ssh || []).map((k) => h`<span class="mono">${k.type} ${k.fingerprint}</span>`), ...(dp.keys?.gpg || []).map((k) => h`<span class="mono">GPG ${k.key_id}</span>${k.emails?.length ? raw(h` <span class="dim">${k.emails.join(", ")}</span>`) : ""}`)].join("<br>");
  const keyState = unknown("ssh_keys") && unknown("gpg_keys") ? unknown("ssh_keys") : keys + (keys && (unknown("ssh_keys") || unknown("gpg_keys")) ? "<br>" : "") + (keys || !(unknown("ssh_keys") || unknown("gpg_keys")) ? "" : "") + (unknown("ssh_keys") && !unknown("gpg_keys") ? '<span class="dim">SSH keys unknown</span>' : !unknown("ssh_keys") && unknown("gpg_keys") ? '<span class="dim">GPG keys unknown</span>' : "");
  return h`<p class="muted small">From the GitHub details lookup${dp.cached ? " (cached)" : ""}:</p>` + kv([
    ["Organisations", val("orgs", (dp.orgs || []).map((o) => ev(o.url, o.login)).join(", "))],
    ["Top repos", val("top_repos", repos)],
    ["Languages", val("top_repos", esc((dp.languages || []).join(", ")))],
    ["Key fingerprints", keyState || '<span class="dim">none</span>'],
    ["Commit emails", val("commit_emails", (dp.commit_emails || []).map((e) => h`<span class="mono">${e.email}</span> <span class="dim">${[e.name, e.repo].filter(Boolean).join(" · ")}</span>`).join("<br>"))],
    ["Social accounts", val("social_accounts", (dp.social_accounts || []).map((a) => h`${a.provider || ""} ${raw(ev(a.url, a.url))}`).join("<br>"))],
    ["README links", val("readme_links", (dp.readme_links || []).slice(0, 12).map((u) => ev(u, u)).join("<br>"))],
  ]);
}

const TITLES = { nameResult: NAME_SOURCE, adultCheck: ADULT_SOURCE, linkCheck: "Link check", githubDeep: "GitHub details", avatarHash: "Avatar comparison", sherlock: "Sherlock", maigret: "Maigret", holehe: "Holehe", platformCheck: "Platform check", hibp: "Breaches", github: "GitHub", gravatar: "Gravatar", enricher: "Profile enrichment", profileScrape: "Scraped profiles", harvester: "Domain harvest", hunter: "Hunter.io", hash: "Hash lookup", phone: "Phone lookup" };
export const sourceCards = Object.fromEntries(Object.entries(CARDS).map(([id, fn]) => [id, (d, extra) => (d && typeof d === "object" && sourceOutcome(d).state === "error" ? errorCard(TITLES[id] || id, d) : fn(d, extra))]));
