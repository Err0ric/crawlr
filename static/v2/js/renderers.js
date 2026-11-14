// Per-source cards for the "By source" section. Every value goes through h`` / esc.
import { h, raw, esc, link, fmtNum, plural, sourceOutcome } from "./core.js";

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

function accountCard(title, data, limit = 8) {
  const all = data?.results || [];
  const ok = all.filter((r) => r.confidence !== "false_positive");
  const verified = ok.filter((r) => r.verified);
  const rows = ok.slice(0, limit).map((r) => li(h`${raw(link(r.url, r.site || r.name))}${r.verified ? raw(' <span class="tag ok">profile read</span>') : ""}${r.profile?.name ? h` ${r.profile.name}` : ""}`));
  const badge = (verified.length ? tag(`${fmtNum(verified.length)} confirmed`, "ok") + " " : "") + tag(`${fmtNum(ok.length - verified.length)} possible`) + (all.length - ok.length ? " " + tag(`${fmtNum(all.length - ok.length)} noisy`) : "");
  return card(title, badge, (rows.length ? list(rows) : none("No accounts reported.")) + more(ok.length - limit));
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
    + (!em.length && !ho.length ? h`<p class="muted">No public sources returned anything for this domain.</p>` : ""));
}

const CARDS = {
  sherlock: (d) => accountCard("Sherlock", d),
  maigret: (d) => accountCard("Maigret", d),
  holehe: (d) => {
    const rows = (d?.results || []).map((r) => li(h`${r.site || r.domain}`));
    return card("Holehe", tag(`${fmtNum(rows.length)} registered`, rows.length ? "ok" : ""), rows.length ? list(rows) : h`<p class="muted">No registrations detected.</p>`);
  },
  platformCheck: (d) => {
    const found = (d?.results || []).filter((r) => r.found);
    const manual = (d?.results || []).filter((r) => r.manual);
    const rows = [...found.map((r) => li(link(r.url, r.platform))), ...manual.map((r) => li(h`${raw(link(r.url, r.platform))} <span class="tag">check by hand</span>`))];
    return card("Platform check", tag(`${fmtNum(found.length)} possible`), (rows.length ? list(rows) : none("No profile URLs answered.")) + h`<p class="muted small">A profile URL that answers is a weak signal. These sites often answer for any name.</p>`);
  },
  hibp: (d) => {
    const b = d?.breaches || [];
    const rows = b.map((x) => li(h`${raw(link(`https://haveibeenpwned.com/PwnedWebsites`, x))}`));
    return card("Breaches", tag(plural(b.length, "breach", "breaches"), b.length ? "warn" : "ok"), rows.length ? list(rows) : h`<p class="muted">Not found in any known breach.</p>`);
  },
  github: (d) => {
    if (!d?.found) return card("GitHub", tag("not found"), none("GitHub has no account with this username."));
    return card("GitHub", tag("found", "ok"), kv([
      ["Profile", link(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Bio", esc(d.bio)], ["Company", esc(d.company)],
      ["Location", esc(d.location)], ["Email", esc(d.email)], ["Website", link(d.blog, d.blog)],
      ["Repos", esc(d.public_repos)], ["Followers", esc(d.followers)], ["Since", esc(String(d.created_at || "").slice(0, 10))],
    ]));
  },
  gravatar: (d) => {
    if (!d?.found) return card("Gravatar", tag("not found"), h`<p class="muted">No Gravatar for this address.</p>`);
    return card("Gravatar", tag("found", "ok"), kv([["Profile", link(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Display name", esc(d.display_name)], ["Location", esc(d.location)]]));
  },
  enricher: (d) => {
    const p = d?.profiles || [];
    const rows = p.slice(0, 10).map((x) => li(h`${raw(link(x.url, x.platform || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.bio ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 150)}</div>`) : ""}`));
    return card("Profile enrichment", tag(`${fmtNum(p.length)} profiles`), rows.length ? list(rows) : h`<p class="muted">Nothing to enrich.</p>`);
  },
  profileScrape: (d) => {
    const p = (d?.results || []).filter((r) => !r.error);
    const rows = p.map((x) => li(h`${raw(link(x.url, x.site || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.location ? h` · ${x.location}` : ""}${x.emails?.length ? raw(h`<div class="mono" style="font-size:var(--fs-0)">${x.emails.join(", ")}</div>`) : ""}${x.bio ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 200)}</div>`) : ""}`));
    return card("Scraped profiles", tag(`${fmtNum(p.length)} scraped`), rows.length ? list(rows) : h`<p class="muted">No profile pages could be read.</p>`);
  },
  harvester: (d) => harvestCard(d),
  hunter: (d) => {
    if (!d) return "";
    const em = d.emails || [];
    const rows = em.slice(0, 15).map((e) => li(h`<span class="mono">${e.email}</span>${e.confidence != null ? raw(h` <span class="tag ${Number(e.confidence) >= 80 ? "ok" : ""}">${e.confidence}%</span>`) : ""}${e.position ? h` · ${e.position}` : ""}`));
    return card("Hunter.io", tag(`${fmtNum(em.length)} emails`, em.length ? "ok" : ""), (d.pattern ? h`<p style="font-size:var(--fs-1);margin-bottom:6px">Pattern <span class="mono">${d.pattern}</span></p>` : "") + (rows.length ? list(rows) : h`<p class="muted">No addresses found.</p>`));
  },
  hash: (d) => {
    const v = String(d?.verdict || "UNKNOWN").toUpperCase();
    const cls = v === "MALICIOUS" ? "warn" : v === "CLEAN" ? "ok" : "";
    const src = [];
    if (d?.malware_bazaar?.found) src.push(["MalwareBazaar", esc([d.malware_bazaar.file_name, d.malware_bazaar.file_type, d.malware_bazaar.signature, d.malware_bazaar.first_seen].filter(Boolean).join(" · "))]);
    if (d?.circl?.found) src.push(["CIRCL", esc([d.circl.file_name, d.circl.known_malicious ? "known malicious" : "known file"].filter(Boolean).join(" · "))]);
    if (d?.alienvault?.found) src.push(["AlienVault OTX", esc(`${d.alienvault.pulse_count ?? 0} pulses` + (d.alienvault.malware_families?.length ? ` · ${d.alienvault.malware_families.join(", ")}` : ""))]);
    if (d?.threatfox?.found) src.push(["ThreatFox", esc(`${d.threatfox.count ?? 0} IOCs` + (d.threatfox.malware_names?.length ? ` · ${d.threatfox.malware_names.join(", ")}` : ""))]);
    return card("Hash lookup", tag(v, cls), kv([["Type", esc(d?.hash_type)], ["Hash", h`<span class="mono">${d?.hash}</span>`], ["Families", esc((d?.malware_families || []).join(", "))], ...src, ["VirusTotal", link(d?.virustotal_url, "open")]]));
  },
  phone: (d) => {
    const links = Object.entries(d?.lookup_links || {}).map(([n, u]) => link(u, n)).join(" · ");
    const noData = !d?.carrier && !d?.line_type;
    const badge = d?.api_error ? tag("key problem", "warn") : noData ? tag("links only") : tag(d?.valid === false ? "invalid" : "valid", d?.valid === false ? "warn" : "ok");
    const note = d?.api_error ? d.api_error : noData ? "Add a NumLookup key in Settings for carrier and line type." : "";
    return card("Phone lookup", badge, kv([["Number", h`<span class="mono">${d?.normalized || d?.input}</span>`], ["Carrier", esc(d?.carrier)], ["Line type", esc(d?.line_type)], ["Location", esc([d?.location, d?.country].filter(Boolean).join(", "))], ["Lookups", links]]) + (note ? h`<p style="color:var(--ink-3);font-size:var(--fs-0);margin-top:8px">${note}</p>` : ""));
  },
  nameSearch: (name) => {
    const q = encodeURIComponent(name);
    const sites = [["TruePeopleSearch", `https://www.truepeoplesearch.com/results?name=${q}`], ["FastPeopleSearch", `https://www.fastpeoplesearch.com/name/${q}`], ["Spokeo", `https://www.spokeo.com/${q}`], ["BeenVerified", `https://www.beenverified.com/people/${q}/`], ["WhitePages", `https://www.whitepages.com/name/${q}`], ["LinkedIn", `https://www.linkedin.com/search/results/people/?keywords=${q}`], ["Facebook", `https://www.facebook.com/search/people/?q=${q}`]];
    return card("People search", tag("manual"), list(sites.map(([n, u]) => li(link(u, n)))) + h`<p style="color:var(--ink-3);font-size:var(--fs-0);margin-top:8px">These open in a new tab. CrawlR does not query people-search sites itself.</p>`);
  },
  reverseImage: (url) => {
    const q = encodeURIComponent(url);
    return card("Reverse image", tag("manual"), list([li(link(`https://lens.google.com/uploadbyurl?url=${q}`, "Google Lens")), li(link(`https://tineye.com/search?url=${q}`, "TinEye")), li(link(`https://yandex.com/images/search?rpt=imageview&url=${q}`, "Yandex"))]));
  },
};

const TITLES = { sherlock: "Sherlock", maigret: "Maigret", holehe: "Holehe", platformCheck: "Platform check", hibp: "Breaches", github: "GitHub", gravatar: "Gravatar", enricher: "Profile enrichment", profileScrape: "Scraped profiles", harvester: "Domain harvest", hunter: "Hunter.io", hash: "Hash lookup", phone: "Phone lookup" };
export const sourceCards = Object.fromEntries(Object.entries(CARDS).map(([id, fn]) => [id, (d) => (d && typeof d === "object" && sourceOutcome(d).state === "error" ? errorCard(TITLES[id] || id, d) : fn(d))]));
