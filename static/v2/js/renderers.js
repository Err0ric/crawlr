// Per-source cards for the "By source" section. Every value goes through h`` / esc.
import { h, raw, esc, link, fmtNum, plural } from "./core.js";

const card = (title, badge, body) => h`
  <article class="card">
    <div class="card-head"><h3>${title}</h3>${raw(badge)}</div>
    <div class="card-body">${raw(body)}</div>
  </article>`;
const tag = (text, cls = "") => h`<span class="tag ${cls}">${text}</span>`;
const list = (rows) => `<ul style="margin:0;padding-left:18px;font-size:var(--fs-1)">${rows.join("")}</ul>`;
const li = (inner) => `<li>${inner}</li>`;
const kv = (pairs) => `<dl class="kv">${pairs.filter(([, v]) => v).map(([k, v]) => h`<dt>${k}</dt><dd>${raw(v)}</dd>`).join("")}</dl>`;
const more = (n) => (n > 0 ? h`<div style="color:var(--ink-4);font-size:var(--fs-0);margin-top:6px">+${fmtNum(n)} more in the ledger above</div>` : "");

function accountCard(title, data, limit = 8) {
  if (data?.error) return card(title, tag("error", "warn"), h`<p style="color:var(--ink-3)">${data.error}</p>`);
  const all = data?.results || [];
  const ok = all.filter((r) => r.confidence !== "false_positive");
  const rows = ok.slice(0, limit).map((r) => li(h`${raw(link(r.url, r.site || r.name))}${r.confidence === "high_confidence" ? raw(' <span class="tag ok">high</span>') : ""}${r.category ? raw(h`<span class="tag">${r.category}</span>`) : ""}`));
  const badge = tag(`${fmtNum(ok.length)} found`, ok.length ? "ok" : "") + (all.length - ok.length ? " " + tag(`${fmtNum(all.length - ok.length)} unverified`) : "");
  return card(title, badge, (rows.length ? list(rows) : h`<p style="color:var(--ink-3)">No accounts found.</p>`) + more(ok.length - limit));
}

export const sourceCards = {
  sherlock: (d) => accountCard("Sherlock", d),
  maigret: (d) => accountCard("Maigret", d),
  holehe: (d) => {
    const rows = (d?.results || []).map((r) => li(h`${r.site || r.domain}`));
    return card("Holehe", tag(`${fmtNum(rows.length)} registered`, rows.length ? "ok" : ""), rows.length ? list(rows) : h`<p style="color:var(--ink-3)">No registrations detected.</p>`);
  },
  platformCheck: (d) => {
    const found = (d?.results || []).filter((r) => r.found);
    const rows = found.map((r) => li(h`${raw(link(r.url, r.platform))}${r.manual ? raw(' <span class="tag">manual check</span>') : ""}`));
    return card("Platform check", tag(`${fmtNum(found.length)} found`, found.length ? "ok" : ""), rows.length ? list(rows) : h`<p style="color:var(--ink-3)">No platforms confirmed.</p>`);
  },
  hibp: (d) => {
    const b = d?.breaches || [];
    const rows = b.map((x) => li(h`${raw(link(`https://haveibeenpwned.com/PwnedWebsites`, x))}`));
    return card("Breaches", tag(plural(b.length, "breach", "breaches"), b.length ? "warn" : "ok"), rows.length ? list(rows) : h`<p style="color:var(--ink-3)">Not found in any known breach.</p>`);
  },
  github: (d) => {
    if (!d?.found) return card("GitHub", tag("not found"), h`<p style="color:var(--ink-3)">No GitHub account with this username.</p>`);
    return card("GitHub", tag("found", "ok"), kv([
      ["Profile", link(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Bio", esc(d.bio)], ["Company", esc(d.company)],
      ["Location", esc(d.location)], ["Email", esc(d.email)], ["Website", link(d.blog, d.blog)],
      ["Repos", esc(d.public_repos)], ["Followers", esc(d.followers)], ["Since", esc(String(d.created_at || "").slice(0, 10))],
    ]));
  },
  gravatar: (d) => {
    if (!d?.found) return card("Gravatar", tag("not found"), h`<p style="color:var(--ink-3)">No Gravatar for this address.</p>`);
    return card("Gravatar", tag("found", "ok"), kv([["Profile", link(d.profile_url, d.profile_url)], ["Name", esc(d.name)], ["Display name", esc(d.display_name)], ["Location", esc(d.location)]]));
  },
  enricher: (d) => {
    const p = d?.profiles || [];
    const rows = p.slice(0, 10).map((x) => li(h`${raw(link(x.url, x.platform || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.bio ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 150)}</div>`) : ""}`));
    return card("Profile enrichment", tag(`${fmtNum(p.length)} profiles`), rows.length ? list(rows) : h`<p style="color:var(--ink-3)">Nothing to enrich.</p>`);
  },
  profileScrape: (d) => {
    const p = (d?.results || []).filter((r) => !r.error);
    const rows = p.map((x) => li(h`${raw(link(x.url, x.site || x.url))}${x.display_name ? h` · ${x.display_name}` : ""}${x.location ? h` · ${x.location}` : ""}${x.emails?.length ? raw(h`<div class="mono" style="font-size:var(--fs-0)">${x.emails.join(", ")}</div>`) : ""}${x.bio ? raw(h`<div style="color:var(--ink-3);font-size:var(--fs-0)">${String(x.bio).slice(0, 200)}</div>`) : ""}`));
    return card("Scraped profiles", tag(`${fmtNum(p.length)} scraped`), rows.length ? list(rows) : h`<p style="color:var(--ink-3)">No profile pages could be read.</p>`);
  },
  harvester: (d) => {
    if (d?.error) return card("theHarvester", tag(d.error === "unavailable" ? "unavailable" : "error", "warn"), h`<p style="color:var(--ink-3)">${d.message || d.error}</p>`);
    const em = d?.emails || [], ho = d?.hosts || [];
    return card("theHarvester", tag(`${fmtNum(em.length)} emails · ${fmtNum(ho.length)} hosts`), (em.length ? `<div class="mono" style="font-size:var(--fs-0)">${em.map(esc).join("<br>")}</div>` : "") + (ho.length ? `<div class="mono" style="font-size:var(--fs-0);margin-top:6px">${ho.slice(0, 30).map(esc).join("<br>")}</div>` : "") + (!em.length && !ho.length ? h`<p style="color:var(--ink-3)">Nothing harvested.</p>` : ""));
  },
  hunter: (d) => {
    if (!d || d.error) return "";
    const em = d.emails || [];
    const rows = em.slice(0, 15).map((e) => li(h`<span class="mono">${e.email}</span>${e.confidence != null ? raw(h` <span class="tag ${Number(e.confidence) >= 80 ? "ok" : ""}">${e.confidence}%</span>`) : ""}${e.position ? h` · ${e.position}` : ""}`));
    return card("Hunter.io", tag(`${fmtNum(em.length)} emails`, em.length ? "ok" : ""), (d.pattern ? h`<p style="font-size:var(--fs-1);margin-bottom:6px">Pattern <span class="mono">${d.pattern}</span></p>` : "") + (rows.length ? list(rows) : h`<p style="color:var(--ink-3)">No addresses found.</p>`));
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
    return card("Phone lookup", d?.api_error ? tag("no key", "warn") : tag(d?.valid === false ? "invalid" : "valid", d?.valid === false ? "warn" : "ok"), kv([["Number", h`<span class="mono">${d?.normalized || d?.input}</span>`], ["Carrier", esc(d?.carrier)], ["Line type", esc(d?.line_type)], ["Location", esc([d?.location, d?.country].filter(Boolean).join(", "))], ["Lookups", links]]) + (d?.api_error ? h`<p style="color:var(--ink-3);font-size:var(--fs-0);margin-top:8px">Add a NumLookup key in Settings for carrier and location.</p>` : ""));
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
