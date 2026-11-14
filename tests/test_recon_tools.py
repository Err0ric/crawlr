import asyncio
import base64
import json
from pathlib import Path

import dns.exception
import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient

from main import app
from modules import crtsh, email_posture as ep, lookalikes as la, takeover as tk, wellknown as wk
from modules.dns_depth import parse_caa
from modules.subdomain_enum import summarize_certificates
from modules.wayback import interesting_paths

FIX = Path(__file__).parent / "fixtures" / "recon"
fixture = lambda name: json.loads((FIX / name).read_text())

SPF_STRICT = "v=spf1 include:_spf.google.com -all"
DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:d@example.com"


def titles(result, level=None):
    return [f["title"] for f in result["findings"] if level is None or f["level"] == level]


# ---- email posture -----------------------------------------------------------

def test_spf_parsing():
    s = ep.parse_spf("v=spf1 ip4:192.0.2.0/24 include:a.example include:b.example a mx ~all")
    assert s["all"] == "softfail" and s["includes"] == ["a.example", "b.example"] and s["lookups"] == 4
    assert ep.parse_spf("v=spf1 +all")["all"] == "pass"
    assert ep.parse_spf("v=spf1 redirect=_spf.example.com")["redirect"] == "_spf.example.com"


def test_dmarc_parsing():
    d = ep.parse_dmarc("v=DMARC1; p=quarantine; sp=none; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s")
    assert (d["policy"], d["subdomain_policy"], d["pct"]) == ("quarantine", "none", 50)
    assert d["rua"] == ["mailto:a@x.com", "mailto:b@x.com"] and d["alignment"]["dkim"] == "s"


def test_fully_protected_domain_gets_an_a():
    r = ep.assess([SPF_STRICT], [DMARC_REJECT], [{"selector": "google", "found": True, "key_bits": 2048}], ["mx.example.com"], "v=STSv1; id=1", "v=TLSRPTv1; rua=mailto:t@x.com", "")
    assert (r["grade"], r["spoofable"]) == ("A", "no")
    assert titles(r, "flag") == []


def test_no_records_is_spoofable_f():
    r = ep.assess([], [], [], ["mx.example.com"], "", "", "")
    assert (r["grade"], r["spoofable"]) == ("F", "yes")
    assert "No SPF record" in titles(r, "flag") and "No DMARC record" in titles(r, "flag")


def test_monitor_only_dmarc_is_still_spoofable():
    r = ep.assess([SPF_STRICT], ["v=DMARC1; p=none; rua=mailto:d@example.com"], [], ["mx"], "", "", "")
    assert r["spoofable"] == "yes" and r["grade"] == "D"
    assert "DMARC is monitor-only (p=none)" in titles(r, "flag")


@pytest.mark.parametrize("spf,expected", [
    (["v=spf1 +all"], "SPF ends in +all"),
    (["v=spf1 a", "v=spf1 mx"], "More than one SPF record"),
    (["v=spf1 " + " ".join(f"include:s{i}.example" for i in range(11)) + " -all"], "SPF needs 11 DNS lookups"),
    (["v=spf1 ip4:192.0.2.1"], "SPF does not reject anything"),
])
def test_spf_problems_are_flagged(spf, expected):
    assert expected in titles(ep.assess(spf, [DMARC_REJECT], [], ["mx"], "", "", ""), "flag")


def test_missing_dkim_is_not_reported_as_a_fact():
    r = ep.assess([SPF_STRICT], [DMARC_REJECT], [], ["mx"], "", "", "")
    row = next(f for f in r["findings"] if "DKIM" in f["title"])
    assert row["level"] == "info" and "not proof" in row["detail"]


def test_unprotected_subdomains_are_flagged():
    r = ep.assess([SPF_STRICT], ["v=DMARC1; p=reject; sp=none; rua=mailto:a@x.com"], [], ["mx"], "", "", "")
    assert "Subdomains are not protected (sp=none)" in titles(r, "flag")


def test_run_email_posture_reads_dns(monkeypatch):
    records = {"example.com": ["some-verification=abc", SPF_STRICT], "_dmarc.example.com": [DMARC_REJECT],
               "selector1._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + "A" * 400]}
    monkeypatch.setattr(ep, "_txt", lambda name: records.get(name, []))
    monkeypatch.setattr(ep, "_mx", lambda name: ["mx1.example.com"])
    out = asyncio.run(ep.run_email_posture("example.com"))
    assert out["grade"] == "A" and out["spf"]["all"] == "fail" and out["dmarc"]["policy"] == "reject"
    assert out["dkim"] == [{"selector": "selector1", "found": True, "revoked": False, "key_bits": 2048}]
    assert out["dkim_selectors_checked"] == len(ep.DKIM_SELECTORS)


# ---- email posture for a domain with no mail ------------------------------------

def test_darkwire_recording_flagged_a_domain_with_no_mx():
    before = fixture("darkwire.email_posture.json")        # what the endpoint said on 2026-11-14
    assert before["mx"] == [] and before["grade"] == "F" and titles(before, "flag") == ["No SPF record", "No DMARC record"]


def test_no_mx_turns_missing_spf_and_dmarc_into_notes():
    r = ep.assess([], [], [], [], "", "", "")
    assert titles(r, "flag") == [] and r["mail_enabled"] is False and r["grade"] != "F" and r["grade"] == "N/A"
    assert "Note: no SPF record" in titles(r, "info") and "Note: no DMARC record" in titles(r, "info")
    assert all(f["level"] in ("flag", "ok", "info") for f in r["findings"])
    tip = next(f for f in r["findings"] if f["title"].startswith("Suggested records"))
    assert tip["level"] == "info" and all(x in tip["detail"] for x in ("v=spf1 -all", "v=DMARC1; p=reject;", "0 ."))
    assert r["suggested_records"] == [{"type": "TXT", "name": "@", "value": "v=spf1 -all"}, {"type": "TXT", "name": "_dmarc", "value": "v=DMARC1; p=reject;"},
                                      {"type": "MX", "name": "@", "value": "0 ."}]
    assert "no MX records" in r["summary"]


def test_no_mx_domain_that_published_the_null_records_is_an_a():
    r = ep.assess(["v=spf1 -all"], ["v=DMARC1; p=reject;"], [], [], "", "", "", null_mx=True)
    assert (r["grade"], r["spoofable"], r["mail_enabled"]) == ("A", "no", False)
    assert r["suggested_records"] == [] and "Null MX published" in titles(r, "info") and titles(r, "flag") == []


def test_no_mx_still_flags_a_record_that_is_wrong():
    r = ep.assess(["v=spf1 +all"], [], [], [], "", "", "")
    assert titles(r, "flag") == ["SPF ends in +all"] and "Note: no DMARC record" in titles(r, "info")
    assert [x["name"] for x in r["suggested_records"]] == ["_dmarc", "@"]


def test_domain_with_mx_is_assessed_exactly_as_before():
    r = ep.assess([], [], [], ["mx.example.com"], "", "", "")
    assert (r["grade"], r["spoofable"], r["mail_enabled"]) == ("F", "yes", True)
    assert titles(r) == ["No SPF record", "No DMARC record", "No DKIM key at common selectors", "No MTA-STS"]
    assert r["suggested_records"] == [] and r["summary"].startswith("The domain can be spoofed")


def test_failed_mx_lookup_is_not_treated_as_no_mail():
    r = ep.assess([], [], [], [], "", "", "", mx_checked=False)
    assert r["mail_enabled"] is None and r["grade"] == "F" and "No SPF record" in titles(r, "flag")
    assert "Could not check MX records" in titles(r, "info") and "No MX records" not in titles(r)


def run_posture(monkeypatch, txt, mx):
    monkeypatch.setattr(ep, "_txt", txt)
    monkeypatch.setattr(ep, "_mx", mx)
    return asyncio.run(ep.run_email_posture("darkwire.tech"))


def test_run_email_posture_for_darkwire(monkeypatch):
    out = run_posture(monkeypatch, lambda name: [], lambda name: [])
    before = fixture("darkwire.email_posture.json")
    assert out["mail_enabled"] is False and out["grade"] == "N/A" and titles(out, "flag") == []
    assert out["mx"] == before["mx"] == [] and out["spf"] is None and out["dmarc"] is None
    assert set(before) <= set(out)                         # every field the old shape had is still there


def test_run_email_posture_reads_a_null_mx(monkeypatch):
    out = run_posture(monkeypatch, lambda name: [], lambda name: [""])
    assert out["null_mx"] is True and out["mx"] == [] and out["mail_enabled"] is False
    assert [x["type"] for x in out["suggested_records"]] == ["TXT", "TXT"]


def test_run_email_posture_failed_lookups(monkeypatch):
    # a failed MX lookup: assessed strictly, and said so
    out = run_posture(monkeypatch, lambda name: [], lambda name: None)
    assert out["mail_enabled"] is None and out["grade"] == "F" and out["mx"] == []
    # a failed SPF or DMARC lookup: an error, never "No SPF record"
    out = run_posture(monkeypatch, lambda name: None if name == "darkwire.tech" else [], lambda name: ["mx.example.com"])
    assert out["error_code"] == "dns" and out["found"] is False and "grade" not in out and "findings" not in out


class FakeDns:
    """Stands in for dns.resolver.Resolver. `answers` maps (name, type) or name to a result:
    a list of record strings, or an exception to raise."""
    def __init__(self, answers):
        self.answers = answers

    def resolve(self, name, rtype):
        got = self.answers.get((name, rtype), self.answers.get(name, dns.resolver.NoAnswer()))
        if isinstance(got, Exception):
            raise got

        class Rdata:
            def __init__(self, text): self.text, self.strings, self.exchange, self.target = text, [text.encode()], text, text
            def __str__(self): return self.text
        return [Rdata(x) for x in got]


@pytest.mark.parametrize("error,expected", [
    (dns.resolver.NXDOMAIN(), []), (dns.resolver.NoAnswer(), []),
    (dns.exception.Timeout(), None), (dns.resolver.NoNameservers(), None),
])
def test_txt_and_mx_tell_absent_from_failed(monkeypatch, error, expected):
    monkeypatch.setattr(ep, "_resolver", lambda: FakeDns({"example.com": error}))
    assert ep._txt("example.com") == expected and ep._mx("example.com") == expected


# ---- DNS depth -----------------------------------------------------------------

def test_caa_parsing():
    c = parse_caa(['0 issue "letsencrypt.org"', '0 issuewild ";"', '0 iodef "mailto:sec@example.com"', "garbage"])
    assert c == {"issue": ["letsencrypt.org"], "issuewild": [";"], "iodef": ["mailto:sec@example.com"]}


# ---- takeover candidates ---------------------------------------------------------

@pytest.mark.parametrize("cname,service", [
    ("myorg.github.io", "GitHub Pages"), ("app-123.herokuapp.com.", "Heroku"), ("bucket.s3.amazonaws.com", "Amazon S3"),
    ("site.s3-website-us-east-1.amazonaws.com", "Amazon S3 website"), ("x.azurewebsites.net", "Azure App Service"),
    ("shop.myshopify.com", "Shopify"), ("cdn.example.net", None), ("notgithub.io.example.com", None), ("evilgithub.io", None),
])
def test_takeover_service_matching(cname, service):
    assert tk.match_service(cname) == service


def test_takeover_only_checks_hosts_under_the_domain(monkeypatch):
    seen = []

    def fake_check(host):
        seen.append(host)
        return {"host": host, "cname": "gone.github.io", "service": "GitHub Pages", "status": "dangling" if host.startswith("old") else "pointing"}

    monkeypatch.setattr(tk, "_check", fake_check)
    out = asyncio.run(tk.run_takeover("example.com", ["blog.example.com", "OLD.example.com.", "evil.com", "example.com.evil.net", "blog.example.com"]))
    assert sorted(seen) == ["blog.example.com", "old.example.com"]
    assert out["checked"] == 2 and out["dangling"] == 1
    assert out["candidates"][0]["host"] == "old.example.com"      # dangling first


SERVFAIL = dns.resolver.NoNameservers()       # what dnspython raises when every server answers SERVFAIL
TIMEOUT = dns.exception.Timeout()
NXDOMAIN = dns.resolver.NXDOMAIN()
GOOGLE, CLOUDFLARE = tk.RESOLVER_SETS


def use_resolvers(monkeypatch, first, second=None):
    """Give each of the two resolver sets its own canned answers and record who was asked."""
    asked = []

    def make(nameservers):
        asked.append(nameservers[0])
        return FakeDns(first if nameservers == GOOGLE else (second if second is not None else first))

    monkeypatch.setattr(tk, "_resolver", make)
    return asked


def test_resolution_state_resolving_name(monkeypatch):
    asked = use_resolvers(monkeypatch, {("live.example.com", "A"): ["192.0.2.1"]})
    assert tk.resolution_state("live.example.com") == "resolves" and asked == ["8.8.8.8"]
    # no A record but an AAAA: still resolves
    use_resolvers(monkeypatch, {("v6.example.com", "AAAA"): ["2001:db8::1"]})
    assert tk.resolution_state("v6.example.com") == "resolves"


def test_resolution_state_nxdomain_needs_both_resolvers(monkeypatch):
    asked = use_resolvers(monkeypatch, {"gone.example.com": NXDOMAIN})
    assert tk.resolution_state("gone.example.com") == "absent" and asked == ["8.8.8.8", "1.1.1.1"]
    # the second resolver disagrees: the name is not gone
    use_resolvers(monkeypatch, {"flaky.example.com": NXDOMAIN}, {("flaky.example.com", "A"): ["192.0.2.1"]})
    assert tk.resolution_state("flaky.example.com") == "resolves"
    # the second resolver fails: nothing definite
    use_resolvers(monkeypatch, {"flaky.example.com": NXDOMAIN}, {"flaky.example.com": TIMEOUT})
    assert tk.resolution_state("flaky.example.com") == "unknown"


def test_resolution_state_empty_answer_for_every_type_is_absent(monkeypatch):
    use_resolvers(monkeypatch, {})                         # NoAnswer for A, AAAA and CNAME
    assert tk.resolution_state("empty.example.com") == "absent"


@pytest.mark.parametrize("error", [TIMEOUT, SERVFAIL, dns.resolver.LifetimeTimeout(), OSError("network down")])
def test_resolution_state_errors_are_unknown_not_absent(monkeypatch, error):
    use_resolvers(monkeypatch, {"x.example.com": error})
    assert tk.resolution_state("x.example.com") == "unknown"
    # one failed type among empty answers is still not a definite "absent"
    use_resolvers(monkeypatch, {("x.example.com", "AAAA"): error})
    assert tk.resolution_state("x.example.com") == "unknown"


@pytest.mark.parametrize("target_answer,status", [
    ({"gone.herokuapp.com": NXDOMAIN}, "dangling"),
    ({("gone.herokuapp.com", "A"): ["192.0.2.5"]}, "pointing"),
    ({"gone.herokuapp.com": TIMEOUT}, "unknown"),
    ({"gone.herokuapp.com": SERVFAIL}, "unknown"),
])
def test_takeover_check_with_a_mocked_resolver(monkeypatch, target_answer, status):
    use_resolvers(monkeypatch, {("app.example.com", "CNAME"): ["gone.herokuapp.com."], **target_answer})
    assert tk._check("app.example.com") == {"host": "app.example.com", "cname": "gone.herokuapp.com", "service": "Heroku", "status": status}


def test_takeover_cname_lookup_failure_is_not_a_clean_host(monkeypatch):
    use_resolvers(monkeypatch, {("a.example.com", "CNAME"): TIMEOUT, ("b.example.com", "CNAME"): NXDOMAIN, ("c.example.com", "CNAME"): ["cdn.example.net."],
                                ("d.example.com", "CNAME"): ["old.github.io."], "old.github.io": SERVFAIL})
    assert tk._check("a.example.com") == {"host": "a.example.com", "status": "unknown"}
    assert tk._check("b.example.com") is None and tk._check("c.example.com") is None
    out = asyncio.run(tk.run_takeover("example.com", ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]))
    assert out["checked"] == 3 and out["unchecked"] == ["a.example.com"] and out["dangling"] == 0 and out["unknown"] == 1
    assert out["candidates"] == [{"host": "d.example.com", "cname": "old.github.io", "service": "GitHub Pages", "status": "unknown"}]


def test_darkwire_takeover_recording_has_no_candidates(monkeypatch):
    before = fixture("darkwire.takeover.json")
    use_resolvers(monkeypatch, {})                          # none of the three hosts has a CNAME to a claimable service
    out = asyncio.run(tk.run_takeover("darkwire.tech", ["www.darkwire.tech", "api.darkwire.tech", "darkwire.tech"]))
    assert {k: out[k] for k in before} == before and out["unchecked"] == []


# ---- certified names that "no longer resolve" ---------------------------------------------

def test_darkwire_apex_was_reported_as_not_resolving():
    before = fixture("darkwire.subdomains.json")
    assert before["ct_summary"]["not_resolving"] == ["darkwire.tech"]       # the false claim from the audit
    assert fixture("darkwire.dns.json")["records"]["A"] == ["216.198.79.1"]  # while DNS answered for it


def test_not_resolving_is_rechecked_before_it_is_reported(monkeypatch):
    from routers import recon_infra as ri
    states = {"darkwire.tech": "resolves", "old.darkwire.tech": "absent", "vpn.darkwire.tech": "unknown"}
    monkeypatch.setattr(ri, "resolution_state", lambda name: states[name])
    result = fixture("darkwire.subdomains.json")
    result["ct_summary"]["not_resolving"] = ["darkwire.tech", "old.darkwire.tech", "vpn.darkwire.tech"]
    out = asyncio.run(ri.confirm_not_resolving(result))
    assert out["ct_summary"]["not_resolving"] == ["old.darkwire.tech"]
    assert out["ct_summary"]["resolution_unknown"] == ["vpn.darkwire.tech"]
    # nothing to recheck: the result passes through untouched
    assert asyncio.run(ri.confirm_not_resolving({"ct_summary": None})) == {"ct_summary": None}


def test_subdomains_route_drops_the_false_apex_claim(monkeypatch):
    from routers import recon_infra as ri

    async def fake_run(domain):
        return fixture("darkwire.subdomains.json")

    monkeypatch.setattr(ri, "run_subdomains", fake_run)
    monkeypatch.setattr(ri, "resolution_state", lambda name: "resolves")
    with TestClient(app) as c:
        body = c.post("/api/infra/subdomains", json={"domain": "darkwire.tech"}, headers={"x-forwarded-for": "198.51.100.65"}).json()
    assert body["ct_summary"]["not_resolving"] == [] and body["ct_summary"]["resolution_unknown"] == []
    assert body["total"] == 2 and body["ct_summary"]["total"] == 6


# ---- lookalike domains -------------------------------------------------------------

def test_lookalike_generation():
    c = la.generate("www.paypal.com")
    assert "paypal.com" not in c                                   # never the domain itself
    assert c["paypa1.com"] == "lookalike character" and c["paypal.net"] == "different ending"
    assert c["papal.com"] == "missing letter" and c["payapl.com"] == "swapped letters"
    assert c["paypal-login.com"] == "added word"
    assert len(c) <= la.MAX_CANDIDATES
    assert all(not d.startswith("-") and ".." not in d and " " not in d for d in c)


def test_lookalike_generation_keeps_multi_part_suffixes():
    c = la.generate("shop.example.co.uk")
    assert "exampl.co.uk" in c and all(d.endswith(".co.uk") or kind == "different ending" for d, kind in c.items())


def test_lookalikes_report_only_registered_names(monkeypatch):
    registered = {"exampl.com": {"domain": "exampl.com", "ips": ["192.0.2.1"], "nameservers": ["ns1.x.net"], "mail": False},
                  "example.net": {"domain": "example.net", "ips": [], "nameservers": ["ns.y.net"], "mail": True}}
    monkeypatch.setattr(la, "_lookup", lambda c: registered.get(c))
    out = asyncio.run(la.run_lookalikes("example.com"))
    assert out["registered"] == 2 and out["with_mail"] == 1 and out["checked"] > 50
    assert [r["domain"] for r in out["results"]] == ["example.net", "exampl.com"]     # mail-capable first
    assert out["results"][1]["technique"] == "missing letter"


# ---- well-known files ----------------------------------------------------------------

def test_murmur3_matches_reference_vectors():
    # reference values from the MurmurHash3 x86_32 test suite, as signed 32-bit integers
    assert wk.murmur3_32(b"") == 0
    assert wk.murmur3_32(b"hello") == 613153351
    assert wk.murmur3_32(b"The quick brown fox jumps over the lazy dog") == 776992547
    assert wk.murmur3_32(b"abc") == -1277324294


def test_favicon_hash_uses_shodan_base64_form():
    data = bytes(range(256)) * 3
    assert wk.favicon_hash(data) == wk.murmur3_32(base64.encodebytes(data))
    assert b"\n" in base64.encodebytes(data)


def test_security_txt_and_robots_parsing():
    st = wk.parse_security_txt("# comment\nContact: mailto:sec@example.com\nContact: https://example.com/report\nExpires: 2027-01-01T00:00:00Z\nUnknown: x\n")
    assert st == {"contact": ["mailto:sec@example.com", "https://example.com/report"], "expires": ["2027-01-01T00:00:00Z"]}
    rb = wk.parse_robots("User-agent: *\nDisallow: /admin/\nDisallow: /blog/drafts # note\nDisallow: /\nDisallow: /backup.zip\nSitemap: https://example.com/sitemap.xml\n")
    assert rb["disallow_count"] == 3 and rb["interesting"] == ["/admin/", "/backup.zip"]
    assert rb["sitemaps"] == ["https://example.com/sitemap.xml"]


def test_wellknown_goes_through_the_outbound_guard():
    out = asyncio.run(wk.run_wellknown("127.0.0.1"))
    assert out["error_code"] == "blocked_target" and not out["found"]


def test_wellknown_ignores_html_served_for_missing_files(monkeypatch):
    async def fake_fetch(client, url, **kw):
        class Got:
            response = httpx.Response(200, text="<!doctype html><html><body>Contact: us</body></html>")
        return Got()

    monkeypatch.setattr(wk, "safe_fetch", fake_fetch)
    out = asyncio.run(wk.run_wellknown("example.com"))
    assert out["security_txt"] is None and out["robots"] is None and out["favicon"] is None and out["found"] is False


# ---- certificate timeline and shared crt.sh ---------------------------------------------

def test_certificate_summary():
    entries = [
        {"subdomain": "www.example.com", "issuer": "R3", "date": "2021-03-01", "not_after": "2021-05-30", "wildcard": False},
        {"subdomain": "old.example.com", "issuer": "R3", "date": "2022-06-01", "not_after": "2022-08-30", "wildcard": False},
        {"subdomain": "example.com", "issuer": "E5", "date": "2026-10-01", "not_after": "2026-12-30", "wildcard": True},
    ]
    s = summarize_certificates(entries, {"www.example.com", "example.com"}, today="2026-11-13")
    assert (s["total"], s["active"], s["expired"], s["wildcards"]) == (3, 1, 2, 1)
    assert (s["first_issued"], s["last_issued"]) == ("2021-03-01", "2026-10-01")
    assert s["issuers"][0] == {"name": "R3", "count": 2}
    assert s["by_year"] == [{"year": "2021", "count": 1}, {"year": "2022", "count": 1}, {"year": "2026", "count": 1}]
    assert s["not_resolving"] == ["old.example.com"]
    assert s["first_seen"] == [{"name": "www.example.com", "date": "2021-03-01"}, {"name": "old.example.com", "date": "2022-06-01"}, {"name": "example.com", "date": "2026-10-01"}]
    # the earliest certificate wins when a name was certified more than once
    again = summarize_certificates(entries + [{"subdomain": "example.com", "issuer": "E5", "date": "2019-01-05", "not_after": "2019-04-05", "wildcard": False}], set(), today="2026-11-13")
    assert again["first_seen"][0] == {"name": "example.com", "date": "2019-01-05"}
    assert summarize_certificates([], set()) is None


def test_crtsh_is_fetched_once_for_concurrent_callers(monkeypatch):
    crtsh.clear_cache_for_tests()
    calls = []

    async def fake_fetch(domain):
        calls.append(domain)
        await asyncio.sleep(0.05)
        return [{"name_value": "a.example.com"}]

    monkeypatch.setattr(crtsh, "_fetch", fake_fetch)

    async def main():
        a, b = await asyncio.gather(crtsh.fetch_crtsh("example.com"), crtsh.fetch_crtsh("EXAMPLE.com."))
        c = await crtsh.fetch_crtsh("example.com")      # served from the short cache
        return a, b, c

    a, b, c = asyncio.run(main())
    assert a == b == c and calls == ["example.com"]
    crtsh.clear_cache_for_tests()


def test_crtsh_failure_reaches_every_waiter_and_is_not_cached(monkeypatch):
    crtsh.clear_cache_for_tests()
    calls = []

    async def boom(domain):
        calls.append(1)
        await asyncio.sleep(0.02)
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(crtsh, "_fetch", boom)

    async def main():
        return await asyncio.gather(crtsh.fetch_crtsh("example.com"), crtsh.fetch_crtsh("example.com"), return_exceptions=True)

    r = asyncio.run(main())
    assert all(isinstance(x, httpx.ReadTimeout) for x in r) and len(calls) == 1
    with pytest.raises(httpx.ReadTimeout):
        asyncio.run(crtsh.fetch_crtsh("example.com"))
    assert len(calls) == 2
    crtsh.clear_cache_for_tests()


# ---- archived paths ------------------------------------------------------------------------

def test_interesting_archived_paths():
    urls = ["http://example.com/", "https://example.com/wp-admin/install.php", "https://example.com/assets/app.js", "https://example.com/db-backup.sql",
            "https://example.com/.env", "https://example.com/api/v2/users", "https://example.com/about", "https://example.com/phpinfo.php",
            "https://example.com/export.csv", "https://example.com/wp-admin/install.php?x=1"]
    g = interesting_paths(urls)
    assert g["Admin and login"] == ["example.com/wp-admin/install.php"]
    assert g["Backups and dumps"] == ["example.com/db-backup.sql"] and g["Config and secrets"] == ["example.com/.env"]
    assert g["APIs"] == ["example.com/api/v2/users"] and g["Debug and internal"] == ["example.com/phpinfo.php"]
    assert g["Data files"] == ["example.com/export.csv"]
    assert not any("about" in p or "app.js" in p for v in g.values() for p in v)


# ---- routes -----------------------------------------------------------------------------------

@pytest.mark.parametrize("path,body", [
    ("/api/infra/email-posture", {"domain": "8.8.8.8"}),
    ("/api/infra/dns-depth", {"domain": "not a domain"}),
    ("/api/infra/lookalikes", {"domain": "localhost"}),
    ("/api/infra/takeover", {"domain": "exa mple.com", "hosts": []}),
    ("/api/infra/wellknown", {"domain": "a.com; id"}),
])
def test_new_routes_validate_input(path, body):
    with TestClient(app) as c:
        assert c.post(path, json=body, headers={"x-forwarded-for": "198.51.100.40"}).status_code == 400, path


def test_new_routes_are_rate_limited():
    from middleware.rate_limit import match_limit
    assert match_limit("/api/infra/lookalikes")[0] == "/api/infra/lookalikes"
    assert match_limit("/api/infra/takeover")[0] == "/api/infra/takeover"
    for p in ("/api/infra/email-posture", "/api/infra/dns-depth", "/api/infra/wellknown"):
        assert match_limit(p) is not None


def test_recon_ai_prompt_includes_new_checks_only_when_they_succeeded(monkeypatch):
    from modules import ai_provider
    captured = {}

    async def fake(api_key, messages, max_tokens, model):
        captured["p"] = messages[0]["content"]
        return {"text": '{"short_summary": [], "full_report": "r"}', "model": "m", "input_tokens": 1, "output_tokens": 1}

    monkeypatch.setattr(ai_provider, "_call_anthropic", fake)
    ai_provider.clear_cache_for_tests()
    body = {"target": "example.com",
            "email_posture": {"grade": "F", "spoofable": "yes", "findings": [{"level": "flag", "title": "No DMARC record", "detail": ""}]},
            "takeover": {"candidates": [{"host": "old.example.com", "cname": "gone.github.io", "service": "GitHub Pages", "status": "dangling"}]},
            "lookalikes": {"error": "The source took too long to answer.", "error_code": "timeout", "results": [{"domain": "exampl.com"}]},
            "wellknown": {"found": True, "security_txt": None, "robots": {"interesting": ["/admin/"]}}}
    with TestClient(app) as c:
        assert c.post("/api/infra/summarize", json=body, headers={"x-api-key": "k", "x-forwarded-for": "198.51.100.41"}).status_code == 200
    p = captured["p"]
    assert "Email security: grade F, spoofable: yes. Issues: No DMARC record" in p
    assert "old.example.com -> gone.github.io (GitHub Pages, dangling)" in p
    assert "No security.txt published" in p and "robots.txt disallows: /admin/" in p
    assert "exampl.com" not in p            # the lookalike check failed, so its data is not used


def test_recon_prompt_treats_no_mail_and_unknown_lookups_honestly():
    from routers.recon_infra import ReconAnalyzeRequest, extra_recon_lines
    req = ReconAnalyzeRequest(
        target="darkwire.tech",
        email_posture=ep.assess([], [], [], [], "", "", ""),
        takeover={"candidates": [{"host": "a.example.com", "cname": "x.github.io", "service": "GitHub Pages", "status": "unknown"}]})
    lines = "\n".join(extra_recon_lines(req))
    assert "no MX records" in lines and "not a finding" in lines and "grade" not in lines
    assert "takeover" not in lines            # a lookup that failed is not a candidate


def test_recon_prompt_skips_a_dangling_candidate_that_resolves_elsewhere():
    from routers.recon_infra import ReconAnalyzeRequest, extra_recon_lines, resolving_hosts
    row = lambda host: {"host": host, "cname": "gone.herokuapp.com", "service": "Heroku", "status": "dangling"}
    req = ReconAnalyzeRequest(
        target="darkwire.tech",
        dns=fixture("darkwire.dns.json"),
        subdomains=fixture("darkwire.subdomains.json"),
        takeover={"candidates": [row("darkwire.tech"), row("WWW.darkwire.tech."), row("old.darkwire.tech"),
                                 {"host": "api.darkwire.tech", "cname": "x.github.io", "service": "GitHub Pages", "status": "pointing"}]})
    assert resolving_hosts(req) == {"darkwire.tech", "www.darkwire.tech", "api.darkwire.tech"}
    lines = "\n".join(extra_recon_lines(req))
    assert "old.darkwire.tech -> gone.herokuapp.com (Heroku, dangling)" in lines        # nothing contradicts this one
    assert "api.darkwire.tech -> x.github.io (GitHub Pages, pointing)" in lines         # pointing rows are not claims of absence
    assert "darkwire.tech -> gone" not in lines.replace("old.darkwire.tech", "") and "www.darkwire.tech ->" not in lines.lower()
    # a failed DNS or subdomain check is not evidence that a name resolves
    failed = ReconAnalyzeRequest(target="darkwire.tech", dns={"error": "x", "records": {"A": ["1.2.3.4"]}}, takeover={"candidates": [row("darkwire.tech")]})
    assert resolving_hosts(failed) == set() and "darkwire.tech -> gone.herokuapp.com" in "\n".join(extra_recon_lines(failed))
    # every candidate withheld: no takeover line at all
    only = ReconAnalyzeRequest(target="darkwire.tech", dns=fixture("darkwire.dns.json"), takeover={"candidates": [row("darkwire.tech")]})
    assert "takeover" not in "\n".join(extra_recon_lines(only))


def test_not_resolving_recheck_is_bounded_and_uses_the_dns_pool(monkeypatch):
    from routers import recon_infra as ri
    looked_up, pooled = [], []

    async def fake_pool(fn, *args):
        pooled.append(fn)
        return fn(*args)

    monkeypatch.setattr(ri, "dns_thread", fake_pool)
    monkeypatch.setattr(ri, "resolution_state", lambda name: looked_up.append(name) or "absent")
    names = [f"h{i}.example.com" for i in range(ri.MAX_RECHECK + 25)]
    out = asyncio.run(ri.confirm_not_resolving({"ct_summary": {"not_resolving": list(names)}}))
    assert len(looked_up) == ri.MAX_RECHECK == 60 and len(pooled) == 60 and all(fn is ri.resolution_state for fn in pooled)
    assert out["ct_summary"]["not_resolving"] == names[:60]
    assert out["ct_summary"]["resolution_unknown"] == names[60:]        # not looked up, so not called gone
