"""Wildcard DNS in the subdomain check. No network: the resolver is a fake zone.

The bug these tests pin down: a zone with `*.example.com` answers for every name, so the
wordlist "found" every name it guessed. A guess that only repeats the wildcard is not a host.
"""

import asyncio
import itertools
import re
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from fastapi.testclient import TestClient

from core.shared_hosting import wildcard_target
from main import app
from modules import subdomain_enum as se, takeover as tk

WORDS = se.COMMON_SUBDOMAINS
PIXIE = "pixie.porkbun.com"
PIXIE_IPS = ["207.207.210.107", "207.207.210.229"]


class Rdata:
    def __init__(self, text):
        self.text = self.target = self.exchange = text

    def __str__(self):
        return self.text


class Answer(list):
    """What dnspython returns: the records, plus the CNAME chain that led to them."""
    def __init__(self, records, cname=""):
        super().__init__(Rdata(r) for r in records)
        self.chaining_result = SimpleNamespace(cnames=[[Rdata(cname + ".")]] if cname else [])


class Zone:
    """A fake resolver. `records` maps a name to {"A": [...], "CNAME": "target", "MX": [...]}.
    `wildcards` maps a parent to the record every other name under it gets. A list of lists
    under "A" rotates: each query gets the next one. `fail(name, rtype)` raises a timeout."""
    def __init__(self, records=None, wildcards=None, fail=None):
        self.records, self.wildcards, self.fail = records or {}, wildcards or {}, fail or (lambda name, rtype: False)
        self.asked = []
        self._turn = itertools.count()

    def _record(self, name):
        if name in self.records:
            return self.records[name]
        for parent in sorted(self.wildcards, key=len, reverse=True):
            if name.endswith("." + parent):
                return self.wildcards[parent]
        return None

    def _addresses(self, rec, rtype):
        got = rec.get(rtype) or []
        return got[next(self._turn) % len(got)] if got and isinstance(got[0], list) else got

    def resolve(self, name, rtype):
        self.asked.append((name, rtype))
        if self.fail(name, rtype):
            raise dns.exception.Timeout()
        rec = self._record(name)
        if rec is None:
            raise dns.resolver.NXDOMAIN()
        if rtype == "CNAME":
            if rec.get("CNAME"):
                return Answer([rec["CNAME"] + "."])
            raise dns.resolver.NoAnswer()
        if rtype in ("A", "AAAA") and rec.get("CNAME"):
            target = self.records.get(rec["CNAME"])
            if target is None:
                raise dns.resolver.NXDOMAIN()           # the CNAME exists, its target does not
            ips = self._addresses(target, rtype)
            if not ips:
                raise dns.resolver.NoAnswer()
            return Answer(ips, cname=rec["CNAME"])
        got = self._addresses(rec, rtype) if rtype in ("A", "AAAA") else rec.get(rtype) or []
        if not got:
            raise dns.resolver.NoAnswer()
        return Answer(got)


def scan(monkeypatch, zone, domain="example.com", ct=(), states=None):
    """Run the subdomain check against a fake zone. DNS work runs inline, in order."""
    pooled = []

    async def inline(fn, *args):
        pooled.append(fn)
        return fn(*args)

    async def fake_ct(d):
        return sorted(ct), [], False

    monkeypatch.setattr(se, "dns_thread", inline)
    monkeypatch.setattr(se, "_make_resolver", lambda: zone)
    monkeypatch.setattr(se, "_query_crtsh", fake_ct)
    monkeypatch.setattr(tk, "resolution_state", lambda name: (states or {}).get(name, "unknown"))
    out = asyncio.run(se.run_subdomains(domain))
    out["_pooled"] = pooled
    return out


def names(out):
    return [r["subdomain"] for r in out["subdomains"]]


def crawlr_zone(extra=None):
    """The shape of crawlr.lol: the apex has its own address, and every other name is a
    CNAME to the registrar's parking host, whose two addresses come back in either order."""
    return Zone({"crawlr.lol": {"A": ["153.52.255.45"], "NS": ["curitiba.ns.porkbun.com.", "salvador.ns.porkbun.com."]},
                 PIXIE: {"A": [PIXIE_IPS, PIXIE_IPS[::-1]]}, **(extra or {})},
                wildcards={"crawlr.lol": {"CNAME": PIXIE}})


# ---- the probes ------------------------------------------------------------------------

def test_probe_labels_are_random_and_cannot_be_guessed():
    labels = [se.random_label(n) for n in se.PROBE_LENGTHS]
    assert [len(x) for x in labels] == [16, 20, 24] and all(re.fullmatch(r"[a-z0-9]+", x) for x in labels)
    assert len({se.random_label(20) for _ in range(50)}) == 50


def test_three_probes_of_different_lengths_run_before_the_wordlist_on_the_dns_pool(monkeypatch):
    zone = crawlr_zone()
    out = scan(monkeypatch, zone, "crawlr.lol")
    first_word = next(i for i, (name, _) in enumerate(zone.asked) if name == f"{WORDS[0]}.crawlr.lol")
    probes = list(dict.fromkeys(name for name, _ in zone.asked[:first_word]))
    assert sorted(len(p.split(".")[0]) for p in probes) == [16, 20, 24]
    assert {rtype for _, rtype in zone.asked[:first_word]} == {"CNAME", "A", "AAAA"}
    assert se._probe in out["_pooled"] and se._lookup in out["_pooled"]          # nothing ran outside the pool
    again = Zone(zone.records, zone.wildcards)
    scan(monkeypatch, again, "crawlr.lol")
    assert not set(probes) & {name for name, _ in again.asked}                   # new labels on every run


# ---- the crawlr.lol shape ---------------------------------------------------------------

def test_wildcard_cname_zone_lists_no_guessed_names(monkeypatch):
    out = scan(monkeypatch, crawlr_zone(), "crawlr.lol")
    w = out["wildcard"]
    assert out["subdomains"] == [] and out["total"] == 0 and out["checked"] == len(WORDS)
    assert (w["state"], w["probes"], w["matched"], w["name"]) == ("yes", 3, 3, "*.crawlr.lol")
    assert w["cnames"] == [PIXIE] and w["ips"] == sorted(PIXIE_IPS)
    assert w["suppressed"] == len(WORDS) and w["suppressed_names"] == [f"{s}.crawlr.lol" for s in WORDS]
    assert w["provider"] == {"name": "Porkbun", "kind": "parking or forwarding service", "basis": "cname"}
    assert (w["service"], w["target_state"], w["parents"]) == ("", "resolves", [])


def test_the_wildcard_is_one_info_finding_that_says_why_it_matters(monkeypatch):
    out = scan(monkeypatch, crawlr_zone(), "crawlr.lol")
    assert [f["level"] for f in out["findings"]] == ["info"]                     # a configuration fact, not a flag
    f = out["findings"][0]
    assert f["title"] == "Wildcard DNS: any name under crawlr.lol resolves to pixie.porkbun.com"
    assert f["detail"] == (
        f"So a name that resolves is not proof a host exists. {len(WORDS)} guessed names were left out because they only matched the wildcard. "
        "The wildcard points at Porkbun, a third-party parking or forwarding service: what answers there is Porkbun's, not a server of this domain's own.")
    assert out["wildcard"]["note"] == f"{f['title']}. {f['detail']}"
    assert chr(0x2014) not in f["title"] + f["detail"]


def test_a_real_host_in_a_wildcard_zone_is_kept(monkeypatch):
    zone = crawlr_zone({"api.crawlr.lol": {"A": ["198.51.100.7"]},                       # its own address
                        "blog.crawlr.lol": {"CNAME": "crawlr.ghost.io"}, "crawlr.ghost.io": {"A": ["198.51.100.9"]}})
    out = scan(monkeypatch, zone, "crawlr.lol")
    assert out["subdomains"] == [{"subdomain": "api.crawlr.lol", "ips": ["198.51.100.7"], "source": "DNS"},
                                 {"subdomain": "blog.crawlr.lol", "ips": ["198.51.100.9"], "source": "DNS"}]
    assert out["wildcard"]["suppressed"] == len(WORDS) - 2 and "api.crawlr.lol" not in out["wildcard"]["suppressed_names"]


def test_a_name_another_source_attests_is_kept_and_marked(monkeypatch):
    zone = crawlr_zone()
    zone.records["crawlr.lol"]["MX"] = ["mail.crawlr.lol."]
    out = scan(monkeypatch, zone, "crawlr.lol", ct=["www.crawlr.lol", "tools.crawlr.lol", "old.crawlr.lol"])
    zone_ips = sorted(PIXIE_IPS)
    rows = {r["subdomain"]: r for r in out["subdomains"]}
    assert sorted(rows) == ["mail.crawlr.lol", "old.crawlr.lol", "tools.crawlr.lol", "www.crawlr.lol"]
    # guessed and certified: listed, with both sources, and marked
    assert rows["www.crawlr.lol"]["source"] == "DNS+CT" and rows["www.crawlr.lol"]["via_wildcard"] is True
    # certified only: keeps its source, and the mark says the DNS answer proves nothing
    assert rows["tools.crawlr.lol"]["source"] == "CT" and rows["tools.crawlr.lol"]["via_wildcard"] is True
    assert sorted(rows["tools.crawlr.lol"]["ips"]) == zone_ips
    # named by the zone's own MX record
    assert rows["mail.crawlr.lol"] == {"subdomain": "mail.crawlr.lol", "ips": rows["mail.crawlr.lol"]["ips"], "source": "DNS", "via_wildcard": True, "attested": ["MX"]}
    assert out["wildcard"]["suppressed"] == len(WORDS) - 2 and out["ct_found"] == 2
    assert not {"www.crawlr.lol", "mail.crawlr.lol"} & set(out["wildcard"]["suppressed_names"])


def test_a_failed_mx_lookup_is_said_not_hidden(monkeypatch):
    zone = crawlr_zone()
    zone.fail = lambda name, rtype: rtype == "MX"
    out = scan(monkeypatch, zone, "crawlr.lol")
    assert out["wildcard"]["attest_failed"] == ["MX"]
    assert "The MX lookup failed, so a mail or name server may be among the names left out." in out["findings"][0]["detail"]


def scan_with_crtsh(monkeypatch, zone, domain, crtsh):
    """Like scan, but with the real certificate log reader on top of a fake crt.sh."""
    async def inline(fn, *args):
        return fn(*args)

    monkeypatch.setattr(se, "dns_thread", inline)
    monkeypatch.setattr(se, "_make_resolver", lambda: zone)
    monkeypatch.setattr(se, "fetch_crtsh", crtsh)
    return asyncio.run(se.run_subdomains(domain))


def test_certificate_logs_that_cannot_be_read_are_said_not_read_as_empty(monkeypatch):
    async def down(domain):
        raise RuntimeError("rate limited")

    async def up(domain):
        return [{"name_value": "www.crawlr.lol", "common_name": "www.crawlr.lol", "serial_number": "1", "issuer_name": "CN=R3", "not_before": "2026-10-01", "not_after": "2026-12-30", "id": 1}]

    caveat = "Certificate logs could not be read, so names a certificate attests may be among those left out."
    out = scan_with_crtsh(monkeypatch, crawlr_zone(), "crawlr.lol", down)
    # www is certified in fact, but without the logs it cannot be told from a guess: it is left out, and the answer says so
    assert out["wildcard"]["ct_failed"] is True and "www.crawlr.lol" in out["wildcard"]["suppressed_names"]
    assert out["findings"][0]["detail"].endswith(caveat) and out["wildcard"]["note"].endswith(caveat)
    assert [f["level"] for f in out["findings"]] == ["info"]
    # the logs answered: the certified name is kept, and there is no caveat
    ok = scan_with_crtsh(monkeypatch, crawlr_zone(), "crawlr.lol", up)
    assert "ct_failed" not in ok["wildcard"] and caveat not in ok["findings"][0]["detail"]
    assert [(r["subdomain"], r["source"], r.get("via_wildcard")) for r in ok["subdomains"]] == [("www.crawlr.lol", "DNS+CT", True)]
    # no wildcard: nothing was left out, so there is nothing to caveat
    plain = scan_with_crtsh(monkeypatch, Zone({"www.example.com": {"A": ["192.0.2.1"]}}), "example.com", down)
    assert "ct_failed" not in plain["wildcard"] and plain["findings"] == [] and names(plain) == ["www.example.com"]


# ---- no wildcard: nothing changes --------------------------------------------------------

def test_a_zone_without_a_wildcard_is_unchanged(monkeypatch):
    zone = Zone({"example.com": {"A": ["192.0.2.1"]}, "www.example.com": {"A": ["192.0.2.1"]}, "mail.example.com": {"A": ["192.0.2.25"]},
                 "shop.example.com": {"CNAME": "shops.myshopify.com"}, "shops.myshopify.com": {"A": ["23.227.38.74"]},
                 "legacy.example.com": {"A": ["192.0.2.77"]}})
    out = scan(monkeypatch, zone, ct=["www.example.com", "legacy.example.com", "gone.example.com"])
    # exactly the rows the check returned before wildcard detection existed, with no new keys
    assert out["subdomains"] == [
        {"subdomain": "www.example.com", "ips": ["192.0.2.1"], "source": "DNS+CT"},
        {"subdomain": "mail.example.com", "ips": ["192.0.2.25"], "source": "DNS"},
        {"subdomain": "shop.example.com", "ips": ["23.227.38.74"], "source": "DNS"},
        {"subdomain": "gone.example.com", "ips": [], "source": "CT"},
        {"subdomain": "legacy.example.com", "ips": ["192.0.2.77"], "source": "CT"},
    ]
    w = out["wildcard"]
    assert (w["state"], w["matched"], w["suppressed"], w["suppressed_names"], w["cnames"], w["ips"], w["note"]) == ("no", 0, 0, [], [], [], "")
    assert out["findings"] == [] and (out["total"], out["ct_found"]) == (5, 2)
    assert not any(rtype in ("MX", "NS", "SRV") for _, rtype in zone.asked)      # no extra queries without a wildcard


# ---- unknown is not "no" -----------------------------------------------------------------

def is_probe(name):
    return len(name.split(".")[0]) >= 16


def test_probes_that_time_out_give_unknown_and_nothing_is_suppressed(monkeypatch):
    zone = Zone({PIXIE: {"A": [PIXIE_IPS]}}, wildcards={"example.com": {"CNAME": PIXIE}}, fail=lambda name, rtype: is_probe(name))
    out = scan(monkeypatch, zone)
    w = out["wildcard"]
    assert (w["state"], w["matched"], w["failed"], w["suppressed"], w["cnames"], w["ips"]) == ("unknown", 0, 3, 0, [], [])
    assert len(out["subdomains"]) == len(WORDS) and not any("via_wildcard" in r for r in out["subdomains"])
    assert [(f["level"], f["title"]) for f in out["findings"]] == [("info", "Wildcard DNS could not be checked for example.com")]
    assert "unknown whether every name under this domain resolves" in out["findings"][0]["detail"]


@pytest.mark.parametrize("failing,expected", [(0, "yes"), (1, "yes"), (2, "unknown"), (3, "unknown")])
def test_two_definite_answers_are_needed_either_way(monkeypatch, failing, expected):
    seen = []

    def fail(name, rtype):
        if is_probe(name) and name not in seen:
            seen.append(name)
        return is_probe(name) and seen.index(name) < failing

    out = scan(monkeypatch, Zone({PIXIE: {"A": [PIXIE_IPS]}}, wildcards={"example.com": {"CNAME": PIXIE}}, fail=fail))
    assert out["wildcard"]["state"] == expected
    # the same failures in a zone with no wildcard: one definite "absent" is not enough for "no"
    seen.clear()
    plain = scan(monkeypatch, Zone({"www.example.com": {"A": ["192.0.2.1"]}}, fail=fail))
    assert plain["wildcard"]["state"] == ("no" if failing <= 1 else "unknown") and names(plain) == ["www.example.com"]


def test_one_failed_record_type_does_not_turn_a_missing_name_into_absent():
    zone = Zone({}, fail=lambda name, rtype: rtype == "CNAME")
    assert se._probe(zone, "nope.example.com")["state"] == "unknown"
    assert se._probe(Zone({}), "nope.example.com") == {"state": "absent", "cnames": [], "ips": []}
    # no record of any of the three types, and no error: the name exists and has no address
    assert se._probe(Zone({"txt.example.com": {"TXT": ["x"]}}), "txt.example.com")["state"] == "absent"


# ---- other wildcard shapes ---------------------------------------------------------------

def test_a_wildcard_a_record_without_a_cname(monkeypatch):
    zone = Zone({"example.com": {"A": ["192.0.2.1"]}, "vpn.example.com": {"A": ["198.51.100.20"]}}, wildcards={"example.com": {"A": ["192.0.2.10"], "AAAA": ["2001:db8::10"]}})
    out = scan(monkeypatch, zone)
    w = out["wildcard"]
    assert (w["state"], w["cnames"], w["ips"], w["provider"], w["target_state"]) == ("yes", [], ["192.0.2.10", "2001:db8::10"], None, "")
    assert names(out) == ["vpn.example.com"] and w["suppressed"] == len(WORDS) - 1
    assert out["findings"][0]["title"] == "Wildcard DNS: any name under example.com resolves to 192.0.2.10, 2001:db8::10"
    assert [f["level"] for f in out["findings"]] == ["info"]


def test_rotating_wildcard_addresses_still_match(monkeypatch):
    pool = [["192.0.2.1", "192.0.2.2"], ["192.0.2.2", "192.0.2.3"], ["192.0.2.3", "192.0.2.4"], ["192.0.2.4", "192.0.2.1"]]
    out = scan(monkeypatch, Zone({"db.example.com": {"A": ["198.51.100.5"]}}, wildcards={"example.com": {"A": pool}}))
    assert names(out) == ["db.example.com"] and out["wildcard"]["suppressed"] == len(WORDS) - 1
    assert len(out["wildcard"]["ips"]) >= 3                                       # the union over the probes
    # a CNAME wildcard whose target rotates: the CNAME match alone is enough
    cname = scan(monkeypatch, Zone({"lb.example.net": {"A": [[f"203.0.113.{i}"] for i in range(1, 200)]}}, wildcards={"example.com": {"CNAME": "lb.example.net"}}))
    assert cname["subdomains"] == [] and cname["wildcard"]["suppressed"] == len(WORDS) and cname["wildcard"]["cnames"] == ["lb.example.net"]


def test_matching_rules():
    w = {"state": "yes", "cnames": ["lb.example.net"], "ips": ["192.0.2.1", "192.0.2.2"]}
    assert se.matches_wildcard({"ips": ["203.0.113.9"], "cname": "lb.example.net"}, w)           # same CNAME, other address
    assert not se.matches_wildcard({"ips": ["192.0.2.1"], "cname": "other.example.net"}, w)      # its own CNAME
    assert se.matches_wildcard({"ips": ["192.0.2.2", "192.0.2.9"], "cname": ""}, w)              # shares an address
    assert not se.matches_wildcard({"ips": ["198.51.100.1"], "cname": ""}, w)
    assert not se.matches_wildcard({"ips": [], "cname": ""}, w)
    assert not se.matches_wildcard({"ips": ["192.0.2.1"], "cname": "lb.example.net"}, {**w, "state": "unknown"})


def test_a_second_level_wildcard_is_tested_once_for_its_parent(monkeypatch):
    kids = [f"{x}.dev.example.com" for x in ("a", "b", "c", "d")]
    zone = Zone({"www.example.com": {"A": ["192.0.2.1"]}, "dev.example.com": {"A": ["192.0.2.50"]}, "api.prod.example.com": {"A": ["192.0.2.60"]}},
                wildcards={"dev.example.com": {"A": ["203.0.113.9"]}})
    out = scan(monkeypatch, zone, ct=kids + ["api.prod.example.com"])
    rows = {r["subdomain"]: r for r in out["subdomains"]}
    assert out["wildcard"]["state"] == "no" and out["wildcard"]["suppressed"] == 0
    assert out["wildcard"]["parents"] == [{"parent": "dev.example.com", "name": "*.dev.example.com", "cnames": [], "ips": ["203.0.113.9"]}]
    assert all(rows[k] == {"subdomain": k, "ips": ["203.0.113.9"], "source": "CT", "via_wildcard": True} for k in kids)   # certified, so kept
    assert "via_wildcard" not in rows["dev.example.com"] and "via_wildcard" not in rows["api.prod.example.com"] and "via_wildcard" not in rows["www.example.com"]
    assert [(f["level"], f["title"]) for f in out["findings"]] == [("info", "Wildcard DNS: any name under dev.example.com resolves to 203.0.113.9")]
    probes = {name.split(".", 1)[1] for name, _ in zone.asked if is_probe(name)}
    assert probes == {"example.com", "dev.example.com"}                           # prod has one child: not tested


def test_extra_parents_are_capped_and_real_siblings_are_not_marked(monkeypatch):
    parents = [f"p{i}.example.com" for i in range(8)]
    ct = [f"{x}.{p}" for p in parents for x in ("a", "b", "c")]
    zone = Zone({"x.team.example.com": {"A": ["192.0.2.1"]}, "y.team.example.com": {"A": ["192.0.2.1"]}, "z.team.example.com": {"A": ["192.0.2.1"]}},
                wildcards={p: {"A": ["203.0.113.9"]} for p in parents})
    out = scan(monkeypatch, zone, ct=ct + ["x.team.example.com", "y.team.example.com", "z.team.example.com"])
    tested = {name.split(".", 1)[1] for name, _ in zone.asked if is_probe(name)} - {"example.com"}
    assert len(tested) == se.MAX_PARENT_TESTS == 5
    assert len(out["wildcard"]["parents"]) <= 5
    # three real hosts behind one address look alike, are tested when there is room, and are not a wildcard
    only = scan(monkeypatch, Zone(zone.records), ct=["x.team.example.com", "y.team.example.com", "z.team.example.com"])
    assert only["wildcard"]["parents"] == [] and not any("via_wildcard" in r for r in only["subdomains"])


# ---- the wildcard's own target, and the takeover check -------------------------------------

def test_a_dangling_wildcard_target_is_one_flag_about_the_wildcard(monkeypatch):
    zone = Zone({}, wildcards={"example.com": {"CNAME": "gone-app.herokuapp.com"}})
    out = scan(monkeypatch, zone, states={"gone-app.herokuapp.com": "absent"})
    w = out["wildcard"]
    assert (w["state"], w["cnames"], w["ips"], w["service"], w["target_state"]) == ("yes", ["gone-app.herokuapp.com"], [], "Heroku", "absent")
    assert [f["level"] for f in out["findings"]] == ["info", "flag"]
    assert out["findings"][1]["title"] == "Wildcard DNS points at gone-app.herokuapp.com (Heroku), which no longer resolves"
    assert "verify by hand" in out["findings"][1]["detail"] and out["subdomains"] == []
    # the two-resolver test could not finish: unknown, and no flag
    unsure = scan(monkeypatch, Zone({}, wildcards={"example.com": {"CNAME": "gone-app.herokuapp.com"}}), states={})
    assert unsure["wildcard"]["target_state"] == "unknown" and [f["level"] for f in unsure["findings"]] == ["info"]
    assert "could not be checked: unknown, not safe" in unsure["findings"][0]["detail"]
    # a wildcard to a claimable service that resolves is said once, on the wildcard
    live = scan(monkeypatch, Zone({"app.herokuapp.com": {"A": ["192.0.2.80"]}}, wildcards={"example.com": {"CNAME": "app.herokuapp.com"}}))
    assert [f["level"] for f in live["findings"]] == ["info"] and "The target is hosted on Heroku." in live["findings"][0]["detail"]


def test_takeover_does_not_list_hosts_that_only_repeat_the_wildcard(monkeypatch):
    answers = {("a.example.com", "CNAME"): ["app.herokuapp.com."], ("b.example.com", "CNAME"): ["app.herokuapp.com."],
               ("real.example.com", "CNAME"): ["other.github.io."], ("app.herokuapp.com", "A"): ["192.0.2.80"], "other.github.io": dns.resolver.NXDOMAIN()}

    class Fake:
        def resolve(self, name, rtype):
            got = answers.get((name, rtype), answers.get(name, dns.resolver.NoAnswer()))
            if isinstance(got, Exception):
                raise got
            return [Rdata(x) for x in got]

    monkeypatch.setattr(tk, "_resolver", lambda nameservers: Fake())
    hosts = ["a.example.com", "b.example.com", "real.example.com"]
    before = asyncio.run(tk.run_takeover("example.com", hosts))
    assert [c["host"] for c in before["candidates"]] == ["real.example.com", "a.example.com", "b.example.com"] and before["via_wildcard"] == 0
    after = asyncio.run(tk.run_takeover("example.com", hosts, ["App.Herokuapp.com."]))
    assert [(c["host"], c["status"]) for c in after["candidates"]] == [("real.example.com", "dangling")]
    assert (after["via_wildcard"], after["dangling"], after["checked"]) == (2, 1, 3)


def test_takeover_route_accepts_the_wildcard_targets(monkeypatch):
    from routers import recon_infra as ri
    got = {}

    async def fake(domain, hosts, wildcard_cnames=None):
        got.update(domain=domain, hosts=hosts, wild=wildcard_cnames)
        return {"domain": domain, "found": True, "candidates": []}

    monkeypatch.setattr(ri, "run_takeover", fake)
    with TestClient(app) as c:
        assert c.post("/api/infra/takeover", json={"domain": "example.com", "hosts": ["a.example.com"], "wildcard_cnames": ["app.herokuapp.com"]}, headers={"x-forwarded-for": "198.51.100.71"}).status_code == 200
        assert got == {"domain": "example.com", "hosts": ["a.example.com"], "wild": ["app.herokuapp.com"]}
        # an older page sends no wildcard_cnames
        assert c.post("/api/infra/takeover", json={"domain": "example.com", "hosts": ["a.example.com"]}, headers={"x-forwarded-for": "198.51.100.71"}).status_code == 200
        assert got["wild"] == []


# ---- the route and the AI prompt -------------------------------------------------------------

def test_subdomains_route_returns_the_wildcard_and_only_real_names(monkeypatch):
    async def inline(fn, *args):
        return fn(*args)

    async def no_ct(d):
        return [], [], False

    monkeypatch.setattr(se, "dns_thread", inline)
    monkeypatch.setattr(se, "_make_resolver", lambda: crawlr_zone({"api.crawlr.lol": {"A": ["198.51.100.7"]}}))
    monkeypatch.setattr(se, "_query_crtsh", no_ct)
    with TestClient(app) as c:
        body = c.post("/api/infra/subdomains", json={"domain": "crawlr.lol"}, headers={"x-forwarded-for": "198.51.100.72"}).json()
    assert [r["subdomain"] for r in body["subdomains"]] == ["api.crawlr.lol"] and body["total"] == 1
    assert body["wildcard"]["state"] == "yes" and body["wildcard"]["suppressed"] == len(WORDS) - 1
    assert {"domain", "total", "checked", "ct_found", "ct_entries", "ct_summary", "subdomains"} <= set(body)      # the old keys are all there


def wildcard_request(**over):
    from routers.recon_infra import ReconAnalyzeRequest
    subs = {"domain": "crawlr.lol", "subdomains": [{"subdomain": "api.crawlr.lol", "ips": ["198.51.100.7"], "source": "DNS"},
                                                  {"subdomain": "www.crawlr.lol", "ips": PIXIE_IPS, "source": "CT", "via_wildcard": True}],
            "wildcard": {"state": "yes", "cnames": [PIXIE], "ips": PIXIE_IPS, "probes": 3, "matched": 3, "suppressed": 90,
                         "suppressed_names": ["pop.crawlr.lol", "imap.crawlr.lol"], "provider": {"name": "Porkbun", "kind": "parking or forwarding service"}, **over}}
    return ReconAnalyzeRequest(target="crawlr.lol", subdomains=subs)


def test_the_prompt_says_there_is_a_wildcard_and_lists_only_real_names():
    from routers.recon_infra import recon_prompt, wildcard_lines
    p = recon_prompt(wildcard_request())
    assert "WILDCARD DNS: every name under crawlr.lol resolves to pixie.porkbun.com (Porkbun, a third-party parking or forwarding service)." in p
    assert "90 guessed names that only matched the wildcard were left out" in p
    assert "Subdomains found (2): api.crawlr.lol, www.crawlr.lol (resolves only through the wildcard)" in p
    assert "pop.crawlr.lol" not in p and "imap.crawlr.lol" not in p
    assert "Wildcard DNS could not be checked" in "\n".join(wildcard_lines(wildcard_request(state="unknown")))
    assert "one possible takeover that covers every name" in "\n".join(wildcard_lines(wildcard_request(service="Heroku", target_state="absent")))
    assert wildcard_lines(wildcard_request(state="no")) == []


def test_the_prompt_is_unchanged_for_results_without_a_wildcard_key():
    from routers.recon_infra import ReconAnalyzeRequest, recon_prompt, wildcard_lines
    old = ReconAnalyzeRequest(target="example.com", subdomains={"subdomains": [{"subdomain": "www.example.com", "ips": ["192.0.2.1"], "source": "DNS"}]})
    assert wildcard_lines(old) == [] and recon_prompt(old).endswith("Subdomains found (1): www.example.com") and "ildcard" not in recon_prompt(old).split("Recon data:")[1]
    for junk in ({"error": "x", "wildcard": {"state": "yes"}}, {"wildcard": "yes"}, {"wildcard": {"state": "yes", "cnames": "x", "suppressed": "many", "parents": ["x"], "provider": "p"}}):
        wildcard_lines(ReconAnalyzeRequest(target="example.com", subdomains=junk))         # a case file is outside data: never raises
    assert wildcard_lines(ReconAnalyzeRequest(target="example.com", subdomains={"error": "x", "wildcard": {"state": "yes"}})) == []


# ---- who answers behind the wildcard -----------------------------------------------------------

def test_wildcard_target_names_parking_and_hosting_services():
    assert wildcard_target(["Pixie.Porkbun.com."], PIXIE_IPS) == {"name": "Porkbun", "kind": "parking or forwarding service", "basis": "cname"}
    assert wildcard_target(["parkingpage.namecheap.com"])["name"] == "Namecheap"
    assert wildcard_target(["cname.vercel-dns.com"], []) == {"name": "Vercel", "kind": "hosting platform", "basis": "cname"}
    assert wildcard_target([], ["104.21.5.5"]) == {"name": "Cloudflare", "kind": "hosting platform", "basis": "ip_range"}
    assert wildcard_target(["lb.example.net"], ["192.0.2.1"]) is None and wildcard_target() is None
    assert wildcard_target(["notpixie.porkbun.com.example.org"]) is None
