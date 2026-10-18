import asyncio

from modules import harvester as hv


D = "example.com"


def test_parsers_keep_only_in_scope_hosts():
    assert hv.parse_crtsh([{"name_value": "*.example.com\nwww.example.com\nevil.com"}], D) == {"example.com", "www.example.com"}
    assert hv.parse_certspotter([{"dns_names": ["api.example.com", "example.com.evil.net"]}], D) == {"api.example.com"}
    assert hv.parse_hackertarget("mail.example.com,1.2.3.4\nvpn.example.com,5.6.7.8", D) == {"mail.example.com", "vpn.example.com"}
    assert hv.parse_hackertarget("API count exceeded - Increase Quota", D) == set()
    assert hv.parse_rapiddns("<td>dev.example.com</td><td>x.other.org</td>", D) == {"dev.example.com"}
    assert hv.parse_urlscan({"results": [{"page": {"domain": "shop.example.com"}, "task": {"domain": "example.com"}}]}, D) == {"shop.example.com", "example.com"}
    assert hv.parse_otx({"passive_dns": [{"hostname": "old.example.com"}, {"hostname": "cdn.akamai.net"}]}, D) == {"old.example.com"}
    assert hv.parse_anubis(["a.example.com", "b.example.com", 5], D) == {"a.example.com", "b.example.com"}


def test_wayback_extracts_hosts_and_in_domain_emails():
    rows = [["original"], ["https://blog.example.com/post?contact=jane.doe%40example.com"], ["http://x.example.com/mailto:bob@gmail.com"]]
    hosts, emails = hv.parse_wayback(rows, D)
    assert hosts == {"blog.example.com", "x.example.com"}
    assert emails == {"jane.doe@example.com"}


def test_shared_mail_domains_are_skipped():
    r = asyncio.run(hv._run_harvester_impl("someone@gmail.com"))
    assert r["skipped"] and r["hosts"] == [] and "gmail.com" in r["message"]


def test_impl_merges_sources_and_survives_failures(monkeypatch):
    async def good(c, d): return {"www.example.com", "api.example.com"}, {"a@example.com"}
    async def also(c, d): return {"api.example.com"}, set()
    async def bad(c, d): raise RuntimeError("rate limited")
    async def slow(c, d):
        await asyncio.sleep(5)
        return {"late.example.com"}, set()
    monkeypatch.setattr(hv, "SOURCES", {"One": good, "Two": also, "Broken": bad, "Slow": slow})
    r = asyncio.run(hv._run_harvester_impl("jane@example.com", timeout=0.3))
    assert r["domain"] == "example.com"
    assert r["hosts"][0] == "api.example.com"  # seen by two sources ranks first
    assert r["host_sources"]["api.example.com"] == ["One", "Two"]
    assert r["emails"] == ["a@example.com"]
    assert "error" in r["sources"]["Broken"] and r["sources"]["Slow"]["error"] == "timed out"
    assert r["total_hosts"] == 2
