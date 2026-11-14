"""Shared-host detection, with the darkwire.tech responses recorded on 2026-11-14. No network."""

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from core import shared_hosting as sh
from main import app
from modules import internetdb as idb, shodan_lookup

FIX = Path(__file__).parent / "fixtures" / "recon"
load = lambda name: json.loads((FIX / name).read_text())
IDB, ASN = load("darkwire.internetdb.json"), load("darkwire.asn.json")
NEIGHBORS = ["10c0b549a5d8fbfc.vercel-dns-017.com", "nail-ao.com"]


@pytest.mark.parametrize("ip,provider", [
    ("216.198.79.1", "Vercel"), ("76.76.21.21", "Vercel"), ("64.29.17.1", "Vercel"),
    ("104.21.5.9", "Cloudflare"), ("172.67.1.1", "Cloudflare"), ("151.101.1.140", "Fastly"), ("199.232.69.194", "Fastly"),
    ("185.199.108.153", "GitHub Pages"), ("185.199.111.153", "GitHub Pages"), ("75.2.60.5", "Netlify"),
])
def test_published_ranges(ip, provider):
    assert sh.shared_provider(ip=ip) == {"provider": provider, "basis": "ip_range"}


@pytest.mark.parametrize("ip", ["8.8.8.8", "153.52.255.17", "216.198.80.1", "75.2.60.6", "185.199.112.1", "not-an-ip", "", None, "2606:4700::1"])
def test_other_addresses_are_not_shared(ip):
    assert sh.shared_provider(ip=ip) is None


@pytest.mark.parametrize("cname,provider", [
    ("cname.vercel-dns.com.", "Vercel"), ("abc123.vercel-dns-017.com", "Vercel"), ("example.com.cdn.cloudflare.net", "Cloudflare"),
    ("prod.global.fastly.net", "Fastly"), ("d111111abcdef8.cloudfront.net", "CloudFront"), ("my-site.netlify.app", "Netlify"),
    ("apex-loadbalancer.netlify.com", "Netlify"), ("someone.GitHub.io", "GitHub Pages"),
])
def test_cname_suffixes(cname, provider):
    assert sh.shared_provider(ip="8.8.8.8", cnames=[cname]) == {"provider": provider, "basis": "cname"}


@pytest.mark.parametrize("cname", ["notvercel-dns.com", "vercel-dns.com.evil.net", "evilgithub.io", "vercel-dns-x.com", "cdn.example.net"])
def test_lookalike_cnames_do_not_match(cname):
    assert sh.shared_provider(cnames=[cname]) is None


def test_hostname_pattern_and_signal_order():
    assert sh.shared_provider(ip="8.8.8.8", hostnames=NEIGHBORS) == {"provider": "Vercel", "basis": "hostname_pattern"}
    assert sh.shared_provider(hostnames=["server-1-2-3-4.fra50.r.cloudfront.net"])["provider"] == "CloudFront"
    # the strongest signal wins
    assert sh.shared_provider(ip="216.198.79.1", cnames=["x.github.io"], hostnames=["a.fastly.net"], asn_org="CLOUDFLARENET")["basis"] == "ip_range"
    assert sh.shared_provider(cnames=["x.github.io"], hostnames=["a.fastly.net"], asn_org="CLOUDFLARENET") == {"provider": "GitHub Pages", "basis": "cname"}


def test_asn_is_a_weak_signal_for_cdn_only_networks():
    assert sh.shared_provider(asn_org="CLOUDFLARENET") == {"provider": "Cloudflare", "basis": "asn"}
    assert sh.shared_provider(asn_org="Fastly, Inc.") == {"provider": "Fastly", "basis": "asn"}
    for org in (ASN["org"], "AMAZON-02", "GOOGLE", "MICROSOFT-CORP-MSN-AS-BLOCK", "DIGITALOCEAN-ASN", "GITHUB", "Not Cloudflare", ""):
        assert sh.shared_provider(asn_org=org) is None, org


def test_neighbors_are_names_outside_the_target():
    names = ["darkwire.tech", "API.darkwire.tech.", "nail-ao.com", "nail-ao.com", "x.vercel-dns-017.com", ""]
    assert sh.neighbors("darkwire.tech", names) == ["nail-ao.com", "x.vercel-dns-017.com"]
    assert sh.neighbors("www.darkwire.tech", ["darkwire.tech", "other.org"]) == ["other.org"]
    # an IP has no site of its own: its hostnames are neighbors only on a known shared edge
    assert sh.neighbors("216.198.79.1", NEIGHBORS, {"provider": "Vercel", "basis": "ip_range"}) == NEIGHBORS
    assert sh.neighbors("192.0.2.7", ["mail.example.org"], None) == []


# ---- InternetDB and Shodan ---------------------------------------------------------------

def fake_client(status, body, seen=None):
    class Client:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False

        async def get(self, url, params=None):
            if seen is not None:
                seen.append(url)
            return httpx.Response(status, json=body, request=httpx.Request("GET", url))
    return Client


def run_idb(monkeypatch, target, ip, status, body, cname=""):
    async def fake_resolve(name):
        return ip

    monkeypatch.setattr(idb, "resolve_domain", fake_resolve)
    monkeypatch.setattr(idb, "_canonical_name", lambda name: cname)
    monkeypatch.setattr(idb.httpx, "AsyncClient", fake_client(status, body))
    return asyncio.run(idb.run_internetdb(target))


def test_darkwire_neighbors_on_the_vercel_edge_are_not_its_services(monkeypatch):
    upstream = {k: IDB[k] for k in ("ip", "ports", "vulns", "hostnames", "tags", "cpes")}
    out = run_idb(monkeypatch, "darkwire.tech", "216.198.79.1", 200, upstream)
    assert out["shared_host"] == {"provider": "Vercel", "basis": "ip_range"}
    assert out["neighbors"] == NEIGHBORS and out["hostnames"] == NEIGHBORS          # hostnames keeps its meaning
    assert out["ports"] == [80, 443] and "Vercel" in out["ports_note"] and "not necessarily the target's" in out["ports_note"]
    for key in IDB:                                                                  # nothing the old shape had is lost
        assert out[key] == IDB[key], key


def test_dedicated_host_has_no_shared_note(monkeypatch):
    out = run_idb(monkeypatch, "example.org", "192.0.2.10", 200, {"ip": "192.0.2.10", "ports": [22], "hostnames": ["example.org", "mail.example.org", "old.example.net"]})
    assert out["shared_host"] is None and out["ports_note"] == ""
    assert out["neighbors"] == ["old.example.net"]


def test_cname_to_a_platform_marks_the_host_shared(monkeypatch):
    out = run_idb(monkeypatch, "www.example.org", "192.0.2.10", 200, {"ip": "192.0.2.10", "ports": [443], "hostnames": []}, cname="d111111abcdef8.cloudfront.net")
    assert out["shared_host"] == {"provider": "CloudFront", "basis": "cname"} and out["neighbors"] == []


def test_ip_with_no_record_still_says_it_is_shared(monkeypatch):
    out = run_idb(monkeypatch, "76.76.21.21", "76.76.21.21", 404, {"detail": "No information available"})
    assert out["found"] is False and "error" not in out and out["shared_host"]["provider"] == "Vercel" and out["neighbors"] == []


def test_internetdb_failure_stays_a_failure(monkeypatch):
    out = run_idb(monkeypatch, "darkwire.tech", "216.198.79.1", 500, {})
    assert out["error_code"] == "upstream" and out["found"] is False


def test_internetdb_route(monkeypatch):
    async def fake_resolve(name):
        return "216.198.79.1"

    monkeypatch.setattr(idb, "resolve_domain", fake_resolve)
    monkeypatch.setattr(idb, "_canonical_name", lambda name: "")
    monkeypatch.setattr(idb.httpx, "AsyncClient", fake_client(200, {k: IDB[k] for k in ("ip", "ports", "hostnames")}))
    with TestClient(app) as c:
        body = c.post("/api/recon/internetdb", json={"target": "darkwire.tech"}, headers={"x-forwarded-for": "198.51.100.64"}).json()
    assert body["shared_host"]["provider"] == "Vercel" and body["neighbors"] == NEIGHBORS


def test_shodan_result_carries_the_same_fields(monkeypatch):
    host = {"ip_str": "104.21.5.9", "org": "Cloudflare, Inc.", "ports": [80, 443, 8443], "hostnames": ["target.example", "stranger.example"],
            "data": [{"port": 443, "transport": "tcp", "product": "cloudflare", "data": "HTTP/1.1 403"}]}
    monkeypatch.setattr(shodan_lookup.httpx, "AsyncClient", fake_client(200, host))
    out = asyncio.run(shodan_lookup.run_shodan("target.example", "test-key"))
    assert out["shared_host"] == {"provider": "Cloudflare", "basis": "ip_range"}
    assert out["neighbors"] == ["stranger.example"] and out["hostnames"] == ["target.example", "stranger.example"]
    assert "Cloudflare" in out["ports_note"] and out["total_services"] == 1

    monkeypatch.setattr(shodan_lookup.httpx, "AsyncClient", fake_client(200, {**host, "ip_str": "192.0.2.9"}))
    assert asyncio.run(shodan_lookup.run_shodan("target.example", "test-key"))["shared_host"] == {"provider": "Cloudflare", "basis": "asn"}

    monkeypatch.setattr(shodan_lookup.httpx, "AsyncClient", fake_client(401, {}))
    assert asyncio.run(shodan_lookup.run_shodan("target.example", "bad"))["error_code"] == "auth"


def test_recon_prompt_tells_the_model_the_ip_is_shared():
    from routers.recon_infra import ReconAnalyzeRequest, recon_prompt
    shodan = {**IDB, "shared_host": {"provider": "Vercel", "basis": "ip_range"}, "neighbors": NEIGHBORS}
    p = recon_prompt(ReconAnalyzeRequest(target="darkwire.tech", shodan=shodan))
    assert "shared Vercel edge" in p and "nail-ao.com" not in p
    assert "SHARED HOSTING" not in recon_prompt(ReconAnalyzeRequest(target="darkwire.tech", shodan=IDB))
