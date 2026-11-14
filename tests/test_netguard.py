import asyncio
import socket

import httpx
import pytest

from core import netguard as ng
from core.netguard import BlockedTarget, is_public_ip, resolve_public, safe_fetch


def run(coro):
    return asyncio.run(coro)


def fake_dns(monkeypatch, table: dict[str, list[str]]):
    monkeypatch.setattr(ng, "_public_dns_blocking", lambda host: [])
    real_sleep = asyncio.sleep
    monkeypatch.setattr(ng.asyncio, "sleep", lambda s: real_sleep(0))
    async def getaddrinfo(self, host, port, **kw):
        if host not in table:
            raise socket.gaierror("nope")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in table[host]]
    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", getaddrinfo)


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.8.8.8", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "fd12:3456::1",
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "not-an-ip", "",
])
def test_non_public_addresses_are_rejected(ip):
    assert is_public_ip(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("host", [
    "localhost", "LOCALHOST.", "127.0.0.1", "[::1]", "169.254.169.254", "10.1.2.3",
    "api.railway.internal", "db.internal", "printer.local", "intranet", "metadata.google.internal",
])
def test_internal_names_and_literals_are_blocked_without_a_lookup(host, monkeypatch):
    fake_dns(monkeypatch, {})  # any lookup would raise gaierror, not BlockedTarget
    with pytest.raises(BlockedTarget):
        run(resolve_public(host))


def test_public_name_resolving_to_private_address_is_blocked(monkeypatch):
    fake_dns(monkeypatch, {"evil.example.com": ["127.0.0.1"], "meta.example.com": ["169.254.169.254"]})
    for host in ("evil.example.com", "meta.example.com"):
        with pytest.raises(BlockedTarget):
            run(resolve_public(host))


def test_mixed_public_and_private_answers_are_blocked(monkeypatch):
    fake_dns(monkeypatch, {"rebind.example.com": ["93.184.216.34", "10.0.0.1"]})
    with pytest.raises(BlockedTarget):
        run(resolve_public("rebind.example.com"))


def test_public_name_resolves_ipv4_first(monkeypatch):
    fake_dns(monkeypatch, {"ok.example.com": ["2606:4700:4700::1111", "93.184.216.34"]})
    assert run(resolve_public("ok.example.com")) == ["93.184.216.34", "2606:4700:4700::1111"]


def test_unresolvable_name_is_a_lookup_error_not_a_block(monkeypatch):
    fake_dns(monkeypatch, {})
    with pytest.raises(LookupError):
        run(resolve_public("nope.example.com"))


# ---- safe_fetch -------------------------------------------------------------

def client_with(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_connection_is_pinned_to_the_vetted_ip(monkeypatch):
    fake_dns(monkeypatch, {"site.example.com": ["93.184.216.34"]})
    seen = []

    def handler(request: httpx.Request):
        seen.append((str(request.url), request.headers["host"], request.extensions.get("sni_hostname")))
        return httpx.Response(200, text="hello", headers={"server": "x"})

    async def go():
        async with client_with(handler) as c:
            return await safe_fetch(c, "https://site.example.com/path?q=1")

    got = run(go())
    assert got.response.text == "hello" and got.url == "https://site.example.com/path?q=1"
    # the socket goes to the IP that was checked; Host and SNI still name the site
    assert seen == [("https://93.184.216.34/path?q=1", "site.example.com", "site.example.com")]


def test_redirect_to_internal_address_is_blocked(monkeypatch):
    fake_dns(monkeypatch, {"site.example.com": ["93.184.216.34"]})
    calls = []

    def handler(request: httpx.Request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    async def go():
        async with client_with(handler) as c:
            return await safe_fetch(c, "https://site.example.com/")

    with pytest.raises(BlockedTarget):
        run(go())
    assert calls == ["https://93.184.216.34/"]   # the metadata address was never contacted


@pytest.mark.parametrize("location", [
    "http://127.0.0.1:8000/api/health", "http://localhost/", "http://[::1]/", "https://app.railway.internal/",
    "http://internal.example.com/", "file:///etc/passwd", "gopher://93.184.216.34/",
])
def test_every_redirect_hop_is_rechecked(monkeypatch, location):
    fake_dns(monkeypatch, {"site.example.com": ["93.184.216.34"], "hop.example.com": ["1.1.1.1"], "internal.example.com": ["10.0.0.9"]})

    def handler(request: httpx.Request):
        if request.headers["host"] == "site.example.com":
            return httpx.Response(301, headers={"location": "https://hop.example.com/next"})
        return httpx.Response(302, headers={"location": location})

    async def go():
        async with client_with(handler) as c:
            return await safe_fetch(c, "https://site.example.com/")

    with pytest.raises(BlockedTarget):
        run(go())


def test_redirects_are_followed_and_recorded(monkeypatch):
    fake_dns(monkeypatch, {"a.example.com": ["93.184.216.34"], "b.example.org": ["1.1.1.1"]})

    def handler(request: httpx.Request):
        if request.headers["host"] == "a.example.com":
            return httpx.Response(301, headers={"location": "https://b.example.org/landing"})
        return httpx.Response(200, text="done")

    async def go():
        async with client_with(handler) as c:
            return await safe_fetch(c, "https://a.example.com/")

    got = run(go())
    assert got.url == "https://b.example.org/landing"
    assert [(h["url"], h["status_code"], h["ip"]) for h in got.hops] == [
        ("https://a.example.com/", 301, "93.184.216.34"), ("https://b.example.org/landing", 200, "1.1.1.1")]


def test_redirect_loops_stop(monkeypatch):
    fake_dns(monkeypatch, {"loop.example.com": ["93.184.216.34"]})

    async def go():
        async with client_with(lambda r: httpx.Response(302, headers={"location": "/again"})) as c:
            return await safe_fetch(c, "https://loop.example.com/", max_redirects=3)

    with pytest.raises(httpx.TooManyRedirects):
        run(go())


def test_urls_with_credentials_or_other_schemes_are_refused():
    async def go(url):
        async with client_with(lambda r: httpx.Response(200)) as c:
            return await safe_fetch(c, url)

    for url in ("ftp://93.184.216.34/", "https://user:pw@93.184.216.34/", "http://"):
        with pytest.raises(BlockedTarget):
            run(go(url))


# ---- the modules that use the guard ---------------------------------------

@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "localhost"])
def test_modules_refuse_internal_targets(target, monkeypatch):
    from modules.headers_check import run_headers
    from modules.port_scan import run_portscan
    from modules.profile_scraper import scrape_profiles
    from modules.redirect_chain import run_redirect_chain
    from modules.ssl_check import run_ssl
    from modules.tech_fingerprint import run_tech_fingerprint
    import modules.port_scan as ps
    import modules.resolver as resolver

    # resolver falls back to public DNS for names; make "localhost" resolve the way a hostile name would
    monkeypatch.setattr(resolver, "_resolve_blocking", lambda d: "127.0.0.1")
    touched = []
    monkeypatch.setattr(ps, "_check_port", lambda *a, **k: touched.append(a) or False)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: touched.append(a) or (_ for _ in ()).throw(AssertionError("connected")))

    for coro in (run_headers(target), run_tech_fingerprint(target), run_redirect_chain(target), run_portscan(target), run_ssl(target)):
        out = run(coro)
        assert out.get("error_code") in ("blocked_target",), (target, out)
        assert not out.get("found")
    scraped = run(scrape_profiles([{"site": "x", "url": f"http://{target}:8000/api/health"}]))
    assert scraped[0]["error_code"] == "blocked_target" and "display_name" not in scraped[0]
    assert touched == []


def test_ip_literal_targets_work(monkeypatch):
    """resolve_domain("1.2.3.4") used to run an A query on the string and fail."""
    from modules.resolver import resolve_domain, resolve_public_ip
    assert run(resolve_domain("8.8.8.8")) == "8.8.8.8"
    assert run(resolve_public_ip("8.8.8.8")) == "8.8.8.8"
    with pytest.raises(BlockedTarget):
        run(resolve_public_ip("192.168.0.1"))


def test_system_resolver_failure_falls_back_to_public_dns(monkeypatch):
    fake_dns(monkeypatch, {})                                        # system resolver knows nothing
    monkeypatch.setattr(ng, "_public_dns_blocking", lambda host: {"ok.example.com": ["93.184.216.34"], "bad.example.com": ["10.0.0.7"]}.get(host, []))
    assert run(resolve_public("ok.example.com")) == ["93.184.216.34"]
    with pytest.raises(BlockedTarget):                               # the fallback answer is vetted too
        run(resolve_public("bad.example.com"))
    with pytest.raises(LookupError):
        run(resolve_public("nope.example.com"))


def test_bulk_dns_uses_the_shared_bounded_pool():
    import inspect
    from core import dnspool
    from modules import dns_depth, dns_lookup, email_posture, lookalikes, subdomain_enum, takeover
    assert 1 <= dnspool.DNS_POOL_SIZE <= 64
    for mod in (dns_depth, dns_lookup, email_posture, lookalikes, subdomain_enum, takeover):
        src = inspect.getsource(mod)
        assert "dns_thread" in src and "asyncio.to_thread" not in src, mod.__name__


def test_resolution_is_retried_once(monkeypatch):
    import dns.resolver
    import modules.resolver as resolver
    import modules.whois_lookup as wl
    monkeypatch.setattr(resolver, "RETRY_PAUSE", 0)
    monkeypatch.setattr(wl, "RETRY_PAUSE", 0)
    calls = []

    def flaky(name):
        calls.append(name)
        if len(calls) == 1:
            raise dns.resolver.NXDOMAIN("blip")
        return "93.184.216.34"

    monkeypatch.setattr(resolver, "_resolve_blocking", flaky)
    assert run(resolver.resolve_domain("example.com")) == "93.184.216.34" and len(calls) == 2

    def always(name):
        raise dns.resolver.NXDOMAIN("gone")

    monkeypatch.setattr(resolver, "_resolve_blocking", always)
    with pytest.raises(dns.resolver.NXDOMAIN):                      # a real failure still fails, after one retry
        run(resolver.resolve_domain("nope.example.com"))

    tries = []

    class Record(dict):
        registrar = "R"; creation_date = "2001-01-01"; expiration_date = "2030-01-01"; updated_date = ""; name_servers = []; status = []

    def flaky_whois(domain):
        tries.append(domain)
        if len(tries) == 1:
            raise socket.gaierror(8, "nodename nor servname provided, or not known")
        return Record()

    monkeypatch.setattr(wl.whois, "whois", flaky_whois)
    out = run(wl.run_whois("example.com"))
    assert out["found"] is True and out["registrar"] == "R" and len(tries) == 2
