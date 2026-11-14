import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from core import validate as v
from main import app


@pytest.mark.parametrize("good", ["torvalds", "john.smith", "a", "user_name-1", "x" * 64, "@jdoe"])
def test_username_accepts(good):
    assert v.username(good) == good.lstrip("@")


@pytest.mark.parametrize("bad", [
    "", " ", "--proxy", "--proxy=http://evil", "-x", "a b", "a/b", "..\\..\\x", "../../etc/passwd", "x" * 65,
    "name;rm -rf", "a\nb", "$(id)", "`id`", "tèst", "a@b.com",
])
def test_username_rejects(bad):
    with pytest.raises(HTTPException) as e:
        v.username(bad)
    assert e.value.status_code == 400


@pytest.mark.parametrize("good", ["a@b.co", "first.last+tag@sub.example.com", "x_y%z@example.museum"])
def test_email_accepts(good):
    assert v.email(good) == good


@pytest.mark.parametrize("bad", [
    "", "a@", "@b.com", "a@b", "a b@c.com", "--output=x@y.com", "a@b..com", "a@-b.com", "a@b.c", "a@@b.com",
    "x" * 65 + "@b.com", "a@b.com --proxy x", "a@b.com\nx",
])
def test_email_rejects(bad):
    with pytest.raises(HTTPException):
        v.email(bad)


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"), ("https://example.com/path?q=1", "example.com"), ("example.com.", "example.com"),
    ("example.com:8443", "example.com"), ("sub.example.co.uk", "sub.example.co.uk"), ("8.8.8.8", "8.8.8.8"),
    ("_dmarc.example.com", "_dmarc.example.com"), ("[2606:4700:4700::1111]", "2606:4700:4700::1111"),
])
def test_host_normalizes(raw, expected):
    assert v.host(raw) == expected


@pytest.mark.parametrize("bad", ["", "nodots", "exa mple.com", "-a.com", "a..com", "a.com;id", "http://", "*.example.com", "a" * 300 + ".com"])
def test_host_rejects(bad):
    with pytest.raises(HTTPException):
        v.host(bad)


def test_host_can_refuse_ips():
    with pytest.raises(HTTPException):
        v.host("8.8.8.8", allow_ip=False)


def test_http_url():
    assert v.http_url("example.com/a") == "https://example.com/a"
    assert v.http_url("http://example.com") == "http://example.com"
    for bad in ("https://user:pw@example.com", "https://", "javascript:alert(1)"):
        with pytest.raises(HTTPException):
            v.http_url(bad)


@pytest.mark.parametrize("host,reg", [
    ("example.com", "example.com"), ("a.b.example.com", "example.com"), ("www.example.co.uk", "example.co.uk"),
    ("example.co.uk", "example.co.uk"), ("8.8.8.8", "8.8.8.8"), ("EXAMPLE.com.", "example.com"),
])
def test_registrable_domain(host, reg):
    assert v.registrable_domain(host) == reg


def test_same_site_is_not_substring_matching():
    assert v.same_site("a.com", "www.a.com")
    assert not v.same_site("a.com", "evila.com")       # a suffix match is not the same site
    assert not v.same_site("a.com", "a.com.evil.net")
    assert not v.same_site("shop.co.uk", "evil.co.uk")
    assert not v.same_site("", "a.com")


def test_redirect_chain_clean_flag():
    from modules.redirect_chain import is_clean_chain
    assert is_clean_chain("https://a.com", "https://www.a.com/home")
    assert not is_clean_chain("https://a.com", "https://evila.com/")
    assert not is_clean_chain("https://a.com", "http://a.com/")       # https to http downgrade
    assert is_clean_chain("http://a.com", "https://a.com/")
    assert not is_clean_chain("https://a.com", "")


# ---- argument injection in the subprocess tools ------------------------------

@pytest.mark.parametrize("module,func,kwargs,tool", [
    ("modules.sherlock", "_run_sherlock_impl", {"username": "jdoe"}, "sherlock"),
    ("modules.maigret_mod", "_run_maigret_impl", {"username": "jdoe"}, "maigret"),
    ("modules.holehe", "_run_holehe_impl", {"email": "j@example.com"}, "holehe"),
])
def test_user_input_comes_after_double_dash(monkeypatch, module, func, kwargs, tool):
    import importlib
    mod = importlib.import_module(module)
    seen = {}

    class Proc:
        returncode = 0
        async def communicate(self): return b"", b""

    async def fake_exec(*argv, **kw):
        seen["argv"] = list(argv)
        return Proc()

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", fake_exec)
    if tool == "maigret":
        monkeypatch.setattr(mod, "MAIGRET_AVAILABLE", True)
    asyncio.run(getattr(mod, func)(**kwargs))
    argv = seen["argv"]
    value = next(iter(kwargs.values()))
    assert argv[0] == tool and argv[-2:] == ["--", value]
    assert argv.index("--") == len(argv) - 2          # nothing user-controlled before the separator


def test_missing_tool_binary_is_reported_not_a_500(monkeypatch):
    import modules.sherlock as sh

    async def missing(*a, **k):
        raise FileNotFoundError("sherlock")

    monkeypatch.setattr(sh.asyncio, "create_subprocess_exec", missing)
    out = asyncio.run(sh._run_sherlock_impl("jdoe"))
    assert out["error_code"] == "not_installed" and out["results"] == []


@pytest.mark.parametrize("path,body", [
    ("/api/recon/sherlock", {"username": "--proxy=http://evil"}),
    ("/api/recon/maigret", {"username": "-J"}),
    ("/api/recon/holehe", {"email": "--only-used"}),
    ("/api/recon/hibp", {"email": "a@b"}),
    ("/api/recon/harvester", {"domain": "exa mple.com"}),
    ("/api/infra/dns", {"domain": "8.8.8.8"}),
    ("/api/infra/portscan", {"domain": "a.com; id"}),
    ("/api/infra/redirects", {"target": "https://user:pw@example.com"}),
])
def test_routes_reject_bad_input_with_400(path, body):
    with TestClient(app) as c:
        r = c.post(path, json=body, headers={"x-forwarded-for": "198.51.100.10"})
        assert r.status_code == 400, (path, r.text)


@pytest.mark.parametrize("path,body", [
    ("/api/recon/sherlock", {"username": "x" * 400}),
    ("/api/infra/dns", {"domain": "a" * 400 + ".com"}),
    ("/api/hash/hash", {"hash": "a" * 200}),
    ("/api/email/analyze", {"headers": "x" * 200_001}),
    ("/api/recon/scrape-profiles", {"urls": [{"site": "s", "url": "https://example.com"}] * 21}),
    ("/api/analyze/summarize", {"target": "x" * 400}),
])
def test_request_fields_have_length_limits(path, body):
    with TestClient(app) as c:
        assert c.post(path, json=body, headers={"x-forwarded-for": "198.51.100.11"}).status_code == 422, path


def test_oversized_body_is_refused():
    with TestClient(app) as c:
        r = c.post("/api/analyze/summarize", content=b"{" + b" " * (3 * 1024 * 1024) + b"}", headers={"content-type": "application/json", "x-forwarded-for": "198.51.100.12"})
        assert r.status_code == 413
