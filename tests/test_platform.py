import gzip
import re

import pytest
from fastapi.testclient import TestClient

from main import app, asset_fingerprint
from middleware.observability import CSP


@pytest.fixture(scope="module")
def c():
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("path", ["/", "/api/health", "/robots.txt", "/sitemap.xml"])
def test_head_is_allowed(c, path):
    r = c.head(path)
    assert r.status_code == 200 and r.text == ""


def test_index_references_fingerprinted_assets(c):
    html = c.get("/").text
    fp = asset_fingerprint()
    assert re.fullmatch(r"[0-9a-f]{12}", fp)
    assert f"/assets/{fp}/js/app.js" in html and f"/assets/{fp}/css/app.css" in html
    assert "/static/v2/" not in html and "{{SITE_URL}}" not in html


def test_fingerprinted_assets_are_cached_for_a_year_and_html_is_not(c):
    fp = asset_fingerprint()
    r = c.get(f"/assets/{fp}/js/app.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"]
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert c.get("/").headers["cache-control"] == "no-cache"
    # a stale fingerprint (page loaded before a deploy) still resolves
    assert c.get("/assets/000000000000/js/core.js").status_code == 200
    # misses are not cached, and the mount cannot escape static/v2
    miss = c.get(f"/assets/{fp}/js/nope.js")
    assert miss.status_code == 404 and "immutable" not in miss.headers.get("cache-control", "")
    assert c.get(f"/assets/{fp}/../../main.py").status_code == 404
    assert c.get(f"/assets/{fp}/%2e%2e/%2e%2e/main.py").status_code == 404


def test_fingerprint_changes_when_a_file_changes(tmp_path, monkeypatch):
    import main
    (tmp_path / "index.html").write_text("<script src='/static/v2/js/a.js'></script>")
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "a.js").write_text("one")
    monkeypatch.setattr(main, "UI_DIR", tmp_path)
    monkeypatch.setattr(main, "_fingerprint_cache", None)
    before = main.asset_fingerprint()
    assert main.asset_fingerprint() == before
    (tmp_path / "js" / "a.js").write_text("two, and longer")
    assert main.asset_fingerprint() != before


def test_responses_are_gzipped(c):
    fp = asset_fingerprint()
    for path in ("/", f"/assets/{fp}/css/app.css", f"/assets/{fp}/js/investigate.js"):
        r = c.get(path, headers={"accept-encoding": "gzip"})
        assert r.headers.get("content-encoding") == "gzip", path
    raw = c.get(f"/assets/{fp}/css/app.css", headers={"accept-encoding": "identity"})
    assert "content-encoding" not in raw.headers


def test_robots_and_sitemap(c):
    robots = c.get("/robots.txt")
    assert robots.headers["content-type"].startswith("text/plain")
    assert "Disallow: /api/" in robots.text and "Sitemap: https://crawlr.lol/sitemap.xml" in robots.text
    sm = c.get("/sitemap.xml")
    assert "xml" in sm.headers["content-type"] and "<loc>https://crawlr.lol/</loc>" in sm.text


def test_social_and_seo_tags(c):
    html = c.get("/").text
    for needle in ('<link rel="canonical" href="https://crawlr.lol/">', 'property="og:title"', 'property="og:description"',
                   'property="og:image" content="https://crawlr.lol/static/og.png"', 'name="twitter:card" content="summary_large_image"',
                   'name="description"'):
        assert needle in html, needle
    og = c.get("/static/og.png")
    assert og.status_code == 200 and og.headers["content-type"] == "image/png"


def test_csp_has_no_inline_scripts_or_third_party_hosts(c):
    csp = c.get("/").headers["content-security-policy"]
    assert csp == CSP
    script = next(d for d in csp.split("; ") if d.startswith("script-src"))
    assert script == "script-src 'self'"
    for gone in ("unsafe-inline' https://cdnjs", "cdnjs.cloudflare.com", "fonts.googleapis.com", "fonts.gstatic.com"):
        assert gone not in csp


def test_page_loads_nothing_from_third_party_origins(c):
    html = c.get("/").text
    assert "fonts.googleapis.com" not in html and "fonts.gstatic.com" not in html and "cdnjs" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html), "inline script found"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler found"
    fp = asset_fingerprint()
    assert c.get(f"/assets/{fp}/vendor/d3.min.js").status_code == 200
    css = c.get(f"/assets/{fp}/css/app.css").text
    assert "font-display: swap" in css.replace("font-display:swap", "font-display: swap")
    for url in re.findall(r"url\(([^)]+)\)", css):
        assert not url.strip("'\"").startswith("http"), url
    assert "cdnjs" not in c.get(f"/assets/{fp}/js/recon.js").text


def test_ci_compiles_core():
    ci = open(".github/workflows/ci.yml").read()
    assert "compileall -q main.py routers modules middleware core" in ci
    for t in ("detect", "contrast", "brief"):
        assert f"node tests/js/{t}.test.mjs" in ci
