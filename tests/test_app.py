"""End-to-end checks against the FastAPI app.

Skipped when the full dependency set (sherlock, maigret, anthropic, ...)
is not installed, so the pure unit tests still run in a minimal env.
"""
import pytest

testclient = pytest.importorskip("fastapi.testclient")

try:
    from main import app
except ImportError as exc:  # pragma: no cover
    pytest.skip(f"app dependencies missing: {exc}", allow_module_level=True)


@pytest.fixture(scope="module")
def client():
    return testclient.TestClient(app)


def test_root_serves_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "/static/v2/js/app.js" in resp.text  # / now serves the v2 interface


def test_invalid_hash_rejected(client):
    resp = client.post("/api/hash/hash", json={"hash": "nope"})
    assert resp.status_code == 400


def test_v2_route_serves_new_ui():
    from fastapi.testclient import TestClient
    from main import app
    with TestClient(app) as c:
        r = c.get("/v2")
        assert r.status_code == 200 and "/static/v2/js/app.js" in r.text
        assert c.get("/static/v2/js/app.js").status_code == 200


def test_classic_route_still_serves_original_ui():
    from fastapi.testclient import TestClient
    from main import app
    with TestClient(app) as c:
        r = c.get("/classic")
        assert r.status_code == 200 and "CrawlR" in r.text
