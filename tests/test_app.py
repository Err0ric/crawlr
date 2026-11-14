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
    assert "/js/app.js" in resp.text and "/assets/" in resp.text  # fingerprinted v2 assets


def test_invalid_hash_rejected(client):
    resp = client.post("/api/hash/hash", json={"hash": "nope"})
    assert resp.status_code == 400


def test_v2_alias_redirects_to_root(client):
    r = client.get("/v2", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/"
    assert client.get("/static/v2/js/app.js").status_code == 200


def test_classic_ui_is_retired(client):
    # The v1 interface and its files are gone; old bookmarks land on the current UI.
    r = client.get("/classic", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/"
    assert client.get("/static/index.html").status_code == 404
    assert client.get("/static/app.js").status_code == 404
