import asyncio
import json
import logging

from fastapi.testclient import TestClient

from main import app
from core import subprocess_guard as sg
from core.logging import JsonFormatter, request_id_var
from middleware.observability import SECURITY_HEADERS


def test_security_headers_present_on_html_and_api():
    with TestClient(app) as c:
        for path in ("/", "/api/health"):
            r = c.get(path)
            assert r.status_code == 200
            for k in SECURITY_HEADERS:
                assert k in r.headers, f"{k} missing on {path}"
            assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_request_id_generated_and_echoed():
    with TestClient(app) as c:
        r = c.get("/api/health")
        assert len(r.headers["X-Request-ID"]) == 12
        r2 = c.get("/api/health", headers={"X-Request-ID": "abc123"})
        assert r2.headers["X-Request-ID"] == "abc123"


def test_json_formatter_includes_extra_and_request_id():
    token = request_id_var.set("req-1")
    try:
        rec = logging.LogRecord("t", logging.INFO, __file__, 1, "hello %s", ("world",), None)
        rec.module_name = "sherlock"
        rec.ms = 42
        out = json.loads(JsonFormatter().format(rec))
    finally:
        request_id_var.reset(token)
    assert out["msg"] == "hello world"
    assert out["request_id"] == "req-1"
    assert out["module_name"] == "sherlock" and out["ms"] == 42


def test_tool_slot_limits_concurrency(monkeypatch):
    monkeypatch.setattr(sg, "_semaphore", None)
    monkeypatch.setattr(sg, "MAX_CONCURRENT_TOOLS", 2)
    monkeypatch.setattr(sg, "TOOL_QUEUE_TIMEOUT", 0.2)
    peak = 0
    running = 0

    async def job():
        nonlocal peak, running
        async with sg.tool_slot("fake"):
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.05)
            running -= 1

    async def main():
        await asyncio.gather(*(job() for _ in range(6)))

    asyncio.run(main())
    assert peak == 2


def test_tool_slot_returns_busy_when_saturated(monkeypatch):
    monkeypatch.setattr(sg, "_semaphore", None)
    monkeypatch.setattr(sg, "MAX_CONCURRENT_TOOLS", 1)
    monkeypatch.setattr(sg, "TOOL_QUEUE_TIMEOUT", 0.05)

    async def main():
        async with sg.tool_slot("a"):
            try:
                async with sg.tool_slot("b"):
                    return "acquired"
            except sg.ToolBusy:
                return "busy"

    assert asyncio.run(main()) == "busy"
    assert sg.busy_result(username="x")["error"] == "busy"
