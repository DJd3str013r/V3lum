"""Live check of batch p9-G13-2 (ACTIVE pentest_recon). Run with V3LUM_LIVE=1.

These are ACTIVE target-contact modules, so the live check NEVER contacts a third-party host: the
only allowed live target is a server the test starts itself on 127.0.0.1 (batch rule). This test
drives the real engine, HTTP client, egress profile and scope binding (no FakeHttp) of ``cors_probe``
against a loopback HTTP server that reflects the forged Origin, under an ACTIVE scope that lists
127.0.0.1/32. ``axfr``'s real raw-socket (ctx.net) path is already exercised against a loopback TCP
DNS server in the offline suite (tests/modules/test_axfr.py); ``cloud_buckets`` cannot be live-checked
without contacting a real provider, which the batch rules forbid, so it is covered offline only.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope

pytestmark = pytest.mark.live

REF = "PENTEST-2026-283-LIVE"


class _ReflectingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # silence
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        origin = self.headers.get("Origin", "")
        body = b'{"data": 1}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if origin:  # reflect the forged Origin with credentials (a misconfigured server)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)


def test_cors_probe_live_against_loopback_server():
    from v3lum.modules.pentest_recon.cors_probe import CorsProbe

    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scope = Scope.from_dict({
            "authorization_ref": REF,
            "owner": "live loopback check",
            "contacts": ["soc@example.com"],
            "ticket": "LIVE-1",
            "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2030-01-01T00:00:00Z",
            "targets": {"cidrs": ["127.0.0.1/32"]},
        })
        options = ScanOptions(mode=Opsec.ACTIVE, authorized=True, authorization_ref=REF, scope=scope,
                              include={"cors_probe"}, threads=1, save_evidence=False)
        rt = Runtime(Config(), no_cache=True)
        seed = Entity.make(EntityType.URL, f"http://127.0.0.1:{port}/")
        res = Engine(rt, options).run_module(CorsProbe, seed)
        assert res.status is Status.OK, res.error
        high = [f for f in res.findings if f.severity.name == "HIGH"]
        assert high, "the reflecting loopback server should produce a HIGH CORS finding"
        assert any(r["acao_reflected"] and r["acac"] for r in res.attributes["cors_results"])
    finally:
        server.shutdown()
        server.server_close()
