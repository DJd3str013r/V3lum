"""Live checks of batch p9-G03-1 (favicon_hash, favicon_fetch, security_headers, wellknown_files,
js_endpoints_archive, js_endpoints_live, unshorten_preview, unshorten_me, unshorten_trace); run with
V3LUM_LIVE=1.

Target-contact (LIGHT) code never touches a third-party site here: favicon_fetch, wellknown_files,
js_endpoints_live and unshorten_trace run against a local server this test starts on 127.0.0.1 (an
internal analyst-typed seed). PASSIVE sources use benign public values: Wayback CDX lookups of
example.com (favicon_hash, js_endpoints_archive) and one unshorten.me lookup of a public conference short
link the research already resolved (bit.ly/nicar22-web; the service fetches it, V3LUM does not).
security_headers and unshorten_preview make no request at all.

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence.
"""

from __future__ import annotations

import gzip
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web import unshorten as U
from v3lum.modules.url_web.favicon import FaviconFetch, FaviconHash
from v3lum.modules.url_web.js_endpoints import JsEndpointsArchive, JsEndpointsLive
from v3lum.modules.url_web.security_headers import SecurityHeaders
from v3lum.modules.url_web.unshorten import UnshortenMe, UnshortenPreview, UnshortenTrace
from v3lum.modules.url_web.wellknown_files import WellknownFiles

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
LIGHT = ScanOptions(mode=Opsec.LIGHT)
ICO = bytes.fromhex("00000100010010100000010020006804000016000000") + b"\x28" + b"\x00" * 1127  # a small valid-looking ICO
AWS = "AKIA" + "QX7Z" + "PLMN" + "4RTW" + "2B6D"  # synthetic, built at run time


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


class Local:
    """A loopback HTTP server answering ``routes`` {path: (status, headers, body)} and recording requests."""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], bytes]] | Callable[[int], dict]) -> None:
        self.seen: list[tuple[str, str]] = []
        self._routes = routes
        local = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _answer(self, with_body: bool) -> None:
                local.seen.append((self.command, self.path))
                routes = local._routes(local.port) if callable(local._routes) else local._routes
                status, headers, body = routes.get(self.path, (404, {"Content-Type": "text/html"}, b"<html><body>not found</body></html>"))
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if with_body:
                    self.wfile.write(body)

            def do_GET(self):  # noqa: N802 - http.server API
                self._answer(True)

            def do_HEAD(self):  # noqa: N802 - http.server API
                self._answer(False)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self) -> Local:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.srv.shutdown()
        self.srv.server_close()


# ---------------------------------------------------------------------------------- PASSIVE


def test_favicon_hash_from_the_wayback_machine_for_example_com():
    res = run_module(FaviconHash, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"web.archive.org"}
    if res.status is Status.OK:
        assert isinstance(res.attributes["favicon"]["mmh3"], int)


def test_js_endpoints_archive_of_example_com():
    res = run_module(JsEndpointsArchive, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"web.archive.org"}


def test_unshorten_me_resolves_a_public_conference_short_link():
    res = run_module(UnshortenMe, "url:https://bit.ly/nicar22-web", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) <= {"unshorten.me"} and res.hosts.get("unshorten.me", 0) <= 1
    if res.status is Status.OK:
        (pivot,) = res.pivots
        assert pivot.relation == "redirects_to" and "github.com" in pivot.entity.value


def test_offline_modules_make_no_request():
    rt = live_runtime()
    res = run_module(UnshortenPreview, "url:https://bit.ly/nicar22-web", runtime=rt)
    assert res.status is Status.OK and res.hosts == {}
    res = run_module(SecurityHeaders, "domain:example.com", runtime=rt)
    assert res.status in (Status.OK, Status.SKIPPED) and res.hosts == {}


# ---------------------------------------------------------------------------------- LIGHT (loopback only)


def test_favicon_fetch_against_a_local_server():
    routes = {
        "/": (200, {"Content-Type": "text/html"}, b'<html><head><link rel="icon" href="/static/icon.ico"></head></html>'),
        "/static/icon.ico": (200, {"Content-Type": "image/x-icon"}, ICO),
    }
    with Local(routes) as srv:
        res = run_module(FaviconFetch, f"url:http://127.0.0.1:{srv.port}/", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    assert res.status in (Status.OK, Status.EMPTY), (res.status, res.error)
    assert srv.seen[:2] == [("GET", "/"), ("GET", "/static/icon.ico")] and len(srv.seen) == 2
    assert {m for m, _p in srv.seen} == {"GET"}


def test_wellknown_files_against_a_local_server():
    def routes(port: int) -> dict:
        base = f"http://127.0.0.1:{port}"
        sitemap = (f'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                   f"<url><loc>{base}/produtos</loc></url><url><loc>{base}/contato</loc></url></urlset>").encode()
        return {
            "/.well-known/security.txt": (200, {"Content-Type": "text/plain"},
                                          b"Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n"),
            "/robots.txt": (200, {"Content-Type": "text/plain"},
                            f"User-agent: *\nDisallow: /admin/\nSitemap: {base}/sitemap.xml.gz\n".encode()),
            "/sitemap.xml.gz": (200, {"Content-Type": "application/gzip"}, gzip.compress(sitemap)),
        }

    with Local(routes) as srv:
        res = run_module(WellknownFiles, f"url:http://127.0.0.1:{srv.port}/", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    assert res.status is Status.OK, (res.status, res.error)
    paths = [p for _m, p in srv.seen]
    assert "/.well-known/security.txt" in paths and "/robots.txt" in paths and "/sitemap.xml.gz" in paths
    assert "/admin/" not in paths and "/produtos" not in paths  # listed, never requested
    assert {m for m, _p in srv.seen} == {"GET"}
    assert res.attributes["security_txt"]["state"] == "present"


def test_js_endpoints_live_against_a_local_server():
    js = (b'fetch("/api/v1/orders?id=1");var k="' + AWS.encode() + b'";$.ajax({url:"/internal/report"});')
    routes = {
        "/": (200, {"Content-Type": "text/html"}, b'<html><body><script src="/static/app.js"></script></body></html>'),
        "/static/app.js": (200, {"Content-Type": "application/javascript"}, js),
    }
    with Local(routes) as srv:
        res = run_module(JsEndpointsLive, f"url:http://127.0.0.1:{srv.port}/", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    assert res.status is Status.OK, (res.status, res.error)
    assert [p for _m, p in srv.seen] == ["/", "/static/app.js"]
    assert "/api/v1/orders" not in [p for _m, p in srv.seen]  # endpoints are listed, never requested
    assert any(f.title == "Secret in public JavaScript: aws-access-token" for f in res.findings)
    assert AWS not in repr(res.attributes) and AWS not in repr([f.description for f in res.findings])


@pytest.fixture
def loopback_shortener(monkeypatch):
    """List 127.0.0.1 as a shortener for this test only (no real shortener is ever contacted)."""
    table = dict(U.load_shorteners())
    table["127.0.0.1"] = {"host": "127.0.0.1", "source": "test"}
    monkeypatch.setattr(U, "_SHORTENERS", table)


def test_unshorten_trace_reads_the_location_and_never_visits_the_destination(loopback_shortener):
    routes = {"/s": (302, {"Location": "https://www.example.com/landing?utm_source=sms"}, b"")}
    with Local(routes) as srv:
        res = run_module(UnshortenTrace, f"url:http://127.0.0.1:{srv.port}/s", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    assert res.status is Status.OK, (res.status, res.error)
    assert srv.seen == [("HEAD", "/s")]
    assert set(res.hosts) == {"127.0.0.1"}  # www.example.com is recorded, not contacted
    (pivot,) = res.pivots
    assert pivot.entity.value == "https://www.example.com/landing?utm_source=sms" and pivot.relation == "redirects_to"


@pytest.mark.parametrize("location", ["http://10.0.0.5/", "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:1/admin"])
def test_unshorten_trace_refuses_internal_redirects(loopback_shortener, location):
    routes = {"/s": (302, {"Location": location}, b"")}
    with Local(routes) as srv:
        res = run_module(UnshortenTrace, f"url:http://127.0.0.1:{srv.port}/s", runtime=live_runtime(unshorten_trace_follow_final=True),
                         options=LIGHT, internal_seed=True)
    assert srv.seen == [("HEAD", "/s")]
    assert set(res.hosts) == {"127.0.0.1"}
    assert res.attributes["unshorten_refused"]["action"] == "refuse" and res.pivots == []


def test_unshorten_trace_head_refused_then_get_meta_refresh(loopback_shortener):
    page = b'<html><head><meta http-equiv="refresh" content="0; url=https://landing.example.org/p"></head></html>'

    routes = {"/m": (200, {"Content-Type": "text/html"}, page)}
    with Local(routes) as srv:
        res = run_module(UnshortenTrace, f"url:http://127.0.0.1:{srv.port}/m", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    assert res.status is Status.OK, (res.status, res.error)
    assert srv.seen == [("HEAD", "/m"), ("GET", "/m")]
    assert [p.entity.value for p in res.pivots] == ["https://landing.example.org/p"]
