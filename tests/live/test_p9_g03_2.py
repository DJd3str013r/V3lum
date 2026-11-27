"""Live checks of batch p9-G03-2 (web_fingerprint, web_fingerprint_archive, posture_third_party,
site_contacts, site_contacts_archive); run with V3LUM_LIVE=1.

Target-contact (LIGHT) code never touches a third-party site here: ``web_fingerprint`` sends its single
homepage GET to the IANA documentation domain example.com only, and ``site_contacts`` (robots.txt + a
bounded crawl) runs against a local server this test starts on 127.0.0.1 (internal typed seed).
PASSIVE helpers use benign public values: Wayback lookups of example.com, the runtime download of the
webappanalyzer fingerprint data (raw.githubusercontent.com) and the HSTS preload status of example.com.
SSL Labs is not called live (non-commercial terms, and ssllabs_assess would start a third-party scan).

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web.posture_third_party import SRC_HSTS, PostureThirdParty
from v3lum.modules.url_web.site_contacts import SiteContacts, SiteContactsArchive
from v3lum.modules.url_web.web_fingerprint import WebFingerprint, WebFingerprintArchive

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
LIGHT = ScanOptions(mode=Opsec.LIGHT)


def live_runtime(org=None, **settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True, org=org)


def test_web_fingerprint_archive_of_example_com():
    res = run_module(WebFingerprintArchive, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert isinstance(res.attributes["technologies"], list)
        assert res.attributes["fingerprint_db"]["technologies"] > 1000  # the real webappanalyzer data was downloaded
        assert set(res.hosts) - {"archive.org", "web.archive.org"} == set()


def test_web_fingerprint_single_get_of_the_iana_documentation_domain():
    res = run_module(WebFingerprint, "domain:example.com", runtime=live_runtime(), options=LIGHT)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    target_hosts = {h for h in res.hosts if h.endswith("example.com")}
    assert target_hosts <= {"example.com", "www.example.com"}
    assert sum(res.hosts.get(h, 0) for h in target_hosts) <= 3  # one GET (+ at most a redirect)
    if res.status is Status.OK:
        assert res.attributes["http_status"] == 200 and res.attributes["fingerprint_verdict"]["verdict"] == "ok"


def test_posture_third_party_hsts_status_only():
    own = OrgProfile.from_dict({"domains": [{"name": "example.com", "verification": "confirmed"}]})
    res = run_module(PostureThirdParty, "domain:example.com", runtime=live_runtime(org=own), allowed_sources={SRC_HSTS})
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["hsts_preload"]["status"] in ("unknown", "preloaded", "pending", "rejected", "removed")
        assert set(res.hosts) == {"hstspreload.org"}


def test_site_contacts_archive_of_example_com():
    res = run_module(SiteContactsArchive, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    assert set(res.hosts) - {"archive.org", "web.archive.org"} == set()


PAGES = {
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /privado\n"),
    "/": ("text/html", "<html><head><title>Loja local</title></head><body><a href='/contato'>Fale conosco</a>"
          "<a href='/privado'>Contato privado</a><a href='/login'>Entrar</a><footer><a href='/sobre'>Sobre</a></footer></body></html>"),
    "/contato": ("text/html", "<html><body><a href='mailto:sac@example.com'>SAC</a> maria.souza@example.com "
                 "<a href='tel:+551155550100'>(11) 5555-0100</a></body></html>"),
    "/sobre": ("text/html", "<html><body>Empresa ficticia - CNPJ 11.222.333/0001-81</body></html>"),
}


def test_site_contacts_crawls_a_local_server_only():
    seen: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def do_GET(self):  # noqa: N802 - http.server API
            seen.append((self.command, self.path))
            ctype, body = PAGES.get(self.path, ("text/html", "<html><body>not found</body></html>"))
            data = body.encode("utf-8")
            self.send_response(200 if self.path in PAGES else 404)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        port = srv.server_address[1]
        res = run_module(SiteContacts, f"url:http://127.0.0.1:{port}/", runtime=live_runtime(), options=LIGHT, internal_seed=True)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.status is Status.OK, (res.status, res.error)
    paths = [p for _m, p in seen]
    assert paths[0] == "/robots.txt" and "/contato" in paths and "/sobre" in paths
    assert "/privado" not in paths and "/login" not in paths  # robots.txt and the excluded-page rules
    assert {m for m, _p in seen} == {"GET"}
    emails = {e["address"] for e in res.attributes["site_contacts"]["emails"]}
    assert emails == {"sac@example.com"}
    assert res.attributes["third_party_counts"] == {"personal_emails": 1}
