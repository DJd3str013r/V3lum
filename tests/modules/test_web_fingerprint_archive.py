"""web_fingerprint_archive (P072, PASSIVE): offline tests.

Fixtures in tests/fixtures/web_fingerprint_archive/ (prep p9-G03-2 and P059 web_archives captures):
``wayback_available_ok.json`` / ``_empty.json`` / ``_error_in_200.txt`` (real Wayback availability answers),
``snapshot_example_2009.http.json`` (a real pywb ``id_`` exchange of http://www.example.com/ from 2009 with its
``x-archive-orig-*`` headers and the archive's own Server/HSTS/Via headers) and
``snapshot_registrobr_latin1.html`` (a real ISO-8859-1 archived page). The hand-written fingerprint file of
tests/fixtures/web_fingerprint/ stands in for the GPL-3.0 webappanalyzer data (FC4).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from tests.modules.test_web_fingerprint import install_wa
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web.web_fingerprint import WebFingerprintArchive

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "web_fingerprint_archive"
AVAIL = "https://archive.org/wayback/available?" + urlencode({"url": "http://example.com/"})
SNAP = "https://web.archive.org/web/20261126034206id_/https://example.com/"


@pytest.fixture(autouse=True)
def _dataset():
    install_wa()
    yield


def snapshot(http: FakeHttp, ex: dict | None = None, *, body: bytes | None = None, headers: dict | None = None, status: int = 200) -> None:
    ex = ex or module_fixture(WebFingerprintArchive, "snapshot_example_2009.http.json")
    hdrs = headers if headers is not None else {k: v for k, v in ex["headers"]}
    http.add("GET", SNAP, status=status, body=body if body is not None else ex["body"].encode("utf-8"), headers=hdrs)


def test_metadata_passive_default_archive_only():
    cls = WebFingerprintArchive
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.default_enabled is True
    assert cls.hosts == ("archive.org", "web.archive.org") and cls.terms == "open" and cls.max_requests <= 10


def test_archived_homepage_uses_only_the_original_headers():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    snapshot(http)
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.OK, res.error
    techs = {t["name"]: t["version"] for t in res.attributes["technologies"]}
    assert techs.get("Apache HTTP Server") == "2.2.3" and "Red Hat" in techs
    # the archive's own HSTS / Server: Apache / Via: Caddy are never attributed to the target (FC1)
    assert "HSTS" not in techs
    assert res.attributes["server"] == "Apache/2.2.3 (Red Hat)"
    assert res.attributes["archive_snapshot"]["captured_at"] == "2026-11-26T03:42:06Z"
    assert res.attributes["title"] == "Example Web Page"
    assert not [f for f in res.findings if "version_inferred" in f.tags]
    http.assert_hosts_within(WebFingerprintArchive)
    assert "example.com" not in {c["url"].split("/")[2] for c in http.calls}  # never the live site


def test_archived_snapshot_cves_are_context_not_findings():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    page = b"<html><head><title>old shop</title><script src='/js/jquery-1.12.4.min.js'></script></head></html>"
    snapshot(http, body=page, headers={"content-type": "text/html", "x-archive-orig-server": "nginx"})
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.OK
    assert not [f for f in res.findings if "version_inferred" in f.tags]
    rows = res.attributes["technology_cves"]
    assert rows and rows[0]["technology"] == "jQuery" and rows[0]["version"] == "1.12.4" and rows[0]["cve_count"] >= 1


def test_latin1_snapshot_is_decoded():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    body = (FIXTURES / "snapshot_registrobr_latin1.html").read_bytes()
    snapshot(http, body=body, headers={"content-type": "text/html", "x-archive-orig-server": "Apache"})
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.OK
    assert res.attributes["title"].startswith("Registro.br")
    assert "Apache HTTP Server" in {t["name"] for t in res.attributes["technologies"]}


def test_no_capture_is_empty_with_the_reason():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_empty.json"))
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.EMPTY
    assert len(http.calls) == 1


def test_error_in_200_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", AVAIL, text=(FIXTURES / "wayback_available_error_in_200.txt").read_text(encoding="utf-8"),
             headers={"content-type": "text/plain"})
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.ERROR


def test_malformed_json_is_an_error():
    http = FakeHttp()
    http.add("GET", AVAIL, body=b"{not json", headers={"content-type": "application/json"})
    assert run_module(WebFingerprintArchive, "domain:example.com", http).status is Status.ERROR


def test_429_is_rate_limited_and_5xx_is_error():
    http = FakeHttp()
    http.add("GET", AVAIL, status=429, text="slow down")
    assert run_module(WebFingerprintArchive, "domain:example.com", http).status is Status.RATE_LIMITED
    http2 = FakeHttp()
    http2.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    snapshot(http2, status=503, body=b"<html>busy</html>", headers={"content-type": "text/html"})
    assert run_module(WebFingerprintArchive, "domain:example.com", http2).status is Status.ERROR


def test_archived_challenge_page_is_not_fingerprinted():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    zscaler = (Path(__file__).resolve().parents[1] / "fixtures" / "web_fingerprint" / "corporate_block_zscaler_synthetic.html").read_bytes()
    snapshot(http, body=zscaler, headers={"content-type": "text/html"})
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    # an archived block page could not be fingerprinted: could not verify, never 'no technologies' (rule 5)
    assert res.status is Status.ERROR and "could not verify" in res.error and "technologies" not in res.attributes
    assert json.dumps(res.attributes["fingerprint_verdict"]).count("corporate_proxy") == 1


def test_archived_error_page_without_header_facts_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(WebFingerprintArchive, "wayback_available_ok.json"))
    snapshot(http, status=404, body=b"<html><title>Not Found</title></html>", headers={"content-type": "text/html"})
    res = run_module(WebFingerprintArchive, "domain:example.com", http)
    assert res.status is Status.ERROR and "inconclusive" in res.error


def test_snapshot_url_with_secrets_is_never_fetched_and_never_empty():
    http = FakeHttp()
    personal_url = "https://example.com/u/fulana@example.com/"
    avail = {"url": personal_url, "archived_snapshots": {"closest": {"status": "200", "available": True, "timestamp": "20261126034206",
                                                                     "url": f"http://web.archive.org/web/20261126034206/{personal_url}"}}}
    http.add("GET", "https://archive.org/wayback/available?" + urlencode({"url": personal_url}), json=avail)
    res = run_module(WebFingerprintArchive, f"url:{personal_url}", http)
    # a capture exists but its URL carries an e-mail address: never fetched, and never reported as 'no capture'
    assert res.status is Status.SKIPPED and res.reason_code == "policy"
    assert not [c for c in http.calls if "web.archive.org" in c["url"]]
    assert "fulana" not in json.dumps(res.attributes) + str(res.error)


@pytest.mark.parametrize(("etype", "value"), [("domain", "example.com"), ("url", "https://example.com/")])
def test_golden_acceptance_routes_replay_with_runtime_dataset_downloads(etype, value):
    """tests/fixtures/acceptance/{domain,url}/web_fingerprint_archive.json: the default module downloads the
    fingerprint data at runtime (hand-written stand-in for the GPL-3.0 files) and fingerprints the snapshot."""
    from v3lum import paths
    from tests.fakes import fixture

    for p in paths.datasets_dir().glob("webappanalyzer.*"):
        p.unlink()
    doc = fixture(f"acceptance/{etype}/web_fingerprint_archive.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "web_fingerprint_archive"
    http = FakeHttp()
    for r in doc["routes"]:
        body = {"json": r["json"]} if "json" in r else {"text": r["text"]}
        http.add(r["method"], r["url"], status=r["status"], headers=r.get("headers"), **body)
    res = run_module(WebFingerprintArchive, f"{etype}:{value}", http)
    assert res.status is Status.OK, res.error
    assert "Apache HTTP Server" in {t["name"] for t in res.attributes["technologies"]}
    assert not [f for f in res.findings if f.severity.name not in ("INFO",)]
    assert len(http.calls) == len(doc["routes"])
