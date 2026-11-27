"""js_endpoints_archive (P068, PASSIVE, opt-in): JavaScript of Wayback id_ snapshots, offline.

Fixtures in tests/fixtures/js_endpoints_archive/ (batch p9-G03-1): a Wayback CDX JSON listing in the
recorded web_archives shape (synthetic rows: the live Wayback CDX reset the connection from the batch
egress), the synthetic app bundle with positive-control placeholders and the synthetic kit script
(the placeholders are replaced at test time by values built by concatenation). Every request goes to
web.archive.org; the live site is never contacted.
"""

from __future__ import annotations

import re

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.url_web.js_endpoints import JsEndpointsArchive

FX = FIXTURES / "js_endpoints_archive"
CDX = re.compile(r"^https://web\.archive\.org/cdx/search/cdx\?url=www\.example\.com%2F%2A")
AWS = "AKIA" + "QX7Z" + "PLMN" + "4RTW" + "2B6D"
TG = "7123456789:" + "AAH" + "x9Q2mLp4Rt6Vw8Yz1Ab3Cd5Ef7Gh9Ij0K"


def snap(ts: str, url: str) -> str:
    return f"https://web.archive.org/web/{ts}id_/{url}"


def bundle() -> str:
    return (FX / "app_bundle_synthetic.js").read_text().replace("__AWS_KEY__", AWS).replace("__GITHUB_PAT__", "x").replace("__GCP_KEY__", "y")


def test_newest_archived_js_files_are_analysed_from_the_archive_only():
    http = FakeHttp()
    http.add("GET", CDX, json=module_fixture("js_endpoints_archive", "wayback_cdx_js_synthetic.json"))
    http.add("GET", snap("20261001000000", "https://www.example.com/static/js/app.min.js"), text=bundle())
    kit = (FX / "kit_exfil_synthetic.js").read_text().replace("__TG_TOKEN__", TG).replace("__DISCORD_WEBHOOK__", "https://drop.example.net/x")
    http.add("GET", snap("20261010000000", "https://www.example.com/kit/send.js"), text=kit)
    res = run_module(JsEndpointsArchive, "domain:www.example.com", http)
    assert res.status is Status.OK, res.error
    http.assert_hosts_within(JsEndpointsArchive)
    # the newest capture of each URL; the token URL (an e-mail in the query) is never replayed
    urls = [c["url"] for c in http.calls]
    assert snap("20250101000000", "https://www.example.com/static/js/app.min.js") not in urls
    assert not any("track.js" in u for u in urls)
    assert any(p.relation == "js_endpoint" and p.entity.value == "https://www.example.com/api/v1/users?id=1" for p in res.pivots)
    assert any(f.title == "Secret in public JavaScript: aws-access-token" for f in res.findings)
    assert any(f.title == "Phishing-kit exfiltration channels in page scripts" for f in res.findings)
    sources = {f["source"] for f in res.attributes["js_files"]["files"]}
    assert sources == {"wayback:20261001000000", "wayback:20261010000000"}
    assert_no_secret(AWS, res.findings, res.attributes, res.raw)
    assert_no_secret(TG, res.findings, res.attributes, res.raw)


def test_no_archived_js_is_empty():
    http = FakeHttp().add("GET", CDX, json=[["timestamp", "original", "digest", "statuscode", "mimetype"]])
    assert run_module(JsEndpointsArchive, "domain:www.example.com", http).status is Status.EMPTY


def test_archive_failures_are_could_not_verify():
    http = FakeHttp().add("GET", CDX, status=429, text="Too Many Requests")
    assert run_module(JsEndpointsArchive, "domain:www.example.com", http).status is Status.RATE_LIMITED
    http = FakeHttp().add("GET", CDX, status=503, text="unavailable")
    assert run_module(JsEndpointsArchive, "domain:www.example.com", http).status is Status.ERROR
    http = FakeHttp().add("GET", CDX, text="<html><body>Wayback Machine error</body></html>")
    assert run_module(JsEndpointsArchive, "domain:www.example.com", http).status is Status.ERROR


def test_html_snapshots_are_not_analysed():
    http = FakeHttp()
    rows = [["timestamp", "original", "digest", "statuscode", "mimetype"],
            ["20261001000000", "https://www.example.com/a.js", "A", "200", "application/javascript"]]
    http.add("GET", CDX, json=rows)
    http.add("GET", snap("20261001000000", "https://www.example.com/a.js"), text="<!DOCTYPE html><html><body>Hrm.</body></html>")
    res = run_module(JsEndpointsArchive, "domain:www.example.com", http)
    assert res.status is Status.ERROR and "HTML page" in res.error


def test_contract_metadata():
    assert JsEndpointsArchive.default_enabled is False and JsEndpointsArchive.trust_tier == "trusted"
    assert JsEndpointsArchive.max_requests == 11 and JsEndpointsArchive.hosts == ("web.archive.org",)
