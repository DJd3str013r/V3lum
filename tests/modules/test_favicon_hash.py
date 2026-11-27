"""favicon_hash (P062, PASSIVE, default): archived favicon bytes and typed hashes, offline.

Fixtures in tests/fixtures/favicon_hash/ (batch p9-G03-1 prep, 2026-11-26):

* ``google_favicon.ico`` - Google's favicon (5,430 bytes) from the favicorn test suite (Apache-2.0,
  notice ``favicorn_test_icon``): the Shodan test vector, mmh3 708578229, MD5 f3418a44... (the value
  ZoomEye documents for Google's icon);
* ``favicon_google_20090914.ico`` - the archived Google favicon of 2009-09-14 (archive_mining fixture);
* ``wayback_cdx_google_favicon_derived.json`` - the recorded Arquivo.pt CDX rows of
  www.google.com/favicon.ico (archive_mining fixture) re-shaped as the Wayback JSON array (derived: the
  live Wayback CDX reset the connection from the prep and batch egress);
* ``wayback_error_in_200.json`` - a Wayback HTML error page served with HTTP 200 (synthetic shape);
* ``design_pivots_and_js_recorded.json`` - the recorded research pivot checks (Vercel checkpoint page
  answering 429: a challenge, never a result);
* ``blank_1x1.gif`` - a 1x1 transparent GIF (V3LUM computed blank-icon noise entry).
"""

from __future__ import annotations

import base64
import hashlib
import re

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.url_web import favicon as F
from v3lum.modules.url_web.favicon import FaviconHash

FX = FIXTURES / "favicon_hash"
CDX = "https://web.archive.org/cdx/search/cdx"
GOOGLE_ICO = (FX / "google_favicon.ico").read_bytes()
OLD_ICO = (FX / "favicon_google_20090914.ico").read_bytes()


def cdx_route(http: FakeHttp, host: str, **kw) -> FakeHttp:
    """The CDX listing of <host>/favicon.ico (the archive_mining query: shared through the HTTP cache)."""
    return http.add("GET", re.compile(r"^" + re.escape(f"{CDX}?url={host}%2Ffavicon.ico&output=json")), **kw)


# ---------------------------------------------------------------------------------- hashing (c1)


def test_shodan_test_vector_google_favicon():
    hashes = F.favicon_hashes(GOOGLE_ICO)
    assert hashes["mmh3"] == 708578229  # Shodan http.favicon.hash of Google's favicon
    assert hashes["md5"] == "f3418a443e7d841097c714d69ec4bcb8"  # the MD5 ZoomEye documents for the same icon
    assert hashes["sha256"] == hashlib.sha256(GOOGLE_ICO).hexdigest()
    assert hashes["mmh3_hex_unsigned"] == format(708578229, "08x") and hashes["format"] == "ico"
    # Shodan hashes base64.encodebytes (76-char lines + trailing newline), never plain b64encode
    assert F.mmh3_32(base64.b64encode(GOOGLE_ICO)) != 708578229


@pytest.mark.parametrize(("data", "expected"), [(b"foo", -156908512), (b"hello", 613153351), (b"", 0)])
def test_mmh3_reference_vectors(data, expected):
    assert F.mmh3_32(data) == expected


def test_parse_typed_hash_inputs():
    assert F.parse_favicon_hash_input("http.favicon.hash:708578229") == {"mmh3": 708578229}
    assert F.parse_favicon_hash_input("icon_hash=\"-1184133586\"") == {"mmh3": -1184133586}
    assert F.parse_favicon_hash_input(str(2**32 - 1)) == {"mmh3": -1}  # unsigned form
    assert F.parse_favicon_hash_input("F3418A443E7D841097C714D69EC4BCB8") == {"md5": "f3418a443e7d841097c714d69ec4bcb8"}
    assert F.parse_favicon_hash_input("not a hash") is None


# ---------------------------------------------------------------------------------- noise (c5)


def test_default_favicon_suppression():
    defaults = F.load_favicon_defaults()
    google = F.favicon_noise(708578229, defaults)
    assert google == {"reason": "default", "name": "google", "category": "platform"}
    blank = F.favicon_noise(F.shodan_favicon_hash((FX / "blank_1x1.gif").read_bytes()), defaults)
    assert blank and blank["reason"] == "blank"
    assert F.favicon_noise(-1184133586, defaults) is None
    assert F.favicon_noise(-1184133586, defaults, reported_hosts=5000)["reason"] == "mass"  # > 1,000 hosts
    assert F.favicon_noise(-1184133586, defaults, reported_hosts=999) is None


# ---------------------------------------------------------------------------------- engine links (c6)


def test_engine_pivot_links_default_set():
    links = F.engine_pivot_links(F.favicon_hashes(GOOGLE_ICO))
    assert [x["engine"] for x in links] == ["shodan", "fofa", "criminalip", "netlas", "zoomeye"]
    by = {x["engine"]: x["url"] for x in links}
    assert by["shodan"] == "https://www.shodan.io/search?query=http.favicon.hash%3A708578229"
    assert by["fofa"] == "https://en.fofa.info/result?qbase64=" + base64.b64encode(b'icon_hash="708578229"').decode().replace("=", "%3D")
    assert by["netlas"].endswith(hashlib.sha256(GOOGLE_ICO).hexdigest())
    # a typed mmh3 has no SHA-256: Netlas is skipped
    assert "netlas" not in {x["engine"] for x in F.engine_pivot_links({"mmh3": 1})}


def test_recorded_pivot_checks_challenge_shape():
    """The research pivot checks: a Vercel checkpoint answering 429 is a challenge, never data."""
    rec = module_fixture("favicon_hash", "design_pivots_and_js_recorded.json")
    vercel = rec["pivot::web_check"]
    page = f"<html><head><title>{vercel['title']}</title></head><body></body></html>"
    fmt, why = F.classify_favicon_response(vercel["status"], {"content-type": "text/html"}, page.encode())
    assert fmt is None and why.startswith("challenge")
    assert rec["pivot::dnsviz"]["status"] == 200 and rec["pivot::dnsviz"]["echoes_input"] is True


# ---------------------------------------------------------------------------------- typed hashes (c2)


def test_typed_hash_makes_no_request_and_emits_links():
    http = FakeHttp()
    res = run_module(FaviconHash, "favicon_hash:-1184133586", http)
    assert res.status is Status.OK
    assert http.calls == []  # links only, no request
    assert res.attributes["favicon_mmh3"] == -1184133586
    assert {label.split(":")[0] for label, _url in res.links} == {"Shodan", "FOFA", "Criminal IP", "ZoomEye"}
    assert "favicon_noise" not in res.attributes and not res.pivots  # the typed value is the subject itself


def test_typed_default_hash_is_flagged_as_noise():
    res = run_module(FaviconHash, "favicon_hash:708578229", FakeHttp())
    assert res.attributes["favicon_noise"]["name"] == "google"


# ---------------------------------------------------------------------------------- archived favicon (c2)


def test_archived_favicon_is_hashed_from_the_newest_snapshot():
    http = FakeHttp()
    cdx_route(http, "www.google.com", json=module_fixture("favicon_hash", "wayback_cdx_google_favicon_derived.json"))
    snap = "https://web.archive.org/web/20090520104006id_/http://www.google.com/favicon.ico"
    http.add("GET", snap, body=OLD_ICO, headers={"content-type": "image/x-icon"})
    res = run_module(FaviconHash, "domain:www.google.com", http)
    assert res.status is Status.OK, res.error
    fav = res.attributes["favicon"]
    assert fav["mmh3"] == -1184133586 and fav["source"] == "wayback" and fav["snapshot"] == "2009-05-20T10:40:06Z"
    assert fav["sha256"] == hashlib.sha256(OLD_ICO).hexdigest()
    # a 2009 icon is not the site's current favicon: historical relation, listed only
    (pivot,) = res.pivots
    assert pivot.entity.value == "-1184133586" and pivot.relation == "historical_favicon" and pivot.expand is False
    assert any("shodan.io" in url for _label, url in res.links)
    http.assert_hosts_within(FaviconHash)
    assert [c["url"].split("?")[0] for c in http.calls] == [CDX, snap]


def test_recent_archived_favicon_pivots_as_the_current_icon():
    rows = [["timestamp", "original", "digest", "statuscode", "mimetype"],
            ["20261101000000", "https://www.example.com/favicon.ico", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "200", "image/x-icon"]]
    http = FakeHttp()
    cdx_route(http, "www.example.com", json=rows)
    http.add("GET", "https://web.archive.org/web/20261101000000id_/https://www.example.com/favicon.ico", body=OLD_ICO)
    res = run_module(FaviconHash, "url:https://www.example.com/login", http)
    (pivot,) = res.pivots
    assert pivot.relation == "favicon" and pivot.expand is True


def test_archived_default_favicon_is_recorded_never_pivoted():
    rows = [["timestamp", "original", "digest", "statuscode", "mimetype"],
            ["20261101000000", "https://www.example.com/favicon.ico", "BBBB", "200", "image/x-icon"]]
    http = FakeHttp()
    cdx_route(http, "www.example.com", json=rows)
    http.add("GET", "https://web.archive.org/web/20261101000000id_/https://www.example.com/favicon.ico", body=GOOGLE_ICO)
    res = run_module(FaviconHash, "domain:www.example.com", http)
    assert res.attributes["favicon_noise"]["reason"] == "default"
    assert res.pivots == []
    assert res.links  # still linked for the analyst


def test_no_archived_capture_is_empty_never_no_favicon():
    http = FakeHttp()
    cdx_route(http, "www.example.com", json=[])
    res = run_module(FaviconHash, "domain:www.example.com", http)
    assert res.status is Status.EMPTY


@pytest.mark.parametrize(("status", "text", "expected"), [
    (429, "Too Many Requests", Status.RATE_LIMITED),
    (503, "Service Unavailable", Status.ERROR),
    (403, "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>", Status.BLOCKED),
])
def test_cdx_failures_are_could_not_verify(status, text, expected):
    http = FakeHttp()
    cdx_route(http, "www.example.com", status=status, text=text)
    res = run_module(FaviconHash, "domain:www.example.com", http)
    assert res.status is expected
    assert "could not verify" in res.error


def test_wayback_error_page_in_200_is_never_hashed():
    page = module_fixture("favicon_hash", "wayback_error_in_200.json")
    rows = [["timestamp", "original", "digest", "statuscode", "mimetype"],
            ["20261101000000", "https://www.example.com/favicon.ico", "CCCC", "200", "image/x-icon"]]
    http = FakeHttp()
    cdx_route(http, "www.example.com", json=rows)
    http.add("GET", "https://web.archive.org/web/20261101000000id_/https://www.example.com/favicon.ico", status=page["status"],
             text=page["body"])
    res = run_module(FaviconHash, "domain:www.example.com", http)
    assert res.status is Status.ERROR and "HTML page" in res.error
    assert "favicon" not in res.attributes


def test_malformed_cdx_answer_is_an_error():
    http = FakeHttp()
    cdx_route(http, "www.example.com", text='[["timestamp","original"],["2026')
    res = run_module(FaviconHash, "domain:www.example.com", http)
    assert res.status is Status.ERROR


def test_contract_metadata():
    assert FaviconHash.default_enabled is True and FaviconHash.terms == "open"
    assert FaviconHash.trust_tier == "trusted" and FaviconHash.hosts == ("web.archive.org",)
    assert FaviconHash.max_requests <= 10 and FaviconHash.expected_latency <= 10


@pytest.mark.parametrize(("etype", "value"), [("domain", "example.com"), ("url", "https://example.com/")])
def test_acceptance_routes_replay_the_golden_inputs(etype, value):
    """AR21 golden path: one CDX request (no capture of /favicon.ico -> EMPTY), never the live site."""
    import json

    from tests.fakes import fixture

    doc = fixture(f"acceptance/{etype}/favicon_hash.json")
    assert (doc["schema"], doc["module"]) == ("v3lum.acceptance_routes/1", "favicon_hash")
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], body=json.dumps(r["json"]).encode(), headers=r["headers"])
    res = run_module(FaviconHash, f"{etype}:{value}", http)
    assert res.status is Status.EMPTY and len(http.calls) == len(doc["routes"]) == 1
    assert {c["url"].split("/")[2] for c in http.calls} == {"web.archive.org"} and not res.findings
