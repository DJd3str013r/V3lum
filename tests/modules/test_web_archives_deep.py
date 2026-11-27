"""web_archives_deep (P059 cond 3): Common Crawl latest indexes + WARC homepage record, CarbonDate.

Fixtures in tests/fixtures/web_archives_deep/: real collinfo.json (5 of 130 entries) and the real
404 'No Captures found' answer recorded 2026-11-26, the recorded transport outcome of the index
connection reset, a synthetic per-crawl CDX answer in the pywb format (queries with results were reset
from the datacenter egress), real CarbonDate answers (every source empty) and a synthetic CarbonDate
estimate. The WARC record is built in the test from the real example.com snapshot (gzip member).
"""

from __future__ import annotations

import gzip
from urllib.parse import urlencode

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.url_web import web_archives_deep as D
from v3lum.modules.url_web.web_archives_deep import WebArchivesDeep

F = FIXTURES / "web_archives_deep"
COLLINFO = "https://index.commoncrawl.org/collinfo.json"
NEW, OLD = "CC-MAIN-2026-47", "CC-MAIN-2026-43"
WARC_URL = "https://data.commoncrawl.org/crawl-data/CC-MAIN-2026-47/segments/0000000000000.00/warc/CC-MAIN-20261108000000-20261108030000-00000.warc.gz"
CARBON = "https://carbondate.cs.odu.edu/cd/example.com"


def index_url(crawl, query="example.com", domain=True):
    params = {"url": query, "output": "json", "limit": "1000"}
    if domain:
        params["matchType"] = "domain"
    return f"https://index.commoncrawl.org/{crawl}-index?" + urlencode(params)


def text(name):
    return (F / name).read_text(encoding="utf-8")


def warc_record(html: bytes, *, chunked=False, gzip_body=False) -> bytes:
    body = gzip.compress(html) if gzip_body else html
    if chunked:
        body = b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n"
    headers = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n"
    headers += b"Transfer-Encoding: chunked\r\n" if chunked else b""
    headers += b"Content-Encoding: gzip\r\n" if gzip_body else b""
    record = b"WARC/1.0\r\nWARC-Type: response\r\nContent-Type: application/http; msgtype=response\r\n\r\n" + headers + b"\r\n" + body
    return gzip.compress(record)


def snapshot_html() -> bytes:
    return (FIXTURES / "web_archives" / "homepage_indicators_synthetic.html").read_bytes()


def _routes(http, *, cc_new=True, carbon="carbondate_ok_synthetic.json"):
    http.add("GET", COLLINFO, json=module_fixture(WebArchivesDeep, "commoncrawl_collinfo.json"))
    if cc_new:
        http.add("GET", index_url(NEW), text=text("commoncrawl_cdx_ok_synthetic.ndjson"), headers={"content-type": "text/x-ndjson"})
    http.add("GET", index_url(OLD), status=404, json=module_fixture(WebArchivesDeep, "commoncrawl_cdx_not_found.json"))
    http.add("GET", WARC_URL, status=206, body=warc_record(snapshot_html()), headers={"content-type": "application/octet-stream"},
             match_headers={"Range": "bytes=567890-569123"})
    if carbon:
        http.add("GET", CARBON, json=module_fixture(WebArchivesDeep, carbon))
    return http


def test_contract_metadata():
    cls = WebArchivesDeep
    assert cls.default_enabled is False and cls.fetches_target is True and cls.terms == "open"
    assert cls.hosts == ("index.commoncrawl.org", "data.commoncrawl.org", "carbondate.cs.odu.edu")
    assert cls.sources == ("commoncrawl.cdx_index", "commoncrawl.web_archives_deep_warc", "odu_carbondate.carbondate")


def test_latest_crawls_warc_homepage_and_carbondate():
    http = _routes(FakeHttp())
    res = run_module(WebArchivesDeep, "domain:example.com", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["archive_sources"][f"commoncrawl_{NEW}"] == "ok" and a["archive_sources"][f"commoncrawl_{OLD}"].startswith("empty")
    assert a["archive_first"] == "2026-11-08T12:34:56Z" and a["archive_count"] == 2
    assert "https://example.com/?sessionid=***" in a["archived_urls"]  # session id masked
    assert a["homepage_indicators"]["source"] == "commoncrawl" and a["homepage_indicators"]["cnpjs"] == ["00.000.000/0001-91"]
    assert a["archive_estimate"]["estimated_creation"] == "2002-01-20T14:25:10Z"
    assert "never a registration date" in res.findings[0].description
    assert all(not p.expand for p in res.pivots)
    assert "https://example.com/?sessionid=***" not in {p.entity.value for p in res.pivots}
    assert "Todos os direitos" not in str(res.raw) and "Todos os direitos" not in str(res.attributes)
    warc = [c for c in http.calls if c["url"] == WARC_URL]
    assert len(warc) == 1 and warc[0]["headers"].get("Range") == "bytes=567890-569123"
    http.assert_hosts_within(WebArchivesDeep)


def test_index_reset_backs_off_and_never_says_never_archived():
    recorded = module_fixture(WebArchivesDeep, "commoncrawl_cdx_connection_reset.json")
    assert recorded["http_status"] is None
    http = FakeHttp()
    http.add("GET", COLLINFO, json=module_fixture(WebArchivesDeep, "commoncrawl_collinfo.json"))
    http.add("GET", index_url(NEW), error=NetworkError("ConnectionError contacting index.commoncrawl.org: Connection reset by peer"))
    http.add("GET", CARBON, json=module_fixture(WebArchivesDeep, "carbondate_empty.json"))
    res = run_module(WebArchivesDeep, "domain:example.com", http)
    assert not [c for c in http.calls if OLD in c["url"]]  # backoff: the older crawl is not asked
    assert res.attributes["archive_sources"][f"commoncrawl_{NEW}"].startswith("could_not_verify") and "archive unreachable" in res.attributes["archive_sources"][f"commoncrawl_{NEW}"]
    assert res.source_statuses["commoncrawl.cdx_index"]["status"] == "error"
    assert res.attributes["archive_sources"]["carbondate"].startswith("empty") and "never 'new site'" in res.attributes["archive_sources"]["carbondate"]
    assert "never archived" not in str(res.attributes).lower()


def test_everything_unreachable_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", COLLINFO, status=504, text="Gateway Time-out")
    http.add("GET", CARBON, error=NetworkError("ReadTimeout contacting carbondate.cs.odu.edu: timed out"))
    res = run_module(WebArchivesDeep, "domain:example.com", http)
    assert res.status is Status.ERROR and "could not verify" in res.error and "archive unreachable" in res.error


def test_carbondate_never_receives_tokens_query_strings_or_identifiers():
    assert D.carbondate_path("https://example.com/") == "/cd/example.com"
    assert D.carbondate_path("example.com/about") == "/cd/example.com/about"
    for bad in ("https://example.com/?token=0123456789abcdef0123", "https://user:pass@example.com/", "https://example.com/u/alice@example.com",
                "https://example.com/#frag", "ftp://example.com/", "", None):
        assert D.carbondate_path(bad) is None, bad
    http = FakeHttp()
    http.add("GET", COLLINFO, json=module_fixture(WebArchivesDeep, "commoncrawl_collinfo.json"))
    url = "https://example.com/login?session=0123456789abcdef0123"
    http.add("GET", index_url(NEW, "https://example.com/login", domain=False), status=404, json=module_fixture(WebArchivesDeep, "commoncrawl_cdx_not_found.json"))
    http.add("GET", index_url(OLD, "https://example.com/login", domain=False), status=404, json=module_fixture(WebArchivesDeep, "commoncrawl_cdx_not_found.json"))
    http.add("GET", "https://carbondate.cs.odu.edu/cd/example.com/login", json=module_fixture(WebArchivesDeep, "carbondate_noscheme_empty.json"))
    res = run_module(WebArchivesDeep, "url:" + url, http)
    assert res.status is Status.OK
    assert not [c for c in http.calls if "0123456789abcdef0123" in c["url"]]


def test_parsers():
    info = D.parse_collinfo(module_fixture(WebArchivesDeep, "commoncrawl_collinfo.json"), 2)
    assert [i["id"] for i in info["indexes"]] == [NEW, OLD] and info["total"] == 5
    assert D.parse_collinfo([{"id": "CC-MAIN-2026-47", "cdx-api": "https://evil.example/CC-MAIN-2026-47-index"}])["indexes"] == []
    rows = D.parse_cc_cdx(text("commoncrawl_cdx_ok_synthetic.ndjson"))["rows"]
    assert rows[0]["_filename"].startswith("crawl-data/CC-MAIN-2026-47/") and rows[1]["secret_masked"] is True
    assert D.record_request(rows[0])["headers"]["Range"] == "bytes=567890-569123"
    assert D.record_request({"_filename": "crawl-data/../../etc/passwd.warc.gz", "_offset": "1", "_length": "2"}) is None
    assert D.record_request({**rows[0], "_length": str(2 * 1024 * 1024)}) is None
    est = D.parse_carbondate(module_fixture(WebArchivesDeep, "carbondate_ok_synthetic.json"))
    assert est["state"] == "ok" and est["sources"]["archives"] == "2002-01-20T14:25:10Z"
    assert D.parse_carbondate(module_fixture(WebArchivesDeep, "carbondate_empty.json"))["state"] == "empty"
    assert D.parse_carbondate("<html>busy</html>")["state"] == "error"


def test_warc_record_parsing_is_bounded():
    html = snapshot_html()
    for chunked, gz in ((False, False), (True, False), (False, True)):
        rec = D.parse_warc_record(warc_record(html, chunked=chunked, gzip_body=gz))
        assert rec["http_status"] == 200 and rec["body"].startswith(b"<!DOCTYPE html>"), (chunked, gz)
    assert D.parse_warc_record(b"not gzip") is None
    assert D.parse_warc_record(gzip.compress(b"WARC/1.0\r\nWARC-Type: request\r\n\r\nGET / HTTP/1.1\r\n\r\n")) is None
    bomb = gzip.compress(b"WARC/1.0\r\nWARC-Type: response\r\n\r\nHTTP/1.1 200 OK\r\n\r\n" + b"a" * (5 * 1024 * 1024))
    rec = D.parse_warc_record(bomb, limit=1024)
    assert rec is None or len(rec["body"]) <= 1025


def test_url_pivots_are_archived_url_expand_false():
    http = _routes(FakeHttp(), carbon="carbondate_empty.json")
    res = run_module(WebArchivesDeep, "domain:example.com", http)
    urls = [p for p in res.pivots if p.entity.type is T.URL]
    assert urls and all(p.relation == "archived_url" and p.expand is False for p in urls)
