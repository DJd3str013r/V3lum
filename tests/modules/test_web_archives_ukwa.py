"""web_archives_ukwa (P059 cond 3): disabled until the UK Web Archive answers.

Fixture in tests/fixtures/web_archives_ukwa/: the real 403 'Under Maintenance' page recorded on
2026-11-25 and 2026-11-26 (title and main paragraph kept).
"""

from __future__ import annotations

from urllib.parse import urlencode

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.modules.url_web.web_archives_ukwa import WebArchivesUkwa

CDX = "https://www.webarchive.org.uk/wayback/archive/cdx?" + urlencode({"url": "example.com/*", "output": "json"})
ENABLED = {"web_archives_ukwa_enabled": True}


def page():
    return (FIXTURES / "web_archives_ukwa" / "ukwa_cdx_403_maintenance.html").read_text(encoding="utf-8")


def test_contract_metadata():
    cls = WebArchivesUkwa
    assert cls.default_enabled is False and cls.terms == "unknown" and cls.hosts == ("www.webarchive.org.uk",)
    assert cls.max_requests == 1


def test_disabled_until_it_answers():
    http = FakeHttp()
    res = run_module(WebArchivesUkwa, "domain:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and http.calls == []


def test_403_maintenance_page_is_could_not_verify():
    http = FakeHttp().add("GET", CDX, status=403, text=page())
    res = run_module(WebArchivesUkwa, "domain:example.com", http, settings=ENABLED)
    assert res.status is Status.ERROR and "maintenance" in res.error.lower() and "never 'no captures'" in res.error
    http.assert_hosts_within(WebArchivesUkwa)


def test_answering_service_is_parsed_like_pywb_ndjson():
    body = '{"urlkey": "com,example)/", "timestamp": "20120305101010", "url": "http://example.com/", "mime": "text/html", "status": "200"}\n'
    http = FakeHttp().add("GET", CDX, text=body, headers={"content-type": "text/x-ndjson"})
    res = run_module(WebArchivesUkwa, "domain:example.com", http, settings=ENABLED)
    assert res.status is Status.OK and res.attributes["archive_first"] == "2012-03-05T10:10:10Z"
    assert [p.expand for p in res.pivots] == [False]
    empty = FakeHttp().add("GET", CDX, text="", headers={"content-type": "text/x-ndjson"})
    assert run_module(WebArchivesUkwa, "domain:example.com", empty, settings=ENABLED).status is Status.EMPTY
    limited = FakeHttp().add("GET", CDX, status=429, text="slow down")
    assert run_module(WebArchivesUkwa, "domain:example.com", limited, settings=ENABLED).status is Status.RATE_LIMITED
