"""web_archives (P059): Wayback availability + CDX summary + archived homepage, Arquivo.pt, rule 5,
redaction of archived URLs and the 15 s budget.

Fixtures in tests/fixtures/web_archives/: real Wayback availability answers recorded 2026-11-26
(newest, earliest with timestamp=19960101, empty, and the 'Error: no url parameter' error-in-200 body),
the recorded transport outcome of the CDX connection reset (web.archive.org reset every connection from
the datacenter egress), synthetic CDX JSON bodies in the documented format (ok with resume key,
truncated, Blocked Site Error), real Arquivo.pt CDX NDJSON (example.com with the user:pass@ sample,
registro.br, an empty body) plus a derived truncated body, a real Arquivo.pt id_ snapshot of
example.com and of registro.br (head plus a short excerpt), and a synthetic homepage with analytics
ids and the public BB CNPJ 00.000.000/0001-91.
"""

from __future__ import annotations

import json
from urllib.parse import urlencode

import pytest

from tests.fakes import FIXTURES, FakeHttp, assert_no_secret, make_ctx, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.url_web import web_archives as WA
from v3lum.modules.url_web.web_archives import WebArchives

F = FIXTURES / "web_archives"
AVAIL = "https://archive.org/wayback/available?url={}"
CDX_PARAMS = {"output": "json", "fl": "original,timestamp,statuscode,mimetype", "collapse": "urlkey", "limit": "5000", "showResumeKey": "true"}
RESET = NetworkError("ConnectionError contacting web.archive.org: ('Connection aborted.', ConnectionResetError(104, 'Connection reset by peer'))")


def text(name):
    return (F / name).read_text(encoding="utf-8", errors="replace")


def cdx_url(query, match="domain", **extra):
    return "https://web.archive.org/cdx/search/cdx?" + urlencode({"url": query, "matchType": match, **CDX_PARAMS, **extra})


def arquivo_url(query, limit="2000"):
    return "https://arquivo.pt/wayback/cdx?" + urlencode({"url": query, "output": "json", "limit": limit})


def ndjson(http, url, name):
    return http.add("GET", url, text=text(name), headers={"content-type": "text/x-ndjson"})


def everything(res):
    return json.dumps({"attributes": res.attributes, "raw": res.raw, "findings": [f.to_dict() for f in res.findings],
                       "pivots": [p.entity.value for p in res.pivots], "links": res.links, "error": res.error,
                       "sources": res.source_statuses}, default=str)


# =================================================================== metadata
def test_contract_metadata():
    cls = WebArchives
    assert (cls.terms, cls.disclosure, cls.default_enabled, cls.trust_tier, cls.run_on) == ("open", "third_party", True, "trusted", "seeds")
    assert cls.hosts == ("archive.org", "web.archive.org", "arquivo.pt")
    assert cls.sources == ("internet_archive.wayback", "internet_archive.web_archives_cdx", "arquivo_pt.cdx")
    assert cls.max_requests <= 10 and cls.expected_latency <= 10


# =================================================================== happy path
def _happy(http):
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_ok.json"))
    http.add("GET", cdx_url("example.com"), json=module_fixture(WebArchives, "wayback_cdx_ok_synthetic.json"))
    http.add("GET", "https://web.archive.org/web/20261126034206id_/https://example.com/", text=text("arquivo_snapshot_example.html"))
    return http


def test_default_scan_summary_snapshot_and_pivots():
    http = _happy(FakeHttp())
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    assert a["archive_first"] == "2002-01-20T14:25:10Z" and a["archive_last"] == "2026-11-26T03:42:06Z"
    assert a["archive_count"] == 5 and a["archive_sources"]["wayback_availability"] == "ok"
    assert a["archive_snapshot"]["url"] == "https://web.archive.org/web/20261126034206/https://example.com/"
    assert a["homepage_indicators"]["title"] == "Example Web Page" and len(a["homepage_indicators"]["sha256"]) == 64
    assert "partial" in a["archive_sources"]["wayback_cdx"]  # the resume key says more pages exist: never complete
    assert res.partial and res.stop_reason == "request_cap"
    history = [f for f in res.findings if f.title == "Web archive history"][0]
    assert "never a registration date" in history.description and history.observed_first == "2002-01-20T14:25:10Z"
    assert all(p.expand is False for p in res.pivots)
    assert {p.relation for p in res.pivots if p.entity.type is T.URL} == {"archived_url"}
    assert "https://www.example.com/favicon.ico" not in {p.entity.value for p in res.pivots}  # images are noise
    assert any(label.startswith("Wayback Machine: closest") for label, _ in res.links)
    http.assert_hosts_within(WebArchives)
    assert not [c for c in http.calls if "/save" in c["url"]]  # Save Page Now is never called (c7)
    assert [c["url"].split("/")[2] for c in http.calls] == ["archive.org", "web.archive.org", "web.archive.org"]


def test_userinfo_and_tokens_are_masked_everywhere():
    """P059 c5 unit test with the recorded user:pass@ sample (Arquivo.pt CDX of example.com)."""
    http = _happy(FakeHttp())
    res = run_module(WebArchives, "domain:example.com", http)
    blob = everything(res)
    assert_no_secret("user:pass", blob)
    assert_no_secret("0123456789abcdef0123", blob)
    assert "http://***@example.com/" in res.attributes["archived_urls"]
    leak = [f for f in res.findings if f.title.startswith("Archived URLs carried")][0]
    assert set(leak.data["kinds"]) == {"userinfo", "query_secret"} and leak.severity.label == "info"
    assert not [p for p in res.pivots if "***" in p.entity.value]  # masked URLs are never pivots
    rows = WA.parse_arquivo_cdx(text("arquivo_cdx_ok.ndjson"))["rows"]
    assert rows[0]["url"] == "http://***@example.com/" and rows[0]["secret_masked"] is True
    assert_no_secret("user:pass", json.dumps([{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]))


@pytest.mark.parametrize("url,expected,kinds", [
    ("http://user:pass@example.com/", "http://***@example.com/", ["userinfo"]),
    ("https://example.com/a?token=0123456789abcdef0123&x=1", "https://example.com/a?token=***&x=1", ["query_secret"]),
    ("https://example.com/;jsessionid=ABCDEF0123456789?a=1", "https://example.com/;jsessionid=***?a=1", ["path_session_id"]),
    ("https://example.com/u/alice@example.com/profile", "https://example.com/u/***/profile", ["email"]),
    ("https://example.com/reset?mail=alice%40example.com", "https://example.com/reset?mail=***", ["query_secret"]),
    ("https://example.com/p?ref=Zx9Kq2Lm8Np4Rs7T", "https://example.com/p?ref=***", ["opaque_token"]),
    ("https://example.com/docs/report.pdf?page=2", "https://example.com/docs/report.pdf?page=2", []),
])
def test_redact_archived_url(url, expected, kinds):
    assert WA.redact_archived_url(url) == (expected, kinds)


def test_archive_snapshot_urls_only_on_archive_hosts():
    assert WA.archive_snapshot_url("wayback", "20020120142510", "http://example.com/") == "https://web.archive.org/web/20020120142510id_/http://example.com/"
    assert WA.archive_snapshot_url("arquivo", "20091222153217", "http://www.example.com/") == "https://arquivo.pt/wayback/20091222153217id_/http://www.example.com/"
    assert WA.archive_snapshot_url("wayback", "20020120142510", "http://user:pass@example.com/") is None  # never fetched
    assert WA.archive_snapshot_url("live", "20020120142510", "http://example.com/") is None
    assert WA.archive_snapshot_url("wayback", "bad", "http://example.com/") is None
    assert WA.archive_snapshot_url("wayback", "20020120142510", "javascript:alert(1)") is None


def test_homepage_indicators_keep_no_body():
    body = text("homepage_indicators_synthetic.html")
    ind = WA.homepage_indicators(body)
    assert {i["id"] for i in ind["analytics_ids"]} == {"UA-1234567-1", "G-ABC123XYZ9", "GTM-W2XYZ9K", "ca-pub-1234567890123456"}
    assert ind["cnpjs"] == ["00.000.000/0001-91"]  # 11.111.111/1111-11 has invalid check digits
    assert ind["lang"] == "pt-br" and ind["generator"] == "WordPress 6.4.2" and ind["meta_refresh"] == "https://www.example.com/login"
    assert "Todos os direitos" not in json.dumps(ind)
    big = WA.homepage_indicators("<title>x</title>" + "a" * (WA.HOMEPAGE_MAX_BYTES + 10))
    assert big["truncated"] is True and big["bytes"] == WA.HOMEPAGE_MAX_BYTES
    latin = WA.homepage_indicators((F / "arquivo_snapshot_registrobr.html").read_bytes())
    assert latin["title"] == "Registro.br" and latin["lang"] == "pt-br"


def test_homepage_pivots_are_expand_false():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_ok.json"))
    http.add("GET", cdx_url("example.com"), json=[["original", "timestamp", "statuscode", "mimetype"]])
    http.add("GET", "https://web.archive.org/web/20261126034206id_/https://example.com/", text=text("homepage_indicators_synthetic.html"))
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_empty.ndjson")  # lang pt-BR on the homepage: Arquivo.pt asked too
    res = run_module(WebArchives, "domain:example.com", http)
    by_type = {}
    for p in res.pivots:
        by_type.setdefault(p.entity.type, []).append(p)
    assert {p.entity.value for p in by_type[T.ANALYTICS_ID]} >= {"UA-1234567-1", "G-ABC123XYZ9"}
    assert by_type[T.CNPJ][0].relation == "company_of" and all(not p.expand for p in res.pivots)
    assert res.attributes["archive_sources"]["arquivo_pt"].startswith("empty")
    assert_no_secret("Todos os direitos reservados", everything(res))


# =================================================================== Arquivo.pt (c2)
def test_arquivo_is_queried_for_br_domains_even_when_wayback_answers():
    http = FakeHttp()
    http.add("GET", AVAIL.format("registro.br"), json={"url": "registro.br", "archived_snapshots": {}})
    ndjson(http, arquivo_url("registro.br/*"), "arquivo_cdx_br.ndjson")
    http.add("GET", cdx_url("registro.br"), json=[["original", "timestamp", "statuscode", "mimetype"]])
    http.add("GET", "https://arquivo.pt/wayback/20110705092801id_/http://www.registro.br/", body=(F / "arquivo_snapshot_registrobr.html").read_bytes(),
             headers={"content-type": "text/html; charset=iso-8859-1"})
    res = run_module(WebArchives, "domain:registro.br", http)
    assert res.status is Status.OK, res.error
    assert [c["url"].split("/")[2] for c in http.calls][:2] == ["archive.org", "arquivo.pt"]  # interleaved before the CDX
    assert res.attributes["archive_first"] == "2010-05-30T16:38:33Z"
    assert res.attributes["homepage_indicators"]["source"] == "arquivo" and res.attributes["homepage_indicators"]["title"] == "Registro.br"


def test_wayback_cdx_connection_reset_is_archive_unreachable_and_arquivo_is_the_fallback():
    recorded = module_fixture(WebArchives, "wayback_cdx_connection_reset.json")
    assert recorded["http_status"] is None and "reset" in recorded["error"].lower()
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    http.add("GET", cdx_url("example.com"), error=RESET)
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_ok.ndjson")
    http.add("GET", "https://arquivo.pt/wayback/20100401115258id_/http://www.example.com/", text=text("arquivo_snapshot_example.html"))
    http.add("GET", AVAIL.format("example.com") + "&timestamp=19960101", json=module_fixture(WebArchives, "wayback_available_first.json"))
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.OK
    cdx = res.attributes["archive_sources"]["wayback_cdx"]
    assert cdx.startswith("could_not_verify") and "archive unreachable" in cdx
    assert res.source_statuses["internet_archive.web_archives_cdx"]["status"] == "error"
    assert res.attributes["archive_sources"]["arquivo_pt"] == "ok"
    assert res.attributes["archive_first"] == "2002-01-20T14:25:10Z"  # earliest homepage capture from availability
    assert "never archived" not in everything(res).lower()


def test_arquivo_empty_truncated_and_html_bodies():
    assert WA.parse_arquivo_cdx(text("arquivo_cdx_empty.ndjson"))["state"] == "empty"
    cut = WA.parse_arquivo_cdx(text("arquivo_cdx_truncated.ndjson"))
    assert cut["partial"] is True and cut["stop"] == "body_truncated" and len(cut["rows"]) == 3
    assert WA.parse_arquivo_cdx("<html><body>error</body></html>")["state"] == "error"


# =================================================================== rule 5 and markers (c4, c11)
def test_truncated_cdx_body_is_partial_never_complete():
    parsed = WA.parse_wayback_cdx(text("wayback_cdx_truncated_synthetic.json"))
    assert parsed["partial"] is True and parsed["stop"] == "body_truncated" and len(parsed["rows"]) == 3
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    http.add("GET", cdx_url("example.com"), text=text("wayback_cdx_truncated_synthetic.json"), headers={"content-type": "application/json"})
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "request_cap"
    assert "partial: body_truncated" in res.attributes["archive_sources"]["wayback_cdx"]


def test_row_cap_and_resume_key():
    rows = [["original", "timestamp", "statuscode", "mimetype"]] + [[f"http://example.com/p{i}", "20200101000000", "200", "text/html"] for i in range(30)]
    capped = WA.parse_wayback_cdx(json.dumps(rows), row_cap=10)
    assert len(capped["rows"]) == 10 and capped["partial"] and capped["stop"] == "row_cap"
    ok = WA.parse_wayback_cdx(text("wayback_cdx_ok_synthetic.json"))
    assert ok["resume_key"] == "com,example,www)/favicon.ico 20261126034206"


def test_deep_preset_pages_the_cdx_with_the_resume_key():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    page1 = [["original", "timestamp", "statuscode", "mimetype"], ["http://example.com/a", "20200101000000", "200", "text/html"], [], ["k1"]]
    page2 = [["original", "timestamp", "statuscode", "mimetype"], ["http://example.com/b", "20210101000000", "200", "text/html"]]
    http.add("GET", cdx_url("example.com"), json=page1)
    http.add("GET", cdx_url("example.com", resumeKey="k1"), json=page2)
    res = run_module(WebArchives, "domain:example.com", http, options=ScanOptions(preset="deep"))
    assert res.attributes["archive_count"] == 2 and not res.partial
    assert res.attributes["archive_sources"]["wayback_cdx"] == "ok"


def test_availability_error_in_200_is_never_empty():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), text=text("wayback_available_error_in_200.txt"))
    http.add("GET", cdx_url("example.com"), json=module_fixture(WebArchives, "wayback_cdx_ok_synthetic.json"))
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_empty.ndjson")  # the Wayback answer failed: Arquivo.pt fallback
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.attributes["archive_sources"]["wayback_availability"].startswith("could_not_verify")
    assert "no url parameter" in res.source_statuses["internet_archive.wayback"]["reason"]
    assert WA.parse_wayback_available(text("wayback_available_error_in_200.txt"))["state"] == "error"


def test_blocked_site_is_could_not_verify_not_no_captures():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    http.add("GET", cdx_url("example.com"), status=403, text=text("wayback_cdx_blocked_synthetic.txt"), headers={"content-type": "text/plain"})
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_empty.ndjson")
    http.add("GET", AVAIL.format("example.com") + "&timestamp=19960101", json=module_fixture(WebArchives, "wayback_available_empty.json"))
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.ERROR and "could not verify" in res.error and "excluded" in res.error
    assert "never archived" not in res.error.lower()


def test_everything_unreachable_is_error_never_absent():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), error=NetworkError("ReadTimeout contacting archive.org: timed out"))
    http.add("GET", cdx_url("example.com"), error=RESET)
    http.add("GET", arquivo_url("example.com/*"), status=504, text="gateway timeout")
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.ERROR and res.reason_code in ("error", "timeout")
    assert "could not verify" in res.error and "archive unreachable" in res.error
    assert {s["status"] for s in res.source_statuses.values()} == {"error"}


def test_all_archives_answer_empty_is_empty():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.org"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    http.add("GET", cdx_url("example.org"), json=[])
    http.add("GET", AVAIL.format("example.org") + "&timestamp=19960101", json=module_fixture(WebArchives, "wayback_available_empty.json"))
    res = run_module(WebArchives, "domain:example.org", http)
    assert res.status is Status.EMPTY and not res.findings  # no captures never means a new domain


def test_cdx_429_is_rate_limited_for_that_source_only():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_ok.json"))
    http.add("GET", cdx_url("example.com"), status=429, text="Too Many Requests")
    http.add("GET", "https://web.archive.org/web/20261126034206id_/https://example.com/", text=text("arquivo_snapshot_example.html"))
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_empty.ndjson")
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.status is Status.OK and res.source_statuses["internet_archive.web_archives_cdx"]["status"] == "rate_limited"
    assert res.attributes["archive_last"] == "2026-11-26T03:42:06Z"


def test_malformed_availability_json_is_an_error_not_empty():
    assert WA.parse_wayback_available('{"archived_snapshots": ')["state"] == "error"
    assert WA.parse_wayback_available("<html><head></head><body>x</body></html>")["state"] == "error"
    assert WA.parse_wayback_available({"archived_snapshots": {"closest": {"available": True, "url": "https://evil.example/x"}}})["state"] == "error"
    assert WA.parse_wayback_available(module_fixture(WebArchives, "wayback_available_empty.json"))["state"] == "empty"


# =================================================================== URL seeds and budget
def test_url_seed_with_a_token_is_looked_up_without_the_query_string():
    url = "https://example.com/login?token=0123456789abcdef0123&email=alice@example.com"
    q = WA.query_target(Entity.make(T.URL, url))
    assert q["query"] == "https://example.com/login" and "carry secrets" in q["note"]
    http = FakeHttp()
    http.add("GET", AVAIL.format("https://example.com/login"), json=module_fixture(WebArchives, "wayback_available_empty.json"))
    http.add("GET", cdx_url("https://example.com/login", match="prefix"), json=[])
    http.add("GET", AVAIL.format("https://example.com/login") + "&timestamp=19960101", json=module_fixture(WebArchives, "wayback_available_empty.json"))
    res = run_module(WebArchives, "url:" + url, http)
    assert res.status is Status.EMPTY
    assert_no_secret("0123456789abcdef0123", [c["url"] for c in http.calls])
    assert_no_secret("alice@example.com", [c["url"] for c in http.calls])


def test_budget_skips_sources_once_time_is_up():
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_ok.json"), latency=14.5)
    res = run_module(WebArchives, "domain:example.com", http)
    assert res.attributes["archive_sources"]["wayback_cdx"].startswith("not_run: time budget")
    assert len(http.calls) == 1 and res.status is Status.OK


def test_never_raise_on_junk():
    for junk in (None, 5, "", "x", b"\xff\xfe", [], {}, [[1, 2]], {"archived_snapshots": []}):
        WA.parse_wayback_available(junk)
        WA.parse_wayback_cdx(junk if isinstance(junk, (str, bytes, list)) else "")
        WA.parse_arquivo_cdx(junk if isinstance(junk, (str, bytes)) else "")
        WA.homepage_indicators(junk)
        WA.redact_archived_url(junk)
    assert WA.query_target(Entity.make(T.URL, "https://example.com/")) is not None
    assert not WebArchives().applies(Entity.make(T.URL, "ftp://example.com/x"), make_ctx(WebArchives)) if Entity.try_make(T.URL, "ftp://example.com/x") else True


def test_cdx_reset_skips_the_wayback_snapshot_and_keeps_the_availability_answer():
    """Live behaviour from the datacenter egress: web.archive.org resets while archive.org answers.
    The budget goes to Arquivo.pt instead of a second web.archive.org reset, and the availability
    source that answered is not reported as failed."""
    http = FakeHttp()
    http.add("GET", AVAIL.format("example.com"), json=module_fixture(WebArchives, "wayback_available_ok.json"))
    http.add("GET", cdx_url("example.com"), error=RESET)
    ndjson(http, arquivo_url("example.com/*"), "arquivo_cdx_ok.ndjson")
    http.add("GET", "https://arquivo.pt/wayback/20100401115258id_/http://www.example.com/", text=text("arquivo_snapshot_example.html"))
    http.add("GET", AVAIL.format("example.com") + "&timestamp=19960101", json=module_fixture(WebArchives, "wayback_available_first.json"))
    res = run_module(WebArchives, "domain:example.com", http)
    sources = res.attributes["archive_sources"]
    assert sources["wayback_homepage_snapshot"] == "not_run: web.archive.org unreachable (see wayback_cdx)"
    assert not [c for c in http.calls if "/web/20261126034206id_/" in c["url"]]
    assert res.attributes["homepage_indicators"]["source"] == "arquivo"
    assert "internet_archive.wayback" not in res.source_statuses  # availability answered
    assert res.source_statuses["internet_archive.web_archives_cdx"]["reason_code"] == "error"
    assert res.attributes["archive_first"] == "2002-01-20T14:25:10Z"  # earliest capture through the availability API
