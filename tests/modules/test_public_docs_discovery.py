"""public_docs_discovery (P287): passive document discovery - offline tests with tests/fakes.py.

Proves: archives first (Wayback CDX + Common Crawl), archived copies only (the live site is never
contacted), Brave only when both archives found nothing (seed, key, URL + title, never cached),
per-source 'could not verify' (never 'no documents'), the caps, token URLs never fetched and the
minimisation of names/usernames for third-party domains.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import public_docs_discovery as pdd
from v3lum.modules.pentest_recon.public_docs_discovery import PublicDocsDiscovery

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "public_docs_discovery"
DOMAIN = "example.com"
CDX = "https://web.archive.org/cdx/search/cdx*"
RAW = "https://web.archive.org/web/"
COLLINFO = "https://index.commoncrawl.org/collinfo.json"
CC_INDEX = "https://index.commoncrawl.org/CC-MAIN-2026-47-index*"
BRAVE = "https://api.search.brave.com/res/v1/web/search*"
NAMES = ("Fulano", "Beltrano", "bsilva", "fsilva", "ciclano", "contato@")


def raw(name):
    return (FIXTURES / name).read_bytes()


def archives(http, *, cdx="wayback_cdx_ok.json", cc="cc_index_ok.ndjson", cc_status=200):
    http.add("GET", CDX, body=raw(cdx), headers={"content-type": "application/json"}, times=1)
    http.add("GET", CDX, body=raw("wayback_cdx_empty.json"), headers={"content-type": "application/json"})
    http.add("GET", COLLINFO, body=raw("cc_collinfo_ok.json"), headers={"content-type": "application/json"})
    http.add("GET", CC_INDEX, status=cc_status, body=raw(cc), headers={"content-type": "text/x-ndjson"})
    return http


def copies(http):
    http.add("GET", RAW + "20240315101010id_/https://www.example.com/arquivos/relatorio-anual-2023.pdf", body=raw("doc_ok.pdf"),
             headers={"content-type": "application/pdf"})
    http.add("GET", RAW + "20230102030405id_/http://example.com/docs/politica-de-privacidade.docx", body=raw("doc_ok.docx"),
             headers={"content-type": "application/octet-stream"})
    soft = module_fixture("public_docs_discovery", "doc_soft404.http.json")["response"]
    http.add("GET", RAW + "20220506070809id_/https://intranet.example.com/rh/planilha-ferias.xlsx", status=200, text=soft["body"],
             headers=soft["headers"])
    http.add("GET", RAW + "*", status=404, text="not archived")
    http.add("GET", "https://data.commoncrawl.org/*", status=404, text="no")
    return http


def test_archives_first_copies_parsed_and_names_withheld_for_third_parties():
    http = copies(archives(FakeHttp()))
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.OK, res.error
    docs = res.attributes["public_docs"]
    assert docs["documents"] == 2 and docs["personal_minimised"] is True
    assert docs["authors_count"] >= 1 and docs["usernames_count"] >= 1
    assert docs["author_samples"] == [] and docs["username_samples"] == []
    blob = json.dumps(res.attributes) + json.dumps([f.description for f in res.findings]) + json.dumps([p.entity.value for p in res.pivots])
    assert not any(n in blob for n in NAMES)
    urls = {p.entity.value for p in res.pivots}
    assert "https://www.example.com/arquivos/relatorio-anual-2023.pdf" in urls
    assert not any("token=" in u or "secret" in u or "example-evil" in u for u in urls)
    assert all(p.expand is False for p in res.pivots)
    cov = res.attributes["public_docs_coverage"]
    assert cov["wayback"] == "ok" and cov["commoncrawl"] == "ok" and cov["brave"].startswith("not_queried")
    assert cov["downloads"]["parsed"] == 2 and cov["downloads"]["failed"] >= 1  # the soft-404 HTML copy was rejected
    assert not [c for c in http.calls if "www.example.com" in c["url"].split("/")[2]]  # the live site is never contacted
    assert not [c for c in http.calls if "token=" in c["url"]]
    assert not [c for c in http.calls if c["url"].startswith("https://api.search.brave.com")]
    http.assert_hosts_within(PublicDocsDiscovery)


def test_verified_or_in_scope_domain_keeps_at_most_five_samples_unexpanded():
    http = copies(archives(FakeHttp()))
    scope = Scope.from_dict({"authorization_ref": "PENTEST-2026-042", "owner": "o", "contacts": ["soc@acme.example"], "ticket": "t",
                             "window_start": "2026-11-26T00:00:00Z", "window_end": "2026-11-27T00:00:00Z",
                             "targets": {"domains": [DOMAIN, f"*.{DOMAIN}"]}})
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http, options=ScanOptions(scope=scope))
    docs = res.attributes["public_docs"]
    assert docs["personal_minimised"] is False and 1 <= len(docs["author_samples"]) <= 5
    people = [p for p in res.pivots if p.relation == "public_document_author"]
    assert people and all(p.expand is False for p in people)


def test_aggregate_minimises_and_redacts_user_segments():
    records = module_fixture("public_docs_discovery", "docmeta_records.json")
    third = pdd.aggregate_doc_metadata(records)
    assert third["documents"] == 5 and third["emails_count"] >= 1
    assert not any(n in json.dumps(third) for n in NAMES)
    assert any("[user]" in p for p in third["internal_paths"])
    own = pdd.aggregate_doc_metadata(records, personal_allowed=True)
    assert len(own["author_samples"]) <= 5 and "contato@example.com" not in json.dumps(own)


def test_cdx_parser_skips_revisits_offsite_tokens_and_userinfo():
    parsed = pdd.parse_cdx_docs(raw("wayback_cdx_ok.json"), DOMAIN)
    urls = [r["url"] for r in parsed["rows"]]
    assert parsed["resume_key"] and parsed["skipped"]["revisit"] == 1 and parsed["skipped"]["off_domain"] == 1
    assert "https://www.example.com/old/manual.doc" in urls  # userinfo stripped, never kept
    assert all("secret" not in u for u in urls)
    token = [r for r in parsed["rows"] if "token=" in r["url"]]
    assert token and token[0]["token_reason"]
    plan = pdd.plan_downloads(parsed["rows"])
    assert all("token=" not in p["url"] for p in plan["planned"])
    malformed = pdd.parse_cdx_docs(raw("wayback_cdx_malformed.json"), DOMAIN)
    assert malformed["partial"] or malformed["state"] == "malformed"
    assert pdd.parse_cdx_docs(raw("wayback_cdx_blocked.txt"), DOMAIN)["state"] == "blocked"
    assert pdd.parse_cdx_docs(raw("wayback_cdx_empty.json"), DOMAIN)["state"] == "empty"


def test_blocked_site_is_could_not_verify_even_when_cc_is_empty():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_blocked.txt", cc="cc_index_not_found.json", cc_status=404)
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    # the primary archive could not be read: never 'no documents' (rule 5), whatever Common Crawl said
    assert res.status is Status.ERROR and "wayback could not be queried" in res.error and "commoncrawl answered" in res.error
    cov = res.attributes["public_docs_coverage"]
    assert cov["wayback"] == "could_not_verify" and cov["commoncrawl"] == "empty" and cov["brave"] == "needs_key"
    assert res.source_statuses["internet_archive.wayback"]["status"] == "error"
    assert res.source_statuses["brave_search.web"]["status"] == "needs_key"


def test_both_archives_answering_empty_is_empty():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json", cc="cc_index_not_found.json", cc_status=404)
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.EMPTY, res.error
    cov = res.attributes["public_docs_coverage"]
    assert cov["wayback"] == "empty" and cov["commoncrawl"] == "empty"


def test_commoncrawl_error_in_200_is_could_not_verify_never_empty():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json", cc="wayback_cdx_blocked.txt", cc_status=200)
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.ERROR and "commoncrawl could not be queried" in res.error, (res.status, res.error)
    assert res.attributes["public_docs_coverage"]["commoncrawl"] == "could_not_verify"
    assert res.source_statuses["commoncrawl.cdx_index"]["status"] == "error"
    assert pdd.parse_cc_docs(b'{"error": "Internal Error"}', DOMAIN)["state"] == "error"
    assert pdd.parse_cc_docs(b"", DOMAIN)["state"] == "error"
    assert pdd.parse_cc_docs(b"<html>No such collection</html>", DOMAIN, http_status=404)["state"] == "error"
    assert pdd.parse_cc_docs(raw("cc_index_not_found.json"), DOMAIN, http_status=404)["state"] == "empty"


def test_offline_mode_is_unavailable_never_empty():
    from v3lum.core.http import OfflineError

    http = FakeHttp()
    http.add("GET", CDX, error=OfflineError("offline: request not sent"))
    http.add("GET", COLLINFO, error=OfflineError("offline: request not sent"))
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline", (res.status, res.error)


def test_every_source_down_is_error_never_empty():
    http = FakeHttp()
    http.add("GET", CDX, error=NetworkError("connection reset by peer", kind="ConnectionError"))
    http.add("GET", COLLINFO, status=503, text="overloaded")
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_429_from_the_archives_is_rate_limited():
    http = FakeHttp()
    http.add("GET", CDX, status=429, text="Too Many Requests")
    http.add("GET", COLLINFO, status=429, text="slow down")
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.RATE_LIMITED


def test_brave_fallback_only_when_archives_find_nothing():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json", cc="cc_index_not_found.json", cc_status=404)
    brave = module_fixture("public_docs_discovery", "brave_ok.http.json")
    http.add("GET", BRAVE, json=brave["body"], headers=brave["headers"], match_headers={"x-subscription-token": "brave-test-key"})
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http, keys={"brave_search": "brave-test-key"})
    assert res.status is Status.OK, res.error
    urls = {p.entity.value for p in res.pivots}
    assert "https://www.example.com/arquivos/relatorio-anual-2023.pdf" in urls and not any("other.example.org" in u for u in urls)
    assert "snippet" not in json.dumps(res.attributes)
    assert res.attributes["public_docs_coverage"]["brave"] == "ok"
    brave_calls = [c for c in http.calls if c["url"].startswith("https://api.search.brave.com")]
    assert len(brave_calls) == 1 and "filetype%3Apdf" in brave_calls[0]["url"]
    assert not [c for c in http.calls if "licitacoes.example.com" in c["url"].split("/")[2]]  # Brave-only URLs are never fetched


def test_brave_422_is_needs_key_and_pivots_never_search():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json", cc="cc_index_not_found.json", cc_status=404)
    bad = module_fixture("public_docs_discovery", "brave_needs_key.http.json")
    http.add("GET", BRAVE, status=bad["status"], json=bad["body"], headers={"content-type": "application/json"})
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http, keys={"brave_search": "brave-test-key"})
    assert res.source_statuses["brave_search.web"]["status"] == "needs_key" and res.status is Status.EMPTY
    http2 = FakeHttp()
    archives(http2, cdx="wayback_cdx_empty.json", cc="cc_index_not_found.json", cc_status=404)
    pivot = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http2, keys={"brave_search": "brave-test-key"}, is_seed=False, depth=1)
    assert pivot.attributes["public_docs_coverage"]["brave"].startswith("not_queried")
    assert not [c for c in http2.calls if "brave" in c["url"]]


def test_brave_quota_and_rate_limit_codes():
    for name, expected in (("brave_quota.http.json", "quota"), ("brave_rate_limited.http.json", "rate_limited")):
        fixture = module_fixture("public_docs_discovery", name)
        reason = pdd.classify_search_error(fixture["status"], json.dumps(fixture["body"]))
        assert reason.startswith(expected)


def test_licence_profile_narrowing_skips_brave():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json", cc="cc_index_not_found.json", cc_status=404)
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http, keys={"brave_search": "k"},
                     allowed_sources=("internet_archive.wayback", "commoncrawl.cdx_index", "commoncrawl.public_docs_discovery_warc"))
    assert res.attributes["public_docs_coverage"]["brave"].startswith("not_queried")


def test_discovery_only_setting_downloads_nothing():
    http = archives(FakeHttp())
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http, settings={"public_docs_discovery_max_documents": 0})
    assert res.status is Status.OK
    assert not [c for c in http.calls if c["url"].startswith(RAW) or "data.commoncrawl.org" in c["url"]]


def test_commoncrawl_warc_copy_is_read_by_range():
    http = FakeHttp()
    archives(http, cdx="wayback_cdx_empty.json")
    pdf = raw("doc_ok.pdf")
    record = (b"WARC/1.0\r\nWARC-Type: response\r\nContent-Length: 1\r\n\r\n"
              b"HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n" + pdf)
    http.add("GET", "https://data.commoncrawl.org/crawl-data/*", status=206, body=gzip.compress(record), match_headers={"range": "bytes=123456789-123626788"},
             times=1)
    http.add("GET", "https://data.commoncrawl.org/*", status=404, text="no")
    res = run_module(PublicDocsDiscovery, f"domain:{DOMAIN}", http)
    assert res.status is Status.OK
    assert res.attributes["public_docs"]["documents"] >= 1
    assert res.attributes["public_docs"]["copies"][0]["copy"] == "commoncrawl"


def test_download_markers_and_warc_parsing():
    soft = module_fixture("public_docs_discovery", "doc_soft404.http.json")["response"]
    assert pdd.doc_download_marker(200, soft["headers"], soft["body"].encode(), "pdf").startswith("not_found")
    assert pdd.doc_download_marker(200, {}, raw("doc_ok.pdf")[:512], "pdf") is None
    assert pdd.doc_download_marker(200, {}, raw("doc_ok.pdf")[:512], "docx").startswith("error: magic")
    assert pdd.doc_download_marker(200, {"content-length": str(11 * 1024 * 1024)}, b"%PDF-", "pdf").startswith("policy")
    assert pdd.doc_download_marker(429, {}, b"", "pdf").startswith("rate_limited")
    assert pdd.warc_record_body(b"not gzip") == (None, b"")
    assert pdd.url_token_reason("https://www.example.com/relatorio-anual-2023-final.pdf") is None
    assert pdd.url_token_reason("https://www.example.com/d?token=abcdef0123456789") is not None
