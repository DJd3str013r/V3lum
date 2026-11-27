"""public_api_exposure (P069, batch p3-G03-1): Postman public search metadata + APIs.guru directory.

Fixtures in tests/fixtures/public_api_exposure/ (prep 2026-11-26, minimised and scrubbed; individual
publishers pseudonymised as example-user-NNNN, secret values replaced by EXAMPLE-NOT-A-SECRET):
postman_public_search.json (the research record's recorded sample, P069 cond 7), postman_ok_example.json /
postman_page2_example.json / postman_ok_cloudflare.json / postman_nohit_fuzzy.json (live answers),
postman_empty.json (derived), postman_secret_in_url.json, postman_schema_changed*.json,
postman_error_envelope.json, postman_html_spa_200.html and postman_challenge_403.html (synthetic in
the observed shape); apisguru_list_ok.json (8 real entries of list.json), apisguru_list_truncated.json
(derived), apisguru_list_wrong_type.json / apisguru_list_html.html (synthetic), apisguru_metrics.json
(the research record's recorded sample, cond 7) and apisguru_metrics_live.json.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core import datasets, links, providers
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import public_api_exposure as M
from v3lum.modules.url_web.public_api_exposure import PublicApiExposure

URL = M.POSTMAN_SEARCH_URL
FX = Path(__file__).resolve().parent.parent / "fixtures" / "public_api_exposure"
ORG = {"domains": [{"name": "example.com", "verification": "confirmed"}], "brands": [{"keyword": "ExampleBrand"}]}
NOW = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)


def fx(name: str):
    return module_fixture(PublicApiExposure, name)


def raw(name: str) -> bytes:
    return (FX / name).read_bytes()


def org() -> OrgProfile:
    return OrgProfile.from_dict(ORG)


def postman_bodies(http: FakeHttp) -> list[dict]:
    return [json.loads(c["body"]) for c in http.calls if c["method"] == "POST" and c["url"] == URL]


@pytest.fixture()
def env(monkeypatch):
    """A runtime over FakeHttp (frozen clock) and an installer that serves the APIs.guru files at their
    registered URLs through the real `v3lum data update` path (download, validator, atomic install)."""
    http = FakeHttp()
    rt = make_runtime(http, clock=FakeClock(), org_profile=org())
    monkeypatch.setitem(datasets.DATASETS[M.APISGURU_LIST], "min_bytes", 1)  # the fixture is 8 entries of a 8.9 MB file
    monkeypatch.setattr(M, "APISGURU_MIN_ENTRIES", 1)

    def install(list_name: str = "apisguru_list_ok.json", metrics: str | None = "apisguru_metrics.json"):
        http.add("GET", M.APISGURU_LIST_URL, body=raw(list_name), headers={"content-type": "application/json"}, times=1)
        assert rt.data.update(M.APISGURU_LIST).ok
        if metrics:
            http.add("GET", M.APISGURU_METRICS_URL, body=raw(metrics), headers={"content-type": "application/json"}, times=1)
            assert rt.data.update(M.APISGURU_METRICS).ok
        http.calls.clear()

    return http, rt, install


# ------------------------------------------------------------------------------------------ metadata
def test_metadata_registry_and_datasets():
    cls = PublicApiExposure
    assert cls.default_enabled is False and cls.terms == "unknown"  # c2, c6 (A3: unknown terms never default)
    assert cls.terms_sources == {M.SOURCE_POSTMAN: "unknown", M.SOURCE_APISGURU: "open"}
    assert cls.disclosure == "third_party" and cls.hosts == ("www.postman.com",) and cls.trust_tier == "community"
    assert cls.max_requests == M.POSTMAN_MAX_PAGES == 2
    reg = providers.registry()
    assert reg.provider_for_host("www.postman.com").id == "postman" and reg.get("postman").tier == "trusted"
    assert reg.provider_for_host("api.apis.guru").id == "apisguru" and reg.get("apisguru").tier == "community"
    big = datasets.DATASETS[M.APISGURU_LIST]
    assert big["large"] is True and big["licence"] == "CC0-1.0" and big["terms_class"] == "open" and big["source"] == M.SOURCE_APISGURU
    assert datasets.DATASETS[M.APISGURU_METRICS]["source"] == M.SOURCE_APISGURU
    assert links.validate_manual_link(cls.manual_link) == []
    link = links.render(cls.manual_link, Entity.make(T.ORG, "ExampleBrand"))
    assert link.url == "https://www.postman.com/search?q=ExampleBrand&scope=public&type=all" and link.tier == "trusted"
    hc = cls.health_check()
    assert (hc.etype, hc.value, hc.expect) == (T.DOMAIN, "example.com", "empty")


# ------------------------------------------------------------------------------- Postman parsers
def test_recorded_research_sample_parses_and_is_discarded_cond7():
    parsed = M.parse_postman_search(fx("postman_public_search.json"))
    assert parsed["status"] == "ok" and len(parsed["hits"]) == 3 and parsed["totals"]["workspace"] == 571
    assert {h["publisher"]["handle"] for h in parsed["hits"]} == {"postman"}
    assert parsed["hits"][0]["location"] == "https://www.postman.com/postman/workspace/test-examples-in-postman"
    out = M.filter_postman_hits(parsed["hits"], ["example.com"], ["examplebrand"])
    assert out["kept"] == [] and out["discarded"] == 3  # name mentions are never a tie (c3)
    assert out["discarded_by_reason"] == {"no_publisher_or_host_tie": 3}


def test_live_answer_keeps_only_host_ties_and_masks_values_cond3_cond4():
    parsed = M.parse_postman_search(fx("postman_ok_example.json"))
    out = M.filter_postman_hits(parsed["hits"], ["example.com"], ["examplebrand"])
    hosts = sorted(h["request"]["host"] for h in out["kept"])
    assert hosts == ["example.com", "example.com", "www.example.com"]  # example.cisco.com, example-casino.test, templates dropped
    assert out["discarded_by_reason"]["request_host_not_target"] == 3  # example.cisco.com, api.example-casino.test, api.getpostman.com
    assert out["discarded_by_reason"]["templated_host"] == 1
    secret = next(h for h in out["kept"] if h["request"]["host"] == "www.example.com")
    assert secret["exposed_kinds"] == ["query_param:password"] and secret["tied_by"] == ["request_host"]
    assert secret["request"]["redacted_url"] == "www.example.com?user=***&password=***"
    facts = [M.postman_facts(h) for h in out["kept"]]
    assert_no_secret("EXAMPLE-NOT-A-SECRET", facts)
    individual = next(f for f in facts if f["publisher_handle"] == "example-user-0001")
    assert individual["publisher_name"] is None  # individual publishers lose their display name (A4)


def test_secret_in_url_answer_reports_types_only_cond4(env):
    http, rt, _install = env
    http.add("POST", URL, json=fx("postman_secret_in_url.json"))
    res = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt)
    assert res.status is Status.OK
    high = [f for f in res.findings if f.severity is Severity.HIGH]
    assert len(high) == 1 and high[0].data["exposed_kinds"] == ["query_param:api_key", "url_userinfo_password"]
    templated = next(f for f in res.findings if f.data.get("request_host") == "auth.example.com")
    assert templated.severity is Severity.LOW  # a {{client_secret}} variable is not a literal secret
    assert_no_secret("EXAMPLE-NOT-A-SECRET", res.attributes, res.findings, res.raw)
    assert_no_secret("EXAMPLEKEY000000000000000000000000", res.attributes, res.findings, res.raw)


def test_userinfo_and_key_parameters_are_typed_never_kept():
    info = M.postman_url_info("https://svc-user:EXAMPLE-NOT-A-SECRET@api.example.com/v1/orders?api_key=EXAMPLEKEY000000000000000000000000&limit=10")
    assert info["host"] == "api.example.com"
    assert info["exposed_kinds"] == ["query_param:api_key", "url_userinfo_password"]
    assert info["redacted_url"] == "https://api.example.com/v1/orders?api_key=***&limit=***"
    templated = M.postman_url_info("https://auth.example.com/oauth/token?client_secret={{client_secret}}&grant_type=client_credentials")
    assert templated["exposed_kinds"] == []  # a Postman variable is not a literal secret
    token = M.postman_url_info("https://api.example.com/hooks/ghp_0123456789abcdefghijklmnopqrstuvwxyzAB/run")
    assert "path_token" in token["exposed_kinds"] and "ghp_" not in token["redacted_url"]
    assert M.postman_url_info("{{base_url}}/signup")["host"] == ""


@pytest.mark.parametrize("name, reason", [
    ("postman_schema_changed.json", "schema changed: 'data' is not a list"),
    ("postman_schema_changed_items.json", "schema changed: 2 items without a document object"),
    ("postman_error_envelope.json", "postman error: Something went wrong"),
    ("postman_html_spa_200.html", "schema changed: html instead of json"),
])
def test_unexpected_shapes_are_errors_never_empty_cond5(name, reason):
    parsed = M.parse_postman_search(raw(name))
    assert parsed["status"] == "error" and parsed["reason"].startswith(reason)


def test_empty_and_fuzzy_answers():
    assert M.parse_postman_search(fx("postman_empty.json"))["status"] == "empty"
    fuzzy = M.parse_postman_search(fx("postman_nohit_fuzzy.json"))
    assert fuzzy["status"] == "ok" and M.filter_postman_hits(fuzzy["hits"], ["example.com"], [])["kept"] == []


def test_publisher_ties_exact_and_token():
    parsed = M.parse_postman_search(fx("postman_ok_cloudflare.json"))
    out = M.filter_postman_hits(parsed["hits"], ["cloudflare.com"], ["cloudflare"])
    by_handle = {(h["publisher"]["handle"], h["entity_type"]): h for h in out["kept"]}
    r2 = by_handle[("cloudflare-r2", "workspace")]
    assert r2["tied_by"] == ["publisher_token"] and r2["confidence"] == 0.4  # unverified brand token: the analyst checks it
    mcp = by_handle[("getmcp", "request")]
    assert mcp["tied_by"] == ["request_host"] and mcp["matched_domain"] == "cloudflare.com"
    assert ("example-user-0001", "workspace") not in by_handle  # a workspace named 'Cloudflare' by a user is not a tie


def test_request_body_and_bounded_pagination_cond5():
    body = M.postman_search_body("example.com", 1)
    assert body["service"] == "search" and body["path"] == "/search-all"
    assert body["body"]["queryText"] == "example.com" and body["body"]["from"] == 25 and body["body"]["domain"] == "public"
    with pytest.raises(ValueError):
        M.postman_search_body("example.com", 2)
    with pytest.raises(ValueError):
        M.postman_search_body("  ", 0)
    assert M.postman_next_page({"request": 10000}, 0) == 1
    assert M.postman_next_page({"request": 10000}, 1) is None
    assert M.postman_next_page({"workspace": 3}, 0) is None


# ------------------------------------------------------------------------------ module: Postman
def test_org_domain_search_findings_pivots_and_no_secret(env):
    http, rt, _install = env  # directory not installed: Postman data still reported, APIs.guru 'not checked'
    headers = json.loads(raw("postman_headers_ok.http.json"))["response"]["headers"]  # the live answer's header set
    http.add("POST", URL, json=fx("postman_ok_example.json"), headers=headers, times=1)
    http.add("POST", URL, json=fx("postman_page2_example.json"), headers=headers, times=1)
    res = run_module(PublicApiExposure, "domain:example.com", runtime=rt)
    assert res.status is Status.OK
    bodies = postman_bodies(http)
    assert [b["body"]["from"] for b in bodies] == [0, 25] and {b["body"]["queryText"] for b in bodies} == {"example.com"}
    assert all("origin" not in {k.lower() for k in c["headers"]} for c in http.calls)  # no web-app imitation
    summary = res.attributes["public_api_search"]
    assert summary["pages"] == 2 and summary["kept"] == 4 and summary["partial"] is False
    high = [f for f in res.findings if f.severity is Severity.HIGH]
    assert len(high) == 1 and "credential_exposure" in high[0].tags and high[0].criterion
    assert high[0].data["exposed_kinds"] == ["query_param:password"]
    lows = [f for f in res.findings if f.severity is Severity.LOW]
    assert len(lows) == 3 and all(f.source == M.SOURCE_POSTMAN for f in res.findings)
    urls = [p for p in res.pivots if p.entity.type is T.URL]
    assert urls and all(p.relation == "public_api_location" and not p.expand for p in urls)
    assert {p.entity.value for p in res.pivots if p.entity.type is T.DOMAIN} == {"www.example.com"}
    assert res.source_statuses[M.SOURCE_APISGURU]["status"] == "unavailable"
    assert_no_secret("EXAMPLE-NOT-A-SECRET", res.attributes, res.findings, res.raw, res.pivots)
    http.assert_hosts_within(PublicApiExposure)


def test_brand_entity_is_searched_and_publisher_tied(env):
    http, rt, _install = env
    page = {"data": [{"score": 1.0, "document": {
        "entityType": "workspace", "id": "00000000-0000-4000-8000-000000000201", "name": "ExampleBrand public APIs",
        "slug": "examplebrand-apis", "publisherHandle": "examplebrand", "publisherName": "ExampleBrand",
        "publisherType": "team", "isPublisherVerified": True}}], "meta": {"total": {"workspace": 1}}}
    http.add("POST", URL, json=page, times=1)
    res = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt)
    assert res.status is Status.OK and len(postman_bodies(http)) == 1
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and finding.data["tied_by"] == ["publisher_exact"]
    assert res.attributes["public_api_locations"][0]["location"] == "https://www.postman.com/examplebrand/workspace/examplebrand-apis"


def test_no_search_about_third_parties_cond3(env):
    http, rt, install = env
    install()
    res = run_module(PublicApiExposure, "domain:example.net", runtime=rt)  # not in the org profile
    assert res.status is Status.EMPTY and postman_bodies(http) == []
    assert "not an org_profile domain" in res.error
    other = run_module(PublicApiExposure, Entity.make(T.ORG, "Other Company"), runtime=rt)
    assert other.status is Status.SKIPPED and other.reason_code == "not_applicable" and postman_bodies(http) == []
    plain = run_module(PublicApiExposure, Entity.make(T.KEYWORD, "examplebrand"), FakeHttp())  # no org profile at all
    assert plain.status is Status.SKIPPED and "no org profile" in plain.error


def test_licence_gate_keeps_postman_out_cond2(env):
    http, rt, install = env
    install()
    res = run_module(PublicApiExposure, "domain:example.com", runtime=rt, allowed_sources=frozenset({M.SOURCE_APISGURU}))
    assert res.status is Status.EMPTY and postman_bodies(http) == []
    assert "licence gate" in res.error


@pytest.mark.parametrize("route, status, code", [
    ({"status": 403, "text": raw("postman_challenge_403.html").decode()}, Status.BLOCKED, "challenge"),
    ({"status": 403, "json": {"message": "Forbidden"}}, Status.BLOCKED, "challenge"),
    ({"status": 429, "json": {"message": "Too Many Requests"}}, Status.RATE_LIMITED, "rate_limited"),
    ({"status": 500, "json": {"error": "internal"}}, Status.ERROR, "error"),
    ({"status": 200, "text": raw("postman_html_spa_200.html").decode()}, Status.ERROR, "error"),
    ({"status": 200, "json": fx("postman_schema_changed.json")}, Status.ERROR, "error"),
    ({"status": 200, "json": fx("postman_error_envelope.json")}, Status.ERROR, "error"),
])
def test_could_not_verify_answers_cond5(env, route, status, code):
    http, rt, _install = env
    http.add("POST", URL, **route)
    res = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt)
    assert res.status is status and res.reason_code == code
    assert "could not verify" in res.error or status is Status.BLOCKED


def test_blocked_search_wins_over_missing_directory(env):
    http, rt, _install = env
    http.add("POST", URL, status=403, text=raw("postman_challenge_403.html").decode())
    res = run_module(PublicApiExposure, "domain:example.com", runtime=rt)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_second_page_failure_keeps_the_first(env):
    http, rt, _install = env
    http.add("POST", URL, json=fx("postman_ok_example.json"), times=1)
    http.add("POST", URL, status=429, json={"message": "slow down"}, times=1)
    res = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt)
    assert res.status is Status.OK
    summary = res.attributes["public_api_search"]
    assert summary["partial"] is True and summary["pages"] == 1 and summary["page_errors"]


def test_empty_search_is_empty_with_discard_counts(env):
    http, rt, _install = env
    http.add("POST", URL, json=fx("postman_public_search.json"))
    res = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt)
    assert res.status is Status.EMPTY and res.findings == []
    assert res.attributes["public_api_search"]["discarded"] == 3


def test_per_case_query_cap_cond5(env):
    http, rt, _install = env
    http.add("POST", URL, json=fx("postman_empty.json"))
    for _ in range(M.POSTMAN_MAX_QUERIES_PER_CASE):
        assert run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt, case_id="case-0001").status is Status.EMPTY
    capped = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt, case_id="case-0001")
    assert capped.status is Status.SKIPPED and capped.reason_code == "policy"
    assert len(postman_bodies(http)) == M.POSTMAN_MAX_QUERIES_PER_CASE
    other_case = run_module(PublicApiExposure, Entity.make(T.ORG, "ExampleBrand"), runtime=rt, case_id="case-0002")
    assert other_case.status is Status.EMPTY


# ----------------------------------------------------------------------------- module: APIs.guru
def test_directory_match_findings_and_pivots(env):
    http, rt, install = env
    install()
    res = run_module(PublicApiExposure, "domain:github.com", runtime=rt)
    assert res.status is Status.OK and postman_bodies(http) == [] and http.calls == []  # matched locally
    keys = [m["key"] for m in res.attributes["public_api_directory"]]
    assert keys == ["github.com", "github.com:api.github.com"]
    service = res.attributes["public_api_directory"][1]
    assert service["matched_by"] == ["provider", "service_host"] and service["new_hosts"] == ["api.github.com"]
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and finding.source == M.SOURCE_APISGURU and finding.data["count"] == 2
    assert {(p.entity.value, p.relation) for p in res.pivots} == {("api.github.com", "subdomain")}
    info = res.attributes["public_api_directory_info"]
    assert info["entries"] == 8 and info["metrics_num_apis"] == 2529 and info["complete"] is False
    assert any(d["name"] == M.APISGURU_LIST for d in res.datasets)  # dataset citation


def test_directory_origin_spec_url_on_target(env):
    _http, rt, install = env
    install(metrics=None)
    res = run_module(PublicApiExposure, "domain:inpe.br", runtime=rt)
    assert res.status is Status.OK
    match = res.attributes["public_api_directory"][0]
    assert match["matched_by"] == ["provider", "x-origin"]
    assert match["origin_urls_on_target"] == ["http://queimadas.dgi.inpe.br/queimadas/dados-abertos/api/swagger.json"]
    pivots = {(p.entity.type, p.relation) for p in res.pivots}
    assert (T.URL, "api_spec_url") in pivots and (T.DOMAIN, "subdomain") in pivots
    assert res.attributes["public_api_directory_info"]["complete"] is None  # no metrics copy: no cross-check


def test_local_pseudo_providers_never_match_by_name():
    index = M.ApisGuruIndex(fx("apisguru_list_ok.json"))
    assert index.match("1password.local", NOW) == []
    assert index.newest_update and index.newest_update.startswith("20")
    assert [m["key"] for m in index.match("api.github.com", NOW)] == ["github.com:api.github.com"]
    assert index.match("notgithub.com", NOW) == []


def test_missing_directory_is_unavailable_never_empty(env):
    http, rt, _install = env
    res = run_module(PublicApiExposure, "domain:example.net", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and http.calls == []
    assert "v3lum data update" in res.error


def test_directory_validator_rejects_partial_and_wrong_files():
    assert M.validate_apisguru_list(raw("apisguru_list_ok.json"), min_entries=1) is True
    with pytest.raises(ValueError, match="too few entries"):
        M.validate_apisguru_list(raw("apisguru_list_ok.json"), min_entries=1000)  # a partial copy never installs
    with pytest.raises(ValueError, match="invalid json"):
        M.validate_apisguru_list(raw("apisguru_list_truncated.json"))  # a download cut mid-body
    with pytest.raises(ValueError, match="top level is list"):
        M.validate_apisguru_list(raw("apisguru_list_wrong_type.json"))
    with pytest.raises(ValueError, match="html instead of json"):
        M.validate_apisguru_list(raw("apisguru_list_html.html"))


def test_recorded_metrics_sample_cond7():
    for name in ("apisguru_metrics.json", "apisguru_metrics_live.json"):
        parsed = M.parse_apisguru_metrics(raw(name))
        assert parsed["status"] == "ok" and parsed["num_apis"] == 2529 and parsed["num_providers"] == 677
    assert M.parse_apisguru_metrics(b"[1, 2]")["status"] == "error"
    assert M.parse_apisguru_metrics(b'{"numSpecs": 1}')["reason"] == "schema changed: numAPIs missing"
    assert M.validate_apisguru_metrics(raw("apisguru_metrics.json")) is True
