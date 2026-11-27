"""digital_asset_links (P008): keyless statements:list, attributes, wording and could-not-verify statuses.

Fixtures in tests/fixtures/digital_asset_links/ (live 2026-11-26 from a datacenter egress):
``statements_ok.json`` is the real google.com answer trimmed to 4 packages / 8 statements of 58 (maxAge
kept); ``not_published_200.json`` the real example.com answer (HTTP 200, ERROR_CODE_FETCH_ERROR, 404 for the
site's assetlinks.json); ``invalid_argument_400.json`` the real answer without a source. Synthetic (Google
API error shape / documented ErrorCode): the 429, 503, redirect-error, web-target and empty-list answers.
"""

from __future__ import annotations

from types import SimpleNamespace

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import digital_asset_links as mod
from v3lum.modules.domain_dns.digital_asset_links import DigitalAssetLinks

GOOGLE = "https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https%3A%2F%2Fgoogle.com&relation=delegate_permission%2Fcommon.handle_all_urls"
EXAMPLE = mod.statements_url("example.com")
CALENDAR_FP = "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83"


def fx(name):
    return module_fixture(DigitalAssetLinks, name)


def test_contract_metadata():
    cls = DigitalAssetLinks
    assert (cls.terms, cls.disclosure, cls.provider, cls.sources, cls.hosts) == (
        "open", "third_party", "google_dal", ("google_dal.statements",), ("digitalassetlinks.googleapis.com",))
    assert cls.cache_ttl == 86400 and cls.max_requests == 1 and cls.default_enabled is True  # cond 1
    assert not cls.requires_keys and not cls.optional_keys  # keyless
    assert mod.statements_url("google.com") == GOOGLE


def test_real_google_answer_records_apps_and_shared_certificates():
    http = FakeHttp().add("GET", GOOGLE, json=fx("statements_ok.json"))
    res = run_module(DigitalAssetLinks, "domain:google.com", http)
    assert res.status is Status.OK
    apps = {a["package"]: a["sha256"] for a in res.attributes["official_android_apps"]}
    assert set(apps) == {"com.google.android.calendar", "com.google.android.apps.maps", "com.google.android.apps.classroom", "com.google.android.gm"}
    assert len(apps["com.google.android.apps.maps"]) == 3 and apps["com.google.android.calendar"] == [CALENDAR_FP]
    shared = next(f for f in res.findings if f.title.startswith("Same signing certificate"))
    links = {link["cert_sha256"]: link["packages"] for link in shared.data["shared_certificates"]}
    assert links[CALENDAR_FP] == ["com.google.android.apps.maps", "com.google.android.calendar", "com.google.android.gm"]
    assert all(f.severity.label == "info" for f in res.findings)  # cond 2: organisation-asset link (info)
    # no pivot expansion (cond 2): packages and certificates are listed for the analyst only
    assert res.pivots and all(p.expand is False for p in res.pivots)
    assert {p.entity.value for p in res.pivots if p.entity.type is T.KEYWORD} == set(apps)
    assert CALENDAR_FP.replace(":", "").lower() in {p.entity.value for p in res.pivots if p.entity.type is T.CERT_FP}
    http.assert_hosts_within(DigitalAssetLinks)


def test_real_not_published_answer_reads_no_statements_published():
    http = FakeHttp().add("GET", EXAMPLE, json=fx("not_published_200.json"))
    res = run_module(DigitalAssetLinks, "domain:example.com", http)
    assert res.status is Status.EMPTY and res.error == "no Digital Asset Links statements published"
    assert "no official apps" not in res.error


def test_empty_statement_list_reads_no_statements_published():
    http = FakeHttp().add("GET", EXAMPLE, json=fx("empty_statements_synthetic.json"))
    res = run_module(DigitalAssetLinks, "domain:example.com", http)
    assert res.status is Status.EMPTY and res.error == mod.EMPTY_WORDING


def test_other_error_codes_are_could_not_verify():
    http = FakeHttp().add("GET", EXAMPLE, json=fx("redirect_error_synthetic.json"))
    res = run_module(DigitalAssetLinks, "domain:example.com", http)
    assert res.status is Status.ERROR and "ERROR_CODE_REDIRECT" in res.error and "could not verify" in res.error


def test_web_targets_only():
    http = FakeHttp().add("GET", EXAMPLE, json=fx("web_target_synthetic.json"))
    res = run_module(DigitalAssetLinks, "domain:example.com", http)
    assert res.status is Status.OK and res.attributes["asset_link_sites"] == ["https://www.example.net"]
    assert "official_android_apps" not in res.attributes


def test_rate_limit_and_server_errors_are_never_empty():
    http = FakeHttp().add("GET", EXAMPLE, status=429, json=fx("rate_limited_429_synthetic.json"))
    assert run_module(DigitalAssetLinks, "domain:example.com", http).status is Status.RATE_LIMITED
    http2 = FakeHttp().add("GET", EXAMPLE, status=503, json=fx("unavailable_503_synthetic.json"))
    assert run_module(DigitalAssetLinks, "domain:example.com", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", EXAMPLE, status=403, json={"error": {"code": 403, "message": "forbidden"}})
    assert run_module(DigitalAssetLinks, "domain:example.com", http3).status is Status.BLOCKED
    http4 = FakeHttp().add("GET", EXAMPLE, status=400, json=fx("invalid_argument_400.json"))
    assert run_module(DigitalAssetLinks, "domain:example.com", http4).status is Status.ERROR


def test_junk_bodies_are_errors():
    http = FakeHttp().add("GET", EXAMPLE, body=b"{not json", headers={"content-type": "application/json"})
    assert run_module(DigitalAssetLinks, "domain:example.com", http).status is Status.ERROR
    http2 = FakeHttp().add("GET", EXAMPLE, json=["x"])
    assert run_module(DigitalAssetLinks, "domain:example.com", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", EXAMPLE, json={"statements": "x"})
    assert run_module(DigitalAssetLinks, "domain:example.com", http3).status is Status.ERROR


def test_subdomains_are_not_applicable_and_send_nothing():
    http = FakeHttp()
    res = run_module(DigitalAssetLinks, "domain:www.google.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and not http.calls


def test_only_usable_answers_are_cached():
    def resp(doc):
        return SimpleNamespace(json=lambda: doc)

    assert mod.cacheable(resp(fx("statements_ok.json"))) and mod.cacheable(resp(fx("not_published_200.json")))
    assert not mod.cacheable(resp(fx("redirect_error_synthetic.json"))) and not mod.cacheable(resp(["x"]))


def test_shared_client_helpers_for_p346():
    parsed = mod.parse_statements(fx("statements_ok.json"))
    assert mod.confirms_app(parsed, "com.google.android.gm")
    assert mod.confirms_app(parsed, "com.google.android.gm", CALENDAR_FP.replace(":", "").lower())
    assert not mod.confirms_app(parsed, "com.google.android.gm", "00" * 32)
    assert not mod.confirms_app(parsed, "com.example.fake")
    assert mod.normalize_cert_sha256("zz") is None and mod.normalize_cert_sha256(CALENDAR_FP.lower()) == CALENDAR_FP
    assert mod.parse_statements({"statements": [{"target": {"androidApp": {"packageName": "bad name"}}}]})["state"] == "not_published"


def test_golden_path_route_replays():
    """tests/fixtures/acceptance/domain/digital_asset_links.json answers the module's exact request."""
    from tests.fakes import fixture

    routes = fixture("acceptance/domain/digital_asset_links.json")["routes"]
    http = FakeHttp()
    for r in routes:
        http.add(r["method"], r["url"], status=r["status"], json=r["json"], headers=r["headers"])
    res = run_module(DigitalAssetLinks, "domain:example.com", http)
    assert res.status is Status.EMPTY and res.error == mod.EMPTY_WORDING
