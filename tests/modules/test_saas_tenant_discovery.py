"""Batch p3-G13-1 - P371 saas_tenant_discovery (v3lum/modules/pentest_recon/saas_tenant_discovery.py).

Trimmed real answers captured live on 2026-11-26 (tests/fixtures/saas_tenant_discovery/: the vendors' own
tenants okta.okta.com, ecosystem.atlassian.net and support.zendesk.com as positives, a random name as the
negative; '*_derived' files are documented shapes that cannot be captured without abusing the vendor, e.g.
a forced 429). Candidate names in the module tests come from synthetic org profiles (*.example).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.lint import blocking, lint_module_source
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import saas_tenant_discovery as std
from v3lum.modules.pentest_recon.saas_tenant_discovery import SaasTenantDiscovery

MOD = SaasTenantDiscovery
#: FC3: tokens that must never appear in a request (login, authn, sign-up, reset, user lookup, credential type)
FORBIDDEN = re.compile(r"login|logon|signin|authn|authorize|oauth2|signup|register|password|reset|forgot|recover|/users?\b|/api/|"
                       r"account|credential|factor|webfinger|okta-organization|introspect|username|email|@|%40|\?", re.I)


def fx(name: str) -> dict[str, Any]:
    return module_fixture(MOD, f"{name}.json")


def add(http: FakeHttp, vendor: str, candidate: str, name: str, *, times: int | None = None) -> FakeHttp:
    resp = fx(name)["response"]
    body = resp.get("body")
    return http.add("GET", std.tenant_url(vendor, candidate), status=resp["status"], headers=resp.get("headers") or {},
                    body=(body or "").encode("utf-8"), times=times)


def org(**extra: Any) -> OrgProfile:
    data: dict[str, Any] = {"org": {"name": "Okta"}, "domains": [{"name": "okta.example", "verification": "confirmed"}]}
    data.update(extra)
    return OrgProfile.from_dict(data)


def assert_fc3(http: FakeHttp, allowed: set[str]) -> None:
    urls = http.urls()
    assert urls, "the module made no request"
    for url in urls:
        assert url in allowed, url
        assert std.rule2_violation(url) is None, url
        assert not FORBIDDEN.search(url.split("://", 1)[1].split("/", 1)[1] if "/" in url.split("://", 1)[1] else ""), url
        assert "@" not in url and "%40" not in url.lower() and "?" not in url, url


# ------------------------------------------------------------------ registration (FC6) and lint (FC7)
def test_metadata_is_the_council_decision() -> None:
    assert MOD.default_enabled is False
    assert MOD.terms == "open" and MOD.disclosure == "third_party" and MOD.opsec.name == "PASSIVE"
    assert MOD.trust_tier == "trusted" and MOD.max_tlp.value_str == "amber+strict" and MOD.shares_input is True
    assert MOD.run_on == "seeds" and MOD.category == "pentest_recon"
    assert set(MOD.hosts) == {"*.okta.com", "*.atlassian.net", "*.zendesk.com"}
    assert MOD.max_requests == 15 and MOD.requires_keys == ()
    assert set(MOD.accepts) == {T.DOMAIN, T.ORG, T.KEYWORD}


def test_module_source_passes_the_p327_lint() -> None:
    assert blocking(lint_module_source(Path(std.__file__))) == []


# ------------------------------------------------------------------ FC4 markers on the captured pairs
@pytest.mark.parametrize(("vendor", "name", "candidate", "state", "marker"), [
    ("okta", "okta_exists", "okta", "exists", "openid_configuration_issuer"),
    ("okta", "okta_not_found_e0000006", "thisorgdoesnotexist0000x", "absent", "E0000006"),
    ("okta", "okta_generic_403_html_derived", "thisorgdoesnotexist0000x", "unknown", None),
    ("okta", "okta_rate_limited_429_derived", "okta", "unknown", "rate_limited"),
    ("okta", "okta_error_in_200_html_derived", "okta", "unknown", None),
    ("okta", "okta_issuer_mismatch_derived", "okta", "unknown", "issuer_mismatch"),
    ("atlassian", "atlassian_exists", "ecosystem", "exists", "tenant_info_cloudId"),
    ("atlassian", "atlassian_not_found_404", "thisorgdoesnotexist0000x", "absent", "edge_404_page_unavailable"),
    ("atlassian", "atlassian_malformed_200_derived", "ecosystem", "unknown", None),
    ("atlassian", "atlassian_unavailable_503_derived", "ecosystem", "unknown", None),
    ("zendesk", "zendesk_exists_hc_301_locale", "support", "exists", "hc_locale_redirect"),
    ("zendesk", "zendesk_not_found_hc_404", "thisorgdoesnotexist0000x", "absent", "hc_404"),
    ("zendesk", "zendesk_exists_hc_locale_200", "support", "exists", "hc_200"),
    ("zendesk", "zendesk_help_center_closed_301_research", "thisorgdoesnotexist0000x", "absent", "help_center_closed"),
    ("zendesk", "zendesk_challenge_403", "thisorgdoesnotexist0000x", "unknown", "cloudflare_challenge"),
    ("zendesk", "zendesk_login_redirect_derived", "support", "unknown", "login_redirect"),
    ("zendesk", "zendesk_rate_limited_429_derived", "support", "unknown", "rate_limited:retry_after=60"),
])
def test_differential_markers(vendor: str, name: str, candidate: str, state: str, marker: str | None) -> None:
    resp = fx(name)["response"]
    row = std.decide_tenant(vendor, resp["status"], resp.get("headers"), resp.get("body"), candidate)
    assert row["state"] == state, row
    if marker is not None:
        assert row["marker"] == marker, row
    if state == "exists":
        assert row["label"] == "candidate tenant" and row["confidence"] == "candidate"
    if state != "absent":
        assert row["state"] != "absent"


def test_ids_are_kept_and_the_challenge_stops_the_vendor() -> None:
    ok = fx("okta_exists")["response"]
    assert std.decide_okta(ok["status"], ok["headers"], ok["body"], "okta")["ids"] == {"issuer": "https://okta.okta.com"}
    atl = fx("atlassian_exists")["response"]
    assert std.decide_atlassian(atl["status"], atl["headers"], atl["body"], "ecosystem")["ids"]["cloud_id"].endswith("-ecosystem")
    zd = fx("zendesk_exists_hc_301_locale")["response"]
    assert std.decide_zendesk(zd["status"], zd["headers"], zd["body"], "support")["ids"] == {"locale": "en-us"}
    ch = fx("zendesk_challenge_403")["response"]
    assert std.decide_zendesk(ch["status"], ch["headers"], ch["body"], "support")["stop"] is True
    # the okta issuer of another candidate is never attributed
    assert std.decide_okta(ok["status"], ok["headers"], ok["body"], "acme")["state"] == "unknown"


def test_zendesk_strict_mode_reads_only_the_literal_markers() -> None:
    for name in ("zendesk_exists_hc_301_locale", "zendesk_not_found_hc_404"):
        resp = fx(name)["response"]
        assert std.decide_zendesk(resp["status"], resp["headers"], resp["body"], "support", strict=True)["state"] == "unknown"
    closed = fx("zendesk_help_center_closed_301_research")["response"]
    assert std.decide_zendesk(closed["status"], closed["headers"], closed["body"], "x1", strict=True)["state"] == "absent"
    page = fx("zendesk_exists_hc_locale_200")["response"]
    assert std.decide_zendesk(page["status"], page["headers"], page["body"], "support", strict=True)["state"] == "exists"


def test_junk_answers_never_raise_and_are_unknown() -> None:
    for vendor in std.VENDORS:
        for status, headers, body in [(None, None, None), (200, None, b"\xff\xfe"), (200, "x", "["), (500, {}, "oops"), (True, {}, "")]:
            assert std.decide_tenant(vendor, status, headers, body, "acme")["state"] == "unknown"


# ------------------------------------------------------------------ FC1-FC3 builders, candidates and the rule-2 guard
def test_fixed_url_builders_and_refused_candidates() -> None:
    assert std.tenant_url("okta", "acme") == "https://acme.okta.com/.well-known/openid-configuration"
    assert std.tenant_url("atlassian", "acme") == "https://acme.atlassian.net/_edge/tenant_info"
    assert std.tenant_url("zendesk", "acme") == "https://acme.zendesk.com/hc"
    for bad in ("login", "www", "id", "signup", "a.b", "a@b", "x/y", "", "1234", "-acme", "acme-"):
        with pytest.raises(ValueError):
            std.tenant_url("okta", bad)
    with pytest.raises(ValueError):
        std.tenant_url("github", "acme")
    for raw in ("someone@example.com", "https://acme.example/", "acme.example", "a/b", "a?b", "a#b", "100%", "1234", "xn--acm-1ba"):
        assert std.normalise_candidate(raw) is None, raw
    assert std.normalise_candidate("Açaí Brasil S/A") is None  # '/' refused: never guessed
    assert std.normalise_candidate("Banco Exemplo") == "bancoexemplo"
    assert std.normalise_candidate("Café-Bar") == "cafe-bar"
    assert std.candidate_from_domain("portal.acme.com.br") == "acme"
    assert std.candidate_from_domain("com.br") is None


@pytest.mark.parametrize("url", [
    "http://acme.okta.com/.well-known/openid-configuration",
    "https://acme.okta.com/login/login.htm",
    "https://acme.okta.com/api/v1/authn",
    "https://acme.okta.com/oauth2/v1/authorize",
    "https://acme.okta.com/.well-known/okta-organization",
    "https://acme.okta.com/.well-known/webfinger",
    "https://acme.okta.com/.well-known/openid-configuration?login_hint=someone@example.com",
    "https://someone%40example.com@acme.okta.com/.well-known/openid-configuration",
    "https://user:pw@acme.okta.com/.well-known/openid-configuration",
    "https://login.okta.com/.well-known/openid-configuration",
    "https://acme.okta.com.evil.example/.well-known/openid-configuration",
    "https://acme.atlassian.net/signup",
    "https://acme.atlassian.net/rest/api/3/user",
    "https://id.atlassian.net/_edge/tenant_info",
    "https://acme.atlassian.net/_edge/tenant_info#x",
    "https://acme.zendesk.com/access/unauthenticated",
    "https://acme.zendesk.com/auth/v2/login/signin",
    "https://acme.zendesk.com/hc/en-us/requests/new",
    "https://acme.zendesk.com/password/reset",
    "https://acme.zendesk.com/api/v2/users/me.json",
    "https://acme.zendesk.com/",
])
def test_rule2_guard_refuses_every_other_url(url: str) -> None:
    assert std.rule2_violation(url) is not None


def test_candidates_only_from_the_org_profile_capped_without_permutations() -> None:
    prof = OrgProfile.from_dict({
        "org": {"name": "Acme Corp"},
        "domains": [{"name": d, "verification": "seeded"} for d in ("acme.example", "acme-store.example", "acmepay.example")],
        "brands": [{"keyword": k} for k in ("Acme Bank", "Acme Cloud", "Acme Seguros", "AcmeX")],
    })

    class Ctx:
        org = prof
        authorized = False
        options = ScanOptions()

    cands, basis, why = std.select_candidates(Entity.make(T.DOMAIN, "www.acme.example"), Ctx())
    assert basis == "org_profile" and not why
    assert cands == ["acme", "acme-store", "acmepay", "acmebank", "acmecloud"]  # domain labels, then brands; cap 5
    assert std.select_candidates(Entity.make(T.KEYWORD, "acme bank"), Ctx())[0][0] == "acmebank"
    assert std.select_candidates(Entity.make(T.ORG, "Acme Corp"), Ctx())[0][0] == "acmecorp"
    # not in the profile: nothing is asked, no permutation is tried
    for entity in (Entity.make(T.DOMAIN, "other.example"), Entity.make(T.KEYWORD, "acmee"), Entity.make(T.ORG, "Globex")):
        cands, basis, why = std.select_candidates(entity, Ctx())
        assert cands == [] and basis == "" and "organisation profile" in why
    assert std.select_candidates(Entity.make(T.DOMAIN, "acme.example"), Ctx(), limit=50)[0].__len__() == 5


def _scope(domains: list[str]) -> Scope:
    return Scope({
        "authorization_ref": "ENG-2026-042", "owner": "Client Security Team", "contacts": ["soc@client.example"], "ticket": "SEC-1",
        "window_start": "2026-11-01T00:00:00Z", "window_end": "2026-12-31T00:00:00Z", "targets": {"domains": domains},
    })


def test_scope_file_candidates_only_with_authorization() -> None:
    scope = _scope(["client.example", "client-shop.example"])
    assert not scope.problems, scope.problems

    class Ctx:
        org = OrgProfile.empty()
        authorized = True
        options = ScanOptions(authorized=True, authorization_ref="ENG-2026-042", scope=scope)

    cands, basis, _why = std.select_candidates(Entity.make(T.DOMAIN, "client.example"), Ctx())
    assert basis == "authorized_scope" and cands == ["client", "client-shop"]
    Ctx.authorized = False
    assert std.select_candidates(Entity.make(T.DOMAIN, "client.example"), Ctx())[0] == []


# ------------------------------------------------------------------ the module through the engine
def _all_vendors(http: FakeHttp, candidate: str, okta: str, atlassian: str, zendesk: str) -> set[str]:
    add(http, "okta", candidate, okta)
    add(http, "atlassian", candidate, atlassian)
    add(http, "zendesk", candidate, zendesk)
    return {std.tenant_url(v, candidate) for v in std.VENDORS}


def test_found_tenant_is_a_candidate_with_tri_state_rows_and_passive_pivots() -> None:
    http = FakeHttp()
    allowed = _all_vendors(http, "okta", "okta_exists", "atlassian_not_found_404", "zendesk_not_found_hc_404")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert res.status is Status.OK
    rows = res.attributes["saas_tenant_checks"]
    assert [(r["vendor"], r["state"]) for r in rows] == [("okta", "exists"), ("atlassian", "absent"), ("zendesk", "absent")]
    assert rows[0]["label"] == "candidate tenant" and rows[0]["confidence"] == "candidate"
    assert res.attributes["saas_tenants"][0]["tenant_host"] == "okta.okta.com"
    assert res.attributes["identity_provider_hosts"] == ["okta.okta.com"]
    assert res.attributes["presence"]["state"] == "found"
    piv = {p.entity.value: p for p in res.pivots}
    assert set(piv) == {"okta.okta.com"}
    assert piv["okta.okta.com"].relation == "identity_provider" and piv["okta.okta.com"].expand is False  # FC5: never attributed by name
    finding = res.findings[0]
    assert finding.title == std.FINDING_TITLE and finding.severity.label == "info" and "candidate_tenant" in finding.tags
    assert finding.source == "okta.openid_configuration" and finding.confidence_label.value == "possible"
    assert_fc3(http, allowed)
    http.assert_hosts_within(MOD)


def test_org_profile_corroborates_the_tenant() -> None:
    http = FakeHttp()
    _all_vendors(http, "okta", "okta_exists", "atlassian_not_found_404", "zendesk_not_found_hc_404")
    prof = org(app_ids=[{"kind": "okta_tenant", "value": "okta.okta.com"}])
    res = run_module(MOD, "domain:okta.example", http, org_profile=prof)
    row = res.attributes["saas_tenant_checks"][0]
    assert row["confidence"] == "corroborated" and row["corroboration"] == [{"kind": "org_profile", "detail": "okta.okta.com"}]
    pivot = res.pivots[0]
    assert pivot.expand is True and pivot.confidence_label.value == "probable"


def test_every_vendor_absent_is_empty_with_positive_markers() -> None:
    http = FakeHttp()
    _all_vendors(http, "okta", "okta_not_found_e0000006", "atlassian_not_found_404", "zendesk_not_found_hc_404")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert res.status is Status.EMPTY
    assert res.attributes["presence"]["state"] == "absent"
    assert set(res.attributes["presence"]["marker"].split(",")) == {"E0000006", "edge_404_page_unavailable", "hc_404"}
    assert not res.pivots and not res.findings


def test_seed_outside_the_profile_is_skipped_without_any_request() -> None:
    http = FakeHttp()
    res = run_module(MOD, "domain:globex.example", http, org_profile=org())
    assert res.status is Status.SKIPPED and res.reason_code == "own_asset"
    assert http.urls() == []
    res2 = run_module(MOD, "keyword:okta", FakeHttp(), org_profile=OrgProfile.empty())
    assert res2.status is Status.SKIPPED


def test_challenge_stops_the_vendor_for_the_rest_of_the_run() -> None:
    http = FakeHttp()
    prof = org(brands=[{"keyword": "Acme Bank"}])  # candidates: okta, acmebank
    _all_vendors(http, "okta", "okta_not_found_e0000006", "atlassian_not_found_404", "zendesk_challenge_403")
    add(http, "okta", "acmebank", "okta_not_found_e0000006")
    add(http, "atlassian", "acmebank", "atlassian_not_found_404")
    res = run_module(MOD, "domain:okta.example", http, org_profile=prof)
    rows = res.attributes["saas_tenant_checks"]
    zendesk = [r for r in rows if r["vendor"] == "zendesk"]
    assert zendesk[0]["state"] == "unknown" and zendesk[0]["reason"] == "challenge"
    assert zendesk[1]["state"] == "unknown" and zendesk[1]["reason"].startswith("circuit")
    assert std.tenant_url("zendesk", "acmebank") not in http.urls()  # never requested after the challenge
    assert res.source_statuses["zendesk.help_center"]["status"] == "blocked"
    assert res.attributes["presence"]["state"] == "unknown"  # some vendors could not be verified: never 'absent'
    assert res.status is Status.OK


def test_429_is_rate_limited_never_absent() -> None:
    http = FakeHttp()
    _all_vendors(http, "okta", "okta_rate_limited_429_derived", "atlassian_not_found_404", "zendesk_rate_limited_429_derived")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    states = {r["vendor"]: (r["state"], r["reason"]) for r in res.attributes["saas_tenant_checks"]}
    assert states["okta"] == ("unknown", "rate_limited") and states["zendesk"] == ("unknown", "rate_limited")
    assert res.source_statuses["okta.openid_configuration"]["status"] == "rate_limited"


def test_all_vendors_rate_limited_is_rate_limited() -> None:
    http = FakeHttp()
    for vendor in std.VENDORS:
        add(http, vendor, "okta", "okta_rate_limited_429_derived")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert res.status is Status.RATE_LIMITED


def test_all_vendors_challenged_is_blocked() -> None:
    http = FakeHttp()
    for vendor in std.VENDORS:
        add(http, vendor, "okta", "zendesk_challenge_403")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_5xx_timeouts_and_errors_in_200_are_could_not_verify() -> None:
    http = FakeHttp()
    add(http, "okta", "okta", "okta_error_in_200_html_derived")
    add(http, "atlassian", "okta", "atlassian_unavailable_503_derived")
    http.add("GET", std.tenant_url("zendesk", "okta"), error=NetworkError("timed out"))
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert {r["state"] for r in res.attributes["saas_tenant_checks"]} == {"unknown"}


def test_malformed_json_and_generic_403_are_unknown() -> None:
    http = FakeHttp()
    add(http, "okta", "okta", "okta_generic_403_html_derived")
    add(http, "atlassian", "okta", "atlassian_malformed_200_derived")
    add(http, "zendesk", "okta", "zendesk_not_found_hc_404")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    rows = {r["vendor"]: r for r in res.attributes["saas_tenant_checks"]}
    assert rows["okta"]["state"] == "unknown" and rows["atlassian"]["state"] == "unknown" and rows["zendesk"]["state"] == "absent"
    assert res.attributes["presence"]["state"] == "unknown"


def test_login_redirect_is_never_followed() -> None:
    http = FakeHttp()
    allowed = _all_vendors(http, "okta", "okta_not_found_e0000006", "atlassian_not_found_404", "zendesk_login_redirect_derived")
    res = run_module(MOD, "domain:okta.example", http, org_profile=org())
    zendesk = [r for r in res.attributes["saas_tenant_checks"] if r["vendor"] == "zendesk"][0]
    assert zendesk["state"] == "unknown"
    assert_fc3(http, allowed)  # /access/unauthenticated was never requested


def test_fc3_no_login_endpoint_and_no_identifier_is_ever_sent() -> None:
    """Rule 2 (P371 FC3) over every request the module makes with five candidates and mixed answers."""
    http = FakeHttp()
    prof = OrgProfile.from_dict({
        "org": {"name": "Okta"},
        "domains": [{"name": "okta.example"}, {"name": "ecosystem.example"}],
        "brands": [{"keyword": "Acme Bank"}, {"keyword": "someone@example.com"}, {"keyword": "Login"}, {"keyword": "Acme Corp"}],
    })
    allowed: set[str] = set()
    for cand in ("okta", "ecosystem", "acmebank", "acmecorp"):
        allowed |= _all_vendors(http, cand, "okta_not_found_e0000006", "atlassian_not_found_404", "zendesk_login_redirect_derived")
    res = run_module(MOD, "domain:okta.example", http, org_profile=prof)
    assert res.attributes["saas_tenant_checks"]
    candidates = res.raw["candidates"]
    assert "login" in candidates  # a profile brand, but a reserved vendor label: never requested
    login_rows = [r for r in res.attributes["saas_tenant_checks"] if r["candidate"] == "login"]
    assert len(login_rows) == 3 and all(r["state"] == "unknown" and r["reason"].startswith("refused") for r in login_rows)
    assert len(candidates) <= 5 and all("@" not in c for c in candidates)
    assert_fc3(http, allowed)
    assert len(http.urls()) <= 15


def test_one_get_per_vendor_per_candidate_without_retries() -> None:
    http = FakeHttp()
    add(http, "okta", "okta", "okta_rate_limited_429_derived", times=1)
    add(http, "atlassian", "okta", "atlassian_unavailable_503_derived", times=1)
    add(http, "zendesk", "okta", "zendesk_not_found_hc_404", times=1)
    run_module(MOD, "domain:okta.example", http, org_profile=org())
    assert sorted(http.urls()) == sorted(std.tenant_url(v, "okta") for v in std.VENDORS)


# ------------------------------------------------------------------ FC5 corroboration helper
def test_corroborate_sources_never_echo_token_values() -> None:
    row = std._row("okta", "acme", "exists", status=200, marker="openid_configuration_issuer", ids={"issuer": "https://acme.okta.com"})
    assert std.corroborate(row)["confidence"] == "candidate"
    dns = std.corroborate(row, txt_records=['"okta-verification=AbCdEf0123456789"'])
    assert dns["corroboration"] == [{"kind": "dns_verification", "detail": "okta-verification"}]
    assert "AbCdEf" not in str(dns)
    assert std.corroborate(row, idp_hosts=["https://acme.okta.com/app/x"])["corroboration"][0]["kind"] == "idp_issuer"
    assert std.corroborate(row, idp_hosts=["acme.oktapreview.com"])["confidence"] == "candidate"
    atl = std._row("atlassian", "acme", "exists", marker="tenant_info_cloudId", ids={"cloud_id": "abcdef12-3456"})
    assert std.corroborate(atl, saas_vendors=["Atlassian", "Google"])["confidence"] == "corroborated"
    assert std.corroborate(atl, org_values=["abcdef12-3456"])["corroboration"][0]["kind"] == "org_profile"
    absent = std._row("zendesk", "acme", "absent", marker="hc_404")
    assert std.corroborate(absent, saas_vendors=["zendesk"])["corroboration"] == []


# ------------------------------------------------------------------ FC5 after the scan: the corroboration rule
TENANT_RULE_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rules" / "p3g131_saas_tenant_corroborated"


@pytest.mark.parametrize("path", sorted(TENANT_RULE_FIXTURES.glob("*.json")), ids=lambda p: p.stem)
def test_corroboration_rule_fixtures(path: Path) -> None:
    from v3lum.core import correlate

    assert correlate.check_fixture("p3g131_saas_tenant_corroborated", path) == []


def test_corroboration_rule_names_the_evidence_and_never_echoes_tokens() -> None:
    from v3lum.core import correlate

    fx = correlate.load_graph_fixture(TENANT_RULE_FIXTURES / "positive_okta_tenant_is_the_federated_idp.json")
    corr = correlate.run_rules(fx.graph, fx.results, only={"p3g131_saas_tenant_corroborated"}, rctx=fx.rctx)[0]
    assert corr.entity_keys() == ["domain:acme.example", "domain:acme.okta.com"]
    assert corr.tags == ["saas_tenant"] and corr.label.value == "probable"
    assert any(e.startswith("idp_issuer:") for e in corr.evidence)
    fx2 = correlate.load_graph_fixture(TENANT_RULE_FIXTURES / "positive_atlassian_dns_verification.json")
    corr2 = correlate.run_rules(fx2.graph, fx2.results, only={"p3g131_saas_tenant_corroborated"}, rctx=fx2.rctx)[0]
    assert any("saas_vendors: atlassian at acme.example" in e for e in corr2.evidence)
