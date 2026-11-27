"""m365_tenant (P011): Microsoft first-party, domain-level tenant discovery.

Fixtures in tests/fixtures/m365_tenant/: the recorded research answers (microsoft.com OpenID
configuration, github.com v2 OpenID configuration, two GetUserRealm answers whose Login echoes the
research tools' own local parts, the microsoft.com ODC answer) and live answers recorded 2026-11-26 with
the fixed probe constant (microsoft.com managed realm, cloudflare.com federated to Cloudflare Access -
SSO app hash zeroed -, example.com claimed by an unmanaged test tenant - tenant id and names replaced by
placeholders -, example.invalid HTTP 400 AADSTS90002 - trace ids zeroed - and the ODC answer without
tenantId). Files ending in _derived are built from the documented shapes (HTML page, Unknown realm,
renamed ODC keys).
"""

from __future__ import annotations

import inspect
import re
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import m365_tenant as M
from v3lum.modules.domain_dns.m365_tenant import M365Tenant

MS_TID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
DOC_TID = "0e0e0e0e-0000-4000-8000-000000000001"
OPENID = "https://login.microsoftonline.com/{d}/.well-known/openid-configuration"
REALM = "https://login.microsoftonline.com/getuserrealm.srf?login=nonexistent.realm.probe@{d}&json=1"
ODC = "https://odc.officeapps.live.com/odc/v2.1/federationprovider?domain={d}"


def fx(name):
    return module_fixture(M365Tenant, name)


def routes(domain, *, openid="openid_ok.json", realm="getuserrealm_managed.json", odc="odc_ok.json", openid_status=200):
    http = FakeHttp()
    if openid is not None:
        body = fx(openid)
        if isinstance(body, str):
            http.add("GET", OPENID.format(d=domain), status=openid_status, text=body)
        else:
            http.add("GET", OPENID.format(d=domain), status=openid_status, json=body)
    if realm is not None:
        http.add("GET", REALM.format(d=domain), json=fx(realm))
    if odc is not None:
        http.add("GET", ODC.format(d=domain), json=fx(odc))
    return http


def run(http, entity, **kw):
    res = run_module(M365Tenant, entity, http, **kw)
    http.assert_hosts_within(M365Tenant)
    return res


def assert_only_probe_local_part(http, forbidden=()):
    """P011 c2: no request URL carries the input's local part; every login= local part is the constant."""
    for url in http.urls():
        for token in forbidden:
            assert token.lower() not in url.lower(), url
        query = parse_qs(urlsplit(url).query)
        for login in query.get("login", []):
            assert login.split("@", 1)[0] == M.PROBE_LOCAL_PART, url


# ------------------------------------------------------------------ metadata
def test_metadata_first_party_trusted_default():
    cls = M365Tenant
    assert (cls.provider, cls.terms, cls.trust_tier, cls.default_enabled) == ("microsoft_entra", "open", "trusted", True)
    assert cls.sources == ("microsoft_entra.openid", "microsoft_entra.getuserrealm", "microsoft_entra.odc")
    assert cls.hosts == ("login.microsoftonline.com", "odc.officeapps.live.com")
    assert (cls.max_requests, cls.cache_ttl, cls.opsec.label.lower()) == (3, 86400, "passive")
    assert cls.accepts == frozenset({T.DOMAIN, T.EMAIL})


# ------------------------------------------------------------------ c1, c4, c5: managed, federated, unmanaged
def test_managed_tenant_microsoft_com_recorded_answers():
    http = routes("microsoft.com")
    res = run(http, "domain:microsoft.com")
    assert res.status is Status.OK
    a = res.attributes
    assert a["m365_tenant_id"] == MS_TID and a["m365_tenant_region"] == "WW"
    assert a["m365_namespace_type"] == "Managed" and a["m365_brand_name"] == "Microsoft"
    assert a["m365_odc_environment"] == "Global" and "m365_anomalies" not in a
    assert http.urls() == [OPENID.format(d="microsoft.com"), REALM.format(d="microsoft.com"), ODC.format(d="microsoft.com")]
    finding = res.findings[0]
    assert finding.title == "Microsoft 365 / Entra ID tenant" and finding.severity.label.lower() == "info"
    assert finding.source == "microsoft_entra.openid" and MS_TID in finding.description
    orgs = [p for p in res.pivots if p.entity.type is T.ORG]
    assert [(p.entity.value, p.relation, p.expand) for p in orgs] == [("Microsoft", "company_of", False)]
    assert_only_probe_local_part(http)


def test_github_v2_openid_issuer_and_research_realm_fixtures():
    """The six recorded research fixtures (P011 c9): the v2 issuer carries the tenant id too; realm answers
    whose Login echoes another local part (sent by the research tools, never by V3LUM) are flagged."""
    http = routes("github.com", openid="openid_v2_ok.json", realm="getuserrealm_managed_research.json")
    res = run(http, "domain:github.com")
    assert res.attributes["m365_tenant_id"] == MS_TID
    assert any("echoed a login other than the probe" in a for a in res.attributes["m365_anomalies"])
    assert any("answered for microsoft.com" in a for a in res.attributes["m365_anomalies"])
    http2 = routes("microsoft.com", realm="getuserrealm_managed_research_test.json")
    res2 = run(http2, "domain:microsoft.com")
    assert any("echoed a login other than the probe" in a for a in res2.attributes["m365_anomalies"])


def test_federated_domain_records_the_identity_provider_as_a_passive_pivot():
    """cloudflare.com realm (live, federated to Cloudflare Access) served with the recorded OpenID/ODC shapes."""
    http = routes("cloudflare.com", realm="getuserrealm_federated.json")
    res = run(http, "domain:cloudflare.com")
    idp = res.attributes["m365_identity_provider"]
    assert idp["host"] == "cloudflare-security.cloudflareaccess.com" and idp["kind"] == "cloudflare_access"
    assert "?" not in idp["url"]  # the query (it echoes the probe login) is dropped
    assert res.attributes["m365_namespace_type"] == "Federated" and res.attributes["m365_brand_name"] == "Cloudflare, Inc."
    pivots = {(p.entity.value, p.relation) for p in res.pivots if p.entity.type is T.DOMAIN}
    assert pivots == {("cloudflare-security.cloudflareaccess.com", "identity_provider")}
    assert "cloudflareaccess.com" not in " ".join(http.hosts())  # the module never contacts the IdP (c5)


def test_unmanaged_test_tenant_is_flagged_and_never_pivots_its_brand():
    http = routes("example.com", openid="openid_unmanaged_example_com.json", realm="getuserrealm_federated_msft_sts.json",
                  odc="odc_unmanaged_example_com.json")
    res = run(http, "domain:example.com")
    a = res.attributes
    assert a["m365_tenant_id"] == DOC_TID and a["m365_identity_provider"]["kind"] == "microsoft_sts"
    assert any("unmanaged" in x for x in a["m365_anomalies"])
    assert res.pivots == []  # no IdP pivot to Microsoft's STS, no brand pivot for a junk tenant
    titles = {f.title: f for f in res.findings}
    assert titles["Microsoft 365 / Entra ID tenant"].confidence_label == "possible"
    assert "weak_signal" in titles["Unmanaged or test Microsoft 365 tenant claims the domain"].tags


def test_classify_idp_kinds():
    assert M.classify_idp("https://adfs.contoso.example/adfs/ls/?username=x")["kind"] == "adfs"
    assert M.classify_idp("https://contoso.okta.com/app/office365/sso/wsfed/passive")["kind"] == "okta"
    assert M.classify_idp("https://sso.connect.pingidentity.com/sso/wsf")["kind"] == "ping"
    sts = M.classify_idp("https://sts.microsoftonline.com/Trust/2005/UsernameMixed?username=a")
    assert sts["kind"] == "microsoft_sts" and sts["pivot"] is False
    assert M.classify_idp("javascript:alert(1)") is None and M.classify_idp(None) is None


# ------------------------------------------------------------------ c4: no tenant, one call per registrable domain
def test_no_tenant_is_empty_after_one_call():
    http = routes("example.invalid", openid="openid_not_found.json", realm=None, odc=None, openid_status=400)
    res = run_module(M365Tenant, "domain:example.invalid", http)
    assert res.status is Status.EMPTY and "AADSTS90002" in res.error
    assert len(http.calls) == 1  # GetUserRealm and ODC only when a tenant exists


def test_realm_unknown_after_a_tenant_is_an_anomaly():
    http = routes("microsoft.com", realm="getuserrealm_unknown_derived.json")
    res = run(http, "domain:microsoft.com")
    assert res.status is Status.OK
    assert res.source_statuses["microsoft_entra.getuserrealm"]["status"] == "empty"
    assert any("NameSpaceType Unknown" in a for a in res.attributes["m365_anomalies"])


def test_subdomains_query_their_registrable_domain_once_and_cache(tmp_path):
    http = routes("microsoft.com")
    rt = make_runtime(http, cache=True)
    first = run_module(M365Tenant, "domain:login.mail.microsoft.com", runtime=rt)
    second = run_module(M365Tenant, "domain:microsoft.com", runtime=rt)
    assert first.attributes["m365_tenant_id"] == second.attributes["m365_tenant_id"] == MS_TID
    assert [c["url"] for c in http.calls].count(OPENID.format(d="microsoft.com")) == 1  # 24 h cache: one call per domain


def test_public_suffix_inputs_are_not_applicable():
    res = run_module(M365Tenant, "domain:github.io", FakeHttp())
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")


# ------------------------------------------------------------------ c2: e-mail inputs
@pytest.mark.parametrize("address", ["Analyst.Name+tag@Microsoft.com", "j.doe@mail.microsoft.com"])
def test_email_inputs_are_reduced_to_the_domain(address):
    http = routes("microsoft.com")
    res = run(http, f"email:{address}")
    assert res.attributes["m365_tenant_id"] == MS_TID
    local = address.split("@", 1)[0]
    assert_only_probe_local_part(http, forbidden=(local, local.split("+")[0], "analyst", "j.doe"))
    assert all("microsoft.com" in u for u in http.urls())


def test_email_input_needs_a_purpose_but_not_explicit_selection():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.EMAIL, "someone@example.com")
    refused = policy.decide(M365Tenant, ent, policy.make_context(rt, ScanOptions(), path="scan"), run=RunInfo(entity=ent, is_seed=True))
    assert (refused.allowed, refused.reason_code) == (False, "privacy")
    allowed = policy.decide(M365Tenant, ent, policy.make_context(rt, ScanOptions(purpose="incident 42"), path="scan"),
                            run=RunInfo(entity=ent, is_seed=True))
    assert allowed.allowed  # the provider records a personal-data review: only the domain is ever sent


# ------------------------------------------------------------------ c3: rule 2, user oracles cannot be built
def test_user_oracles_cannot_be_built():
    assert set(M.TEMPLATES) == {"openid", "getuserrealm", "odc"}
    for kind in ("getcredentialtype", "autodiscover", "onedrive", "teams", "login", "getfederationinformation"):
        with pytest.raises(ValueError):
            M.build_url(kind, "contoso.example")
    forbidden = [
        "https://login.microsoftonline.com/common/GetCredentialType",
        "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc",
        "https://contoso-my.sharepoint.com/personal/jdoe_contoso_com/_layouts/15/onedrive.aspx",
        "https://teams.microsoft.com/api/mt/emea/beta/users/jdoe@contoso.example/externalsearchv3",
        "https://login.microsoftonline.com/getuserrealm.srf?login=jdoe@contoso.example&json=1",
        "https://login.microsoftonline.com/common/oauth2/token",
        "https://login.microsoftonline.com/contoso.example/.well-known/openid-configuration?x=GetCredentialType",
    ]
    for url in forbidden:
        assert M.url_allowed(url) is False, url
    assert M.url_allowed(M.build_url("openid", "myonedrive.example"))  # a marker inside the domain is not refused
    # no https literal of a user oracle exists anywhere in the module source
    literals = re.findall(r"https://[^\s\"']+", inspect.getsource(M))
    assert literals and not [u for u in literals if any(m in u.lower() for m in M.USER_ORACLE_MARKERS)]


def test_built_urls_send_only_the_probe_constant():
    url = M.build_url("getuserrealm", "contoso.example")
    assert url == "https://login.microsoftonline.com/getuserrealm.srf?login=nonexistent.realm.probe@contoso.example&json=1"
    with pytest.raises(ValueError):
        M.build_url("openid", "contoso.example/../common")


# ------------------------------------------------------------------ ODC states (c4: schema change is ERROR, never EMPTY)
def test_odc_schema_change_is_an_error_for_that_source_never_empty():
    http = routes("microsoft.com", odc="odc_schema_changed_derived.json")
    res = run(http, "domain:microsoft.com")
    assert res.status is Status.OK  # the OpenID facts stand
    st = res.source_statuses["microsoft_entra.odc"]
    assert (st["status"], st["reason_code"]) == ("error", "error") and "schema changed" in st["reason"]
    assert any("schema changed" in a for a in res.attributes["m365_anomalies"])


def test_odc_without_tenant_or_with_another_tenant_is_an_anomaly():
    http = routes("microsoft.com", odc="odc_no_tenant.json")
    assert any("no tenantId" in a for a in run(http, "domain:microsoft.com").attributes["m365_anomalies"])
    http2 = routes("microsoft.com", odc="odc_unmanaged_example_com.json")
    assert any("differs" in a for a in run(http2, "domain:microsoft.com").attributes["m365_anomalies"])


def test_parsers_on_odd_answers():
    assert M.parse_odc(b"<html>") == {"state": "schema_changed", "reason": M.ODC_SCHEMA_CHANGED}
    assert M.parse_odc({"environment": "Global", "endpoint": [], "authority_host": "x", "tenantId": "nope"})["state"] == "schema_changed"
    assert M.parse_openid(200, b"[1, 2]")["state"] == "error"
    assert M.parse_openid(200, {"issuer": "https://sts.windows.net/not-a-guid/"})["state"] == "error"
    assert M.parse_realm(b"{}", "x.example")["state"] == "error"


# ------------------------------------------------------------------ rule 5: could not verify, never 'no tenant'
def test_openid_failures_are_never_empty():
    cases = [
        (429, "slow down", Status.RATE_LIMITED),
        (500, "server error", Status.ERROR),
        (403, "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>", Status.BLOCKED),
    ]
    for status, body, expected in cases:
        http = FakeHttp().add("GET", OPENID.format(d="microsoft.com"), status=status, text=body)
        assert run_module(M365Tenant, "domain:microsoft.com", http).status is expected, status
    html = FakeHttp().add("GET", OPENID.format(d="microsoft.com"), text=fx("openid_html_derived.html"))
    assert run_module(M365Tenant, "domain:microsoft.com", html).status is Status.ERROR
    junk = FakeHttp().add("GET", OPENID.format(d="microsoft.com"), body=b'{"issuer": "https://sts.windows', headers={"content-type": "application/json"})
    assert run_module(M365Tenant, "domain:microsoft.com", junk).status is Status.ERROR
    other400 = FakeHttp().add("GET", OPENID.format(d="microsoft.com"), status=400, json={"error": "invalid_request", "error_codes": [900144]})
    assert run_module(M365Tenant, "domain:microsoft.com", other400).status is Status.ERROR


def test_realm_rate_limit_keeps_the_openid_facts():
    http = routes("microsoft.com", realm=None)
    http.add("GET", REALM.format(d="microsoft.com"), status=429, text="too many requests")
    res = run(http, "domain:microsoft.com")
    assert res.status is Status.OK and res.attributes["m365_tenant_id"] == MS_TID
    assert res.source_statuses["microsoft_entra.getuserrealm"]["status"] == "rate_limited"


# ------------------------------------------------------------------ AR21 golden-path routes (section 19)
@pytest.mark.parametrize("etype,value", [("domain", "example.com"), ("email", "someone@example.com")])
def test_acceptance_routes_answer_every_request_of_the_golden_input(etype, value):
    """tests/fixtures/acceptance/<type>/m365_tenant.json: the three recorded example.com answers (claimed by
    an unmanaged test tenant) cover exactly the module's requests; only the probe local part is sent."""
    from tests.fakes import fixture

    doc = fixture(f"acceptance/{etype}/m365_tenant.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "m365_tenant"
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], json=r["json"], headers=r["headers"])
    res = run(http, f"{etype}:{value}")
    assert res.status is Status.OK and res.attributes["m365_tenant_id"] == DOC_TID
    assert len(http.calls) == len(doc["routes"]) == 3 and http.unexpected == []
    assert all(f.severity.label == "info" for f in res.findings)
    assert_only_probe_local_part(http, forbidden=("someone",))
