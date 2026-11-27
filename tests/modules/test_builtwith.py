"""builtwith (P073, batch p3-G03-1): BuiltWith Free / Domain / Relationships APIs (keyed).

Fixtures in tests/fixtures/builtwith/ (prep 2026-11-26): real keyless answers (free_nokey_error_in_200.json,
free_badkey_error_in_200.json from the research record, domain_badkey_error_in_200.http.json with the
X-RATELIMIT headers, relationships_badkey_error_in_200.json, relationship_types.json = the rv5 TYPES list);
BuiltWith's official documented samples (free_ok_documented.json, domain_ok_documented.json trimmed from
samples/domain_api_v22.json with the sample WHOIS/e-mails/phones removed, domain_v26_documented.json,
relationships_ok_documented.json served with a UTF-8 BOM, whoami_documented.json); synthetic answers in
the documented shapes for credits_exhausted.json, one_lookup_at_a_time.json, plan_upgrade.json,
invalid_domain.json, html_error_page.html, domain_pii_returned.json (documentation e-mails and +55 11
5555-01xx phones) and relationships_fanout.json (documentation domains, 192.0.2.10). P073 cond 6: no
team-key success capture exists yet (backlog p3-G03-1).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core import links, providers
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.url_web import builtwith as B
from v3lum.modules.url_web.builtwith import BuiltWith

KEY = "bwtestkey-0000-4000-8000-000000000001"
FX = Path(__file__).resolve().parent.parent / "fixtures" / "builtwith"
DOMAIN_MODE = {"builtwith_mode": "domain"}


def fx(name: str):
    return module_fixture(BuiltWith, name)


def raw(name: str) -> bytes:
    return (FX / name).read_bytes()


def url(endpoint: str, lookup: str = "example.com", page: int | None = None) -> str:
    q = f"KEY={KEY}&LOOKUP={lookup}&NOPII=yes&HIDETEXT=yes" + (f"&PAGE={page}" if page is not None else "")
    return f"{B.BUILTWITH_BASE}{B.ENDPOINTS[endpoint]}?{q}"


def run(http: FakeHttp, entity: str = "domain:example.com", settings: dict | None = None, **kw):
    return run_module(BuiltWith, entity, http, keys={"builtwith": KEY}, settings=settings, **kw)


def org(*domains: str) -> OrgProfile:
    return OrgProfile.from_dict({"domains": [{"name": d, "verification": "confirmed"} for d in domains or ("example.com",)],
                                 "brands": [{"keyword": "Example"}]})


# ------------------------------------------------------------------------------------------ metadata
def test_metadata_and_registry():
    cls = BuiltWith
    assert cls.default_enabled is False and cls.terms == "key-terms" and cls.requires_keys == ("builtwith",)
    assert cls.provider == "builtwith" and cls.sources == ("builtwith.api",) and cls.hosts == ("api.builtwith.com",)
    assert cls.trust_tier == "trusted" and cls.min_interval == 1.0 and cls.cache_ttl == 604800
    assert links.validate_manual_link(cls.manual_link) == []
    assert links.render(cls.manual_link, Entity.make(T.DOMAIN, "example.com")).url == "https://builtwith.com/relationships/example.com"
    markers = {m.id for m in providers.registry().get("builtwith").error_markers}
    assert {"builtwith_credits_exhausted", "builtwith_credits_message", "builtwith_one_lookup_at_a_time"} <= markers


def test_every_call_carries_nopii_and_hidetext_cond3():
    for endpoint in B.ENDPOINTS:
        params = B.builtwith_params(endpoint, "Example.COM", KEY, 1 if endpoint == "relationships" else None)
        assert params["NOPII"] == "yes" and params["HIDETEXT"] == "yes" and params["LOOKUP"] == "example.com"
    with pytest.raises(ValueError):
        B.builtwith_params("free", "a.com,b.com", KEY)


def test_missing_key_is_needs_key_without_request():
    http = FakeHttp()
    res = run_module(BuiltWith, "domain:example.com", http)
    assert res.status is Status.NEEDS_KEY and http.calls == []


# ------------------------------------------------------------------------------------------ Free API
def test_free_api_technology_groups_and_key_redaction():
    http = FakeHttp().add("GET", url("free"), json=fx("free_ok_documented.json"))
    res = run(http)
    assert res.status is Status.OK
    groups = res.attributes["builtwith_groups"]
    assert groups["endpoint"] == "free1" and [g["name"] for g in groups["groups"]] == ["javascript", "analytics"]
    assert groups["groups"][0]["categories"][0] == {"name": "social-sdk", "live": 2, "dead": 0, "latest": "2016-10-15T23:00:00Z",
                                                    "oldest": "2013-03-26T13:00:00Z"}
    assert groups["first"] == "2011-01-03T13:00:00Z"
    sent = http.calls[0]["url"]
    assert "NOPII=yes" in sent and "HIDETEXT=yes" in sent
    assert_no_secret(KEY, res.attributes, res.raw, res.error, res.findings, res.links)  # AR01: KEY= never leaves the client
    http.assert_hosts_within(BuiltWith)


@pytest.mark.parametrize("name", ["free_badkey_error_in_200.json", "free_nokey_error_in_200.json", "plan_upgrade.json"])
def test_login_and_plan_errors_in_200_are_needs_key_cond4(name):
    http = FakeHttp().add("GET", url("free"), json=fx(name))
    res = run(http)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


@pytest.mark.parametrize("name, status, code", [
    ("credits_exhausted.json", Status.QUOTA, "quota"),  # provider marker builtwith_credits_exhausted
    ("one_lookup_at_a_time.json", Status.RATE_LIMITED, "rate_limited"),  # provider marker builtwith_one_lookup_at_a_time
    ("invalid_domain.json", Status.ERROR, "error"),
])
def test_other_errors_in_200_are_never_empty_cond4(name, status, code):
    http = FakeHttp().add("GET", url("free"), json=fx(name))
    res = run(http)
    assert res.status is status and res.reason_code == code


def test_credit_message_without_code_is_quota():
    http = FakeHttp().add("GET", url("free"), json={"Errors": [{"Message": "You've run out of API Credits.", "Code": None}]})
    assert run(http).status is Status.QUOTA


@pytest.mark.parametrize("route, status", [
    ({"status": 401, "json": {"Errors": []}}, Status.NEEDS_KEY),
    ({"status": 403, "json": {"message": "forbidden"}}, Status.NEEDS_KEY),
    ({"status": 429, "json": {"message": "slow down"}}, Status.RATE_LIMITED),
    ({"status": 500, "text": raw("html_error_page.html").decode()}, Status.ERROR),
    ({"status": 200, "text": raw("html_error_page.html").decode()}, Status.ERROR),
    ({"status": 200, "body": b'{"groups": [', "headers": {"content-type": "text/json"}}, Status.ERROR),
    ({"status": 200, "json": {"domain": "example.com"}}, Status.ERROR),
])
def test_http_failures_and_malformed_answers(route, status):
    http = FakeHttp().add("GET", url("free"), **route)
    res = run(http)
    assert res.status is status
    if status is Status.ERROR:
        assert "could not verify" in res.error or "HTTP" in res.error


def test_empty_free_answer_is_empty():
    http = FakeHttp().add("GET", url("free"), json={"domain": "example.com", "first": 0, "last": 0, "groups": []})
    assert run(http).status is Status.EMPTY


# ------------------------------------------------------------------------- Domain + Relationships
def test_domain_and_relationships():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_ok_documented.json"),
                           headers={"x-api-credits-remaining": "198766", "x-ratelimit-limit-persecond": "10"})
            .add("GET", url("relationships", page=1), body=raw("relationships_ok_documented.json"), headers={"content-type": "text/json"}))
    res = run(http, settings=DOMAIN_MODE)
    assert res.status is Status.OK
    names = {t["name"] for t in res.attributes["technologies"]}
    assert {"MooTools", "WordPress 3.6", "Linode"} <= names
    profile = res.attributes["builtwith_profile"]
    assert profile["company"] == {"name": "Example Inc", "vertical": "Travel", "country": "US", "registrations": []}
    assert profile["pii_dropped"] == 0
    subs = {p.entity.value for p in res.pivots if p.relation == "subdomain"}
    assert subs == {"blog.example.com", "widgets.example.com"}
    related = [p for p in res.pivots if p.relation == "same_analytics"]
    assert [(p.entity.value, p.expand) for p in related] == [("related-example.com", False)]
    assert related[0].confidence <= 0.7
    ident = res.attributes["builtwith_identifiers"][0]
    assert ident["analytics_id"] == "UA-123456" and ident["kind"] == "analytics" and ident["shared"] is False
    budget = res.attributes["builtwith_budget"]
    assert budget["local_used_today"] == 2 and budget["credits_remaining"] == 198766
    assert all("NOPII=yes" in c["url"] and "HIDETEXT=yes" in c["url"] for c in http.calls)
    assert_no_secret(KEY, res.attributes, res.raw, res.pivots)


def test_personal_meta_is_dropped_and_never_cached_cond3():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_pii_returned.json"))
            .add("GET", url("relationships", page=1), json={"Relationships": [], "Errors": []}))
    res = run(http, settings=DOMAIN_MODE)
    assert res.status is Status.OK and res.attributes["builtwith_profile"]["pii_dropped"] == 8  # 2 e-mails, 2 phones, 1 WHOIS name, city, postcode, social
    assert_no_secret("person.one@example.com", res.attributes, res.raw, res.findings, res.pivots)
    assert_no_secret("5555-0100", res.attributes, res.raw)
    assert B.has_personal_meta(fx("domain_pii_returned.json")) is True
    assert B.has_personal_meta(fx("domain_ok_documented.json")) is False


def test_shared_ids_and_pivot_caps_without_org_profile_cond5():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_v26_documented.json"))
            .add("GET", url("relationships", page=1), json=fx("relationships_fanout.json")))
    res = run(http, settings=DOMAIN_MODE)
    assert res.status is Status.OK
    assert res.attributes["shared_tracking_ids"] == ["UA-1234567"]  # 60 domains > 50: 'shared ID', no pivots
    assert res.attributes["analytics_shared_id"][0]["domains"] == 60
    rows = {r["type"]: r for r in res.attributes["builtwith_identifiers"]}
    assert rows["UA"]["shared"] is True and rows["UA"]["pivots"] == [] and rows["UA"]["confidence"] <= 0.3
    assert len(rows["GTM"]["pivots"]) == 10  # 12 overlapping matches, capped at 10 per id
    assert rows["IP"]["value"] is None and rows["IP"]["kind"] == "infrastructure" and rows["IP"]["pivots"] == []
    assert rows["CNPJ"]["kind"] == "company_registration" and rows["CNPJ"]["pivots"] == []
    assert rows["ZZNEW"]["truncated"] is True  # last identifier of a page with more results
    same = {p.entity.value for p in res.pivots if p.relation == "same_analytics"}
    assert len(same) == 12 and not any(v.startswith("site") for v in same)  # 10 GTM + 2 AdSense, never the shared UA sites
    assert "shared-host.example.net" not in same  # IP ids never create relations
    ids = {p.entity.value for p in res.pivots if p.entity.type is T.ANALYTICS_ID}
    assert ids == {"GTM-ABC123", "pub-0000000000000001"}
    assert all(not p.expand for p in res.pivots if p.relation in ("same_analytics", "mentions"))
    assert res.attributes["builtwith_profile"]["company"]["registrations"] == [{"type": "ABN", "number": "23232322"}]


def test_clone_rule_with_org_profile_cond5():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_v26_documented.json"))
            .add("GET", url("relationships", page=1), json=fx("relationships_fanout.json")))
    res = run(http, settings=DOMAIN_MODE, org_profile=org("example.com"))
    clones = [f for f in res.findings if "possible_clone" in f.tags]
    assert clones and all(f.severity is Severity.MEDIUM and f.confidence <= 0.4 for f in clones)
    assert all("suspicious" not in f.tags for f in clones)  # the own site is never tagged hostile
    sites = {f.data["site"] for f in clones}
    assert {"example-login.test", "example.com.br"} <= sites and len(clones) <= B.CLONE_FINDING_CAP
    assert not any(p.relation == "same_analytics" for p in res.pivots)  # never a same-owner link
    assert all(not p.expand for p in res.pivots if p.relation == "copied_tracking_id")


def test_lookup_carrying_an_own_id_is_the_possible_clone():
    rel = {"Relationships": [{"Domain": "example-login.test", "Identifiers": [{
        "Value": "GTM-ABC123", "Type": "GTM", "First": 1609459200000, "Last": 1735689600000,
        "Matches": [{"Domain": "example.com", "First": 1640995200000, "Last": 1704067200000, "Overlap": True}]}]}],
        "Errors": [], "more_results": False}
    http = (FakeHttp().add("GET", url("domain", "example-login.test"), json={"Results": [], "Errors": []})
            .add("GET", url("relationships", "example-login.test", page=1), json=rel))
    res = run(http, "domain:example-login.test", settings=DOMAIN_MODE, org_profile=org("example.com"))
    finding = next(f for f in res.findings if "possible_clone" in f.tags)
    assert "suspicious" in finding.tags and finding.data["own_site"] == "example.com"


def test_relationship_types_are_classified():
    kinds = {t["abbreviation"]: B.identifier_kind(t["abbreviation"]) for t in fx("relationship_types.json") if isinstance(t, dict)}
    assert kinds["UA"] == "analytics" and kinds["IP"] == "infrastructure"
    assert kinds.get("CNPJ", "company_registration") == "company_registration"
    assert B.analytics_label("UA", "123456") == "UA-123456" and B.analytics_label("UA", "UA-123456-2") == "UA-123456-2"
    assert B.analytics_label("CA-PUB", "ca-pub-0000000000000001") == "pub-0000000000000001"
    assert B.analytics_label("GTM", "not an id!") is None


def test_relationships_failure_keeps_the_domain_profile():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_ok_documented.json"))
            .add("GET", url("relationships", page=1), json=fx("relationships_badkey_error_in_200.json")))
    res = run(http, settings=DOMAIN_MODE)
    assert res.status is Status.OK and "relationships_error" in res.attributes["builtwith_profile"]
    assert res.attributes["technologies"]


def test_relationships_rate_limit_keeps_data_as_partial():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_ok_documented.json"))
            .add("GET", url("relationships", page=1), status=429, json={"message": "slow down"}))
    res = run(http, settings=DOMAIN_MODE)
    assert res.attributes.get("technologies") and res.partial is True and res.stop_reason == "rate_limited"


def test_domain_api_errors_map_like_the_free_api():
    body = json.loads(raw("domain_badkey_error_in_200.http.json"))["response"]["body"]  # the capture wraps the real body
    http = FakeHttp().add("GET", url("domain"), text=body, headers={"content-type": "text/json; charset=utf-8", "x-ratelimit-limit-persecond": "10"})
    res = run(http, settings=DOMAIN_MODE)
    assert res.status is Status.NEEDS_KEY and len(http.calls) == 1  # no relationships call after a key error


# ------------------------------------------------------------------------------- local credit budget
def test_local_daily_credit_budget_cond2():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_ok_documented.json"))
            .add("GET", url("relationships", page=1), body=raw("relationships_ok_documented.json")))
    rt = make_runtime(http, keys={"builtwith": KEY}, settings={"builtwith_mode": "domain", "builtwith_daily_credits": 1}, clock=FakeClock())
    first = run_module(BuiltWith, "domain:example.com", runtime=rt)
    assert first.status is Status.OK and "credit budget" in first.attributes["builtwith_profile"]["relationships_error"]
    assert len(http.calls) == 1
    second = run_module(BuiltWith, "domain:example.net", runtime=rt)
    assert second.status is Status.QUOTA and second.reason_code == "quota" and len(http.calls) == 1


def test_credits_remaining_zero_stops_paid_lookups():
    http = (FakeHttp().add("GET", url("domain"), json=fx("domain_ok_documented.json"), headers={"x-api-credits-remaining": "0"})
            .add("GET", url("relationships", page=1), body=raw("relationships_ok_documented.json")))
    rt = make_runtime(http, keys={"builtwith": KEY}, settings=DOMAIN_MODE, clock=FakeClock())
    first = run_module(BuiltWith, "domain:example.com", runtime=rt)
    assert first.status is Status.OK and len(http.calls) == 1  # relationships skipped: no credits left
    second = run_module(BuiltWith, "domain:example.net", runtime=rt)
    assert second.status is Status.QUOTA and len(http.calls) == 1


def test_whoami_documented_sample_is_account_metadata_only():
    who = fx("whoami_documented.json")
    assert who["privacy"]["flags_supported"] == ["NOPII"] and who["credits"]["remaining"] == 198766
