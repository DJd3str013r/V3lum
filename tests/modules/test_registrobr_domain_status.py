"""registrobr_domain_status (P021): registro.br avail API with BrasilAPI fallback, offline.

Fixtures in tests/fixtures/registrobr_domain_status/ (batch p3-G01-1 prep): real answers recorded from a datacenter
egress - ``avail_registered.json`` / ``brasilapi_registered.json`` (google.com.br, research 2026-11-25; suggestions
trimmed), ``brasilapi_registered_bbcombr.json`` (research), ``avail_registered_exempt.json`` /
``brasilapi_registered_exempt.json`` (nic.br, live 2026-11-26), ``avail_parent_answer.json`` /
``brasilapi_parent_answer.json`` (www.registro.br answered for registro.br, live) and ``*_rewritten_name.json``
(example.com answered as example.com.br, live). ``avail_html_200.html`` is the real registro.br SPA page (a sibling
live capture) served as an HTML-in-200 and ``brasilapi_challenge.html`` a real Cloudflare challenge page (tokens
redacted). The ``*_synthetic`` answers use the documented status table with ``v3lum-fixture-*.com.br`` names; the 403
envelopes are the stock nginx 403 page and the empty-body 403 shape rdap.registro.br served (cond 5).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, module_fixture, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.domain_dns import registrobr_domain_status as R
from v3lum.modules.domain_dns.registrobr_domain_status import RegistrobrDomainStatus

FX = FIXTURES / "registrobr_domain_status"


def fx(name):
    return module_fixture("registrobr_domain_status", name)


def avail(name):
    return R.AVAIL_URL.format(name=name)


def brapi(name):
    return R.BRASILAPI_URL.format(name=name)


def envelope(name):
    resp = fx(name)["response"]
    body = resp["body"]
    kw = {"status": resp["status"], "headers": resp.get("headers") or {}}
    if isinstance(body, (dict, list)):
        kw["json"] = body
    elif body:
        kw["text"] = body
    else:
        kw["body"] = b""
    return kw


def own(*names):
    return OrgProfile.from_dict({"org": {"name": "Example Org"},
                                 "domains": [{"name": n, "verification": "attested", "attested_by": "analyst", "attested_date": "2026-11-20"}
                                             for n in names]})


LOOKALIKE = (("domain:exemplo.com.br", "lookalike", "typosquat"),)


def run(entity, http, **kw):
    kw.setdefault("case_id", f"case-{id(http)}")  # a fresh per-run cap for every test
    return run_module(RegistrobrDomainStatus, entity, http, **kw)


# ------------------------------------------------------------------ metadata (cond 2, 4)
def test_contract_metadata():
    cls = RegistrobrDomainStatus
    assert cls.default_enabled is False and cls.terms == "open" and cls.trust_tier == "community"
    assert cls.min_interval >= 5.0 and cls.cache_ttl == 86400 and cls.max_requests == 2
    assert cls.produces == frozenset() and cls.max_pivots == 0  # never a CNPJ source, never pivots (cond 3)
    assert cls.sources == ("registrobr.avail", "brasilapi.registrobr") and cls.hosts == ("registro.br", "brasilapi.com.br")
    assert cls.shares_input is True


# ------------------------------------------------------------------ recorded answers (cond 3, 5)
def test_registered_name_from_the_recorded_avail_answer():
    http = FakeHttp().add("GET", avail("google.com.br"), json=fx("avail_registered.json"), match_headers={"Accept": "application/json"})
    res = run("domain:google.com.br", http)
    assert res.status is Status.OK
    assert res.attributes["registrobr_status"] == "registered"
    rec = res.attributes["registrobr_availability"]
    assert rec["status_code"] == 2 and rec["checked_name"] == "google.com.br" and rec["source"] == "registrobr.avail"
    assert rec["exempt"] is False and rec["publication_status"] == "published"
    assert res.attributes["registrobr_expires_at"] == "2027-05-18T03:00:00Z"  # -03:00 -> UTC; a fallback name, never 'expires'
    assert "expires" not in res.attributes and "created" not in res.attributes and not res.pivots
    assert not res.findings  # registered: facts only
    assert res.source_statuses["registrobr.avail"]["status"] == "ok" and "brasilapi.registrobr" not in res.source_statuses
    assert [c["url"] for c in http.calls] == [avail("google.com.br")]  # no fallback after a normal answer
    http.assert_hosts_within(RegistrobrDomainStatus)


def test_exempt_name_has_no_expiry():
    http = FakeHttp().add("GET", avail("nic.br"), json=fx("avail_registered_exempt.json"))
    res = run("domain:nic.br", http)
    assert res.attributes["registrobr_status"] == "registered" and res.attributes["registrobr_availability"]["exempt"] is True
    assert "registrobr_expires_at" not in res.attributes


@pytest.mark.parametrize("name,fixture_name", [
    ("google.com.br", "brasilapi_registered.json"),
    ("bb.com.br", "brasilapi_registered_bbcombr.json"),
    ("nic.br", "brasilapi_registered_exempt.json"),
])
def test_brasilapi_fallback_after_a_403(name, fixture_name):
    http = FakeHttp()
    http.add("GET", avail(name), **envelope("avail_403.http.json"))
    http.add("GET", brapi(name), json=fx(fixture_name))
    res = run(f"domain:{name}", http)
    assert res.status is Status.OK and res.attributes["registrobr_status"] == "registered"
    assert res.attributes["registrobr_availability"]["source"] == "brasilapi.registrobr"
    st = res.source_statuses
    assert st["registrobr.avail"]["status"] == "blocked" and st["registrobr.avail"]["reason_code"] == "challenge"
    assert st["brasilapi.registrobr"]["status"] == "ok"


def test_own_domain_available_is_high():
    name = "v3lum-fixture-livre.com.br"
    http = FakeHttp().add("GET", avail(name), json=fx("avail_available_synthetic.json"))
    res = run(f"domain:{name}", http, org_profile=own(name), is_seed=False, depth=1, provenance=(("domain:example.com", "related", "x"),))
    assert res.status is Status.OK and res.attributes["registrobr_status"] == "available"
    f = res.findings[0]
    assert f.title == "Own .br domain is available for registration" and f.severity is Severity.HIGH
    assert f.criterion and "own_asset" in f.tags and f.source == "registrobr.avail"


@pytest.mark.parametrize("fixture_name,phase", [("avail_release_synthetic.json", "open"), ("avail_waiting_release_synthetic.json", "waiting")])
def test_own_domain_in_release_is_high(fixture_name, phase):
    doc = fx(fixture_name)
    name = doc["fqdn"]
    http = FakeHttp().add("GET", avail(name), json=doc)
    res = run(f"domain:{name}", http, org_profile=own(name))
    assert res.attributes["registrobr_status"] == "in_release"
    assert res.attributes["registrobr_availability"]["release_phase"] == phase
    f = res.findings[0]
    assert f.title == "Own .br domain is in the registro.br release process" and f.severity is Severity.HIGH and "in_release" in f.tags


def test_lookalike_found_by_typosquat_is_checked_and_available_is_info():
    name = "v3lum-fixture-livre.com.br"
    http = FakeHttp().add("GET", avail(name), json=fx("avail_available_synthetic.json"))
    res = run(f"domain:{name}", http, is_seed=False, depth=1, provenance=LOOKALIKE)
    assert res.status is Status.OK
    f = res.findings[0]
    assert f.title == "Lookalike .br name is not registered" and f.severity is Severity.INFO and "typosquat" in f.tags


def test_brasilapi_available_answer():
    name = "v3lum-fixture-livre.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), status=429, text="<html><head><title>429 Too Many Requests</title></head></html>")
    http.add("GET", brapi(name), json=fx("brasilapi_available_synthetic.json"))
    res = run(f"domain:{name}", http)
    assert res.status is Status.OK and res.attributes["registrobr_status"] == "available"
    assert res.source_statuses["registrobr.avail"]["status"] == "rate_limited"


# ------------------------------------------------------------------ applicability and the per-run cap (cond 1)
@pytest.mark.parametrize("entity,kw", [
    ("domain:example.com", {}),  # not .br: the service would rewrite it to example.com.br
    ("domain:www.registro.br", {}),  # a subdomain is answered for its parent
    ("domain:v3lum-fixture.com.br", {"is_seed": False, "depth": 1, "provenance": (("domain:example.com.br", "subdomain", "ct_logs"),)}),
    ("domain:v3lum-fixture.com.br", {"is_seed": False, "depth": 1, "provenance": (("domain:example.com.br", "lookalike", "ct_logs"),)}),
])
def test_not_applicable_names_are_never_sent(entity, kw):
    http = FakeHttp()
    res = run(entity, http, **kw)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_per_run_cap_of_twenty_names():
    http = FakeHttp()
    names = [f"v3lum-fixture-{i}.com.br" for i in range(21)]
    for n in names:
        http.add("GET", avail(n), json={"status": 2, "fqdn": n, "fqdnace": "", "exempt": False})
    results = [run(f"domain:{n}", http, case_id="case-cap") for n in names]
    assert all(r.status is Status.OK for r in results[:20])
    assert results[20].status is Status.SKIPPED and results[20].reason_code == "policy"
    assert len(http.calls) == 20
    again = run(f"domain:{names[0]}", http, case_id="case-cap")  # a name already counted does not take a new slot
    assert again.status is Status.OK


# ------------------------------------------------------------------ could not verify (cond 4)
def test_403_on_both_sources_is_blocked_never_available():
    name = "v3lum-fixture.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), **envelope("avail_403_empty.http.json"))
    http.add("GET", brapi(name), status=403, text=(FX / "brasilapi_challenge.html").read_text(encoding="utf-8"))
    res = run(f"domain:{name}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    assert "registrobr_status" not in res.attributes and not res.findings
    assert "could not verify" in res.error


def test_429_on_both_is_rate_limited():
    name = "v3lum-fixture.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), **envelope("avail_429.http.json"))
    http.add("GET", brapi(name), status=429, json={"message": "Too many requests"})
    res = run(f"domain:{name}", http)
    assert res.status is Status.RATE_LIMITED and "registrobr_status" not in res.attributes


def test_timeout_and_brasilapi_500_are_error():
    name = "v3lum-fixture.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), error=NetworkError(fx("avail_timeout.http.json")["transport_error"], kind="ReadTimeout"))
    http.add("GET", brapi(name), **envelope("brasilapi_500.http.json"))
    res = run(f"domain:{name}", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert res.source_statuses["registrobr.avail"]["reason_code"] == "timeout"


@pytest.mark.parametrize("primary", [
    {"text": (FX / "avail_html_200.html").read_text(encoding="utf-8")},
    {"json": fx("avail_error_status8_synthetic.json")},
    {"text": '{"status": 2, "fqdn": "v3lum-fix', "headers": {"content-type": "application/json"}},
    {"json": ["not", "an", "object"]},
    {"json": {"status": 42, "fqdn": "v3lum-fixture.com.br"}},
])
def test_unusable_primary_answers_fall_back(primary):
    name = "v3lum-fixture.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), **primary)
    http.add("GET", brapi(name), json={"status_code": 2, "status": "REGISTERED", "fqdn": name, "fqdnace": "", "exempt": False})
    res = run(f"domain:{name}", http)
    assert res.status is Status.OK and res.attributes["registrobr_availability"]["source"] == "brasilapi.registrobr"
    assert res.source_statuses["registrobr.avail"]["status"] == "error"


@pytest.mark.parametrize("fallback", ["brasilapi_error_in_200_synthetic.json", "brasilapi_inconsistent_synthetic.json"])
def test_brasilapi_error_in_200_is_never_a_claim(fallback):
    name = "v3lum-fixture-livre.com.br"
    http = FakeHttp()
    http.add("GET", avail(name), **envelope("avail_403.http.json"))
    http.add("GET", brapi(name), json=fx(fallback))
    res = run(f"domain:{name}", http)
    assert res.status in (Status.BLOCKED, Status.ERROR) and "registrobr_status" not in res.attributes and not res.findings
    assert res.source_statuses["brasilapi.registrobr"]["status"] == "error"


def test_answer_for_another_name_is_invalid_and_never_falls_back():
    name = "v3lum-fixture.com.br"
    http = FakeHttp().add("GET", avail(name), json=fx("avail_rewritten_name.json"))  # answered for example.com.br
    res = run(f"domain:{name}", http)
    assert res.status is Status.ERROR and "another name" in res.error
    assert [c["url"] for c in http.calls] == [avail(name)]


def test_only_brasilapi_allowed():
    http = FakeHttp().add("GET", brapi("google.com.br"), json=fx("brasilapi_registered.json"))
    res = run("domain:google.com.br", http, allowed_sources={"brasilapi.registrobr"})
    assert res.status is Status.OK and [c["url"] for c in http.calls] == [brapi("google.com.br")]


# ------------------------------------------------------------------ parser (live rewrite/parent answers)
def test_parse_answer_live_rewrite_and_parent_answers():
    p = R.parse_answer("registrobr.avail", (FX / "avail_parent_answer.json").read_bytes(), "www.registro.br")
    assert p["valid"] is False and p["answered_for"] == "parent"
    p = R.parse_answer("brasilapi.registrobr", (FX / "brasilapi_parent_answer.json").read_bytes(), "www.registro.br")
    assert p["valid"] is False and p["answered_for"] == "parent"
    p = R.parse_answer("brasilapi.registrobr", (FX / "brasilapi_rewritten_name.json").read_bytes(), "example.com")
    assert p["valid"] is False and p["answered_for"] == "other"
    p = R.parse_answer("registrobr.avail", (FX / "avail_registered_exempt.json").read_bytes(), "nic.br")
    assert p["valid"] is True and p["status"] == "registered" and p["hosts"][0] == "a.dns.br"


def test_brasilapi_400_body_is_the_documented_error_schema():
    doc = fx("brasilapi_bad_request_400.http.json")["response"]["body"]
    p = R.parse_answer("brasilapi.registrobr", __import__("json").dumps(doc), "v3lum-fixture.com.br")
    assert p["valid"] is False and "error body" in p["problem"]


def test_to_utc_iso():
    assert R.to_utc_iso("2027-05-18T00:00:00-03:00") == "2027-05-18T03:00:00Z"
    assert R.to_utc_iso("2026-10-01") == "2026-10-01T00:00:00Z"
    assert R.to_utc_iso("garbage") is None and R.to_utc_iso(None) is None


# ------------------------------------------------------------------ doctor self-test
def test_health_selftest_uses_the_registry_own_name():
    from tests.fakes import make_ctx

    hc = RegistrobrDomainStatus.health_check()
    assert hc.offline is False and hc.selftest is not None and hc.entity is None  # not a probe on example.com
    http = FakeHttp().add("GET", avail("registro.br"), json=fx("avail_parent_answer.json"))  # live answer for registro.br
    assert hc.selftest(make_ctx(RegistrobrDomainStatus, http)).status == "ok"
    blocked = FakeHttp().add("GET", avail("registro.br"), **envelope("avail_403.http.json"))
    assert hc.selftest(make_ctx(RegistrobrDomainStatus, blocked)).status == "blocked"
