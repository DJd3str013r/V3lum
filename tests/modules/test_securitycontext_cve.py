"""securitycontext_cve (P188): comparison-only CVE facts from SecurityContext (unknown terms and tier).

Fixtures in tests/fixtures/securitycontext_cve/ (prep batch p2-G08-1, 2026-11-26): ``cve_ok.json``,
``not_found.http.json`` and ``bad_input.http.json`` are live (no personal data); ``rate_limited.http`` and
``challenge.http`` are DOC-SHAPED (a 429 was never provoked); ``schema_drift.json`` removes keys and changes a
type to exercise the schema check of cond 4.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.core.tlp import TLP
from v3lum.modules.vulnerability_cve.cve_record import CASE_COUNTERS
from v3lum.modules.vulnerability_cve.securitycontext_cve import CVE_URL, SecurityContextCve, schema_problem

CVE = "CVE-2021-44228"


@pytest.fixture(autouse=True)
def fresh_counters():
    CASE_COUNTERS.reset()
    yield
    CASE_COUNTERS.reset()


def fx(name: str):
    return module_fixture(SecurityContextCve, name)


def exchange(name: str) -> dict:
    resp = fx(name)["response"]
    return {"status": resp["status"], "headers": resp["headers"], "body": resp["body"].encode()}


def test_metadata_matches_the_council_decision():
    cls = SecurityContextCve
    assert cls.default_enabled is False and cls.terms == "unknown" and cls.trust_tier == "unknown"
    assert cls.max_tlp is TLP.GREEN  # excluded at AMBER and above (A2/A8)
    assert {t.value for t in cls.accepts} == {"cve"}  # keywords are not IOC_TYPES an unknown-tier provider may receive
    assert cls.opsec is Opsec.PASSIVE and cls.hosts == ("api.securitycontext.com",) and cls.cache_ttl == 86400


def test_values_are_comparison_only_never_primary_card_facts():
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), json=fx("cve_ok.json"))
    res = run_module(SecurityContextCve, f"cve:{CVE}", http)
    assert res.status is Status.OK, res.error
    a = res.attributes
    for primary in ("cvss", "cvss_scores", "epss", "kev", "exploited", "cwe"):
        assert primary not in a
    sec = a["cve_secondary"]
    assert sec["cvss"]["score"] == 10.0 and sec["epss"]["score"] == 0.99999
    assert sec["kev_lists"] == ["cisa", "vulncheck"] and sec["kev_cisa_added"] == "2021-12-10"
    assert sec["provider"] == "securitycontext" and "comparison" in sec["note"]
    assert a["nuclei_templates"] == ["CVE-2021-44228"]  # ids only (cond 5)
    urls = [p for p in res.pivots if p.entity.type.value == "url"]
    assert urls and all(p.expand is False and p.relation == "public_exploit" for p in urls)
    assert not any("nuclei-templates" in p.entity.value for p in res.pivots)  # templates never pivots
    assert not res.findings and res.requests == 1
    http.assert_hosts_within(SecurityContextCve)


def test_404_and_found_false_are_empty():
    ex = exchange("not_found.http.json")
    http = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-9999999"), status=404, body=ex["body"], headers=ex["headers"])
    assert run_module(SecurityContextCve, "cve:CVE-2021-9999999", http).status is Status.EMPTY
    http2 = FakeHttp().add("GET", CVE_URL.format(cve="CVE-2021-9999999"), json={"found": False, "code": "not_found"})
    assert run_module(SecurityContextCve, "cve:CVE-2021-9999999", http2).status is Status.EMPTY


def test_400_invalid_parameter_is_an_error():
    ex = exchange("bad_input.http.json")
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), status=400, body=ex["body"], headers=ex["headers"])
    assert run_module(SecurityContextCve, f"cve:{CVE}", http).status is Status.ERROR


def test_long_retry_after_is_rate_limited_short_one_waits_once():
    ex = exchange("rate_limited.http.json")  # Retry-After 42 s > 15 s: never waited
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), status=429, body=ex["body"], headers=ex["headers"])
    res = run_module(SecurityContextCve, f"cve:{CVE}", http)
    assert res.status is Status.RATE_LIMITED and len(http.calls) == 1
    http2 = FakeHttp()
    http2.add("GET", CVE_URL.format(cve=CVE), status=429, body=ex["body"], headers=dict(ex["headers"], **{"retry-after": "2"}), times=1)
    http2.add("GET", CVE_URL.format(cve=CVE), json=fx("cve_ok.json"))
    res2 = run_module(SecurityContextCve, f"cve:{CVE}", http2)
    assert res2.status is Status.OK and len(http2.calls) == 2


def test_cloudflare_challenge_is_blocked():
    ex = exchange("challenge.http.json")
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), status=403, body=ex["body"], headers=ex["headers"])
    res = run_module(SecurityContextCve, f"cve:{CVE}", http)
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_schema_drift_is_an_error_never_empty():
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), json=fx("schema_drift.json"))
    res = run_module(SecurityContextCve, f"cve:{CVE}", http)
    assert res.status is Status.ERROR and "schema" in res.error
    assert schema_problem(fx("cve_ok.json")) is None and schema_problem([]) == "schema: body is not an object"
    malformed = FakeHttp().add("GET", CVE_URL.format(cve=CVE), body=b'{"found": tr', headers={"content-type": "application/json"})
    assert run_module(SecurityContextCve, f"cve:{CVE}", malformed).status is Status.ERROR


def test_answer_for_another_id_is_an_error():
    doc = dict(fx("cve_ok.json"), cve="CVE-2020-0001")
    http = FakeHttp().add("GET", CVE_URL.format(cve=CVE), json=doc)
    assert run_module(SecurityContextCve, f"cve:{CVE}", http).status is Status.ERROR


def test_policy_gate_keeps_it_off_under_the_default_profile():
    """Unknown terms and tier: never in the effective default set, refused at the default TLP:AMBER (cond 2)."""
    from tests.fakes import make_runtime
    from v3lum.core import policy
    from v3lum.core.context import RunInfo, ScanOptions
    from v3lum.core.entities import Entity
    from v3lum.core.entities import EntityType as T

    rt = make_runtime(FakeHttp())
    entity = Entity.make(T.CVE, CVE)
    pctx = policy.make_context(rt, ScanOptions(include={"securitycontext_cve"}), explicit={"securitycontext_cve"})
    decision = policy.decide(SecurityContextCve, entity, pctx, run=RunInfo(entity=entity, is_seed=True))
    assert decision.allowed is False and decision.status is Status.SKIPPED
    assert decision.reason_code in ("licence", "tlp", "tier")


def test_conflict_rule_lists_each_disagreement_and_stays_silent_on_agreement():
    from tests.fakes import graph_fixture
    from v3lum.core import correlate

    base = "tests/fixtures/rules/g08_cve_secondary_conflicts/"
    graph, results, rctx = graph_fixture(base + "positive_cvss_epss_kev_cwe.json")
    corrs = correlate.run_rules(graph, results, only={"g08_cve_secondary_conflicts"}, rctx=rctx)
    assert len(corrs) == 1 and "context_only" in corrs[0].tags
    lines = corrs[0].evidence
    assert any(line.startswith("CVSS: card 10.0 (CISA-ADP v3.1 [cve_record]) vs securitycontext") for line in lines)
    assert any(line.startswith("EPSS: card 0.94000") for line in lines)
    assert any(line.startswith("KEV: CISA KEV lists the CVE") for line in lines)
    assert any(line.startswith("CWE: card CWE-502") for line in lines)
    graph2, results2, rctx2 = graph_fixture(base + "negative_agreement.json")
    assert correlate.run_rules(graph2, results2, only={"g08_cve_secondary_conflicts"}, rctx=rctx2) == []
