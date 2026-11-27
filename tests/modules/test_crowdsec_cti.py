"""Offline tests of crowdsec_cti (P152) with the fixtures in tests/fixtures/crowdsec_cti/.

Provenance: ``needs_key_403.json`` is the real keyless answer (research 2026-11-25); the 200, 404 and
429 bodies are documented shapes (CrowdSec CTI v2 OpenAPI, AWS API Gateway error bodies) with
documentation addresses, until the team key exists (P152 c7, backlog)."""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, assert_no_secret, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import crowdsec_cti as mod
from v3lum.modules.threat_intel_ioc.crowdsec_cti import NOT_IN_DATA, CrowdsecCti, parse_smoke, request_allowed, verdict

FIX = "crowdsec_cti"
URL = "https://cti.api.crowdsec.net/v2/smoke/{ip}"
KEY_VALUE = "cs-test-key-0123456789abcdef"
KEYS = {"crowdsec": KEY_VALUE}
IP = "192.0.2.10"


def body(name: str) -> bytes:
    return json.dumps(module_fixture(FIX, name)).encode()


def route(ip: str, name: str | None = None, *, status: int = 200, http: FakeHttp | None = None, raw: bytes | None = None,
          headers: dict[str, str] | None = None, times: int | None = None) -> FakeHttp:
    http = http or FakeHttp()
    content = raw if raw is not None else (body(name) if name else b"")
    return http.add("GET", URL.format(ip=ip), status=status, body=content, times=times,
                    headers={"content-type": "application/json", **(headers or {})}, match_headers={"x-api-key": KEY_VALUE})


@pytest.fixture(autouse=True)
def doc_ips(monkeypatch):
    """The documented shapes use documentation addresses: let the module treat them as public."""
    monkeypatch.setattr(mod, "public_ip", lambda value: True)
    mod.CASE_COUNTERS.reset()


# --------------------------------------------------------------------------------------
# metadata (c1-c3, c7)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = CrowdsecCti
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure, cls.shares_input) == ("key-terms", True, "trusted", "third_party", True)
    assert cls.requires_keys == ("crowdsec",) and cls.run_on == "seeds" and cls.cache_ttl == 259200
    assert cls.hosts == ("cti.api.crowdsec.net",) and cls.sources == ("crowdsec.smoke",)
    assert cls.manual_link == "threat_intel_g07_p2:crowdsec_cti_ip" and cls.absent_statuses == frozenset({404})
    assert set(cls.settings) == {"crowdsec_monthly_quota", "crowdsec_case_budget"} and "reputation" in cls.tags
    prov = registry().get("crowdsec")
    assert prov.tier == "trusted" and prov.quota.month == 120 and prov.quota.scope == "key"
    assert registry().source("crowdsec.smoke").terms.free_plan_business_use is False
    keys = registry().keys()
    assert "V3LUM_CROWDSEC_KEY" in keys["crowdsec"].env
    assert prov.extra.get("x_redistribution", {}).get("external_exports") == "verdict, link and source name only"


def test_request_allow_list_is_one_smoke_lookup():
    assert request_allowed("GET", "https://cti.api.crowdsec.net/v2/smoke/192.0.2.10")
    assert request_allowed("GET", "https://cti.api.crowdsec.net/v2/smoke/2001:db8::1")
    for method, url in [
        ("POST", "https://cti.api.crowdsec.net/v2/smoke/192.0.2.10"),
        ("GET", "https://cti.api.crowdsec.net/v2/smoke?ips=192.0.2.10,192.0.2.11"),
        ("GET", "https://cti.api.crowdsec.net/v2/smoke/search?query=x"),
        ("GET", "https://cti.api.crowdsec.net/v2/fire"),
        ("GET", "https://cti.api.crowdsec.net/v2/smoke/not-an-ip"),
        ("GET", "http://cti.api.crowdsec.net/v2/smoke/192.0.2.10"),
        ("GET", "https://evil.example/v2/smoke/192.0.2.10"),
    ]:
        assert not request_allowed(method, url), url


def test_parser_reads_techniques_and_cves_from_scenarios():
    p = parse_smoke(module_fixture(FIX, "ok_malicious_synthetic.json"))
    assert p["reputation"] == "malicious" and [t["id"] for t in p["techniques"]] == ["T1190", "T1595"]
    assert p["cves"] == ["CVE-2021-44228"] and p["as_num"] == 64500 and p["country"] == "US"
    assert p["first_seen"] == "2026-10-03T23:00:00Z" and p["last_seen"] == "2026-11-24T23:30:00Z"
    assert parse_smoke({"message": "Forbidden"}) is None and parse_smoke(["x"]) is None
    # CVE ids named only by attack_details scenarios are merged (c6)
    q = parse_smoke({"ip": IP, "reputation": "suspicious", "attack_details": [{"name": "crowdsecurity/fortinet-cve-2018-13379"}]})
    assert q["cves"] == ["CVE-2018-13379"]


# --------------------------------------------------------------------------------------
# mapping (c5, c6, c7)
# --------------------------------------------------------------------------------------


def test_malicious_ip_is_medium_with_technique_and_attempted_cve_pivots():
    http = route(IP, "ok_malicious_synthetic.json")
    res = run_module(CrowdsecCti, f"ipv4:{IP}", http, keys=KEYS)
    assert res.status is Status.OK
    verdict_f = next(f for f in res.findings if f.title == "Malicious IP (CrowdSec CTI)")
    assert verdict_f.severity is Severity.MEDIUM and "malicious" in verdict_f.tags
    assert {"scanner", "exploit_attempt"} <= set(verdict_f.tags) and verdict_f.criterion and verdict_f.source == "crowdsec.smoke"
    assert str(verdict_f.observed_last).startswith("2026-11-24")
    cve_f = next(f for f in res.findings if f.title == "Exploitation attempts seen by CrowdSec")
    assert "attempted exploitation of CVE-2021-44228 seen by CrowdSec" in cve_f.description and cve_f.severity is Severity.INFO
    pivots = {(p.entity.type, p.entity.value): p for p in res.pivots}
    assert set(pivots) == {(T.MITRE, "T1190"), (T.MITRE, "T1595"), (T.CVE, "CVE-2021-44228")}
    assert all(not p.expand for p in res.pivots)
    assert pivots[(T.MITRE, "T1190")].relation == "uses_technique"
    cve = pivots[(T.CVE, "CVE-2021-44228")]
    assert cve.relation == "attempted_exploit" and "attempted exploitation of CVE-2021-44228 seen by CrowdSec" in cve.note
    assert not any(p.relation == "has_vuln" for p in res.pivots)  # c6: never feeds own-asset vulnerability rules (CR15)
    assert res.attributes["reputation"] == {"crowdsec": "malicious"} and res.attributes["asn"] == "AS64500"
    assert res.attributes["attack_techniques"] == ["T1190", "T1595"] and res.attributes["is_scanner"] is True
    restriction = res.attributes["export_restriction"]
    assert restriction["redistributable"] is False and restriction["external_exports"] == "verdict, link and source name only"
    assert ("CrowdSec CTI console", f"https://app.crowdsec.net/cti/{IP}") in res.links
    assert http.calls[0]["headers"]["x-api-key"] == KEY_VALUE  # header only, never in the URL
    assert KEY_VALUE not in http.calls[0]["url"]
    assert_no_secret(KEY_VALUE, res.to_dict())
    http.assert_hosts_within(CrowdsecCti)


def test_false_positive_crawler_is_info_context_that_dampens_never_known_good():
    ip = "198.51.100.66"
    res = run_module(CrowdsecCti, f"ipv4:{ip}", route(ip, "benign_crawler_synthetic.json"), keys=KEYS)
    assert res.status is Status.OK
    [f] = res.findings
    assert f.severity is Severity.INFO and f.title == "Benign or false-positive activity (CrowdSec CTI)"
    assert "known_good" not in f.tags and "malicious" not in f.tags
    assert "CrowdSec false positive: SEO crawler" in res.attributes["allowlisted"]
    assert "known_good" not in res.attributes


def test_legit_scanner_classification_marks_a_benign_scanner():
    ip = "203.0.113.77"
    res = run_module(CrowdsecCti, f"ipv4:{ip}", route(ip, "noise_scanner_synthetic.json"), keys=KEYS)
    [f] = res.findings
    assert f.tags == ["benign_scanner"] and f.severity is Severity.INFO
    assert res.attributes["scanner_classification"] == "benign" and res.attributes["is_scanner"] is True
    assert [p.entity.value for p in res.pivots] == ["T1595"]


def test_background_noise_scanner_is_low_and_never_votes():
    ip = "203.0.113.78"
    doc = module_fixture(FIX, "noise_scanner_synthetic.json")
    doc["classifications"]["classifications"] = []
    doc["reputation"] = "malicious"
    res = run_module(CrowdsecCti, f"ipv4:{ip}", route(ip, raw=json.dumps(doc).encode()), keys=KEYS)
    [f] = res.findings
    assert f.title == "Background-noise scanner (CrowdSec CTI)" and f.severity is Severity.LOW
    assert "scanner" in f.tags and not {"malicious", "botnet", "malware"} & set(f.tags)


def test_suspicious_ip_is_low_without_vote_tags():
    ip = "203.0.113.79"
    doc = module_fixture(FIX, "ok_malicious_synthetic.json")
    doc.update(reputation="suspicious", behaviors=[{"name": "generic:botnet", "label": "Botnet"}])
    res = run_module(CrowdsecCti, f"ipv4:{ip}", route(ip, raw=json.dumps(doc).encode()), keys=KEYS)
    f = next(f for f in res.findings if f.title == "Suspicious IP (CrowdSec CTI)")
    assert f.severity is Severity.LOW and "suspicious" in f.tags and "botnet" not in f.tags


def test_verdict_table():
    base = {"false_positives": [], "classifications": [], "behaviors": [], "background_noise": "none", "background_noise_score": 0}
    assert verdict({**base, "reputation": "malicious"})["severity"] == "medium"
    assert verdict({**base, "reputation": "suspicious"})["severity"] == "low"
    assert verdict({**base, "reputation": "unknown"})["band"] == "unknown"
    assert verdict({**base, "reputation": "safe"})["band"] == "benign_context"
    assert verdict({**base, "reputation": "malicious", "background_noise_score": 9})["band"] == "noise_scanner"


# --------------------------------------------------------------------------------------
# statuses (c4): rule 5 everywhere
# --------------------------------------------------------------------------------------


def test_404_is_not_in_crowdsec_data_never_benign():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, "not_found_404_synthetic.json", status=404), keys=KEYS)
    assert res.status is Status.EMPTY and res.error == NOT_IN_DATA and not res.findings
    assert res.attributes["crowdsec"]["state"] == "not_in_data"
    assert "benign" in res.error and "not a benign verdict" in res.error


def test_403_forbidden_is_needs_key():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, "needs_key_403.json", status=403), keys=KEYS)
    assert res.status is Status.NEEDS_KEY and res.reason_code == "needs_key"


def test_429_is_rate_limited_and_a_plan_limit_is_quota():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, "rate_limited_429_synthetic.json", status=429), keys=KEYS)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"
    ip = "192.0.2.11"
    res2 = run_module(CrowdsecCti, f"ipv4:{ip}", route(ip, "quota_429_synthetic.json", status=429), keys=KEYS)
    assert res2.status is Status.QUOTA and res2.reason_code == "quota"


def test_5xx_timeout_and_challenge_are_could_not_verify():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, raw=b'{"message": "Internal server error"}', status=503), keys=KEYS)
    assert res.status is Status.ERROR
    http = FakeHttp().add("GET", URL.format(ip=IP), error=TimeoutError("read timed out"))
    assert run_module(CrowdsecCti, f"ipv4:{IP}", http, keys=KEYS).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    http2 = FakeHttp().add("GET", URL.format(ip=IP), status=403, text=page)
    assert run_module(CrowdsecCti, f"ipv4:{IP}", http2, keys=KEYS).status is Status.BLOCKED


def test_error_in_200_and_malformed_answers_are_errors_never_empty():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, raw=b'{"message": "Internal error"}'), keys=KEYS)
    assert res.status is Status.ERROR and "error inside an HTTP 200" in res.error
    res2 = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, raw=b'{"ip": "192.0.2.10", "reputation": '), keys=KEYS)
    assert res2.status is Status.ERROR and "malformed JSON" in res2.error
    res3 = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, raw=b'["not", "an", "object"]'), keys=KEYS)
    assert res3.status is Status.ERROR


def test_without_a_key_nothing_is_sent():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", FakeHttp())
    assert res.status is Status.NEEDS_KEY


# --------------------------------------------------------------------------------------
# skips and budgets (c3)
# --------------------------------------------------------------------------------------


def test_seeds_only_pivots_are_never_looked_up():
    res = run_module(CrowdsecCti, f"ipv4:{IP}", FakeHttp(), keys=KEYS, is_seed=False, depth=1,
                     provenance=[("domain:example.com", "resolves_to", "dns_records")])
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    unconfirmed = ScanOptions(unconfirmed_seeds={f"ipv4:{IP}"})
    assert run_module(CrowdsecCti, f"ipv4:{IP}", FakeHttp(), keys=KEYS, options=unconfirmed).status is Status.SKIPPED


def test_private_noise_and_range_inputs_spend_no_lookup(monkeypatch):
    monkeypatch.setattr(mod, "public_ip", lambda value: mod.noise.is_public_ip(value))
    res = run_module(CrowdsecCti, "ipv4:10.0.0.1", FakeHttp(), keys=KEYS)
    assert res.status is Status.SKIPPED and "private" in res.error
    res2 = run_module(CrowdsecCti, "ipv4:8.8.8.8", FakeHttp(), keys=KEYS)  # public resolver: noise list
    assert res2.status is Status.SKIPPED and "noise" in res2.error
    res3 = run_module(CrowdsecCti, "cidr:203.0.113.0/24", FakeHttp(), keys=KEYS)
    assert res3.status is Status.SKIPPED and "one IP" in res3.error


def test_single_host_cidr_is_looked_up_as_the_ip():
    res = run_module(CrowdsecCti, f"cidr:{IP}/32", route(IP, "ok_malicious_synthetic.json"), keys=KEYS)
    assert res.status is Status.OK


def test_monthly_budget_setting_defers_further_lookups():
    settings = {"crowdsec_monthly_quota": 2}  # 80% of 2 -> one lookup this month
    first = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, "ok_malicious_synthetic.json"), keys=KEYS, settings=settings)
    assert first.status is Status.OK
    second = run_module(CrowdsecCti, "ipv4:192.0.2.12", FakeHttp(), keys=KEYS, settings=settings)
    assert second.status is Status.QUOTA and "monthly budget" in second.error and second.reason_code == "quota"


def test_case_budget_caps_one_scan():
    settings = {"crowdsec_case_budget": 1}
    first = run_module(CrowdsecCti, f"ipv4:{IP}", route(IP, "ok_malicious_synthetic.json"), keys=KEYS, settings=settings, case_id="case-1")
    assert first.status is Status.OK
    second = run_module(CrowdsecCti, "ipv4:192.0.2.13", FakeHttp(), keys=KEYS, settings=settings, case_id="case-1")
    assert second.status is Status.QUOTA and "this case" in second.error


def test_answers_are_cached_72h_and_a_cached_answer_spends_nothing():
    http = route(IP, "ok_malicious_synthetic.json", times=1)
    rt = make_runtime(http, keys=KEYS, cache=True)
    assert run_module(CrowdsecCti, f"ipv4:{IP}", runtime=rt).status is Status.OK
    again = run_module(CrowdsecCti, f"ipv4:{IP}", runtime=rt)
    assert again.status is Status.OK and len(http.calls) == 1
    from v3lum.core.context import ModuleState

    assert ModuleState("crowdsec_cti").get("monthly_lookups")["used"] == 1


# --------------------------------------------------------------------------------------
# licence (c2): the policy gate reads the key plan
# --------------------------------------------------------------------------------------


def test_licence_gate_needs_a_business_plan_under_corporate():
    from v3lum.core import module as module_mod
    from v3lum.core import policy
    from v3lum.core.context import RunInfo
    from v3lum.core.entities import Entity

    module_mod.load_modules()
    ip = Entity.make(T.IPV4, "203.0.113.5")
    free = policy.make_context(make_runtime(keys=KEYS), ScanOptions(), path="scan")
    decision = policy.decide(CrowdsecCti, ip, free, run=RunInfo(entity=ip, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.SKIPPED, "licence")
    assert decision.emit_manual_link is True
    business = policy.make_context(make_runtime(keys=KEYS, settings={"key_plans": {"crowdsec": "business"}}), ScanOptions(), path="scan")
    assert policy.decide(CrowdsecCti, ip, business, run=RunInfo(entity=ip, is_seed=True)).allowed
