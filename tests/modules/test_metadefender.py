"""Offline tests of the OPSWAT MetaDefender adapter (P177, module metadefender).

The success fixtures are synthetic (the documented v4 layout) until a key holder captures a real
answer (docs/backlog/p3-G07-2.md); the CloudFront block page is a real answer from this egress.
"""

from __future__ import annotations

import copy
from typing import Any

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.hash_lookup_keyed import MetaDefender, parse_metadefender_hash

KEY = "metadefender-test-key-0123456789"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
OTHER = "7854a196c32610db487a0b7226da730a94952776af5d577848754ecde8d68690"
URL = "https://api.metadefender.com/v4/hash/{h}"


def exchange(http: FakeHttp, url: str, name: str) -> FakeHttp:
    fx = module_fixture("metadefender", name)["response"]
    body = fx["body"]
    if isinstance(body, (dict, list)):
        return http.add("GET", url, status=fx["status"], json=body, headers=fx.get("headers"))
    return http.add("GET", url, status=fx["status"], text=body, headers=fx.get("headers"))


def run(value: str, http: FakeHttp, **kw: Any) -> Any:
    kw.setdefault("keys", {"metadefender": KEY})
    return run_module(MetaDefender, f"sha256:{value}", http, **kw)


def malicious_doc() -> dict[str, Any]:
    doc = copy.deepcopy(module_fixture("metadefender", "hash_ok_synthetic.json"))
    doc["file_info"].update({"sha256": OTHER.upper(), "md5": "3EFC2543CC833A797281A3467F1E1EAD", "sha1": None})
    doc.update({"threat_name": "Trojan.AgentTesla", "malware_family": "AgentTesla", "malware_type": ["trojan"]})
    return doc


def test_eicar_answer_is_a_test_file_with_engines_and_clean_text() -> None:
    http = FakeHttp().add("GET", URL.format(h=EICAR), json=module_fixture("metadefender", "hash_ok_synthetic.json"),
                          match_headers={"apikey": KEY})
    res = run(EICAR, http)
    assert res.status is Status.OK, res.error
    md = res.attributes["metadefender"]
    assert md["verdict"] == "malicious" and md["detected"] == 3 and md["total"] == 6
    assert md["wording"].startswith("3/6 engines flagged")
    assert res.findings[0].title == "MetaDefender: AV test file (EICAR)" and res.findings[0].severity.label == "info"
    assert "\x1b" not in str(res.to_dict())  # ANSI escape of the K7 entry stripped
    assert not [p for p in res.pivots if p.relation == "family"]
    assert_no_secret(KEY, res.to_dict())
    http.assert_hosts_within(MetaDefender)


def test_malicious_verdict_is_one_medium_opswat_vote_with_family() -> None:
    http = FakeHttp().add("GET", URL.format(h=OTHER), json=malicious_doc())
    res = run(OTHER, http)
    f = res.findings[0]
    assert f.title == "Flagged as malicious by MetaDefender engines" and f.severity.label == "medium"
    assert "OPSWAT vote" in f.criterion and f.source == "opswat_metadefender.hash_lookup"
    assert [p.entity.value for p in res.pivots if p.relation == "family"] == ["agenttesla"]
    assert res.attributes["av_signatures"]


def test_no_threat_is_info_and_never_called_clean() -> None:
    doc = module_fixture("metadefender", "hash_no_threat_synthetic.json")
    sha = parse_metadefender_hash(doc)["hashes"]["sha256"]
    res = run(sha, FakeHttp().add("GET", URL.format(h=sha), json=doc))
    assert res.status is Status.OK
    assert res.findings[0].severity.label == "info" and "not proof of safety" in res.findings[0].description


def test_404_is_an_absence_and_401_needs_a_key() -> None:
    assert run(OTHER, exchange(FakeHttp(), URL.format(h=OTHER), "not_found_404_synthetic.http.json")).status is Status.EMPTY
    assert run(OTHER, exchange(FakeHttp(), URL.format(h=OTHER), "invalid_key_401_synthetic.http.json")).status is Status.NEEDS_KEY


def test_429_is_quota_when_the_daily_allowance_is_gone_else_rate_limited() -> None:
    res = run(OTHER, exchange(FakeHttp(), URL.format(h=OTHER), "quota_429_synthetic.http.json"))
    assert res.status is Status.QUOTA and res.reason_code == "quota"
    res = run(OTHER, FakeHttp().add("GET", URL.format(h=OTHER), status=429, json={"error": {"code": 429000}}))
    assert res.status is Status.RATE_LIMITED


def test_cloudfront_block_page_is_blocked_never_absent() -> None:
    res = run(OTHER, exchange(FakeHttp(), URL.format(h=OTHER), "blocked_cloudfront_403.http.json"))
    assert res.status is Status.BLOCKED


def test_malformed_body_error_object_and_foreign_hash_are_errors() -> None:
    assert run(OTHER, FakeHttp().add("GET", URL.format(h=OTHER), text="<<", headers={"content-type": "application/json"})).status is Status.ERROR
    assert run(OTHER, FakeHttp().add("GET", URL.format(h=OTHER), json={"error": {"code": 500100, "messages": ["boom"]}})).status is Status.ERROR
    wrong = malicious_doc()
    wrong["file_info"]["sha256"] = "AB" * 32
    assert run(OTHER, FakeHttp().add("GET", URL.format(h=OTHER), json=wrong)).status is Status.ERROR
    assert run(OTHER, FakeHttp().add("GET", URL.format(h=OTHER), status=503, text="down", times=3)).status is Status.ERROR


def test_without_a_real_key_nothing_is_sent() -> None:
    http = FakeHttp()
    assert run(OTHER, http, keys={"metadefender": "your-api-key"}).status is Status.NEEDS_KEY
    assert not http.calls
