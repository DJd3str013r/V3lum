"""Offline tests of the PolySwarm adapter (P177, module polyswarm).

The search fixture is synthetic (ArtifactInstance fields of the official client); the known-good and
ambiguous-hash answers come from the provider's documentation.
"""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlencode

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.hash_lookup_keyed import PolySwarm, parse_polyswarm_search

KEY = "polyswarm-test-key-0123456789abcdef"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
GOOD = "1c7aa8fbe407ac48f3149088e8e8d6005205517b7be30be91ee5621b6512f4d4"
OTHER = "7854a196c32610db487a0b7226da730a94952776af5d577848754ecde8d68690"


def url(value: str, kind: str = "sha256") -> str:
    return f"https://api.polyswarm.network/v3/search/hash/{kind}?{urlencode({'hash': value, 'community': 'default'})}"


def exchange(http: FakeHttp, target: str, name: str) -> FakeHttp:
    fx = module_fixture("polyswarm", name)["response"]
    return http.add("GET", target, status=fx["status"], json=fx["body"], headers=fx.get("headers"))


def run(value: str, http: FakeHttp, **kw: Any) -> Any:
    kw.setdefault("keys", {"polyswarm": KEY})
    return run_module(PolySwarm, f"sha256:{value}", http, **kw)


def renamed(doc: dict[str, Any], sha: str) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    for inst in out["result"]:
        inst.update({"sha256": sha, "md5": None, "sha1": None})
    return out


def test_latest_instance_gives_polyscore_engines_and_fuzzy_hashes() -> None:
    doc = module_fixture("polyswarm", "search_hash_ok_synthetic.json")
    http = FakeHttp().add("GET", url(EICAR), json=doc, match_headers={"authorization": KEY})
    res = run(EICAR, http)
    assert res.status is Status.OK, res.error
    ps = res.attributes["polyswarm"]
    assert ps["verdict"] == "malicious" and ps["polyscore"] > 0.99 and ps["detections"]["total"] == 13
    assert "EngineC" not in ps["malicious_engines"]  # verdict false / masked-out assertions are ignored
    assert res.findings[0].title == "PolySwarm: AV test file (EICAR)"  # EICAR: expected detections
    kinds = {p.entity.type.value for p in res.pivots if p.relation == "similarity_hash"}
    assert kinds == {"ssdeep", "tlsh"}
    assert_no_secret(KEY, res.to_dict())
    http.assert_hosts_within(PolySwarm)


def test_malicious_reading_is_a_suggestion_with_family_hints() -> None:
    doc = renamed(module_fixture("polyswarm", "search_hash_ok_synthetic.json"), OTHER)
    res = run(OTHER, FakeHttp().add("GET", url(OTHER), json=doc))
    f = res.findings[0]
    assert f.severity.label == "medium" and "PolySwarm defines no threshold" in f.criterion
    fams = [p.entity.value for p in res.pivots if p.relation == "family"]
    assert fams and fams[0] == "eicar"  # the polyunite label ranks first
    low = copy.deepcopy(doc)
    for inst in low["result"]:
        inst["polyscore"] = 0.4
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json=low)).findings[0].severity.label == "low"
    benign = copy.deepcopy(doc)
    for inst in benign["result"]:
        inst["polyscore"] = 0.05
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json=benign)).findings[0].severity.label == "info"


def test_known_good_documentation_answer() -> None:
    res = run(GOOD, FakeHttp().add("GET", url(GOOD), json=module_fixture("polyswarm", "search_hash_known_good_docs.json")))
    assert res.status is Status.OK
    assert res.attributes["known_good"] is True and res.findings[0].title == "PolySwarm: known-good file"


def test_absence_ambiguity_key_and_rate_limit() -> None:
    assert run(OTHER, exchange(FakeHttp(), url(OTHER), "not_found_404_synthetic.http.json")).status is Status.EMPTY
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json={"has_more": False, "result": []})).status is Status.EMPTY
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    res = run_module(PolySwarm, f"md5:{md5}", exchange(FakeHttp(), url(md5, "md5"), "ambiguous_400_docs.http.json"), keys={"polyswarm": KEY})
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "SHA-256" in res.error
    assert run(OTHER, exchange(FakeHttp(), url(OTHER), "unauthorized_401_synthetic.http.json")).status is Status.NEEDS_KEY
    assert run(OTHER, exchange(FakeHttp(), url(OTHER), "rate_limited_429_synthetic.http.json")).status is Status.RATE_LIMITED


def test_error_envelope_inside_200_and_malformed_json_are_errors() -> None:
    res = run(OTHER, FakeHttp().add("GET", url(OTHER), json={"status": "error", "errors": "internal", "result": None}))
    assert res.status is Status.ERROR
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), text="[", headers={"content-type": "application/json"})).status is Status.ERROR
    assert parse_polyswarm_search({"result": "x"})["status"] == "empty"
    assert parse_polyswarm_search("x")["status"] == "error"


def test_no_request_without_a_key() -> None:
    http = FakeHttp()
    assert run(OTHER, http, keys={}).status is Status.NEEDS_KEY and not http.calls
