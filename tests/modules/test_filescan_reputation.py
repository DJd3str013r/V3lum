"""Offline tests of filescan_reputation (P178): live-captured answers trimmed to the documented fields."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.filescan_reputation import (
    MAX_BYTES,
    FilescanReputation,
    parse_reputation,
    raw_reduction,
    request_allowed,
)

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
OTHER = "7854a196c32610db487a0b7226da730a94952776af5d577848754ecde8d68690"
ZERO = "0" * 64


def url(sha: str) -> str:
    return f"https://www.filescan.io/api/reputation/hash?sha256={sha}"


def exchange(http: FakeHttp, target: str, name: str) -> FakeHttp:
    fx = module_fixture("filescan_reputation", name)["response"]
    headers = {k: v for k, v in fx["headers"].items() if k != "content-length"}
    return http.add("GET", target, status=fx["status"], json=fx["body"], headers=headers)


def run(sha: str, http: FakeHttp) -> Any:
    return run_module(FilescanReputation, f"sha256:{sha}", http)


def as_other(doc: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    out["sha256"] = OTHER
    return out


def test_complete_trimmed_live_answer_for_eicar() -> None:
    http = FakeHttp().add("GET", url(EICAR), json=module_fixture("filescan_reputation", "ok.json"))
    res = run(EICAR, http)
    assert res.status is Status.OK, res.error
    fs = res.attributes["filescan"]
    assert fs["verdict"] == "malicious" and fs["report_count"] == 6
    assert fs["verdict_counts"] == {"malicious": 4, "suspicious": 2}
    assert fs["mdcloud"] == {"detected": 13, "total": 16, "scan_time": "2026-11-26T03:52:38Z"}
    assert fs["first_report"] == "2021-08-22T23:04:07Z" and fs["last_report"] == "2026-11-26T08:55:16Z"
    assert res.findings[0].title == "Filescan: AV test file (EICAR)"
    # FC3: raw keeps only verdict, tags and report ids (newest first)
    assert set(res.raw) == {"verdict", "tags", "report_ids"}
    assert res.raw["report_ids"][0] == "48abf1f8-8bc9-4f37-97f4-21849775a4a3" and len(res.raw["report_ids"]) == 6
    assert any("/uploads/6b07f3f3593e7bf2de23d3b1/reports/48abf1f8" in link[1] for link in res.links)
    sent = http.calls[0]
    assert sent["max_bytes"] == MAX_BYTES
    assert not any(k.lower() in ("apikey", "authorization", "x-api-key") for k in sent["headers"])  # keyless: no key sent
    http.assert_hosts_within(FilescanReputation)


def test_malicious_verdict_is_one_opswat_vote() -> None:
    res = run(OTHER, FakeHttp().add("GET", url(OTHER), json=as_other(module_fixture("filescan_reputation", "ok.json"))))
    f = res.findings[0]
    assert f.title == "Filescan verdict: malicious" and f.severity.label == "medium"
    assert "OPSWAT vote" in f.criterion and f.source == "filescan.filescan_reputation"
    assert FilescanReputation.upstream_families == frozenset({"opswat"})


def test_likely_malicious_is_suspicious_and_informational_is_info() -> None:
    doc = as_other(module_fixture("filescan_reputation", "ok.json"))
    doc["overall_verdict"] = "likely_malicious"
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json=doc)).findings[0].severity.label == "low"
    doc["overall_verdict"] = "informational"
    res = run(OTHER, FakeHttp().add("GET", url(OTHER), json=doc))
    assert res.findings[0].severity.label == "info" and "not proof of safety" in res.findings[0].description


def test_unknown_hash_inside_200_is_an_absence() -> None:
    res = run(ZERO, FakeHttp().add("GET", url(ZERO), json=module_fixture("filescan_reputation", "not_found.json")))
    assert res.status is Status.EMPTY and "not a verdict" in res.error


def test_answer_over_2_mb_is_an_error_and_never_parsed() -> None:
    doc = as_other(module_fixture("filescan_reputation", "ok.json"))
    report = doc["filescan_reports"][0]
    doc["filescan_reports"] = [report] * 40000  # ~5 MB decoded, like popular hashes
    body = json.dumps(doc).encode()
    assert len(body) > MAX_BYTES
    res = run(OTHER, FakeHttp().add("GET", url(OTHER), body=body, headers={"content-type": "application/json"}))
    assert res.status is Status.ERROR and "too large" in res.error
    assert not res.attributes and not res.findings and not res.raw


def test_the_research_head_is_never_read_as_an_answer() -> None:
    head = module_fixture("filescan_reputation", "truncated_head.txt")
    res = run(EICAR, FakeHttp().add("GET", url(EICAR), text=head, headers={"content-type": "application/json"}))
    assert res.status is Status.ERROR and not res.findings


def test_bad_hash_route_change_and_rate_limits() -> None:
    res = run(OTHER, exchange(FakeHttp(), url(OTHER), "malformed_400.http.json"))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "Bad hash" not in res.error
    res = run(OTHER, exchange(FakeHttp(), url(OTHER), "route_404.http.json"))
    assert res.status is Status.ERROR and "route" in res.error
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), status=429, json={"detail": "slow"})).status is Status.RATE_LIMITED
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), status=403, text="forbidden")).status is Status.BLOCKED  # keyless 403
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), status=502, text="bad", times=3)).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), status=200, text=page)).status is Status.BLOCKED


def test_unexpected_layouts_and_foreign_hashes_are_errors() -> None:
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json={"detail": "x"})).status is Status.ERROR
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json=[1, 2])).status is Status.ERROR
    wrong = as_other(module_fixture("filescan_reputation", "ok.json"))
    wrong["sha256"] = "a" * 64
    assert run(OTHER, FakeHttp().add("GET", url(OTHER), json=wrong)).status is Status.ERROR
    p = parse_reputation({"overall_verdict": "malicious", "filescan_reports": [{"verdict": "malicious", "report_id": "../x", "flow_id": "z", "tags": [{"tag": "Loader"}]}, "junk"]})
    assert p["reports"][0]["report_id"] is None and p["tags"] == ["loader"]
    assert raw_reduction(p) == {"verdict": "malicious", "tags": ["loader"], "report_ids": []}


@pytest.mark.parametrize(("method", "target"), [
    ("POST", "https://www.filescan.io/api/scan/file"),
    ("POST", "https://www.filescan.io/api/scan/url"),
    ("GET", "https://www.filescan.io/api/scan/63af8afe0e926711fd75e445/report"),
    ("POST", "https://www.filescan.io/api/uploads"),
    ("GET", "https://www.filescan.io/api/uploads/63af8afe0e926711fd75e445/download"),
    ("POST", f"https://www.filescan.io/api/reputation/hash?sha256={OTHER}"),
    ("GET", f"https://evil.example/api/reputation/hash?sha256={OTHER}"),
    ("GET", f"http://www.filescan.io/api/reputation/hash?sha256={OTHER}"),
    ("GET", f"https://www.filescan.io/api/reputation/hash?sha256={OTHER}&apikey=x"),
    ("GET", "https://www.filescan.io/api/reputation/hash?sha256=abc"),
])
def test_uploads_scans_and_other_requests_are_never_built(method: str, target: str) -> None:
    assert request_allowed(method, target)


def test_the_lookup_is_allowed() -> None:
    assert request_allowed("GET", "https://www.filescan.io/api/reputation/hash", {"sha256": OTHER}) is None
