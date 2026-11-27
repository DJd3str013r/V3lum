"""Offline tests of the Recorded Future Triage adapter (P177, module triage)."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlencode

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.malware_hash.hash_lookup_keyed import (
    Triage,
    check_request,
    parse_triage_overview,
    usable_key,
)

KEY = "triage-test-key-0123456789"
SHA = "22d653dab4765e13c5fce0bf46a28a098d05582148fdf3101093f3687b42a5f1"  # documented TrickBot example
MIXED_SHA = "7854a196c32610db487a0b7226da730a94952776af5d577848754ecde8d68690"
SEARCH = "https://tria.ge/api/v0/search"
OVERVIEW = "https://tria.ge/api/v0/samples/{sid}/overview.json"


def search_url(value: str, kind: str = "sha256") -> str:
    return f"{SEARCH}?{urlencode({'query': f'{kind}:{value}', 'limit': '10'})}"


def exchange(http: FakeHttp, method: str, url: str, name: str) -> FakeHttp:
    fx = module_fixture("triage", name)["response"]
    body = fx["body"]
    if isinstance(body, (dict, list)):
        return http.add(method, url, status=fx["status"], json=body, headers=fx.get("headers"))
    return http.add(method, url, status=fx["status"], text=body, headers=fx.get("headers"))


def search_doc(sid: str = "201026-n8zz26cd4s") -> dict[str, Any]:
    doc = copy.deepcopy(module_fixture("triage", "search_ok_docs.json"))
    doc["data"][0]["id"] = sid
    return doc


def run(value: str, http: FakeHttp, **kw: Any) -> Any:
    kw.setdefault("keys", {"triage": KEY})
    return run_module(Triage, f"sha256:{value}", http, **kw)


def test_documented_overview_gives_family_score_and_hostile_c2_pivots() -> None:
    http = (FakeHttp()
            .add("GET", search_url(SHA), json=search_doc(), match_headers={"authorization": f"Bearer {KEY}"})
            .add("GET", OVERVIEW.format(sid="201026-n8zz26cd4s"), json=module_fixture("triage", "overview_ok_docs.json")))
    res = run(SHA, http)
    assert res.status is Status.OK, res.error
    summary = res.attributes["triage_sandbox"]
    assert summary["score"] == 10 and summary["families"] == ["trickbot"] and summary["c2_count"] == 6
    assert res.attributes["malware_family"] == ["trickbot"]
    finding = res.findings[0]
    assert finding.title == "Triage sandbox: malicious behaviour"
    assert finding.severity.label == "medium" and finding.criterion and finding.source == "triage.triage_overview"
    assert {"malicious", "malware", "c2"} <= set(finding.tags)
    c2 = [p for p in res.pivots if p.relation == "communicates_with"]
    assert {p.entity.value for p in c2} == {f"192.0.2.{n}" for n in range(10, 16)}
    assert all(not p.expand and p.note.startswith("hostile:") for p in c2)  # never contacted, never auto-expanded
    fam = [p for p in res.pivots if p.relation == "family"]
    assert [p.entity.value for p in fam] == ["trickbot"] and not fam[0].expand
    assert any(link[1] == "https://tria.ge/201026-n8zz26cd4s" for link in res.links)
    # only the reported sample is read (the pending one is not); the key never leaves in the result
    assert len(http.calls) == 2
    assert_no_secret(KEY, res.to_dict())
    http.assert_hosts_within(Triage)


def test_extracted_credentials_ransom_notes_and_junk_c2_are_dropped() -> None:
    doc = module_fixture("triage", "overview_mixed_synthetic.json")
    http = (FakeHttp()
            .add("GET", search_url(MIXED_SHA), json=search_doc("261121-abcdefghjk"))
            .add("GET", OVERVIEW.format(sid="261121-abcdefghjk"), json=doc))
    res = run(MIXED_SHA, http)
    assert res.status is Status.OK, res.error
    values = {(p.entity.type.value, p.entity.value) for p in res.pivots if p.relation == "communicates_with"}
    assert ("domain", "c2.example.net") in values and ("domain", "c2.example.org") in values
    assert ("url", "https://c2.example.net/gate.php") in values
    assert ("ipv6", "2001:db8::10") in values and ("ipv4", "203.0.113.45") in values and ("ipv4", "198.51.100.45") in values
    assert not any(v.startswith("127.") or v.startswith("999.") for _, v in values)  # loopback and junk skipped
    drops = [p for p in res.pivots if p.relation == "drops"]
    assert [p.entity.value for p in drops] == ["http://198.51.100.20/payload.bin"] and not drops[0].expand
    assert res.attributes["attack_techniques"] == ["T1056.001", "T1552.001", "T1614"]
    sigs = res.attributes["triage_sandbox"]["signatures"]
    assert sigs[0]["name"] == "AgentTesla" and len(sigs) <= 5
    dump = str(res.to_dict())
    for secret in ("example-password-not-real", "exfil@example.com", "victim-user", "bc1qexample", "decrypt@example.com", "invoice.exe"):
        assert secret not in dump
    assert "config.credentials" in res.raw["reports"][0]["dropped"]


def test_empty_search_is_an_absence() -> None:
    http = FakeHttp().add("GET", search_url(SHA), json=module_fixture("triage", "search_empty_docs.json"))
    res = run(SHA, http)
    assert res.status is Status.EMPTY and "not a verdict" in res.error


def test_report_about_another_file_is_never_attached() -> None:
    other = copy.deepcopy(module_fixture("triage", "overview_ok_docs.json"))
    other["sample"]["sha256"] = "1" * 64
    for target in other["targets"]:
        target["sha256"] = "2" * 64
    http = (FakeHttp().add("GET", search_url(SHA), json=search_doc())
            .add("GET", OVERVIEW.format(sid="201026-n8zz26cd4s"), json=other))
    res = run(SHA, http)
    assert res.status is Status.OK
    assert res.findings[0].title == "Known to Triage, no finished report for this file"
    assert not [p for p in res.pivots if p.relation == "communicates_with"]


def test_untrusted_sample_ids_are_never_placed_in_a_path() -> None:
    doc = search_doc()
    doc["data"][0]["id"] = "../../samples/x/sample"
    http = FakeHttp().add("GET", search_url(SHA), json=doc)
    res = run(SHA, http)
    assert res.status is Status.OK  # only the pending sample is left: no overview request at all
    assert len(http.calls) == 1


@pytest.mark.parametrize("key", ["", "   ", "changeme", "short"])
def test_missing_or_placeholder_key_needs_a_key_and_sends_nothing(key: str) -> None:
    http = FakeHttp()
    res = run(SHA, http, keys={"triage": key} if key else {})
    assert res.status is Status.NEEDS_KEY and not http.calls
    assert not usable_key(key)


def test_401_needs_key_and_429_is_rate_limited() -> None:
    res = run(SHA, exchange(FakeHttp(), "GET", search_url(SHA), "nokey_401.http.json"))
    assert res.status is Status.NEEDS_KEY
    res = run(SHA, exchange(FakeHttp(), "GET", search_url(SHA), "rate_limited_429_synthetic.http.json"))
    assert res.status is Status.RATE_LIMITED


def test_error_object_inside_200_is_never_empty() -> None:
    http = FakeHttp().add("GET", search_url(SHA), json={"error": "INTERNAL", "message": "try again"})
    assert run(SHA, http).status is Status.ERROR
    http = FakeHttp().add("GET", search_url(SHA), json={"error": "UNAUTHORIZED", "message": "bad token"})
    assert run(SHA, http).status is Status.NEEDS_KEY


def test_5xx_malformed_json_and_challenge_pages_are_could_not_verify() -> None:
    assert run(SHA, FakeHttp().add("GET", search_url(SHA), status=500, text="oops", times=3)).status is Status.ERROR
    assert run(SHA, FakeHttp().add("GET", search_url(SHA), text="{not json", headers={"content-type": "application/json"})).status is Status.ERROR
    page = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"
    assert run(SHA, FakeHttp().add("GET", search_url(SHA), status=403, text=page)).status is Status.BLOCKED


def test_overview_404_and_undocumented_layout() -> None:
    http = (FakeHttp().add("GET", search_url(SHA), json=search_doc())
            .add("GET", OVERVIEW.format(sid="201026-n8zz26cd4s"), status=404, json={"error": "NOT_FOUND", "message": "gone"}))
    assert run(SHA, http).status is Status.ERROR  # a listed report that cannot be read: could not verify
    assert parse_triage_overview({"sample": "x"})["status"] == "error"
    assert parse_triage_overview([])["status"] == "error"


def test_md5_search_uses_the_matching_operator() -> None:
    md5 = "3e241f5a1e7be77f25078560c8660351"
    http = (FakeHttp().add("GET", search_url(md5, "md5"), json=search_doc())
            .add("GET", OVERVIEW.format(sid="201026-n8zz26cd4s"), json=module_fixture("triage", "overview_ok_docs.json")))
    res = run_module(Triage, f"md5:{md5}", http, keys={"triage": KEY})
    assert res.status is Status.OK
    same = {p.entity.value for p in res.pivots if p.relation == "same_file"}
    assert SHA in same
    assert check_request("triage", "GET", search_url(md5, "md5")) is None
    assert check_request("triage", "GET", f"{SEARCH}?query=md5:{SHA}&limit=10") is not None  # operator must match
