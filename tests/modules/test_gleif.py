"""Offline tests for P220 ``gleif`` and the shared GLEIF client (batch p2-G10-1).

Fixtures in tests/fixtures/gleif/ are trimmed real GLEIF answers (public companies only: Banco do Brasil,
its subsidiaries and Banco Votorantim), captured 2026-11-25/26, plus three synthetic error shapes
(``*_synthetic*``) and one truncated body.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import NetworkError
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import gleif_client as gc
from v3lum.modules.company_org.gleif import Gleif

BB = "00000000000191"
BB_LEI = "QE0Q0253K88YAGNPE356"
VOTORANTIM = "59588111000103"
VOTORANTIM_LEI = "X2EUTZGMHS8RBQFIUS93"
JSONAPI = {"content-type": "application/vnd.api+json"}


def fx(name: str):
    return module_fixture("gleif", name)


def add_exchange(http: FakeHttp, url: str, name: str) -> FakeHttp:
    ex = fx(name)
    return http.add("GET", url, status=ex["status"], body=ex["body"].encode("utf-8"), headers=ex.get("headers") or {})


def add_doc(http: FakeHttp, url: str, name: str) -> FakeHttp:
    return http.add("GET", url, body=json.dumps(fx(name)).encode("utf-8"), headers=JSONAPI)


def bb_routes(http: FakeHttp | None = None, *, children: bool = True) -> FakeHttp:
    http = http or FakeHttp()
    add_doc(http, gc.cnpj_url(BB), "cnpj_bb_ok.json")
    add_doc(http, gc.relation_url(BB_LEI, "direct-parent-reporting-exception"), "direct_parent_exception_bb.json")
    add_doc(http, gc.relation_url(BB_LEI, "ultimate-parent-reporting-exception"), "ultimate_parent_exception_bb.json")
    if children:
        add_doc(http, gc.relation_url(BB_LEI, "direct-children"), "direct_children_bb.json")
    return http


# ------------------------------------------------------------------ cond 2: formatted CNPJ only
def test_registered_as_filter_always_sends_the_formatted_cnpj():
    url = gc.cnpj_url(BB)
    assert "filter%5Bentity.registeredAs%5D=00.000.000%2F0001-91" in url
    assert BB not in url and "page%5Bsize%5D=10" in url
    assert gc.cnpj_url("00.000.000/0001-91") == url
    with pytest.raises(ValueError):
        gc.cnpj_url("00000000000192")  # wrong check digit: never sent


def test_raw_digits_fixture_documents_why_digits_are_never_sent():
    # research capture: the same filter with raw digits answers 0 hits
    assert gc.parse_lei_records(fx("cnpj_raw_digits_empty.json"))["total"] == 0
    assert gc.parse_lei_records(fx("cnpj_bb_ok.json"))["records"][0]["registered_as"] == "00.000.000/0001-91"


# ------------------------------------------------------------------ cond 3, 5, 6: the happy path
def test_bb_record_with_reporting_exceptions_and_children():
    http = bb_routes()
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.OK
    assert res.attributes["lei"] == BB_LEI
    line = res.attributes["lei_summary"]
    assert line.startswith(f"LEI {BB_LEI} | BANCO DO BRASIL SA | ISSUED | updated 2026-08-07")
    assert "direct parent: none reported (NON_CONSOLIDATING)" in line and "ultimate parent: none reported (NON_CONSOLIDATING)" in line
    record = res.attributes["lei_record"]
    assert record["cnpj"] == BB and record["registered_at"] == "RA000041" and record["jurisdiction"] == "BR"
    kids = res.attributes["lei_children"]
    assert kids["count"] == 3 and kids["shown"] == 3 and not kids["truncated"]
    assert {c["lei"] for c in kids["children"]} == {"635400ULZIFPG1KU1F60", "635400MHDAK5JBDC6M46", VOTORANTIM_LEI}
    pivots = {p.entity.value: p for p in res.pivots}
    assert {p.relation for p in res.pivots} == {"company_of"}
    assert pivots["BANCO VOTORANTIM S.A."].expand is True  # direct child of an analyst seed: one level
    assert "CNPJ 59.588.111/0001-03" in pivots["BANCO VOTORANTIM S.A."].note and "never scope" in pivots["BANCO VOTORANTIM S.A."].note
    assert res.attributes["data_attribution"].startswith("LEI data: GLEIF (CC0 1.0)")
    assert res.findings == []  # an LEI is context, never a finding
    assert len(http.calls) == 4  # cond 3: record, two parent slots, children
    assert any("search.gleif.org/#/record/" in url for _label, url in res.links)
    http.assert_hosts_within(Gleif)


def test_direct_parent_is_reused_as_ultimate_parent_and_pivots_as_partner():
    http = FakeHttp()
    add_doc(http, gc.cnpj_url(VOTORANTIM), "cnpj_votorantim_ok.json")
    add_doc(http, gc.relation_url(VOTORANTIM_LEI, "direct-parent"), "direct_parent_votorantim_ok.json")
    res = run_module(Gleif, f"cnpj:{VOTORANTIM}", http)
    assert res.status is Status.OK
    assert len(http.calls) == 2  # the parent has no parent: the ultimate parent is the same record, not re-requested
    parents = res.attributes["lei_parents"]
    assert parents["direct"]["lei"] == BB_LEI and parents["ultimate"]["lei"] == BB_LEI and parents["ultimate_state"] == "same_as_direct"
    assert f"direct parent: BANCO DO BRASIL SA ({BB_LEI})" in res.attributes["lei_summary"]
    [pivot] = res.pivots
    assert pivot.relation == "partner" and pivot.entity.value == "BANCO DO BRASIL SA" and pivot.expand is True
    assert "CNPJ 00.000.000/0001-91" in pivot.note


def test_relations_found_from_a_pivot_are_never_expanded():
    res = run_module(Gleif, f"cnpj:{BB}", bb_routes(), is_seed=False, depth=1,
                     provenance=(("cnpj:00000000000191", "partner_of", "cnpj_lookup"),))
    assert res.status is Status.OK and res.pivots
    assert all(p.expand is False for p in res.pivots)  # cond 5: beyond one level from the seed


def test_children_are_capped_at_ten():
    doc = fx("direct_children_bb.json")
    base = doc["data"][2]
    many = []
    for i in range(14):
        rec = json.loads(json.dumps(base))
        rec["attributes"]["entity"]["legalName"]["name"] = f"SUBSIDIARY {i:02d} S.A."
        many.append(rec)
    doc["data"] = many
    doc["meta"]["pagination"]["total"] = 14
    parsed = gc.parse_children(doc)
    assert len(parsed["children"]) == 10 and parsed["truncated"] and parsed["total"] == 14


def test_relation_plan_never_exceeds_four_requests():
    record = gc.parse_lei_records(fx("cnpj_bb_ok.json"))["records"][0]
    assert gc.relation_plan(record, used=1) == [
        "direct-parent-reporting-exception", "ultimate-parent-reporting-exception", "direct-children"]
    assert gc.relation_plan(record, used=3) == ["direct-parent-reporting-exception"]
    assert Gleif.max_requests == 4 and gc.PAGE_SIZE == 10


# ------------------------------------------------------------------ cond 6: no LEI is info, never a risk
def test_no_lei_is_an_info_context_finding_and_empty():
    http = FakeHttp().add("GET", gc.cnpj_url(BB), body=json.dumps(fx("cnpj_raw_digits_empty.json")).encode(), headers=JSONAPI)
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.EMPTY
    [finding] = res.findings
    assert finding.title == "No LEI registered (GLEIF)" and finding.severity is Severity.INFO
    assert "context_only" in finding.tags and "not a risk signal" in finding.description
    assert res.attributes["lei_summary"].startswith("no LEI for CNPJ 00.000.000/0001-91")
    assert not res.pivots


# ------------------------------------------------------------------ cond 7: rule 5
def test_404_with_the_gleif_body_on_a_parent_slot_reads_none_reported():
    http = FakeHttp()
    add_doc(http, gc.cnpj_url(VOTORANTIM), "cnpj_votorantim_ok.json")
    add_exchange(http, gc.relation_url(VOTORANTIM_LEI, "direct-parent"), "direct_parent_not_found.http.json")
    add_exchange(http, gc.relation_url(VOTORANTIM_LEI, "ultimate-parent"), "direct_parent_not_found.http.json")
    res = run_module(Gleif, f"cnpj:{VOTORANTIM}", http)
    assert res.status is Status.OK
    assert "direct parent: none reported" in res.attributes["lei_summary"]
    assert not res.pivots


def test_404_without_the_gleif_body_is_an_error_never_an_absence():
    http = FakeHttp().add("GET", gc.cnpj_url(BB), status=404, text="<html><body>Not Found</body></html>")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert not res.findings  # never 'No LEI'


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (403, "forbidden", Status.BLOCKED),
        (401, "unauthorized", Status.BLOCKED),
        (500, "upstream error", Status.ERROR),
        (503, "maintenance", Status.ERROR),
    ],
)
def test_http_failures_are_could_not_verify(status, body, expected):
    http = FakeHttp().add("GET", gc.cnpj_url(BB), status=status, text=body)
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is expected
    assert not res.findings and "lei" not in res.attributes


def test_429_is_rate_limited():
    http = add_exchange(FakeHttp(), gc.cnpj_url(BB), "rate_limited_synthetic.http.json")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.RATE_LIMITED and res.reason_code == "rate_limited"


def test_timeout_is_an_error_with_reason_timeout():
    http = FakeHttp().add("GET", gc.cnpj_url(BB), error=NetworkError("read timed out", kind="ReadTimeout", retryable=False))
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"


def test_error_inside_http_200_is_detected():
    http = add_doc(FakeHttp(), gc.cnpj_url(BB), "error_in_200_synthetic.json")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "error inside HTTP 200" in res.error


def test_html_maintenance_page_in_200_is_an_error():
    http = add_exchange(FakeHttp(), gc.cnpj_url(BB), "html_200_synthetic.http.json")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_truncated_json_is_an_error():
    body = module_fixture("gleif", "cnpj_truncated.txt").encode("utf-8")
    http = FakeHttp().add("GET", gc.cnpj_url(BB), body=body, headers=JSONAPI)
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR


def test_document_without_data_member_is_an_error():
    http = FakeHttp().add("GET", gc.cnpj_url(BB), body=b'{"meta": {}}', headers=JSONAPI)
    assert run_module(Gleif, f"cnpj:{BB}", http).status is Status.ERROR


def test_records_without_the_queried_cnpj_mean_the_filter_was_ignored():
    http = add_doc(FakeHttp(), gc.cnpj_url(BB), "cnpj_votorantim_ok.json")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.ERROR and "filter ignored" in res.error


def test_a_failed_relation_keeps_the_record_and_never_says_none():
    http = bb_routes(children=False)
    add_exchange(http, gc.relation_url(BB_LEI, "direct-children"), "rate_limited_synthetic.http.json")
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"
    assert res.attributes["lei"] == BB_LEI and "lei_children" not in res.attributes
    assert "direct children" in res.error and "could not verify" in res.error


def test_a_blocked_parent_slot_reads_could_not_verify():
    http = FakeHttp()
    add_doc(http, gc.cnpj_url(VOTORANTIM), "cnpj_votorantim_ok.json")
    http.add("GET", gc.relation_url(VOTORANTIM_LEI, "direct-parent"), status=403, text="forbidden")
    http.add("GET", gc.relation_url(VOTORANTIM_LEI, "ultimate-parent"), status=403, text="forbidden")
    res = run_module(Gleif, f"cnpj:{VOTORANTIM}", http)
    assert res.status is Status.OK
    assert "direct parent: could not verify" in res.attributes["lei_summary"]
    assert "ultimate parent: could not verify" in res.attributes["lei_summary"]
    assert not res.pivots


def test_only_usable_documents_are_cacheable():
    class R:
        def __init__(self, status: int, content: bytes) -> None:
            self.status, self.content = status, content

    assert gc._cacheable(R(200, json.dumps(fx("cnpj_bb_ok.json")).encode()))
    assert gc._cacheable(R(404, fx("direct_parent_not_found.http.json")["body"].encode()))
    assert not gc._cacheable(R(200, json.dumps(fx("error_in_200_synthetic.json")).encode()))
    assert not gc._cacheable(R(200, b"<html>maintenance</html>"))
    assert not gc._cacheable(R(404, b"<html>Not Found</html>"))


# ------------------------------------------------------------------ cond 4: names and keywords
def test_exact_company_name_seed_matches_one_record_without_expansion():
    http = FakeHttp()
    add_doc(http, gc.name_url("BANCO DO BRASIL SA"), "name_bb_ok.json")
    add_doc(http, gc.relation_url(BB_LEI, "direct-parent-reporting-exception"), "direct_parent_exception_bb.json")
    add_doc(http, gc.relation_url(BB_LEI, "ultimate-parent-reporting-exception"), "ultimate_parent_exception_bb.json")
    add_doc(http, gc.relation_url(BB_LEI, "direct-children"), "direct_children_bb.json")
    res = run_module(Gleif, "company_name:BANCO DO BRASIL SA", http)
    assert res.status is Status.OK and res.attributes["lei"] == BB_LEI  # 'BANCO DO NORDESTE DO BRASIL SA' is not an exact match
    assert res.pivots and all(p.expand is False and p.confidence <= 0.5 for p in res.pivots)


def test_company_name_pivot_records_only_without_relations():
    http = add_doc(FakeHttp(), gc.name_url("BANCO DO BRASIL SA"), "name_bb_ok.json")
    res = run_module(Gleif, "company_name:BANCO DO BRASIL SA", http, is_seed=False, depth=1,
                     provenance=(("cnpj:59588111000103", "partner", "gleif"),))
    assert res.status is Status.OK and len(http.calls) == 1 and not res.pivots


def test_ambiguous_names_are_hypotheses():
    doc = fx("name_bb_ok.json")
    doc["data"][1]["attributes"]["entity"]["legalName"]["name"] = "BANCO DO BRASIL S.A."  # two normalised-equal names
    http = FakeHttp().add("GET", gc.name_url("Banco do Brasil S/A"), body=json.dumps(doc).encode(), headers=JSONAPI)
    res = run_module(Gleif, "company_name:Banco do Brasil S/A", http)
    assert res.status is Status.OK and "lei" not in res.attributes
    assert len(res.attributes["lei_candidates"]) == 2
    assert all(p.relation == "lei_candidate" and p.expand is False and p.confidence <= 0.5 for p in res.pivots)


def test_legal_name_pivot_of_a_cnpj_record_is_not_searched_again():
    res = run_module(Gleif, "company_name:BANCO DO BRASIL SA", FakeHttp(), is_seed=False, depth=1,
                     provenance=(("cnpj:00000000000191", "legal_name", "cnpj_lookup"),))
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_keyword_runs_only_when_selected_explicitly():
    runtime = make_runtime(FakeHttp())
    runtime.in_scan = True
    res = run_module(Gleif, "keyword:banco do brasil", runtime=runtime, options=ScanOptions(include={"cnpj_lookup"}))
    assert res.status is Status.SKIPPED and res.reason_code == "not_default"


def test_keyword_fuzzy_hits_are_hypotheses_when_selected():
    http = add_doc(FakeHttp(), gc.fuzzy_url("banco do brasil"), "fuzzycompletions_ok.json")
    runtime = make_runtime(http)
    runtime.in_scan = True
    res = run_module(Gleif, "keyword:banco do brasil", runtime=runtime, options=ScanOptions(include={"gleif"}))
    assert res.status is Status.OK
    assert len(res.attributes["lei_candidates"]) == 6
    assert all(p.relation == "lei_candidate" and p.expand is False and p.confidence <= 0.5 for p in res.pivots)
    names = {p.entity.value for p in res.pivots}
    assert "BANCO DO BRASIL S.A. - TOKYO BRANCH" in names


def test_lei_check_digits():
    assert gc.lei_valid(BB_LEI) and gc.lei_valid(VOTORANTIM_LEI)
    assert not gc.lei_valid("QE0Q0253K88YAGNPE357") and not gc.lei_valid("not-a-lei")
    with pytest.raises(ValueError):
        gc.record_url("QE0Q0253K88YAGNPE357")


def test_sole_proprietor_records_keep_no_address_and_never_pivot():
    doc = fx("direct_children_bb.json")
    doc["data"][2]["attributes"]["entity"]["category"] = "SOLE_PROPRIETOR"
    rec = gc.parse_children(doc)["children"][2]
    assert rec["natural_person"] and rec["legal_address"] is None


def test_acceptance_routes_replay_the_golden_cnpj():
    from tests.fakes import fixture

    doc = fixture("acceptance/cnpj/gleif.json")
    assert (doc["schema"], doc["module"]) == ("v3lum.acceptance_routes/1", "gleif")
    http = FakeHttp()
    for r in doc["routes"]:
        http.add(r["method"], r["url"], status=r["status"], body=json.dumps(r["json"]).encode(), headers=r["headers"])
    res = run_module(Gleif, f"cnpj:{BB}", http)
    assert res.status is Status.OK and len(http.calls) == len(doc["routes"]) == 4
    assert not [f for f in res.findings if f.severity is not Severity.INFO]
