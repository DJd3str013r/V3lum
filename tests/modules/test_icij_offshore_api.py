"""Offline tests for P221 ``icij_offshore_api`` (ICIJ reconciliation API fallback, batch p3-G10-1).

Fixtures in tests/fixtures/icij_offshore_api/ are live 2026-11-26 reconcile answers (HTTP 201), a trimmed
research capture, a truncated derivative and the research WAF-challenge answer (README there).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import datasets
from v3lum.core.context import ScanOptions
from v3lum.core.models import Severity, Status
from v3lum.modules.company_org import icij_offshore as icij
from v3lum.modules.company_org.icij_offshore import IcijOffshoreApi

FIX = Path(__file__).resolve().parents[1] / "fixtures/icij_offshore_api"
URL = icij.RECONCILE_URL


def fx(name: str):
    return module_fixture("icij_offshore_api", name)


def answer(name: str, status: int = 201) -> FakeHttp:
    return FakeHttp().add("POST", URL, status=status, json=fx(name))


def test_entity_typed_post_with_five_candidates_and_the_name_only_in_the_body():
    http = answer("reconcile_typed_ok.json")
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear")
    assert res.status is Status.EMPTY  # best ICIJ candidate 'Banco Industrial do Brasil S.A.' scores < 0.90
    (call,) = http.calls
    assert call["url"] == URL and "Banco" not in call["url"]
    body = json.loads(call["body"])
    assert body == {"queries": {"q0": {"query": "Banco do Brasil", "type": icij.ENTITY_TYPE, "limit": 5}}}
    assert res.attributes["offshore_leaks_screening"]["state"] == "no_match"
    http.assert_hosts_within(IcijOffshoreApi)


def test_only_entity_nodes_above_the_matcher_threshold_become_possible_matches():
    http = answer("reconcile_untyped_mixed.json")
    res = run_module(IcijOffshoreApi, "company_name:Mossack Fonseca Limited", http, tlp="green")
    assert res.status is Status.OK
    (match,) = res.attributes["offshore_leaks_matches"]
    assert match["node_id"] == "10022201" and match["node_type"] == "entity" and match["source"] == "api"
    assert match["leak"] == "Panama Papers" and match["score"] >= 0.9
    assert match["node_url"] == "https://offshoreleaks.icij.org/nodes/10022201"
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and finding.confidence_label.value == "possible"
    assert {"offshore_leaks", "context_only", "name_only_match"} <= set(finding.tags)
    assert "node page" in finding.description and "not evidence of wrongdoing" in finding.description
    assert finding.source == "icij.reconcile" and res.pivots == []
    assert ("ICIJ Offshore Leaks node 10022201", match["node_url"]) in [tuple(link) for link in res.links]


def test_weak_and_empty_candidate_lists_are_empty():
    weak = run_module(IcijOffshoreApi, "company_name:Qwzx Vrklm Example Nonexistent Holdings", answer("reconcile_weak_only.json"), tlp="clear")
    assert weak.status is Status.EMPTY and "5 weak candidate" in weak.error
    empty = run_module(IcijOffshoreApi, "company_name:Qwzxv Vrklmq Zzyqt", answer("reconcile_empty.json"), tlp="clear")
    assert empty.status is Status.EMPTY


def test_truncated_or_odd_bodies_are_errors_never_empty():
    http = FakeHttp().add("POST", URL, status=201, body=(FIX / "reconcile_truncated.txt").read_bytes(), headers={"content-type": "application/json"})
    assert run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear").status is Status.ERROR
    odd = FakeHttp().add("POST", URL, status=201, json={"q1": {"result": []}})
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", odd, tlp="clear")
    assert res.status is Status.ERROR and "could not verify" in res.error
    manifest = FakeHttp().add("POST", URL, status=200, json=fx("reconcile_manifest.json"))
    assert run_module(IcijOffshoreApi, "company_name:Banco do Brasil", manifest, tlp="clear").status is Status.ERROR


def test_rule5_statuses_are_could_not_verify():
    for status, expected in ((429, Status.RATE_LIMITED), (403, Status.BLOCKED), (401, Status.BLOCKED), (500, Status.ERROR), (503, Status.ERROR)):
        http = FakeHttp().add("POST", URL, status=status, json={"error": "x"})
        res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear")
        assert res.status is expected, (status, res.status, res.error)


def test_waf_challenge_answer_is_could_not_verify():
    ex = fx("web_search_challenge.http.json")
    http = FakeHttp().add("POST", URL, status=ex["status"], body=ex["body"].encode(), headers=ex["headers"])
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear")
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"


def test_amber_without_explicit_selection_is_unavailable_dataset_and_sends_nothing():
    http = FakeHttp()
    rt = make_runtime(http)
    rt.in_scan = True
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, runtime=rt, tlp="amber", options=ScanOptions())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "v3lum data update icij" in res.error and http.calls == []


def test_explicit_selection_runs_at_amber():
    http = answer("reconcile_typed_ok.json")
    rt = make_runtime(http)
    rt.in_scan = True
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, runtime=rt, tlp="amber",
                     options=ScanOptions(include=["icij_offshore_api"]))
    assert res.status is Status.EMPTY and len(http.calls) == 1


def test_installed_local_index_makes_the_fallback_step_aside(tmp_path):
    from tests.modules.test_icij_offshore import build_zip

    target = datasets.DataStore(None).path(icij.DATASET)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(build_zip(tmp_path / "z.zip"), target)
    icij.validate_and_index(target)
    http = FakeHttp()
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear")
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_pivoted_names_are_never_sent():
    http = FakeHttp()
    res = run_module(IcijOffshoreApi, "company_name:Banco do Brasil", http, tlp="clear", is_seed=False, depth=1,
                     provenance=[("domain:example.com", "company_of", "wikidata")])
    assert res.status is Status.SKIPPED and http.calls == []


def test_declarations():
    assert IcijOffshoreApi.hosts == ("offshoreleaks.icij.org",) and IcijOffshoreApi.max_requests == 1
    assert IcijOffshoreApi.default_enabled is False and IcijOffshoreApi.sources == ("icij.reconcile",)
    assert icij.leak_of("Entity node extracted from the Paradise Papers - Nevis corporate registry data.") == {
        "leak": "Paradise Papers", "detail": "Nevis corporate registry"}
    assert icij.node_url("../x") is None
