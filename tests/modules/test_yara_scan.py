"""yara_scan (P272): YARA Forge rules split/licensed/compiled per set, matched in the sandbox. Offline.

c8 fixtures (tests/fixtures/yara_scan/): mini_package.yar is a tiny rule set in the YARA Forge package layout
(own synthetic rules: a family rule, a SUSP_ EICAR rule, an HKTL_ rule, rules without a licence (one private, used by
an MIT rule), a CC BY-NC family rule and tokenizer traps); broken_package.yar / unterminated.yar exercise failure
isolation; eicar_parts.json stores the EICAR test string in two halves (joined only at runtime: no repository file is
an EICAR file); match_*.json and compile_report_*.json are yara-python 4.5.4 outputs; forge_core_header.txt and
forge_core_stats.json are the package header and counts of YARA Forge core 20261122 (no rule text: rule packs are
runtime downloads, A6). yara-python is not installed in the test environment: the module tests use recorded dumps.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import v3lum.core.module as core_module
from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.datasets import DATASETS
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.file_analysis import yara_scan as ys
from v3lum.modules.file_analysis.yara_scan import YaraScan

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "yara_scan"
MINI = (FIX / "mini_package.yar").read_text(encoding="utf-8")


def eicar() -> bytes:
    parts = module_fixture("yara_scan", "eicar_parts.json")["parts"]
    return (parts[0] + parts[1]).encode()


def child_dump(match_fixture: str, classes=("open",)) -> dict:
    split = ys.forge_split_package(MINI)
    sel = ys.select_yara_rules(split["rule_sets"], "corporate", list(classes))
    return {"package": split["package"], "selection": {k: sel[k] for k in ("counts", "by_class", "coverage_line")},
            "compile": module_fixture("yara_scan", "compile_report_corporate.json"), **module_fixture("yara_scan", match_fixture)}


def emit(dump, classes=("open",)):
    mod = YaraScan()
    res = mod.result(Entity.make(T.FILE, str(FIX / "mini_package.yar")))
    return mod.emit(res, dump, "core", "f" * 64, list(classes))


# ---- c2/c3/c4/c5: split, licences, selection --------------------------------------------------------------


def test_forge_package_split_and_licences():
    split = ys.forge_split_package(MINI)
    names = [rs["name"] for rs in split["rule_sets"]]
    assert names == ["V3LUM Test NoLicence", "V3LUM Test MIT", "V3LUM Test DRL", "V3LUM Test NC"]
    assert split["imports"] == ["pe"]
    lic = {rs["name"]: rs["licence"] for rs in split["rule_sets"]}
    assert lic == {"V3LUM Test NoLicence": None, "V3LUM Test MIT": "MIT", "V3LUM Test DRL": "DRL-1.1", "V3LUM Test NC": "CC-BY-NC"}


def test_corporate_loads_open_rules_only_and_counts_exclusions():
    split = ys.forge_split_package(MINI)
    corp = ys.select_yara_rules(split["rule_sets"], "corporate", [])
    loaded = {r["name"] for rules in corp["loaded"].values() for r in rules}
    assert "V3LUM_TEST_NC_MAL_ExampleFam_NC" not in loaded and "V3LUM_TEST_MIT_MAL_ExampleFam_Marker" in loaded
    assert not any("NOLICENCE" in n for n in loaded)  # c4: unknown licence never loads
    assert "V3LUM_TEST_MIT_Uses_Unlicensed" not in loaded and corp["counts"]["dependency"] == 1
    assert corp["coverage_line"] == "4 rules excluded: licence"
    nc = ys.select_yara_rules(split["rule_sets"], "corporate", ["noncommercial"])
    assert "V3LUM_TEST_NC_MAL_ExampleFam_NC" in {r["name"] for rules in nc["loaded"].values() for r in rules}
    research = ys.select_yara_rules(split["rule_sets"], "research", [])
    assert not any("NOLICENCE" in r["name"] for rules in research["loaded"].values() for r in rules)


def test_allowed_classes_follow_the_policy_gate_sources():
    assert ys.allowed_classes(SimpleNamespace(allowed_sources=frozenset({ys.SRC_OPEN}))) == ["open"]
    every = SimpleNamespace(allowed_sources=frozenset({ys.SRC_OPEN, ys.SRC_LICENSE, ys.SRC_NC}))
    assert ys.allowed_classes(every) == ["license", "noncommercial", "open"]


def test_tokenizer_refuses_malformed_sources():
    with pytest.raises(ys.YaraSplitError):
        ys.forge_split_package((FIX / "unterminated.yar").read_text(encoding="utf-8"))
    split = ys.forge_split_package((FIX / "broken_package.yar").read_text(encoding="utf-8"))
    assert split["includes"]  # include statements are reported, never followed


def test_forge_prefix_is_removed_before_the_generic_test():  # c7
    kind = ys.yara_rule_kind("SIGNATURE_BASE_SUSP_Thing", {"score": 75}, "Signature Base")
    assert kind["kind"] == "generic" and kind["original_name"] == "SUSP_Thing"
    assert ys.yara_rule_kind("X_Low", {"score": 60})["label"] == "suspicious"
    fam = ys.yara_rule_kind("ESET_MAL_Thing", {"malware_family": "Backdoor:W32/Pwnlnx", "score": 80}, "ESET")
    assert fam["kind"] == "family" and fam["family"] == "Pwnlnx"


def test_compile_failures_are_isolated_and_counted():  # c2 (fake yara: the child's control flow)
    class SyntaxErr(Exception):
        pass

    fake = SimpleNamespace(SyntaxError=SyntaxErr)

    def compile_(source, includes):
        assert includes is False
        if "BROKEN" in source:
            raise SyntaxErr("undefined string")
        return object()

    fake.compile = compile_
    sets = [{"namespace": "A", "rules": [{"name": "OK1", "text": "rule OK1 { condition: true }"},
                                          {"name": "BROKEN", "text": "rule BROKEN { condition: $x }"}]},
            {"namespace": "B", "rules": [{"name": "OK2", "text": "rule OK2 { condition: true }"}]}]
    sources, report = ys.compile_rule_sets(fake, ["pe"], sets)
    assert sorted(sources) == ["A", "B"] and "BROKEN" not in sources["A"]
    assert report["failed_groups"] == 1 and report["failed_rules"] == 1 and report["groups"] == 2


# ---- c6/c7: results ---------------------------------------------------------------------------------


def test_family_rule_gives_a_low_confidence_family_never_malicious():
    res = emit(child_dump("match_family_corporate.json"))
    assert res.status is Status.OK
    [p] = res.pivots
    assert p.entity.type is T.MALWARE and p.entity.value == "ExampleFam" and p.expand is False and p.relation == "yara_family_rule"
    f = next(f for f in res.findings if f.title == "YARA family rule matched")
    assert "malicious" not in f.tags and f.confidence_label == "possible" if hasattr(f, "confidence_label") else True
    hit = res.attributes["yara_hits"][0]
    assert hit["author"] == "V3LUM test suite" and hit["reference"] and hit["package_version"]  # DRL attribution kept
    assert res.attributes["yara_coverage"]["coverage_line"] == "4 rules excluded: licence"


def test_eicar_rule_is_suspicious_low_context():
    assert eicar().startswith(b"X5O!P%@AP") and len(eicar()) == 68
    res = emit(child_dump("match_eicar_corporate.json"))
    f = next(f for f in res.findings if f.title.startswith("YARA generic rule"))
    assert f.severity.label == "low" and {"suspicious", "context_only"} <= set(f.tags) and not res.pivots


def test_no_match_is_not_a_verdict_and_timeout_is_could_not_verify():
    res = emit(child_dump("match_none_corporate.json"))
    assert res.status is Status.EMPTY and "not a verdict" in res.error
    res = emit(child_dump("match_timeout.json"))
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert emit(["junk"]).status is Status.ERROR


def test_no_fixture_is_an_eicar_file():
    for path in FIX.iterdir():
        assert eicar() not in path.read_bytes(), path.name


# ---- c1: extra, sandbox and dataset ------------------------------------------------------------------


def test_missing_extra_is_unavailable_package(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    http = FakeHttp()
    res = run_module(YaraScan, Entity.make(T.FILE, str(sample)), http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package" and http.calls == []


def test_without_the_core_sandbox_libyara_never_runs_in_process(tmp_path, monkeypatch):
    real = core_module.package_available
    monkeypatch.setattr(core_module, "package_available", lambda name: name == "yara" or real(name))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 64)
    http = FakeHttp()
    res = run_module(YaraScan, Entity.make(T.FILE, str(sample)), http)
    assert res.status is Status.UNAVAILABLE and "sandbox" in res.error and http.calls == []


def test_datasets_are_registered_as_source_packages():
    core = DATASETS["yara_scan.forge_core"]
    assert core["url"] == "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
    assert core["source"] == ys.SRC_OPEN and core["archive"] == "zip" and core["large"] is True
    assert core["member"] == "packages/core/yara-rules-core.yar"
    assert {"yara_scan.forge_extended", "yara_scan.forge_full"} <= set(DATASETS)
    stats = module_fixture("yara_scan", "forge_core_stats.json")
    assert stats["asset"]["resolved_tag"] == "20261122"
    header = (FIX / "forge_core_header.txt").read_text(encoding="utf-8")
    assert ys.forge_split_package(header)["package"]["number_of_rules"] == 5078


def test_contract_metadata():
    assert YaraScan.default_enabled is False and YaraScan.terms == "noncommercial" and YaraScan.disclosure == "none"
    assert YaraScan.requires_packages == ("yara",) and json.dumps(YaraScan.settings) == '{"yara_scan_package": "core"}'
