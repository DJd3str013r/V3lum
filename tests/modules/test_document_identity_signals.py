"""document_identity_signals (P273, batch p3-G12-1): name windows + nearest CPF inside the case's own documents.

Synthetic text fixtures only (placeholder names, documentation CPFs 000.000.00N-DV with valid check digits).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from tests.fakes import FakeHttp, make_runtime, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.graph import Graph
from v3lum.core.models import Status
from v3lum.modules.file_analysis import document_identity_signals as DIS
from v3lum.modules.file_analysis.document_identity_signals import DocumentIdentitySignals

FIX = Path(__file__).parents[1] / "fixtures" / "document_identity_signals"
SUBJECT = "Fulano de Tal Souza"
FULL_CPFS = ("00000000191", "000.000.001-91", "00000000272", "000.000.002-72", "00000000353", "000.000.003-53",
             "00000000434", "000.000.004-34")


def doc(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def runtime_with_case(*seeds: Entity):
    """A runtime whose 'running investigation' graph holds the given typed seeds (the case documents)."""
    rt = make_runtime(FakeHttp())
    graph = Graph()
    for ent in seeds:
        graph.add_node(ent, seed=True)
    rt.policy_context = SimpleNamespace(graph=graph)
    return rt


def run(*seeds: Entity, person: str = SUBJECT, **kw):
    rt = runtime_with_case(Entity.make(T.PERSON, person), *seeds)
    return run_module(DocumentIdentitySignals, Entity.make(T.PERSON, person), runtime=rt, **kw)


def assert_no_full_cpf(blob: str) -> None:
    for cpf in FULL_CPFS:
        assert cpf not in blob, f"full CPF {cpf[:3]}... leaked"


def test_gazette_paragraph_attaches_only_the_subjects_own_cpf():
    res = run(Entity.make(T.TEXT, doc("gazette_paragraph.txt")), Entity.make(T.KEYWORD, "cidade: Campinas"))
    assert res.status is Status.OK
    sig = res.attributes["identity_signals"]
    d = sig["per_document"][0]
    assert d["nearest_cpf_masked"] == "***.000.001-**"  # never the neighbour's ***.000.002-**
    assert "city_near_name" in d["signals"] and d["layout"] == "prose"
    f = res.findings[0]
    assert {"privacy", "no_cross_case_index"} <= set(f.tags) and f.severity.name == "INFO"
    assert res.pivots == []  # FC4: never a CPF entity
    assert_no_full_cpf(json.dumps({"a": res.attributes, "r": res.raw, "f": [x.description for x in res.findings]}))


def test_typed_cpf_next_to_name_is_strong_and_compared_only_in_memory():
    res = run(Entity.make(T.TEXT, doc("gazette_paragraph.txt")), Entity.make(T.CPF, "000.000.001-91"),
              Entity.make(T.KEYWORD, "cidade: Campinas"))
    d = res.attributes["identity_signals"]["per_document"][0]
    assert "typed_cpf_next_to_name" in d["signals"] and d["confidence"] == "strong"
    assert d["typed_cpf"] == {"masked": "***.000.001-**", "found_in_document": True, "next_to_name": True}
    assert_no_full_cpf(json.dumps({"a": res.attributes, "r": res.raw}))


def test_a_different_cpf_next_to_the_name_raises_the_homonym_alert():
    res = run(Entity.make(T.TEXT, doc("gazette_paragraph.txt")), Entity.make(T.CPF, "000.000.002-72"))
    d = res.attributes["identity_signals"]["per_document"][0]
    assert d["alert"] and "possible homonym" in d["alert"] and d["confidence"] == "weak"


def test_table_layout_never_borrows_a_cpf_from_another_line():
    res = run(Entity.make(T.TEXT, doc("gazette_table.txt")), person="Deltrano Costa")
    d = res.attributes["identity_signals"]["per_document"][0]
    assert d["layout"] == "lines" and d["name_found"] is True
    assert d["nearest_cpf_masked"] is None  # the subject's line has no CPF: neighbours' CPFs never attach
    assert "homonyms possible" in d["criterion"]


def test_name_with_no_cpf_nearby():
    res = run(Entity.make(T.TEXT, doc("no_cpf.txt")), person="Deltrano Costa")
    d = res.attributes["identity_signals"]["per_document"][0]
    assert d["name_found"] and d["nearest_cpf_masked"] is None  # Beltrana's CPF is far away, in another record


def test_masked_list_is_never_joined_with_the_typed_cpf_digits():
    res = run(Entity.make(T.TEXT, doc("masked_list.txt")), Entity.make(T.CPF, "000.000.001-91"))
    d = res.attributes["identity_signals"]["per_document"][0]
    assert "masked_cpf_next_to_name" in d["signals"] and "typed_cpf_next_to_name" not in d["signals"]
    assert "no fragment join" in d["criterion"]


def test_contract_form_with_cpf_label_on_the_next_line(tmp_path):
    path = tmp_path / "contrato.txt"
    path.write_text(doc("contract_form.txt"), encoding="utf-8")
    res = run(Entity.make(T.FILE, str(path)), Entity.make(T.KEYWORD, "uf: SP"))
    d = res.attributes["identity_signals"]["per_document"][0]
    assert d["document"] == "contrato.txt" and d["nearest_cpf_masked"] == "***.000.001-**"
    assert "uf_near_name" in d["signals"]


def test_name_not_found_is_empty_and_no_documents_is_not_applicable():
    res = run(Entity.make(T.TEXT, doc("gazette_table.txt")), person="Pessoa Inexistente Exemplo")
    assert res.status is Status.EMPTY
    res2 = run(person=SUBJECT)
    assert res2.status is Status.SKIPPED and res2.reason_code == "not_applicable"
    # outside a scan there is no case: nothing to read
    res3 = run_module(DocumentIdentitySignals, Entity.make(T.PERSON, SUBJECT), FakeHttp())
    assert res3.status is Status.SKIPPED


def test_pivot_person_is_refused_privacy():
    rt = runtime_with_case(Entity.make(T.TEXT, doc("gazette_paragraph.txt")))
    res = run_module(DocumentIdentitySignals, Entity.make(T.PERSON, SUBJECT), runtime=rt, is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and res.reason_code == "privacy"


def test_windows_are_bounded_and_masked():
    r = DIS.identity_signals(doc("gazette_paragraph.txt"), SUBJECT)
    assert all(w["end"] - w["start"] <= DIS.MAX_WINDOW for w in r["windows"])
    assert_no_full_cpf(json.dumps(r))
    assert DIS.mask_cpf("52998224725") == "***.982.247-**"


def test_every_renderer_shows_the_cpf_masked(tmp_path):
    """FC6: terminal, HTML, Markdown and JSON outputs of a real scan carry masked CPFs only."""
    from v3lum.report import write_reports
    from v3lum.ui.render import render_case
    from v3lum.ui.theme import make_console

    text = doc("gazette_paragraph.txt")
    rt = make_runtime(FakeHttp())
    opts = ScanOptions(include={"document_identity_signals"}, include_disabled=True, purpose="due diligence test")
    case = Engine(rt, opts).investigate([Entity.make(T.TEXT, text), Entity.make(T.PERSON, SUBJECT)]).to_dict()
    mods = [m for m in case.get("modules", []) if m.get("module") == "document_identity_signals"]
    assert mods and mods[0].get("status") == "ok", mods
    # the module's own output never holds a full CPF
    assert_no_full_cpf(json.dumps(mods, default=str))
    console = make_console(no_color=True, width=240)
    with console.capture() as cap:
        render_case(console, case, full=True)
    out = write_reports(case, ["html", "md", "json"], tmp_path, record=False)
    blobs = {"terminal": cap.get()}
    for fmt, path in out.items():
        if not str(fmt).startswith("_"):
            blobs[fmt] = Path(path).read_text(encoding="utf-8")
    # the JSON report embeds the analyst's own seed document verbatim (core: AR24 masking of text_blob seeds in
    # exports is a core request); everything this module produced must be masked in it
    data = json.loads(blobs.pop("json"))
    produced = [m for m in data.get("modules", []) if m.get("module") == "document_identity_signals"]
    produced += [n.get("attributes", {}).get(k) for n in data.get("entities", []) if isinstance(n, dict)
                 for k in ("identity_signals", "identity_windows")]
    produced += [f for f in data.get("findings", []) if isinstance(f, dict) and f.get("module") == "document_identity_signals"]
    assert produced and all(p is not None for p in produced[:1])
    assert_no_full_cpf(json.dumps(produced, default=str))
    for fmt, blob in blobs.items():
        for cpf in ("000.000.001-91", "00000000191"):
            assert cpf not in blob, f"{fmt} shows a full CPF"


def test_metadata_matches_the_council_decision():
    assert DocumentIdentitySignals.disclosure == "none" and DocumentIdentitySignals.terms == "open"
    assert DocumentIdentitySignals.default_enabled is False and DocumentIdentitySignals.run_on == "seeds"
    assert DocumentIdentitySignals.max_tlp.name == "RED" and DocumentIdentitySignals.produces == frozenset()
