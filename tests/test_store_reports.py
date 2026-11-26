"""Case store, feedback loop, report writers (JSON/MD/HTML/STIX)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, make_runtime
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec
from v3lum.core.module import Module, register
from v3lum.core.store import Store, reliability_from
from v3lum.report import write_reports
from v3lum.report.stix import bundle


@pytest.fixture()
def case_dict(clean_registry):
    class Src(Module):
        name = "t_report_src"
        title = "Synthetic report source"
        description = "Offline synthetic module feeding the report writers."
        accepts = {T.DOMAIN}
        category = "domain_dns"
        terms = "open"
        opsec = Opsec.PASSIVE
        disclosure = "none"
        hosts = ()

        def run(self, entity, ctx):
            res = self.result(entity)
            res.attr("created", "2026-11-20T10:00:00Z")
            res.attr("domain_age_days", 5)
            res.finding(
                "<script>alert(1)</script> phishing kit",
                "critical",
                "desc & more",
                criterion="synthetic phishing-kit match",
                tags=["phishing", "malicious"],
                references=["https://example.net/ref"],
            )
            res.pivot(T.IPV4, "203.0.113.5", "resolves_to")
            res.pivot(T.CVE, "CVE-2024-3400", "has_vuln", expand=False)
            res.link("Example tool", "https://tool.example/?q=" + entity.value)
            res.raw = {"x": 1}
            return res

    register(Src)
    rt = make_runtime(FakeHttp())
    case = Engine(rt, ScanOptions(include={"t_report_src"})).investigate([Entity.make("domain", "evil.example")])
    yield case.to_dict()


def test_store_roundtrip_and_feedback(case_dict, tmp_path):
    st = Store(tmp_path / "db.sqlite")
    st.save_case(case_dict)
    assert st.list_cases()[0]["id"] == case_dict["case_id"]
    assert st.get_case("last")["case_id"] == case_dict["case_id"]
    assert st.get_case(case_dict["case_id"][:12])["case_id"] == case_dict["case_id"]
    st.add_feedback(case_dict["case_id"], "partial", "one false positive")
    fid = case_dict["findings"][0]["id"]
    st.flag_finding(case_dict["case_id"], fid, "t_report_src", correct=False)
    st.flag_finding(case_dict["case_id"], fid, "t_report_src", correct=False)
    rel = st.reliability()["t_report_src"]
    assert 0.3 <= rel < 1.0
    summary = st.feedback_summary()
    assert summary["verdicts"]["partial"] == 1
    with pytest.raises(ValueError):
        st.add_feedback(case_dict["case_id"], "maybe")
    assert st.delete_case(case_dict["case_id"])


def test_reliability_formula():
    assert reliability_from(0, 0) == 1.0
    assert reliability_from(10, 0) == 1.0
    assert reliability_from(0, 10) == 0.3
    assert 0.5 < reliability_from(8, 2) < 1.0


def test_case_dict_shape(case_dict):
    for key in ("schema", "case_id", "summary", "entities", "edges", "findings", "correlations", "modules", "coverage", "links", "timeline", "risk"):
        assert key in case_dict
    assert case_dict["timeline"][0]["date"] == "2026-11-20"
    assert any(c["rule"] == "young_domain" for c in case_dict["correlations"])
    json.dumps(case_dict)  # serializable


def test_reports_written(case_dict, tmp_path):
    paths = write_reports(case_dict, ["html", "md", "json", "stix"], tmp_path)
    assert set(paths) == {"html", "md", "json", "stix"}
    html = Path(paths["html"]).read_text(encoding="utf-8")
    # self-contained: no external scripts/styles/images/fonts
    assert not re.search(r'<(script|link|img|iframe)[^>]+(src|href)="https?://', html)
    assert "@import" not in html
    # escaped
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    md = Path(paths["md"]).read_text(encoding="utf-8")
    assert "evil.example" in md and "Manual pivots" in md
    data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert data["case_id"] == case_dict["case_id"]


def test_stix_bundle(case_dict):
    b = bundle(case_dict)
    types = {o["type"] for o in b["objects"]}
    assert {"identity", "domain-name", "ipv4-addr", "vulnerability", "indicator", "relationship", "report"} <= types
    dom = next(o for o in b["objects"] if o["type"] == "domain-name")
    # deterministic SCO id (same value -> same id, any case)
    again = next(o for o in bundle(case_dict)["objects"] if o["type"] == "domain-name")
    assert dom["id"] == again["id"]
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[domain-name:value = 'evil.example']"
    ids = {o["id"] for o in b["objects"]}
    for rel in (o for o in b["objects"] if o["type"] == "relationship"):
        assert rel["source_ref"] in ids and rel["target_ref"] in ids


def test_unknown_format(case_dict, tmp_path):
    with pytest.raises(ValueError):
        write_reports(case_dict, ["pdfx"], tmp_path)
