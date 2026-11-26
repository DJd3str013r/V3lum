"""Result model v2 (WP01): statuses, reason codes, confidence labels, ids, strict contract mode."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from v3lum.core import models
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import (
    CONFIDENCE_TABLE,
    DEFAULT_REASON,
    REASON_CODES,
    STOP_REASONS,
    Confidence,
    ContractViolation,
    Correlation,
    Finding,
    ModuleResult,
    Pivot,
    Severity,
    Status,
    UnknownVocab,
    collect_results,
    correlation_id,
    finding_id,
    status_for,
    valid_reason,
)

ROOT = Path(__file__).resolve().parent.parent

A3_CODES = {
    Status.SKIPPED: [
        "not_default", "demoted", "licence", "tlp", "tier", "privacy", "own_asset", "opsec", "authorization",
        "scope", "egress_country", "deadline", "policy", "config", "not_applicable",
    ],
    Status.NEEDS_KEY: ["needs_key"],
    Status.UNAVAILABLE: ["package", "dataset", "offline"],
    Status.QUOTA: ["quota"],
    Status.RATE_LIMITED: ["rate_limited"],
    Status.BLOCKED: ["hostile_host", "circuit", "challenge", "geo_block", "login_wall"],
    Status.ERROR: ["timeout", "sanitizer", "error"],
}

V1_FINDING_KEYS = {"id", "title", "severity", "description", "confidence", "data", "tags", "references", "entity", "module"}


@pytest.fixture()
def strict(monkeypatch):
    monkeypatch.setenv("V3LUM_STRICT", "1")


@pytest.fixture()
def lenient(monkeypatch):
    monkeypatch.setenv("V3LUM_STRICT", "0")


def result(module: str = "t_mod", value: str = "example.org") -> ModuleResult:
    return ModuleResult(module=module, entity=Entity.make("domain", value))


# ------------------------------------------------------------------ statuses and reason codes
def test_status_keeps_v1_values_and_adds_quota():
    v1 = ["ok", "empty", "error", "skipped", "needs_key", "rate_limited", "blocked", "unavailable"]
    assert [s.value for s in Status] == v1 + ["quota"]
    assert Status("quota") is Status.QUOTA
    assert Status.QUOTA.could_not_verify and Status.BLOCKED.could_not_verify
    assert not Status.EMPTY.could_not_verify and not Status.OK.could_not_verify


def test_reason_codes_match_a3_exactly():
    expected = {code: status for status, codes in A3_CODES.items() for code in codes}
    assert expected == REASON_CODES
    assert list(REASON_CODES) == [c for codes in A3_CODES.values() for c in codes]  # documented order
    assert frozenset({"request_cap", "deadline", "quota", "rate_limited", "cancelled"}) == STOP_REASONS
    assert {
        Status.SKIPPED: "not_applicable", Status.NEEDS_KEY: "needs_key", Status.UNAVAILABLE: "offline", Status.QUOTA: "quota",
        Status.RATE_LIMITED: "rate_limited", Status.BLOCKED: "challenge", Status.ERROR: "error",
    } == DEFAULT_REASON
    for status, code in DEFAULT_REASON.items():
        assert REASON_CODES[code] is status


def test_reason_code_copies_in_sibling_packages_match_the_canonical_table():
    """http.py and providers.py keep local copies of the A3 codes (no import of models); they must
    never drift from models.REASON_CODES (wave-1 integration)."""
    from v3lum.core import http as http_mod
    from v3lum.core import providers

    def codes(status):
        return frozenset(c for c, s in REASON_CODES.items() if s is status)

    assert codes(Status.SKIPPED) == http_mod._SKIPPED_CODES
    assert codes(Status.BLOCKED) == http_mod._BLOCKED_CODES
    assert codes(Status.ERROR) == http_mod._ERROR_CODES
    marker_status = {"blocked": Status.BLOCKED, "rate_limited": Status.RATE_LIMITED, "quota": Status.QUOTA, "error": Status.ERROR}
    for maps_to, status in marker_status.items():
        assert providers._MARKER_CODES[maps_to] == codes(status)
        assert http_mod._MARKER_CODES[maps_to] == codes(status)
        assert http_mod._MARKER_DEFAULT_CODE[maps_to] == DEFAULT_REASON[status]


def test_status_for_and_valid_reason():
    assert status_for("licence") is Status.SKIPPED
    assert status_for("geo_block") is Status.BLOCKED
    assert status_for("sanitizer") is Status.ERROR
    with pytest.raises(ValueError):
        status_for("not_found")
    assert valid_reason(Status.BLOCKED, "challenge")
    assert valid_reason("quota", "quota")
    assert not valid_reason(Status.BLOCKED, "quota")
    assert not valid_reason(Status.SKIPPED, "nonsense")
    assert valid_reason(Status.OK, "") and valid_reason(Status.EMPTY, "")
    assert not valid_reason(Status.OK, "error")
    assert not valid_reason(Status.ERROR, "")
    assert not valid_reason("bogus_status", "error")


def test_mark_default_reasons_and_invalid_code():
    res = result()
    assert res.mark("blocked", "anti-bot page") is res
    assert (res.status, res.reason_code, res.error) == (Status.BLOCKED, "challenge", "anti-bot page")
    for status, code in DEFAULT_REASON.items():
        assert result().mark(status).reason_code == code
    assert result().mark("quota").reason_code == "quota"
    assert result().mark(Status.ERROR, reason_code="timeout").reason_code == "timeout"
    res = result().mark("ok")
    assert res.reason_code == ""
    with pytest.raises(ValueError):
        result().mark("blocked", reason_code="quota")
    with pytest.raises(ValueError):
        result().mark("skipped", reason_code="made_up")
    with pytest.raises(ValueError):
        result().mark("ok", reason_code="error")
    with pytest.raises(ValueError):
        result().mark("not_a_status")


def test_stop_partial_runs():
    res = result()
    assert res.stop("request_cap") is res
    assert res.partial and res.stop_reason == "request_cap" and res.status is Status.OK
    with pytest.raises(ValueError):
        result().stop("tired")
    d = res.to_dict()
    assert d["partial"] is True and d["stop_reason"] == "request_cap" and d["reason_code"] == ""


# ------------------------------------------------------------------ confidence
@pytest.mark.parametrize(
    ("value", "label"),
    [
        (0.85, Confidence.CONFIRMED), (0.849, Confidence.PROBABLE), (0.55, Confidence.PROBABLE),
        (0.549, Confidence.POSSIBLE), (1.0, Confidence.CONFIRMED), (0.0, Confidence.POSSIBLE), (1, Confidence.CONFIRMED),
        ("confirmed", Confidence.CONFIRMED), ("PROBABLE", Confidence.PROBABLE), (" Possible ", Confidence.POSSIBLE),
        ("0.9", Confidence.CONFIRMED), (Confidence.PROBABLE, Confidence.PROBABLE),
    ],
)
def test_confidence_from_value(value, label):
    assert Confidence.from_value(value) is label


@pytest.mark.parametrize("bad", ["sure", "", None, True, float("nan"), [0.9]])
def test_confidence_from_value_rejects(bad):
    with pytest.raises(ValueError):
        Confidence.from_value(bad)


def test_confidence_table_and_levels():
    assert [(c.weight, c.stix, c.rank) for c in Confidence] == [(1.0, 90, 2), (0.7, 70, 1), (0.4, 40, 0)]
    assert set(CONFIDENCE_TABLE) == set(Confidence)
    for label, row in CONFIDENCE_TABLE.items():
        assert row["label"] == label.value
        assert Confidence.from_value(row["weight"]) is label  # weights map back to their label
        assert Confidence.from_value(row["min_value"]) is label
    assert Confidence.CONFIRMED.lower() is Confidence.PROBABLE
    assert Confidence.POSSIBLE.lower() is Confidence.POSSIBLE
    assert Confidence.POSSIBLE.higher() is Confidence.PROBABLE
    assert Confidence.CONFIRMED.higher() is Confidence.CONFIRMED
    assert f"{Confidence.PROBABLE}" == "probable" and str(Confidence.POSSIBLE) == "possible"


def test_finding_accepts_float_or_label():
    res = result()
    f1 = res.finding("context", confidence=0.9)
    f2 = res.finding("labelled", confidence="possible")
    assert f1.confidence_label is Confidence.CONFIRMED and f1.confidence == 0.9
    assert f2.confidence_label is Confidence.POSSIBLE and f2.confidence == 0.4
    assert Finding("x", confidence=0.6).confidence_label is Confidence.PROBABLE
    assert Finding("x", confidence=3.0).confidence == 1.0  # clamped


def test_pivot_labels():
    res = result()
    ip = res.pivot(T.IPV4, "203.0.113.7", "resolves_to", confidence="possible")
    assert ip is not None
    p = res.pivots[0]
    assert p.confidence == 0.4 and p.confidence_label is Confidence.POSSIBLE
    assert Pivot(ip, "resolves_to", Confidence.CONFIRMED).confidence == 1.0
    assert Pivot(ip, "resolves_to", 0.6).confidence_label is Confidence.PROBABLE
    assert res.to_dict()["pivots"][0]["confidence_label"] == "possible"
    assert res.pivot(T.IPV4, "not-an-ip", "resolves_to") is None
    assert res.pivot(T.DOMAIN, "example.org", "related") is None  # the subject itself


# ------------------------------------------------------------------ deterministic ids (AR09)
def test_finding_id_formula_and_key():
    expected = hashlib.sha256(b"mod|domain:example.org|Title|").hexdigest()[:16]
    assert finding_id("mod", "domain:example.org", "Title") == expected
    assert finding_id("mod", "domain:example.org", "Title", "k1") != expected
    res = result("mod")
    f = res.finding("Title")
    assert f.id == expected and len(f.id) == 16
    other = res.finding("Title", key="second")
    assert other.id == finding_id("mod", "domain:example.org", "Title", "second")


def test_correlation_id_formula_sorted_entities():
    expected = hashlib.sha256(b"rule|r1|domain:a.example,domain:b.example|").hexdigest()[:16]
    assert correlation_id("r1", ["domain:b.example", "domain:a.example"]) == expected
    assert correlation_id("r1", ["domain:a.example", "domain:b.example"], "k") != expected
    c = Correlation("r1", "t", Severity.LOW, "d", entities=[Entity.make("domain", "b.example"), Entity.make("domain", "a.example")])
    assert c.id == expected
    c.key = "k"
    c.ensure_id()
    assert c.id == correlation_id("r1", ["domain:a.example", "domain:b.example"], "k")
    kept = Correlation("r1", "t", "low", "d", id="abcdef123456")
    assert kept.ensure_id() == "abcdef123456"  # explicit/stored ids are kept


def test_ids_stable_across_processes():
    code = (
        "from v3lum.core.models import finding_id, correlation_id;"
        "print(finding_id('m', 'domain:example.org', 'T', 'k'), correlation_id('r', ['b', 'a'], 'k'))"
    )
    env = dict(os.environ, PYTHONHASHSEED="12345")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT), env=env, timeout=60, check=True)
    assert out.stdout.split() == [finding_id("m", "domain:example.org", "T", "k"), correlation_id("r", ["b", "a"], "k")]


def test_ensure_id_follows_module_and_keeps_explicit_ids():
    f = Finding("Title", entity=Entity.make("domain", "example.org"))
    assert f.ensure_id() == finding_id("", "domain:example.org", "Title")
    f.module = "engine_forced"
    assert f.ensure_id() == finding_id("engine_forced", "domain:example.org", "Title")  # derived ids are refreshed
    v1 = Finding("Title", id="0123456789ab", module="m")
    assert v1.ensure_id() == "0123456789ab"


def test_duplicate_finding_ids(strict):
    res = result()
    res.finding("Same")
    with pytest.raises(ContractViolation):
        res.finding("Same")


def test_duplicate_finding_ids_non_strict(lenient):
    res = result()
    a = res.finding("Same")
    b = res.finding("Same")
    assert a.id != b.id and b.key == "#2"


# ------------------------------------------------------------------ downgrade / upgrade / override (P322)
def test_downgrade_warninglist_criterion():
    f = result().finding("Listed by feed", "high", criterion="listed by 1 feed", confidence=0.9)
    f.downgrade("warninglist", "on warninglist alexa_top")
    assert f.confidence_label is Confidence.PROBABLE and f.confidence <= 0.7
    assert f.criterion == "PROBABLE - on warninglist alexa_top | listed by 1 feed"
    f.downgrade("warninglist", "on warninglist x", to=Confidence.POSSIBLE)
    assert f.confidence_label is Confidence.POSSIBLE
    assert f.criterion.startswith("POSSIBLE - on warninglist x | PROBABLE - on warninglist alexa_top")
    f.downgrade("sinkhole", "known sinkhole")  # floor
    assert f.confidence_label is Confidence.POSSIBLE
    assert [s["rule"] for s in f.suppressed_by] == ["warninglist", "warninglist", "sinkhole"]
    assert f.suppressed_by[0] == {"rule": "warninglist", "reason": "on warninglist alexa_top"}


def test_downgrade_to_possible_and_never_raises():
    f = Finding("IOC", confidence=0.95)
    f.downgrade("warninglist", "on warninglist cdn", to="possible")
    assert f.confidence_label is Confidence.POSSIBLE and f.criterion == "POSSIBLE - on warninglist cdn"
    g = Finding("weak", confidence=0.4)
    g.downgrade("x", "y", to=Confidence.CONFIRMED)  # a downgrade never raises the label
    assert g.confidence_label is Confidence.POSSIBLE


def test_upgrade_needs_two_independent_families_and_is_plus_one():
    f = Finding("weak", confidence=0.4, criterion="one feed")
    f.upgrade(1, "consensus", "one family only")
    assert f.confidence_label is Confidence.POSSIBLE and f.criterion == "one feed"
    f.upgrade(["abuse.ch", "abuse.ch"], "consensus", "same family twice")
    assert f.confidence_label is Confidence.POSSIBLE
    f.upgrade(["abuse.ch", "spamhaus"], "consensus", "confirmed by 2 independent families")
    assert f.confidence_label is Confidence.PROBABLE and f.confidence >= 0.55
    assert f.criterion == "PROBABLE - confirmed by 2 independent families | one feed"
    f.upgrade(3, "consensus", "again")  # at most +1 level per finding
    assert f.confidence_label is Confidence.PROBABLE
    assert f.upgraded_by == [{"rule": "consensus", "reason": "confirmed by 2 independent families", "from": "possible", "to": "probable"}]
    stored = Finding.from_dict(f.to_dict())  # the +1 cap survives a store/reload cycle
    stored.upgrade(4, "consensus", "re-scored from the stored case")
    assert stored.confidence_label is Confidence.PROBABLE and stored.upgraded_by == f.upgraded_by


def test_apply_override_wins_and_blocks_automatic_changes():
    f = result().finding("Malicious per feed", "high", criterion="feed verdict", confidence=0.9)
    f.apply_override(label="possible", severity="low", verdict="false_positive", analyst="ana", note="benign CDN", at="2026-11-26T10:00:00Z")
    assert f.confidence_label is Confidence.POSSIBLE and f.severity is Severity.LOW
    assert f.override["auto"] == {"label": "confirmed", "severity": "high", "criterion": "feed verdict"}
    assert f.override["analyst"] == "ana" and f.override["verdict"] == "false_positive"
    before = (f.confidence_label, f.confidence, f.criterion, f.severity)
    f.downgrade("warninglist", "on warninglist x", to="possible")
    f.upgrade(5, "consensus", "many families")
    assert (f.confidence_label, f.confidence, f.criterion, f.severity) == before
    assert f.suppressed_by == [
        {"rule": "warninglist", "reason": "on warninglist x", "blocked_by": "analyst"},
        {"rule": "consensus", "reason": "many families", "blocked_by": "analyst"},
    ]
    f.apply_override(label="confirmed")  # a later decision keeps the original automatic values
    assert f.override["auto"]["label"] == "confirmed" and f.override["severity"] == "low"
    assert f.confidence_label is Confidence.CONFIRMED


def test_override_round_trip():
    f = result().finding("Flagged", "medium", criterion="c", confidence="probable")
    f.apply_override(label=Confidence.CONFIRMED, analyst="ana", at="2026-11-26T10:00:00Z")
    g = Finding.from_dict(f.to_dict())
    assert g.override == f.override and g.confidence_label is Confidence.CONFIRMED and g.id == f.id
    g.downgrade("x", "y")
    assert g.confidence_label is Confidence.CONFIRMED  # still protected after reload


# ------------------------------------------------------------------ serialisation / stored cases
def test_finding_to_dict_superset_and_v1_from_dict():
    f = result().finding(
        "Thing", "low", "desc", criterion="why", source="test_provider.default", observed_first="2026-01-01T00:00:00Z",
        attack=["T1656"], key="k", tags=["phishing"], references=["https://example.net/x"],
    )
    d = f.to_dict()
    assert set(d) >= V1_FINDING_KEYS
    assert {"confidence_label", "criterion", "source", "observed_first", "observed_last", "attack", "key", "suppressed_by", "ownership", "override"} <= set(d)
    assert d["attack"] == ["T1684.001"]  # revoked id canonicalised
    v1 = {
        "id": "a1b2c3d4e5f6", "title": "Old finding", "severity": "high", "description": "from a v1 case",
        "confidence": 0.6, "data": {"x": 1}, "tags": ["malicious"], "references": [], "entity": "domain:evil.example", "module": "old_mod",
    }
    g = Finding.from_dict(v1)
    assert g.id == "a1b2c3d4e5f6" and g.ensure_id() == "a1b2c3d4e5f6"
    assert g.confidence_label is Confidence.PROBABLE and g.severity is Severity.HIGH
    assert g.entity == Entity.make("domain", "evil.example") and g.criterion == ""
    assert {k: v for k, v in g.to_dict().items() if k in V1_FINDING_KEYS} == v1


def test_v1_case_dict_renders_with_existing_report_writers(tmp_path):
    from v3lum.report import write_reports

    v1_findings = [
        {"id": "0a1b2c3d4e5f", "title": "Phishing kit", "severity": "critical", "description": "d", "confidence": 0.9,
         "data": {}, "tags": ["phishing"], "references": ["https://example.net/r"], "entity": "domain:evil.example", "module": "src"},
        {"id": "1a1b2c3d4e5f", "title": "Info", "severity": "info", "description": "", "confidence": 0.5,
         "data": {}, "tags": ["info"], "references": [], "entity": "domain:evil.example", "module": "src"},
    ]
    case = {
        "schema": "v3lum.case/1", "tool": {"name": "V3LUM", "version": "1.0.0"}, "case_id": "20250101-000000-abcd",
        "created": "2025-01-01T00:00:00+00:00", "inputs": [], "seeds": ["domain:evil.example"], "options": {"mode": "passive"},
        "summary": {"risk_score": 10.0, "risk_level": "low", "entities": 1, "investigated": 1, "relations": 0, "findings": 2,
                    "findings_by_severity": {"critical": 1, "info": 1}, "correlations": 0, "module_runs": 1,
                    "module_status": {"ok": 1}, "duration": 1.0, "requests": 1, "cache_hits": 0, "interrupted": False},
        "risk": {"score": 10.0, "level": "low", "entities": {}, "top": []},
        "entities": [{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "display": "evil.example", "depth": 0,
                      "seed": True, "investigated": True, "noise": False, "sources": ["src"], "attributes": {}, "findings": ["0a1b2c3d4e5f", "1a1b2c3d4e5f"]}],
        "edges": [], "findings": [Finding.from_dict(f).to_dict() for f in v1_findings], "correlations": [],
        "modules": [{"module": "src", "entity": "domain:evil.example", "status": "ok", "findings": [], "pivots": [], "attributes": {},
                     "links": [], "error": "", "duration": 1.0, "requests": 1, "cache_hits": 0, "evidence": "", "evidence_sha256": ""}],
        "coverage": {}, "links": {}, "timeline": [], "notes": [], "case_dir": "",
    }
    paths = write_reports(case, ["html", "md", "json", "stix"], tmp_path)
    assert "Phishing kit" in Path(paths["html"]).read_text(encoding="utf-8")
    assert "Phishing kit" in Path(paths["md"]).read_text(encoding="utf-8")
    # the graph rebuilds from the stored case and keeps the v1 ids
    from v3lum.core.graph import Graph

    graph = Graph.from_dict(case)
    assert [f.id for f in graph.findings()] == ["0a1b2c3d4e5f", "1a1b2c3d4e5f"]


def test_raw_v1_case_dict_renders_and_v2_case_dict_renders(tmp_path):
    from v3lum.report import write_reports

    v1_case = {
        "schema": "v3lum.case/1", "case_id": "20250101-000000-beef", "created": "2025-01-01T00:00:00+00:00", "inputs": [],
        "seeds": ["domain:evil.example"], "options": {"mode": "passive"},
        "summary": {"risk_score": 0.0, "risk_level": "clean", "entities": 1, "findings": 1, "correlations": 0},
        "risk": {"score": 0.0, "level": "clean"},
        "entities": [{"key": "domain:evil.example", "type": "domain", "value": "evil.example", "display": "evil.example", "depth": 0,
                      "seed": True, "attributes": {}, "findings": ["0a1b2c3d4e5f"]}],
        "edges": [],
        "findings": [{"id": "0a1b2c3d4e5f", "title": "Old v1 finding", "severity": "high", "description": "", "confidence": 0.9,
                      "data": {}, "tags": [], "references": [], "entity": "domain:evil.example", "module": "src"}],
        "correlations": [], "modules": [], "coverage": {}, "links": {}, "timeline": [], "notes": [],
    }
    paths = write_reports(v1_case, ["html", "md", "json", "stix"], tmp_path / "v1")  # stored as-is, no conversion
    assert "Old v1 finding" in Path(paths["html"]).read_text(encoding="utf-8")
    from v3lum.core.graph import Graph

    g = Graph.from_dict(v1_case)
    assert g.findings()[0].id == "0a1b2c3d4e5f" and g.findings()[0].confidence_label is Confidence.CONFIRMED
    # a v2 graph dump keeps every v2 field through to_dict/from_dict
    res = result("v2_mod")
    f = res.finding("New v2 finding", "medium", criterion="two feeds", attack=["T1566"], source="feeds.a")
    f.apply_override(label="possible", analyst="ana", at="2026-11-26T10:00:00Z")
    g2 = Graph()
    node, _ = g2.add_node(res.entity, 0, seed=True)
    node.ownership, node.tlp = "own_asset", "amber"
    node.add_tag("own_asset")
    g2.add_finding(f)
    again = Graph.from_dict(g2.to_dict())
    back = again.findings()[0]
    assert back.to_dict() == f.to_dict() and again.get(res.entity).tagged("own_asset") and again.get(res.entity).tlp == "amber"


def test_epoch_milliseconds_and_missing_pivot_confidence():
    res = result()
    f = res.finding("Seen", observed_first=1_700_000_000_000, observed_last=1_700_000_000)
    assert f.observed_first == f.observed_last == "2023-11-14T22:13:20+00:00"
    d = res.to_dict()
    d["pivots"] = [{"entity": "ipv4:203.0.113.7", "relation": "resolves_to", "confidence": None}]
    assert ModuleResult.from_dict(d).pivots[0].confidence == 0.9


def test_contract_messages_never_quote_a_configured_key(strict):
    redact = pytest.importorskip("v3lum.core.redact")
    secret = "ContractKey0123456789abcd"
    redact.register_secret(secret)
    with pytest.raises(ContractViolation) as info:
        result().link("ftp", f"ftp://files.example.net/export?token={secret}")
    assert secret not in str(info.value)


def test_module_result_to_dict_v2_keys_and_round_trip():
    res = result()
    res.attr("country", "BR")
    res.finding("F", criterion="c", severity="low")
    res.link("Example", "https://example.net/x")
    res.hosts = {"api.example.test": 2}
    res.datasets = [{"name": "ds", "sha256": "0" * 64}]
    res.redacted_fields = ["raw.password"]
    res.set_marking("amber")
    d = res.to_dict()
    for key in ("reason_code", "partial", "stop_reason", "tlp", "hosts", "datasets", "redacted_fields", "source_statuses"):
        assert key in d
    assert d["tlp"] == "amber"
    again = ModuleResult.from_dict(d, findings={f.id: f for f in res.findings})
    assert again.to_dict() == d


# ------------------------------------------------------------------ builders: links, presence, marking, source status
def test_link_keeps_only_http_urls(lenient):
    res = result()
    res.link("ok", "https://example.net/a")
    res.link("js", "javascript:alert(1)")
    res.link("data", "data:text/html,<b>x</b>")
    res.link("ctrl", "https://example.net/\x1b[31m")
    res.link("ftp", "ftp://example.net/f")
    assert res.links == [("ok", "https://example.net/a")]


def test_link_and_reference_strict(strict):
    with pytest.raises(ContractViolation):
        result().link("js", "javascript:alert(1)")
    with pytest.raises(ContractViolation):
        result().finding("x", "info", references=["javascript:alert(1)"])


def test_presence_tri_state(strict):
    res = result()
    res.presence("found", marker="profile-header", url="https://example.net/u/alice", checked_at="2026-11-26T10:00:00Z", source="site.x")
    assert res.attributes["presence"] == {
        "state": "found", "marker": "profile-header", "url": "https://example.net/u/alice", "checked_at": "2026-11-26T10:00:00Z", "source": "site.x",
    }
    res.presence("absent", marker="Page not found marker")
    assert res.attributes["presence"]["state"] == "absent"
    res.presence("unknown")
    assert res.attributes["presence"]["state"] == "unknown" and res.attributes["presence"]["checked_at"]
    with pytest.raises(ContractViolation):
        result().presence("absent")
    with pytest.raises(ValueError):
        result().presence("maybe")


def test_presence_absent_without_evidence_is_unknown_when_lenient(lenient):
    res = result()
    res.presence("absent")
    assert res.attributes["presence"]["state"] == "unknown"


def test_set_marking_keeps_highest():
    res = result()
    res.set_marking("green").set_marking("TLP:AMBER+STRICT").set_marking("amber")
    assert res.tlp == "amber+strict"
    res.set_marking("white")
    assert res.tlp == "amber+strict"
    with pytest.raises(ValueError):
        res.set_marking("purple")


class _Aggregator:
    name = "t_aggregator"
    sources = ("feeds.alpha", "feeds.beta")


def test_source_status_validation_and_to_dict(strict, monkeypatch):
    from v3lum.core import module as modreg

    monkeypatch.setitem(modreg.REGISTRY, "t_aggregator", _Aggregator)
    res = ModuleResult(module="t_aggregator", entity=Entity.make("ipv4", "203.0.113.9"))
    res.source_status("feeds.alpha", "ok")
    res.source_status("feeds.beta", Status.BLOCKED, reason="feed answered with a challenge page")
    assert res.to_dict()["source_statuses"] == {
        "feeds.alpha": {"status": "ok", "reason_code": "", "reason": ""},
        "feeds.beta": {"status": "blocked", "reason_code": "challenge", "reason": "feed answered with a challenge page"},
    }
    res.source_status("feeds.beta", "rate_limited")
    assert res.source_statuses["feeds.beta"]["reason_code"] == "rate_limited"
    with pytest.raises(ContractViolation):
        res.source_status("feeds.gamma", "ok")
    with pytest.raises(ValueError):
        res.source_status("feeds.alpha", "blocked", reason_code="quota")


def test_source_status_unknown_source_lenient(lenient, monkeypatch):
    from v3lum.core import module as modreg

    monkeypatch.setitem(modreg.REGISTRY, "t_aggregator", _Aggregator)
    res = ModuleResult(module="t_aggregator", entity=Entity.make("ipv4", "203.0.113.9"))
    res.source_status("feeds.gamma", "error")
    assert res.source_statuses["feeds.gamma"]["reason_code"] == "error"


# ------------------------------------------------------------------ strict contract mode
def test_strict_missing_criterion_raises(strict):
    res = result()
    res.finding("Context only", "info")  # info needs no criterion
    with pytest.raises(ContractViolation, match="criterion"):
        res.finding("Bad thing", "low")
    f = res.finding("Bad thing", "high", criterion="listed by two feeds")
    assert f.criterion == "listed by two feeds"


def test_strict_unknown_vocab_raises(strict):
    res = result()
    with pytest.raises(UnknownVocab):
        res.attr("no_such_attribute_xyz", 1)
    with pytest.raises(UnknownVocab):
        res.finding("x", "info", tags=["no_such_tag_xyz"])
    with pytest.raises(UnknownVocab):
        res.pivot(T.IPV4, "203.0.113.1", "no_such_relation_xyz")
    assert issubclass(UnknownVocab, ContractViolation)
    with pytest.raises(ContractViolation):
        res.finding("x", "info", attack=["T9999"])


def test_non_strict_never_raises_and_logs_once(lenient, caplog):
    caplog.set_level(logging.WARNING, logger="v3lum.contract")
    res = result("t_lenient_mod")
    f = res.finding("Bad thing", "high")
    assert f.criterion == "unspecified"
    res.finding("Bad thing 2", "high")
    res.attr("no_such_attribute_xyz", 1)
    res.attr("no_such_attribute_xyz", 2)
    res.finding("x", "info", tags=["no_such_tag_xyz"], attack=["T9999"])
    assert res.attributes["no_such_attribute_xyz"] == 2  # unknown names are kept
    assert "no_such_tag_xyz" in res.findings[-1].tags and res.findings[-1].attack == ["T9999"]
    messages = [r.getMessage() for r in caplog.records if r.name == "v3lum.contract"]
    assert sum("criterion" in m for m in messages) == 1
    assert sum("no_such_attribute_xyz" in m for m in messages) == 1


def test_attr_skips_empty_values():
    res = result()
    res.attr("country", None)
    res.attr("country", "")
    res.attr("names", [])
    assert res.attributes == {}


# ------------------------------------------------------------------ collect_results
def test_collect_results_captures_results_created_inside():
    outside = result("before")
    with collect_results() as built:
        a = result("a")
        b = result("b")
    after = result("after")
    assert built == [a, b] and outside not in built and after not in built
    with collect_results() as other:
        pass
    assert other == []


def test_correlation_v2_fields_and_round_trip():
    c = Correlation(
        "r1", "Two sources agree", "high", "desc", entities=[Entity.make("domain", "evil.example")], confidence="probable",
        criterion="2 families", attack=["T1566"], references=["https://example.net/r"], why="independent feeds", key="k",
    )
    d = c.to_dict()
    assert {"criterion", "confidence_label", "attack", "references", "version", "why", "key", "suppressed_by"} <= set(d)
    assert d["confidence_label"] == "probable" and d["version"] == "1" and len(d["id"]) == 16
    again = Correlation.from_dict(d)
    assert again.to_dict() == d
    c.downgrade("generic_address", "role address", to="possible")
    assert c.label is Confidence.POSSIBLE and c.criterion.startswith("POSSIBLE - role address")


def test_models_exports():
    for name in ("Status", "Severity", "Opsec", "REASON_CODES", "STOP_REASONS", "DEFAULT_REASON", "status_for", "valid_reason",
                 "Confidence", "CONFIDENCE_TABLE", "Finding", "Pivot", "ModuleResult", "Correlation", "finding_id",
                 "correlation_id", "collect_results", "ContractViolation"):
        assert hasattr(models, name), name
