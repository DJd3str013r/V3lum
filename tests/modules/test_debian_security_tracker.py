"""debian_security_tracker (P355): streaming tracker index, dpkg comparison, banner backport check.

Fixtures in tests/fixtures/debian_security_tracker/ (prep batch p3-G08-1, live 2026-11-26):
``tracker_trimmed.json`` (92,859,058 B -> 4 packages / 8 ids, compact separators as served),
``malformed_truncated.json`` (the first 900 bytes: an interrupted download), ``head_gzip.http.json`` and
``not_modified.http.json`` (the conditional-GET behaviour of the live host: 304 keeps the copy).
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from tests.fakes import FakeHttp, graph_fixture, module_fixture, run_module
from v3lum.core import correlate
from v3lum.core.datasets import DATASETS, DataStore
from v3lum.core.models import Confidence, Opsec, Status
from v3lum.modules.vulnerability_cve import debian_security_tracker as mod
from v3lum.modules.vulnerability_cve.debian_security_tracker import (
    DATASET,
    SUPPRESSION_REASON,
    SUPPRESSION_RULE,
    DebianSecurityTracker,
    TrackerError,
    adjustment,
    backport_verdict,
    build_index,
    debian_applicable,
    dpkg_compare,
    index_path,
    iter_tracker,
    lookup_cve,
    open_index,
    parse_debian_banner,
    rows_from_distro_fixes,
)

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "debian_security_tracker"
RULES = Path(__file__).resolve().parents[1] / "fixtures" / "rules"
TRACKER = FIX / "tracker_trimmed.json"


@pytest.fixture
def small_thresholds(monkeypatch):
    monkeypatch.setattr(mod, "MIN_PACKAGES", 1)
    monkeypatch.setattr(mod, "MIN_IDS", 1)


@pytest.fixture
def installed(small_thresholds):
    """The trimmed tracker installed as the local dataset copy (as `v3lum data update` would leave it)."""
    target = DataStore(None).path(DATASET)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(TRACKER.read_bytes())
    return target


# ------------------------------------------------------------------ council metadata (cond 1)
def test_metadata_and_dataset_registration():
    cls = DebianSecurityTracker
    assert cls.default_enabled is False and cls.terms == "open" and cls.disclosure == "none" and cls.trust_tier == "n/a"
    assert cls.opsec is Opsec.PASSIVE and cls.hosts == () and cls.sources == ("debian.security_tracker",)
    reg = DATASETS[DATASET]
    assert reg["url"] == "https://security-tracker.debian.org/tracker/data/json" and reg["large"] is True
    assert reg["expect"] == "bytes" and reg["min_bytes"] == 50_000_000 and reg["ttl"] == 86400  # never json.load'ed whole
    assert reg["validate"] is mod.validate_dataset and reg["terms_class"] == "open"
    assert module_fixture("debian_security_tracker", "not_modified.http.json")["response"]["status"] == 304


# ------------------------------------------------------------------ streaming parser (cond 1)
def test_streaming_parser_yields_entries_one_at_a_time():
    stats: dict = {}
    triples = list(iter_tracker(io.BytesIO(TRACKER.read_bytes()), chunk_size=64, stats=stats))
    assert stats["packages"] == 4 and stats["ids"] == 8 and len(triples) == 8
    assert ("openssh", "CVE-2024-6387") in {(p, i) for p, i, _ in triples}


@pytest.mark.parametrize("body", [
    (FIX / "malformed_truncated.json").read_bytes(),
    b'{"a": {"CVE-2020-0001": {"releases": {}}}} trailing',
    b'{"a": {"CVE-2020-0001": 5}}',
    b"\xff\xfe{}",
])
def test_truncated_or_malformed_tracker_is_refused(body):
    with pytest.raises(TrackerError):
        list(iter_tracker(io.BytesIO(body)))


def test_index_build_keeps_the_previous_index_on_failure(tmp_path, small_thresholds):
    meta = build_index(TRACKER)
    assert int(meta["packages"]) == 3 and int(meta["ids"]) == 7 and int(meta["temp_skipped"]) == 1  # TEMP- ids (adduser) are skipped
    bad = tmp_path / "bad.json"
    bad.write_bytes((FIX / "malformed_truncated.json").read_bytes())
    with pytest.raises(TrackerError):
        build_index(bad)
    html = tmp_path / "page.json"
    html.write_text("<!DOCTYPE html><html><title>Just a moment...</title></html>")
    with pytest.raises(TrackerError, match="HTML"):
        build_index(html)
    con = open_index()
    try:
        assert {r["release"] for r in lookup_cve(con, "CVE-2024-6387")} == {"bookworm", "trixie", "forky", "sid"}
    finally:
        con.close()
    assert oct(index_path().stat().st_mode & 0o777) == "0o600"
    assert not list(index_path().parent.glob(".tmp-debian-*"))


def test_implausible_tracker_is_refused_with_the_real_thresholds():
    with pytest.raises(TrackerError, match="too few packages"):
        build_index(TRACKER)
    assert not index_path().exists()


# ------------------------------------------------------------------ dpkg algorithm (cond 3)
@pytest.mark.parametrize(("left", "right", "expected"), [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("1:1.0", "2.0", 1),  # the epoch wins
    ("1.0~rc1", "1.0", -1),  # '~' sorts before everything, even the end
    ("1.0~~", "1.0~", -1),
    ("1.0a", "1.0+", -1),  # letters before non-letters
    ("1.0.10", "1.0.9", 1),  # numeric runs compared as numbers
    ("1.007", "1.7", 0),  # leading zeros
    ("2.30-1", "2.4-1", 1),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", 1),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u10", -1),
    ("8.2.29-1~deb12u1", "8.2.29-1", -1),
    ("1.2-3-4", "1.2-3-5", -1),  # hyphenated upstream: the revision is after the last hyphen
    ("0:1.0", "1.0", 0),
])
def test_dpkg_compare_vectors(left, right, expected):
    assert dpkg_compare(left, right) == expected
    assert dpkg_compare(right, left) == -expected


def test_dpkg_compare_rejects_invalid_versions():
    for bad in ("a:1.0", "1.0 beta", "", ":1", "1.0-"):
        with pytest.raises(ValueError):
            dpkg_compare(bad, "1.0")


# ------------------------------------------------------------------ banners and verdicts (cond 2/3/4)
def test_banner_parsing():
    ssh = parse_debian_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")
    assert ssh == {"distro": "debian", "source_package": "openssh", "upstream": "9.2p1", "revision": "2+deb12u3",
                   "version": "9.2p1-2+deb12u3", "release": "bookworm", "release_hint": "deb12"}
    assert parse_debian_banner("PHP/8.2.29-1~deb12u1")["source_package"] == "php8.2"
    assert parse_debian_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")["distro"] == "ubuntu"
    assert parse_debian_banner("PHP/8.3.1-1+debian12~1.gbp")["distro"] == "third_party"
    assert parse_debian_banner("OpenSSH_8.4p1 Raspbian-5+deb11u1")["distro"] == "debian_derivative"
    assert parse_debian_banner("Apache/2.4.62 (Debian)") is None and parse_debian_banner(None) is None


def test_applicability_needs_debian_evidence():
    assert debian_applicable({"banners": ["Apache/2.4.62 (Debian)"]})["exact"] is True
    assert debian_applicable({"os": "Ubuntu 22.04"}) == {"applicable": True, "distro": "ubuntu", "evidence": "fingerprint", "exact": False}
    assert debian_applicable({"analyst_os": "debian"})["evidence"] == "analyst input"
    assert debian_applicable({"banners": ["Microsoft-IIS/10.0"], "os": "Windows"})["applicable"] is False


def tracker_rows(cve: str) -> list[dict]:
    return [r for r in (dict(package=p, cve=i, release=rel, status=v.get("status"), fixed_version=v.get("fixed_version"))
                        for p, ids in module_fixture("debian_security_tracker", "tracker_trimmed.json").items()
                        for i, e in ids.items() for rel, v in e.get("releases", {}).items()) if r["cve"] == cve]


def test_backport_verdicts_and_adjustments():
    info = parse_debian_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3")
    fixed = backport_verdict(info, "CVE-2023-48795", tracker_rows("CVE-2023-48795"))
    assert fixed["verdict"] == "fixed" and fixed["installed"] == "1:9.2p1-2+deb12u3"  # epoch from SOURCE_EPOCHS
    assert adjustment(fixed) == {"action": "suppress", "rule": SUPPRESSION_RULE, "reason": SUPPRESSION_REASON,
                                 "criterion": adjustment(fixed)["criterion"]}
    assert backport_verdict(info, "CVE-2008-3259", tracker_rows("CVE-2008-3259"))["verdict"] == "not_affected"
    unfixed = backport_verdict(info, "CVE-2026-73281", tracker_rows("CVE-2026-73281"))
    assert unfixed["verdict"] == "unfixed" and adjustment(unfixed)["action"] == "raise"
    old = parse_debian_banner("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2")
    assert backport_verdict(old, "CVE-2024-6387", tracker_rows("CVE-2024-6387"))["verdict"] == "unfixed"
    # P355 cond 3's own example: bullseye has left the tracker export -> nothing changes
    bullseye = parse_debian_banner("OpenSSH_8.4p1 Debian-5+deb11u3")
    gone = backport_verdict(bullseye, "CVE-2024-6387", tracker_rows("CVE-2024-6387"))
    assert gone["verdict"] == "release_not_tracked" and adjustment(gone) is None
    assert backport_verdict({}, "CVE-2024-6387", [])["verdict"] == "no_revision"
    ubuntu = parse_debian_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    assert backport_verdict(ubuntu, "CVE-2024-6387", tracker_rows("CVE-2024-6387"))["verdict"] == "not_debian"


def test_distro_fixes_round_trip():
    rows = rows_from_distro_fixes("CVE-2023-48795", [
        {"distro": "debian", "release": "12", "package": "openssh", "fixed": "1:9.2p1-2+deb12u2", "status": "fixed"},
        {"distro": "ubuntu", "release": "22.04", "package": "openssh", "fixed": "1", "status": "fixed"},
        {"distro": "debian", "codename": "trixie", "package": "openssh", "status": "unfixed"},
    ])
    assert [(r["release"], r["status"]) for r in rows] == [("bookworm", "resolved"), ("trixie", "open")]


# ------------------------------------------------------------------ the module (cond 1/2)
def test_without_the_dataset_the_module_is_unavailable():
    res = run_module(DebianSecurityTracker, "cve:CVE-2024-6387", FakeHttp())
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "data update" in res.error


def test_cve_seed_shows_per_release_status_offline(installed):
    http = FakeHttp()
    res = run_module(DebianSecurityTracker, "cve:CVE-2024-6387", http)
    assert res.status is Status.OK, res.error
    assert not http.calls and res.requests == 0  # no per-query network call
    a = res.attributes
    bookworm = next(f for f in a["distro_fixes"] if f["codename"] == "bookworm")
    assert bookworm == {"distro": "debian", "release": "12", "codename": "bookworm", "package": "openssh",
                        "fixed": "1:9.2p1-2+deb12u3", "status": "fixed", "urgency": "not yet assigned",
                        "record": "https://security-tracker.debian.org/tracker/CVE-2024-6387"}
    assert a["debian_tracker"]["packages"] == ["openssh"] and a["debian_tracker"]["resolved"] == 4
    assert {"product": "Debian bookworm openssh", "fixed": "1:9.2p1-2+deb12u3"} in a["fixed_versions"]
    assert res.datasets and res.datasets[0]["name"] == DATASET


def test_never_affected_and_open_states(installed):
    a = run_module(DebianSecurityTracker, "cve:CVE-2008-3259", FakeHttp()).attributes
    assert {f["status"] for f in a["distro_fixes"]} == {"not_affected"} and "fixed_versions" not in a
    b = run_module(DebianSecurityTracker, "cve:CVE-2026-73281", FakeHttp()).attributes
    assert b["debian_tracker"]["open"] == 2


def test_pivot_cves_are_not_shown(installed):
    res = run_module(DebianSecurityTracker, "cve:CVE-2024-6387", FakeHttp(), is_seed=False, depth=1)
    assert res.status is Status.SKIPPED and "Debian-based" in res.error


def test_unknown_cve_is_empty_and_package_keyword_lists_status(installed):
    assert run_module(DebianSecurityTracker, "cve:CVE-2020-0001", FakeHttp()).status is Status.EMPTY
    res = run_module(DebianSecurityTracker, "keyword:openssh", FakeHttp())
    assert res.status is Status.OK
    statuses = res.attributes["debian_package_status"]
    assert {s["cve"] for s in statuses} >= {"CVE-2024-6387", "CVE-2026-73281"}
    assert [p.entity.value for p in res.pivots] == ["CVE-2026-73281"] and all(not p.expand for p in res.pivots)
    assert run_module(DebianSecurityTracker, "keyword:not a package!", FakeHttp()).status is Status.SKIPPED
    assert run_module(DebianSecurityTracker, "keyword:nosuchpkg", FakeHttp()).status is Status.EMPTY


def test_validate_callback_refuses_a_truncated_download(tmp_path, small_thresholds):
    bad = tmp_path / "json"
    bad.write_bytes((FIX / "malformed_truncated.json").read_bytes())
    with pytest.raises(TrackerError):
        mod.validate_dataset(bad)
    assert mod.validate_dataset(TRACKER) is True and index_path().is_file()


def test_selftest_reports_the_index(installed):
    assert DebianSecurityTracker.health_check().offline is True
    from tests.fakes import make_ctx

    assert DebianSecurityTracker.health_check().selftest(make_ctx(DebianSecurityTracker)).status == "dead"
    build_index(TRACKER)
    assert DebianSecurityTracker.health_check().selftest(make_ctx(DebianSecurityTracker)).status == "ok"


# ------------------------------------------------------------------ the backport rule (cond 3/4)
def _run_rule(name: str, rule_id: str = "p3g081_debian_backport", settings: dict | None = None):
    graph, results, rctx = graph_fixture(RULES / rule_id / name)
    for name, value in (settings or {}).items():
        rctx.settings.set(name, value)
    out = correlate.run_rules(graph, results, only={rule_id}, rctx=rctx)
    return graph, out


def test_fixed_in_distro_package_suppresses_the_version_inferred_finding():
    graph, out = _run_rule("positive_fixed_in_distro_package_suppressed.json")
    finding = graph.get("ipv4:203.0.113.20").findings[0]
    assert finding.suppressed_by[-1] == {"rule": SUPPRESSION_RULE, "reason": SUPPRESSION_REASON}
    assert finding.label is Confidence.POSSIBLE and "context_only" in finding.tags
    assert finding.criterion.startswith("POSSIBLE - fixed in distro package")
    assert finding.data["distro_backport"]["fixed"] == ["CVE-2023-38408", "CVE-2023-48795"]
    assert len(out) == 1 and "fixed in the distro package" in out[0].title


def test_unfixed_raises_confidence_once_and_caps_at_probable():
    graph, out = _run_rule("positive_unfixed_raises_confidence.json")
    finding = graph.get("ipv4:203.0.113.21").findings[0]
    assert finding.label is Confidence.PROBABLE and finding.upgraded_by[0]["rule"] == "distro_backport_unfixed"
    assert not finding.suppressed_by and "still unfixed" in out[0].title


def test_nothing_changes_without_a_distro_revision_or_on_ubuntu():
    for name, key in (("negative_no_distro_revision_nothing_changes.json", "ipv4:203.0.113.22"),
                      ("negative_not_debian_based.json", "ipv4:203.0.113.23")):
        graph, out = _run_rule(name)
        finding = graph.get(key).findings[0]
        assert not out and not finding.suppressed_by and not finding.upgraded_by and finding.label is Confidence.POSSIBLE


def test_analyst_override_wins_over_the_suppression():
    graph, results, rctx = graph_fixture(RULES / "p3g081_debian_backport" / "positive_fixed_in_distro_package_suppressed.json")
    finding = graph.get("ipv4:203.0.113.20").findings[0]
    finding.apply_override(label="probable", verdict="true_positive", analyst="analyst-1")
    correlate.run_rules(graph, results, only={"p3g081_debian_backport"}, rctx=rctx)
    assert finding.label is Confidence.PROBABLE and finding.suppressed_by[-1]["blocked_by"] == "analyst"


def test_setting_off_disables_the_check():
    graph, out = _run_rule("positive_fixed_in_distro_package_suppressed.json", settings={"debian_security_tracker_backport_check": False})
    assert not out and not graph.get("ipv4:203.0.113.20").findings[0].suppressed_by


def test_rule_reads_the_local_index_when_the_cve_node_has_no_distro_facts(small_thresholds):
    build_index(TRACKER)
    graph, results, rctx = graph_fixture(RULES / "p3g081_debian_backport" / "positive_fixed_in_distro_package_suppressed.json")
    for cve in ("CVE-2023-38408", "CVE-2023-48795"):
        graph.get(f"cve:{cve}").attributes.pop("distro_fixes", None)
    out = correlate.run_rules(graph, results, only={"p3g081_debian_backport"}, rctx=rctx)
    assert out and graph.get("ipv4:203.0.113.20").findings[0].suppressed_by[-1]["rule"] == SUPPRESSION_RULE


def test_analyst_declared_asset_with_release():
    graph, results, rctx = graph_fixture(RULES / "p3g081_debian_backport" / "positive_unfixed_raises_confidence.json")
    node = graph.get("ipv4:203.0.113.21")
    node.attributes["services"] = [(["22/tcp ssh SSH-2.0-OpenSSH_9.2p1 Debian-2"], "port_scan")]  # no +debNN release hint
    rctx.settings.set("debian_security_tracker_assets", ["203.0.113.21=bookworm"])
    out = correlate.run_rules(graph, results, only={"p3g081_debian_backport"}, rctx=rctx)
    assert out and node.findings[0].label is Confidence.PROBABLE


def test_vex_not_affected_lowers_but_never_deletes():
    graph, out = _run_rule("positive_not_affected_lowers_match.json", rule_id="p3g081_vex_not_affected")
    finding = graph.get("ipv4:203.0.113.30").findings[0]
    assert finding.label is Confidence.POSSIBLE and finding.suppressed_by[-1]["rule"] == "vex_not_affected"
    assert "context_only" not in finding.tags and finding.data["vex"]["not_affected"] == ["CVE-2023-51767"]
    assert len(graph.get("ipv4:203.0.113.30").findings) == 1 and out[0].severity.label == "info"
