"""``v3lum cases`` (WP18; A10, P324, P325, P334, P322): purge, delete, legal hold, verify, resume,
override and confirm end to end through ``main([...])`` on a temporary home. Cases are produced by
the real engine with synthetic modules (offline, deterministic) and the case audit hook."""

from __future__ import annotations

import datetime as _dt
import io
import json
import os

import pytest

from tests.fakes import FakeClock, FakeHttp, define_module
from v3lum import paths
from v3lum.cli import main
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import QuotaExceeded
from v3lum.core.store import Store

NOW = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setenv("COLUMNS", "250")


@pytest.fixture()
def http(monkeypatch):
    """Runtimes built by the App go over this FakeHttp (nothing is needed: the modules are offline)."""
    from v3lum.app import App
    from v3lum.core.context import Runtime

    fake = FakeHttp()
    clock = FakeClock(NOW - _dt.timedelta(minutes=5))
    fake.clock = clock

    def runtime(self, listener=None):
        return Runtime(self.config, transport=fake, clock=clock, no_cache=True, offline=self.offline, listener=listener)

    monkeypatch.setattr(App, "runtime", runtime)
    return fake


RUNS: list[tuple[str, str, bool, int, tuple]] = []
STATE = {"quota": True}


@pytest.fixture()
def modules(clean_registry):
    """t_case_dom (domain: a finding, raw evidence, an IP pivot) and t_case_ip (ipv4: exhausted
    quota while STATE['quota'], else OK), t_case_ip_ok (ipv4: always OK)."""
    RUNS.clear()
    STATE["quota"] = True

    def dom(self, entity, ctx):
        RUNS.append((self.name, entity.key, ctx.is_seed, ctx.depth, ctx.provenance))
        res = self.result(entity)
        res.finding("Domain listed by the test feed", "high", criterion="listed by the synthetic test feed", tags=["malicious"])
        res.pivot(T.IPV4, "45.33.32.9", "resolves_to")
        res.raw = {"answer": entity.value}
        return res

    def ip(self, entity, ctx):
        RUNS.append((self.name, entity.key, ctx.is_seed, ctx.depth, ctx.provenance))
        if STATE["quota"]:
            raise QuotaExceeded("test provider: daily quota exhausted")
        res = self.result(entity)
        res.finding("IP seen by the test feed", "info")
        return res

    def ip_ok(self, entity, ctx):
        RUNS.append((self.name, entity.key, ctx.is_seed, ctx.depth, ctx.provenance))
        return self.result(entity)

    define_module("t_case_dom", [T.DOMAIN], dom)
    define_module("t_case_ip", [T.IPV4], ip)
    define_module("t_case_ip_ok", [T.IPV4], ip_ok)
    yield


def _scan(*, created: _dt.datetime | None = None, seed: str = "acme-case.example", reports: bool = True) -> dict:
    """One investigation through the real engine, with the case audit hook, stored like App.scan."""
    from v3lum.config import Config
    from v3lum.core.context import Runtime, ScanOptions
    from v3lum.core.engine import Engine
    from v3lum.report import write_reports

    clock = FakeClock(created or (NOW - _dt.timedelta(minutes=10)))
    rt = Runtime(Config.load(), transport=FakeHttp(), clock=clock, no_cache=True)
    store = Store()
    try:
        from v3lum.core.audit import AuditHook

        rt.case_hooks.append(AuditHook(store, analyst="tester"))
    except ImportError:  # pragma: no cover - WP15 not installed
        pass
    options = ScanOptions(include={"t_case_dom", "t_case_ip", "t_case_ip_ok"}, depth=1, tlp="amber")
    case = Engine(rt, options).investigate([Entity.make("domain", seed)])
    data = case.to_dict()
    if reports:
        data["reports"] = write_reports(data, ["json", "md"], case.case_dir)
        store.record_report_paths(case.case_id, data["reports"])
    store.save_case(data)
    store.close()
    return data


def _store() -> Store:
    return Store()


def _out(capsys) -> tuple[str, str]:
    captured = capsys.readouterr()
    return captured.out, captured.err


# --------------------------------------------------------------------------------------
# delete / purge / legal hold (A10)
# --------------------------------------------------------------------------------------


def test_delete_purges_every_copy_and_keeps_a_tombstone(modules, http, tmp_path, capsys):
    data = _scan()
    case_id = data["case_id"]
    case_dir = paths.cases_dir() / case_id
    assert list((case_dir / "evidence").glob("*.json*"))  # evidence written
    assert main(["cases", "report", case_id, "-f", "md", "-o", str(tmp_path)]) == 0  # an -o copy, recorded
    outside = [p for p in tmp_path.iterdir() if case_id in p.name]
    assert outside
    _out(capsys)
    assert main(["cases", "delete", case_id, "--dry-run"]) == 0
    assert "would remove" in _out(capsys)[0] and case_dir.exists()
    assert main(["cases", "delete", case_id]) == 0
    assert "removed" in _out(capsys)[0]
    with _store() as store:
        assert store.get_case(case_id) is None
        tomb = store.tombstone(case_id)
        assert tomb is not None and tomb["counts"]
    assert not case_dir.exists()
    assert not any(p.exists() for p in outside)
    assert main(["cases", "delete", case_id]) == 1  # already purged: nothing left
    assert "already purged" in _out(capsys)[0]


def test_hold_blocks_delete_and_purge_until_unhold(modules, http, capsys):
    case_id = _scan()["case_id"]
    assert main(["cases", "hold", case_id, "--reason", "litigation 42", "--requester", "legal dept"]) == 0
    _out(capsys)
    assert main(["cases", "list"]) == 0
    listing = _out(capsys)[0]
    assert case_id in listing and "held" in listing
    assert main(["cases", "delete", case_id]) == 1
    out, err = _out(capsys)
    assert "legal hold" in out + err
    assert main(["cases", "purge", "--older-than", "0"]) == 0
    out = _out(capsys)[0]
    assert "kept (legal hold: litigation 42)" in out and "under legal hold kept" in out
    with _store() as store:
        assert store.get_case(case_id) is not None
        kinds = [r["kind"] for r in store.audit_rows(case_id)]
    assert "hold" in kinds
    assert main(["cases", "unhold", case_id]) == 0
    with _store() as store:
        assert "unhold" in [r["kind"] for r in store.audit_rows(case_id)]
    assert main(["cases", "unhold", case_id]) == 1  # no longer held
    assert main(["cases", "purge", "--older-than", "0"]) == 0
    with _store() as store:
        assert store.get_case(case_id) is None and store.tombstone(case_id) is not None


def test_purge_by_retention_and_dry_run(modules, http, capsys):
    old = _scan(created=NOW - _dt.timedelta(days=200), seed="old-case.example")["case_id"]
    new = _scan(seed="new-case.example")["case_id"]
    assert main(["cases", "purge", "--dry-run"]) == 0  # default: retention_days (180)
    out = _out(capsys)[0]
    assert old in out and "would remove" in out and new not in out
    with _store() as store:
        assert store.get_case(old) is not None
    assert main(["cases", "purge"]) == 0
    with _store() as store:
        assert store.get_case(old) is None and store.get_case(new) is not None
    assert main(["config", "set", "retention_days", "0"]) == 0
    _out(capsys)
    assert main(["cases", "purge"]) == 0
    assert "retention_days is 0" in _out(capsys)[0]


def test_hold_needs_an_existing_case(capsys):
    assert main(["cases", "hold", "20990101-000000-ffff", "--reason", "r", "--requester", "q"]) == 1
    assert "not found" in _out(capsys)[1]


# --------------------------------------------------------------------------------------
# verify (P324 cond 6)
# --------------------------------------------------------------------------------------


def test_verify_passes_then_detects_tampering(modules, http, capsys):
    pytest.importorskip("v3lum.core.audit")
    case_id = _scan()["case_id"]
    assert main(["cases", "verify", case_id]) == 0
    assert "PASS" in _out(capsys)[0]
    evidence = sorted((paths.cases_dir() / case_id / "evidence").glob("*.json*"))[0]
    evidence.chmod(0o600)
    evidence.write_bytes(evidence.read_bytes() + b" ")
    assert main(["cases", "verify", case_id]) == 1
    out = _out(capsys)[0]
    assert "FAIL" in out and "problem" in out


def test_verify_unknown_case_fails(capsys):
    pytest.importorskip("v3lum.core.audit")
    assert main(["cases", "verify", "20990101-000000-ffff"]) == 1
    assert "not found" in _out(capsys)[0]


# --------------------------------------------------------------------------------------
# resume (P334 cond 7)
# --------------------------------------------------------------------------------------


def test_resume_reruns_only_the_deferred_pairs_with_their_run_facts(modules, http, capsys):
    data = _scan(reports=False)
    case_id = data["case_id"]
    ip_key = "ipv4:45.33.32.9"
    assert any(d["module"] == "t_case_ip" and d["entity"] == ip_key for d in data["deferred"])  # quota-deferred
    with _store() as store:
        from v3lum.core.quota import QuotaBook, default_path

        book = QuotaBook(default_path(store))
        assert [r["module"] for r in book.deferred(case_id, case=data)] == ["t_case_ip"]
        book.close()
    RUNS.clear()
    STATE["quota"] = False
    assert main(["cases", "resume", case_id, "--json", "-f", ""]) == 0
    new = json.loads(_out(capsys)[0])
    assert new["case_id"] != case_id and new["meta"]["resumed_from"] == case_id
    # only the deferred pair ran: not the seed's module, not the IP module that had answered
    assert [(m, k) for m, k, *_ in RUNS] == [("t_case_ip", ip_key)]
    _module, _key, is_seed, depth, provenance = RUNS[0]
    assert is_seed is False and depth == 1  # a pivot is never promoted to a typed seed
    assert provenance == (("domain:acme-case.example", "resolves_to", "t_case_dom"),)
    assert {r["module"] for r in new["modules"]} == {"t_case_ip"}
    assert new["options"]["tlp"] == "amber"
    nodes = {n["key"]: n for n in new["entities"]}
    assert nodes[ip_key]["seed"] is False and nodes["domain:acme-case.example"]["seed"] is True
    with _store() as store:
        assert store.get_case(new["case_id"]) is not None


def test_resume_with_nothing_to_do(modules, http, capsys):
    STATE["quota"] = False
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "resume", case_id]) == 0
    assert "nothing to resume" in _out(capsys)[0]


def test_resume_never_escalates_the_mode(modules, http, capsys):
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "resume", case_id, "--mode", "light"]) == 1
    assert "never escalates" in _out(capsys)[1]


def test_resume_plan_and_run_info_helpers():
    from v3lum.commands.cases import resume_plan, run_info_of

    case = {
        "case_id": "c1", "tlp": "amber", "seeds": ["domain:a.example"],
        "options": {"tlp": "amber", "unconfirmed_seeds": []},
        "entities": [
            {"key": "domain:a.example", "depth": 0, "seed": True, "tlp": "amber"},
            {"key": "ipv4:45.33.32.9", "depth": 1, "seed": False, "tlp": "amber+strict"},
            {"key": "domain:b.example", "depth": 2, "seed": False, "tlp": "amber"},
        ],
        "edges": [
            {"src": "domain:a.example", "dst": "ipv4:45.33.32.9", "relation": "resolves_to", "module": "m1"},
            {"src": "ipv4:45.33.32.9", "dst": "domain:b.example", "relation": "hosted_domain", "module": "m2"},
        ],
        "deferred": [{"module": "m3", "entity": "domain:b.example", "reason": "quota"}],
        "execution": [
            {"module": "m1", "entity": "domain:a.example", "status": "ok"},
            {"module": "m2", "entity": "ipv4:45.33.32.9", "status": "blocked", "reason_code": "challenge"},
            {"module": "m4", "entity": "ipv4:45.33.32.9", "status": "skipped", "reason_code": "licence"},
            {"module": "m5", "entity": "domain:a.example", "status": "skipped", "reason_code": "deadline"},
            {"module": "m6", "entity": "jwt:eyJ[redacted]", "status": "error"},
        ],
    }
    pairs, notes = resume_plan(case, [{"module": "m7", "entity_key": "email:#0123456789ab"}])
    assert set(pairs) == {("m3", "domain:b.example"), ("m2", "ipv4:45.33.32.9"), ("m5", "domain:a.example")}
    assert pairs[("m2", "ipv4:45.33.32.9")] == {
        "is_seed": False, "depth": 1, "provenance": [["domain:a.example", "resolves_to", "m1"]], "tlp": "amber+strict",
    }
    assert pairs[("m3", "domain:b.example")]["provenance"] == [
        ["domain:a.example", "resolves_to", "m1"], ["ipv4:45.33.32.9", "hosted_domain", "m2"],
    ]
    assert pairs[("m5", "domain:a.example")]["is_seed"] is True
    assert any("could not be mapped back" in n for n in notes) and any("redacted" in n for n in notes)
    unconfirmed = dict(case, options={"tlp": "amber", "unconfirmed_seeds": ["domain:a.example"]})
    assert run_info_of(unconfirmed, "domain:a.example")["is_seed"] is False


# --------------------------------------------------------------------------------------
# override / confirm (P322 cond 3)
# --------------------------------------------------------------------------------------


def test_override_and_confirm_are_recorded_audited_and_shown(modules, http, capsys):
    data = _scan(reports=False)
    case_id = data["case_id"]
    finding = next(f for f in data["findings"] if f["title"] == "Domain listed by the test feed")
    fid = finding["id"]
    assert finding["confidence_label"] != "possible"
    assert main(["cases", "override", case_id, fid[:10], "--label", "possible", "--severity", "low", "--verdict", "wrong", "--note", "benign infra"]) == 0
    assert "override recorded" in _out(capsys)[0]
    with _store() as store:
        stored = store.overrides_for([fid])[fid]
        assert (stored["label"], stored["severity"], stored["verdict"]) == ("possible", "low", "wrong")
        rows = [r for r in store.audit_rows(case_id) if r["kind"] == "override"]
    assert len(rows) == 1 and rows[0]["payload"]["finding_id"] == fid and rows[0]["payload"]["verdict"] == "wrong"
    assert main(["cases", "show", case_id, "--json"]) == 0
    shown = json.loads(_out(capsys)[0])
    item = next(f for f in shown["findings"] if f["id"] == fid)
    assert item["confidence_label"] == "possible" and item["severity"] == "low"
    assert item["override"]["verdict"] == "wrong" and item["override"]["auto"]["severity"] == "high"
    with _store() as store:
        raw = store.get_case(case_id)
    assert next(f for f in raw["findings"] if f["id"] == fid)["severity"] == "high"  # the stored case is not rewritten
    assert main(["cases", "confirm", case_id, fid]) == 0
    _out(capsys)
    assert main(["cases", "show", case_id, "--json"]) == 0
    item = next(f for f in json.loads(_out(capsys)[0])["findings"] if f["id"] == fid)
    assert item["confidence_label"] == "confirmed" and item["severity"] == "low"  # fields left out are kept
    with _store() as store:
        assert len([r for r in store.audit_rows(case_id) if r["kind"] == "override"]) == 2


def test_override_errors(modules, http, capsys):
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "override", case_id, "ffffffffffffffff", "--label", "confirmed"]) == 1
    assert "not in case" in _out(capsys)[1]
    fid = _store().get_case(case_id)["findings"][0]["id"]
    assert main(["cases", "override", case_id, fid]) == 1
    assert "nothing to record" in _out(capsys)[1]


# --------------------------------------------------------------------------------------
# list / show / report
# --------------------------------------------------------------------------------------


def test_list_show_report(modules, http, tmp_path, capsys):
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "list", "--json"]) == 0
    rows = json.loads(_out(capsys)[0])
    assert rows[0]["id"] == case_id and rows[0]["legal_hold"] is False
    assert main(["cases", "show", "last"]) == 0
    assert main(["cases", "report", "last", "-f", "md,json", "-o", str(tmp_path)]) == 0
    written = [p for p in tmp_path.iterdir() if case_id in p.name]
    assert written
    with _store() as store:
        recorded = store.report_paths(case_id)
    assert {str(p) for p in written} <= set(recorded)  # the purge will find them
    assert main(["cases", "show", "no-such-case"]) == 1


def test_list_masks_personal_seeds_and_never_prints_clean(capsys, monkeypatch):
    """Wave-3 integration (WP14 -> WP18/WP13): `cases list` and App.cases_table read v1 'clean'
    as 'no findings' and show seeds through ui.safe.entity_display (a full CPF never appears, AR24;
    control characters and markup in a stored case stay inert)."""
    from rich.console import Console

    from v3lum.app import App
    from v3lum.ui.theme import THEME

    rows = [
        {"id": "c-v1", "created": "2025-01-01T00:00:00", "seeds": ["cpf:529.982.247-25", "domain:ok.example"], "risk_level": "clean",
         "risk_score": 0, "tlp": "amber", "legal_hold": 0, "engagement": 0, "findings": 0, "entities": 1},
        {"id": "c-v2\x1b]8;;x\x07", "created": "2026-11-26T00:00:00", "seeds": ["domain:[bold]evil.example"], "risk_level": "high",
         "risk_score": 70, "tlp": "red", "legal_hold": 1, "engagement": 0, "findings": 2, "entities": 3},
    ]
    monkeypatch.setattr(Store, "list_cases", lambda self, limit=30, search="": rows)
    assert main(["cases", "list"]) == 0
    out = _out(capsys)[0]
    console = Console(record=True, width=250, theme=THEME)
    console.print(App(console, offline=True).cases_table())
    for text in (out, console.export_text()):
        assert "529.982.247-25" not in text and "52998224725" not in text
        assert "clean" not in text and "no findings 0" in text and "high 70" in text
        assert "\x1b" not in text and "[bold]evil.example" in text


def test_feedback_outside_a_terminal_records_nothing_and_says_so(modules, http, capsys):
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "feedback", case_id]) == 0
    assert "nothing recorded" in _out(capsys)[0]
    with _store() as store:
        assert not [r for r in store.audit_rows(case_id) if r["kind"] in ("feedback", "verdict")]
    assert main(["cases", "feedback", "no-such-case"]) == 1




def test_report_rerender_records_hashes_audits_and_verify_checks_them(modules, http, tmp_path, capsys):
    """`cases report` records each written file with its SHA-256 (P324 cond 6) and an audit row;
    `cases verify` then detects an edited report."""
    pytest.importorskip("v3lum.core.audit")
    case_id = _scan(reports=False)["case_id"]
    assert main(["cases", "report", case_id, "-f", "md,json", "-o", str(tmp_path)]) == 0
    _out(capsys)
    written = sorted(p for p in tmp_path.iterdir() if case_id in p.name and not p.name.endswith(".sha256"))
    with _store() as store:
        hashes = store.report_hashes(case_id)
        rows = [r for r in store.audit_rows(case_id) if r["kind"] == "report"]
    assert len(written) == 2 and {os.path.realpath(p) for p in written} <= {os.path.realpath(k) for k in hashes}
    assert len(rows) == 1 and {f["format"] for f in rows[0]["payload"]["reports"]} == {"md", "json"}
    assert all(str(tmp_path) not in json.dumps(r["payload"]) for r in rows)  # file names only, no directory
    assert main(["cases", "verify", case_id]) == 0
    assert "PASS" in _out(capsys)[0]
    md = next(p for p in written if p.suffix == ".md")
    md.write_text(md.read_text(encoding="utf-8") + "\nedited\n", encoding="utf-8")
    assert main(["cases", "verify", case_id]) == 1
    assert md.name in _out(capsys)[0]


def test_the_org_profile_trail_is_not_a_case(modules, http, capsys):
    """`cases delete org-profile` never wipes the org-profile audit trail (P378 cond 11);
    `cases verify org-profile` checks its hash chain."""
    pytest.importorskip("v3lum.core.audit")
    from v3lum.commands.org import AUDIT_CASE_ID, audit_profile_change

    with _store() as store:
        audit_profile_change(store, {"action": "attest", "field": "domains", "domain": "acme.example"})
    for argv in (["cases", "delete", AUDIT_CASE_ID], ["cases", "delete", AUDIT_CASE_ID, "--dry-run"]):
        assert main(argv) == 1
        assert "not a case" in _out(capsys)[1]
    with _store() as store:
        assert len(store.audit_rows(AUDIT_CASE_ID)) == 1
    assert main(["cases", "verify", AUDIT_CASE_ID]) == 0
    assert "PASS" in _out(capsys)[0]
    assert not (paths.cases_dir() / AUDIT_CASE_ID).exists()  # no case directory for a trail


def test_resuming_an_active_case_needs_its_own_reference_and_scope(tmp_path):
    """A7 on the resume path: ACTIVE needs --authorized REF and --scope FILE again, the case's own
    (same reference, same scope SHA-256) and usable now."""
    from types import SimpleNamespace

    from v3lum.app import UserError
    from v3lum.commands.cases import _stored_options
    from v3lum.core.models import Opsec
    from v3lum.core.scope import Scope

    now = _dt.datetime.now(_dt.timezone.utc)
    scope_doc = {
        "authorization_ref": "PT-2026-001", "owner": "ACME security", "contacts": ["soc@acme.example"], "ticket": "SEC-1",
        "window_start": (now - _dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end": (now + _dt.timedelta(hours=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets": {"domains": ["acme.example"], "cidrs": [], "url_prefixes": []},
    }
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps(scope_doc), encoding="utf-8")
    sha = Scope.load(scope_file).sha256
    case = {"case_id": "c1", "tlp": "amber", "options": {"mode": "active", "tlp": "amber", "authorization_ref": "PT-2026-001", "scope": sha}}
    app = SimpleNamespace(offline=True, no_cache=True, config=None)

    def args(**kw):
        base = {"mode": None, "authorized": None, "scope": None, "timeout": 0.0, "no_evidence": False}
        return SimpleNamespace(**{**base, **kw})

    with pytest.raises(UserError, match="--authorized REF and --scope FILE"):
        _stored_options(case, app, args())
    with pytest.raises(UserError, match="differs from the case's authorization reference"):
        _stored_options(case, app, args(authorized="PT-2026-999", scope=str(scope_file)))
    other = tmp_path / "other.json"
    other.write_text(json.dumps({**scope_doc, "ticket": "SEC-2"}), encoding="utf-8")
    with pytest.raises(UserError, match="differs from the one recorded"):
        _stored_options(case, app, args(authorized="PT-2026-001", scope=str(other)))
    options = _stored_options(case, app, args(authorized="PT-2026-001", scope=str(scope_file)))
    assert options.mode is Opsec.ACTIVE and options.authorized and options.scope.sha256 == sha
    lowered = _stored_options(case, app, args(mode="passive"))  # lowering the mode needs no scope
    assert lowered.mode is Opsec.PASSIVE and not lowered.authorized


@pytest.mark.parametrize("value", ["-1", "nan", "inf", "1e12"])
def test_purge_rejects_impossible_ages(value, capsys):
    assert main(["cases", "purge", "--older-than", value]) == 1
    assert "--older-than must be" in _out(capsys)[1]


def test_a_resumed_case_with_reports_verifies(modules, http, capsys):
    pytest.importorskip("v3lum.core.audit")
    case_id = _scan(reports=False)["case_id"]
    STATE["quota"] = False
    assert main(["cases", "resume", case_id, "--json", "-f", "json,md"]) == 0
    new = json.loads(_out(capsys)[0])
    assert set(new["reports"]) == {"json", "md"}
    with _store() as store:
        assert {os.path.realpath(p) for p in new["reports"].values()} <= {os.path.realpath(p) for p in store.report_hashes(new["case_id"])}
    assert main(["cases", "verify", new["case_id"]]) == 0
    assert "PASS" in _out(capsys)[0]
