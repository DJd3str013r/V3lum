"""Case audit trail and the hash-chained request ledger (P324 cond 4-5, 8; A7 BR13-BR14; A8 BR9; A13).

A LIGHT run over FakeHttp writes its audit record (case_start/case_end) and the request ledger even
with save_evidence False; the chains are intact and anchored; the engagement summary and the
since-last-run counts reach the case dict; undeclared-host attempts become policy_violation rows and
out-of-scope refusals are listed in the engagement summary.
"""

from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from tests.fakes import DOH_HOSTS, FakeClock, FakeHttp, add_dns, define_module, make_runtime, source_ids, test_provider
from v3lum import paths
from v3lum.core import audit as audit_mod
from v3lum.core import evidence as ev
from v3lum.core.audit import AuditHook, CaseAudit, RequestLedger, engagement_of, ledger_entry, ledger_path, since_last_run_of, verify_case
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import RequestInfo
from v3lum.core.models import Opsec
from v3lum.core.store import Store

SEED = Entity.make("domain", "example.org")
TARGET_IP = "93.184.216.34"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    return clean_registry


@pytest.fixture()
def store():
    db = Store()
    yield db
    db.close()


def target_http(*paths_: str) -> FakeHttp:
    http = FakeHttp()
    add_dns(http, "example.org", "A", [TARGET_IP])
    add_dns(http, "example.org", "AAAA", [])
    for p in paths_:
        http.add("GET", f"https://example.org{p}", text="hello")
    return http


def light_module(name: str = "t_light_audit", requests: tuple[str, ...] = ("/",)):
    def run(self, entity, ctx):
        for p in requests:
            ctx.http.get(f"https://{entity.value}{p}")
        res = self.result(entity)
        res.finding("homepage reachable", "info", criterion="synthetic light check")
        return res

    return define_module(name, [T.DOMAIN], run, opsec=Opsec.LIGHT)


def audit_rows(store: Store, case_id: str) -> list[dict]:
    return store.audit_rows(case_id)


def ledger_lines(case) -> list[dict]:
    path = Path(case.case_dir) / audit_mod.LEDGER_FILE
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --------------------------------------------------------------------------------------
# acceptance: every LIGHT/ACTIVE request is in the ledger, even with --no-evidence
# --------------------------------------------------------------------------------------


def test_a_light_run_writes_the_audit_record_and_the_ledger_without_evidence(registry, store):
    light_module(requests=("/", "/robots.txt"))
    http = target_http("/", "/robots.txt")
    rt = make_runtime(http)
    AuditHook(store, analyst="analyst-1").attach(rt)
    case = Engine(rt, ScanOptions(include={"t_light_audit"}, mode=Opsec.LIGHT, save_evidence=False, purpose="incident 42", ticket="SEC-42")).investigate([SEED])
    assert [r.status.value for r in case.results] == ["ok"]
    case_dir = Path(case.case_dir)
    assert not (case_dir / "evidence").exists() and not (case_dir / ev.EVIDENCE_INDEX).exists()  # --no-evidence
    target_calls = [c for c in http.calls if (urlsplit(c["url"]).hostname or "") not in DOH_HOSTS]
    lines = ledger_lines(case)
    assert len(lines) == len(target_calls) == 2  # every LIGHT request, and nothing else (DoH lookups are third-party)
    first = lines[0]
    assert {k: first[k] for k in ("module", "method", "host", "resolved_ip", "port", "path", "status", "egress_profile", "opsec")} == {
        "module": "t_light_audit", "method": "GET", "host": "example.org", "resolved_ip": TARGET_IP, "port": 443, "path": "/",
        "status": 200, "egress_profile": "default", "opsec": "light",
    }
    assert first["ts"].endswith("+00:00") and first["bytes"] == 5 and lines[1]["path"] == "/robots.txt"
    assert stat.S_IMODE(os.stat(case_dir / audit_mod.LEDGER_FILE).st_mode) == 0o600 and stat.S_IMODE(os.stat(case_dir).st_mode) == 0o700
    rows = audit_rows(store, case.case_id)
    assert [r["kind"] for r in rows] == ["case_start", "case_end"]
    start = rows[0]["payload"]
    assert start["analyst"] == "analyst-1" and start["os_user"] and start["mode"] == "light"
    assert start["purpose"] == "incident 42" and start["ticket"] == "SEC-42" and start["targets"] == ["domain:example.org"]
    assert start["egress"] == {"profile": "default", "ip": "", "checked_at": ""} and start["tlp"] == "amber"
    assert start["licence_profile"] and "org_profile_sha256" in start and start["overrides"] == {}
    end = rows[1]["payload"]
    assert end["request_count"] == 2 and end["targets_touched"] == {"example.org": 2} and end["modules"] == ["t_light_audit"]
    assert end["requests"] == {"ledger_lines": 2, "ledger_head": lines[-1]["hash"]} and end["findings"] == 1


def test_the_ledger_and_the_audit_are_hash_chained_and_mirrored(registry, store):
    light_module(requests=("/", "/a", "/b"))
    rt = make_runtime(target_http("/", "/a", "/b"))
    AuditHook(store).attach(rt)
    case = Engine(rt, ScanOptions(include={"t_light_audit"}, mode=Opsec.LIGHT)).investigate([SEED])
    case_dir = Path(case.case_dir)
    ledger = RequestLedger(case_dir).verify()
    assert ledger.ok and ledger.lines == 3
    lines = ledger_lines(case)
    assert lines[0]["prev_hash"] == ev.CHAIN_GENESIS and [line["seq"] for line in lines] == [1, 2, 3]
    assert all(lines[i]["prev_hash"] == lines[i - 1]["hash"] for i in (1, 2))
    assert store.verify_audit_chain(case.case_id) == []
    mirror = [json.loads(line) for line in (case_dir / audit_mod.AUDIT_MIRROR).read_text(encoding="utf-8").splitlines()]
    assert mirror == audit_rows(store, case.case_id)  # the mirror is the DB chain, byte for byte
    assert stat.S_IMODE(os.stat(case_dir / audit_mod.AUDIT_MIRROR).st_mode) == 0o600
    store.save_case(case.to_dict())
    assert verify_case(store, case.case_id).ok


def test_the_engagement_summary_reaches_the_case_dict(registry, store):
    light_module(requests=("/", "/x"))
    rt = make_runtime(target_http("/", "/x"))
    AuditHook(store).attach(rt)
    (paths.home() / audit_mod.EGRESS_CHECK_FILE).write_text(json.dumps({"default": {"ip": "203.0.113.7", "checked_at": "2026-11-25T08:00:00+00:00"}}))
    case = Engine(rt, ScanOptions(include={"t_light_audit"}, mode=Opsec.LIGHT, egress_override="lab VPN agreed with the owner")).investigate([SEED])
    data = case.to_dict()
    summary = data["engagement"]
    assert summary["mode"] == "light" and summary["targets_touched"] == {"example.org": 2} and summary["request_count"] == 2
    assert summary["egress"] == {"profile": "default", "ip": "203.0.113.7", "checked_at": "2026-11-25T08:00:00+00:00"}
    assert summary["egress_override"] == "lab VPN agreed with the owner" and summary["refusals"] == []
    assert summary["ledger"]["lines"] == 2 and data["meta"]["engagement"] == summary and engagement_of(data) == summary
    store.save_case(data)
    assert store.case_info(case.case_id)["engagement"] is True
    start = audit_rows(store, case.case_id)[0]["payload"]
    assert start["egress_ip"] == "203.0.113.7" and start["overrides"] == {"egress_override": "lab VPN agreed with the owner"}


def test_an_active_case_records_the_authorization_scope_and_window(registry, store, tmp_path):
    from v3lum.core.scope import Scope

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "authorization_ref": "PENTEST-2026-11", "owner": "Example Org security team", "contacts": ["soc@example.org"], "ticket": "SEC-1",
        "window_start": "2026-11-01T00:00:00Z", "window_end": "2026-12-31T23:59:59Z",
        "targets": {"domains": ["example.org"], "cidrs": [], "url_prefixes": []}, "exclusions": {"domains": [], "cidrs": [], "url_prefixes": []},
    }))
    scope = Scope.load(scope_path)

    def run(self, entity, ctx):
        ctx.http.get(f"https://{entity.value}/")
        return self.result(entity)

    define_module("t_active_audit", [T.DOMAIN], run, opsec=Opsec.ACTIVE)
    rt = make_runtime(target_http("/"))
    AuditHook(store).attach(rt)
    opts = ScanOptions(include={"t_active_audit"}, mode=Opsec.ACTIVE, authorized=True, authorization_ref="PENTEST-2026-11", scope=scope)
    case = Engine(rt, opts).investigate([SEED])
    assert [(r.module, r.status.value) for r in case.results] == [("t_active_audit", "empty")]
    start = audit_rows(store, case.case_id)[0]["payload"]
    assert start["authorization_ref"] == "PENTEST-2026-11" and start["scope_sha256"] == scope.sha256 and start["mode"] == "active"
    assert start["window"] == {"start": "2026-11-01T00:00:00+00:00", "end": "2026-12-31T23:59:59+00:00"}
    summary = case.to_dict()["engagement"]
    assert (summary["authorization_ref"], summary["scope_sha256"], summary["request_count"]) == ("PENTEST-2026-11", scope.sha256, 1)
    assert ledger_lines(case)[0]["opsec"] == "active"


def test_a_passive_case_gets_an_audit_record_but_no_ledger_nor_engagement(registry, store):
    define_module("t_passive_audit", [T.DOMAIN], lambda self, e, c: self.result(e))
    rt = make_runtime(FakeHttp())
    AuditHook(store).attach(rt)
    case = Engine(rt, ScanOptions(include={"t_passive_audit"}, tlp="clear")).investigate([SEED])
    assert not (Path(case.case_dir) / audit_mod.LEDGER_FILE).exists()
    data = case.to_dict()
    assert "engagement" not in data and engagement_of(data) is None
    kinds = [r["kind"] for r in audit_rows(store, case.case_id)]
    assert kinds == ["case_start", "tlp_change", "case_end"]  # --tlp below the configured default is recorded
    lowered = audit_rows(store, case.case_id)[1]["payload"]
    assert (lowered["from"], lowered["to"], lowered["phase"]) == ("amber", "clear", "start")
    store.save_case(data)
    assert store.case_info(case.case_id)["engagement"] is False and verify_case(store, case.case_id).ok


def test_without_attach_the_ledger_is_written_from_the_run_logs(registry, store):
    light_module(requests=("/",))
    rt = make_runtime(target_http("/"))
    rt.case_hooks.append(AuditHook(store))  # installed as a plain case hook, no event subscription
    case = Engine(rt, ScanOptions(include={"t_light_audit"}, mode=Opsec.LIGHT, save_evidence=False)).investigate([SEED])
    lines = ledger_lines(case)
    assert len(lines) == 1 and lines[0]["host"] == "example.org" and lines[0]["resolved_ip"] == TARGET_IP


def test_an_audit_record_that_cannot_be_written_aborts_the_scan(registry, store):
    ran: list[str] = []
    define_module("t_never", [T.DOMAIN], lambda self, e, c: ran.append(e.key) or self.result(e), opsec=Opsec.LIGHT)
    rt = make_runtime(target_http("/"))
    AuditHook(store).attach(rt)
    case_id = "20261126-120000-abcd"
    planted = paths.cases_dir() / case_id / audit_mod.LEDGER_FILE
    planted.mkdir(parents=True)  # the ledger cannot be created
    with pytest.raises(OSError):
        Engine(rt, ScanOptions(include={"t_never"}, mode=Opsec.LIGHT)).investigate([SEED], case_id=case_id)
    assert ran == []  # fail closed: no target contact without an audit record and a ledger


def test_a_ledger_that_cannot_be_written_stops_target_contact(registry, store, monkeypatch):
    def broken(self, info):
        raise OSError("disk full")

    sent: list[str] = []

    def run(self, entity, ctx):
        for p in ("/", "/a", "/b"):
            ctx.http.get(f"https://{entity.value}{p}")
            sent.append(p)
        return self.result(entity)

    define_module("t_light_stop", [T.DOMAIN], run, opsec=Opsec.LIGHT)
    rt = make_runtime(target_http("/", "/a", "/b"))
    AuditHook(store).attach(rt)
    monkeypatch.setattr(RequestLedger, "append", broken)
    case = Engine(rt, ScanOptions(include={"t_light_stop"}, mode=Opsec.LIGHT)).investigate([SEED])
    assert sent == ["/"]  # the first answer arrived; nothing else was sent
    assert rt.cancel_event.is_set() and any("request ledger not written" in n for n in case.notes)
    assert case.partial == {"cancelled": True}  # the scan stopped (fail closed, A7)


# --------------------------------------------------------------------------------------
# review additions: policy violations and refusals
# --------------------------------------------------------------------------------------


def test_an_undeclared_host_attempt_writes_a_policy_violation_row(registry, store):
    def run(self, entity, ctx):
        ctx.http.get("https://undeclared.example.net/collect")
        return self.result(entity)

    with test_provider() as prov:
        define_module("t_sneaky", [T.DOMAIN], run, disclosure="third_party", provider=prov.id, sources=source_ids(prov), hosts=prov.hosts, access_model="free_noauth_unlimited")
        http = FakeHttp()
        rt = make_runtime(http)
        AuditHook(store).attach(rt)
        case = Engine(rt, ScanOptions(include={"t_sneaky"})).investigate([SEED])
    assert (case.results[0].status.value, case.results[0].reason_code) == ("skipped", "policy")
    assert http.calls == []  # refused before any send
    rows = [r for r in audit_rows(store, case.case_id) if r["kind"] == "policy_violation"]
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert (payload["module"], payload["host"], payload["violation"], payload["reason_code"]) == ("t_sneaky", "undeclared.example.net", "undeclared_host", "policy")
    assert "not declared" in payload["reason"] and payload["entity_type"] == "domain" and payload["disclosure"] == "third_party"
    end = audit_rows(store, case.case_id)[-1]
    assert end["kind"] == "case_end" and end["payload"]["policy_violations"] == 1


def test_a_disclosure_none_module_reaching_for_the_network_is_a_violation(registry, store):
    def run(self, entity, ctx):
        ctx.http.get("https://api.example.test/x")
        return self.result(entity)

    define_module("t_offline_leak", [T.DOMAIN], run)  # disclosure 'none'
    rt = make_runtime(FakeHttp())
    AuditHook(store).attach(rt)
    case = Engine(rt, ScanOptions(include={"t_offline_leak"})).investigate([SEED])
    rows = [r["payload"] for r in audit_rows(store, case.case_id) if r["kind"] == "policy_violation"]
    assert [(r["module"], r["host"], r["violation"]) for r in rows] == [("t_offline_leak", "", "disclosure")]


def test_out_of_scope_refusals_are_listed_in_the_engagement_summary(registry, store):
    def passive(self, entity, ctx):
        res = self.result(entity)
        if entity.value == "example.org":
            res.pivot(T.DOMAIN, "other.example.net", "related")
        return res

    define_module("t_pivoter", [T.DOMAIN], passive)
    light_module(requests=("/",))
    rt = make_runtime(target_http("/"))
    AuditHook(store).attach(rt)
    case = Engine(rt, ScanOptions(include={"t_pivoter", "t_light_audit"}, mode=Opsec.LIGHT, depth=1)).investigate([SEED])
    refusals = case.to_dict()["engagement"]["refusals"]
    assert {"target": "domain:other.example.net", "module": "t_light_audit"}.items() <= refusals[0].items()
    assert refusals[0]["reason_code"] == "scope" and refusals[0]["reason"]
    assert len(refusals) == 1 and case.to_dict()["engagement"]["targets_touched"] == {"example.org": 1}  # the pivot was never contacted


# --------------------------------------------------------------------------------------
# since last run
# --------------------------------------------------------------------------------------


def test_a_re_collection_reports_new_and_resolved_findings(registry, store):
    findings = {"titles": ["open port 22"]}

    def run(self, entity, ctx):
        res = self.result(entity)
        for title in findings["titles"]:
            res.finding(title, "low", criterion="synthetic")
        return res

    define_module("t_recollect", [T.DOMAIN], run)
    clock = FakeClock("2026-11-26T10:00:00+00:00")
    rt = make_runtime(FakeHttp(), clock=clock)
    AuditHook(store).attach(rt)
    first = Engine(rt, ScanOptions(include={"t_recollect"})).investigate([SEED])
    assert since_last_run_of(first.to_dict()) is None  # a first run has nothing to compare with
    store.save_case(first.to_dict())
    clock.advance(86400)
    findings["titles"] = ["open port 8080", "open port 9090"]
    second = Engine(rt, ScanOptions(include={"t_recollect"})).investigate([SEED])
    since = second.to_dict()["since_last_run"]
    assert (since["previous_case"], since["new"], since["resolved"], since["unchanged"], since["not_rechecked"]) == (first.case_id, 2, 1, 0, 0)
    assert since_last_run_of(second.to_dict()) == since
    end = audit_rows(store, second.case_id)[-1]["payload"]
    assert end["since_last_run"] == since
    # P324 cond 8: the report header shows it (summary.header_lines renders meta.header_notes)
    from v3lum.report.summary import header_lines

    line = f"since last run (case {first.case_id}): 2 new findings, 1 resolved"
    assert audit_mod.since_last_run_line(since) == line
    assert second.to_dict()["meta"]["header_notes"].count(line) == 1
    assert any(line in text for text in header_lines(second.to_dict()))
    assert not any("since last run" in n for n in (first.to_dict().get("meta") or {}).get("header_notes") or [])


def test_since_last_run_line_mentions_findings_that_were_not_rechecked():
    assert audit_mod.since_last_run_line(None) == ""
    line = audit_mod.since_last_run_line({"previous_case": "c1", "new": 1, "resolved": 0, "not_rechecked": 2})
    assert line == "since last run (case c1): 1 new finding, 0 resolved, 2 not re-checked (source did not answer)"


def test_the_stored_case_keeps_the_audit_head_of_its_case_end_row(registry, store):
    light_module()
    rt = make_runtime(target_http("/"))
    AuditHook(store, analyst="analyst-1").attach(rt)
    case = Engine(rt, ScanOptions(include={"t_light_audit"}, mode=Opsec.LIGHT)).investigate([SEED])
    end = audit_rows(store, case.case_id)[-1]
    assert end["kind"] == "case_end"
    anchor = case.to_dict()["meta"][audit_mod.STORED_ANCHOR_KEY]
    assert anchor == {"rows": end["seq"], "head": end["hash"]}
    assert audit_mod.STORED_ANCHOR_KEY not in case.to_dict()  # kept in meta only (not lifted)


def test_a_more_restrictive_earlier_case_is_never_compared(registry, store):
    define_module("t_tlp_cmp", [T.DOMAIN], lambda self, e, c: self.result(e))
    clock = FakeClock("2026-11-26T10:00:00+00:00")
    rt = make_runtime(FakeHttp(), clock=clock)
    AuditHook(store).attach(rt)
    red = Engine(rt, ScanOptions(include={"t_tlp_cmp"}, tlp="red")).investigate([SEED])
    store.save_case(red.to_dict())
    clock.advance(60)
    amber = Engine(rt, ScanOptions(include={"t_tlp_cmp"}, tlp="amber")).investigate([SEED])
    assert "since_last_run" not in amber.to_dict()


def test_findings_whose_source_did_not_answer_are_not_resolved(registry, store):
    state = {"fail": False}

    def run(self, entity, ctx):
        if state["fail"]:
            raise RuntimeError("source down")
        res = self.result(entity)
        res.finding("listed somewhere", "medium", criterion="synthetic")
        return res

    define_module("t_flaky", [T.DOMAIN], run)
    clock = FakeClock("2026-11-26T10:00:00+00:00")
    rt = make_runtime(FakeHttp(), clock=clock)
    AuditHook(store).attach(rt)
    store.save_case(Engine(rt, ScanOptions(include={"t_flaky"})).investigate([SEED]).to_dict())
    clock.advance(60)
    state["fail"] = True
    since = Engine(rt, ScanOptions(include={"t_flaky"})).investigate([SEED]).to_dict()["since_last_run"]
    assert (since["resolved"], since["not_rechecked"]) == (0, 1)  # could not verify is never 'resolved'


# --------------------------------------------------------------------------------------
# CaseAudit, ledger entries, events
# --------------------------------------------------------------------------------------


def test_case_audit_chains_like_the_store_and_mirrors_store_native_rows(store, tmp_path):
    case_id = "20261126-100000-aa11"
    case_dir = tmp_path / case_id
    audit = CaseAudit(store, case_id, case_dir)
    row = audit.append("override", {"finding_id": "f1", "label": "confirmed", "analyst": "a"})
    assert row["seq"] == 1 and row["prev_hash"] == ev.CHAIN_GENESIS and store.verify_audit_chain(case_id) == []
    store.save_case({"case_id": case_id, "created": "2026-11-26T10:00:00+00:00", "seeds": [], "options": {}})
    store.hold(case_id, "litigation", "legal")  # written by the store, without the mirror
    assert audit_mod.mirror_audit(store, case_id, case_dir) == 1
    audit.append("override", {"finding_id": "f2"})
    mirror = [json.loads(line) for line in (case_dir / audit_mod.AUDIT_MIRROR).read_text(encoding="utf-8").splitlines()]
    assert [m["kind"] for m in mirror] == ["override", "hold", "override"] and mirror == store.audit_rows(case_id)
    assert ev.verify_chain(case_dir / audit_mod.AUDIT_MIRROR).ok
    assert CaseAudit(store, "org-profile").append("profile_change", {"sha256": "ab"})["seq"] == 1  # no case directory: DB only


def test_mirroring_is_idempotent_and_never_duplicates_a_row_under_concurrency(store, tmp_path):
    case_id = "20261126-100000-bb22"
    case_dir = tmp_path / case_id
    audit = CaseAudit(store, case_id, case_dir)
    audit.append("override", {"finding_id": "f1"})
    assert audit_mod.mirror_audit(store, case_id, case_dir) == 0  # already mirrored: nothing added
    # a mirror write that failed after its row was committed is caught up, once, by the next writers
    store.append_audit(case_id, "override", {"finding_id": "f2"})
    errors: list[BaseException] = []

    def mirror() -> None:
        try:
            audit_mod.mirror_audit(store, case_id, case_dir)
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=mirror) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    lines = (case_dir / audit_mod.AUDIT_MIRROR).read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["seq"] for line in lines] == [1, 2]
    assert ev.verify_chain(case_dir / audit_mod.AUDIT_MIRROR).ok


def test_audit_payloads_never_hold_a_configured_key(store, tmp_path):
    from v3lum.core import redact

    secret = "AuditKey0123456789abcdef"
    redact.register_secret(secret)
    row = CaseAudit(store, "20261126-100000-bb22", tmp_path / "c").append("case_start", {"purpose": f"check {secret}", "nested": {"url": f"https://x.test/?apikey={secret}"}})
    text = json.dumps(store.audit_rows("20261126-100000-bb22")) + (tmp_path / "c" / audit_mod.AUDIT_MIRROR).read_text()
    assert secret not in text and secret not in json.dumps(row)


def test_the_lifted_case_keys_come_from_the_redacted_case_dict():
    """case.to_dict() redacts SECRET_TYPES values; the top-level engagement copy must not bypass it."""
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLXZhbHVlLXNlY3JldA"

    class Case:
        def __init__(self) -> None:
            self.meta: dict = {}

        def to_dict(self) -> dict:
            return {"meta": json.loads(json.dumps(self.meta).replace(secret, "[redacted]"))}

    case = Case()
    audit_mod._set_case_value(case, "engagement", {"refusals": [{"target": f"jwt:{secret}", "module": "m"}]})
    data = case.to_dict()
    assert secret not in json.dumps(data) and data["engagement"] == data["meta"]["engagement"]
    assert case.meta["engagement"]["refusals"][0]["target"].endswith(secret)  # the live object is untouched


def test_ledger_paths_are_redacted():
    assert ledger_path("/") == "/"
    assert ledger_path("/admin/login.php") == "/admin/login.php"
    assert ledger_path("/users/alice%40corp.example/profile") == "/users/***/profile"
    assert ledger_path("/reset/9f8e7d6c5b4a39281706f5e4d3c2b1a0") == "/reset/***"  # opaque token segment
    assert ledger_path("/search?q=alice&page=2#frag") == "/search?q=***&page=***"
    assert ledger_path("/a?alice@corp.example") == "/a?***=***"


def test_connect_and_exec_records_reach_the_ledger_and_cached_or_passive_ones_never(store, tmp_path):
    hook = AuditHook(store)
    case = {"case_id": "20261126-100000-cc33", "case_dir": str(tmp_path / "c3"), "options": {"mode": "active"}, "seeds": ["domain:example.org"], "tlp": "amber"}
    hook.on_case_start(case)
    infos = [
        RequestInfo(ts="2026-11-26T10:00:00+00:00", method="CONNECT", url="tcp://example.org:22", host="example.org", path="", opsec="active", resolved_ip=TARGET_IP, port=22, module="t_ports"),
        RequestInfo(ts="2026-11-26T10:00:01+00:00", method="EXEC", url="exec://nuclei/example.org", host="example.org", path="", opsec="active", status=0, module="t_nuclei"),
        RequestInfo(ts="2026-11-26T10:00:02+00:00", method="GET", url="https://example.org/", host="example.org", path="/", opsec="active", cached=True),
        RequestInfo(ts="2026-11-26T10:00:03+00:00", method="GET", url="https://api.example.test/", host="api.example.test", path="/", opsec="passive"),
    ]
    for info in infos:
        hook.on_event("http_request", {"info": info})
    hook.on_event("http_request", {"info": infos[0]})  # the same record twice is one line
    hook.on_case_end(case)
    lines = [json.loads(x) for x in (tmp_path / "c3" / audit_mod.LEDGER_FILE).read_text().splitlines()]
    assert [(x["method"], x["port"], x["path"]) for x in lines] == [("CONNECT", 22, ""), ("EXEC", 0, "")]
    assert lines[1]["tool"] == "nuclei" and case["engagement"]["targets_touched"] == {"example.org": 2}
    assert ledger_entry({"method": "GET", "url": "https://example.org/x?token=abc", "opsec": "light"})["path"] == "/x?token=***"


def test_late_records_after_case_end_are_kept_and_flagged(store, tmp_path):
    hook = AuditHook(store)
    case = {"case_id": "20261126-100000-dd44", "case_dir": str(tmp_path / "c4"), "options": {"mode": "light"}, "seeds": ["domain:example.org"], "tlp": "amber"}
    hook.on_case_start(case)
    info = {"ts": "2026-11-26T10:00:00+00:00", "method": "GET", "url": "https://example.org/", "host": "example.org", "opsec": "light", "status": 200}
    hook.on_event("http_request", {"info": info})
    hook.on_case_end(case)
    hook.on_event("http_request", {"info": dict(info, url="https://example.org/late")})  # still in flight at case end
    assert hook.state["late"] == 1 and len(RequestLedger(tmp_path / "c4").entries()) == 2
    store.save_case({"case_id": case["case_id"], "created": "2026-11-26T10:00:00+00:00", "seeds": ["domain:example.org"], "options": {"mode": "light"}})
    report = verify_case(store, case["case_id"], case_dir=tmp_path / "c4")
    assert report.ok and any("after the case_end row" in w for w in report.warnings)


def test_concurrent_requests_keep_one_unbroken_chain(store, tmp_path):
    hook = AuditHook(store)
    case = {"case_id": "20261126-100000-ee55", "case_dir": str(tmp_path / "c5"), "options": {"mode": "light"}, "seeds": [], "tlp": "amber"}
    hook.on_case_start(case)

    def worker(n: int) -> None:
        for i in range(20):
            hook.on_event("http_request", {"info": {"method": "GET", "url": f"https://example.org/{n}/{i}", "host": "example.org", "opsec": "light"}})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    hook.on_case_end(case)
    check = RequestLedger(tmp_path / "c5").verify()
    assert check.ok and check.lines == 120 and case["engagement"]["request_count"] == 120


def test_detach_removes_the_hook_and_its_listener(store):
    rt = make_runtime(FakeHttp())
    hook = AuditHook(store, runtime=rt)
    assert hook in rt.case_hooks and hook.runtime is rt
    hook.attach(rt)
    assert rt.case_hooks.count(hook) == 1
    hook.detach()
    assert hook not in rt.case_hooks and hook.runtime is None
