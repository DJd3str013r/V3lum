"""Analyst overrides (P322 cond 3; WP16): stored by deterministic finding id, always win, survive re-runs.

* ``Store.set_override`` validates, merges per (finding, analyst) and refuses findings no stored case
  holds (an override that no purge could reach would outlive the case, A10);
* ``Store.overrides_for`` merges several analysts in time order into ``Finding.apply_override``
  keyword arguments;
* a re-run of the same module on the same entity gives the same deterministic finding id, and the
  ``OverrideHook`` case hook applies the stored decision before the engine's suppression stage: the
  analyst's label wins over the automatic 'POSSIBLE - on warninglist' downgrade, which is recorded as
  blocked by the analyst.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Confidence, Finding, Opsec, Severity
from v3lum.core.module import Module, register
from v3lum.core.store import OverrideHook, Store, apply_overrides

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)


@pytest.fixture()
def clock():
    return FakeClock(NOW)


@pytest.fixture()
def store(tmp_path, clock):
    s = Store(tmp_path / "v3lum.db", clock=clock, health=False)
    yield s
    s.close()


def stored_case(case_id: str, finding_ids=("f-1",), entity="domain:override.example") -> dict:
    return {
        "schema": "v3lum.case/2",
        "case_id": case_id,
        "created": "2026-11-25T10:00:00+00:00",
        "tlp": "amber",
        "seeds": [entity],
        "options": {"mode": "passive", "tlp": "amber"},
        "summary": {"risk_score": 0.0, "risk_level": "clean", "findings": len(finding_ids), "entities": 1},
        "entities": [{"key": entity}],
        "findings": [{"id": fid, "title": f"finding {fid}", "severity": "high", "module": "t_mod", "entity": entity, "tags": ["malicious"]} for fid in finding_ids],
        "correlations": [],
    }


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def test_set_override_validates_and_needs_a_stored_finding(store):
    store.save_case(stored_case("c-1"))
    with pytest.raises(ValueError, match="stored"):
        store.set_override("f-unknown", analyst="ana", label="possible")
    with pytest.raises(ValueError, match="not a finding of case"):
        store.set_override("f-1", analyst="ana", label="possible", case_id="c-other")
    with pytest.raises(ValueError, match="needs a label"):
        store.set_override("f-1", analyst="ana")
    with pytest.raises(ValueError):
        store.set_override("f-1", analyst="ana", label="certain")
    with pytest.raises(ValueError):
        store.set_override("f-1", analyst="ana", severity="apocalyptic")
    with pytest.raises(ValueError):
        store.set_override("f-1", analyst="ana", verdict="not one word!")
    got = store.set_override("f-1", analyst="ana", label="Confirmed", severity="LOW", verdict="False Positive", note="CDN edge, not the actor", case_id="c-1")
    assert got == {"label": "confirmed", "severity": "low", "verdict": "false_positive", "analyst": "ana", "note": "CDN edge, not the actor", "at": NOW.isoformat(timespec="seconds")}


def test_decisions_merge_per_field_and_the_latest_analyst_wins(store, clock):
    store.save_case(stored_case("c-1", ("f-1", "f-2")))
    store.set_override("f-1", analyst="ana", label="confirmed", note="first look")
    clock.advance(60)
    store.set_override("f-1", analyst="ana", verdict="malicious")  # same analyst: fields left out are kept
    clock.advance(60)
    store.set_override("f-1", analyst="bob", label="probable")  # a later analyst replaces only the label
    merged = store.overrides_for(["f-1", "f-2", "", "f-missing"])
    assert set(merged) == {"f-1"}
    assert merged["f-1"] == {
        "label": "probable", "severity": None, "verdict": "malicious", "analyst": "bob", "note": "first look",
        "at": (NOW + dt.timedelta(seconds=120)).isoformat(timespec="seconds"),
    }
    with store.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM overrides WHERE finding_id = 'f-1'").fetchone()[0] == 2  # one row per analyst


def test_override_notes_are_case_data_purged_with_the_case(store):
    store.save_case(stored_case("c-only", ("f-only",)))
    store.save_case(stored_case("c-a", ("f-shared",)))
    store.save_case(stored_case("c-b", ("f-shared",)))
    store.set_override("f-only", analyst="ana", note="note about the only case")
    store.set_override("f-shared", analyst="ana", label="possible")
    store.purge_case("c-only", by="test")
    store.purge_case("c-a", by="test")
    assert set(store.overrides_for(["f-only", "f-shared"])) == {"f-shared"}  # still held by c-b


def test_apply_overrides_is_idempotent_and_keeps_the_automatic_values():
    entity = Entity.make("domain", "override.example")
    f = Finding("Listed by a feed", Severity.HIGH, confidence=0.9, entity=entity, module="t_mod", criterion="feed verdict")
    decision = {f.ensure_id(): {"label": "possible", "severity": "low", "verdict": "false_positive", "analyst": "ana", "note": "n", "at": "2026-11-26T12:00:00+00:00"}}
    assert apply_overrides([f], decision) == 1
    assert apply_overrides([f], decision) == 1  # applying the same decision again changes nothing
    assert f.label is Confidence.POSSIBLE and f.severity is Severity.LOW and f.override["verdict"] == "false_positive"
    assert f.override["auto"] == {"label": "confirmed", "severity": "high", "criterion": "feed verdict"}
    assert apply_overrides([f], {}) == 0


# --------------------------------------------------------------------------------------
# re-runs: overrides win over automatic labels and survive (P322 cond 3)
# --------------------------------------------------------------------------------------


@pytest.fixture()
def resolver_flagger(clean_registry):
    class ResolverFlagger(Module):
        name = "t_resolver_flagger"
        title = "Synthetic flagger"
        description = "Offline synthetic module: flags any IPv4 as malicious (for the override tests)."
        accepts = {T.IPV4}
        category = "utility"
        terms = "open"
        opsec = Opsec.PASSIVE
        disclosure = "none"
        hosts = ()

        def run(self, entity, ctx):
            res = self.result(entity)
            res.finding("Flagged as malicious", "high", "synthetic verdict", confidence=0.9, criterion="synthetic feed verdict", tags=["malicious"])
            return res

    register(ResolverFlagger)
    return ResolverFlagger


def investigate(store=None):
    rt = make_runtime(FakeHttp())
    if store is not None:
        rt.case_hooks.append(OverrideHook(store))
    return Engine(rt, ScanOptions(include={"t_resolver_flagger"})).investigate([Entity.make("ipv4", "8.8.8.8")])


def only_finding(case):
    found = [f for f in case.findings if f.module == "t_resolver_flagger"]
    assert len(found) == 1
    return found[0]


def test_overrides_win_over_automatic_labels_and_survive_a_rerun(resolver_flagger, store):
    first = investigate()
    auto = only_finding(first)
    # 8.8.8.8 is on a warninglist: the suppression stage downgraded the automatic label
    assert auto.label is Confidence.POSSIBLE and auto.criterion.startswith("POSSIBLE - on warninglist")
    store.save_case(first.to_dict())
    store.set_override(auto.id, analyst="ana", label="confirmed", severity="critical", verdict="malicious", note="seen in our proxy logs", case_id=first.case_id)

    second = investigate(store)  # a new case, the same deterministic finding id
    again = only_finding(second)
    assert second.case_id != first.case_id and again.id == auto.id
    assert again.label is Confidence.CONFIRMED and again.severity is Severity.CRITICAL  # the analyst wins
    assert again.override["analyst"] == "ana" and again.override["verdict"] == "malicious"
    assert again.override["auto"]["severity"] == "high"  # the automatic values stay on record
    assert any(s.get("rule") == "SUP-warninglist" and s.get("blocked_by") == "analyst" for s in again.suppressed_by)
    stored = next(f for f in second.to_dict()["findings"] if f["id"] == auto.id)
    assert stored["confidence_label"] == "confirmed" and stored["override"]["note"] == "seen in our proxy logs"

    third = investigate()  # without the hook the automatic label comes back: the hook is what applies it
    assert only_finding(third).label is Confidence.POSSIBLE


def test_a_failing_lookup_never_breaks_the_scan(resolver_flagger):
    class Broken:
        def overrides_for(self, ids):
            raise RuntimeError("case DB down")

    rt = make_runtime(FakeHttp())
    rt.case_hooks.append(OverrideHook(Broken()))
    case = Engine(rt, ScanOptions(include={"t_resolver_flagger"})).investigate([Entity.make("ipv4", "8.8.8.8")])
    assert only_finding(case).override is None
    assert any("OverrideHook.on_before_finish failed" in n for n in case.notes)
