"""case_sightings (P375, A2, A4, A12): 'seen in N previous cases' from the local case DB.

The module reads the case DB only through ``runtime.meta['sightings_lookup']`` (``Store.sightings_for``,
installed by the App); the fixtures under tests/fixtures/case_sightings/ are synthetic stored cases at
AMBER, AMBER+STRICT, RED and an AMBER LIGHT engagement (documentation values only). End to end, the
``recurrent_infrastructure`` rule fires on an IOC seen in an earlier case and never on a personal
identifier, and the new case never carries the ids, dates or verdicts of other cases.
"""

from __future__ import annotations

import copy
import datetime as dt
import json

import pytest

from tests.fakes import FakeClock, FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.engine import Engine
from v3lum.core.entities import IOC_TYPES, PERSONAL_TYPES, Entity
from v3lum.core.models import Opsec, Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.store import SightingsSummary, Store
from v3lum.modules.utility.case_sightings import CRITERION, FINDING_KEY, LOOKUP_KEY, NO_CASE_DB, CaseSightings, call_lookup

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
DOMAIN = "domain:recurrent-c2.example"
EMAIL = "email:victim@example.com"
NEW_CASE = "20261126-120000-new0"
AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID = "20261120-100000-a1a1", "20261121-090000-b2b2", "20261122-080000-c3c3", "20261123-070000-d4d4"
EARLIER = ("earlier_case_amber.json", "earlier_case_strict.json", "earlier_case_red.json", "earlier_case_engagement.json")


def load(name: str) -> dict:
    return copy.deepcopy(module_fixture("case_sightings", name))


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "v3lum.db", settings={"retention_days": 180}, clock=FakeClock(NOW), health=False)
    for name in EARLIER:
        s.save_case(load(name))
    yield s
    s.close()


def runtime_with(lookup, **kw):
    rt = make_runtime(FakeHttp(), **kw)
    if lookup is not None:
        rt.meta[LOOKUP_KEY] = lookup
    return rt


def run(entity, lookup, *, tlp="amber", **kw):
    settings = kw.pop("settings", None)
    org = kw.pop("org_profile", None)
    return run_module(CaseSightings, entity, runtime=runtime_with(lookup, settings=settings, org_profile=org), tlp=tlp, case_id=NEW_CASE, **kw)


def blob(res) -> str:
    return json.dumps(res.to_dict(), default=str)


# ------------------------------------------------------------------ metadata (offline, disclosure none)
def test_module_metadata():
    assert CaseSightings.name == "case_sightings" and CaseSightings.category == "utility"
    assert CaseSightings.disclosure == "none" and CaseSightings.terms == "open" and tuple(CaseSightings.hosts) == ()
    assert CaseSightings.access_model == "offline" and CaseSightings.default_enabled is True
    assert CaseSightings.opsec == Opsec.PASSIVE
    assert set(IOC_TYPES) | set(PERSONAL_TYPES) <= set(CaseSightings.accepts)


# ------------------------------------------------------------------ no case DB: could not verify
def test_without_the_case_db_lookup_the_module_is_unavailable():
    res = run(DOMAIN, None)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline" and NO_CASE_DB in res.error
    assert res.findings == []


def test_a_failing_lookup_is_could_not_verify_never_absent():
    def broken(entity, *, case_id, case_tlp):
        raise RuntimeError("database is locked")

    res = run(DOMAIN, broken)
    assert res.status is Status.ERROR and "case DB lookup failed" in res.error and res.findings == []
    res = run(DOMAIN, lambda entity: None)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline"


# ------------------------------------------------------------------ the attribute and the one finding (P375 cond 6)
def test_seen_before_gives_the_attribute_and_one_info_finding(store):
    res = run(DOMAIN, store.sightings_for, tlp="amber")
    assert res.status is Status.OK
    assert res.attributes["sightings"] == {"count": 2, "last": "2026-11-23", "verdict": "malicious", "restricted": 1, "verdicts": {"malicious": 1}}
    [finding] = res.findings
    assert finding.title == "seen in 2 previous cases, last 2026-11-23, verdict: malicious"
    assert finding.severity.label == "info" and finding.criterion == CRITERION == "case DB sighting" and finding.key == FINDING_KEY == "sightings"
    assert finding.confidence_label.value == "confirmed" and "1 restricted case" in finding.description
    text = blob(res)
    for other in (AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID):  # no cross-case ids in the result (never copied)
        assert other not in text
    assert "phishing" not in text and "2026-11-21" not in text and "2026-11-22" not in text  # nothing of the higher-TLP cases


def test_never_seen_is_empty_without_a_finding(store):
    res = run("domain:never-seen.example", store.sightings_for)
    assert res.status is Status.EMPTY and res.findings == [] and "sightings" not in res.attributes


# ------------------------------------------------------------------ TLP (A2): the entity TLP filters the lookup
@pytest.mark.parametrize("viewer", ["clear", "green"])
def test_lower_tlp_entities_see_restricted_counts_only(store, viewer):
    res = run(DOMAIN, store.sightings_for, tlp=viewer)
    assert res.attributes["sightings"] == {"count": 0, "last": "", "verdict": "", "restricted": 2, "verdicts": {}}  # AMBER + STRICT only
    assert [f.title for f in res.findings] == ["seen in 2 restricted cases"]
    text = blob(res)
    for secret in (AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID, "2026-11-20", "2026-11-21", "2026-11-22", "2026-11-23", "malicious", "phishing"):
        assert secret not in text  # no ids, dates or verdicts; RED and engagement cases not even counted


def test_a_red_case_never_surfaces_below_red(store):
    for viewer in ("clear", "green", "amber", "amber+strict"):
        res = run(DOMAIN, store.sightings_for, tlp=viewer)
        assert RED_ID not in blob(res) and "2026-11-22" not in blob(res)
    res = run(DOMAIN, store.sightings_for, tlp="red")  # disclosure 'none': allowed at RED, sees every earlier case
    assert res.status is Status.OK and res.attributes["sightings"]["count"] == 4 and res.attributes["sightings"]["restricted"] == 0


def test_the_lookup_gets_the_case_id_and_the_entity_tlp():
    calls: list[tuple] = []

    def lookup(entity, *, case_id, case_tlp):
        calls.append((entity.key, case_id, case_tlp))
        return SightingsSummary()

    run(DOMAIN, lookup, tlp="amber+strict")
    assert calls == [(DOMAIN, NEW_CASE, "amber+strict")]
    # a lookup without the keywords is called with the entity alone (mapping summaries accepted)
    plain = run(DOMAIN, lambda entity: {"visible": [{"case_id": "c1", "created": "2026-11-01T00:00:00+00:00", "verdict": "benign"}], "restricted_count": 0})
    assert plain.attributes["sightings"]["verdict"] == "benign" and plain.findings[0].title == "seen in 1 previous case, last 2026-11-01, verdict: benign"
    assert call_lookup(lambda entity, case_tlp: case_tlp, Entity.make("domain", "a.example"), case_id="x", case_tlp="red") == "red"


# ------------------------------------------------------------------ personal identifiers (A4), noise and own assets
def test_personal_identifiers_need_the_setting_and_a_purpose():
    email = Entity.make("email", "victim@example.com")
    assert not CaseSightings().applies(email, make_ctx(CaseSightings))
    assert not CaseSightings().applies(email, make_ctx(CaseSightings, settings={"sightings_personal": True}))
    assert not CaseSightings().applies(email, make_ctx(CaseSightings, options=ScanOptions(purpose="incident response INC-1")))
    on = make_ctx(CaseSightings, settings={"sightings_personal": True}, options=ScanOptions(purpose="incident response INC-1"))
    assert CaseSightings().applies(email, on)
    assert CaseSightings().applies(Entity.make("domain", "recurrent-c2.example"), make_ctx(CaseSightings))


def test_personal_sightings_match_by_hmac_when_enabled(tmp_path):
    s = Store(tmp_path / "personal.db", settings={"sightings_personal": True}, clock=FakeClock(NOW), health=False)
    s.save_case(load("earlier_case_amber.json"))  # the case recorded a purpose: the e-mail is indexed as its HMAC
    with s.connection() as conn:
        assert "victim@example.com" not in json.dumps([tuple(r) for r in conn.execute("SELECT * FROM sightings")])
    res = run(EMAIL, s.sightings_for, settings={"sightings_personal": True}, options=ScanOptions(purpose="incident response INC-2"))
    assert res.status is Status.OK and res.attributes["sightings"]["count"] == 1
    s.close()


def test_noise_and_own_assets_are_not_looked_up():
    asked: list[str] = []

    def lookup(entity, *, case_id, case_tlp):
        asked.append(entity.key)
        return SightingsSummary()

    org = OrgProfile.from_dict({"name": "Corp", "domains": [{"name": "corp.example", "verification": "txt_verified"}]})
    module = CaseSightings()
    ctx = make_ctx(CaseSightings, runtime=runtime_with(lookup, org_profile=org))
    assert not module.applies(Entity.make("ipv4", "8.8.8.8"), ctx)  # public resolver (noise list)
    assert not module.applies(Entity.make("domain", "mail.corp.example"), ctx)  # own org asset
    assert module.applies(Entity.make("domain", "recurrent-c2.example"), ctx)
    assert not module.applies(Entity.make("cnpj", "11222333000181"), ctx)  # outside IOC_TYPES | PERSONAL_TYPES
    assert asked == []


# ------------------------------------------------------------------ end to end: engine, rule, stored case
def scan(store, seeds, *, tlp="amber", purpose="", settings=None):
    rt = runtime_with(store.sightings_for, settings=settings)
    options = ScanOptions(include={"case_sightings"}, tlp=tlp, threads=1, purpose=purpose)
    return Engine(rt, options).investigate([Entity.make(*s.split(":", 1)) for s in seeds], case_id=NEW_CASE)


def test_recurrent_infrastructure_fires_end_to_end_without_cross_case_references(store):
    case = scan(store, [DOMAIN, "domain:fresh.example"])
    rules = [(c.rule, c.severity.label, [e.key for e in c.entities]) for c in case.correlations if c.rule == "recurrent_infrastructure"]
    assert rules == [("recurrent_infrastructure", "medium", [DOMAIN])]  # 'malicious' in an earlier visible case
    data = case.to_dict()
    store.save_case(data)  # the new case is indexed in turn
    text = json.dumps(store.get_case(NEW_CASE), default=str)
    for other in (AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID, "2026-11-21", "2026-11-22"):
        assert other not in text  # never the ids of other cases, nor anything of the higher-TLP ones
    later = store.sightings_for(DOMAIN, case_id="20261127-090000-next", case_tlp="amber")
    assert NEW_CASE in {v["case_id"] for v in later.visible}


def test_a_lower_tlp_scan_only_counts_and_the_rule_names_no_case(store):
    case = scan(store, [DOMAIN], tlp="green")
    [corr] = [c for c in case.correlations if c.rule == "recurrent_infrastructure"]
    assert corr.severity.label == "low" and "2 restricted cases" in corr.description
    text = json.dumps(case.to_dict(), default=str)
    for secret in (AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID, "2026-11-20", "2026-11-21", "2026-11-22", "2026-11-23", "phishing"):
        assert secret not in text


def test_the_recurrence_rule_never_applies_to_personal_identifiers(tmp_path):
    s = Store(tmp_path / "personal.db", settings={"sightings_personal": True}, clock=FakeClock(NOW), health=False)
    s.save_case(load("earlier_case_amber.json"))
    case = scan(s, [EMAIL], purpose="incident response INC-2", settings={"sightings_personal": True})
    hits = [r for r in case.results if r.module == "case_sightings"]
    assert hits and hits[0].status is Status.OK  # seen before (by HMAC) ...
    assert [c for c in case.correlations if c.rule == "recurrent_infrastructure"] == []  # ... but never 'recurrent'
    s.close()
