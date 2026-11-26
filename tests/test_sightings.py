"""Cross-case sightings index (P375, A2, A4, A10; WP16): what is indexed at save time, who may see it.

* the index covers IOC_TYPES; personal identifiers only as the keyed HMAC and only with
  sightings_personal on and a case purpose (never the value, A4);
* TLP leakage (A2): a case sees sightings only from cases with TLP <= its own; higher AMBER/AMBER+STRICT
  cases are counted only (no ids, dates or verdicts); RED and LIGHT/ACTIVE engagement cases never
  surface in a lower-TLP case - acceptance: 'a RED case never appears in a lower-TLP case's sightings';
* noise entities and own org assets are not indexed; purge removes a case's index rows (A10);
* the entity verdict per case follows hostile tags and analyst decisions; the policy guard protocol.
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import sqlite3

import pytest

from tests.fakes import FakeClock, module_fixture
from v3lum.core import hmacid, store as store_mod
from v3lum.core.entities import Entity
from v3lum.core.orgprofile import OrgProfile
from v3lum.core.store import SightingsSummary, Store, entity_verdicts, sighting_rows
from v3lum.core.tlp import TLP

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
DOMAIN = "domain:recurrent-c2.example"
EMAIL = "email:victim@example.com"


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "v3lum.db", settings={"retention_days": 180}, clock=FakeClock(NOW), health=False)
    yield s
    s.close()


def load(name: str) -> dict:
    return copy.deepcopy(module_fixture("case_sightings", name))


def case(case_id: str, *, tlp: str = "amber", mode: str = "passive", entities=(DOMAIN,), findings=(), purpose: str = "", created: str = "2026-11-20T10:00:00+00:00", **extra) -> dict:
    return {
        "schema": "v3lum.case/2",
        "case_id": case_id,
        "created": created,
        "tlp": tlp,
        "seeds": list(entities),
        "options": {"mode": mode, "tlp": tlp, "purpose": purpose},
        "summary": {"risk_score": 0.0, "risk_level": "clean", "findings": len(findings), "entities": len(entities)},
        "entities": [e if isinstance(e, dict) else {"key": e} for e in entities],
        "findings": list(findings),
        "correlations": extra.pop("correlations", []),
        **extra,
    }


def rows(store: Store, case_id: str) -> list[dict]:
    with store.connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM sightings WHERE case_id = ? ORDER BY entity_type, entity_key", (case_id,))]


# --------------------------------------------------------------------------------------
# what is indexed (P375 cond 1-2, A4)
# --------------------------------------------------------------------------------------


def test_save_case_indexes_ioc_types_only_by_default(store):
    sha = "sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    store.save_case(case("c-ioc", entities=(DOMAIN, "ipv4:45.33.32.156", sha, EMAIL, "username:recurring_handle", "cnpj:11222333000181", "text_blob:some pasted text")))
    got = rows(store, "c-ioc")
    assert {r["entity_type"] for r in got} == {"domain", "ipv4", "sha256"}  # IOC_TYPES only (A4 default)
    for r in got:
        assert r["entity_key"] and r["entity_hmac"] == hmacid.hmac_hex(r["entity_type"], r["entity_key"].split(":", 1)[1])
        assert r["case_tlp"] == "amber" and r["engagement"] == 0 and r["created"] == "2026-11-20T10:00:00+00:00"


def test_personal_identifiers_are_indexed_only_as_hmac_with_the_setting_and_a_purpose(tmp_path):
    db = tmp_path / "v3lum.db"
    off = Store(db, settings={"sightings_personal": False}, clock=FakeClock(NOW), health=False)
    off.save_case(case("c-off", entities=(EMAIL,), purpose="incident response"))
    assert rows(off, "c-off") == []  # default off (A4/A8)
    off.close()
    on = Store(db, settings={"sightings_personal": True}, clock=FakeClock(NOW), health=False)
    on.save_case(case("c-nopurpose", entities=(EMAIL,)))
    assert rows(on, "c-nopurpose") == []  # enabled, but the case recorded no purpose
    on.save_case(case("c-purpose", entities=(EMAIL, "phone:+5511987654321"), purpose="incident response INC-7"))
    got = rows(on, "c-purpose")
    assert {r["entity_type"] for r in got} == {"email", "phone"}
    email = next(r for r in got if r["entity_type"] == "email")
    assert email["entity_key"] == "" and email["entity_hmac"] == hmacid.hmac_hex("email", "victim@example.com")
    # equality lookups still work (the query is hashed), from another case at the same TLP
    seen = on.sightings_for(EMAIL, case_id="c-new", case_tlp="amber")
    assert [v["case_id"] for v in seen.visible] == ["c-purpose"]
    assert on.sightings_for("email:other@example.com", case_id="c-new", case_tlp="amber").total == 0
    on.close()
    # the value is in the case JSON only: the sightings table never holds it
    con = sqlite3.connect(db)
    dumped = json.dumps(con.execute("SELECT * FROM sightings").fetchall())
    con.close()
    assert "victim@example.com" not in dumped and "987654321" not in dumped
    # with the setting off again personal lookups answer nothing, whatever the index holds
    again = Store(db, settings={"sightings_personal": False}, clock=FakeClock(NOW), health=False)
    assert again.sightings_for(EMAIL, case_id="c-new", case_tlp="red").total == 0
    again.close()


def test_noise_entities_and_own_assets_are_not_indexed(store):
    entities = (
        {"key": "ipv4:8.8.8.8", "noise": True, "noise_kind": "resolver"},  # public resolver (recorded noise)
        {"key": "domain:sinkhole-test.example", "tags": ["sinkhole"]},  # sinkhole tag
        {"key": "domain:allowed.example", "tags": ["known_good"]},  # allow-listed
        {"key": "domain:www.corp.example", "ownership": "own_asset", "tags": ["own_asset"]},  # recorded own asset
        {"key": "domain:mail.corp-two.example"},  # own asset per the org profile below
        {"key": "ipv4:203.0.113.77"},  # documentation range: computed noise ('private')
        {"key": "ipv4:1.1.1.1"},  # public resolver from the noise lists (nothing recorded on the node)
        {"key": DOMAIN},
    )
    org = OrgProfile.from_dict({"name": "Corp", "domains": [{"name": "corp-two.example", "verification": "txt_verified"}]})
    assert store.index_case(case("c-noise", entities=entities), org=org) == 0  # not stored: no rows (A10)
    assert rows(store, "c-noise") == []
    store.save_case(case("c-noise", entities=entities))
    assert store.index_case(case("c-noise", entities=entities), org=org) == 1
    assert [r["entity_key"] for r in rows(store, "c-noise")] == [DOMAIN]


def test_types_outside_the_index_never_have_sightings(store):
    store.save_case(case("c-1", entities=(DOMAIN,)))
    assert store.sightings_for("cnpj:11222333000181", case_id="x", case_tlp="red") == SightingsSummary()
    assert store.sightings_for("not a key", case_id="x", case_tlp="red") == SightingsSummary()
    assert store.sightings_for(Entity.make("domain", "recurrent-c2.example"), case_id="x", case_tlp="amber").count == 1


# --------------------------------------------------------------------------------------
# TLP leakage (A2) - acceptance: a RED case never appears in a lower-TLP case's sightings
# --------------------------------------------------------------------------------------


@pytest.fixture()
def tlp_store(store):
    for name in ("earlier_case_amber.json", "earlier_case_strict.json", "earlier_case_red.json", "earlier_case_engagement.json"):
        store.save_case(load(name))
    return store


AMBER_ID, STRICT_ID, RED_ID, ENGAGEMENT_ID = "20261120-100000-a1a1", "20261121-090000-b2b2", "20261122-080000-c3c3", "20261123-070000-d4d4"


@pytest.mark.parametrize("viewer", ["clear", "green", "amber", "amber+strict"])
def test_a_red_case_never_surfaces_in_a_lower_tlp_case(tlp_store, viewer):
    summary = tlp_store.sightings_for(DOMAIN, case_id="20261126-120000-new0", case_tlp=viewer)
    assert RED_ID not in {v["case_id"] for v in summary.visible}
    expected_restricted = {"clear": 2, "green": 2, "amber": 1, "amber+strict": 0}[viewer]  # AMBER/AMBER+STRICT only
    assert summary.restricted_count == expected_restricted  # the RED case is not even counted
    blob = json.dumps(summary.to_dict()) + json.dumps(summary.attribute()) + summary.line()
    assert RED_ID not in blob and "2026-11-22" not in blob  # no id or date of the RED case anywhere


def test_a_red_case_sees_every_earlier_case(tlp_store):
    summary = tlp_store.sightings_for(DOMAIN, case_id="20261126-120000-new0", case_tlp="red")
    assert [v["case_id"] for v in summary.visible] == [ENGAGEMENT_ID, RED_ID, STRICT_ID, AMBER_ID]  # newest first
    assert summary.restricted_count == 0 and summary.verdict == "malicious" and summary.last == "2026-11-23"
    assert {v["case_id"]: v["tlp"] for v in summary.visible}[RED_ID] == "red"


def test_higher_amber_cases_are_counted_only(tlp_store):
    green = tlp_store.sightings_for(DOMAIN, case_id="20261126-120000-new0", case_tlp="green")
    assert green.visible == [] and green.restricted_count == 2  # AMBER + AMBER+STRICT; engagement and RED never
    assert green.attribute() == {"count": 0, "last": "", "verdict": "", "restricted": 2, "verdicts": {}}
    assert green.line() == "seen in 2 restricted cases"
    for secret in (AMBER_ID, STRICT_ID, "2026-11-20", "2026-11-21", "malicious", "phishing"):
        assert secret not in json.dumps(green.to_dict()) + green.line()
    amber = tlp_store.sightings_for(DOMAIN, case_id="20261126-120000-new0", case_tlp="amber")
    assert [v["case_id"] for v in amber.visible] == [ENGAGEMENT_ID, AMBER_ID] and amber.restricted_count == 1
    assert amber.visible[1]["verdict"] == "malicious" and amber.visible[0]["verdict"] == ""  # per-case entity verdicts (most severe tag)
    assert amber.line() == "seen in 2 previous cases, last 2026-11-23, verdict: malicious; also in 1 restricted case (higher TLP)"


def test_engagement_cases_never_surface_in_a_lower_tlp_case(store):
    store.save_case(load("earlier_case_engagement.json"))
    for viewer in ("clear", "green"):
        summary = store.sightings_for(DOMAIN, case_id="x", case_tlp=viewer)
        assert summary.visible == [] and summary.restricted_count == 0  # not even counted
    assert [v["case_id"] for v in store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").visible] == [ENGAGEMENT_ID]
    assert rows(store, ENGAGEMENT_ID)[0]["engagement"] == 1


@pytest.mark.parametrize("mode", ["light", "active"])
def test_a_mislabelled_engagement_case_is_indexed_at_least_amber(store, mode):
    # LIGHT/ACTIVE cases are at least AMBER (A2): a stored engagement case labelled CLEAR is
    # indexed at AMBER, so it never surfaces (not even counted) in a CLEAR or GREEN case
    store.save_case(case(f"c-{mode}-clear", tlp="clear", mode=mode))
    assert {r["case_tlp"] for r in rows(store, f"c-{mode}-clear")} == {"amber"}
    for viewer in ("clear", "green"):
        assert store.sightings_for(DOMAIN, case_id="x", case_tlp=viewer).total == 0
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").count == 1
    store.save_case(case("c-passive-clear", tlp="clear"))  # a passive CLEAR case keeps its label
    assert {r["case_tlp"] for r in rows(store, "c-passive-clear")} == {"clear"}


def test_unreadable_tlps_fail_closed(store):
    store.save_case(case("c-amber", tlp="amber"))
    with store.connection() as conn:  # a damaged row: treated as RED
        conn.execute(
            "INSERT INTO sightings (entity_key, entity_hmac, entity_type, case_id, case_tlp, engagement, created, verdict)"
            " VALUES (?, '', 'domain', 'c-damaged', 'not-a-tlp', 0, '2026-11-01T00:00:00+00:00', 'malicious')",
            (DOMAIN,),
        )
    assert {v["case_id"] for v in store.sightings_for(DOMAIN, case_id="x", case_tlp="amber+strict").visible} == {"c-amber"}
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber+strict").restricted_count == 0
    assert "c-damaged" in {v["case_id"] for v in store.sightings_for(DOMAIN, case_id="x", case_tlp="red").visible}
    # a viewer without a readable TLP sees as CLEAR: the AMBER case is counted, never listed
    for viewer in ("", "bogus"):
        summary = store.sightings_for(DOMAIN, case_id="x", case_tlp=viewer)
        assert summary.visible == [] and summary.restricted_count == 1


def test_entity_tlp_above_the_case_tlp_wins(store):
    entities = ({"key": DOMAIN, "tlp": "red"}, {"key": "domain:other.example", "tlp": "green"})
    store.save_case(case("c-mixed", tlp="amber", entities=entities))
    assert {r["entity_key"]: r["case_tlp"] for r in rows(store, "c-mixed")} == {DOMAIN: "red", "domain:other.example": "amber"}
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").total == 0


def test_the_viewing_case_is_never_listed(store):
    store.save_case(case("c-self"))
    assert store.sightings_for(DOMAIN, case_id="c-self", case_tlp="red").total == 0
    assert store.sightings_for(DOMAIN, case_id="c-other", case_tlp="red").count == 1


# --------------------------------------------------------------------------------------
# retention (A10)
# --------------------------------------------------------------------------------------


def test_purge_removes_the_index_rows_immediately(store):
    store.save_case(load("earlier_case_amber.json"))
    assert rows(store, AMBER_ID)
    report = store.purge_case(AMBER_ID, by="test")
    assert report.purged and report.counts["sightings"] == 2  # the domain and the hash (the IP is noise)
    assert rows(store, AMBER_ID) == [] and store.sightings_for(DOMAIN, case_id="x", case_tlp="red").total == 0


# --------------------------------------------------------------------------------------
# verdicts (feed the summary line and the hostile-host guard)
# --------------------------------------------------------------------------------------


def finding(fid, entity, tags, **kw):
    return {"id": fid, "title": f"t {fid}", "severity": "high", "confidence": 0.9, "module": "t_mod", "entity": entity, "tags": list(tags), **kw}


def test_entity_verdicts_follow_hostile_tags_and_analyst_decisions():
    data = case(
        "c-v",
        entities=(DOMAIN, {"key": "domain:b.example", "attributes": {"suspicious": [{"value": True, "source": "t"}]}}, "domain:c.example", "domain:d.example", "domain:e.example"),
        findings=[
            finding("f1", DOMAIN, ["phishing"]),
            finding("f2", DOMAIN, ["c2"]),
            finding("f3", "domain:c.example", ["malicious"], override={"verdict": "false_positive"}),
            finding("f4", "domain:d.example", ["malicious", "context_only"]),
            finding("f5", "domain:e.example", ["malicious"], suppressed_by=[{"rule": "SUP-warninglist", "reason": "on warninglist x"}]),
        ],
        correlations=[{"id": "k1", "rule": "multi_source_malicious", "entities": ["domain:d.example"], "tags": ["malicious"]}],
    )
    assert entity_verdicts(data) == {DOMAIN: "c2", "domain:b.example": "suspicious", "domain:d.example": "malicious"}
    # analyst decisions win: an explicit verdict beats every tag; a 'wrong' vote rejects a finding
    assert entity_verdicts(data, {"f2": {"verdict": "benign"}}, {"f1": "wrong"})[DOMAIN] == "benign"
    assert entity_verdicts(data, {"f3": {"verdict": "malicious"}})["domain:c.example"] == "malicious"
    assert entity_verdicts(data, {}, {"k1": "wrong"}).get("domain:d.example") is None


def test_overrides_and_votes_refresh_the_indexed_verdict(store):
    data = load("earlier_case_amber.json")
    store.save_case(data)
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").verdict == "malicious"  # tags c2 + malicious
    store.vote(data["case_id"], "a1a1f00000000001", analyst="ana", vote="wrong", reason="benign_infra")
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").verdict == ""  # the only hostile finding was rejected
    store.set_override("a1a1f00000000001", analyst="bob", verdict="malicious", note="confirmed in our proxy logs")
    assert store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").verdict == "malicious"  # an analyst verdict wins


def test_case_verdicts_are_shown_with_visible_rows(store):
    store.save_case(load("earlier_case_amber.json"))
    store.record_verdict(AMBER_ID, "partial", "one finding was a homonym", analyst="ana")
    row = store.sightings_for(DOMAIN, case_id="x", case_tlp="amber").visible[0]
    assert row == {"case_id": AMBER_ID, "created": "2026-11-20T10:00:00+00:00", "verdict": "malicious", "tlp": "amber", "case_verdict": "partial"}


def test_policy_guard_reads_hostile_sightings_through_the_protocol(store):
    from v3lum.core import policy

    store.save_case(load("earlier_case_amber.json"))
    store.save_case(load("earlier_case_red.json"))
    run = type("Run", (), {"case_id": "20261126-120000-new0"})()
    entity = Entity.make("domain", "recurrent-c2.example")
    summary = policy._call_sightings(store.sightings_for, entity, run, TLP.GREEN)  # keywords added from the signature
    assert summary.visible == [] and policy._hostile_sighting(summary) == ""  # restricted sightings never block by themselves
    summary = policy._call_sightings(store.sightings_for, entity, run, TLP.AMBER)
    assert policy._hostile_sighting(summary) == "malicious"


# --------------------------------------------------------------------------------------
# robustness and maintenance
# --------------------------------------------------------------------------------------


def test_an_index_failure_never_fails_save_case(store, monkeypatch):
    store.save_case(case("c-keep"))

    def broken(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(store_mod, "sighting_rows", broken)
    store.save_case(case("c-keep", tlp="red"))  # the case is saved; its earlier index rows stay
    assert store.case_info("c-keep")["tlp"] == "red" and len(rows(store, "c-keep")) == 1
    store.save_case(case("c-new"))
    assert store.get_case("c-new") is not None and rows(store, "c-new") == []


def test_reindex_rebuilds_every_case(store):
    store.save_case(case("c-a"))
    store.save_case(case("c-b", created="2026-11-21T10:00:00+00:00"))
    with store.connection() as conn:
        conn.execute("DELETE FROM sightings")
    assert store.reindex_sightings() == 2
    assert store.sightings_for(DOMAIN, case_id="c-c", case_tlp="amber").count == 2


def test_cases_of_a_v1_case_db_are_indexed_when_it_is_upgraded(tmp_path):
    from v3lum.core.migrations import CASES_V1_SCHEMA

    path = tmp_path / "v1.db"
    con = sqlite3.connect(path)
    con.executescript(CASES_V1_SCHEMA)  # a case DB written before the sightings index existed
    for cid, tlp in (("v1-amber", "amber"), ("v1-red", "red")):
        data = case(cid, tlp=tlp)
        con.execute(
            "INSERT INTO cases (id, created, seeds, risk_score, risk_level, findings, entities, data) VALUES (?,?,?,?,?,?,?,?)",
            (cid, data["created"], json.dumps(data["seeds"]), 0.0, "clean", 0, 1, json.dumps(data)),
        )
    con.commit()
    con.close()
    with Store(path, settings={"retention_days": 180}, clock=FakeClock(NOW), health=False) as upgraded:
        assert {r["case_id"] for r in rows(upgraded, "v1-amber") + rows(upgraded, "v1-red")} == {"v1-amber", "v1-red"}
        summary = upgraded.sightings_for(DOMAIN, case_id="new", case_tlp="amber")
        assert [v["case_id"] for v in summary.visible] == ["v1-amber"] and summary.restricted_count == 0  # RED stays hidden
    with Store(path, settings={"retention_days": 180}, clock=FakeClock(NOW), health=False) as again:
        assert again.sightings_for(DOMAIN, case_id="new", case_tlp="red").count == 2  # opened again: no second backfill needed


def test_sighting_rows_is_pure_and_dedupes(monkeypatch):
    data = case("c-pure", entities=(DOMAIN, DOMAIN, "domain:Recurrent-C2.example"))
    got = sighting_rows(data)
    assert len(got) == 1 and got[0][:4] == (DOMAIN, hmacid.hmac_hex("domain", "recurrent-c2.example"), "domain", "c-pure")
    assert sighting_rows({"entities": [{"key": DOMAIN}]}) == []  # no case id, no rows


def test_summary_without_sightings_and_with_restricted_only():
    empty = SightingsSummary()
    assert empty.total == 0 and empty.headline() == "" and empty.attribute()["count"] == 0
    restricted = SightingsSummary(restricted_count=1)
    assert restricted.headline() == "seen in 1 restricted case" and restricted.line() == "seen in 1 restricted case"
    one = SightingsSummary(visible=[{"case_id": "c1", "created": "2026-11-20T10:00:00+00:00", "verdict": "", "tlp": "green", "case_verdict": ""}])
    assert one.headline() == "seen in 1 previous case, last 2026-11-20, verdict: none"


# --------------------------------------------------------------------------------------
# A2: CLEAR/GREEN exports and shareable reports omit cross-case references
# --------------------------------------------------------------------------------------


def cross_case_dict() -> dict:
    """A case dict as the engine writes it after a case_sightings hit and a recurrence."""
    attr = {"value": {"count": 2, "last": "2026-11-23", "verdict": "malicious", "restricted": 1, "verdicts": {"malicious": 1}}, "source": "case_sightings"}
    return case(
        "c-export",
        entities=({"key": DOMAIN, "attributes": {"sightings": [attr], "resolves": [{"value": "x", "source": "t_mod"}]}, "findings": ["f-cs", "f-other"]},),
        findings=(
            {"id": "f-cs", "title": "seen in 2 previous cases, last 2026-11-23, verdict: malicious", "module": "case_sightings", "entity": DOMAIN,
             "severity": "info", "data": dict(attr["value"]), "tags": ["info"]},
            {"id": "f-other", "title": "Listed by a feed", "module": "t_mod", "entity": DOMAIN, "severity": "high", "tags": ["malicious"]},
        ),
        correlations=[
            {"id": "k-rec", "rule": "recurrent_infrastructure", "entities": [DOMAIN], "severity": "medium",
             "description": "recurrent-c2.example (domain) also appears in 2 earlier cases (last 2026-11-23, verdict: malicious)",
             "evidence": ["seen in 2 earlier cases (last 2026-11-23, verdict: malicious)", "f-cs"], "why": "x"},
            {"id": "k-other", "rule": "t_rule", "entities": [DOMAIN], "severity": "low"},
        ],
        risk={"contributors": [{"finding_id": "f-cs"}, {"finding_id": "f-other"}]},
    )


def test_cross_case_references_are_omitted_below_amber():
    from v3lum.correlations.sightings import RULE_ID
    from v3lum.modules.utility.case_sightings import CaseSightings

    assert {RULE_ID} == store_mod.CROSS_CASE_RULES and {CaseSightings.name} == store_mod.CROSS_CASE_MODULES
    assert [store_mod.cross_case_allowed(t) for t in ("clear", "green", "amber", "amber+strict", "red", "", "bogus")] == [False, False, True, True, True, False, False]
    original = cross_case_dict()
    frozen = json.dumps(original, sort_keys=True)
    clean = store_mod.omit_cross_case(original)
    assert json.dumps(original, sort_keys=True) == frozen  # the case itself is never changed
    assert [f["id"] for f in clean["findings"]] == ["f-other"] and [c["id"] for c in clean["correlations"]] == ["k-other"]
    node = clean["entities"][0]
    assert "sightings" not in node["attributes"] and "resolves" in node["attributes"] and node["findings"] == ["f-other"]
    assert clean["risk"]["contributors"] == [{"finding_id": "f-other"}]
    text = json.dumps(clean)
    assert "2026-11-23" not in text and "previous case" not in text and "earlier case" not in text


def test_amber_exports_keep_counts_only():
    kept = store_mod.omit_cross_case(cross_case_dict(), keep_count=True)
    assert kept["entities"][0]["attributes"]["sightings"] == [{"value": {"count": 2, "restricted": 1}, "source": "case_sightings"}]
    finding = next(f for f in kept["findings"] if f["id"] == "f-cs")
    assert finding["title"] == "seen in 2 previous cases" and finding["data"] == {"count": 2, "restricted": 1}
    rec = next(c for c in kept["correlations"] if c["id"] == "k-rec")
    assert rec["description"] == "The same indicator appears in 3 earlier V3LUM cases (count only)." and rec["evidence"] == ["seen in 3 earlier cases"]
    text = json.dumps(kept)
    assert "2026-11-23" not in text and "verdict: malicious" not in text and '"verdicts"' not in text
