"""Breach and infostealer validation pack (P146: CR09-CR12 + the Céos verdict heuristics).

The graph fixtures under tests/fixtures/rules/{corporate_credentials_in_infostealer,
email_in_multiple_password_breaches,generic_or_shared_email_suppression,breach_predates_domain}/ run
through tests/test_rule_fixtures.py, including the named regressions of cond 12 (test@example.com
with 5 generic stealers capped at POSSIBLE, a recent own-domain log CRITICAL, a 2-year-old log HIGH
or MEDIUM). These tests pin one final condition each: suppression first and downgrade only, the A4
breach scope, same-upstream counting, the named heuristics with their verdict drivers, the
first_seen_breach timeline entry, the LGPD wording and metadata-only outputs.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from v3lum.core import correlate, vocab
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import RuleContext, load_graph_fixture, run_rules
from v3lum.core.entities import Entity
from v3lum.core.graph import Graph
from v3lum.core.models import Confidence, Finding, Severity
from v3lum.core.orgprofile import OrgProfile
from v3lum.correlations import breach as br

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "rules"
PACK_RULES = (br.RULE_INFOSTEALER, br.RULE_MULTI_BREACH, br.RULE_GENERIC, br.RULE_PREDATES)
CODES = {br.RULE_INFOSTEALER: "CR09", br.RULE_MULTI_BREACH: "CR10", br.RULE_GENERIC: "CR11", br.RULE_PREDATES: "CR12"}
PROFILE = {
    "org": {"name": "Acme Pagamentos S.A."},
    "domains": [
        {"name": "acmepay.com.br", "verification": "txt_verified"},
        {"name": "acme-seeded.com.br", "verification": "seeded"},
    ],
    "brands": [{"keyword": "acmepay"}],
}
SCOPE_ALL = {"breach_scope": "all", "purpose": "IR-2026-117 phishing triage"}


def ctx(**opts) -> RuleContext:
    return RuleContext(now=NOW, org=OrgProfile.from_dict(PROFILE), options=ScanOptions(**opts))


def ago(days: int) -> str:
    return (NOW - dt.timedelta(days=days)).date().isoformat()


def identity(email: str, *, seed: bool = True, attrs: dict | None = None, created: str | None = None,
             graph: Graph | None = None) -> tuple[Graph, Entity]:
    g = graph or Graph(noise_check=False)
    ent = Entity.make("email", email)
    g.add_node(ent, 0 if seed else 1, seed=seed)
    for name, value in (attrs or {}).items():
        g.add_attributes(ent, {name: value}, _module_for(name))
    if created is not None:
        dom = Entity.make("domain", email.rsplit("@", 1)[1])
        g.add_node(dom, 1)
        g.add_attributes(dom, {"created": created}, "rdap")
    return g, ent


def _module_for(name: str) -> str:
    return {"stealer_logs": "hudson_rock", "infostealer": "hudson_rock", "breach_hit_count": "leakcheck_public"}.get(name, "hibp_account")


def log(days: int, *, corporate: int = 2, family: str = "Lumma") -> dict:
    return {"date_compromised": f"{ago(days)}T08:00:00.000Z", "stealer_family": family, "total_corporate_services": corporate,
            "total_user_services": 7}


def record(name: str, date: str, *, source: str = "hibp.account", verified: bool | None = True, **kw) -> dict:
    out = {"name": name, "date": date, "data_classes": ["Email addresses", "Passwords"], "verified": verified, "source": source}
    out.update(kw)
    return out


def run(g: Graph, *rules: str, rc: RuleContext | None = None):
    return run_rules(g, [], only=set(rules or PACK_RULES), rctx=rc or ctx())


def one(g: Graph, rule_id: str, rc: RuleContext | None = None):
    corrs = run(g, rule_id, rc=rc)
    assert len(corrs) == 1, corrs
    return corrs[0]


# ------------------------------------------------------------------ registration (cond 1)
def test_pack_rules_are_registered_and_replace_the_legacy_rule_by_new_ids():
    correlate.load_rules()
    for rid in PACK_RULES:
        info = correlate.RULES[rid]
        assert info.origin.startswith("v3lum.correlations.breach.") and info.code == CODES[rid]
        assert info.takes_context and not info.legacy and rid not in correlate.RULE_ERRORS
        assert info.criterion and info.attack and info.references and info.false_positives
        assert info.fixtures and all(Path(f).is_file() for f in info.fixtures), rid
    legacy = correlate.RULES.get("breach_and_infostealer")
    assert legacy is None or legacy.legacy  # removed from generic.py by WP22; never a pack rule


def test_named_constants_match_the_final_conditions():
    assert br.STEALER_RECENT_DAYS == 365 and br.STEALER_DECAY_TAU_DAYS == 365
    assert br.MIN_VERIFIED_BREACHES == 3 and br.MIN_CONFIRMING_FAMILIES == 2 and br.RECENT_BREACH_DAYS == 3 * 365
    assert br.LEAKCHECK_SHARED_FOUND == 100 and br.SHARED_STEALER_COMPUTERS == 5
    assert br.THIRD_PARTY_MAX is Severity.MEDIUM and br.GENERIC_MAX is Severity.MEDIUM


# ------------------------------------------------------------------ cond 5: CR09 severities
def test_cr09_recent_own_domain_log_is_critical():
    g, _ = identity("maria.silva@acmepay.com.br", attrs={"stealer_logs": [log(169)], "infostealer": True})
    corr = one(g, br.RULE_INFOSTEALER)
    assert corr.severity is Severity.CRITICAL and corr.label is Confidence.PROBABLE
    assert {"infostealer", "privacy", "credential_exposure", "own_asset"} <= set(corr.tags)
    assert any("decay weight" in e for e in corr.evidence)


@pytest.mark.parametrize(("corporate", "expected"), [(3, Severity.HIGH), (0, Severity.MEDIUM)])
def test_cr09_old_own_domain_logs_are_high_with_corporate_services_else_medium(corporate, expected):
    g, _ = identity("joao.souza@acmepay.com.br", attrs={"stealer_logs": [log(730, corporate=corporate)]})
    corr = one(g, br.RULE_INFOSTEALER)
    assert corr.severity is expected and corr.severity is not Severity.CRITICAL


def test_cr09_critical_needs_a_verified_domain_not_just_a_profile_entry():
    g, _ = identity("ana@acme-seeded.com.br", attrs={"stealer_logs": [log(30)]})
    assert run(g, br.RULE_INFOSTEALER) == []  # seeded, not verified: third party outside the A4 scope
    corr = one(g, br.RULE_INFOSTEALER, ctx(**SCOPE_ALL))
    assert corr.severity is Severity.MEDIUM and {"third_party", "context_only"} <= set(corr.tags)
    assert "credential_exposure" not in corr.tags  # no exposure score for third parties


def test_cr09_domain_level_counts_are_high_never_critical():
    g = Graph(noise_check=False)
    dom = Entity.make("domain", "acmepay.com.br")
    g.add_node(dom, 0, seed=True)
    g.add_attributes(dom, {"stealer_exposure": {"employees": 4, "users": 120}}, "hudson_rock_domain")
    corr = one(g, br.RULE_INFOSTEALER)
    assert corr.severity is Severity.HIGH and "4 employee identities" in corr.description


# ------------------------------------------------------------------ cond 7: the A4 breach scope
@pytest.mark.parametrize(("opts", "seed", "unconfirmed", "evaluated"), [
    ({}, True, False, False),  # default scope 'own'
    ({"breach_scope": "all"}, True, False, False),  # no recorded purpose
    (SCOPE_ALL, False, False, False),  # a pivot, not an analyst-typed seed
    (SCOPE_ALL, True, True, False),  # a seed the analyst did not confirm (extracted from text)
    (SCOPE_ALL, True, False, True),
])
def test_third_parties_only_under_the_breach_scope(opts, seed, unconfirmed, evaluated):
    g, ent = identity("ana.costa@partner-firm.com.br", seed=seed, attrs={"stealer_logs": [log(30)]})
    if unconfirmed:
        opts = {**opts, "unconfirmed_seeds": {ent.key}}
    corrs = run(g, br.RULE_INFOSTEALER, rc=ctx(**opts))
    assert bool(corrs) is evaluated
    for corr in corrs:
        assert corr.severity <= Severity.MEDIUM and "context_only" in corr.tags and "third_party" in corr.tags


def test_in_breach_scope_reports_own_verified_addresses():
    g, ent = identity("maria@acmepay.com.br")
    assert br.in_breach_scope(g.get(ent), ctx()) == (True, True)
    g2, ent2 = identity("maria@gmail.example")
    assert br.in_breach_scope(g2.get(ent2), ctx()) == (False, False)
    assert br.in_breach_scope(g2.get(ent2), ctx(**SCOPE_ALL)) == (True, False)


# ------------------------------------------------------------------ cond 2-3: CR11 suppression first, downgrade only
def test_generic_own_address_is_kept_but_capped_with_a_visible_label():
    g, _ = identity("rh@acmepay.com.br", attrs={"stealer_logs": [log(20)]})
    corr = one(g, br.RULE_INFOSTEALER)  # never deleted
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE
    assert corr.suppressed_by and corr.suppressed_by[0]["rule"] == br.SUPPRESSION_GENERIC
    assert corr.criterion.startswith("POSSIBLE - generic or shared address")
    assert "context_only" in corr.tags and "credential_exposure" not in corr.tags
    [cr11] = run(g, br.RULE_GENERIC)
    assert cr11.severity is Severity.INFO and cr11.label is Confidence.POSSIBLE and "context_only" in cr11.tags


def test_leakcheck_found_100_or_more_marks_a_shared_address():
    recs = [record("SynthForum", ago(200)), record("ShopSynth", ago(400)), record("GameSynth", ago(500))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs, "breach_hit_count": 99})
    assert run(g, br.RULE_GENERIC) == []
    assert one(g, br.RULE_MULTI_BREACH).severity is Severity.HIGH
    g2, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs, "breach_hit_count": 100})
    corr = one(g2, br.RULE_MULTI_BREACH)
    assert corr.label is Confidence.POSSIBLE and corr.severity is Severity.MEDIUM
    assert "100 breach-corpus hits" in one(g2, br.RULE_GENERIC).description


def test_hudson_rock_five_computers_marks_a_shared_identity():
    logs = [log(10 + i, family=f) for i, f in enumerate(("Lumma", "RedLine", "Vidar", "Raccoon"))]
    g, _ = identity("carla@acmepay.com.br", attrs={"stealer_logs": logs})
    assert one(g, br.RULE_INFOSTEALER).severity is Severity.CRITICAL  # 4 computers
    g2, _ = identity("carla@acmepay.com.br", attrs={"stealer_logs": [*logs, log(30, family="StealC")]})
    corr = one(g2, br.RULE_INFOSTEALER)
    assert corr.severity is Severity.MEDIUM and corr.label is Confidence.POSSIBLE
    assert "5 infected computers" in br.generic_reason(g2.get(Entity.make("email", "carla@acmepay.com.br")))


def test_test_example_with_five_generic_stealers_never_reaches_critical():
    fx = load_graph_fixture(FIXTURES / br.RULE_GENERIC / "positive_test_example_five_stealers.json")
    corrs = run_rules(fx.graph, fx.results, only=set(PACK_RULES), rctx=fx.rctx)
    assert corrs and all(c.severity < Severity.CRITICAL for c in corrs)
    assert all(c.label is Confidence.POSSIBLE for c in corrs if c.rule in (br.RULE_INFOSTEALER, br.RULE_GENERIC))
    assert all("context_only" in c.tags for c in corrs)


# ------------------------------------------------------------------ cond 6 + 8: CR10
def test_cr10_three_verified_recent_password_breaches_is_high_for_own_addresses():
    recs = [record("SynthForum", ago(200)), record("ShopSynth", "2021-07"), record("GameSynth", "2019")]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    corr = one(g, br.RULE_MULTI_BREACH)
    assert corr.severity is Severity.HIGH and "3 verified password breaches" in corr.criterion
    assert {"breach", "privacy", "own_asset", "credential_exposure"} <= set(corr.tags)


def test_cr10_needs_one_breach_in_the_last_three_years():
    recs = [record("SynthForum", "2019-02-01"), record("ShopSynth", "2018"), record("GameSynth", "2016-05")]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    assert run(g, br.RULE_MULTI_BREACH) == []


def test_cr10_two_independent_sources_confirm():
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [
        record("SynthForum", ago(300), verified=False), record("ArcadeSynth", ago(700), source="leakcheck.public", verified=None),
    ]})
    corr = one(g, br.RULE_MULTI_BREACH)
    assert "confirmed by 2 independent sources" in corr.criterion and corr.severity is Severity.HIGH


def test_cr10_same_upstream_counts_once():
    # an aggregator re-serving HIBP data (source hibp.account) adds nothing; spelling variants merge
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [
        record("SynthForum", ago(300), verified=False), record("synthforum.example", ago(300)[:7], verified=False),
        record("Shop Synth", ago(500), verified=False), record("ShopSynth", ago(500), verified=False),
    ]})
    assert run(g, br.RULE_MULTI_BREACH) == []
    merged = br.merge_breaches(br.breach_records(g, g.get(Entity.make("email", "pedro@acmepay.com.br"))))
    assert [m.key for m in merged] == ["shopsynth", "synthforum"]
    assert all(len(m.families) == 1 for m in merged)


def test_cr10_fabricated_and_spam_list_breaches_never_count():
    recs = [record("SynthForum", ago(100)), record("ShopSynth", ago(200), fabricated=True),
            record("SpamSynth", ago(300), spam_list=True)]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    assert run(g, br.RULE_MULTI_BREACH) == []
    g2, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [*recs, record("GameSynth", ago(50)),
                                                                        record("ChatSynth", ago(60))]})
    corr = one(g2, br.RULE_MULTI_BREACH)
    not_counted = corr.description.split("Not counted: ", 1)[1]
    assert "ShopSynth" in not_counted and "SpamSynth" in not_counted
    assert "ShopSynth" not in corr.criterion and "SpamSynth" not in corr.criterion
    # an excluded fabricated listing never turns the verdict on the counted breaches into 'false positive'
    assert "false positive" not in corr.why and "spam list" in corr.why


def test_cr10_hint_only_classes_are_not_password_breaches():
    recs = [record(n, ago(100 + i), data_classes=["Email addresses", "Password hints"]) for i, n in enumerate(("A1", "B2", "C3"))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    assert run(g, br.RULE_MULTI_BREACH) == []


def test_cr10_third_party_is_context_only_under_the_scope():
    recs = [record("SynthForum", ago(200)), record("ShopSynth", ago(300)), record("GameSynth", ago(400))]
    g, _ = identity("ana@partner-firm.com.br", attrs={"breach_records": recs})
    assert run(g, br.RULE_MULTI_BREACH) == []
    corr = one(g, br.RULE_MULTI_BREACH, ctx(**SCOPE_ALL))
    assert corr.severity is Severity.MEDIUM and {"third_party", "context_only", "privacy"} <= set(corr.tags)
    assert "credential_exposure" not in corr.tags


# ------------------------------------------------------------------ cond 4: CR12
def test_cr12_is_silent_without_the_rdap_creation_date():
    g, _ = identity("pedro@acmepay.com.br", attrs={"first_seen_breach": "2012-05-01"})
    assert run(g, br.RULE_PREDATES) == []


def test_cr12_breach_before_registration_downgrades_the_breach_correlations():
    recs = [record("OldSynth", "2012-05"), record("SynthForum", ago(200)), record("ShopSynth", ago(300))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs, "first_seen_breach": "2012-05-01"},
                    created="2015-03-10")
    [cr12] = run(g, br.RULE_PREDATES)
    assert cr12.severity is Severity.INFO and "2015-03-10" in cr12.description
    assert "suggested verdict: false positive" in cr12.why
    cr10 = one(g, br.RULE_MULTI_BREACH)
    assert any(s["rule"] == br.SUPPRESSION_PREDATES for s in cr10.suppressed_by)
    assert cr10.label is Confidence.POSSIBLE and cr10.severity is Severity.HIGH  # confidence only, never deleted


def test_cr12_breach_after_registration_is_silent_and_year_dates_use_their_last_day():
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [record("SynthForum", "2015")]}, created="2015-03-10")
    assert run(g, br.RULE_PREDATES) == []  # '2015' may be after 10 March 2015
    g2, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [record("SynthForum", "2014")]}, created="2015-03-10")
    assert len(run(g2, br.RULE_PREDATES)) == 1


# ------------------------------------------------------------------ cond 9: the Céos heuristics, one function each
def merged(*recs: dict) -> list[br.MergedBreach]:
    out = []
    for rec in recs:
        r = br._record(rec, source=str(rec.get("source") or ""), module="test")
        assert r is not None
        out.append(r)
    return br.merge_breaches(out)


def test_is_fabricated_against():
    assert br.is_fabricated_against(merged(record("A", "2020"))) is None
    sig = br.is_fabricated_against(merged(record("A", "2020", IsFabricated=True)))
    assert sig.level == br.AGAINST and "IsFabricated" in sig.criterion


def test_spam_list_alert():
    assert br.spam_list_alert(merged(record("A", "2020"))) is None
    assert br.spam_list_alert(merged(record("Spam", "2020", IsSpamList=True))).level == br.ALERT


def test_compilation_doubt_by_flag_and_by_name():
    assert br.compilation_doubt(merged(record("A", "2020"))) is None
    assert br.compilation_doubt(merged(record("Collection #1", "2019"))).level == br.DOUBT
    assert br.compilation_doubt(merged(record("X", "2019", source="leakcheck.public", compilation=True))).level == br.DOUBT


def test_sources_agree_counts_independent_families():
    assert br.sources_agree(merged(record("A", "2020"), record("B", "2021"))) is None  # one family
    sig = br.sources_agree(merged(record("A", "2020"), record("B", "2021", source="leakcheck.public")))
    assert sig.level == br.OK and "2 independent sources" in sig.criterion


def test_profile_plausible_needs_a_profile_on_the_breached_service():
    items = merged(record("SynthForum", "2020", domain="synthforum.example"))
    g, ent = identity("pedro@acmepay.com.br")
    assert br.profile_plausible(g, g.get(ent), items) is None
    g.add_attributes(ent, {"profiles": [{"platform": "synthforum", "url": "https://synthforum.example/u/pedro"}]}, "profiles")
    sig = br.profile_plausible(g, g.get(ent), items)
    assert sig is not None and sig.level == br.OK and "synthforum.example" in sig.criterion


def test_verified_listing_stealer_alert_generic_alert_and_ownership():
    assert br.verified_listing(merged(record("A", "2020"))).level == br.OK
    assert br.verified_listing(merged(record("A", "2020", verified=False))).level == br.ALERT
    assert br.stealer_alert([]) is None
    assert br.stealer_alert([br.StealerLog("2026-01-01", NOW, "Lumma")]).level == br.ALERT
    assert br.generic_alert("") is None and br.generic_alert("role mailbox").level == br.ALERT
    assert br.ownership_signal(True, False).level == br.OK and br.ownership_signal(False, True).level == br.OK
    assert br.ownership_signal(False, False).level == br.ALERT


def test_domain_after_breach_against():
    created = dt.datetime(2015, 3, 10, tzinfo=dt.timezone.utc)
    assert br.domain_after_breach_against(created, dt.datetime(2016, 1, 1, tzinfo=dt.timezone.utc)) is None
    assert br.domain_after_breach_against(None, dt.datetime(2014, 1, 1, tzinfo=dt.timezone.utc)) is None
    sig = br.domain_after_breach_against(created, dt.datetime(2014, 12, 31, tzinfo=dt.timezone.utc), "Old 2014", "corp.example")
    assert sig.level == br.AGAINST and "corp.example" in sig.criterion


def test_suggest_verdict_positive_false_positive_inconclusive_with_drivers():
    ok_verified = br.Signal("verified_listing", br.OK, "verified breach listing (A)")
    ok_owner = br.Signal("ownership", br.OK, "address on a verified org-profile domain")
    ok_sources = br.Signal("sources_agree", br.OK, "confirmed by 2 independent sources")
    positive = br.suggest_verdict([ok_verified, ok_owner, ok_sources, None])
    assert positive.verdict == "positive" and 2 <= len(positive.drivers) <= 3
    assert positive.drivers[0] == ok_verified.criterion and ok_owner.criterion in positive.drivers
    fabricated = br.Signal("is_fabricated_against", br.AGAINST, "breach flagged fabricated")
    fp = br.suggest_verdict([ok_verified, ok_owner, fabricated])
    assert fp.verdict == "false_positive" and fp.drivers == ("breach flagged fabricated",) and fp.label == "false positive"
    spam = br.Signal("spam_list_alert", br.ALERT, "listed in a spam list")
    inc = br.suggest_verdict([ok_verified, ok_owner, spam])
    assert inc.verdict == "inconclusive" and inc.drivers == ("listed in a spam list",)
    assert br.suggest_verdict([ok_verified]).verdict == "inconclusive"  # no ownership anchor
    assert br.suggest_verdict([]).drivers  # always explains itself


def test_correlations_show_the_suggested_verdict_and_its_criteria():
    recs = [record("SynthForum", ago(200)), record("ShopSynth", ago(300)), record("GameSynth", ago(400))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    corr = one(g, br.RULE_MULTI_BREACH)
    assert corr.why.startswith("suggested verdict: positive (") and "verified breach listing" in corr.why
    assert "Suggested verdict: positive" in corr.description and "a suggestion, the analyst decides" in corr.description


# ------------------------------------------------------------------ cond 10: first_seen_breach on the timeline
def test_first_seen_breach_is_declared_with_a_timeline_label():
    assert vocab.timeline_attributes()["first_seen_breach"] == "first seen in a breach"
    doc = json.loads((Path(vocab.__file__).resolve().parent.parent / "data" / "vocab" / "pack_breach.json").read_text("utf-8"))
    assert "first_seen_breach" in doc["attributes"] and "never scored" in doc["attributes"]["first_seen_breach"]


def test_earliest_breach_reads_every_source():
    g, ent = identity("pedro@acmepay.com.br", attrs={"first_seen_breach": "2016-02-01", "breach_records": [record("Old", "2013-07")]})
    g.add_attributes(ent, {"first_seen_breach": "2014-09-09"}, "xposedornot")
    low, high, label = br.earliest_breach(g.get(ent), br.merge_breaches(br.breach_records(g, g.get(ent))))
    assert low == dt.datetime(2013, 7, 1, tzinfo=dt.timezone.utc) and high.day == 31 and label.startswith("Old")


# ------------------------------------------------------------------ cond 1 + 11: metadata only, LGPD wording, never tested
def test_outputs_carry_metadata_only_and_the_lgpd_notice():
    recs = [record("SynthForum", ago(200), password="hunter2-Secret", hash="5f4dcc3b5aa765d61d8327deb882cf99",
                   password_hint="pet name"),
            record("ShopSynth", ago(300)), record("GameSynth", ago(400))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs, "stealer_logs": [
        {**log(30), "computer_name": "DESKTOP-PEDRO", "ip": "203.0.113.9", "malware_path": "C:\\\\Users\\\\x\\\\a.exe"}]})
    corrs = run(g)
    assert {c.rule for c in corrs} >= {br.RULE_INFOSTEALER, br.RULE_MULTI_BREACH}
    text = json.dumps([c.to_dict() for c in corrs], ensure_ascii=False)
    for leaked in ("hunter2", "5f4dcc3b", "pet name", "DESKTOP-PEDRO", "203.0.113.9", "a.exe"):
        assert leaked not in text
    for corr in corrs:
        assert "privacy" in corr.tags
        assert br.NEVER_TESTED in corr.recommendation
    stealer = next(c for c in corrs if c.rule == br.RULE_INFOSTEALER)
    assert br.LGPD_NOTICE in stealer.description and "LGPD art. 20" in stealer.recommendation


def test_combo_lines_in_source_names_are_scrubbed():
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": [
        record("leak pedro@acmepay.com.br:Senha123! dump", ago(100)), record("ShopSynth", ago(200)), record("GameSynth", ago(300)),
    ]})
    corr = one(g, br.RULE_MULTI_BREACH)
    assert "Senha123" not in json.dumps(corr.to_dict())


def test_sensitive_breach_names_are_withheld():
    recs = [record("AdultSynth", ago(100), sensitive=True), record("ShopSynth", ago(200)), record("GameSynth", ago(300))]
    g, _ = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    corr = one(g, br.RULE_MULTI_BREACH)
    assert "AdultSynth" not in json.dumps(corr.to_dict()) and "sensitive breach (name withheld)" in corr.description


def test_sensitive_breach_service_domain_is_withheld_from_the_plausibility_criterion():
    """profile_plausible names the breached service's domain: for a sensitive breach that would name it (LGPD art. 11)."""
    recs = [record("AdultSynth", ago(100), sensitive=True, domain="adultsynth.example"), record("ShopSynth", ago(200)),
            record("GameSynth", ago(300))]
    g, ent = identity("pedro@acmepay.com.br", attrs={"breach_records": recs})
    g.add_attributes(ent, {"profiles": [{"platform": "adultsynth", "url": "https://adultsynth.example/u/pedro"}]}, "profiles")
    sig = br.profile_plausible(g, g.get(ent), br.merge_breaches(br.breach_records(g, g.get(ent))))
    assert sig is not None and sig.level == br.OK and "name withheld" in sig.criterion
    corr = one(g, br.RULE_MULTI_BREACH)
    dumped = json.dumps(corr.to_dict()).lower()
    assert "adultsynth" not in dumped and "name withheld): plausible" in corr.why


def test_findings_tagged_breach_and_analyst_false_positives():
    ent = Entity.make("email", "pedro@acmepay.com.br")
    g, _ = identity("pedro@acmepay.com.br")
    for i, name in enumerate(("SynthForum", "ShopSynth", "GameSynth")):
        f = Finding(title=f"Breached: {name}", severity=Severity.MEDIUM, criterion="listed", tags=["breach"], entity=ent,
                    module="hibp_account", source="hibp.account",
                    data={"Name": name, "BreachDate": ago(100 + i), "DataClasses": ["Passwords"], "IsVerified": True})
        if i == 2:
            f.override = {"verdict": "false_positive", "by": "analyst"}
        g.add_finding(f)
    assert run(g, br.RULE_MULTI_BREACH) == []  # only two count once the analyst rejected one
