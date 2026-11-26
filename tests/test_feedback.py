"""Analyst verdict, idempotent feedback and Beta reliability (P325; WP16), attention points (P325 cond 5).

* ``ui.feedback.ask_feedback``: yes / partial / no paths with fake input; 'yes' stores only the verdict
  (credits no finding) plus explicit 'which were right?' votes; 'no' + Enter marks nothing correct;
  at most 10 items ordered by score contribution, correlations included; one-key reasons;
* acceptance: re-running ``cases feedback`` never double-counts (votes are UPSERTs per case, item and
  analyst; the aggregates move, they never add up);
* ``Store.source_reliability``: Admiralty prior (A 1.0, B 0.85, C 0.7...), prior strength 4, 'partly'
  = 0.5, fewer than 5 votes change nothing, floor 0.3, votes older than 12 months weigh half (exactly
  for votes on record, by month once purged); ``rule_precision`` per correlation rule;
* purge removes the votes and notes but keeps the aggregates (A10); A3 demotion totals;
* ``core.attention``: attention points and limitations are pure functions of the coverage.
"""

from __future__ import annotations

import copy
import datetime as dt
import io
import sqlite3

import pytest
from rich.console import Console

from tests.fakes import FakeClock, test_provider
from v3lum.core import attention, store as store_mod
from v3lum.core.health import HealthState
from v3lum.core.store import (
    MIN_VOTES,
    OLD_VOTE_WEIGHT,
    RELIABILITY_FLOOR,
    REJECT_VERDICTS,
    Store,
    beta_weight,
    bucket_weight,
    vote_weight,
)
from v3lum.ui.feedback import MAX_ITEMS, FeedbackResult, ask_feedback, parse_selection, review_items

NOW = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
NOTE_MARKER = "analyst-note-7f3a"


# --------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------


@pytest.fixture()
def clock():
    return FakeClock(NOW)


@pytest.fixture()
def providers():
    """Three synthetic registry providers with Admiralty grades A, B and C."""
    with test_provider("t_fb_a", hosts=("a.feedback.example.test",), reliability={"grade": "A", "justification": "tests"}), \
            test_provider("t_fb_b", hosts=("b.feedback.example.test",), reliability={"grade": "B", "justification": "tests"}), \
            test_provider("t_fb_c", hosts=("c.feedback.example.test",), reliability={"grade": "C", "justification": "tests"}):
        yield {"A": "t_fb_a.default", "B": "t_fb_b.default", "C": "t_fb_c.default"}


@pytest.fixture()
def store(tmp_path, clock):
    s = Store(tmp_path / "v3lum.db", settings={"retention_days": 180}, clock=clock, health=False)
    yield s
    s.close()


def finding(fid: str, title: str, severity: str, confidence: float, *, source: str = "", module: str = "t_fb_mod", tags=("malicious",), entity="domain:fb.example") -> dict:
    return {"id": fid, "title": title, "severity": severity, "confidence": confidence, "module": module, "source": source, "entity": entity, "tags": list(tags), "criterion": "synthetic"}


def make_case(case_id: str, findings=(), correlations=(), **extra) -> dict:
    return {
        "schema": "v3lum.case/2",
        "case_id": case_id,
        "created": "2026-11-25T10:00:00+00:00",
        "tlp": "amber",
        "seeds": ["domain:fb.example"],
        "options": {"mode": "passive", "tlp": "amber", "purpose": ""},
        "summary": {"risk_score": 40.0, "risk_level": "medium", "findings": len(findings), "entities": 1},
        "entities": [{"key": "domain:fb.example"}],
        "findings": list(findings),
        "correlations": list(correlations),
        **extra,
    }


def scored_case(case_id: str = "20261125-100000-fb01", source: str = "") -> dict:
    """A case with findings of every weight and one correlation (score-contribution order:
    critical 9.0, correlation 4.9, high 4.2, medium 3.6, low 2.0; info and context-only excluded)."""
    return make_case(
        case_id,
        findings=[
            finding("f-low", "Low finding", "low", 1.0, source=source),
            finding("f-high", "High finding", "high", 0.6, source=source),
            finding("f-crit", "Critical finding", "critical", 0.9, source=source),
            finding("f-med", "Medium finding", "medium", 0.9, source=source),
            finding("f-info", "Info finding", "info", 1.0, source=source),
            finding("f-ctx", "Third-party breach context", "high", 0.9, source=source, tags=("breach", "context_only")),
        ],
        correlations=[{"id": "k-1", "rule": "t_rule", "title": "Rule hit", "severity": "high", "confidence": 0.7, "entities": ["domain:fb.example"], "tags": ["malicious"]}],
    )


def answers(*values: str):
    """A fake terminal: returns the next answer for every prompt (and fails on an unexpected one)."""
    queue = list(values)
    asked: list[str] = []

    def ask(prompt: str) -> str:
        asked.append(prompt)
        if not queue:
            raise AssertionError(f"unexpected prompt: {prompt!r}")
        return queue.pop(0)

    ask.asked = asked  # type: ignore[attr-defined]
    ask.left = queue  # type: ignore[attr-defined]
    return ask


def console() -> Console:
    return Console(file=io.StringIO(), width=140, color_system=None)


def table(store: Store, name: str, where: str = "", args=()) -> list[dict]:
    with store.connection() as conn:
        return [dict(r) for r in conn.execute(f"SELECT * FROM {name} {where}", args)]


# --------------------------------------------------------------------------------------
# pure pieces
# --------------------------------------------------------------------------------------


def test_beta_weight_prior_threshold_and_floor():
    assert beta_weight(0.85, 0, 4, 4) == 0.85  # fewer than 5 votes: the prior mean, unchanged
    assert beta_weight(0.85, 0, 5, 5) == pytest.approx(0.85 * 4 / (4 + 5))
    assert beta_weight(0.7, 2.5, 2.5, 5) == pytest.approx((2.8 + 2.5) / (4 + 5))  # 'partly' counts 0.5 each side
    assert beta_weight(1.0, 0, 50, 50) == RELIABILITY_FLOOR  # never below 0.3
    assert beta_weight(0.3, 0, 0, 0) == 0.3 and beta_weight(1.0, 9, 0, 9) == 1.0
    assert MIN_VOTES == 5 and OLD_VOTE_WEIGHT == 0.5


def test_vote_and_bucket_weights_follow_calendar_months():
    now = dt.datetime(2026, 11, 26, 12, 0, tzinfo=dt.timezone.utc)
    assert vote_weight("2025-11-26T12:00:00+00:00", now) == 1.0  # exactly 12 months: not older
    assert vote_weight("2025-11-26T11:59:59+00:00", now) == 0.5
    assert vote_weight("2026-01-01T00:00:00+00:00", now) == 1.0 and vote_weight("not a date", now) == 1.0
    leap = dt.datetime(2028, 2, 29, 12, 0, tzinfo=dt.timezone.utc)
    assert vote_weight("2027-02-28T11:00:00+00:00", leap) == 0.5 and vote_weight("2027-02-28T13:00:00+00:00", leap) == 1.0
    assert bucket_weight("2025-10", now) == 0.5  # every vote of October 2025 is older than 12 months
    assert bucket_weight("2025-11", now) == 1.0  # some November 2025 votes are not: never weighed half early
    assert bucket_weight("2025-12", dt.datetime(2026, 12, 31, tzinfo=dt.timezone.utc)) == 1.0
    assert bucket_weight("2025-12", dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc)) == 0.5
    assert bucket_weight("bogus", now) == 1.0 and bucket_weight("2025-13", now) == 1.0


def test_reject_verdicts_match_the_correlation_evidence_rule():
    from v3lum.correlations.generic import FALSE_POSITIVE_VERDICTS

    assert set(FALSE_POSITIVE_VERDICTS) <= REJECT_VERDICTS


def test_review_items_ordered_by_score_contribution_with_correlations():
    items = review_items(scored_case())
    assert [i["id"] for i in items] == ["f-crit", "k-1", "f-high", "f-med", "f-low"]  # info and context-only excluded
    assert items[1]["kind"] == "correlation" and items[1]["rule"] == "t_rule" and items[1]["module"] == ""
    many = make_case("c-many", findings=[finding(f"f{i:02d}", f"F{i}", "medium", 0.5 + i / 100) for i in range(15)])
    assert len(review_items(many)) == MAX_ITEMS == 10
    assert review_items(many)[0]["id"] == "f14"
    ranked = scored_case()
    ranked["risk"] = {"contributors": [{"finding_id": "f-low", "weight": 0.9}]}  # the risk model's own ranking first
    assert review_items(ranked)[0]["id"] == "f-low"


def test_parse_selection():
    assert parse_selection("1, 3p 5", 5, vote="wrong") == {1: "wrong", 3: "partly", 5: "wrong"}
    assert parse_selection("2-4", 5, vote="right") == {2: "right", 3: "right", 4: "right"}
    assert parse_selection("", 5, vote="wrong") == {} and parse_selection("0, 9, x, 1r", 5, vote="wrong") == {1: "right"}


# --------------------------------------------------------------------------------------
# the loop: yes / partial / no
# --------------------------------------------------------------------------------------


def test_yes_stores_only_the_verdict_and_credits_no_finding(store, providers):
    case = scored_case(source=providers["B"])
    store.save_case(case)
    result = ask_feedback(console(), store, case, analyst="ana", ask=answers("y", "", f"all fine {NOTE_MARKER}"))
    assert result == FeedbackResult(case_id=case["case_id"], verdict="yes", notes=f"all fine {NOTE_MARKER}")
    assert store.feedback_for(case["case_id"]) == [{"verdict": "yes", "notes": f"all fine {NOTE_MARKER}", "created": NOW.isoformat(timespec="seconds"), "analyst": "ana"}]
    assert store.votes_for(case["case_id"]) == []  # no finding credited
    assert store.source_reliability() == {} and store.reliability() == {}


def test_yes_then_which_were_right_records_explicit_positive_votes(store, providers):
    case = scored_case(source=providers["B"])
    store.save_case(case)
    result = ask_feedback(console(), store, case, analyst="ana", ask=answers("y", "1, 3p", ""))
    assert result.right == ["f-crit"] and result.partly == ["f-high"] and result.wrong == []
    votes = {v["finding_id"]: v["vote"] for v in store.votes_for(case["case_id"])}
    assert votes == {"f-crit": "right", "f-high": "partly"}  # only the listed items


def test_partial_lists_wrong_items_with_one_key_reasons(store, providers):
    case = scored_case(source=providers["B"])
    store.save_case(case)
    ask = answers("p", "1,2,4p", "h", "", "the CDN hit is a homonym")
    result = ask_feedback(console(), store, case, analyst="ana", ask=ask)
    assert result.verdict == "partial" and result.wrong == ["f-crit", "k-1"] and result.partly == ["f-med"]
    assert result.reasons == {"f-crit": "homonym"}
    rows = {v["finding_id"]: v for v in store.votes_for(case["case_id"])}
    assert set(rows) == {"f-crit", "k-1", "f-med"}  # f-high and f-low stay unrated (no row)
    assert rows["f-crit"]["reason"] == "homonym" and rows["k-1"]["reason"] is None
    assert rows["k-1"]["rule_id"] == "t_rule" and rows["k-1"]["source_id"] == ""  # correlations are voted per rule
    assert rows["f-crit"]["source_id"] == providers["B"]
    assert sum("reason for #" in p for p in ask.asked) == 2  # one reason question per wrong item, none for 'partly'
    assert store.rule_precision() == {"t_rule": (0.0, 1)}


def test_no_and_enter_marks_nothing_correct(store, providers):
    case = scored_case(source=providers["B"])
    store.save_case(case)
    result = ask_feedback(console(), store, case, analyst="ana", ask=answers("n", "", ""))
    assert result.verdict == "no" and result.right == result.wrong == result.partly == []
    assert store.votes_for(case["case_id"]) == []  # v1 marked all 30 reviewed findings correct here
    assert table(store, "module_stats") == [] and table(store, "source_stats") == []
    assert store.feedback_for(case["case_id"])[0]["verdict"] == "no"


@pytest.mark.parametrize("key", ["s", "", "x"])
def test_skip_stores_nothing(store, key):
    case = scored_case()
    store.save_case(case)
    result = ask_feedback(console(), store, case, analyst="ana", ask=answers(key))
    assert result is not None and result.skipped
    assert store.feedback_for(case["case_id"]) == [] and store.votes_for(case["case_id"]) == []


@pytest.mark.parametrize("error", [KeyboardInterrupt, EOFError])
def test_an_aborted_round_stores_nothing(store, error):
    case = scored_case()
    store.save_case(case)

    def ask(prompt):
        if prompt.startswith("notes"):
            raise error
        return {"did": "n"}.get(prompt[:3], "1")

    assert ask_feedback(console(), store, case, analyst="ana", ask=ask) is None
    assert store.feedback_for(case["case_id"]) == [] and store.votes_for(case["case_id"]) == []


def test_a_vote_that_cannot_be_stored_is_reported_and_the_others_are_kept(store, providers):
    stored = scored_case(source=providers["B"])
    store.save_case(stored)
    shown = copy.deepcopy(stored)  # the dict on screen lists one finding the stored case does not hold
    shown["findings"].append(finding("f-ghost", "Ghost finding", "critical", 1.0, source=providers["B"]))
    out = console()
    result = ask_feedback(out, store, shown, analyst="ana", ask=answers("n", "1,2", "", "", ""))
    assert result.verdict == "no" and result.wrong == ["f-crit"]  # #1 is the ghost (highest contribution)
    assert "vote on #1 not stored" in out.file.getvalue()
    assert {v["finding_id"] for v in store.votes_for(stored["case_id"])} == {"f-crit"}


def test_a_verdict_that_cannot_be_stored_stores_nothing(store):
    case = scored_case()
    store.save_case(case)

    class LockedStore:
        def case_info(self, case_id):
            return {"case_id": case_id}

        def record_verdict(self, *args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        def vote(self, *args, **kwargs):  # pragma: no cover - never reached
            raise AssertionError("no vote after a failed verdict")

    out = console()
    assert ask_feedback(out, LockedStore(), case, analyst="ana", ask=answers("n", "1", "", "")) is None
    assert "feedback not stored: database is locked" in out.file.getvalue()


def test_nothing_is_asked_outside_a_terminal(store):
    case = scored_case()
    store.save_case(case)
    assert ask_feedback(console(), store, case, analyst="ana") is None  # pytest's stdin is not a TTY
    assert ask_feedback(console(), store, {"findings": []}, ask=answers()) is None  # no case id


def test_the_analyst_defaults_to_the_setting(tmp_path, clock):
    s = Store(tmp_path / "v3lum.db", settings={"analyst": "Ana Analyst"}, clock=clock, health=False)
    case = scored_case()
    s.save_case(case)
    ask_feedback(console(), s, case, ask=answers("y", "", ""))
    assert s.feedback_for(case["case_id"])[0]["analyst"] == "Ana Analyst"
    s.close()


# --------------------------------------------------------------------------------------
# acceptance: re-running `cases feedback` never double-counts
# --------------------------------------------------------------------------------------


def test_rerunning_cases_feedback_never_double_counts(store, providers):
    case = scored_case(source=providers["B"])
    store.save_case(case)
    for _ in range(3):
        ask_feedback(console(), store, case, analyst="ana", ask=answers("n", "1,5", "o", "", "same answer"))
    assert len(store.feedback_for(case["case_id"])) == 1  # one verdict per case and analyst
    votes = store.votes_for(case["case_id"])
    assert sorted(v["finding_id"] for v in votes) == ["f-crit", "f-low"]
    buckets = table(store, "source_stats")
    assert [(b["source_id"], b["alpha"], b["beta"], b["votes"]) for b in buckets] == [(f"{providers['B']}@2026-11", 0.0, 2.0, 2)]
    assert table(store, "module_stats") == [{"module": "t_fb_mod", "correct": 0, "wrong": 2}]
    # a changed answer replaces the earlier vote: the aggregate moves, it never adds a third vote
    ask_feedback(console(), store, case, analyst="ana", ask=answers("y", "1", ""))
    assert {v["finding_id"]: v["vote"] for v in store.votes_for(case["case_id"])} == {"f-crit": "right", "f-low": "wrong"}
    assert [(b["alpha"], b["beta"], b["votes"]) for b in table(store, "source_stats")] == [(1.0, 1.0, 2)]
    assert table(store, "module_stats") == [{"module": "t_fb_mod", "correct": 1, "wrong": 1}]
    assert [v["verdict"] for v in store.feedback_for(case["case_id"])] == ["yes"]
    # another analyst adds an own vote and verdict (one per analyst)
    ask_feedback(console(), store, case, analyst="bob", ask=answers("n", "1", "", ""))
    assert len(store.votes_for(case["case_id"])) == 3 and len(store.feedback_for(case["case_id"])) == 2


def test_rerunning_the_cases_feedback_command_never_double_counts(monkeypatch, providers):
    """Acceptance (P325 cond 2) through ``v3lum cases feedback <id>`` on the home case DB: the
    terminal is faked at the keypress/line level (one-key verdict, typed selections)."""
    from rich.console import Console as RichConsole

    from v3lum import paths
    from v3lum.cli import main
    from v3lum.ui import feedback as fb

    case = scored_case("20261126-110000-cli1", source=providers["B"])
    with Store(paths.db_file(), health=False) as home:
        home.save_case(case)
    keys: list[str] = []
    lines: list[str] = []
    monkeypatch.setattr(fb, "_stdin_tty", lambda: True)
    monkeypatch.setattr(fb, "_read_key", lambda console, prompt: keys.pop(0))
    monkeypatch.setattr(RichConsole, "input", lambda self, prompt="", **kw: lines.pop(0))
    for _ in range(2):
        keys[:] = ["n", "o"]  # verdict 'no'; reason 'outdated' for the one wrong item
        lines[:] = ["1", "same answer"]  # item #1 (f-crit) is wrong; notes
        assert main(["cases", "feedback", case["case_id"]]) == 0
        assert keys == [] and lines == []  # every question was asked once
    with Store(paths.db_file(), health=False) as home:
        assert [v["verdict"] for v in home.feedback_for(case["case_id"])] == ["no"]
        votes = home.votes_for(case["case_id"])
        assert [(v["finding_id"], v["vote"], v["reason"]) for v in votes] == [("f-crit", "wrong", "outdated")]
        assert [(b["alpha"], b["beta"], b["votes"]) for b in table(home, "source_stats")] == [(0.0, 1.0, 1)]


def test_store_votes_are_idempotent_upserts(store, providers):
    case = scored_case(source=providers["C"])
    store.save_case(case)
    for _ in range(3):
        store.vote(case["case_id"], "f-crit", analyst="ana", vote="wrong", reason="wrong type")
    assert [(v["vote"], v["reason"]) for v in store.votes_for(case["case_id"])] == [("wrong", "wrong_type")]
    assert table(store, "source_stats")[0]["votes"] == 1
    store.vote(case["case_id"], "f-crit", analyst="ana", vote="partly")
    assert [(b["alpha"], b["beta"], b["votes"]) for b in table(store, "source_stats")] == [(0.5, 0.5, 1)]
    with pytest.raises(ValueError, match="right, wrong or partly"):
        store.vote(case["case_id"], "f-crit", analyst="ana", vote="maybe")
    with pytest.raises(ValueError, match="reason"):
        store.vote(case["case_id"], "f-crit", analyst="ana", vote="wrong", reason="because")
    with pytest.raises(ValueError, match="only"):
        store.vote(case["case_id"], "f-crit", analyst="ana", vote="right", reason="homonym")
    with pytest.raises(ValueError, match="not a finding or correlation"):
        store.vote(case["case_id"], "f-nope", analyst="ana", vote="wrong")
    with pytest.raises(ValueError, match="unknown case"):
        store.vote("c-missing", "f-crit", analyst="ana", vote="wrong")
    with pytest.raises(ValueError, match="yes, partial or no"):
        store.record_verdict(case["case_id"], "maybe", analyst="ana")
    with pytest.raises(ValueError, match="unknown case"):
        store.record_verdict("c-missing", "yes", analyst="ana")


def test_v1_flag_finding_is_idempotent_now(store):
    case = scored_case()
    store.save_case(case)
    for _ in range(3):
        store.flag_finding(case["case_id"], "f-crit", "t_legacy", correct=False)
    assert table(store, "module_stats") == [{"module": "t_legacy", "correct": 0, "wrong": 1}]
    assert len(table(store, "finding_feedback")) == 1 and store.reliability()["t_legacy"] == pytest.approx(2 / 3)


# --------------------------------------------------------------------------------------
# Beta reliability per source (P325 cond 3)
# --------------------------------------------------------------------------------------


def vote_n(store, case_id, ids, vote="wrong"):
    for fid in ids:
        store.vote(case_id, fid, analyst="ana", vote=vote)


def many_case(case_id, source, n=12, module="t_fb_mod"):
    return make_case(case_id, findings=[finding(f"{case_id}-{i}", f"F{i}", "high", 0.9, source=source, module=module) for i in range(n)])


def test_fewer_than_five_votes_change_nothing(store, providers):
    case = many_case("c-five", providers["B"])
    store.save_case(case)
    ids = [f["id"] for f in case["findings"]]
    vote_n(store, "c-five", ids[:4])
    assert store.source_reliability() == {providers["B"]: 0.85}  # the Admiralty prior (B) unchanged
    vote_n(store, "c-five", ids[4:5])
    assert store.source_reliability()[providers["B"]] == pytest.approx(round(0.85 * 4 / 9, 4))
    stats = store.source_stats()
    assert stats[0]["grade"] == "B" and stats[0]["votes"] == 5 and stats[0]["active"] is True


def test_the_weight_never_falls_below_the_floor(store, providers):
    case = many_case("c-floor", providers["A"], n=20)
    store.save_case(case)
    vote_n(store, "c-floor", [f["id"] for f in case["findings"]])
    assert store.source_reliability()[providers["A"]] == RELIABILITY_FLOOR  # 4 / (4 + 20) = 0.17 -> 0.3


def test_partly_counts_half_and_unknown_providers_use_grade_f(store, providers):
    case = make_case("c-mix", findings=[finding(f"m{i}", f"M{i}", "high", 0.9, source=providers["C"]) for i in range(5)] + [finding(f"u{i}", f"U{i}", "high", 0.9, source="t_unregistered.feed") for i in range(5)])
    store.save_case(case)
    vote_n(store, "c-mix", [f"m{i}" for i in range(5)], vote="partly")
    vote_n(store, "c-mix", [f"u{i}" for i in range(5)], vote="right")
    rel = store.source_reliability()
    assert rel[providers["C"]] == pytest.approx(round((0.7 * 4 + 2.5) / (4 + 5), 4))
    assert rel["t_unregistered.feed"] == pytest.approx(round((0.5 * 4 + 5) / 9, 4))  # unknown provider: prior 0.5 (F)


def test_votes_older_than_twelve_months_weigh_half(store, providers, clock):
    case = many_case("c-age", providers["C"])
    store.save_case(case)
    clock.now_value = clock.now()  # noqa - keep the fake clock explicit in this test
    old_clock = FakeClock(dt.datetime(2025, 9, 15, 12, 0, tzinfo=dt.timezone.utc))
    store.clock = old_clock
    vote_n(store, "c-age", [f["id"] for f in case["findings"][:5]])  # 5 wrong votes cast on 2025-09-15
    store.clock = clock
    young = store.source_reliability(now=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc))
    old = store.source_reliability(now=NOW)
    assert young[providers["C"]] == pytest.approx(round(2.8 / (4 + 5), 4))  # full weight within 12 months
    assert old[providers["C"]] == pytest.approx(round(2.8 / (4 + 5 * 0.5), 4))  # half weight after
    # exact for votes on record: one day past the 12 months is enough
    assert store.source_reliability(now=dt.datetime(2026, 9, 15, 12, 0, 1, tzinfo=dt.timezone.utc))[providers["C"]] == pytest.approx(round(2.8 / 6.5, 4))
    # and the purged votes keep aging through their monthly buckets
    store.purge_case("c-age", by="test")
    assert table(store, "finding_votes") == []
    assert store.source_reliability(now=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)) == young
    assert store.source_reliability(now=NOW) == old


def test_rule_precision_per_correlation_rule(store):
    corrs = [{"id": f"k{i}", "rule": "t_rule", "title": "R", "severity": "medium", "confidence": 0.7, "entities": ["domain:fb.example"], "tags": []} for i in range(4)]
    case = make_case("c-rule", correlations=corrs)
    store.save_case(case)
    store.vote("c-rule", "k0", analyst="ana", vote="right")
    store.vote("c-rule", "k1", analyst="ana", vote="wrong")
    store.vote("c-rule", "k2", analyst="ana", vote="partly")
    store.vote("c-rule", "k3", analyst="ana", vote="wrong")
    assert store.rule_precision() == {"t_rule": (0.375, 4)}
    summary = store.feedback_summary()
    assert summary["rules"] == [{"rule_id": "t_rule", "precision": 0.375, "votes": 4}]
    assert set(summary) >= {"verdicts", "modules", "sources", "rules"}


# --------------------------------------------------------------------------------------
# A10: purge removes votes and notes, keeps the aggregates
# --------------------------------------------------------------------------------------


def test_purge_removes_votes_and_notes_but_keeps_aggregates(store, providers):
    case = many_case("20261125-100000-fb99", providers["B"], n=6)
    case["correlations"] = [{"id": "k-p", "rule": "t_rule", "title": "R", "severity": "high", "confidence": 0.7, "entities": ["domain:fb.example"], "tags": []}]
    store.save_case(case)
    vote_n(store, case["case_id"], [f["id"] for f in case["findings"]])
    store.vote(case["case_id"], "k-p", analyst="ana", vote="right")
    store.record_verdict(case["case_id"], "no", f"wrong all along {NOTE_MARKER}", analyst="ana")
    before = (store.source_reliability(), store.rule_precision(), store.reliability())
    report = store.purge_case(case["case_id"], by="test")
    assert report.purged and report.counts["finding_votes"] == 7 and report.counts["feedback"] == 1
    assert table(store, "finding_votes") == [] and table(store, "feedback") == []
    assert (store.source_reliability(), store.rule_precision(), store.reliability()) == before  # aggregates survive
    for name in ("source_stats", "rule_stats", "module_stats"):  # value-free: no case id, analyst or finding id
        blob = repr(table(store, name))
        assert case["case_id"] not in blob and "ana" not in blob and "fb99-" not in blob
    con = sqlite3.connect(store.path)
    assert NOTE_MARKER.encode() not in b"".join(str(r).encode() for r in con.execute("SELECT * FROM sqlite_master"))
    con.close()
    with open(store.path, "rb") as fh:
        assert NOTE_MARKER.encode() not in fh.read()  # secure delete + VACUUM: the note is gone from the file


# --------------------------------------------------------------------------------------
# A3 demotion totals (HealthState.record_votes)
# --------------------------------------------------------------------------------------


def test_module_vote_totals_feed_the_a3_demotion(tmp_path, clock):
    health = HealthState(tmp_path / "health.json")
    s = Store(tmp_path / "v3lum.db", clock=clock, health=health)
    case = many_case("c-a3", "", n=10, module="t_noisy")
    s.save_case(case)
    ids = [f["id"] for f in case["findings"]]
    vote_n(s, "c-a3", ids[:4], vote="wrong")
    vote_n(s, "c-a3", ids[4:9], vote="right")
    assert not health.is_demoted("t_noisy")  # 9 votes: below the 10-vote minimum
    s.vote("c-a3", ids[9], analyst="ana", vote="partly")
    assert health.stats("t_noisy")["votes"]["total"] == 10 and health.stats("t_noisy")["votes"]["wrong"] == 4
    assert health.is_demoted("t_noisy")  # 4.5 / 10 wrong > 30%
    s.vote("c-a3", ids[0], analyst="ana", vote="right")  # a re-vote replaces: 3.5 wrong out of 10
    assert health.stats("t_noisy")["votes"] == {"wrong": 3, "total": 10, "at": NOW.isoformat(timespec="seconds")}
    s.close()


def test_stores_outside_the_home_never_write_the_home_health_file(tmp_path, clock, isolated_home):
    s = Store(tmp_path / "elsewhere.db", clock=clock)
    case = many_case("c-x", "", n=1, module="t_mod_x")
    s.save_case(case)
    s.vote("c-x", case["findings"][0]["id"], analyst="ana", vote="wrong")
    assert not (isolated_home / "health.json").exists()
    s.close()


# --------------------------------------------------------------------------------------
# attention points and limitations (P325 cond 5): pure functions of the coverage
# --------------------------------------------------------------------------------------


def coverage_case() -> dict:
    def cov(title, rows, sources=None):
        return {"title": title, "status": "ok", "entities": {f"domain:e{i}.example": r for i, r in enumerate(rows)}, "sources": sources or {}}

    return {
        "case_id": "20261126-120000-at01",
        "tlp": "amber",
        "partial": {"deadline": True},
        "deferred": [{"module": "t_quota", "entity": "domain:e0.example", "reason": "quota"}],
        "coverage": {
            "t_blocked": cov("Blocked Source", [{"status": "blocked", "reason_code": "challenge"}]),
            "t_quota": cov("Quota Source", [{"status": "quota", "reason_code": "quota"}]),
            "t_key": cov("Keyed Source", [{"status": "needs_key", "reason_code": "needs_key"}]),
            "t_licence": cov("Licensed Source", [{"status": "skipped", "reason_code": "licence"}]),
            "t_tlp": cov("Leaky Source", [{"status": "skipped", "reason_code": "tlp"}]),
            "t_policy": cov("Policy Source", [{"status": "skipped", "reason_code": "policy"}]),
            "t_timeout": cov("Slow Source", [{"status": "error", "reason_code": "timeout"}]),
            "t_late": cov("Late Source", [{"status": "skipped", "reason_code": "deadline"}]),
            "t_ok": cov("Fine Source", [{"status": "ok", "reason_code": ""}, {"status": "empty", "reason_code": ""}]),
            "t_optin": cov("Opt-in Source", [{"status": "skipped", "reason_code": "not_default"}]),
            "t_agg": cov("Aggregator", [{"status": "ok", "reason_code": ""}], {"feeds.one": {"status": "rate_limited", "reason_code": "rate_limited"}}),
        },
        "answered": {"domain:e0.example": {"reputation_applicable": 3, "reputation_answered": 1}},
        "entities": [{"key": "domain:e0.example", "attributes": {"sightings": [{"value": {"count": 2, "restricted": 0}, "source": "case_sightings"}]}}],
        "pending_personal": [{"entity": "email:#123456789abc"}],
    }


def test_limitations_list_what_could_not_be_verified():
    lines = attention.limitations(coverage_case())
    assert lines == [
        "could not verify: Blocked Source (blocked: anti-bot challenge)",
        "could not verify: Quota Source (quota used up)",
        "could not verify: Aggregator: feeds.one (rate limited)",
        "could not verify: Keyed Source (API key needed)",
        "could not verify: Licensed Source (licence profile)",
        "could not verify: Leaky Source (TLP)",
        "could not verify: Policy Source (policy)",
        "could not verify: Slow Source (timeout)",
        "could not verify: Late Source (scan deadline)",
        "the scan deadline ended the run: results are partial (sources still pending are listed as 'scan deadline')",
        "a source that could not answer is no evidence of absence: what it would have shown is unknown",
    ]
    assert attention.limitations({"coverage": {"t_ok": {"title": "Fine", "status": "ok", "entities": {}}}}) == []
    assert attention.limitations(coverage_case()) == lines  # pure and deterministic


def test_attention_points_are_suggestions_and_the_verdict_prevails():
    points = attention.attention_points(coverage_case(), verdict="partial")
    assert points[0] == "analyst verdict: partial - it prevails over the suggestions below"
    joined = "\n".join(points)
    for expected in (
        "consider configuring API keys for Keyed Source (v3lum keys setup)",
        "consider resuming 1 deferred lookup once the provider quota resets (Quota Source): v3lum cases resume 20261126-120000-at01",
        "consider checking Blocked Source by hand (manual pivot links): automated access was blocked",
        "consider reviewing the licence profile (Licensed Source): v3lum doctor --licences",
        "Leaky Source may not receive values at TLP:AMBER",
        "see `v3lum info <module>` for why Policy Source were skipped by policy",
        "consider a longer --timeout or a re-run: Late Source, Slow Source did not finish",
        "consider more reputation sources: 1 seed had fewer than 2 answering (inconclusive)",
        "consider reviewing earlier cases: 1 entity appeared in previous cases (case-DB sightings)",
        "1 personal identifier await your selection",
    ):
        assert expected in joined, expected
    assert "Opt-in Source" not in joined and "Fine Source" not in joined
    assert attention.attention_points({}) == [] and attention.SUGGESTION_NOTE.startswith("suggestions only")


def test_partial_runs_and_feeds_are_listed_once_with_their_reason():
    def cov(title, rows, sources=None):
        return {"title": title, "status": "ok", "entities": {f"ipv4:192.0.2.{i}": r for i, r in enumerate(rows)}, "sources": sources or {}}

    case = {
        "case_id": "20261126-120000-at02",
        "coverage": {
            # the module row and its feed row carry the same code: the module is named once
            "t_lic": cov("Licensed Feeds", [{"status": "skipped", "reason_code": "licence"}],
                         {"lic.one": {"status": "skipped", "reason_code": "licence"}}),
            # partial runs answered, but not completely: 'partially verified', never absent
            "t_capped": cov("Capped Source", [{"status": "ok", "partial": True, "stop_reason": "request_cap"}]),
            "t_budget": cov("Budget Source", [{"status": "empty", "partial": True, "stop_reason": "quota"}]),
            "t_whole": cov("Whole Source", [{"status": "ok", "partial": False, "stop_reason": ""}]),
            "t_down": cov("Down Source", [{"status": "unavailable", "reason_code": "offline"}]),
        },
    }
    lines = attention.limitations(case)
    assert lines == [
        "could not verify: Licensed Feeds (licence profile)",
        "could not verify: Down Source (offline)",
        "partially verified: Budget Source (quota used up)",
        "partially verified: Capped Source (request cap reached)",
        "a source that could not answer is no evidence of absence: what it would have shown is unknown",
    ]
    assert attention.partially_verified(case) == {"quota": ["Budget Source"], "request_cap": ["Capped Source"]}
    points = "\n".join(attention.attention_points(case))
    assert "consider resuming the lookups once the provider quota resets (Budget Source)" in points
    assert "consider a longer --timeout or a re-run: Capped Source did not finish" in points
    assert "consider re-running later (or without --offline): Down Source were unavailable" in points
    assert "--debug" not in points  # an unavailable source did not fail
    assert "Whole Source" not in "\n".join(lines) + points


def test_many_names_are_capped_per_line():
    rows = {f"t_{i}": {"title": f"Source {i:02d}", "status": "blocked", "reason_code": "geo_block", "entities": {}} for i in range(9)}
    line = attention.limitations({"coverage": rows})[0]
    assert line == "could not verify: Source 00, Source 01, Source 02, Source 03, Source 04, Source 05 +3 more (blocked: geo restriction)"


def test_store_module_reexports_stay_consistent():
    assert set(store_mod.VOTE_SCORES) == {"right", "wrong", "partly"} and store_mod.VOTE_SCORES["partly"] == 0.5


def test_a_case_that_was_not_stored_is_not_asked(store):
    out = console()
    assert ask_feedback(out, store, scored_case("20261125-100000-nosave"), analyst="ana", ask=answers()) is None
    assert "not in the case DB" in out.file.getvalue() and store.feedback_for("20261125-100000-nosave") == []
