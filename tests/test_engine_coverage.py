"""P328 coverage v2: per-(module, entity) matrix, summary ranking, execution report, answered line,
skip lines, quota deferral, licence rows of aggregators and the P311 manual-link fallback.

Rule 5 throughout: a could-not-verify outcome is never summarised as 'empty'.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, allow_vocab, define_module, make_runtime, source_ids, test_provider
from v3lum.core.context import ScanOptions
from v3lum.core.engine import COVERAGE_RANK, Engine
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import Blocked, QuotaExceeded, RateLimited
from v3lum.core.models import Status

SEED = Entity.make("domain", "example.org")
CHILD = Entity.make("domain", "child.example.org")
MANUAL = "https://lookup.example.test/search?q={q}"


@pytest.fixture()
def registry(clean_registry):
    clean_registry.clear()  # only the synthetic modules of the test are candidates
    with allow_vocab(attributes=("ran",)):
        yield clean_registry


def scan(seeds, *, http=None, rt=None, keys=None, **opts):
    rt = rt or make_runtime(http or FakeHttp(), keys=keys)
    return Engine(rt, ScanOptions(**opts)).investigate(list(seeds))


def answer(self, entity, ctx):
    res = self.result(entity)
    res.attr("ran", True)
    return res


def nothing(self, entity, ctx):
    return self.result(entity)


def pivot_child(self, entity, ctx):
    res = self.result(entity)
    if entity == SEED:
        res.pivot(T.DOMAIN, CHILD.value, "subdomain")
    return res


def _terms(klass: str) -> dict:
    return {"class": klass, "evidence_url": "https://terms.example.test/", "quote": "synthetic terms", "checked_at": "2026-11-26", "reviewer": "tests", "free_plan_business_use": None}


# ------------------------------------------------------------------ the matrix
def test_blocked_on_the_seed_empty_on_a_pivot_summarises_as_blocked(registry):
    def cov(self, entity, ctx):
        if entity == SEED:
            raise Blocked("anti-bot page", 403)
        return self.result(entity)

    define_module("t_piv", [T.DOMAIN], pivot_child)
    define_module("t_cov", [T.DOMAIN], cov)
    case = scan([SEED], include={"t_piv", "t_cov"})
    row = case.coverage["t_cov"]
    assert (row["status"], row["reason_code"]) == ("blocked", "challenge")
    assert row["runs"] == 2 and row["counts"] == {"blocked": 1, "empty": 1}
    assert row["entities"][SEED.key]["status"] == "blocked" and row["entities"][CHILD.key]["status"] == "empty"
    assert row["entities"][CHILD.key]["seed"] == SEED.key
    assert COVERAGE_RANK["blocked"] > COVERAGE_RANK["empty"]


def test_could_not_verify_is_never_summarised_as_empty(registry):
    def limited(self, entity, ctx):
        if entity == SEED:
            raise RateLimited("slow down", 429)
        return self.result(entity)

    define_module("t_piv2", [T.DOMAIN], pivot_child)
    define_module("t_lim", [T.DOMAIN], limited)
    case = scan([SEED], include={"t_piv2", "t_lim"})
    assert case.coverage["t_lim"]["status"] == "rate_limited"
    assert [COVERAGE_RANK[s] for s in ("ok", "quota", "rate_limited", "blocked", "error", "needs_key", "unavailable", "empty", "skipped", "not_run")] == list(range(9, -1, -1))


def test_ok_somewhere_summarises_as_ok_with_the_failures_counted(registry):
    def mixed(self, entity, ctx):
        if entity == SEED:
            return answer(self, entity, ctx)
        raise Blocked("geo", 451, reason_code="geo_block")

    define_module("t_piv3", [T.DOMAIN], pivot_child)
    define_module("t_mixed", [T.DOMAIN], mixed)
    case = scan([SEED], include={"t_piv3", "t_mixed"})
    row = case.coverage["t_mixed"]
    assert (row["status"], row["reason_code"]) == ("ok", "") and row["counts"] == {"ok": 1, "blocked": 1}
    assert row["entities"][CHILD.key]["reason_code"] == "geo_block"


def test_execution_report_rows(registry):
    def partial(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        raise QuotaExceeded("monthly quota used")

    def failing(self, entity, ctx):
        raise RuntimeError("module bug")

    def limited(self, entity, ctx):
        raise RateLimited("slow down", 429)

    define_module("t_x_ok", [T.DOMAIN], answer)
    define_module("t_x_partial", [T.DOMAIN], partial)
    define_module("t_x_fail", [T.DOMAIN], failing)
    define_module("t_x_rate", [T.DOMAIN], limited)
    define_module("t_x_optin", [T.DOMAIN], answer, default_enabled=False)
    case = scan([SEED], categories={"utility"})
    rows = {r["module"]: r for r in case.execution}
    assert {k: rows[k]["outcome"] for k in rows} == {
        "t_x_ok": "completed", "t_x_partial": "partial", "t_x_fail": "failed", "t_x_rate": "rate_limited", "t_x_optin": "skipped",
    }
    assert (rows["t_x_partial"]["partial"], rows["t_x_partial"]["stop_reason"], rows["t_x_partial"]["status"]) == (True, "quota", "ok")
    assert rows["t_x_optin"]["reason_code"] == "not_default" and rows["t_x_optin"]["requests"] == 0
    for row in rows.values():
        assert set(row) == {"module", "entity", "seed", "status", "reason_code", "outcome", "partial", "stop_reason", "requests", "cache_hits", "duration"}
        assert row["entity"] == SEED.key and row["seed"] == SEED.key


def test_skips_are_grouped_by_reason_code(registry):
    with test_provider("t_keyed_prov", keys=("t_cov_key",)) as prov:
        define_module(
            "t_needs_key", [T.DOMAIN], answer, requires_keys=("t_cov_key",), disclosure="third_party", provider=prov.id,
            sources=source_ids(prov), hosts=prov.hosts, access_model="free_auth_limited",
        )
        define_module("t_optin_a", [T.DOMAIN], answer, default_enabled=False)
        define_module("t_optin_b", [T.DOMAIN], answer, default_enabled=False)
        define_module("t_runs", [T.DOMAIN], answer)
        case = scan([SEED], categories={"utility"})
    assert case.skips == {"needs_key": ["t_needs_key"], "not_default": ["t_optin_a", "t_optin_b"]}
    assert case.to_dict()["skips"] == case.skips


# ------------------------------------------------------------------ answered line
def test_answered_line_counts_sources_that_ran_on_the_seed(registry):
    def limited(self, entity, ctx):
        raise RateLimited("slow down", 429)

    def not_applicable(self, entity, ctx):  # applies() False -> SKIPPED, not an applicable source
        return self.result(entity)

    with test_provider("t_feeds", sources=("feed_a", "feed_b")) as prov:
        ids = source_ids(prov)

        def aggregator(self, entity, ctx):
            res = self.result(entity)
            res.attr("ran", True)
            res.source_status(ids[0], Status.OK)
            res.source_status(ids[1], Status.BLOCKED, reason="feed b: challenge page")
            return res

        define_module("t_ans_ok", [T.DOMAIN], answer)
        define_module("t_ans_empty", [T.DOMAIN], nothing)
        define_module("t_ans_rate", [T.DOMAIN], limited)
        skipped = define_module("t_ans_na", [T.DOMAIN], not_applicable)
        skipped.applies = lambda self, entity, ctx: False
        define_module("t_ans_agg", [T.DOMAIN], aggregator, disclosure="third_party", provider=prov.id, sources=ids, hosts=prov.hosts, access_model="free_noauth_unlimited")
        define_module("t_piv4", [T.DOMAIN], pivot_child)
        case = scan([SEED], categories={"utility"})
    line = case.answered[SEED.key]
    assert (line["applicable"], line["answered"], line["could_not_verify"]) == (6, 4, 2)
    feeds = {(s["module"], s["source"]): s["status"] for s in line["sources"]}
    assert feeds[("t_ans_agg", ids[0])] == "ok" and feeds[("t_ans_agg", ids[1])] == "blocked" and feeds[("t_ans_rate", "")] == "rate_limited"
    assert ("t_ans_na", "") not in feeds
    assert set(case.answered) == {SEED.key}  # seeds only; pivots never count


def test_reputation_answered_counts_only_reputation_modules(registry):
    def limited(self, entity, ctx):
        raise RateLimited("slow down", 429)

    define_module("t_rep_ok", [T.DOMAIN], answer, tags=("reputation",))
    define_module("t_rep_rate", [T.DOMAIN], limited, tags=("reputation",))
    define_module("t_plain_ok", [T.DOMAIN], answer)
    case = scan([SEED], categories={"utility"})
    line = case.answered[SEED.key]
    assert (line["reputation_applicable"], line["reputation_answered"]) == (2, 1)
    assert (line["applicable"], line["answered"]) == (3, 2)


# ------------------------------------------------------------------ quota deferral
def test_quota_skips_are_deferred_and_listed(registry):
    def counted(self, entity, ctx):
        ctx.http.get("https://api.example.test/ping")
        return answer(self, entity, ctx)

    with test_provider() as prov:
        define_module(
            "t_daily", [T.DOMAIN], counted, daily_quota=1, disclosure="third_party", provider=prov.id, sources=source_ids(prov),
            hosts=prov.hosts, access_model="free_noauth_limited",
        )
        http = FakeHttp().add("GET", "https://api.example.test/ping", json={"pong": True})
        rt = make_runtime(http)
        first = scan([SEED], rt=rt, include={"t_daily"})
        assert first.results[0].status is Status.OK and first.deferred == []
        second = scan([Entity.make("domain", "example.net")], rt=rt, include={"t_daily"})
    assert not second.results and second.coverage["t_daily"]["status"] == "quota"
    assert second.deferred == [{"module": "t_daily", "entity": "domain:example.net", "reason": second.deferred[0]["reason"]}]
    assert second.to_dict()["deferred"] == second.deferred
    assert next(r for r in second.execution if r["module"] == "t_daily")["outcome"] == "quota"
    book = rt.quota
    if callable(getattr(book, "deferred", None)):  # QuotaBook v2 keeps them for `cases resume`
        stored = book.deferred(second.case_id)
        assert any((getattr(d, "module", None) or d["module"]) == "t_daily" for d in stored)


def test_quota_mid_run_partial_and_quota_status_are_deferred(registry):
    def partial(self, entity, ctx):
        res = self.result(entity)
        res.attr("ran", True)
        raise QuotaExceeded("monthly quota used")

    def exhausted(self, entity, ctx):
        raise QuotaExceeded("daily quota used")

    define_module("t_q_partial", [T.DOMAIN], partial)
    define_module("t_q_status", [T.DOMAIN], exhausted)
    case = scan([SEED], include={"t_q_partial", "t_q_status"})
    assert sorted(d["module"] for d in case.deferred) == ["t_q_partial", "t_q_status"]
    by = {r.module: r for r in case.results}
    assert by["t_q_partial"].partial and by["t_q_partial"].stop_reason == "quota" and by["t_q_status"].status is Status.QUOTA


# ------------------------------------------------------------------ licence rows of aggregators
def test_licence_rows_for_blocked_feeds_merge_with_source_statuses(registry):
    """A1 BR10: under the corporate profile the noncommercial feed of an aggregator is outside
    ctx.allowed_sources; the engine reports it ('licence') next to the module's own per-feed rows."""
    seen: list[frozenset] = []
    sources = {"open_feed": {"terms": _terms("open")}, "nc_feed": {"terms": _terms("noncommercial")}}
    with test_provider("t_agg_prov", sources=sources) as prov:
        ids = source_ids(prov)
        open_id = next(s for s in ids if s.endswith(".open_feed"))
        nc_id = next(s for s in ids if s.endswith(".nc_feed"))

        def aggregator(self, entity, ctx):
            seen.append(ctx.allowed_sources)
            res = self.result(entity)
            res.attr("ran", True)
            res.source_status(open_id, Status.RATE_LIMITED, reason="open feed throttled")
            return res

        define_module(
            "t_agg", [T.DOMAIN], aggregator, disclosure="third_party", provider=prov.id, sources=ids, hosts=prov.hosts,
            terms="noncommercial", access_model="free_noauth_unlimited",
        )
        case = scan([SEED], include={"t_agg"})
    assert seen == [frozenset({open_id})]
    rows = case.coverage["t_agg"]["sources"]
    assert (rows[nc_id]["status"], rows[nc_id]["reason_code"]) == ("skipped", "licence") and "noncommercial" in rows[nc_id]["reason"]
    assert (rows[open_id]["status"], rows[open_id]["reason"]) == ("rate_limited", "open feed throttled")
    assert case.licence_used == {open_id: {"class": "open", "basis": case.licence_used[open_id]["basis"]}}
    assert case.licence_used[open_id]["basis"] == "open"


# ------------------------------------------------------------------ manual-link fallback (P311 cond 9)
def test_manual_link_fallback_for_licence_needs_key_and_blocked(registry):
    def walled(self, entity, ctx):
        raise Blocked("anti-bot page", 403)

    with test_provider("t_nc_prov", terms="noncommercial") as nc, test_provider("t_key_prov", hosts=("keyed.example.test",), keys=("t_ml_key",)) as keyed:
        define_module(
            "t_ml_licence", [T.DOMAIN], answer, disclosure="third_party", provider=nc.id, sources=source_ids(nc), hosts=nc.hosts,
            terms="noncommercial", access_model="free_noauth_unlimited", manual_link=MANUAL,
        )
        define_module(
            "t_ml_key", [T.DOMAIN], answer, requires_keys=("t_ml_key",), disclosure="third_party", provider=keyed.id,
            sources=source_ids(keyed), hosts=keyed.hosts, access_model="free_auth_limited", manual_link=MANUAL,
        )
        define_module("t_ml_blocked", [T.DOMAIN], walled, manual_link=MANUAL)
        define_module("t_ml_plain_ok", [T.DOMAIN], answer, manual_link=MANUAL)
        case = scan([SEED], categories={"utility"})
    manual = [link for link in case.links.get(SEED.key, []) if link.get("manual")]
    notes = sorted((link["module"], link["note"]) for link in manual)
    assert notes == [
        ("t_ml_blocked", "automation skipped: challenge"),
        ("t_ml_key", "automation skipped: needs_key"),
        ("t_ml_licence", "automation skipped: licence"),
    ]
    link = manual[0]
    assert link["url"] == "https://lookup.example.test/search?q=example.org" and link["host"] == "lookup.example.test"
    assert {"label", "url", "host", "note", "manual", "touches_target", "privacy", "badge"} <= set(link)
    stored = case.to_dict()["links"][SEED.key]
    assert sum(1 for item in stored if item.get("manual")) == 3


def test_a_key_refused_at_runtime_also_gets_the_manual_link(registry):
    """P311 cond 9: a configured key the provider refuses (NEEDS_KEY at runtime) leaves the analyst
    the manual link, like a refusal of the gate."""
    from v3lum.core.http import AuthRequired

    def refused(self, entity, ctx):
        raise AuthRequired("HTTP 401: key rejected", 401)

    with test_provider("t_rt_key_prov", keys=("t_rt_key",)) as prov:
        define_module(
            "t_rt_key", [T.DOMAIN], refused, requires_keys=("t_rt_key",), disclosure="third_party", provider=prov.id,
            sources=source_ids(prov), hosts=prov.hosts, access_model="free_auth_limited", manual_link=MANUAL,
        )
        case = scan([SEED], include={"t_rt_key"}, keys={"t_rt_key": "a-key-the-provider-refuses"})
    assert case.results[0].status is Status.NEEDS_KEY
    manual = [link for link in case.links.get(SEED.key, []) if link.get("manual")]
    assert [(m["module"], m["note"]) for m in manual] == [("t_rt_key", "automation skipped: needs_key")]


def test_pack_links_carry_their_metadata_and_privacy_only_for_opted_in_typed_seeds(registry, monkeypatch):
    """Case links keep what the renderers need for P311 cond 5-8 (host, touches_target, privacy,
    badge...); privacy links are asked for only for analyst-typed seeds of a case with
    show_personal and a purpose (cond 6), never for discovered entities."""
    from v3lum.core import links as linklib

    asked: dict[str, bool] = {}

    def fake(entity, *, categories=None, include_privacy=False):
        asked[entity.key] = include_privacy
        return [linklib.RenderedLink(
            ref="t_pack:lookup", label="lookup", url=f"https://lookup.example.test/q/{entity.value}", host="lookup.example.test",
            category="reputation", verified=False, privacy=include_privacy, touches_target=False, antibot=False, tier="unknown",
            badge="unknown operator",
        )]

    monkeypatch.setattr(linklib, "pivot_links_for", fake)

    def mail(self, entity, ctx):
        res = self.result(entity)
        res.pivot(T.EMAIL, "someone.else@example.net", "related")
        return res

    define_module("t_links_mail", [T.EMAIL], mail)
    seed = Entity.make("email", "analyst.typed@example.org")
    case = scan([seed], include={"t_links_mail"}, purpose="phishing triage INC-9", show_personal=True)
    assert asked == {seed.key: True, "email:someone.else@example.net": False}
    item = case.links[seed.key][0]
    assert {k: item[k] for k in ("host", "touches_target", "privacy", "badge", "verified", "ref")} == {
        "host": "lookup.example.test", "touches_target": False, "privacy": True, "badge": "unknown operator", "verified": False, "ref": "t_pack:lookup",
    }
    asked.clear()
    scan([seed], include={"t_links_mail"}, purpose="phishing triage INC-9")  # no opt-in for the case
    assert asked[seed.key] is False
