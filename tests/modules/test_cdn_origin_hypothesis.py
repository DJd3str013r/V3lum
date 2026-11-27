"""Batch p3-G13-1 - P278 cdn_origin_hypothesis.

The rule lives in v3lum/correlations/p3_g13_1.py and the opt-in module in
v3lum/modules/pentest_recon/cdn_origin_hypothesis.py. Synthetic graph fixtures only (FC6):
tests/fixtures/rules/cdn_origin_hypothesis/ (strong, own-asset strong, medium, weak, hostile, quota; CDN/cloud-only,
not fronted, not opted in, malformed). Documentation addresses throughout; the CDN edges carry the labels the
cloud_ranges module and the AR06 noise lists put on real edges.
"""

from __future__ import annotations

import ast
import datetime as dt
import socket
from pathlib import Path
from typing import Any

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.core import correlate
from v3lum.core.context import ScanOptions
from v3lum.core.correlate import RuleContext
from v3lum.core.graph import Graph
from v3lum.core.lint import blocking, lint_module_source
from v3lum.core.models import Status
from v3lum.correlations import p3_g13_1 as rules
from v3lum.modules.pentest_recon import cdn_origin_hypothesis as modfile
from v3lum.modules.pentest_recon.cdn_origin_hypothesis import CdnOriginHypothesis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rules" / rules.RULE_ORIGIN
NOW = dt.datetime(2026, 11, 26, 12, tzinfo=dt.timezone.utc)
AS_OF = NOW.date()


def label_map(mapping: dict[str, str]) -> Any:
    def labeller(ip: str) -> dict[str, Any] | None:
        kind = mapping.get(ip)
        return {"kind": kind, "provider": "Cloudflare" if kind == "cdn" else "AWS", "label": f"{kind} test range"} if kind else None
    return labeller


# ------------------------------------------------------------------ registration, fixtures, opt-in
def test_rule_registered_with_fixtures() -> None:
    correlate.load_rules()
    info = correlate.RULES[rules.RULE_ORIGIN]
    assert info.takes_context and not info.legacy and rules.RULE_ORIGIN not in correlate.RULE_ERRORS
    files = sorted(FIXTURES.glob("*.json"))
    assert any(f.name.startswith("positive_") for f in files) and any(f.name.startswith("negative_") for f in files)


@pytest.mark.parametrize("path", sorted(FIXTURES.glob("*.json")), ids=lambda p: p.stem)
def test_graph_fixtures(path: Path) -> None:
    assert correlate.check_fixture(rules.RULE_ORIGIN, path) == []


def _strong() -> correlate.GraphFixture:
    return correlate.load_graph_fixture(FIXTURES / "positive_strong_cert_history_favicon.json")


def test_opt_in_only_via_deep_preset_all_modules_or_dash_m() -> None:
    fx = _strong()
    for options, results in [(ScanOptions(), []), (ScanOptions(preset="quick", include={"securitytrails"}), [])]:
        rctx = RuleContext(now=NOW, options=options)
        assert rules.cdn_origin_hypothesis(fx.graph, results, rctx) == []
    for options in (ScanOptions(preset="deep"), ScanOptions(include_disabled=True), ScanOptions(include={"cdn_origin_hypothesis"})):
        assert len(rules.cdn_origin_hypothesis(fx.graph, [], RuleContext(now=NOW, options=options))) == 1
    ran = run_module(CdnOriginHypothesis, "domain:example.com", FakeHttp())
    assert len(rules.cdn_origin_hypothesis(fx.graph, [ran], RuleContext(now=NOW, options=ScanOptions()))) == 1


def test_output_is_a_non_expanding_labelled_hypothesis() -> None:
    fx = _strong()
    corr = correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx)[0]
    assert corr.title == "Possible origin (hypothesis) behind a CDN"
    assert "possible origin (hypothesis)" in corr.description and "never connected" in corr.description
    assert {"origin_candidate", "hypothesis"} <= set(corr.tags)
    assert corr.entity_keys() == ["domain:example.com", "ipv4:203.0.113.7"]
    assert "score 0.72 (strong)" in corr.why and corr.label.value == "probable"
    assert corr.attack == ["T1590"]
    # FC4: a correlation never schedules a pivot or touches the graph
    before = (len(fx.graph.nodes), len(fx.graph.edges))
    correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx)
    assert (len(fx.graph.nodes), len(fx.graph.edges)) == before


# ------------------------------------------------------------------ FC1: facts only, no network
def test_sources_have_no_network_client_and_pass_the_p327_lint() -> None:
    for path, profiles in ((Path(rules.__file__), ("code", "module")), (Path(modfile.__file__), ("module",))):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        imported |= {alias.name for n in ast.walk(tree) if isinstance(n, ast.Import) for alias in n.names}
        forbidden = {"socket", "ssl", "http", "urllib", "urllib.request", "requests", "httpx", "subprocess", "v3lum.core.http",
                     "v3lum.core.net", "v3lum.core.dns", "v3lum.core.context"}
        assert not imported & forbidden, (path.name, imported & forbidden)
        for profile in profiles:
            assert blocking(lint_module_source(path, profile=profile)) == [], (path.name, profile)


def test_rule_and_module_make_zero_network_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append(repr(args)[:80])
        raise AssertionError("cdn_origin_hypothesis must not touch the network")

    monkeypatch.setattr(socket.socket, "connect", spy)
    monkeypatch.setattr(socket, "create_connection", spy)
    monkeypatch.setattr(socket, "getaddrinfo", spy)
    total = 0
    for path in sorted(FIXTURES.glob("positive_*.json")):
        fx = correlate.load_graph_fixture(path)
        total += len(correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx))
    http = FakeHttp()
    res = run_module(CdnOriginHypothesis, "domain:example.com", http)
    assert total >= 7 and calls == [] and http.urls() == []
    assert res.status is Status.OK and res.hosts == {}


def test_module_metadata_and_manual_links() -> None:
    cls = CdnOriginHypothesis
    assert cls.default_enabled is False and cls.disclosure == "none" and cls.hosts == () and cls.terms == "open"
    assert cls.trust_tier == "n/a" and cls.run_on == "seeds" and cls.access_model == "offline"
    res = run_module(cls, "domain:www.example.com", FakeHttp())
    urls = [u for _l, u in res.links]
    assert urls == ["https://viewdns.info/iphistory/?domain=www.example.com",
                    "https://securitytrails.com/domain/www.example.com/history/a"]
    assert modfile.manual_links("com") == [] and modfile.manual_links("") == []


# ------------------------------------------------------------------ FC1 adapters (P006 / P015 shapes)
def test_history_adapters_read_every_shape() -> None:
    p006 = [{"ip": "203.0.113.7", "first_seen": "2019-05-10", "last_seen": "2024-02-28", "organizations": []}]
    assert rules.history_records(p006, "securitytrails")[0] == {"ip": "203.0.113.7", "first_seen": dt.date(2019, 5, 10),
                                                                 "last_seen": dt.date(2024, 2, 28), "source": "securitytrails"}
    raw_st = {"records": [{"first_seen": "2020-01-01", "last_seen": "2021-01-01", "values": [{"ip": "203.0.113.1"}, {"ip": "203.0.113.2"}]}]}
    assert [r["ip"] for r in rules.history_records(raw_st)] == ["203.0.113.1", "203.0.113.2"]  # every value, not values[0]
    pdns = [{"hostname": "example.net", "address": "203.0.113.5", "record_type": "A", "first_seen": "2021-06-01T00:00:00Z",
             "last_seen": "2025-09-30T00:00:00Z"},
            {"hostname": "www.example.net", "address": "203.0.113.6", "record_type": "A"},
            {"hostname": "example.net", "address": "mail.example.net", "record_type": "CNAME"}]
    assert [r["ip"] for r in rules.history_records(pdns, "passive_dns", name="example.net")] == ["203.0.113.5"]
    cof = [{"rrtype": "A", "rrname": "example.org", "rdata": "198.51.100.9", "time_first": 1577836800, "time_last": 1609459200}]
    assert rules.history_records(cof)[0]["first_seen"] == dt.date(2020, 1, 1)
    mnemonic = [{"rrtype": "a", "answer": "2001:db8::5", "firstSeenTimestamp": 1577836800000, "lastSeenTimestamp": 1609459200000}]
    assert rules.history_records(mnemonic)[0]["ip"] == "2001:db8::5"
    for junk in (None, "x", 5, [None, "x", {"ip": None}, {"values": "x"}], {"records": "x"}):
        assert rules.history_records(junk) == []


# ------------------------------------------------------------------ FC2 exclusions, no fallback
def _facts(**extra: Any) -> dict[str, Any]:
    base = {"seed": "example.com", "current_a": ["198.51.100.10"],
            "history_a": [{"ip": "198.51.100.10", "first_seen": "2024-03-01", "last_seen": "2026-11-25"},
                          {"ip": "203.0.113.200", "first_seen": "2018-01-01", "last_seen": "2019-12-31"}],
            "site": {}, "ip_observations": []}
    base.update(extra)
    return base


def test_cdn_and_cloud_ranges_are_excluded_by_default() -> None:
    labeller = label_map({"198.51.100.10": "cdn", "203.0.113.200": "cloud"})
    result = rules.origin_hypotheses(_facts(), labeller, as_of=AS_OF)
    assert result["applicable"] and result["candidates"] == []
    assert result["excluded"] == [{"ip": "203.0.113.200", "why": "cloud range: cloud test range"}]
    # the architect's alternative reading (P034 FC6: rented compute is not noise) keeps the IaaS address as a candidate
    kept = rules.origin_hypotheses(_facts(), labeller, as_of=AS_OF, exclude_kinds=("cdn",))
    assert [c["value"] for c in kept["candidates"]] == ["203.0.113.200"]
    assert result["network_requests"] == 0 and result["disclosure"] == "none"


def test_non_routable_and_current_addresses_are_never_candidates() -> None:
    facts = _facts(history_a=[{"ip": ip, "first_seen": "2018-01-01", "last_seen": "2019-01-01"}
                              for ip in ("10.0.0.5", "127.0.0.1", "100.64.1.1", "169.254.1.1", "198.51.100.10", "fd00::1")])
    result = rules.origin_hypotheses(facts, label_map({"198.51.100.10": "cdn"}), as_of=AS_OF)
    assert result["candidates"] == [] and {e["why"] for e in result["excluded"]} == {"non-routable address"}


def test_not_fronted_or_unlabelled_never_guesses() -> None:
    assert rules.origin_hypotheses(_facts(), label_map({}), as_of=AS_OF)["reason"] == "not_cdn_fronted"
    mixed = rules.origin_hypotheses(_facts(current_a=["198.51.100.10", "203.0.113.9"]), label_map({"198.51.100.10": "cdn"}), as_of=AS_OF)
    assert mixed["reason"] == "not_cdn_fronted"
    assert rules.origin_hypotheses(_facts(current_a=[]), label_map({}), as_of=AS_OF)["reason"] == "no_current_resolution"
    assert rules.origin_hypotheses({"seed": ""}, label_map({}), as_of=AS_OF)["reason"] == "no_seed_domain"


def test_quota_and_missing_keys_are_coverage_notes_never_a_fallback() -> None:
    notes = rules.history_coverage({"securitytrails": "quota", "passive_dns": "needs_key", "virustotal": "ok"})
    assert [n["source"] for n in notes] == ["passive_dns", "securitytrails"]
    assert all("no fallback to brute force or active resolution" in n["note"] for n in notes)
    fx = correlate.load_graph_fixture(FIXTURES / "positive_quota_no_history_san_only.json")
    corr = correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx)[0]
    assert any("securitytrails unavailable (quota)" in e for e in corr.evidence)


def test_shared_index_labels_real_cdn_edges() -> None:
    """The bundled MISP CDN warninglist (P169) labels a real Cloudflare edge through the core noise index."""
    graph = Graph(noise_check=False)
    assert rules.range_label(graph, "104.16.132.229")["kind"] == "cdn"
    assert rules.range_label(graph, "203.0.113.7") is None


# ------------------------------------------------------------------ FC3 weights
def test_weights_bands_decay_and_caps() -> None:
    assert rules.WEIGHTS["cert_fingerprint"] > rules.WEIGHTS["cert_san"] > rules.WEIGHTS["historical_a_pre_cdn"] > rules.WEIGHTS["favicon_mmh3"]
    fresh = rules.evidence_weight("historical_a_pre_cdn", last_seen=AS_OF, as_of=AS_OF)
    three_years = rules.evidence_weight("historical_a_pre_cdn", last_seen=AS_OF - dt.timedelta(days=1095), as_of=AS_OF)
    assert fresh == 0.35 and three_years == pytest.approx(0.175, abs=0.001)
    assert rules.evidence_weight("historical_a_pre_cdn", last_seen=dt.date(2000, 1, 1), as_of=AS_OF) == rules.HISTORY_FLOOR
    assert rules.combine_score([0.6, 0.35]) == pytest.approx(0.74)
    assert [rules.strength_of(s) for s in (0.72, 0.5, 0.27, 0.2, 0.15, 0.0)] == ["strong", "strong", "medium", "medium", "weak", "none"]
    obs = [{"ip": "203.0.113.50", "favicon_mmh3": [-1335209478], "title": ["Example Portal"]},
           {"ip": "203.0.113.51", "cert_sans": ["example.com"], "hosted_domain_count": 51},
           {"ip": "203.0.113.52", "cert_sha256": ["ab" * 32], "shared": True}]
    result = rules.origin_hypotheses(_facts(history_a=[], ip_observations=obs,
                                            site={"favicon_mmh3": [-1335209478], "title": ["Example Portal"], "cert_sha256": ["AB" * 32]}),
                                     label_map({"198.51.100.10": "cdn"}), as_of=AS_OF)
    scores = {c["value"]: (c["score"], c["strength"], c["caps"]) for c in result["candidates"]}
    assert scores["203.0.113.50"][:2] == (rules.WEAK_CAP, "weak") and "favicon/title only" in scores["203.0.113.50"][2][0]
    assert scores["203.0.113.51"][:2] == (rules.WEAK_CAP, "weak")  # > 50 domains on the IP
    assert scores["203.0.113.52"][:2] == (rules.WEAK_CAP, "weak")  # shared IP flag


def test_one_item_per_kind_and_default_favicons_ignored() -> None:
    obs = [{"ip": "203.0.113.60", "source": "censys", "cert_sans": ["example.com"], "favicon_mmh3": [116323821]},
           {"ip": "203.0.113.60", "source": "shodan", "cert_sans": ["www.example.com", "*.example.com"]}]
    history = [{"ip": "203.0.113.60", "first_seen": "2020-01-01", "last_seen": "2023-01-01", "source": "securitytrails"},
               {"ip": "203.0.113.60", "first_seen": "2020-01-01", "last_seen": "2023-01-01", "source": "passive_dns"},
               {"ip": "198.51.100.10", "first_seen": "2024-03-01", "last_seen": "2026-11-25"}]
    result = rules.origin_hypotheses(_facts(history_a=history, ip_observations=obs, default_favicons=[116323821],
                                            site={"favicon_mmh3": [116323821]}), label_map({"198.51.100.10": "cdn"}), as_of=AS_OF)
    cand = result["candidates"][0]
    assert sorted(e["kind"] for e in cand["evidence"]) == ["cert_san", "historical_a_pre_cdn"]


def test_cdn_era_places_history_before_or_during_the_cdn() -> None:
    labeller = label_map({"198.51.100.10": "cdn", "198.51.100.11": "cdn"})
    history = [{"ip": "198.51.100.10", "first_seen": "2024-03-01", "last_seen": "2025-01-01"},
               {"ip": "198.51.100.11", "first_seen": "2025-01-20", "last_seen": "2026-11-25"},  # gap < 30 days: same era
               {"ip": "203.0.113.70", "first_seen": "2019-01-01", "last_seen": "2024-02-28"},
               {"ip": "203.0.113.71", "first_seen": "2025-06-01", "last_seen": "2025-07-01"},
               {"ip": "203.0.113.72"}]
    recs = rules.history_records(history)
    assert rules.cdn_era_start(recs, labeller) == dt.date(2024, 3, 1)
    result = rules.origin_hypotheses(_facts(current_a=["198.51.100.11"], history_a=history), labeller, as_of=AS_OF)
    kinds = {c["value"]: c["evidence"][0]["kind"] for c in result["candidates"]}
    assert kinds == {"203.0.113.70": "historical_a_pre_cdn", "203.0.113.71": "historical_a_during_cdn",
                     "203.0.113.72": "historical_a_undated"}


def test_san_and_title_helpers() -> None:
    assert rules.san_covers("*.example.com", "www.example.com") and rules.san_covers("EXAMPLE.com.", "example.com")
    assert not rules.san_covers("*.example.com", "example.com") and not rules.san_covers("*.example.com", "a.b.example.com")
    assert rules.normalise_title("  Welcome to nginx! ") is None and rules.normalise_title("Example  Portal") == "example portal"


# ------------------------------------------------------------------ FC4 hostile-site abuse aid
def test_hostile_site_gets_an_abuse_aid() -> None:
    fx = correlate.load_graph_fixture(FIXTURES / "positive_hostile_abuse_aid.json")
    corr = correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx)[0]
    assert "abuse_aid" in corr.tags and corr.references == ["https://abuse.cloudflare.com/"]
    assert any("abuse contact abuse@example.net" in e and "EXAMPLE-VPS-LTDA" in e for e in corr.evidence)
    aid = rules.abuse_aid({"value": "203.0.113.66", "asn": "AS64502", "as_name": "X", "abuse_email": "not-an-address"}, ["Akamai"])
    assert aid["hoster_abuse_contact"] is None and aid["cdn_abuse_forms"] == [{"provider": "Akamai", "abuse_form": None}]


def test_strong_hypothesis_on_an_own_asset_is_low() -> None:
    fx = correlate.load_graph_fixture(FIXTURES / "positive_strong_own_asset_is_low.json")
    corr = correlate.run_rules(fx.graph, fx.results, only={rules.RULE_ORIGIN}, rctx=fx.rctx)[0]
    assert corr.severity.label == "low" and "WAF/CDN can be bypassed" in corr.recommendation
