"""dns_bruteforce (P370, ACTIVE): the contract, the scope-apex gate (FC1), the A7 pacing, budget,
window and kill switch (FC2), the pinned wordlist (FC3), the resolver policy (FC4), the wildcard
logic (FC5: existence = an A/AAAA/CNAME answer that differs from the wildcard set; NODATA/NXDOMAIN
prove nothing; SERVFAIL = unknown), the brute-force pivots and scope join (FC6) and the summarised,
tri-state output (FC7).

Resolution is through ``ctx.dns`` over DoH, which the tests drive with ``tests.fakes.add_dns`` (no
target host is contacted; an unexpected DoH query fails the test). The deep A7 egress and ledger of
target contact belong to the core and are proved by the AR20 safety suite."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from tests.fakes import FakeClock, add_dns, fixture, make_ctx, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Opsec, Status
from v3lum.core.module import HealthResult
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import dns_bruteforce as module
from v3lum.modules.pentest_recon import g134_parsers as P
from v3lum.modules.pentest_recon.dns_bruteforce import DnsBruteforce

_ORIGINAL_RANDOM_LABELS = P.random_labels

REF = "PENTEST-2026-042"
APEX = "acme.example"
DATA = Path(__file__).resolve().parents[2] / "v3lum" / "data" / "dns_bruteforce"
DOH = r"https://(?:dns\.google/resolve|cloudflare-dns\.com/dns-query)\?"

SCOPE = {
    "authorization_ref": REF,
    "owner": "ACME S.A. - information security",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1234",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",
    "targets": {"domains": [APEX, "*.acme.example"], "cidrs": ["93.184.216.0/24"]},
}

WORDS = "www\nmail\ndev\nadmin\nstaging\nvpn\n"  # a small test wordlist


def make_scope(**changes) -> Scope:
    return Scope.from_dict({**SCOPE, **changes})


def active_options(scope=None) -> ScanOptions:
    return ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=scope or make_scope())


PROBE = "wcprobe"  # the test-only wildcard probe labels (the module draws purely random ones)


@pytest.fixture(autouse=True)
def recognisable_probes(monkeypatch):
    """Make the FC5 random labels recognisable to the routes below (the real ones carry no prefix)."""
    counter = iter(range(10**6))
    monkeypatch.setattr(P, "random_labels", lambda count=3, rng=None, **kw: [f"{PROBE}{next(counter)}" for _ in range(max(3, count))])


def test_random_wildcard_labels_are_random_and_carry_no_tool_signature():
    import random

    labels = _ORIGINAL_RANDOM_LABELS(rng=random.Random(7))
    assert len(labels) >= 3 and len(set(labels)) == len(labels)  # FC5: >= 3 distinct random labels
    for label in labels:
        assert re.fullmatch(r"[a-z][a-z0-9]{11,62}", label) and "v3l" not in label  # no tool signature
    assert _ORIGINAL_RANDOM_LABELS(rng=random.Random(8)) != labels


@pytest.fixture()
def wordlist(tmp_path) -> str:
    path = tmp_path / "words.txt"
    path.write_text(WORDS, encoding="utf-8")
    return str(path)


def wildcard_free_dns(http):
    """Every random wildcard probe under the apex is NXDOMAIN on both resolvers (no wildcard zone)."""
    http.add("GET", re.compile(DOH + r".*name=" + PROBE), json={"Status": 3, "Answer": []})


def nx(http, *labels):
    for label in labels:
        add_dns(http, f"{label}.{APEX}", "A", [], status=3, provider="all")


def exists(http, label, ip, aaaa=()):
    add_dns(http, f"{label}.{APEX}", "A", [ip], provider="all")
    add_dns(http, f"{label}.{APEX}", "AAAA", list(aaaa), provider="all")


def run_bf(http, words, *, settings=None, scope=None, entity=f"domain:{APEX}", **kw):
    base = {"dns_bruteforce_wordlist": words, "dns_bruteforce_permutations": False}
    base.update(settings or {})
    return run_module(DnsBruteforce, entity, http, settings=base, options=active_options(scope), case_id="case-1", **kw)


# --------------------------------------------------------------------------------------
# contract / metadata / pinned data
# --------------------------------------------------------------------------------------


def test_contract_metadata():
    m = DnsBruteforce
    assert m.opsec is Opsec.ACTIVE and m.disclosure == "target" and m.default_enabled is False
    assert m.terms == "open" and m.hosts == () and m.run_on == "seeds" and m.max_requests == 0
    assert m.shares_input is True and m.trust_tier == "n/a" and m.timeout == 600.0 and m.max_rate <= 10.0


def test_health_self_test_is_offline_and_checks_the_pin(monkeypatch):
    hc = DnsBruteforce.health_check()
    assert hc.offline is True and callable(hc.selftest)
    res = hc.selftest(make_ctx(DnsBruteforce))
    assert isinstance(res, HealthResult) and res.status == "ok"
    monkeypatch.setattr(module, "WORDLIST_SHA256", "0" * 64)
    assert hc.selftest(make_ctx(DnsBruteforce)).status == "dead"


def test_bundled_wordlist_is_pinned_and_capped():
    data = (DATA / "subdomains-top1million-5000.txt").read_bytes()
    manifest = json.loads((DATA / "manifest.json").read_text())
    assert hashlib.sha256(data).hexdigest() == manifest["sha256"] == module.WORDLIST_SHA256  # A7 pin
    labels = P.load_wordlist(data)
    assert 0 < len(labels) <= P.WORDLIST_CAP


def test_a_bundled_wordlist_that_changed_without_a_reviewed_pin_is_refused(monkeypatch):
    monkeypatch.setattr(module, "WORDLIST_SHA256", "0" * 64)
    res = run_bf(_NoDns(), "")
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"


def test_real_doh_fixtures_parse_to_the_expected_existence_state():
    """FC5 over trimmed real DoH answers: existence needs an A/AAAA/CNAME answer; NODATA/NXDOMAIN prove
    nothing; SERVFAIL/REFUSED are unknown; an HTML page is a block, never an answer."""
    exists_ = P.parse_doh_json(fixture("dns_bruteforce/doh_exists.json"))
    assert exists_["has_answer_rr"] and P.answer_rr_set(exists_)
    nodata = P.parse_doh_json(fixture("dns_bruteforce/doh_nodata.json"))
    assert not nodata["has_answer_rr"] and nodata["authority_soa"]  # Cloudflare 'black lies'
    assert P.name_exists(nodata, {"is_wildcard": False, "rr_set": frozenset()}) == "not_observed"
    servfail = P.parse_doh_json(fixture("dns_bruteforce/doh_servfail.json"))
    assert P.doh_marker(servfail).startswith("servfail") and P.name_exists(servfail, None) == "unknown"
    refused = P.parse_doh_json(fixture("dns_bruteforce/doh_refused.json"))
    assert P.doh_marker(refused).startswith("refused")
    blocked = P.parse_doh_json(fixture("dns_bruteforce/doh_blocked.html"))
    assert blocked["error"] and "blocked" in blocked["error"]
    same = P.parse_doh_json(fixture("dns_bruteforce/doh_wildcard_same.json"))
    differs = P.parse_doh_json(fixture("dns_bruteforce/doh_wildcard_differs.json"))
    profile = P.wildcard_profile([same, same, same])
    assert profile["is_wildcard"] and P.name_exists(same, profile) == "not_observed"
    assert P.name_exists(differs, profile) == "exists"


# --------------------------------------------------------------------------------------
# FC1 - the scope-apex gate; FC4 - the resolver policy
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("entity,scope_changes", [
    ("domain:not-in-scope.example", {}),
    (f"domain:{APEX}", {"exclusions": {"domains": [APEX]}}),
    (f"domain:{APEX}", {"targets": {"domains": ["*.acme.example"]}}),  # only a wildcard: the apex is not listed
    (f"domain:dev.{APEX}", {}),  # a subdomain is not a listed apex
    (f"domain:{APEX}", {"window_start": "2027-01-01T00:00:00Z", "window_end": "2027-02-01T00:00:00Z"}),
    (f"domain:{APEX}", {"targets": {"domains": [APEX], "cidrs": ["10.0.0.0/4"]}}),  # a scope with problems
])
def test_only_a_listed_apex_of_a_usable_open_scope_is_enumerated(entity, scope_changes, wordlist):
    res = run_bf(_NoDns(), wordlist, scope=make_scope(**scope_changes), entity=entity)
    assert res.status is Status.SKIPPED and res.reason_code == "scope", res.error


@pytest.mark.parametrize("settings", [{"dns_mode": "system"}, {"doh_internal": "https://doh.corp.acme.example/dns-query"}])
def test_resolution_never_goes_through_the_system_or_organisation_resolver(settings, wordlist):
    res = run_bf(_NoDns(), wordlist, settings=settings)
    assert res.status is Status.SKIPPED and res.reason_code == "config" and "FC4" in res.error


def test_candidates_the_scope_excludes_are_never_queried(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    nx(http, "www", "mail", "dev", "staging", "vpn")  # no route for admin: a query for it would fail the test
    res = run_bf(http, wordlist, scope=make_scope(exclusions={"domains": [f"admin.{APEX}"]}))
    assert res.status is Status.EMPTY
    assert res.raw["excluded_by_scope"] == 1 and res.raw["candidates_tried"] == 5


# --------------------------------------------------------------------------------------
# FC5 - wildcard logic and existence
# --------------------------------------------------------------------------------------


def test_discovers_names_in_a_non_wildcard_zone(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "www", "93.184.216.10")
    exists(http, "dev", "93.184.216.20", aaaa=["2606:2800:220:1::20"])
    nx(http, "mail", "admin", "staging", "vpn")
    res = run_bf(http, wordlist)
    assert res.status is Status.OK and not res.partial
    assert {p.entity.value for p in res.pivots} == {f"www.{APEX}", f"dev.{APEX}"}
    for p in res.pivots:
        assert p.expand is False and "provenance: brute-force" in p.note and p.relation == "subdomain"
    assert res.raw["found"][f"dev.{APEX}"] == ["2606:2800:220:1::20", "93.184.216.20"]  # AAAA completed for FC6
    summary = res.attributes["brute_force_summary"]
    assert summary["status"] == "confirmed" and summary["found"] == 2 and summary["wildcard"] is False
    finding = res.findings[0]
    assert finding.title == "Subdomains discovered by authorized DNS enumeration"  # stable id: counts in the text
    assert "2 subdomain(s)" in finding.description


def test_wildcard_zone_only_names_differing_from_the_wildcard_exist(fake_http, wordlist):
    http = fake_http
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=AAAA"), json=_answer("probe", "AAAA", []))
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=A\b"), json=_answer("probe", "A", ["93.184.216.99"]))
    for label in ("www", "mail", "admin", "staging", "vpn"):
        exists(http, label, "93.184.216.99")  # the wildcard's own address: NOT a real name
    exists(http, "dev", "93.184.216.50")  # a different address: real
    res = run_bf(http, wordlist)
    assert res.status is Status.OK
    assert {p.entity.value for p in res.pivots} == {f"dev.{APEX}"}
    assert res.attributes["brute_force_summary"]["wildcard"] is True


def test_round_robin_wildcards_compare_against_the_union_of_the_probes(fake_http, wordlist):
    """A wildcard answering each probe from a pool must not turn every candidate into 'exists'."""
    http = fake_http
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=AAAA"), json=_answer("probe", "AAAA", []))
    for ip in ("93.184.216.91", "93.184.216.92", "93.184.216.93"):
        http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=A\b"), json=_answer("probe", "A", [ip]), times=1)
    for label, ip in (("www", "93.184.216.92"), ("mail", "93.184.216.93"), ("admin", "93.184.216.91"),
                      ("staging", "93.184.216.92"), ("vpn", "93.184.216.91")):
        exists(http, label, ip)
    exists(http, "dev", "93.184.216.50")
    res = run_bf(http, wordlist)
    assert {p.entity.value for p in res.pivots} == {f"dev.{APEX}"}


def test_a_cname_into_the_wildcard_target_is_the_wildcard(fake_http, wordlist):
    http = fake_http
    lb = {"Status": 0, "Answer": [{"name": "x.", "type": 5, "TTL": 60, "data": "lb.cdn-provider.example."},
                                  {"name": "lb.cdn-provider.example.", "type": 1, "TTL": 60, "data": "93.184.216.77"}]}
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=AAAA"), json={"Status": 0, "Answer": [lb["Answer"][0]]})
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r".*type=A\b"), json=lb)
    rotated = {"Status": 0, "Answer": [lb["Answer"][0], {"name": "lb.cdn-provider.example.", "type": 1, "TTL": 60, "data": "93.184.216.78"}]}
    for label in ("www", "mail", "admin", "staging", "vpn"):
        http.add("GET", re.compile(DOH + rf".*name={label}\.acme\.example&type=A\b"), json=rotated)
    exists(http, "dev", "93.184.216.50")
    res = run_bf(http, wordlist)
    assert {p.entity.value for p in res.pivots} == {f"dev.{APEX}"}


def test_cloudflare_nodata_proves_nothing(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    http.add("GET", re.compile(DOH + r".*name=(www|mail|dev|admin|staging|vpn)\."), json={"Status": 0, "Answer": []})
    res = run_bf(http, wordlist)
    assert res.status is Status.EMPTY and not res.pivots  # NODATA is not existence...
    assert res.attributes["brute_force_summary"]["status"] == "not_observed"  # ...and never 'does not exist'


def test_trimmed_real_doh_answer_shapes_through_ctx_dns(fake_http, tmp_path):
    """The fixture bodies served by the resolvers: a CNAME-only answer exists, NXDOMAIN and Cloudflare
    NODATA are 'not observed', SERVFAIL, an error inside an HTTP-200 body and an HTML block page are
    'unknown' (never absent)."""
    http = fake_http
    wildcard_free_dns(http)

    def serve(label, name, *, html=False):
        body = fixture(f"dns_bruteforce/{name}")
        if html:
            http.add("GET", re.compile(DOH + rf".*name={label}\.acme\.example&"), text=body)
        else:
            http.add("GET", re.compile(DOH + rf".*name={label}\.acme\.example&"), json=body if isinstance(body, dict) else json.loads(body))

    serve("www", "doh_exists.json")
    serve("vpn", "doh_cname.json")
    serve("mail", "doh_nxdomain.json")
    serve("dev", "doh_nodata.json")
    serve("admin", "doh_error_in_200.json")
    serve("staging", "doh_blocked.html", html=True)
    words = tmp_path / "ordered.txt"  # the failing answers last: they open the core resolver circuits
    words.write_text("www\nvpn\nmail\ndev\nadmin\nstaging\n", encoding="utf-8")
    res = run_bf(http, str(words))
    assert res.status is Status.OK
    assert {p.entity.value for p in res.pivots} == {f"www.{APEX}", f"vpn.{APEX}"}  # A records / CNAME only
    assert sorted(res.raw["unknown"]) == [f"admin.{APEX}", f"staging.{APEX}"]
    assert res.attributes["brute_force_summary"]["unknown"] == 2


def test_servfail_wildcard_probe_is_could_not_test(fake_http, wordlist):
    http = fake_http
    http.add("GET", re.compile(DOH + r".*name=" + PROBE), json={"Status": 2, "Answer": []})
    res = run_bf(http, wordlist)
    assert res.status is Status.ERROR
    assert res.attributes["brute_force_summary"]["status"] == "could_not_test"


def test_servfail_candidates_are_unknown_never_empty(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    http.add("GET", re.compile(DOH + r".*name=(www|mail|dev|admin|staging|vpn)\."), json={"Status": 2, "Answer": []})
    res = run_bf(http, wordlist)
    assert res.status is Status.ERROR and "could not verify 6 of 6" in res.error
    assert res.attributes["brute_force_summary"]["status"] == "could_not_test"


def test_a_run_whose_resolvers_stop_answering_ends_early_as_could_not_test(fake_http, tmp_path):
    http = fake_http
    wildcard_free_dns(http)
    http.add("GET", re.compile(DOH + r".*name=w\d+\."), json={"Status": 2, "Answer": []})
    words = tmp_path / "many.txt"
    words.write_text("\n".join(f"w{i}" for i in range(200)), encoding="utf-8")
    res = run_bf(http, str(words))
    assert res.status is Status.ERROR and "stopped answering" in res.error
    assert res.raw["candidates_tried"] == module.MAX_CONSECUTIVE_UNKNOWN  # not 200: no pacing through a dead run


def test_some_servfail_candidates_are_reported_next_to_the_found_names(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "dev", "93.184.216.20")
    http.add("GET", re.compile(DOH + r".*name=vpn\."), json={"Status": 2, "Answer": []})
    nx(http, "www", "mail", "admin", "staging")
    res = run_bf(http, wordlist)
    assert res.status is Status.OK
    assert res.attributes["brute_force_summary"]["unknown"] == 1 and res.raw["unknown"] == [f"vpn.{APEX}"]


def test_offline_permutations_of_found_names_use_their_parent_wildcard_profile(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "dev", "93.184.216.20")
    nx(http, "www", "mail", "admin", "staging", "vpn")
    exists(http, "test-dev", "93.184.216.21")  # a permutation ({{word}}-{{sub}}) that exists
    http.add("GET", re.compile(DOH + r".*name=" + PROBE + r"\d+\.dev\.acme\.example"), json={"Status": 3, "Answer": []})
    http.add("GET", re.compile(DOH), json={"Status": 3, "Answer": []})  # every other permutation: NXDOMAIN
    res = run_bf(http, wordlist, settings={"dns_bruteforce_permutations": True})
    found = {p.entity.value for p in res.pivots}
    assert {f"dev.{APEX}", f"test-dev.{APEX}"} <= found
    assert res.raw["parents_profiled"] >= 2  # the apex and the dev.acme.example parent (FC5 per parent)
    assert res.raw["candidates_tried"] <= len(WORDS.split()) + P.PERMUTATIONS_PER_RUN


# --------------------------------------------------------------------------------------
# FC2 - pacing, budget, window end and the kill switch
# --------------------------------------------------------------------------------------


def test_doh_queries_are_paced_at_the_scope_rate(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    nx(http, "www", "mail", "dev", "admin", "staging", "vpn")
    clock = FakeClock()
    res = run_bf(http, wordlist, scope=make_scope(limits={"max_rps": 2}), clock=clock)
    assert res.status is Status.EMPTY
    queries = res.raw["doh_queries"]
    assert queries >= 12 and len(clock.sleeps) >= queries - 1
    assert all(abs(s - 0.5) < 1e-6 for s in clock.sleeps)  # 2 queries/s, never faster


def test_the_default_rate_is_ten_queries_per_second(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    nx(http, "www", "mail", "dev", "admin", "staging", "vpn")
    clock = FakeClock()
    run_bf(http, wordlist, clock=clock)
    assert clock.sleeps and all(abs(s - 0.1) < 1e-6 for s in clock.sleeps)


def test_the_scope_budget_stops_the_run_partial(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "www", "93.184.216.10")
    nx(http, "mail", "dev", "admin", "staging", "vpn")
    res = run_bf(http, wordlist, scope=make_scope(limits={"max_requests": 9}))
    assert res.partial and res.stop_reason == "request_cap"
    assert res.raw["doh_queries"] == 9 and {p.entity.value for p in res.pivots} == {f"www.{APEX}"}


def test_the_end_of_the_scope_window_is_a_kill_switch(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    nx(http, "www", "mail", "dev", "admin", "staging", "vpn")
    scope = make_scope(window_start="2026-11-26T11:00:00Z", window_end="2026-11-26T12:00:01Z")  # FakeClock: 12:00:00
    res = run_bf(http, wordlist, scope=scope, clock=FakeClock())
    assert res.partial and res.stop_reason == "cancelled" and "window" in res.raw["stop"]
    assert res.raw["doh_queries"] <= 11  # 10/s for one second, then nothing


def test_the_kill_switch_keeps_what_was_found(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "www", "93.184.216.10")
    nx(http, "mail", "dev", "admin", "staging", "vpn")
    ent = Entity.make(EntityType.DOMAIN, APEX)
    ctx = make_ctx(DnsBruteforce, http, settings={"dns_bruteforce_wordlist": wordlist, "dns_bruteforce_permutations": False},
                   options=active_options(), entity=ent, case_id="case-1")
    real, calls = ctx.dns.query, []

    def query(name, rtype="A", **kw):
        calls.append(name)
        if len(calls) == 9:  # after the wildcard probes (6) and www (A + AAAA) + mail (A)
            ctx.runtime.cancel("cancelled")
        return real(name, rtype, **kw)

    ctx.dns.query = query
    res = DnsBruteforce().run(ent, ctx)
    assert res.partial and res.stop_reason == "cancelled"
    assert {p.entity.value for p in res.pivots} == {f"www.{APEX}"} and len(calls) == 9  # nothing sent after the kill


# --------------------------------------------------------------------------------------
# FC6 - scope join of found names
# --------------------------------------------------------------------------------------


def test_found_names_join_the_active_scope_only_on_scoped_addresses(fake_http, wordlist):
    http = fake_http
    wildcard_free_dns(http)
    exists(http, "dev", "93.184.216.20")  # inside the scoped CIDR
    exists(http, "www", "8.8.8.8")  # outside every scoped CIDR: passive modules only
    nx(http, "mail", "admin", "staging", "vpn")
    res = run_bf(http, wordlist)
    assert res.attributes["brute_force_summary"]["active_scope_joins"] == 1
    notes = {p.entity.value: p.note for p in res.pivots}
    assert notes[f"dev.{APEX}"].endswith("; active")
    assert "passive_only" in notes[f"www.{APEX}"]


# --------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------


def _answer(name, rtype, records):
    from v3lum.core.dns import RTYPES

    return {"Status": 0, "Answer": [{"name": name + ".", "type": RTYPES[rtype], "TTL": 300, "data": r} for r in records]}


class _NoDns:
    """A FakeHttp-like transport that fails the test if any request is made (gate tests)."""

    def request(self, method, url, **kw):  # pragma: no cover - the gates return before any DoH
        raise AssertionError(f"no request expected, got {method} {url}")

    send = request
