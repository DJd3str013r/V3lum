"""tor_onionoo (P040 c1, c2, c6, c7): Onionoo details only for locally matched Tor IPs.

Fixtures in tests/fixtures/tor_onionoo/: Onionoo v8.0 details answers recorded on 2026-11-26
(details_ok.json: one exit relay, with its 'contact' replaced by a placeholder to prove it is
dropped; details_empty.json: no relay), a Jetty 'HTTP ERROR 400' page, and two documents derived
from the recorded one: details_prefix_matches.json (search= matches prefixes: relays on 192.0.2.10
and 192.0.2.100 come back for 192.0.2.1) and details_relay_only.json (a non-exit relay). The local
lists come from tests/fixtures/tor_exit_local/.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from tests.modules.test_tor_exit_local import BULK_URL, SUMMARY_URL, minimised_fixtures, tor_routes  # noqa: F401 - autouse fixture
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network.tor_exit_local import BULK_EXIT_LIST, RUNNING_RELAYS
from v3lum.modules.ip_network.tor_onionoo import FIELDS, TorOnionoo

DETAILS = "https://onionoo.torproject.org/details?search={search}&fields=" + FIELDS


def prefetched(*routes: tuple[str, str, dict]) -> tuple[FakeHttp, object]:
    """A runtime whose local Tor lists are already downloaded (as by `v3lum data update`); the
    module's own requests are recorded from a clean slate."""
    http = tor_routes()
    for method, url, kw in routes:
        http.add(method, url, **kw)
    rt = make_runtime(http)
    assert rt.data.update(BULK_EXIT_LIST).ok and rt.data.update(RUNNING_RELAYS).ok
    http.calls.clear()
    return http, rt


def test_metadata():
    cls = TorOnionoo
    assert (cls.terms, cls.disclosure, cls.provider, cls.hosts) == ("open", "third_party", "torproject", ("onionoo.torproject.org",))
    assert (cls.max_requests, cls.cache_ttl, cls.min_interval, cls.default_enabled) == (1, 3600, 1.0, True)
    assert "contact" not in FIELDS.split(",")  # operator contact fields are never requested (c2)


def test_exit_relay_details_and_contact_dropped():
    http, rt = prefetched(("GET", DETAILS.format(search="192.0.2.1"), {"json": module_fixture(TorOnionoo, "details_ok.json")}))
    res = run_module(TorOnionoo, "ipv4:192.0.2.1", runtime=rt)
    assert res.status is Status.OK
    assert res.attributes["is_tor_exit"] is True and res.attributes["asn"] == "AS62744"
    relay = res.attributes["tor_relay"][0]
    assert relay["nickname"] == "ExampleRelay5" and "Exit" in relay["flags"] and relay["exit"] is True
    assert "contact" not in relay and "contact" not in str(res.raw) and "example DOT com" not in str(res.to_dict())
    (finding,) = res.findings
    assert finding.severity is Severity.LOW and finding.attack == ["T1090.003"]
    assert {"anonymizer", "context_only"} <= set(finding.tags) and "malicious" not in finding.tags
    assert {p.entity.value for p in res.pivots} == {"AS62744"} and not res.pivots[0].expand
    assert res.attributes["first_seen"] == "2026-07-03 01:00:00"
    http.assert_hosts_within(TorOnionoo)
    assert res.requests == 1


def test_search_prefix_matches_are_filtered_to_the_exact_ip():
    http, rt = prefetched(("GET", DETAILS.format(search="192.0.2.1"), {"json": module_fixture(TorOnionoo, "details_prefix_matches.json")}))
    res = run_module(TorOnionoo, "ipv4:192.0.2.1", runtime=rt)
    assert [r["nickname"] for r in res.attributes["tor_relay"]] == ["ExampleRelay5"]
    assert res.raw["prefix_matches_dropped"] == 2


def test_non_exit_relay_is_info():
    http, rt = prefetched(("GET", DETAILS.format(search="192.0.2.10"), {"json": module_fixture(TorOnionoo, "details_relay_only.json")}))
    res = run_module(TorOnionoo, "ipv4:192.0.2.10", runtime=rt)
    assert res.status is Status.OK and res.attributes["is_tor_exit"] is False
    assert res.findings[0].severity is Severity.INFO and not res.findings[0].attack


def test_ipv6_search_uses_brackets():
    http, rt = prefetched(("GET", DETAILS.format(search="[2001:db8:ff::7]"), {"json": module_fixture(TorOnionoo, "details_relay_only.json")}))
    res = run_module(TorOnionoo, "ipv6:2001:db8:ff::7", runtime=rt)
    assert res.status is Status.OK and "is_tor_exit" not in res.attributes
    assert parse_qs(urlsplit(http.urls()[-1]).query)["search"] == ["[2001:db8:ff::7]"]


def test_non_tor_ips_never_leave_the_machine():
    http, rt = prefetched()
    res = run_module(TorOnionoo, "ipv4:198.51.100.77", runtime=rt)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "nothing sent" in res.error and not http.calls  # no request at all


def test_unverifiable_local_lists_send_nothing():
    http = FakeHttp().add("GET", BULK_URL, status=503, text="down")
    res = run_module(TorOnionoo, "ipv4:192.0.2.1", http)
    assert res.status is Status.ERROR and "nothing sent" in res.error
    assert all("onionoo" not in u for u in http.urls())


def test_empty_answer_after_a_local_match():
    _http, rt = prefetched(("GET", DETAILS.format(search="192.0.2.2"), {"json": module_fixture(TorOnionoo, "details_empty.json")}))
    assert run_module(TorOnionoo, "ipv4:192.0.2.2", runtime=rt).status is Status.EMPTY


@pytest.mark.parametrize(
    ("route", "status", "code"),
    [
        ({"status": 400, "text": None}, Status.ERROR, "error"),
        ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED, "rate_limited"),
        ({"status": 503, "text": "down"}, Status.ERROR, "error"),
        ({"status": 200, "json": ["not", "an", "object"]}, Status.ERROR, "error"),
        ({"status": 200, "body": b"{not json"}, Status.ERROR, "error"),
    ],
)
def test_errors_are_could_not_verify(route, status, code):
    if route.get("text", "") is None:
        route = {"status": 400, "text": module_fixture(TorOnionoo, "error_400.html")}
    _http, rt = prefetched(("GET", DETAILS.format(search="192.0.2.3"), route))
    res = run_module(TorOnionoo, "ipv4:192.0.2.3", runtime=rt)
    assert res.status is status and res.reason_code == code and not res.findings


def test_tlp_red_keeps_onionoo_away_but_not_the_local_check():
    """P040 c1: the local check runs at TLP:RED, the Onionoo lookup never does."""
    from v3lum.core import module as module_mod

    module_mod.load_modules()
    rt = make_runtime()
    pctx = policy.make_context(rt, ScanOptions(tlp="red"), path="scan")
    ip = Entity.make(EntityType.IPV4, "185.220.101.1")
    run = RunInfo(entity=ip, is_seed=True, tlp="red")
    onionoo = policy.decide(TorOnionoo, ip, pctx, run=run)
    local = policy.decide(module_mod.REGISTRY["tor_exit_local"], ip, pctx, run=run)
    assert (onionoo.allowed, onionoo.reason_code) == (False, "tlp")
    assert local.allowed is True


def test_acceptance_routes_cover_the_golden_ipv4():
    """AR21 golden path (8.8.8.8): the local lists are fetched, nothing is sent to Onionoo."""
    import json

    with open("tests/fixtures/acceptance/ipv4/tor_onionoo.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["module"] == "tor_onionoo"
    http = FakeHttp()
    for route in doc["routes"]:
        body = {"json": route["json"]} if "json" in route else {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], **body)
    res = run_module(TorOnionoo, "ipv4:8.8.8.8", http)
    assert res.status is Status.SKIPPED and all("onionoo.torproject.org/details" not in u for u in http.urls())
