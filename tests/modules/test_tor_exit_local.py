"""tor_exit_local (P040 c1, c2, c6, c7): the local Tor exit check.

Fixtures in tests/fixtures/tor_exit_local/: the TorDNSEL bulk exit list and the Onionoo running-relay
summary recorded on 2026-11-26, minimised to 10 exits / 8 relays, with the relay addresses replaced
by RFC 5737/3849 documentation addresses and the nicknames pseudonymised; an empty body (the failure
mode the validator must reject). The documentation ranges are special-purpose, so the tests treat
them as public (``ip_offline_db.TEST_PUBLIC_LABELS``) and lower the validation floors.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import tlp as tlp_mod
from v3lum.core.datasets import DATASETS
from v3lum.core.models import Severity, Status
from v3lum.modules.ip_network import ip_offline_db, tor_exit_local
from v3lum.modules.ip_network.tor_exit_local import BULK_EXIT_LIST, RUNNING_RELAYS, TOR_EXIT_NOTE, TorExitLocal

BULK_URL = "https://check.torproject.org/torbulkexitlist"
SUMMARY_URL = "https://onionoo.torproject.org/summary?type=relay&running=true"
CHALLENGE = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body><div id=\"cf-chl-widget\">x</div></body></html>"


@pytest.fixture(autouse=True)
def minimised_fixtures(monkeypatch):
    """Documentation addresses count as public and the floors fit the minimised fixtures."""
    monkeypatch.setattr(ip_offline_db, "TEST_PUBLIC_LABELS", frozenset({"documentation"}))
    monkeypatch.setattr(tor_exit_local, "MIN_EXITS", 5)
    monkeypatch.setattr(tor_exit_local, "MIN_RELAYS", 1)
    monkeypatch.setitem(DATASETS[BULK_EXIT_LIST], "min_bytes", 10)
    monkeypatch.setitem(DATASETS[RUNNING_RELAYS], "min_bytes", 10)


def bulk_text() -> str:
    return module_fixture(TorExitLocal, "torbulkexitlist_ok.txt")


def summary_doc() -> dict:
    return module_fixture(TorExitLocal, "onionoo_summary_running_ok.json")


def tor_routes(http: FakeHttp | None = None, *, times: int | None = None) -> FakeHttp:
    """Routes for the two local datasets (the bulk list is served without Content-Type, as observed)."""
    http = http or FakeHttp()
    http.add("GET", BULK_URL, body=bulk_text().encode(), headers={"last-modified": "Thu, 26 Nov 2026 11:47:57 GMT"}, times=times)
    http.add("GET", SUMMARY_URL, json=summary_doc(), headers={"last-modified": "Thu, 26 Nov 2026 11:00:00 GMT"}, times=times)
    return http


# ------------------------------------------------------------------ metadata
def test_metadata_split_local_check():
    cls = TorExitLocal
    assert (cls.terms, cls.disclosure, cls.hosts, cls.provider) == ("open", "none", (), "")
    assert cls.sources == ("torproject.exit_list", "torproject.onionoo")
    assert cls.default_enabled is True and cls.max_tlp is tlp_mod.TLP.RED  # allowed at TLP:RED (P040 c1)
    assert cls.manual_link == "tor_relays:exonerator"
    reg = DATASETS[BULK_EXIT_LIST]
    assert (reg["ttl"], reg["source"], reg["terms_class"], reg["large"]) == (3600, "torproject.exit_list", "open", False)
    assert DATASETS[RUNNING_RELAYS]["url"] == SUMMARY_URL


# ------------------------------------------------------------------ verdicts (c2, c6)
def test_current_exit_is_low_context_never_malicious():
    http = tor_routes()
    res = run_module(TorExitLocal, "ipv4:192.0.2.1", http)
    assert res.status is Status.OK
    assert res.attributes["is_tor_exit"] is True and res.attributes["is_tor_relay"] is True
    assert res.attributes["tor_relay"][0]["nickname"] == "ExampleRelay5"
    (finding,) = res.findings
    assert finding.title == "Tor exit node" and finding.severity is Severity.LOW
    assert {"anonymizer", "tor", "context_only"} <= set(finding.tags) and "malicious" not in finding.tags
    assert finding.attack == ["T1090.003"] and TOR_EXIT_NOTE in finding.description
    assert "fetched" in finding.criterion and finding.source == "torproject.exit_list"
    assert any("exonerator.html?ip=192.0.2.1" in url for _label, url in res.links)
    assert any(line.startswith("Tor bulk exit list, fetched 2026-11-26") for line in res.attributes["dataset_age"])
    assert {d["name"] for d in res.datasets} == {BULK_EXIT_LIST, RUNNING_RELAYS}  # provenance of the lists


def test_non_exit_relay_is_info():
    res = run_module(TorExitLocal, "ipv4:192.0.2.10", tor_routes())
    assert res.status is Status.OK
    assert res.attributes["is_tor_exit"] is False and res.attributes["is_tor_relay"] is True
    (finding,) = res.findings
    assert finding.severity is Severity.INFO and finding.title == "Tor relay (not in the exit list)"
    assert not finding.attack


def test_non_tor_ip_never_leaves_the_machine():
    http = tor_routes()
    res = run_module(TorExitLocal, "ipv4:198.51.100.77", http)
    assert res.status is Status.EMPTY and not res.findings
    assert all("198.51.100.77" not in url for url in http.urls())  # only the two dataset downloads
    assert {u.split("?")[0] for u in http.urls()} == {BULK_URL, SUMMARY_URL.split("?")[0]}


def test_ipv6_matches_the_relay_summary_and_is_never_not_an_exit():
    relay = run_module(TorExitLocal, "ipv6:2001:db8:ff::7", tor_routes())
    assert relay.status is Status.OK and relay.attributes["is_tor_relay"] is True
    assert "is_tor_exit" not in relay.attributes  # TorDNSEL measures IPv4 exits only
    other = run_module(TorExitLocal, "ipv6:2001:db8:aaaa::1", tor_routes())
    assert other.status is Status.EMPTY and "is_tor_exit" not in other.attributes
    assert other.source_statuses["torproject.exit_list"]["reason_code"] == "not_applicable"


def test_private_addresses_are_not_applicable():
    res = run_module(TorExitLocal, "ipv4:10.0.0.1", FakeHttp())
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


# ------------------------------------------------------------------ freshness (c7)
def test_stale_list_is_could_not_verify():
    clock = FakeClock()
    http = tor_routes(times=1)
    http.add("GET", BULK_URL, status=503, text="maintenance")
    http.add("GET", SUMMARY_URL, status=503, text="maintenance")
    rt = make_runtime(http, clock=clock)
    assert run_module(TorExitLocal, "ipv4:192.0.2.1", runtime=rt).status is Status.OK
    clock.advance(7 * 3600)  # the hourly refresh fails and the copy is now older than 6 h
    res = run_module(TorExitLocal, "ipv4:192.0.2.1", runtime=rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "could not verify" in res.error and "never 'not an exit'" in res.error
    assert not res.findings


def test_failed_refresh_within_6h_keeps_the_previous_copy_and_shows_its_age():
    clock = FakeClock()
    http = tor_routes(times=1)
    http.add("GET", BULK_URL, status=200, text=CHALLENGE)  # a challenge page never replaces the good copy
    http.add("GET", SUMMARY_URL, status=200, body=b"")  # nor does an empty body
    rt = make_runtime(http, clock=clock)
    run_module(TorExitLocal, "ipv4:192.0.2.1", runtime=rt)
    clock.advance(2 * 3600)
    res = run_module(TorExitLocal, "ipv4:192.0.2.1", runtime=rt)
    assert res.status is Status.OK and res.attributes["is_tor_exit"] is True
    assert "2 h" in res.findings[0].criterion  # the list's age is shown
    assert BULK_URL in http.urls()[2:]  # the refresh was attempted


def test_hourly_refresh_sends_if_modified_since():
    clock = FakeClock()
    http = tor_routes(times=1)
    http.add("GET", BULK_URL, status=304, body=b"", match_headers={"if-modified-since": "Thu, 26 Nov 2026 11:47:57 GMT"})
    http.add("GET", SUMMARY_URL, status=304, body=b"", match_headers={"if-modified-since": "Thu, 26 Nov 2026 11:00:00 GMT"})
    rt = make_runtime(http, clock=clock)
    run_module(TorExitLocal, "ipv4:192.0.2.2", runtime=rt)
    clock.advance(90 * 60)
    res = run_module(TorExitLocal, "ipv4:192.0.2.2", runtime=rt)
    assert res.status is Status.OK and res.attributes["is_tor_exit"] is True
    assert "1 h 30 min" not in res.findings[0].criterion  # a 304 revalidation refreshes the age


@pytest.mark.parametrize(
    ("route", "status", "code"),
    [
        ({"status": 503, "text": "down"}, Status.ERROR, "error"),
        ({"status": 403, "text": CHALLENGE}, Status.BLOCKED, "challenge"),
        ({"status": 429, "text": "slow down"}, Status.RATE_LIMITED, "rate_limited"),
        ({"status": 200, "body": b""}, Status.ERROR, "error"),
    ],
)
def test_no_copy_and_failed_download_is_could_not_verify(route, status, code):
    http = FakeHttp().add("GET", BULK_URL, **route)
    res = run_module(TorExitLocal, "ipv4:192.0.2.1", http)
    assert res.status is status and res.reason_code == code
    assert "could not verify" in res.error and not res.findings


def test_relay_summary_failure_keeps_the_exit_check():
    http = FakeHttp().add("GET", BULK_URL, body=bulk_text().encode()).add("GET", SUMMARY_URL, status=503, text="down")
    res = run_module(TorExitLocal, "ipv4:192.0.2.1", http)
    assert res.status is Status.OK and res.attributes["is_tor_exit"] is True
    assert res.source_statuses["torproject.onionoo"]["status"] == "error"
    v6 = run_module(TorExitLocal, "ipv6:2001:db8:aaaa::1", FakeHttp().add("GET", BULK_URL, body=bulk_text().encode()).add("GET", SUMMARY_URL, status=503, text="down"))
    assert v6.status is Status.UNAVAILABLE and "could not verify" in v6.error


def test_bulk_list_parser_and_validator():
    ips, invalid = tor_exit_local.parse_bulk_exit_list(bulk_text() + "\nnot-an-ip\n# comment\n")
    assert len(ips) == 10 and invalid == 1 and "203.0.113.1" in ips
    index = tor_exit_local.parse_relay_summary(summary_doc())
    assert index["2001:db8:ff::7"][0]["fingerprint"] == "2C3CCC35B53264238AE8066F3C6CAFB6031EB5CF"
    with pytest.raises(ValueError):
        tor_exit_local.parse_relay_summary({"bridges": []})
    assert module_fixture(TorExitLocal, "torbulkexitlist_empty.txt") == ""


def test_acceptance_routes_cover_the_golden_ipv4():
    """AR21 golden path (8.8.8.8): only the two dataset downloads, and 8.8.8.8 is not Tor."""
    import json

    with open("tests/fixtures/acceptance/ipv4/tor_exit_local.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == "tor_exit_local"
    http = FakeHttp()
    for route in doc["routes"]:
        body = {"json": route["json"]} if "json" in route else {"text": route["text"]}
        http.add(route["method"], route["url"], status=route["status"], **body)
    res = run_module(TorExitLocal, "ipv4:8.8.8.8", http)
    assert res.status is Status.EMPTY and len(http.calls) == len(doc["routes"])
