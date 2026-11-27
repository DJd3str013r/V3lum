"""lunar_domain_exposure (P136): 12-month aggregate domain exposure card, confidential (TLP:AMBER).

Fixtures in tests/fixtures/lunar_domain_exposure/: ``example_com_ready.json``, ``nic_br_ready.json`` (the
second request, ~30 s after ``generating.json``) and ``invalid_domain_400.json`` are trimmed live answers
of 2026-11-26 (masked user-name residue in login paths scrubbed); ``rate_limited_429.json`` and
``challenge.html`` are synthetic (not provoked).
"""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Status
from v3lum.modules.breach_leak.lunar_domain_exposure import LunarDomainExposure, parse_exposure

MOD = LunarDomainExposure
API = "https://api.lunarcyber.com/domain-exposure?domain={}"


def fx(name):
    return module_fixture(MOD, name)


def env(http, url, name, **kw):
    data = fx(name)
    body = data.get("body")
    return http.add("GET", url, status=data["status"], json=body, headers=data.get("headers"), **kw)


def test_ready_report_is_an_aggregate_card_marked_amber():
    http = FakeHttp().add("GET", API.format("nic.br"), json=fx("nic_br_ready.json"))
    res = run_module(MOD, "domain:nic.br", http)
    assert res.status is Status.OK
    card = res.attributes["domain_exposure"]
    assert card["totals"]["total_events"] == 9324 and card["totals"]["infostealer_events"] == 746
    assert card["caveats"] == []
    assert res.tlp == "amber"  # cond 5: confidential, minimum TLP:AMBER
    f = res.findings[0]
    assert f.severity.label == "low" and "confidential" in f.tags
    assert "not the compromise of a specific account" in f.description
    blob = json.dumps([res.attributes, res.raw, [x.to_dict() for x in res.findings]], default=str)
    for dropped in ("country_breakdown", "service_classification", "/users/", "top_login_urls"):
        assert dropped not in blob  # aggregate fields only (cond 3)
    http.assert_hosts_within(MOD)


def test_implausible_volume_and_test_domain_carry_the_caveat():
    http = FakeHttp().add("GET", API.format("example.com"), json=fx("example_com_ready.json"))
    res = run_module(MOD, "domain:example.com", http)
    caveats = res.attributes["domain_exposure"]["caveats"]
    assert any("implausible volume" in c for c in caveats) and any("example/test domain" in c for c in caveats)
    assert res.findings[0].severity.label == "info" and "context_only" in res.findings[0].tags


def test_generating_report_is_polled_then_ready():
    http = FakeHttp().add("GET", API.format("nic.br"), json=fx("generating.json"), times=1)
    http.add("GET", API.format("nic.br"), json=fx("nic_br_ready.json"))
    res = run_module(MOD, "domain:nic.br", http)
    assert res.status is Status.OK and len(http.calls) == 2


def test_still_generating_after_the_poll_budget_is_timeout_never_empty():
    http = FakeHttp().add("GET", API.format("nic.br"), json=fx("generating.json"))
    res = run_module(MOD, "domain:nic.br", http)
    assert res.status is Status.ERROR and res.reason_code == "timeout"
    assert len(http.calls) == 3


def test_webmail_and_noise_domains_are_never_sent():
    http = FakeHttp()
    res = run_module(MOD, "domain:gmail.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.calls == []


def test_error_bodies_and_limits():
    http = FakeHttp()
    env(http, API.format("acme.com.br"), "rate_limited_429.json")
    assert run_module(MOD, "domain:acme.com.br", http).status is Status.RATE_LIMITED
    http2 = FakeHttp()
    env(http2, API.format("acme.com.br"), "invalid_domain_400.json")
    assert run_module(MOD, "domain:acme.com.br", http2).status is Status.ERROR
    http3 = FakeHttp().add("GET", API.format("acme.com.br"), json={"error": "Rate limit reached"})
    assert run_module(MOD, "domain:acme.com.br", http3).status is Status.RATE_LIMITED
    http4 = FakeHttp().add("GET", API.format("acme.com.br"), json={"error": "internal failure"})
    assert run_module(MOD, "domain:acme.com.br", http4).status is Status.ERROR
    http5 = FakeHttp().add("GET", API.format("acme.com.br"), status=403, text=fx("challenge.html"))
    assert run_module(MOD, "domain:acme.com.br", http5).status is Status.BLOCKED
    http6 = FakeHttp().add("GET", API.format("acme.com.br"), text="{broken", headers={"content-type": "application/json"})
    assert run_module(MOD, "domain:acme.com.br", http6).status is Status.ERROR


def test_parser_is_defensive():
    assert parse_exposure(None)["state"] == "unknown"
    assert parse_exposure({"status": "REPORT_READY", "report": "x"})["state"] == "unknown"
    assert parse_exposure({"status": "GENERATING_REPORT", "report": None})["state"] == "generating"
