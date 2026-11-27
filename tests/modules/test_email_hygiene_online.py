"""email_hygiene_online (P088 C5): Kickbox Open + MailCheck.ai second opinions, domain only, opt-in.

Recorded answers (2026-11-26) in tests/fixtures/email_hygiene_online/: Kickbox for a disposable and a
regular domain, MailCheck.ai for google.com (MX, not disposable), example.com (no MX) and its 400
answer for an invalid domain.
"""

from __future__ import annotations

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.modules.email.email_hygiene_online import KICKBOX_URL, MAILCHECK_URL, EmailHygieneOnline, parse_kickbox, parse_mailcheck

MOD = EmailHygieneOnline
CHALLENGE = "<html><head><title>Just a moment...</title></head><body>cf-chl-widget</body></html>"


def fx(name):
    return module_fixture(MOD, name)


def test_both_opinions_and_only_the_domain_is_sent():
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="google.com"), json=fx("mailcheck_ok.json")).add("GET", KICKBOX_URL.format(domain="google.com"), json=fx("kickbox_not_disposable.json"))
    res = run_module(MOD, "email:someone.private@google.com", http)
    assert res.status is Status.OK
    opinions = res.attributes["hygiene_opinions"]
    assert opinions["kickbox"] == {"disposable": False}
    assert opinions["mailcheck"]["disposable"] is False and opinions["mailcheck"]["mx_hosts"] == ["smtp.google.com"]
    assert res.attributes["domain_age_days"] == 10664
    assert not [f for f in res.findings if f.severity.label != "info"]
    assert all("someone.private" not in url and "%40" not in url and "@" not in url for url in http.urls())  # C5
    assert res.raw["domain_sent"] == "google.com"
    http.assert_hosts_within(MOD)


def test_disposable_second_opinion():
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="tempbox.example"), json={**fx("mailcheck_ok.json"), "domain": "tempbox.example", "disposable": True}).add("GET", KICKBOX_URL.format(domain="tempbox.example"), json=fx("kickbox_disposable.json"))
    res = run_module(MOD, "domain:tempbox.example", http)
    finding = next(f for f in res.findings if f.title == "Disposable e-mail domain (second opinion)")
    assert finding.severity.label == "low" and finding.label.value == "probable" and finding.criterion
    assert finding.data["providers"] == ["kickbox", "mailcheck"]


def test_relay_is_a_privacy_tool_never_disposable():
    body = {**fx("mailcheck_ok.json"), "domain": "simplelogin.io", "relay_domain": True, "disposable": True}
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="simplelogin.io"), json=body).add("GET", KICKBOX_URL.format(domain="simplelogin.io"), json=fx("kickbox_disposable.json"))
    res = run_module(MOD, "domain:simplelogin.io", http)
    titles = {f.title for f in res.findings}
    assert "Privacy relay domain (second opinion)" in titles and "Disposable e-mail domain (second opinion)" not in titles


def test_no_mx_and_young_domain():
    young = {**fx("mailcheck_no_mx.json"), "domain_age_in_days": 3}
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), json=young).add("GET", KICKBOX_URL.format(domain="example.com"), json=fx("kickbox_not_disposable.json"))
    res = run_module(MOD, "domain:example.com", http)
    titles = {f.title for f in res.findings}
    assert {"Very young e-mail domain", "Domain has no MX according to MailCheck.ai"} <= titles


def test_error_inside_http_200_is_never_an_answer():
    """MailCheck.ai carries its own JSON status: a 400 inside an HTTP 200 is an error marker (rule 5)."""
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), json=fx("mailcheck_error.json")).add("GET", KICKBOX_URL.format(domain="example.com"), json=fx("kickbox_not_disposable.json"))
    res = run_module(MOD, "domain:example.com", http)
    assert res.status is Status.OK  # Kickbox answered
    assert res.source_statuses["mailcheck.domain"]["status"] == "error"
    assert "mailcheck" not in res.attributes["hygiene_opinions"]
    limited = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), json={"status": 429, "error": "Too many requests"}).add("GET", KICKBOX_URL.format(domain="example.com"), json={"error": "internal"})
    res2 = run_module(MOD, "domain:example.com", limited)
    assert res2.status is Status.RATE_LIMITED and res2.reason_code == "rate_limited"
    assert res2.source_statuses["kickbox.disposable"]["status"] == "error"


def test_recorded_400_for_an_invalid_domain():
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), status=400, json=fx("mailcheck_error.json")).add("GET", KICKBOX_URL.format(domain="example.com"), json=fx("kickbox_not_disposable.json"))
    res = run_module(MOD, "domain:example.com", http)
    assert res.status is Status.OK and res.source_statuses["mailcheck.domain"]["reason_code"] == "error"


def test_429_and_challenge_are_could_not_verify():
    both_429 = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), status=429, json={"status": 429, "error": "Too many requests"}).add("GET", KICKBOX_URL.format(domain="example.com"), status=429, text="slow down")
    res = run_module(MOD, "domain:example.com", both_429)
    assert res.status is Status.RATE_LIMITED and not res.attributes
    blocked = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), status=403, text=CHALLENGE).add("GET", KICKBOX_URL.format(domain="example.com"), status=403, text=CHALLENGE)
    assert run_module(MOD, "domain:example.com", blocked).status is Status.BLOCKED


def test_timeout_and_server_errors_are_could_not_verify():
    timeout = NetworkError("read timed out", kind="ReadTimeout", reason_code="timeout", retryable=False)
    slow = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), error=timeout).add("GET", KICKBOX_URL.format(domain="example.com"), error=timeout)
    res = run_module(MOD, "domain:example.com", slow)
    assert res.status is Status.ERROR and res.reason_code == "timeout" and not res.attributes
    server = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), status=503, text="down").add("GET", KICKBOX_URL.format(domain="example.com"), status=502, text="down")
    assert run_module(MOD, "domain:example.com", server).status is Status.ERROR


def test_malformed_answers_are_errors():
    garbled = FakeHttp().add("GET", MAILCHECK_URL.format(domain="example.com"), text="{not json", headers={"content-type": "application/json"}).add("GET", KICKBOX_URL.format(domain="example.com"), json=["not", "an", "object"])
    res = run_module(MOD, "domain:example.com", garbled)
    assert res.status is Status.ERROR and not res.attributes


def test_keyless_mailcheck_budget_is_respected():
    """MailCheck.ai allows 5 keyless requests per hour and IP: the provider quota block (80%) stops
    the 5th call locally (QUOTA for that feed) while Kickbox still answers."""
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="google.com"), json=fx("mailcheck_ok.json")).add("GET", KICKBOX_URL.format(domain="google.com"), json=fx("kickbox_not_disposable.json"))
    for _ in range(4):
        assert run_module(MOD, "domain:google.com", http).status is Status.OK
    res = run_module(MOD, "domain:google.com", http)
    assert res.status is Status.OK and res.source_statuses["mailcheck.domain"]["status"] == "quota"
    assert list(res.attributes["hygiene_opinions"]) == ["kickbox"]


def test_licence_filter_queries_only_allowed_feeds():
    """Kickbox Open terms are 'unknown': under the corporate profile the gate narrows allowed_sources."""
    http = FakeHttp().add("GET", MAILCHECK_URL.format(domain="google.com"), json=fx("mailcheck_ok.json"))
    res = run_module(MOD, "domain:google.com", http, allowed_sources=["mailcheck.domain"])
    assert res.status is Status.OK and list(res.attributes["hygiene_opinions"]) == ["mailcheck"]
    assert all("kickbox" not in u for u in http.urls())
    none = run_module(MOD, "domain:google.com", FakeHttp(), allowed_sources=[])
    assert none.status is Status.SKIPPED and none.reason_code == "licence"


def test_invalid_values_are_never_sent():
    http = FakeHttp()
    res = run_module(MOD, "domain:com.br", http)  # a public suffix
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and http.calls == []


def test_parsers_are_defensive():
    assert parse_kickbox({"disposable": "true"}) == {"disposable": True}
    for bad in (None, [], {"message": "oops"}, {"disposable": "maybe"}):
        try:
            parse_kickbox(bad)
        except Exception as exc:  # noqa: BLE001 - FeedError expected
            assert type(exc).__name__ == "FeedError"
        else:  # pragma: no cover
            raise AssertionError(bad)
    opinion = parse_mailcheck({"status": 200, "disposable": False, "mx_records": [{"hostname": "MX.Example.COM."}, 7], "mx_providers": ["x", {"name": "y"}]})
    assert opinion["mx_hosts"] == ["mx.example.com"] and opinion["mx_providers"] == ["x", "y"]


def test_metadata_matches_the_council_decision():
    assert MOD.default_enabled is False and MOD.disclosure == "third_party" and MOD.terms == "unknown"
    assert MOD.trust_tier == "community" and MOD.max_requests == 2
