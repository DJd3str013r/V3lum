"""Offline tests of google_calendar_ics (P093) with the fixtures in tests/fixtures/google_calendar_ics/.

ok.ics is a trimmed live capture of Google's public 'Feriados no Brasil' calendar (5 of 275 public-holiday
events); not_found.json is the live 404 for test@example.com; ok_synthetic_personal.ics carries personal
fields built from documentation values to prove they never reach the output (P093 cond 2).
"""

from __future__ import annotations

import json
from pathlib import Path

from tests.fakes import FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.links import render
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.email.google_calendar_ics import ABSENT_TEXT, GoogleCalendarIcs, gcal_ics_url, parse_ics_summary

FIXDIR = Path(__file__).resolve().parents[1] / "fixtures/google_calendar_ics"
ICS = {"content-type": "text/calendar; charset=utf-8"}
ADDR = "user@example.com"
URL = gcal_ics_url(ADDR)
OPTS = ScanOptions(purpose="actor schedule check, ticket EX-7")


def raw(name: str) -> bytes:
    return (FIXDIR / name).read_bytes()


def envelope(http: FakeHttp, name: str, **kw) -> FakeHttp:
    item = module_fixture("google_calendar_ics", name)
    return http.add("GET", URL, status=item["status"], text=item["body"], headers=item["headers"], **kw)


def run(http: FakeHttp, **kw):
    kw.setdefault("options", OPTS)
    return run_module(GoogleCalendarIcs, f"email:{ADDR}", http, **kw)


def test_metadata_and_url():
    cls = GoogleCalendarIcs
    assert (cls.default_enabled, cls.run_on, cls.terms, cls.trust_tier, cls.cache_ttl) == (False, "seeds", "open", "trusted", 0)
    assert URL == "https://calendar.google.com/calendar/ical/user%40example.com/public/basic.ics"


def test_public_holiday_calendar_counts_without_contents():
    http = FakeHttp().add("GET", URL, body=raw("ok.ics"), headers=ICS)
    res = run(http)
    assert res.status is Status.OK, res.error
    cal = res.attributes["public_calendar"]
    assert cal["exists"] is True and cal["event_count"] == 5 and cal["timezone"] == "UTC"
    assert cal["first_event_date"] == "2021-01-01" and cal["complete"] is True
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings]}, ensure_ascii=False)
    for gone in ("Carnaval", "Dia dos Pais", "Feriados no Brasil", "Data comemorativa", "@google.com"):
        assert gone not in dump, gone
    assert "privacy" in res.findings[0].tags
    http.assert_hosts_within(GoogleCalendarIcs)


def test_personal_fields_never_reach_the_output():
    http = FakeHttp().add("GET", URL, body=raw("ok_synthetic_personal.ics"), headers=ICS)
    res = run(http)
    cal = res.attributes["public_calendar"]
    assert cal["event_count"] == 3 and cal["recurring_event_count"] == 1 and cal["timezone"] == "America/Sao_Paulo"
    dump = json.dumps({"a": res.attributes, "raw": res.raw, "f": [f.to_dict() for f in res.findings], "e": res.error})
    for gone in ("Weekly sync", "Medical appointment", "Clinica", "Rua Exemplo", "5555-0102", "other@example.org",
                 "Example Person", "Other Person", "Holiday trip", "Room 42", "event reminder"):
        assert gone not in dump, gone


def test_rrule_is_never_expanded_and_alarms_do_not_count():
    facts = parse_ics_summary(raw("ok_synthetic_personal.ics"))
    assert facts["event_count"] == 3  # the weekly event counts once; the VALARM is ignored


def test_404_is_private_or_nonexistent_never_an_existence_signal():
    res = run(envelope(FakeHttp(), "not_found.json"))
    assert res.status is Status.EMPTY and res.error == ABSENT_TEXT
    assert "private or nonexistent" in res.error and "no account" not in res.error


def test_captcha_and_sign_in_pages_are_blocked_never_bypassed():
    res = run(envelope(FakeHttp(), "blocked_sorry.json"))
    assert res.status is Status.BLOCKED and res.reason_code == "challenge"
    res = run(envelope(FakeHttp(), "login_wall.json"))
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"
    http = FakeHttp().add("GET", URL, status=302, headers={"location": "https://accounts.google.com/ServiceLogin?continue=x"})
    res = run(http)
    assert res.status is Status.BLOCKED and res.reason_code == "login_wall"
    assert len(http.calls) == 1  # the redirect is never followed


def test_errors_and_malformed_bodies_could_not_verify():
    assert run(FakeHttp().add("GET", URL, status=500, text="oops", times=2)).status is Status.ERROR
    assert run(FakeHttp().add("GET", URL, text="<html>hello</html>", headers={"content-type": "text/html"})).status is Status.ERROR
    res = run(FakeHttp().add("GET", URL, body=raw("malformed.ics"), headers=ICS))
    assert res.status is Status.OK and res.attributes["public_calendar"]["complete"] is False
    assert res.attributes["public_calendar"]["event_count"] == 1  # the cut event never counts


def test_one_megabyte_cap():
    big = b"BEGIN:VCALENDAR\r\n" + b"X-FILL:" + b"a" * (1_100_000) + b"\r\nEND:VCALENDAR\r\n"
    facts = parse_ics_summary(big)
    assert facts["truncated"] is True and facts["complete"] is False


def test_pivots_are_refused_and_the_feed_is_never_cached():
    http = FakeHttp()
    res = run(http, is_seed=False, depth=1, provenance=(("domain:example.com", "contact_email", "whois"),))
    assert res.status is Status.SKIPPED and res.reason_code == "privacy" and http.calls == []
    rt = make_runtime(FakeHttp().add("GET", URL, body=raw("ok.ics"), headers=ICS, times=2), cache=True)
    for _ in range(2):
        assert run_module(GoogleCalendarIcs, f"email:{ADDR}", runtime=rt, options=OPTS).status is Status.OK
    assert len(rt.http.transport.calls) == 2  # cond 3: no-store


def test_privacy_pivot_link():
    link = render("email_keys_calendar:gcal_public_ics", Entity.make(T.EMAIL, ADDR))
    assert link is not None and link.privacy is True and link.url == URL
