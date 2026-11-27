"""Live checks of batch p3-G04-1 (emailrep, hunter_io*, pgp_keyservers, proton_pks, google_calendar_ics,
grayhatwarfare); run with V3LUM_LIVE=1.

Benign values only: test@example.com and a never-used @example.com address (IANA documentation domain),
Proton's published role address security@proton.me, the Debian security team's key fingerprint and
Google's public holiday calendar. Keyless sources are called live; the keyed ones (EmailRep, Hunter,
GrayhatWarfare) are never called without company keys - the check asserts NEEDS_KEY before any request
and the policy decision (EmailRep: unknown terms never run). A 403/429/challenge/timeout from this
datacenter egress is an acceptable outcome when the module reports it as could-not-verify, never as an
absence. Nothing personal is printed: assertions only look at structure.
"""

from __future__ import annotations

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core import module as module_mod
from v3lum.core import policy
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity, EntityType
from v3lum.core.models import Status
from v3lum.modules.breach_leak.grayhatwarfare import GrayhatWarfare
from v3lum.modules.email.emailrep import EmailRep
from v3lum.modules.email.google_calendar_ics import GoogleCalendarIcs
from v3lum.modules.email.hunter_io import HunterIoCount
from v3lum.modules.email.pgp_keyservers import PgpKeyservers
from v3lum.modules.email.proton_pks import ProtonPks

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}
OPTS = ScanOptions(purpose="V3LUM live check (benign documentation values)")
DEBIAN_SECURITY_FPR = "0D59D2B15144766A14D241C66BAF400B05C3E651"


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


def decision(cls, value: str, **options):
    module_mod.load_modules()
    etype, _, raw = value.partition(":")
    ent = Entity.make(EntityType.parse(etype), raw)
    pctx = policy.make_context(live_runtime(), ScanOptions(**options), explicit={cls.name}, path="run")
    return policy.decide(cls, ent, pctx, run=RunInfo(entity=ent, is_seed=True))


def test_pgp_keyservers_live_email_seed():
    res = run_module(PgpKeyservers, "email:test@example.com", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        keys = res.attributes["pgp_keyserver_keys"]
        assert keys and all(k["claim"] for k in keys)
        assert {u["email"] for k in keys for u in k["uids"]} <= {"test@example.com"}  # minimised (cond 4)
        assert not [p for p in res.pivots if p.expand]
    assert set(res.hosts) <= {"keyserver.ubuntu.com", "keys.openpgp.org"}


def test_pgp_keyservers_live_fingerprint():
    res = run_module(PgpKeyservers, f"pgp_fingerprint:{DEBIAN_SECURITY_FPR}", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        fprs = {k["fingerprint"] for k in res.attributes["pgp_keyserver_keys"]}
        assert DEBIAN_SECURITY_FPR in fprs


def test_pgp_keyservers_live_never_used_address_is_no_key_published():
    res = run_module(PgpKeyservers, "email:v3lum-live-check-never-used-7f3a@example.com", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.EMPTY:
        assert "no key published on" in res.error


def test_proton_pks_live_role_address():
    res = run_module(ProtonPks, "email:security@proton.me", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        fact = res.attributes["proton_key"]
        assert fact["published"] is True and fact["earliest_created"] and all(len(k["fingerprint"]) in (40, 64) for k in fact["keys"])
    assert set(res.hosts) <= {"api.protonmail.ch", "dns.google", "cloudflare-dns.com"}


def test_proton_pks_live_non_proton_domain_makes_no_keyserver_call():
    res = run_module(ProtonPks, "email:test@example.com", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.SKIPPED, Status.ERROR}, (res.status, res.error)
    assert "api.protonmail.ch" not in res.hosts


def test_google_calendar_ics_live_404_is_private_or_nonexistent():
    res = run_module(GoogleCalendarIcs, "email:test@example.com", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.EMPTY:
        assert "private or nonexistent" in res.error


def test_google_calendar_ics_live_public_holiday_calendar():
    # Google's public 'Feriados no Brasil' calendar id (a public calendar, not a person)
    res = run_module(GoogleCalendarIcs, "email:pt-br.brazilian#holiday@group.v.calendar.google.com", runtime=live_runtime(), options=OPTS)
    assert res.status in {Status.OK, Status.EMPTY, Status.SKIPPED} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        cal = res.attributes["public_calendar"]
        assert cal["exists"] and cal["event_count"] > 0 and cal["first_event_date"]


def test_keyed_sources_need_keys_and_emailrep_never_runs_under_corporate():
    for cls, value in ((EmailRep, "email:someone@example.com"), (HunterIoCount, "domain:example.com"),
                       (GrayhatWarfare, "keyword:example")):
        http = FakeHttp()
        res = run_module(cls, value, http, options=OPTS, tlp="green")
        assert res.status is Status.NEEDS_KEY, (cls.name, res.status, res.error)
        assert http.calls == []
    refused = decision(EmailRep, "email:someone@example.com", purpose="live check")
    assert not refused.allowed and refused.reason_code in {"licence", "tlp", "needs_key", "privacy"}
