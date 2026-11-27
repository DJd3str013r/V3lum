"""Live checks of batch p3-G04-2 (intelx_metadata, intelx_phonebook, leak_lookup_public, the Pwned Passwords
helper); run with V3LUM_LIVE=1.

* Pwned Passwords (keyless): HIBP's documented example 'password' (prefix 5BAA6) and a random fixture-only
  value through the core HTTP client, the way the core wiring will call the helper (prefix only,
  Add-Padding, no-store).
* Intelligence X and Leak-Lookup need company keys that do not exist yet: the modules are checked to end
  NEEDS_KEY before any request, and each provider is probed once WITHOUT a key and WITHOUT any
  investigated value (an unknown search id; an empty form) to confirm the recorded refusal shapes are
  still what the module and the provider error markers expect (401; HTTP 200 error 'true'). A
  403/429/challenge/timeout from this datacenter egress is an acceptable outcome (could not verify).
"""

from __future__ import annotations

import uuid

import pytest

from tests.fakes import FakeHttp, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.http import HttpError, NetworkError
from v3lum.core.models import Status
from v3lum.core.orgprofile import OrgProfile
from v3lum.modules.breach_leak.intelx_metadata import IntelxMetadata, IntelxPhonebook, intelx_url
from v3lum.modules.breach_leak.leak_lookup_public import SEARCH_URL, LeakLookupPublic
from v3lum.modules.breach_leak.pwned_passwords_internal import http_fetch, lookup

pytestmark = pytest.mark.live
OWN = {"domains": [{"name": "example.com", "verification": "attested", "attested_by": "live check", "attested_date": "2026-11-26"}]}
OPTS = ScanOptions(purpose="V3LUM live check (benign documentation values)")


def live_runtime() -> Runtime:
    return Runtime(Config(), no_cache=True)


class CoreGet:
    """The core client behind a `.get()` - what the P141 wiring hands the helper."""

    def __init__(self, rt: Runtime) -> None:
        self.rt = rt

    def get(self, url, **kw):
        return self.rt.http.request("GET", url, module="pwned_passwords_internal", **kw)


def test_pwned_passwords_live_documented_example_and_random_value():
    fetch = http_fetch(CoreGet(live_runtime()))
    res = lookup("password", fetch, finding_kind="password", enabled=True)
    if res.count is None:  # could not verify from this egress: never a 0
        assert "could not verify" in res.reason
        return
    assert res.count > 1_000_000 and res.note.startswith("appears ") and "CC BY 4.0" in res.attribution
    other = lookup(f"v3lum-live-{uuid.uuid4()}", fetch, finding_kind="password", enabled=True)
    assert other.count is None or other.count >= 0


def test_intelx_modules_need_a_key_before_any_request():
    http = FakeHttp()
    res = run_module(IntelxMetadata, "email:someone@example.com", http, org_profile=OrgProfile.from_dict(OWN), options=OPTS, keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []
    res = run_module(IntelxPhonebook, "domain:example.com", http, org_profile=OrgProfile.from_dict(OWN), keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []


def test_intelx_keyless_refusal_shape_live():
    _method, url = intelx_url("intelligent_result", id=str(uuid.uuid4()), limit=1)  # unknown id, no selector sent
    try:
        resp = live_runtime().http.request("GET", url, source="intelx.search", ttl=0, allow_redirects=False, module="intelx_metadata")
    except (HttpError, NetworkError) as exc:  # refused or unreachable from this egress: could not verify
        pytest.skip(f"Intelligence X not reachable from this egress: {type(exc).__name__}")
    assert resp.status in (401, 402, 403, 429), resp.status  # 401 recorded 2026-11-25 (needs a key)


def test_leak_lookup_module_needs_a_key_and_the_error_body_is_never_empty_live():
    http = FakeHttp()
    res = run_module(LeakLookupPublic, "email:someone@example.com", http, org_profile=OrgProfile.from_dict(OWN), keys={})
    assert res.status is Status.NEEDS_KEY and http.calls == []
    form = {"key": "", "type": "email_address", "query": ""}  # no key and no value: only the refusal shape
    try:
        resp = live_runtime().http.request("POST", SEARCH_URL, data=form, source="leaklookup.search", allow_redirects=False,
                                           module="leak_lookup_public")
    except (HttpError, NetworkError) as exc:
        pytest.skip(f"Leak-Lookup not reachable from this egress: {type(exc).__name__}")
    if resp.status == 200:
        assert resp.classification is not None and resp.classification.status in ("error", "quota", "rate_limited")
        assert resp.classification.marker_id and resp.classification.marker_id.startswith("leaklookup_")
    else:
        assert resp.status in (403, 429, 503), resp.status
