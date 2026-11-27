"""Live checks of batch p9-G13-4 (nuclei_runner P369, dns_bruteforce P370); run with V3LUM_LIVE=1.

These are TARGET-CONTACT (ACTIVE) modules, so they NEVER contact a real organisation's hosts from a
live check (we hold no authorization for any). The live traffic here is:

* ``nuclei_runner``: the pinned allow-list is checked against the real nuclei-templates release it
  pins (raw.githubusercontent.com, the proposal's own source host): every reviewed template is
  downloaded at the pinned tag, must hash to its pinned SHA-256 and must pass the FC8 gate over its
  real content (the CI test over the pinned set). No target is scanned; nuclei is not installed here,
  so the run path is asserted only as its offline UNAVAILABLE 'package' outcome.
* ``dns_bruteforce``: a handful of benign DoH resolutions through the core public resolvers - the
  wildcard profile of the IANA documentation zone ``example.com`` (3 random labels) and the existence
  check of ``www.example.com`` - proving the FC5 logic against real resolvers. No brute-force run.

A 403/429/challenge/timeout from this datacenter egress is an acceptable outcome (skip, or the
helper reports 'could not verify', never an absence)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import requests

from v3lum.config import Config
from v3lum.core.context import RunInfo, Runtime, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Status
from v3lum.core.scope import Scope
from v3lum.modules.pentest_recon import g134_parsers as P
from v3lum.modules.pentest_recon.dns_bruteforce import DnsBruteforce, _Run
from v3lum.modules.pentest_recon.nuclei_runner import NucleiRunner

pytestmark = pytest.mark.live

REF = "PENTEST-2026-042"
SCOPE = Scope.from_dict({
    "authorization_ref": REF,
    "owner": "ACME S.A.",
    "contacts": ["soc@acme.example"],
    "ticket": "SEC-1",
    "window_start": "2026-01-01T00:00:00Z",
    "window_end": "2099-12-31T23:59:59Z",
    "targets": {"domains": ["example.com", "*.example.com"]},
})
ALLOWLIST = Path(__file__).resolve().parents[2] / "v3lum" / "data" / "nuclei_runner" / "allowlist.json"
TEMPLATES_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{release}/{path}"


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def test_nuclei_runner_without_a_binary_is_unavailable_package_offline(tmp_path, monkeypatch):
    """No network: without a nuclei binary -> UNAVAILABLE 'package' (never an empty result)."""
    monkeypatch.setenv("PATH", str(tmp_path))
    rt = live_runtime()
    ent = Entity.make(T.IPV4, "93.184.216.34")
    options = ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=SCOPE)
    ctx = rt.context(NucleiRunner, options, run=RunInfo(entity=ent, case_id="live"))
    res = NucleiRunner().run(ent, ctx)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "package"


def test_the_pinned_templates_match_the_real_release_and_pass_the_gate():
    """FC4/FC8 over the real pinned set: every reviewed template at the pinned release hashes to its pin
    and passes the gate (all tags governing, GET/HEAD, http/ssl/dns, no OAST, no exploit confirmation)."""
    allow = json.loads(ALLOWLIST.read_text())
    pins = NucleiRunner._pins(allow)
    assert pins and set(pins) == set(allow["reviewed_ids"])
    metas = []
    for tid, pin in sorted(pins.items()):
        url = TEMPLATES_URL.format(release=allow["release"], path=pin["path"])
        try:
            resp = requests.get(url, timeout=20)
        except requests.RequestException as exc:
            pytest.skip(f"raw.githubusercontent.com unreachable from this egress: {type(exc).__name__}")
        if resp.status_code in (403, 429) or resp.status_code >= 500:
            pytest.skip(f"raw.githubusercontent.com refused from this egress: HTTP {resp.status_code}")
        assert resp.status_code == 200, (tid, resp.status_code)
        assert hashlib.sha256(resp.content).hexdigest() == pin["sha256"], f"{tid}: upstream bytes differ from the pin"
        meta = P.parse_template_meta(resp.content)
        assert meta["id"] == tid
        metas.append(meta)
    audit = P.audit_template_set(metas, frozenset(pins))
    assert audit["ok"], audit["rejected"]


def test_dns_bruteforce_existence_logic_against_real_resolvers():
    """A few benign DoH resolutions: example.com has no wildcard, www.example.com exists."""
    rt = live_runtime()
    ent = Entity.make(T.DOMAIN, "example.com")
    options = ScanOptions(mode=Opsec.ACTIVE, authorization_ref=REF, scope=SCOPE)
    ctx = rt.context(DnsBruteforce, options, run=RunInfo(entity=ent, case_id="live"))
    assert DnsBruteforce._resolver_problem(ctx) == ""
    run = _Run(ctx, "example.com", SCOPE)
    profile = run.profile("example.com")
    if profile["undecidable"]:
        pytest.skip("no DoH resolver answered from this egress (could not verify, never 'absent')")
    assert profile["is_wildcard"] is False  # random labels under example.com do not exist
    run.check("www.example.com", profile)
    if run.unknown:
        pytest.skip("www.example.com could not be verified from this egress")
    assert "www.example.com" in run.found and run.found["www.example.com"]
    run.check("v3l-nonexistent-9x7q2.example.com", profile)
    assert "v3l-nonexistent-9x7q2.example.com" not in run.found
    assert run.queries <= 12  # a handful of queries, paced at <= 10/s
