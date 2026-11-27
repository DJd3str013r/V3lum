"""Live checks of batch p3-G01-2 (whois_history_keyed P022, ooni P023); run with V3LUM_LIVE=1.

Keyless sources only, benign public values: the OONI API for www.google.com (probes in BR plus CN as the case
country) and example.com. A 403/429/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify, never as an absence. whois_history_keyed needs company-paid keys: without them it
must end NEEDS_KEY before any request (no keyed API is called from here).
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import run_module
from v3lum.config import Config
from v3lum.core.context import Runtime
from v3lum.core.models import Status
from v3lum.modules.domain_dns.ooni import ISO_3166_ALPHA2, Ooni
from v3lum.modules.domain_dns.whois_history_keyed import WhoisHistoryKeyed

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR}


def live_runtime(**settings) -> Runtime:
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def outcome(res) -> str:
    return f"{res.status.value} {res.reason_code or ''} {res.error[:300]} {json.dumps(res.attributes.get('ooni_censorship'), default=str)[:900]}"


def test_ooni_www_google_com_br_and_cn():
    res = run_module(Ooni, "domain:www.google.com", runtime=live_runtime(ooni_case_country="CN"))
    print("ooni www.google.com:", outcome(res))
    if res.status in COULD_NOT_VERIFY:
        assert "could not verify" in res.error, outcome(res)
        return
    assert res.status is Status.OK, outcome(res)
    by_cc = {s["probe_cc"]: s for s in res.attributes["ooni_censorship"]}
    assert "BR" in by_cc and set(by_cc) <= ISO_3166_ALPHA2
    for s in by_cc.values():
        assert s["state"] in {"no_measurements", "confirmed_blocking", "anomalies_consistent", "anomalies_sporadic", "failures_only",
                              "no_anomaly", "could_not_verify"}
        if s["state"] != "could_not_verify":
            assert s["measurement_count"] >= s["anomaly_count"] >= 0
            assert all(u.startswith("https://api.ooni.io/") for u in s["evidence"])
    for f in res.findings:  # context only, never scored (P023 cond 2)
        assert f.severity.name == "INFO" and "context_only" in f.tags
    assert res.attributes["data_attribution"].startswith("Censorship measurements: OONI")
    assert not res.pivots


def test_ooni_example_com_is_empty_or_measured_never_not_blocked():
    res = run_module(Ooni, "domain:example.com", runtime=live_runtime())
    print("ooni example.com:", outcome(res))
    assert res.status in COULD_NOT_VERIFY | {Status.OK, Status.EMPTY}, outcome(res)
    if res.status is Status.EMPTY:
        assert "no evidence either way" in res.error


def test_whois_history_keyed_without_keys_is_needs_key_without_requests():
    res = run_module(WhoisHistoryKeyed, "domain:example.com", runtime=live_runtime())
    print("whois_history_keyed example.com:", res.status.value, res.error)
    assert res.status is Status.NEEDS_KEY
    assert not res.hosts
