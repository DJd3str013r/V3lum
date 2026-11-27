"""Live checks of batch p2-G01-4 (saas_verification_tokens P342, whois_fallback and
whois_fallback_public P343); run with V3LUM_LIVE=1.

Keyless sources and benign public values only: google.com / example.com TXT through the core DoH
resolvers, the IANA RDAP bootstrap and the IANA root zone page of .de for google.de (.de has no RDAP
service), and the public who-dat.as93.net instance for google.ru (opt-in module, called here at
TLP:CLEAR with --allow-unknown semantics) plus its benign self-test on example.com.

A 403/429/challenge/reset/timeout from this datacenter egress is an acceptable outcome when the module
reports it as could-not-verify (BLOCKED / RATE_LIMITED / QUOTA / ERROR / UNAVAILABLE), never as an
absence. Port 43 needs the core whois43 helper, which this build does not have: whois_fallback ends
UNAVAILABLE 'offline' with the registry WHOIS server taken from the live IANA page.
"""

from __future__ import annotations

import json

import pytest

from tests.fakes import make_ctx, run_module
from v3lum.config import Config
from v3lum.core.context import Runtime, ScanOptions
from v3lum.core.models import Status
from v3lum.modules.domain_dns.saas_verification_tokens import SaasVerificationTokens, split_txt_key
from v3lum.modules.domain_dns.whois_fallback import WhoisFallback, WhoisFallbackPublic, _public_selftest, _root_db_selftest

pytestmark = pytest.mark.live
COULD_NOT_VERIFY = {Status.BLOCKED, Status.RATE_LIMITED, Status.QUOTA, Status.ERROR, Status.UNAVAILABLE}


def live_runtime(**settings):
    cfg = Config()
    cfg.settings.update(settings)
    return Runtime(cfg, no_cache=True)


def reported(res) -> str:
    parts = [json.dumps(res.attributes, default=str), res.error or ""]
    for f in res.findings:
        parts += [f.title, f.description, f.criterion, json.dumps(f.data, default=str)]
    return "\n".join(parts)


# ------------------------------------------------------------------ saas_verification_tokens (P342)
def test_saas_verification_tokens_google_com():
    res = run_module(SaasVerificationTokens, "domain:google.com", runtime=live_runtime())
    assert res.status in {Status.OK} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is not Status.OK:
        return
    assert res.attributes["saas_vendors"] and res.pivots == []
    assert res.findings[0].title == "SaaS verification records present"
    values = []
    for record in res.raw["txt_answer"]["records"]:
        key, _sep, value = split_txt_key(record)
        if key and len(value) >= 12 and not record.lower().startswith("v=spf1"):
            values.append(value)
    text = reported(res)
    assert values and not [v for v in values if v in text]  # FC4: values stay in the evidence
    assert set(res.hosts) <= {"dns.google", "cloudflare-dns.com"}


def test_saas_verification_tokens_example_com_is_empty():
    res = run_module(SaasVerificationTokens, "domain:example.com", runtime=live_runtime())
    assert res.status in {Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)


# ------------------------------------------------------------------ whois_fallback (P343)
def test_whois_fallback_google_com_is_not_applicable_from_the_live_bootstrap():
    res = run_module(WhoisFallback, "domain:google.com", runtime=live_runtime())
    assert res.status in {Status.SKIPPED} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.SKIPPED:
        assert res.reason_code == "not_applicable" and "www.iana.org" not in res.hosts


def test_whois_fallback_google_de_reaches_the_registry_server_then_port43_is_unavailable():
    res = run_module(WhoisFallback, "domain:google.de", runtime=live_runtime())
    assert res.status in COULD_NOT_VERIFY | {Status.OK, Status.EMPTY}, (res.status, res.error)
    if res.status is Status.UNAVAILABLE and res.reason_code == "offline":
        assert res.attributes.get("registry_whois_server") == "whois.denic.de"
        assert "whois43" in res.error
    assert set(res.hosts) <= {"www.iana.org", "data.iana.org"}


def test_whois_fallback_doctor_selftest():
    ctx = make_ctx(WhoisFallback, runtime=live_runtime())
    result = _root_db_selftest(ctx)
    assert result.status in ("ok", "blocked", "quota"), result


# ------------------------------------------------------------------ whois_fallback_public (P343 FC2, opt-in)
def test_whois_fallback_public_google_ru():
    options = ScanOptions(include={"whois_fallback_public"}, include_disabled=True, allow_unknown=True, tlp="clear")
    res = run_module(WhoisFallbackPublic, "domain:google.ru", runtime=live_runtime(), options=options, tlp="clear")
    assert res.status in {Status.OK, Status.EMPTY} | COULD_NOT_VERIFY, (res.status, res.error)
    if res.status is Status.OK:
        assert res.attributes["registration_via"] == "whodat_public" and res.attributes["registered"] is True
        assert res.attributes.get("created") or res.attributes.get("nameservers")
        assert all(p.relation == "nameserver" and not p.expand for p in res.pivots)
        assert not any("@" in str(v) for k, v in res.attributes.items() if k != "abuse_contact")
    assert set(res.hosts) <= {"who-dat.as93.net", "data.iana.org"}


def test_whois_fallback_public_selftest_example_com():
    ctx = make_ctx(WhoisFallbackPublic, runtime=live_runtime())
    result = _public_selftest(ctx)
    assert result.status in ("ok", "blocked", "quota", "dead"), result
