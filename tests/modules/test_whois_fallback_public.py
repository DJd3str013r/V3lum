"""whois_fallback_public (P343 FC2): the public who-dat.as93.net instance as a separate, opt-in module.

Fixtures (tests/fixtures/whois_fallback_public/): live who-dat answers recorded from the public
instance on 2026-11-26 (example.com, google.com, registro.br with the natural-person tech contact
replaced by documentation values, and a subdomain query answered for example.com), plus synthetic
shapes that could not be observed with benign values (not registered, error in a 200, 429, Vercel
checkpoint). The IANA bootstrap comes from tests/fixtures/whois_fallback/ (P003 shared helper).
"""

from __future__ import annotations

import json

from tests.fakes import FakeHttp, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core import policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.http import NetworkError
from v3lum.core.models import Status
from v3lum.core.tlp import TLP
from v3lum.modules.domain_dns.whois_fallback import WhoisFallbackPublic, _public_selftest, whodat_from_flat_extract

NAME = "whois_fallback_public"
BOOT_URL = "https://data.iana.org/rdap/dns.json"
URL = "https://who-dat.as93.net/{domain}"
EXPLICIT = ScanOptions(include={NAME})


def fx(name: str):
    return module_fixture(NAME, name)


def boot(http: FakeHttp) -> FakeHttp:
    http.add("GET", BOOT_URL, json=module_fixture("whois_fallback", "rdap_bootstrap_dns_min.json"))
    return http


def exchange(http: FakeHttp, url: str, doc: dict) -> None:
    resp = doc["response"]
    headers = {k: v for k, v in (resp.get("headers") or {}).items() if v is not None}
    http.add("GET", url, status=resp["status"], body=(resp.get("body") or "").encode(), headers=headers)


def yandex_record() -> dict:
    gap = module_fixture("whois_fallback", "gaps__whois_fallback.json")
    return whodat_from_flat_extract(next(r for r in gap["requests"] if r["label"] == "whodat_yandex_ru")["body"])


# ------------------------------------------------------------------ metadata and policy (FC2, A3/A8)
def test_metadata_unknown_tier_opt_in_and_never_above_green():
    cls = WhoisFallbackPublic
    assert cls.default_enabled is False and cls.trust_tier == "unknown" and cls.max_tlp is TLP.GREEN
    assert cls.terms == "open" and cls.disclosure == "third_party" and cls.provider == "as93"
    assert cls.hosts == ("who-dat.as93.net", "data.iana.org") and cls.daily_quota and cls.min_interval >= 2.0


def test_policy_gate_excludes_it_at_amber_and_needs_allow_unknown_at_clear():
    rt = make_runtime(FakeHttp())
    ent = Entity.make(T.DOMAIN, "yandex.ru")

    def decide(options: ScanOptions, tlp: str, explicit=(NAME,)):
        pctx = policy.make_context(rt, options, explicit=explicit)
        return policy.decide(WhoisFallbackPublic, ent, pctx, run=RunInfo(entity=ent, tlp=tlp))

    plain = decide(ScanOptions(), "amber", explicit=())
    assert not plain.allowed and plain.reason_code == "not_default"
    amber = decide(ScanOptions(include={NAME}), "amber")
    assert not amber.allowed and amber.reason_code == "tlp"
    clear = decide(ScanOptions(include={NAME}, tlp="clear"), "clear")
    assert not clear.allowed and clear.reason_code == "tier"
    allowed = decide(ScanOptions(include={NAME}, tlp="clear", allow_unknown=True), "clear")
    assert allowed.allowed


# ------------------------------------------------------------------ FC1 applicability (bootstrap only)
def test_tld_with_rdap_is_not_applicable_and_never_sent():
    http = boot(FakeHttp())
    res = run_module(WhoisFallbackPublic, "domain:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert "who-dat.as93.net" not in http.hosts()


# ------------------------------------------------------------------ answers
def test_recorded_yandex_record_through_the_public_instance():
    http = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), json=yandex_record())
    res = run_module(WhoisFallbackPublic, "domain:yandex.ru", http)
    assert res.status is Status.OK and res.attributes["registration_via"] == "whodat_public"
    assert res.attributes["registrar"] == "Regional Network Information Center" and res.attributes["registration_source"] == "rdap"
    http.assert_hosts_within(WhoisFallbackPublic)


def test_live_registro_br_answer_on_explicit_selection_drops_contacts_and_never_pivots_cnpj():
    http = boot(FakeHttp()).add("GET", URL.format(domain="registro.br"), json=fx("whodat_registro_br.json"))
    assert run_module(WhoisFallbackPublic, "domain:registro.br", http).status is Status.SKIPPED  # not selected explicitly
    res = run_module(WhoisFallbackPublic, "domain:registro.br", http, options=EXPLICIT)
    assert res.status is Status.OK and res.attributes["nameservers"] == ["a.dns.br", "b.dns.br", "c.dns.br", "d.dns.br", "e.dns.br"]
    text = json.dumps(res.to_dict(), ensure_ascii=False) + json.dumps(res.raw, ensure_ascii=False)
    for value in ("Example Tech Contact", "tech-contact@example.com", "Núcleo", "05.506.560/0001-36"):
        assert value not in text
    assert {p.entity.type for p in res.pivots} == {T.DOMAIN} and all(not p.expand for p in res.pivots)


def test_live_example_com_answer_shape_with_a_role_abuse_mailbox():
    # .com has RDAP: the module never sends it; the live answer is parsed through the selftest instead
    http = FakeHttp().add("GET", URL.format(domain="example.com"), json=fx("whodat_example_com.json"))
    result = _public_selftest(make_ctx(WhoisFallbackPublic, http))
    assert result.status == "ok"
    google = FakeHttp().add("GET", URL.format(domain="example.com"), json=fx("whodat_google_com.json"))
    assert _public_selftest(make_ctx(WhoisFallbackPublic, google)).status == "dead"  # answered for another name


def test_not_registered_and_subdomain_answers():
    record = dict(fx("whodat_not_registered.json"), domain="yandex.ru", query="yandex.ru")
    http = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), json=record)
    res = run_module(WhoisFallbackPublic, "domain:yandex.ru", http)
    assert res.status is Status.EMPTY and "not registered according to who-dat.as93.net" in res.error
    http2 = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), json=fx("whodat_subdomain_reduced.json"))
    res2 = run_module(WhoisFallbackPublic, "domain:yandex.ru", http2)
    assert res2.status is Status.ERROR and "instead of yandex.ru" in res2.error and not res2.attributes


# ------------------------------------------------------------------ rule 5: could not verify
def test_rate_limit_checkpoint_error_in_200_404_and_garbage_are_never_absences():
    http = boot(FakeHttp())
    exchange(http, URL.format(domain="yandex.ru"), fx("whodat_rate_limited.http.json"))
    assert run_module(WhoisFallbackPublic, "domain:yandex.ru", http).status is Status.RATE_LIMITED
    http2 = boot(FakeHttp())
    exchange(http2, URL.format(domain="yandex.ru"), fx("whodat_blocked.http.json"))
    res2 = run_module(WhoisFallbackPublic, "domain:yandex.ru", http2)
    assert res2.status is Status.BLOCKED and res2.reason_code == "challenge"
    http3 = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), json=fx("whodat_error_in_200.json"))
    res3 = run_module(WhoisFallbackPublic, "domain:yandex.ru", http3)
    assert res3.status is Status.ERROR and "error in an HTTP 200" in res3.error
    http4 = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), status=404, json={"error": "not found"})
    assert run_module(WhoisFallbackPublic, "domain:yandex.ru", http4).status is Status.ERROR  # never 'not registered'
    http5 = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), text="<html><body>maintenance</body></html>")
    assert run_module(WhoisFallbackPublic, "domain:yandex.ru", http5).status is Status.ERROR


def test_server_errors_and_timeouts_are_errors_never_absences():
    http = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), status=503, text="Service Unavailable")
    res = run_module(WhoisFallbackPublic, "domain:yandex.ru", http)
    assert res.status is Status.ERROR and not res.attributes
    assert http.urls().count(URL.format(domain="yandex.ru")) == 2  # the profile's single retry, then could not verify
    http2 = boot(FakeHttp()).add("GET", URL.format(domain="yandex.ru"), error=NetworkError("ReadTimeout contacting who-dat.as93.net: timed out", kind="ReadTimeout"))
    res2 = run_module(WhoisFallbackPublic, "domain:yandex.ru", http2)
    assert res2.status is Status.ERROR and not res2.attributes
