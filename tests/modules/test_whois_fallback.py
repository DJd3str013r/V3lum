"""whois_fallback (P343): WHOIS for TLDs without RDAP - self-hosted who-dat, IANA root zone database,
port 43 through the core whois43 helper.

Fixtures (tests/fixtures/whois_fallback/): the recorded research sample gaps__whois_fallback (who-dat
json_extract records for yandex.ru, registro.br and example.com; IANA root-zone snippets for .ru/.cn),
the live IANA RDAP bootstrap trimmed to com/net/org/br/uk and the http-only kg, live IANA root-zone
pages of .ru/.br/.gr/.com cut to their 'Additional Information' rows, the live whois.iana.org answer
for example.com, and port-43 texts in the documented layouts of registro.br, RIPN, CNNIC, DENIC and
Verisign (synthetic: port 43 is unreachable from the recording egress; each starts with a '%
SYNTHETIC FIXTURE' line, values are documentation values or public registry facts). who-dat answers
come from tests/fixtures/whois_fallback_public/ (the self-hosted instance runs the same software).

The core whois43 helper does not exist in this build: the module reports UNAVAILABLE 'offline' until
it lands; tests of the port-43 path install a fake helper on the socket connector.
"""

from __future__ import annotations

import copy
import json

import pytest

from tests.fakes import FakeClock, FakeHttp, fixture, make_ctx, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.http import NetworkError, OfflineError
from v3lum.core.models import Status
from v3lum.core.net import Connector
from v3lum.core.tlp import TLP
from v3lum.modules.domain_dns.whois_fallback import (
    WHOIS43_CAP_BYTES,
    WHOIS43_TIMEOUT_S,
    WhoisFallback,
    _root_db_selftest,
    applicability,
    decode_whois,
    domain_age_days,
    is_thin,
    merge_referral,
    minimise_whois_text,
    next_referral,
    norm_date,
    parse_iana_root_db,
    parse_whodat,
    parse_whois_text,
    whodat_from_flat_extract,
    whodat_lookup,
    whois_query,
    whois_referral,
    whois_text_marker,
)

NAME = "whois_fallback"
BOOT_URL = "https://data.iana.org/rdap/dns.json"
IANA_URL = "https://www.iana.org/domains/root/db/{tld}.html"
WHODAT = "https://whodat.example.org"
EXPLICIT = ScanOptions(include={NAME})
NIC_BR_CNPJ = ("05.506.560/0001-36", "05506560000136", "05506560")


def fx(name: str):
    return module_fixture(NAME, name)


def public_fx(name: str):
    return module_fixture("whois_fallback_public", name)


def boot(http: FakeHttp, data=None) -> FakeHttp:
    http.add("GET", BOOT_URL, json=fx("rdap_bootstrap_dns_min.json") if data is None else data)
    return http


def iana(http: FakeHttp, tld: str, name: str | None = None) -> FakeHttp:
    http.add("GET", IANA_URL.format(tld=tld), text=fx(name or f"iana_root_{tld}.html"))
    return http


def exchange(http: FakeHttp, url: str, doc: dict, *, times: int | None = None) -> None:
    resp = doc["response"]
    headers = {k: v for k, v in (resp.get("headers") or {}).items() if v is not None}
    http.add("GET", url, status=resp["status"], body=(resp.get("body") or "").encode(), headers=headers, times=times)


def gap_record(label: str) -> dict:
    gap = fx("gaps__whois_fallback.json")
    return next(r for r in gap["requests"] if r["label"] == label)


def http_only_com_bootstrap() -> dict:
    """The live bootstrap with .com's service downgraded to http:// (synthetic, documented): the
    'rdap_http_only' path, so example.com can carry the referral case."""
    data = copy.deepcopy(fx("rdap_bootstrap_dns_min.json"))
    for svc in data["services"]:
        if svc[0] == ["com"]:
            svc[1] = ["http://rdap.verisign.com/com/v1/"]
    return data


def dumped(res) -> str:
    """Everything the result carries (report-facing fields AND the evidence payload)."""
    return json.dumps(res.to_dict(), default=str, ensure_ascii=False) + json.dumps(res.raw, default=str, ensure_ascii=False)


class FakeWhois43:
    """Stand-in for the requested core helper ``ctx.net.whois43(server, query, *, timeout, max_bytes)``."""

    def __init__(self, answers: dict):
        self.answers = answers
        self.calls: list[tuple[str, str, float, int]] = []

    def __call__(self, server, query, *, timeout, max_bytes):
        self.calls.append((server, query, timeout, max_bytes))
        answer = self.answers[server]
        if isinstance(answer, BaseException):
            raise answer
        return answer.encode("utf-8") if isinstance(answer, str) else answer


@pytest.fixture
def port43(monkeypatch):
    def install(answers: dict) -> FakeWhois43:
        fake = FakeWhois43(answers)
        monkeypatch.setattr(Connector, "whois43", lambda self, server, query, *, timeout, max_bytes: fake(server, query, timeout=timeout, max_bytes=max_bytes), raising=False)
        return fake

    return install


# ------------------------------------------------------------------ metadata
def test_metadata_matches_the_council_decision():
    cls = WhoisFallback
    assert cls.terms == "open" and cls.default_enabled is True and cls.disclosure == "third_party"
    assert cls.trust_tier == "trusted" and cls.max_tlp is TLP.AMBER_STRICT
    assert cls.hosts == ("www.iana.org", "data.iana.org") and cls.provider == "registry_whois"
    assert set(cls.sources) == {"registry_whois.port43", "iana.whois_fallback_root_db", "iana.tlds", "whodat_selfhosted.api"}
    assert "whodat_url" in cls.settings and cls.max_requests <= 10 and cls.daily_quota and cls.min_interval >= 1.0
    assert not cls.publishes_queries and not cls.reuses_queries


# ------------------------------------------------------------------ FC1: applicability from the bootstrap only
def test_fc1_applicability_comes_from_the_p003_bootstrap_helper():
    ctx = make_ctx(WhoisFallback, boot(FakeHttp()), entity="domain:yandex.ru")
    assert applicability(ctx, "yandex.ru").path == "no_rdap"
    assert applicability(ctx, "nic.kg").path == "rdap_http_only"  # http:// only: https downgrade refused
    assert applicability(ctx, "example.com").applies is False
    assert applicability(ctx, "registro.br").applies is False
    assert applicability(ctx, "registro.br", explicit=True).path == "br_second_path"
    assert applicability(ctx, "xn--d1acpjx3f.xn--p1ai").path == "no_rdap"


def test_fc1_rdap_tld_is_not_applicable_and_sends_nothing():
    http = boot(FakeHttp())
    res = run_module(WhoisFallback, "domain:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"
    assert http.hosts() == {"data.iana.org"}  # only the shared bootstrap dataset


def test_fc1_second_br_path_only_on_explicit_selection_of_a_typed_seed():
    http = boot(FakeHttp())
    assert run_module(WhoisFallback, "domain:registro.br", http).status is Status.SKIPPED
    assert run_module(WhoisFallback, "domain:registro.br", http, options=EXPLICIT, is_seed=False, depth=1).status is Status.SKIPPED
    iana(http, "br")
    res = run_module(WhoisFallback, "domain:registro.br", http, options=EXPLICIT)
    assert res.status is Status.UNAVAILABLE and res.raw["path"] == "br_second_path"
    assert res.attributes["registry_whois_server"] == "whois.registro.br"


def test_fc1_unreadable_bootstrap_is_unavailable_never_not_applicable():
    http = FakeHttp().add("GET", BOOT_URL, status=500, text="upstream error")
    res = run_module(WhoisFallback, "domain:yandex.ru", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset" and "bootstrap" in res.error


def test_subdomains_are_not_applicable():
    http = boot(FakeHttp())
    res = run_module(WhoisFallback, "domain:www.yandex.ru", http)
    assert res.status is Status.SKIPPED and not http.calls


# ------------------------------------------------------------------ FC2/FC3: this build (no core whois43 helper)
def test_without_the_core_helper_port43_is_unavailable_with_the_iana_facts():
    http = iana(boot(FakeHttp()), "ru")
    res = run_module(WhoisFallback, "domain:yandex.ru", http)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "offline"
    assert "whois43 helper" in res.error and "could not verify" in res.error
    assert res.attributes == {"registry_whois_server": "whois.tcinet.ru"}
    assert ("Registry website of .ru (manual WHOIS lookup)", "http://www.cctld.ru/en") in res.links
    assert res.source_statuses["registry_whois.port43"]["status"] == "unavailable"
    assert not res.pivots and not res.findings
    http.assert_hosts_within(WhoisFallback)


def test_fc2_iana_root_zone_answer_is_reused_for_7_days():
    clock = FakeClock("2026-11-26T10:00:00Z")
    http = iana(boot(FakeHttp(clock=clock)), "ru")
    rt = make_runtime(http, clock=clock)
    run_module(WhoisFallback, "domain:yandex.ru", runtime=rt)
    run_module(WhoisFallback, "domain:ya.ru", runtime=rt)
    assert http.urls().count(IANA_URL.format(tld="ru")) == 1  # module state, not the HTTP cache
    clock.advance(8 * 86400)
    res = run_module(WhoisFallback, "domain:ya.ru", runtime=rt)
    assert http.urls().count(IANA_URL.format(tld="ru")) == 2 and res.raw["iana_root_db"]["cached"] is False


def test_fc2_tld_without_a_whois_server_is_not_applicable_with_a_manual_link():
    http = iana(boot(FakeHttp()), "gr", "iana_root_gr_no_whois.html")
    res = run_module(WhoisFallback, "domain:example.gr", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable" and "no WHOIS server" in res.error
    assert ("Registry website of .gr (manual WHOIS lookup)", "http://www.gr") in res.links


def test_fc2_iana_404_is_not_applicable_and_never_kept():
    http = boot(FakeHttp())
    exchange(http, IANA_URL.format(tld="ru"), fx("iana_root_not_found.http.json"), times=1)
    res = run_module(WhoisFallback, "domain:yandex.ru", http)
    assert res.status is Status.SKIPPED and "not a delegated TLD" in res.error
    iana(http, "ru")
    res2 = run_module(WhoisFallback, "domain:yandex.ru", http)  # a 404 is never kept in the module state
    assert res2.attributes == {"registry_whois_server": "whois.tcinet.ru"}


def test_fc2_iana_challenge_rate_limit_and_wrong_page():
    http2 = boot(FakeHttp())
    exchange(http2, IANA_URL.format(tld="ru"), fx("iana_root_challenge.http.json"))
    res2 = run_module(WhoisFallback, "domain:yandex.ru", http2)
    assert res2.status is Status.BLOCKED and res2.reason_code == "challenge" and not res2.attributes
    http3 = boot(FakeHttp()).add("GET", IANA_URL.format(tld="ru"), status=429, text="slow down")
    assert run_module(WhoisFallback, "domain:yandex.ru", http3).status is Status.RATE_LIMITED
    http4 = iana(boot(FakeHttp()), "ru", "iana_root_com.html")  # the .com page served for .ru
    res4 = run_module(WhoisFallback, "domain:yandex.ru", http4)
    assert res4.status is Status.ERROR and "unexpected page" in res4.error


# ------------------------------------------------------------------ FC2: the self-hosted who-dat instance first
def test_fc2_fc6_selfhosted_whodat_answers_first_with_the_recorded_research_record():
    record = whodat_from_flat_extract(gap_record("whodat_yandex_ru")["body"])
    http = boot(FakeHttp()).add("GET", f"{WHODAT}/yandex.ru", json=record)
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": WHODAT})
    assert res.status is Status.OK
    attrs = res.attributes
    assert attrs["registrar"] == "Regional Network Information Center"
    assert attrs["created"] == "1997-09-23T09:45:07Z" and attrs["expires"] == "2027-09-30T21:00:00Z"
    assert attrs["registration_source"] == "rdap" and attrs["registration_server"] == "https://cctld.ru/tci-ripn-rdap"
    assert attrs["registration_via"] == "whodat" and attrs["registered"] is True and attrs["domain_age_days"] > 10000
    assert IANA_URL.format(tld="ru") not in http.urls()  # the port-43 path is not needed
    http.assert_hosts_within(WhoisFallback)  # the whodat_url host comes from hosts_from_settings


def test_fc2_whodat_failure_falls_back_to_the_port43_path(port43):
    http = iana(boot(FakeHttp()), "ru")
    exchange(http, f"{WHODAT}/yandex.ru", public_fx("whodat_rate_limited.http.json"))
    fake = port43({"whois.tcinet.ru": fx("whois43_ripn_ru.txt")})
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": WHODAT})
    assert res.status is Status.OK and res.attributes["registration_via"] == "whois43"
    assert fake.calls == [("whois.tcinet.ru", "yandex.ru", WHOIS43_TIMEOUT_S, WHOIS43_CAP_BYTES)]


def test_whodat_and_port43_failures_report_the_first_and_keep_both_source_statuses():
    http = iana(boot(FakeHttp()), "ru")
    exchange(http, f"{WHODAT}/yandex.ru", public_fx("whodat_rate_limited.http.json"))
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": WHODAT})
    assert res.status is Status.RATE_LIMITED
    assert res.source_statuses["whodat_selfhosted.api"]["status"] == "rate_limited"
    assert res.source_statuses["registry_whois.port43"]["reason_code"] == "offline"


def test_selfhosted_whodat_refusals_and_bad_configuration():
    http = iana(boot(FakeHttp()), "ru")
    exchange(http, f"{WHODAT}/yandex.ru", fx("whodat_auth_required.http.json"))
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": WHODAT})
    assert res.status is Status.BLOCKED and "sends no credentials" in res.error
    http2 = iana(boot(FakeHttp()), "ru")
    res2 = run_module(WhoisFallback, "domain:yandex.ru", http2, settings={"whodat_url": "http://whodat.example.org"})
    assert res2.status is Status.SKIPPED and res2.reason_code == "config"
    assert not [u for u in http2.urls() if "whodat" in u]


def test_whodat_url_pointing_at_the_public_instance_is_never_used():
    http = iana(boot(FakeHttp()), "ru")  # no route for who-dat.as93.net: a request would fail the test
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": "https://who-dat.as93.net"})
    assert res.source_statuses["whodat_selfhosted.api"]["reason_code"] == "policy"
    assert "who-dat.as93.net" not in http.hosts()


def test_whodat_not_registered_error_in_200_and_bare_404():
    http = boot(FakeHttp()).add("GET", f"{WHODAT}/yandex.ru", json=dict(public_fx("whodat_not_registered.json"), domain="yandex.ru", query="yandex.ru"))
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"whodat_url": WHODAT})
    assert res.status is Status.EMPTY and "not registered according to" in res.error and "registered" not in res.attributes
    http2 = iana(boot(FakeHttp()), "ru").add("GET", f"{WHODAT}/yandex.ru", json=public_fx("whodat_error_in_200.json"))
    res2 = run_module(WhoisFallback, "domain:yandex.ru", http2, settings={"whodat_url": WHODAT})
    assert res2.source_statuses["whodat_selfhosted.api"]["status"] == "error" and "error in an HTTP 200" in res2.error
    http3 = iana(boot(FakeHttp()), "ru").add("GET", f"{WHODAT}/yandex.ru", status=404, json={"detail": "not found"})
    res3 = run_module(WhoisFallback, "domain:yandex.ru", http3, settings={"whodat_url": WHODAT})
    assert res3.status is Status.ERROR and res3.status is not Status.EMPTY  # never 'not registered'


# ------------------------------------------------------------------ FC4/FC5: the .br samples
def test_fc4_fc5_registro_br_whodat_contacts_dropped_and_no_cnpj():
    http = boot(FakeHttp()).add("GET", f"{WHODAT}/registro.br", json=public_fx("whodat_registro_br.json"))
    res = run_module(WhoisFallback, "domain:registro.br", http, settings={"whodat_url": WHODAT}, options=EXPLICIT)
    assert res.status is Status.OK
    assert res.attributes["registrar_whois_server"] == "whois.registro.br" and res.attributes["delegation_signed"] is True
    assert res.attributes["created"] == "1999-02-21T12:00:00Z" and res.attributes["nameservers"][0] == "a.dns.br"
    text = dumped(res)
    for value in ("Example Tech Contact", "tech-contact@example.com", "Núcleo", "NIC.BR", *NIC_BR_CNPJ):
        assert value not in text
    assert {"contacts.tech.name", "contacts.tech.email", "contacts.registrant.name"} <= set(res.raw["record"]["dropped_fields"])
    assert {p.entity.type.value for p in res.pivots} == {"domain"} and all(p.relation == "nameserver" and not p.expand for p in res.pivots)


def test_fc4_fc5_registro_br_port43_text(port43):
    http = iana(boot(FakeHttp()), "br")
    fake = port43({"whois.registro.br": fx("whois43_registro_br.txt")})
    res = run_module(WhoisFallback, "domain:registro.br", http, options=EXPLICIT)
    assert res.status is Status.OK and fake.calls[0][:2] == ("whois.registro.br", "registro.br")
    attrs = res.attributes
    assert attrs["created"] == "1999-02-21" and attrs["updated"] == "2018-04-02"  # never the contact-block dates
    assert attrs["status"] == ["published"] and attrs["delegation_signed"] is True
    assert attrs["registration_source"] == "whois" and attrs["registration_server"] == "whois.registro.br"
    assert [p.entity.value for p in res.pivots] == ["a.dns.br", "b.dns.br", "c.dns.br", "d.dns.br", "e.dns.br"]
    text = dumped(res)
    for value in ("Example Owner Contact", "owner-contact@example.com", "Example Responsible Person", "192.0.2.10", "Núcleo", *NIC_BR_CNPJ):
        assert value not in text
    assert {"owner", "ownerid", "responsible", "person", "e-mail"} <= set(res.raw["record"]["dropped_fields"])
    evidence = res.raw["whois_text"][0]
    assert "domain:      registro.br" in evidence and "ownerid" not in evidence and "Copyright" not in evidence


# ------------------------------------------------------------------ FC3: port 43 through the helper
def test_fc3_ripn_record_and_answers_per_registry(port43):
    http = iana(boot(FakeHttp()), "ru")
    port43({"whois.tcinet.ru": fx("whois43_ripn_ru.txt")})
    res = run_module(WhoisFallback, "domain:yandex.ru", http)
    attrs = res.attributes
    assert res.status is Status.OK and attrs["registrar"] == "RU-CENTER-RU"
    assert attrs["created"] == "1997-09-23T09:45:07Z" and attrs["expires"] == "2027-09-30T21:00:00Z"
    assert attrs["status"] == ["REGISTERED", "DELEGATED", "VERIFIED"] and attrs["nameservers"] == ["ns1.yandex.ru", "ns2.yandex.ru"]
    assert "7700000000" not in dumped(res) and "YANDEX, LLC." not in dumped(res)
    cn = parse_whois_text(fx("whois43_cnnic_cn.txt"), server="whois.cnnic.cn", domain="example.cn")
    assert cn["registrar"]["name"] == "Example Registrar Co., Ltd." and cn["dates"]["created"] == "2003-03-17T12:20:05"
    assert cn["dnssec"]["signed"] is False and "registrant contact email" in cn["dropped_fields"]
    de = parse_whois_text(fx("whois43_denic_de.txt"), server="whois.denic.de", domain="example.de")
    assert de["dates"]["updated"] == "2020-01-01T09:00:00Z" and de["dnssec"]["signed"] is True and de["status"] == ["connect"]


def test_fc3_not_found_answers_are_empty(port43):
    http = iana(boot(FakeHttp()), "ru")
    port43({"whois.tcinet.ru": fx("whois43_ripn_not_found.txt")})
    res = run_module(WhoisFallback, "domain:yandex.ru", http)
    assert res.status is Status.EMPTY and "no registration record" in res.error and not res.attributes.get("registered")
    assert whois_text_marker(fx("whois43_cnnic_not_found.txt")).startswith("not_found")
    assert parse_whois_text(fx("whois43_registro_br_not_found.txt"), domain="does-not-exist-0000.com.br")["registered"] is False


def test_fc3_rate_limited_answers(port43):
    http = iana(boot(FakeHttp()), "br")
    port43({"whois.registro.br": fx("whois43_registro_br_rate_limited.txt")})
    res = run_module(WhoisFallback, "domain:registro.br", http, options=EXPLICIT)
    assert res.status is Status.OK and res.partial and res.stop_reason == "rate_limited"  # reduced record still parses
    assert res.attributes["nameservers"] == ["a.dns.br", "b.dns.br"]
    http2 = iana(boot(FakeHttp()), "br")
    port43({"whois.registro.br": "% Query rate limit exceeded\n"})
    res2 = run_module(WhoisFallback, "domain:registro.br", http2, options=EXPLICIT)
    assert res2.status is Status.RATE_LIMITED and not res2.attributes.get("registered")


def test_fc3_blocked_43_tcp_timeouts_and_garbage_are_could_not_verify(port43):
    for error, status, code in ((OfflineError("43/tcp refused"), Status.UNAVAILABLE, "offline"),
                                (NetworkError("ReadTimeout contacting whois.tcinet.ru: timed out", kind="ReadTimeout"), Status.ERROR, "timeout")):
        http = iana(boot(FakeHttp()), "ru")
        port43({"whois.tcinet.ru": error})
        res = run_module(WhoisFallback, "domain:yandex.ru", http)
        assert res.status is status and res.reason_code == code and not res.attributes.get("registered")
    http = iana(boot(FakeHttp()), "ru")
    port43({"whois.tcinet.ru": "<html><head><title>blocked</title></head></html>"})
    assert run_module(WhoisFallback, "domain:yandex.ru", http).status is Status.ERROR
    http = iana(boot(FakeHttp()), "ru")
    port43({"whois.tcinet.ru": "% Access denied: your IP address has been blacklisted\n"})
    assert run_module(WhoisFallback, "domain:yandex.ru", http).status is Status.BLOCKED


def test_fc3_proxy_configured_never_uses_port43(port43):
    http = iana(boot(FakeHttp()), "ru")
    fake = port43({"whois.tcinet.ru": fx("whois43_ripn_ru.txt")})
    res = run_module(WhoisFallback, "domain:yandex.ru", http, settings={"proxy": "http://proxy.example.org:3128"})
    assert res.status is Status.UNAVAILABLE and "proxy" in res.error and fake.calls == []


def test_fc3_query_syntax_injection_guard_and_cap():
    assert whois_query("whois.denic.de", "example.de") == "-T dn,ace example.de"
    assert whois_query("whois.jprs.jp", "example.jp") == "example.jp/e"
    assert whois_query("whois.verisign-grs.com", "EXAMPLE.com") == "domain example.com"
    assert whois_query("whois.tcinet.ru", "яндекс.рф") == "xn--d1acpjx3f.xn--p1ai"
    for bad in ("example.ru\r\nhelp", "example .ru", "-T dn example.de", ""):
        assert whois_query("whois.tcinet.ru", bad) is None
    text, cut = decode_whois(b"a" * (WHOIS43_CAP_BYTES + 10))
    assert cut and len(text) == WHOIS43_CAP_BYTES
    assert decode_whois("nserver: ns.caf\xe9.ru".encode("latin-1"))[0].endswith("é.ru")


# ------------------------------------------------------------------ FC6: the referral case (at most one hop)
def test_fc6_referral_case_merge_and_one_hop_only():
    registry = parse_whois_text(fx("whois43_verisign_example_com_referral.txt"), server="whois.verisign-grs.com", domain="example.com")
    assert whois_referral(registry, "whois.verisign-grs.com") == "whois.iana.org"
    assert whois_referral(registry, "whois.iana.org") is None  # the same server is never a referral
    iana_answer = parse_whois_text(fx("whois43_iana_example_com.txt"), server="whois.iana.org", domain="example.com")
    merged = merge_referral(registry, iana_answer, "whois.iana.org")
    assert merged["dates"]["created"] == "1995-08-14T04:00:00Z"  # registry values win (IANA says 1992-01-01)
    assert merged["meta"] == {**registry["meta"], "referral": "whois.iana.org"}
    assert next_referral(merged, "whois.iana.org", hops_done=1) is None
    assert not is_thin(registry) and is_thin(parse_whois_text(fx("whois43_verisign_example_com_thin.txt"), domain="example.com"))


def test_fc6_one_referral_hop_for_a_thin_record_at_clear_with_allow_unknown(port43):
    http = iana(boot(FakeHttp(), http_only_com_bootstrap()), "com")
    fake = port43({"whois.verisign-grs.com": fx("whois43_verisign_example_com_thin.txt"), "whois.iana.org": fx("whois43_iana_example_com.txt")})
    res = run_module(WhoisFallback, "domain:example.com", http, options=ScanOptions(tlp="clear", allow_unknown=True), tlp="clear")
    assert res.status is Status.OK and res.raw["path"] == "rdap_http_only"
    assert [c[:2] for c in fake.calls] == [("whois.verisign-grs.com", "domain example.com"), ("whois.iana.org", "example.com")]
    assert res.attributes["registration_referral"] == "whois.iana.org" and res.attributes["created"] == "1995-08-14T04:00:00Z"
    assert len(res.raw["whois_text"]) == 2


def test_fc6_referral_is_recorded_not_queried_at_amber_or_for_thick_records(port43):
    http = iana(boot(FakeHttp(), http_only_com_bootstrap()), "com")
    fake = port43({"whois.verisign-grs.com": fx("whois43_verisign_example_com_thin.txt"), "whois.iana.org": fx("whois43_iana_example_com.txt")})
    res = run_module(WhoisFallback, "domain:example.com", http)  # default TLP:AMBER
    assert len(fake.calls) == 1 and res.attributes["registration_referral"] == "whois.iana.org"
    http2 = iana(boot(FakeHttp(), http_only_com_bootstrap()), "com")
    fake2 = port43({"whois.verisign-grs.com": fx("whois43_verisign_example_com_referral.txt"), "whois.iana.org": fx("whois43_iana_example_com.txt")})
    res2 = run_module(WhoisFallback, "domain:example.com", http2, options=ScanOptions(tlp="clear", allow_unknown=True), tlp="clear")
    assert len(fake2.calls) == 1 and res2.attributes["registrar"] == "RESERVED-Internet Assigned Numbers Authority"
    assert res2.attributes["registrar_iana_id"] == "376"


# ------------------------------------------------------------------ FC6: the recorded research sample
def test_fc6_recorded_gaps_whois_fallback_records():
    yandex = parse_whodat(whodat_from_flat_extract(gap_record("whodat_yandex_ru")["body"]), "yandex.ru")
    assert yandex["registrar"]["name"] == "Regional Network Information Center" and yandex["meta"]["cached"] is True
    br = parse_whodat(whodat_from_flat_extract(gap_record("whodat_registro_br")["body"]), "registro.br")
    assert br["registrar"]["whois_server"] == "whois.registro.br" and br["dates"]["updated"] == "2018-04-02T12:19:10Z"
    assert "Núcleo" not in json.dumps(br, ensure_ascii=False) and "contacts.registrant.name" in br["dropped_fields"]
    example = parse_whodat(whodat_from_flat_extract(gap_record("whodat_example_com")["body"]), "example.com")
    assert example["contacts_redacted"] == {"registrant": True} and example["dates"]["expires"] == "2027-08-13T04:00:00Z"
    for tld, server in (("ru", "whois.tcinet.ru"), ("cn", "whois.cnnic.cn")):
        snippet = gap_record(f"iana_root_db_{tld}")["body"]
        text = f"<title>{snippet['title']}</title>\n" + "\n".join(next(iter(snippet["matches"].values())))
        assert parse_iana_root_db(text, tld)["whois_server"] == server


def test_iana_root_db_parser_on_live_pages():
    assert parse_iana_root_db(fx("iana_root_br.html"), "br")["rdap_base_urls"] == ["https://rdap.registro.br/"]
    com = parse_iana_root_db(fx("iana_root_com.html"), "com")
    assert com["whois_server"] == "whois.verisign-grs.com" and com["website"] == "http://www.verisigninc.com"
    assert parse_iana_root_db(fx("iana_root_gr_no_whois.html"), "gr")["status"] == "no_whois_server"
    assert parse_iana_root_db(fx("iana_root_ru.html"), "br")["status"] == "error"  # title checked
    assert parse_iana_root_db("<html><title>Hello</title></html>", "ru")["status"] == "error"


def test_parsers_and_helpers():
    assert norm_date("19990221 #11026") == "1999-02-21"
    assert norm_date("2020-01-01T10:00:00+01:00") == "2020-01-01T09:00:00Z"
    assert norm_date("21-Feb-1999") == "1999-02-21" and norm_date("1999.02.21") == "1999-02-21" and norm_date("soon") is None
    from datetime import datetime, timezone

    now = datetime(2026, 11, 26, tzinfo=timezone.utc)
    assert domain_age_days("2026-11-20T23:59:59", now) == 6 and domain_age_days("2027-01-01", now) is None
    minimised = minimise_whois_text(fx("whois43_registro_br.txt"))
    assert "nserver:     a.dns.br" in minimised and "e-mail" not in minimised and "IP:" not in minimised
    google = parse_whodat(module_fixture("whois_fallback_public", "whodat_google_com.json"), "google.com")
    assert google["registrar"]["abuse_email"] == "abusecomplaints@markmonitor.com"  # a role mailbox is kept
    assert "registrar.abusePhone" in google["dropped_fields"] and "+1.2086851750" not in json.dumps(google)
    mismatch = whodat_lookup(module_fixture("whois_fallback_public", "whodat_subdomain_reduced.json"), "does-not-exist-0000.example.com", "who-dat")
    assert mismatch.failure and "instead of" in mismatch.failure[2]


def test_doctor_selftest_reads_the_iana_page_only():
    http = iana(FakeHttp(), "ru")
    ctx = make_ctx(WhoisFallback, http)
    result = _root_db_selftest(ctx)
    assert result.status == "ok" and "whois.tcinet.ru" in result.detail
    http2 = FakeHttp()
    exchange(http2, IANA_URL.format(tld="ru"), fx("iana_root_challenge.http.json"))
    assert _root_db_selftest(make_ctx(WhoisFallback, http2)).status == "blocked"
    assert WhoisFallback.health_check().selftest is _root_db_selftest


def test_acceptance_routes_cover_the_golden_domain():
    doc = fixture("acceptance/domain/whois_fallback.json")
    assert doc["schema"] == "v3lum.acceptance_routes/1" and doc["module"] == NAME
    http = FakeHttp()
    for route in doc["routes"]:
        http.add(route["method"], route["url"], status=route["status"], json=route["json"], headers=route.get("headers"))
    res = run_module(WhoisFallback, "domain:example.com", http)
    assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"  # .com has RDAP: no WHOIS lookup at all
    assert len(http.calls) == len(doc["routes"]) and not res.findings


def test_whodat_answer_without_the_domain_name_is_never_used():
    record = whodat_from_flat_extract(gap_record("whodat_yandex_ru")["body"])
    del record["domain"]
    look = whodat_lookup(record, "yandex.ru", "who-dat")
    assert look.record is None and look.failure and "without the domain name" in look.failure[2]
