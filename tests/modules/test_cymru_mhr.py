"""Offline tests of cymru_mhr (P176) with the fixtures in tests/fixtures/cymru_mhr/.

Provenance: ``doh_google_md5_eicar*.json``, ``doh_google_sha1_eicar.json``,
``doh_cloudflare_*.json``, ``doh_google_empty_file_md5.json``, ``doh_google_nxdomain.json`` and
``doh_google_sha256_400.html`` are real DoH answers (live 2026-11-26 / research 2026-11-25; EICAR test
file and empty-file hashes only); ``*_synthetic.json`` keep the live shape with an invented answer."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeHttp, add_dns, add_dns_failure, doh_url, module_fixture, run_module
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.malware_hash.cymru_mhr import CymruMHR, band, parse_txt, qname, wording

FIX = "cymru_mhr"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def answer(http: FakeHttp, digest: str, name: str, *, provider: str = "google") -> FakeHttp:
    http.add("GET", doh_url(f"{digest}.hash.cymru.com", "TXT", provider=provider), json=module_fixture(FIX, name))
    return http


def run(entity: str, http: FakeHttp, **kw):
    return run_module(CymruMHR, entity, http, **kw)


# --------------------------------------------------------------------------------------
# metadata and helpers (c1, c2, c3)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = CymruMHR
    assert cls.accepts == {T.MD5, T.SHA1} and T.SHA256 not in cls.accepts
    assert (cls.terms, cls.default_enabled, cls.hosts, cls.max_requests, cls.requires_keys) == ("noncommercial", True, (), 0, ())
    assert cls.opsec is Opsec.PASSIVE and cls.category == "malware_hash" and cls.disclosure == "third_party"
    assert "DNS-over-HTTPS" in cls.notice and "also sees" in cls.notice
    src = registry().source("team_cymru.mhr")
    assert src.terms.class_ == "noncommercial" and registry().get("team_cymru").tier == "trusted"


def test_qname_only_fits_md5_and_sha1():
    assert qname(EICAR_MD5.upper()) == f"{EICAR_MD5}.hash.cymru.com"
    assert qname(EICAR_SHA1) == f"{EICAR_SHA1}.hash.cymru.com"
    for bad in (EICAR_SHA256, "xyz", "", None, EICAR_MD5 + ".evil.example"):
        with pytest.raises(ValueError):
            qname(bad)


def test_epoch_percent_parser():
    assert parse_txt("1795635863 100") == {"last_seen_epoch": 1795635863, "last_seen": "2026-11-25T19:44:23Z", "detection_pct": 100}
    assert parse_txt('"1795635863 100"') == parse_txt("1795635863 100") == parse_txt(['"1795635863 ', '100"'])
    for bad in ("v=spf1 -all", "1795635863", "1795635863 101", "abc 50", "0000000000 50", "", None, 5, "1795635863 50 extra"):
        assert parse_txt(bad) is None, bad


def test_bands_and_wording():
    assert band(100) == band(30) == ("malicious", "medium")
    assert band(29) == band(10) == ("suspicious", "low")
    assert band(9) == band(0) == ("info", "info")
    assert wording(parse_txt("1795635863 91")) == "AV detection 91% (Team Cymru MHR, last seen 2026-11-25)"


# --------------------------------------------------------------------------------------
# answers (c3, c4)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["doh_google_md5_eicar.json", "doh_google_md5_eicar_live.json"])
def test_eicar_md5_is_a_known_malware_hash(name):
    http = answer(FakeHttp(), EICAR_MD5, name)
    res = run(f"md5:{EICAR_MD5}", http)
    finding = res.findings[0]
    assert finding.title == "Known malware hash (Team Cymru MHR)" and finding.severity is Severity.MEDIUM
    assert finding.tags == ["malicious", "malware"] and "AV detection 100% (Team Cymru MHR, last seen 2026-11-25)" in finding.description
    assert finding.data["upstream_families"] == ["team_cymru_mhr"]
    assert res.attributes["reputation"] == {"team_cymru_mhr": "100%"} and res.attributes["cymru_mhr"]["resolver"] == "google"
    assert len(http.calls) == 1 and http.calls[0]["url"].startswith("https://dns.google/resolve?")


def test_eicar_sha1_answers_the_same():
    http = answer(FakeHttp(), EICAR_SHA1, "doh_google_sha1_eicar.json")
    assert run(f"sha1:{EICAR_SHA1}", http).findings[0].severity is Severity.MEDIUM
    http2 = FakeHttp()
    add_dns_failure(http2, f"{EICAR_SHA1}.hash.cymru.com", "TXT", kind="http500")
    answer(http2, EICAR_SHA1, "doh_cloudflare_sha1_eicar_live.json", provider="cloudflare")
    assert run(f"sha1:{EICAR_SHA1}", http2).findings[0].severity is Severity.MEDIUM


def test_cloudflare_quoted_txt_is_read_through_the_core_resolver():
    http = FakeHttp()
    add_dns_failure(http, f"{EICAR_MD5}.hash.cymru.com", "TXT", kind="http500")
    answer(http, EICAR_MD5, "doh_cloudflare_md5_eicar_quoted.json", provider="cloudflare")
    res = run(f"md5:{EICAR_MD5}", http)
    assert res.attributes["cymru_mhr"]["detection_pct"] == 100 and res.attributes["cymru_mhr"]["resolver"] == "cloudflare"


def test_low_and_marginal_detections():
    name = f"{'a' * 32}.hash.cymru.com"
    http = FakeHttp()
    add_dns(http, name, "TXT", ["1795635863 15"])
    finding = run(f"md5:{'a' * 32}", http).findings[0]
    assert finding.title == "Low AV detection (Team Cymru MHR)" and finding.severity is Severity.LOW and finding.tags == ["suspicious"]
    http2 = FakeHttp()
    add_dns(http2, name, "TXT", ["1795635863 5"])
    finding2 = run(f"md5:{'a' * 32}", http2).findings[0]
    assert finding2.severity is Severity.INFO and "malicious" not in finding2.tags and "below 10%" in finding2.description


def test_empty_file_hash_is_a_known_false_positive():
    http = answer(FakeHttp(), EMPTY_MD5, "doh_google_empty_file_md5.json")
    res = run(f"md5:{EMPTY_MD5}", http)
    finding = res.findings[0]
    assert finding.severity is Severity.INFO and "false_positive" in finding.tags and "malicious" not in finding.tags
    assert res.attributes["cymru_mhr"]["detection_pct"] == 91


def test_nxdomain_is_empty_never_clean():
    digest = "0" * 32
    http = answer(FakeHttp(), digest, "doh_google_nxdomain.json")
    res = run(f"md5:{digest}", http)
    assert res.status is Status.EMPTY and not res.findings and "not 'clean'" in res.error
    http2 = FakeHttp()
    add_dns(http2, f"{digest}.hash.cymru.com", "TXT", [], status=3, provider="all")
    assert run(f"md5:{digest}", http2).status is Status.EMPTY


# --------------------------------------------------------------------------------------
# could not verify (c3, rule 5)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(("kind", "code"), [("servfail", "error"), ("refused", "error"), ("timeout", "timeout"), ("http429", "error"),
                                            ("challenge", "error")])
def test_resolver_failures_are_could_not_verify(kind, code):
    http = FakeHttp()
    add_dns_failure(http, f"{EICAR_MD5}.hash.cymru.com", "TXT", kind=kind, provider="all")
    res = run(f"md5:{EICAR_MD5}", http)
    assert res.status is Status.ERROR and res.reason_code == code and not res.findings


def test_servfail_fixture_and_malformed_or_missing_txt():
    http = answer(FakeHttp(), EICAR_MD5, "doh_servfail_synthetic.json")
    add_dns_failure(http, f"{EICAR_MD5}.hash.cymru.com", "TXT", kind="servfail", provider="cloudflare")
    assert run(f"md5:{EICAR_MD5}", http).status is Status.ERROR
    http2 = answer(FakeHttp(), EICAR_MD5, "doh_malformed_txt_synthetic.json")
    res2 = run(f"md5:{EICAR_MD5}", http2)
    assert res2.status is Status.ERROR and "malformed" in res2.error and not res2.findings
    http3 = FakeHttp()
    add_dns(http3, f"{EICAR_MD5}.hash.cymru.com", "TXT", [])
    assert run(f"md5:{EICAR_MD5}", http3).status is Status.ERROR


def test_sha256_is_never_queried():
    assert (FIXTURES / "doh_google_sha256_400.html").read_text().lstrip().startswith("<!DOCTYPE html>")  # Google DoH: label > 63
    http = FakeHttp()
    res = run(f"sha256:{EICAR_SHA256}", http)
    assert res.status is Status.SKIPPED and not http.calls


def test_malware_zone_fixture_documents_the_alternative_zone():
    data = module_fixture(FIX, "doh_google_md5_eicar_malware_zone.json")
    assert data["Answer"][0]["data"] == "1795635863 100"  # same answer; the module uses hash.cymru.com only
