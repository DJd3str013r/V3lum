"""Offline tests of kaspersky_opentip (P162) with the fixtures in tests/fixtures/kaspersky_opentip/.

Provenance: ``needs_key_401.txt`` and ``bad_key_401.txt`` are the real 401 answers (research
2026-11-25: EMPTY bodies, kept as empty files); ``*_synthetic.json`` use the field names of the
OpenTIP help snippets and the official client (Zone, FileGeneralInfo, DetectionsInfo, IpGeneralInfo,
CategoriesWithZone) with documentation values until the team key exists (P162 cond 3, backlog)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from tests.fakes import FakeHttp, assert_no_secret, module_fixture, run_module
from v3lum import config
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Opsec, Severity, Status
from v3lum.core.providers import registry
from v3lum.modules.threat_intel_ioc import kaspersky_opentip as mod
from v3lum.modules.threat_intel_ioc.kaspersky_opentip import KasperskyOpenTIP, clean_url, detection_family, request_allowed, search_url

FIX = "kaspersky_opentip"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / FIX
KEY_VALUE = "opentip0123456789abcdef0123456789abcdef"
KEYS = {"opentip": KEY_VALUE}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def route(http: FakeHttp, etype: T, value: str, *, name: str | None = None, raw: bytes | None = None, status: int = 200) -> FakeHttp:
    content = raw if raw is not None else body(name or "")
    return http.add("GET", search_url(etype, value), status=status, body=content,
                    headers={"content-type": "application/json"} if content else {}, match_headers={"x-api-key": KEY_VALUE})


@pytest.fixture(autouse=True)
def allowed_by_compliance(monkeypatch):
    """Most tests run as if compliance had recorded vendor_policy_ok; the gate test turns it off."""
    monkeypatch.setattr(mod, "public_ip", lambda value: True)
    monkeypatch.setattr(mod, "vendor_policy_ok", lambda: True)


def run(entity: str, http: FakeHttp, **kw):
    return run_module(KasperskyOpenTIP, entity, http, keys=KEYS, **kw)


# --------------------------------------------------------------------------------------
# metadata, vendor-policy gate, allow-list (c1, c2)
# --------------------------------------------------------------------------------------


def test_metadata_matches_the_council_decision():
    cls = KasperskyOpenTIP
    assert (cls.terms, cls.default_enabled, cls.trust_tier, cls.disclosure) == ("key-terms", False, "trusted", "third_party")
    assert cls.opsec is Opsec.PASSIVE and cls.provider == "kaspersky" and cls.hosts == ("opentip.kaspersky.com",)
    assert cls.daily_quota == 1600 and cls.cache_ttl == 86400
    assert cls.requires_keys == (("opentip",) if "opentip" in config.key_registry() else ())
    src = registry().source("kaspersky.kaspersky_opentip_search")
    assert src.terms.class_ == "key-terms" and src.terms.free_plan_business_use is False
    assert registry().provider_for_host("opentip.kaspersky.com").id == "kaspersky"


def test_disabled_until_compliance_records_vendor_policy_ok(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(mod, "public_ip", lambda value: True)
    http = FakeHttp()
    res = run(f"sha256:{EICAR_SHA256}", http)
    assert res.status is Status.SKIPPED and res.reason_code == "policy" and "vendor_policy_ok" in res.error and not http.calls


def test_vendor_policy_flag_is_read_from_the_provider_registry(monkeypatch):
    monkeypatch.undo()
    for prov, expected in [
        (SimpleNamespace(flags=SimpleNamespace(), extra={}), False),
        (SimpleNamespace(flags=SimpleNamespace(), extra={"x_vendor_policy_ok": True}), True),
        (SimpleNamespace(flags=SimpleNamespace(vendor_policy_ok=True), extra={}), True),
        (SimpleNamespace(flags=SimpleNamespace(), extra={"x_vendor_policy_ok": "yes"}), False),
        (None, False),
    ]:
        monkeypatch.setattr(mod.providers_mod, "registry", lambda p=prov: SimpleNamespace(get=lambda pid: p))
        assert mod.vendor_policy_ok() is expected
    assert mod.vendor_policy_ok.__module__ == mod.__name__


def test_allow_list_never_builds_the_scan_or_upload_endpoints():
    for etype, value in [(T.SHA256, EICAR_SHA256), (T.MD5, "44d88612fea8a8f36de82e1278abb02f"), (T.IPV4, "198.51.100.7"),
                         (T.DOMAIN, "example.com"), (T.URL, "http://login.example.net/a.php")]:
        assert request_allowed("GET", search_url(etype, value)), (etype, value)
    base = "https://opentip.kaspersky.com/api/v1"
    for method, url in [
        ("POST", f"{base}/scan/file?filename={EICAR_SHA256}"), ("GET", f"{base}/scan/file?filename=x"), ("GET", f"{base}/getresult/file?request=x"),
        ("POST", f"{base}/search/hash?request={EICAR_SHA256}"), ("GET", f"{base}/search/file?request=x"),
        ("GET", f"{base}/search/hash?request={EICAR_SHA256}&extra=1"), ("GET", f"{base}/search/url?request=http%3A%2F%2Fa.example%2F%3Fq%3D1"),
        ("GET", f"{base}/search/ip?request=2001%3Adb8%3A%3A1"), ("GET", f"http://opentip.kaspersky.com/api/v1/search/hash?request={EICAR_SHA256}"),
        ("GET", f"{base}/search/hash?request=3395856ce81f2b7382dee72602f798b642f14140"),
    ]:
        assert not request_allowed(method, url), (method, url)


def test_urls_are_sent_without_query_string_fragment_or_userinfo():
    assert clean_url("https://user:pw@Login.Example.net:8443/a/b.php?token=x#frag") == "https://login.example.net:8443/a/b.php"
    assert clean_url("http://example.com") == "http://example.com/" and clean_url("ftp://example.com/") is None


def test_detection_family_names():
    assert detection_family("Trojan-Ransom.Win32.Wanna.m") == "Wanna"
    assert detection_family("HEUR:Trojan.Win32.Generic") is None
    assert detection_family("not-a-virus:HEUR:AdWare.Win32.Example.gen") is None and detection_family("EICAR-Test-File") is None


def test_without_the_key_nothing_is_sent():
    http = FakeHttp()
    assert run_module(KasperskyOpenTIP, f"sha256:{EICAR_SHA256}", http).status is Status.NEEDS_KEY and not http.calls


# --------------------------------------------------------------------------------------
# zones (c3)
# --------------------------------------------------------------------------------------


def test_red_hash_is_malicious_high_with_listed_families():
    http = route(FakeHttp(), T.SHA256, EICAR_SHA256, name="hash_red_synthetic.json")
    res = run(f"sha256:{EICAR_SHA256}", http)
    finding = res.findings[0]
    assert finding.title == "Malicious per Kaspersky OpenTIP" and finding.severity is Severity.HIGH and finding.tags == ["malicious"]
    assert finding.data["upstream_families"] == ["kaspersky"] and "EICAR-Test-File" in finding.criterion
    assert [p.entity.value for p in res.pivots] == ["Example"] and all(p.expand is False for p in res.pivots)
    assert res.attributes["opentip"]["file"]["sha256"] == EICAR_SHA256 and res.attributes["file_size"] == 68
    http.assert_hosts_within(KasperskyOpenTIP)
    assert all(request_allowed(c["method"], c["url"]) for c in http.calls)
    assert_no_secret(KEY_VALUE, res.to_dict())


def test_green_is_known_good_only_for_file_hashes():
    sha = "7ad4c9b8c7af0fe090d2286ba6dac3e90365c7e29c29a6105d97a41ae79beae0"
    http = route(FakeHttp(), T.SHA256, sha, name="hash_green_synthetic.json")
    res = run(f"sha256:{sha}", http)
    assert res.attributes["known_good"] is True and res.findings[0].tags == ["known_good", "info"]
    http2 = route(FakeHttp(), T.DOMAIN, "example.com", name="domain_green_synthetic.json")
    res2 = run("domain:example.com", http2)
    assert res2.status is Status.OK and not res2.findings and "known_good" not in res2.attributes


def test_grey_is_no_finding_and_yellow_is_potentially_unwanted_info():
    http = route(FakeHttp(), T.SHA256, "0" * 64, name="hash_grey_synthetic.json")
    res = run(f"sha256:{'0' * 64}", http)
    assert res.status is Status.OK and not res.findings
    http2 = route(FakeHttp(), T.SHA256, "1" * 64, name="hash_yellow_synthetic.json")
    finding = run(f"sha256:{'1' * 64}", http2).findings[0]
    assert finding.severity is Severity.INFO and "potentially_unwanted" in finding.tags and "malicious" not in finding.tags


def test_orange_ip_is_suspicious_low_and_whois_is_never_copied():
    http = route(FakeHttp(), T.IPV4, "198.51.100.7", name="ip_orange_synthetic.json")
    res = run("ipv4:198.51.100.7", http)
    finding = res.findings[0]
    assert finding.severity is Severity.LOW and finding.tags == ["suspicious"]
    assert res.attributes["country"] == "BR"
    assert "EXAMPLE-NET" not in str(res.to_dict()) and "host7.example.net" not in str(res.to_dict())


def test_red_url_is_looked_up_without_its_query_string():
    url = "http://login.example.net/account/verify.php?session=abc123#top"
    http = route(FakeHttp(), T.URL, "http://login.example.net/account/verify.php", name="url_red_synthetic.json")
    res = run(f"url:{url}", http)
    assert res.findings[0].severity is Severity.HIGH
    sent = parse_qs(urlsplit(http.calls[0]["url"]).query)["request"]
    assert sent == ["http://login.example.net/account/verify.php"] and "abc123" not in http.calls[0]["url"]


# --------------------------------------------------------------------------------------
# statuses (c3, rule 5)
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["needs_key_401.txt", "bad_key_401.txt"])
def test_401_with_an_empty_body_is_needs_key(name):
    assert body(name) == b""
    http = route(FakeHttp(), T.SHA256, EICAR_SHA256, name=name, status=401)
    assert run(f"sha256:{EICAR_SHA256}", http).status is Status.NEEDS_KEY


@pytest.mark.parametrize(("status", "expected"), [(403, Status.QUOTA), (404, Status.EMPTY), (400, Status.ERROR), (429, Status.RATE_LIMITED),
                                                  (500, Status.ERROR)])
def test_documented_statuses(status, expected):
    http = route(FakeHttp(), T.IPV4, "198.51.100.8", raw=b"", status=status)
    assert run("ipv4:198.51.100.8", http).status is expected


def test_unusable_200_bodies_are_could_not_verify():
    for raw in (b"", b"{}", b'{"Zone": "Purple"}', b"[1]", b'{"Zone": "Red", "FileGen'):
        http = route(FakeHttp(), T.IPV4, "198.51.100.9", raw=raw)
        assert run("ipv4:198.51.100.9", http).status is Status.ERROR, raw


def test_fixture_shapes_are_documented():
    assert module_fixture(FIX, "hash_red_synthetic.json")["Zone"] == "Red"
