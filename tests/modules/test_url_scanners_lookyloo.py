"""Offline tests of url_scanners_lookyloo (P078: CIRCL Lookyloo, existing captures only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, module_fixture, run_module
from v3lum.core.http import PolicyError
from v3lum.core.models import Status
from v3lum.modules.url_web import url_scanners_third_party as mod
from v3lum.modules.url_web.url_scanners_third_party import UrlScannersLookyloo

URL_INFO = "https://lookyloo.circl.lu/json/url_info"
HOST_INFO = "https://lookyloo.circl.lu/json/hostname_info"
REDIRECTS = "https://lookyloo.circl.lu/json/{uuid}/redirects"
SEED = "url:https://login.example.com/secure/"


def fx(name: str) -> dict:
    return module_fixture("url_scanners_lookyloo", name)


def add(http: FakeHttp, method: str, url: str, envelope: dict) -> FakeHttp:
    body = envelope.get("body")
    if isinstance(body, (dict, list)):
        return http.add(method, url, status=envelope["status"], json=body, headers=dict(envelope.get("headers") or {}))
    return http.add(method, url, status=envelope["status"], text=str(body or ""))


def run(entity: str, http: FakeHttp):
    return run_module(UrlScannersLookyloo, entity, http, clock=FakeClock())


def uuids(envelope: dict) -> list[str]:
    return [c["capture_uuid"] for c in envelope["body"]["response"]]


def test_metadata_terms_unknown_until_legal_records_circl_terms():
    cls = UrlScannersLookyloo
    assert cls.terms == "unknown" and cls.default_enabled is False
    assert cls.sources == ("circl.lookyloo",) and cls.trust_tier == "trusted"
    assert cls.hosts == ("lookyloo.circl.lu",) and cls.run_on == "seeds"
    assert cls.publishes_queries is False


def test_existing_captures_with_dates_and_redirects():
    http = FakeHttp()
    info = fx("url_info_ok_documented.http.json")
    add(http, "POST", URL_INFO, info)
    first, second = uuids(info)[:2]
    add(http, "GET", REDIRECTS.format(uuid=first), fx("redirects_ok_documented.http.json"))
    add(http, "GET", REDIRECTS.format(uuid=second), fx("redirects_none_documented.http.json"))
    res = run(SEED, http)
    assert res.status is Status.OK, res.error
    caps = res.attributes["lookyloo_captures"]
    assert caps[0]["capture_uuid"] == first and caps[0]["scan_date"].startswith("2026-11-21") and caps[0]["historical"] is False
    assert caps[0]["final_url"] == "https://www.example.org/landing" and caps[0]["redirect_count"] == 2
    assert caps[0]["tree_url"] == f"https://lookyloo.circl.lu/tree/{first}"
    pivots = {(p.entity.type.value, p.entity.value, p.relation) for p in res.pivots}
    assert ("url", "https://www.example.org/landing", "scanner_final_url") in pivots
    assert ("domain", "www.example.org", "scanner_final_host") in pivots
    assert any(label.startswith("Lookyloo capture") for label, _u in res.links)
    assert not res.findings  # Lookyloo gives captures, never a verdict
    blob = json.dumps(res.attributes, default=str)
    assert "user%40example.com" not in blob and "user@example.com" not in blob
    body = json.loads(http.calls[0]["body"])
    assert body["cached_captures_only"] is True and body["url"] == "https://login.example.com/secure/"
    http.assert_hosts_within(UrlScannersLookyloo)
    for call in http.calls:
        assert mod.allowed_request(call["method"], call["url"]) is None


def test_real_hostname_lookup_pivots_only_captures_of_the_value():
    """Observed 2026-11-26: hostname_info lists every capture whose tree contains the host - also captures of
    unrelated sites that only load or link it. Only captures OF the value (submitted for it or redirecting to
    it) give pivots; a duplicate capture in one answer is kept once."""
    http = FakeHttp()
    info = json.loads(json.dumps(fx("hostname_info_example_com_observed.http.json")))
    info["body"]["response"].append(dict(info["body"]["response"][0]))  # the live instance repeats captures
    add(http, "POST", HOST_INFO, info)
    redirector, other = "a1787b91-d9d4-4e7f-b5fb-e74004250a43", "2e3ccad3-5196-4131-bfbd-b683bbb4e7d0"
    add(http, "GET", REDIRECTS.format(uuid=redirector), fx("redirects_via_redirector_observed.http.json"))
    add(http, "GET", REDIRECTS.format(uuid=other), fx("redirects_other_site_observed.http.json"))
    res = run("domain:example.com", http)
    assert res.status is Status.OK, res.error
    caps = {c["capture_uuid"]: c for c in res.attributes["lookyloo_captures"]}
    assert len(res.attributes["lookyloo_captures"]) == 2
    assert caps[redirector]["subject_role"] == "redirect" and caps[redirector]["capture_url"] == "https://macffab.com/"
    assert caps[other]["subject_role"] == "resource" and caps[other]["final_url"] == "https://www.krito.fr/"
    values = {p.entity.value for p in res.pivots}
    assert not any("krito" in v for v in values)  # an unrelated site that references the host is never a lead
    summary = res.attributes["third_party_scan_summary"]["lookyloo"]
    assert summary["total"] == 327 and summary["partial"] is True  # meta.warning: some captures not cached


def test_a_failed_redirect_read_keeps_the_listed_captures():
    http = FakeHttp()
    info = fx("url_info_ok_documented.http.json")
    add(http, "POST", URL_INFO, info)
    http.add("GET", REDIRECTS.format(uuid=uuids(info)[0]), status=503, json={"error": "unavailable"})
    res = run(SEED, http)
    assert res.status is Status.OK
    assert len(res.attributes["lookyloo_captures"]) == 2 and not res.pivots
    summary = res.attributes["third_party_scan_summary"]["lookyloo"]
    assert summary["partial"] is True and "not read" in summary["detail_error"]


def test_domain_uses_hostname_info():
    http = FakeHttp()
    info = fx("hostname_info_ok_documented.http.json")
    add(http, "POST", HOST_INFO, info)
    add(http, "GET", REDIRECTS.format(uuid=uuids(info)[0]), fx("redirects_none_documented.http.json"))
    res = run("domain:login.example.com", http)
    assert res.status is Status.OK
    assert json.loads(http.calls[0]["body"])["hostname"] == "login.example.com"


def test_no_capture_is_empty():
    http = FakeHttp()
    add(http, "POST", URL_INFO, fx("url_info_empty_documented.http.json"))
    assert run(SEED, http).status is Status.EMPTY


def test_uncached_captures_are_listed_and_never_recached():
    http = FakeHttp()
    info = fx("url_info_uncached_documented.http.json")
    add(http, "POST", URL_INFO, info)
    for uid in uuids(info)[:2]:
        add(http, "GET", REDIRECTS.format(uuid=uid), fx("uuid_missing_400_documented.http.json"))
    res = run(SEED, http)
    assert res.status is Status.OK
    summary = res.attributes["third_party_scan_summary"]["lookyloo"]
    assert summary["partial"] is True and summary["total"] == 9
    assert all(json.loads(c["body"]).get("cached_captures_only") is True for c in http.calls if c["method"] == "POST")


def test_only_uncached_captures_is_could_not_verify():
    http = FakeHttp()
    env = json.loads(json.dumps(fx("url_info_uncached_documented.http.json")))
    env["body"]["response"] = []
    add(http, "POST", URL_INFO, env)
    res = run(SEED, http)
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_lookyloo_401_is_a_missing_field_never_needs_key():
    http = FakeHttp()
    add(http, "POST", URL_INFO, fx("missing_hostname_401_documented.http.json"))
    res = run(SEED, http)
    assert res.status is Status.ERROR and res.status is not Status.NEEDS_KEY


@pytest.mark.parametrize(("status", "expected"), [(429, Status.RATE_LIMITED), (500, Status.ERROR)])
def test_rate_limit_and_server_errors(status, expected):
    http = FakeHttp().add("POST", URL_INFO, status=status, json={"error": "x"})
    assert run(SEED, http).status is expected


def test_truncated_body_and_error_in_200_are_errors():
    truncated = Path(_fixture_path("recent_captures_malformed.json")).read_text(encoding="utf-8")
    http = FakeHttp().add("POST", URL_INFO, status=200, text=truncated)
    assert run(SEED, http).status is Status.ERROR
    http2 = FakeHttp().add("POST", URL_INFO, status=200, json={"error": "Something went wrong"})
    assert run(SEED, http2).status is Status.ERROR
    http3 = FakeHttp().add("POST", URL_INFO, status=200, text="<html><body>maintenance</body></html>")
    assert run(SEED, http3).status in (Status.ERROR, Status.BLOCKED)


def test_submit_is_never_buildable():
    for method, url in (("POST", "https://lookyloo.circl.lu/submit"), ("GET", "https://lookyloo.circl.lu/submit"),
                        ("POST", "https://lookyloo.circl.lu/json/upload"), ("GET", "https://lookyloo.circl.lu/capture")):
        with pytest.raises(PolicyError):
            mod.build_request(method, url)


def _fixture_path(name: str) -> str:
    return str(Path(__file__).resolve().parents[1] / "fixtures" / "url_scanners_lookyloo" / name)
