"""gtm_expand (P061 cond 1-3, batch p2-G03-1).

Fixtures in tests/fixtures/gtm_expand/ (prep p2-G03-1, recorded 2026-11-26 from www.googletagmanager.com):
``ok_govbr_GTM-NHZSKTD.js`` (public gov.br container, minimised: unneeded macros replaced by
``{"function":"__e"}`` to keep indices, runtime removed), ``ok_cloudflare_GTM-NDGPDFZ.js`` (Cloudflare's
container, minimised the same way), ``not_found_GTM-ZZZZ999.js`` (unknown container: HTTP 200, generic
runtime, data object without macros/tags), ``malformed_truncated.js`` (the gov.br body cut inside the
data object), ``challenge_synthetic.html`` (Google 'sorry' interstitial shape, synthetic).
"""

from __future__ import annotations

import pytest

from tests.fakes import FIXTURES, FakeHttp, run_module
from v3lum.core.models import Status
from v3lum.modules.url_web import gtm_expand as mod
from v3lum.modules.url_web.gtm_expand import GtmExpand

URL = "https://www.googletagmanager.com/gtm.js?id={id}"
JS = {"Content-Type": "application/javascript; charset=UTF-8", "Server": "Google Tag Manager"}


def fx(name: str) -> bytes:
    return (FIXTURES / "gtm_expand" / name).read_bytes()


@pytest.fixture(autouse=True)
def fresh_budget():
    mod.BUDGET.reset()
    yield
    mod.BUDGET.reset()


def run(gtm_id: str, body: bytes, status: int = 200, headers=None, **kw):
    http = FakeHttp().add("GET", URL.format(id=gtm_id), status=status, body=body, headers=headers or JS)
    res = run_module(GtmExpand, f"analytics_id:{gtm_id}", http, **kw)
    http.assert_hosts_within(GtmExpand)
    return res


def test_metadata():
    cls = GtmExpand
    assert (cls.disclosure, cls.provider, cls.hosts, cls.terms) == ("third_party", "googletagmanager", ("www.googletagmanager.com",), "open")
    assert cls.cache_ttl == 7 * 86400 and cls.max_requests == 1 and cls.default_enabled is True
    assert cls.trust_tier == "trusted"


def test_recorded_govbr_container_expands_three_ids():
    res = run("GTM-NHZSKTD", fx("ok_govbr_GTM-NHZSKTD.js"))
    assert res.status is Status.OK
    assert {p.entity.value for p in res.pivots} == {"G-WGZPDK4DH1", "UA-80181585-36", "AW-16635352617"}
    assert all(p.relation == "gtm_loads" and p.expand and p.confidence <= 0.7 for p in res.pivots)
    assert all("GTM container GTM-NHZSKTD" in p.note for p in res.pivots)  # c8 provenance
    container = res.attributes["gtm_container"]
    assert container["found"] is True and container["version"] == "155"
    assert {"www.gov.br", "vlibras.gov.br", "acesso.gov.br"} <= set(res.attributes["gtm_linker_domains"])
    assert "www.facebook.com" in res.attributes.get("gtm_script_hosts", [])


def test_recorded_cloudflare_container_dc_ids_stay_context():
    res = run("GTM-NDGPDFZ", fx("ok_cloudflare_GTM-NDGPDFZ.js"))
    assert res.status is Status.OK
    pivots = {p.entity.value for p in res.pivots}
    assert {"G-8BK794H3J9", "G-SQCRB0TXZW", "G-NPJQ92CQTK"} <= pivots
    assert not any(v.startswith("DC-") for v in pivots)
    loaded = {i["id"] for i in res.attributes["gtm_loaded_ids"]}
    assert {"DC-9309168", "DC-9973066"} <= loaded
    assert res.attributes["gtm_host_map"]["www.cloudflare.com"] == "G-SQCRB0TXZW"


def test_unknown_container_not_found_from_content_not_status():
    res = run("GTM-ZZZZ999", fx("not_found_GTM-ZZZZ999.js"))
    assert res.status is Status.EMPTY  # HTTP 200, decided from the content
    assert res.attributes["gtm_container"]["found"] is False
    assert res.pivots == []


def test_truncated_container_is_could_not_verify():
    res = run("GTM-NHZSKTD", fx("malformed_truncated.js"))
    assert res.status is Status.ERROR and "could not verify" in res.error
    assert res.pivots == []


def test_challenge_interstitial_is_blocked():
    res = run("GTM-NHZSKTD", fx("challenge_synthetic.html"), headers={"Content-Type": "text/html"})
    assert res.status is Status.BLOCKED


def test_429_is_rate_limited():
    res = run("GTM-NHZSKTD", b"Too Many Requests", status=429, headers={"Content-Type": "text/plain"})
    assert res.status is Status.RATE_LIMITED


def test_5xx_is_error_never_empty():
    http = FakeHttp().add("GET", URL.format(id="GTM-NHZSKTD"), status=503, text="unavailable", times=5)
    res = run_module(GtmExpand, "analytics_id:GTM-NHZSKTD", http)
    assert res.status is Status.ERROR


def test_garbage_body_is_error():
    res = run("GTM-NHZSKTD", b"window.foo = 1;")
    assert res.status is Status.ERROR and "could not verify" in res.error


def test_echoed_id_mismatch_is_error():
    body = fx("ok_govbr_GTM-NHZSKTD.js").replace(b'"10":"GTM-NHZSKTD"', b'"10":"GTM-OTHER01"')
    parsed = mod.parse_gtm_container(body, "GTM-NHZSKTD")
    assert parsed["status"] == "error" and "GTM-OTHER01" in parsed["reason"]


def test_size_cap_truncates_and_never_reads_as_not_found():
    parsed = mod.parse_gtm_container(fx("ok_govbr_GTM-NHZSKTD.js"), "GTM-NHZSKTD", max_bytes=600)
    assert parsed["truncated"] is True and parsed["status"] == "error"


def test_template_and_invalid_ids_not_applicable():
    for value in ("GTM-XXXX", "G-WGZPDK4DH1"):
        res = run_module(GtmExpand, f"analytics_id:{value}", FakeHttp())
        assert res.status is Status.SKIPPED and res.reason_code == "not_applicable"


def test_five_containers_per_run_cap():
    ids = ["GTM-AAAA001", "GTM-AAAA002", "GTM-AAAA003", "GTM-AAAA004", "GTM-AAAA005", "GTM-AAAA006"]
    http = FakeHttp()
    for gid in ids:
        http.add("GET", URL.format(id=gid), body=fx("not_found_GTM-ZZZZ999.js").replace(b"GTM-ZZZZ999", gid.encode()), headers=JS)
    statuses = [run_module(GtmExpand, f"analytics_id:{gid}", http, case_id="case-1").status for gid in ids]
    assert statuses[:5] == [Status.EMPTY] * 5
    assert statuses[5] is Status.SKIPPED
    assert len(http.calls) == 5


def test_url_builder_validates_ids():
    assert mod.gtm_container_url("GTM-NHZSKTD") == "https://www.googletagmanager.com/gtm.js?id=GTM-NHZSKTD"
    assert mod.gtm_container_url("GTM-nhzsktd") is None
    assert mod.gtm_container_url("GTM-ABC&x=1") is None
