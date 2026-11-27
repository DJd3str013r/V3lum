"""url_domain_blocklists_c2 (P071, batch p1-G03-1): the CyberCrime-Tracker C2 panel list, matched
locally. Non-default (A3: the list operator is of unknown tier); panel paths are family hints only.

Fixture tests/fixtures/url_domain_blocklists_c2/cybercrime_tracker_ok.txt is a real slice of the
public all.php list of 2026-11-26 (public C2 infrastructure, no personal data), minimised.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.fakes import FakeClock, FakeHttp, make_runtime, run_module
from v3lum.core import datasets
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.url_web import url_domain_blocklists as B
from v3lum.modules.url_web.url_domain_blocklists import UrlDomainBlocklistsC2

CYBER = "url_domain_blocklists.cybercrime_tracker.txt"
SOURCE = "cybercrime_tracker.panel_list"
FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "url_domain_blocklists_c2"


def body() -> str:
    return (FIXTURES / "cybercrime_tracker_ok.txt").read_text(encoding="utf-8")


@pytest.fixture()
def env(monkeypatch):
    http = FakeHttp()
    clock = FakeClock()
    rt = make_runtime(http, clock=clock)

    def install(text: str | bytes, *, expect_ok: bool = True):
        _feed, part = B.PARTS[CYBER]
        monkeypatch.setitem(datasets.DATASETS[CYBER], "min_bytes", 1)  # the fixture is a slice of a larger list
        http.add("GET", part.url, body=text.encode("utf-8") if isinstance(text, str) else text, times=1)
        result = rt.data.update(CYBER)
        assert result.ok is expect_ok, result.reason
        return result

    return rt, clock, install


def run(entity, rt, *, settings=None):
    saved = dict(rt.config.settings)
    rt.config.settings.update(settings or {})
    try:
        return run_module(UrlDomainBlocklistsC2, entity, runtime=rt)
    finally:
        rt.config.settings.clear()
        rt.config.settings.update(saved)


def hits(res):
    return res.attributes.get("blocklist_hits", [])


def test_metadata():
    cls = UrlDomainBlocklistsC2
    assert (cls.name, cls.disclosure, cls.hosts, cls.terms) == ("url_domain_blocklists_c2", "none", (), "open")
    assert cls.default_enabled is False  # A3: provider tier unknown
    assert cls.sources == (SOURCE,) and cls.produces == {T.URL} and cls.accepts == {T.DOMAIN, T.URL, T.IPV4}
    assert B.PARTS[CYBER][0].module == "c2" and B.PARTS[CYBER][1].tables == ("url", "urlhost")


def test_not_downloaded_is_not_checked(env):
    rt, _clock, _install = env
    res = run("ipv4:5.182.86.32", rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"
    assert "not checked" in res.error and not hits(res)
    assert res.source_statuses[SOURCE]["status"] == "unavailable"


def test_ip_host_hit_reports_panel_urls_as_unexpanded_pivots(env):
    rt, _clock, install = env
    install(body())
    res = run("ipv4:5.182.86.32", rt)
    assert res.status is Status.OK
    [hit] = hits(res)
    assert (hit["feed"], hit["match"], hit["category"]) == ("cybercrime_tracker", "host", "c2")
    [finding] = [f for f in res.findings if f.data.get("category") == "c2"]
    assert finding.severity.name == "HIGH" and "c2" in finding.tags
    assert res.attributes["c2_panel_hints"] == ["panel login page"]
    [pivot] = [p for p in res.pivots if p.entity.type is T.URL]
    assert pivot.entity.value == "http://5.182.86.32/auth/login" and pivot.expand is False and pivot.relation == "related"
    assert res.attributes.get("malicious") is True


def test_url_exact_match_and_family_hint(env):
    rt, _clock, install = env
    install(body())
    res = run("url:http://greenbazaar.xyz/blac/panel/five/PvqDq929BSx_A_D_M1n_a.php", rt)
    matches = sorted(h["match"] for h in hits(res))
    assert matches == ["host", "url"]
    assert "LokiBot panel admin page" in res.attributes["c2_panel_hints"]
    assert "c2 panel path (/panel/)" in res.attributes["c2_panel_hints"]


def test_port_and_double_slash_entries_are_indexed(env):
    rt, _clock, install = env
    install(body())
    res = run("ipv4:193.56.146.60", rt)
    [pivot] = [p for p in res.pivots if p.entity.type is T.URL]
    assert pivot.entity.value.startswith("http://193.56.146.60:44413/")
    assert run("ipv4:37.0.10.102", rt).status is Status.OK
    assert run("domain:matix.cf", rt).attributes["c2_panel_hints"] == ["c2 panel path (/panel/)", "panel login page"]


def test_unlisted_values_are_empty(env):
    rt, _clock, install = env
    install(body())
    for value in ("domain:example.com", "ipv4:192.0.2.10", "url:https://www.example.org/panel/login.php"):
        res = run(value, rt)
        assert res.status is Status.EMPTY and not hits(res), value


def test_html_challenge_page_is_never_installed(env):
    rt, _clock, install = env
    page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
    install(page, expect_ok=False)
    res = run("ipv4:5.182.86.32", rt)
    assert res.status is Status.UNAVAILABLE and res.reason_code == "dataset"  # 'could not verify', never 'empty'


def test_stale_copy_is_not_checked(env):
    rt, clock, install = env
    install(body())
    clock.advance(80 * 3600)  # stale_h = 72
    res = run("ipv4:5.182.86.32", rt)
    assert res.status is Status.UNAVAILABLE and "h old" in res.error and not hits(res)


def test_disabled_by_setting(env):
    rt, _clock, install = env
    install(body())
    res = run("ipv4:5.182.86.32", rt, settings={"url_domain_blocklists_disabled_feeds": ["cybercrime_tracker"]})
    assert res.status is Status.UNAVAILABLE and not hits(res)
    assert res.source_statuses[SOURCE]["status"] == "skipped" and res.source_statuses[SOURCE]["reason_code"] == "config"


def test_policy_gate_removes_the_feed(env):
    rt, _clock, install = env
    install(body())
    res = run_module(UrlDomainBlocklistsC2, "ipv4:5.182.86.32", runtime=rt, allowed_sources=[])
    assert res.status is Status.UNAVAILABLE and not hits(res)
