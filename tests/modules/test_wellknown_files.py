"""wellknown_files (P065, LIGHT, opt-in): security.txt, robots.txt, sitemaps and the MTA-STS policy, offline.

Fixtures in tests/fixtures/wellknown_files/ (batch p9-G03-1 prep, 2026-11-26): the recorded
security.txt and robots.txt of www.google.com (research samples, 2026-11-25; role contact addresses
only) with the research parse of that security.txt, and synthetic files in the documented shapes
(the prep never contacts a target): a signed and expired security.txt, a file without a Contact line,
soft-404 pages, 404/403/challenge answers, sitemap urlset/index/plain-text files, an XML-entity bomb,
a gzip bomb (12 MB from 12 KB) and MTA-STS policies (valid, testing, invalid, soft 404).
"""

from __future__ import annotations

import time

import pytest

from tests.fakes import FIXTURES, FakeHttp, add_dns, make_runtime, module_fixture, run_module
from v3lum.core.context import ScanOptions
from v3lum.core.models import Opsec, Severity, Status
from v3lum.modules.url_web import wellknown_files as W
from v3lum.modules.url_web.wellknown_files import WellknownFiles

FX = FIXTURES / "wellknown_files"
SITE = "example.com"
IP = "93.184.216.34"
LIGHT = ScanOptions(mode=Opsec.LIGHT)
TXT = {"content-type": "text/plain; charset=utf-8"}
XML = {"content-type": "application/xml"}


def target(http: FakeHttp, host: str, ip: str = IP) -> None:
    add_dns(http, host, "A", [ip])
    add_dns(http, host, "AAAA", [])


def site(http: FakeHttp | None = None, *, mta_txt: list[str] | None = None) -> FakeHttp:
    http = http or FakeHttp()
    for host in (SITE, f"www.{SITE}", f"mta-sts.{SITE}"):
        target(http, host)
    if mta_txt is None:
        add_dns(http, f"_mta-sts.{SITE}", "TXT", [], status=3)  # NXDOMAIN: no policy published
    else:
        add_dns(http, f"_mta-sts.{SITE}", "TXT", mta_txt)
    return http


def target_calls(http: FakeHttp) -> list[str]:
    return [c["url"] for c in http.calls if "dns.google" not in c["url"] and "cloudflare-dns" not in c["url"]]


def run(http: FakeHttp, entity: str = f"domain:{SITE}", **kw):
    return run_module(WellknownFiles, entity, http, options=kw.pop("options", LIGHT), **kw)


def absent(http: FakeHttp, *paths: str) -> None:
    for path in paths:
        http.add("GET", f"https://{SITE}{path}", status=404, text="<html><title>404 Not Found</title></html>")


# ---------------------------------------------------------------------------------- the full fixed set


def test_recorded_security_txt_and_robots_with_mta_sts_policy():
    http = site(mta_txt=["v=STSv1; id=20261101"])
    http.add("GET", f"https://{SITE}/.well-known/security.txt", text=(FX / "securitytxt_ok_recorded.txt").read_text(), headers=TXT)
    http.add("GET", f"https://{SITE}/robots.txt", text=(FX / "robots_ok_recorded.txt").read_text(), headers=TXT)
    http.add("GET", f"https://mta-sts.{SITE}/.well-known/mta-sts.txt", text=(FX / "mta_sts_ok_synthetic.txt").read_text(), headers=TXT)
    res = run(http)
    assert res.status is Status.OK, res.error
    # the fixed request set: no legacy security.txt (the well-known one exists), no sitemap of another site
    assert target_calls(http) == [f"https://{SITE}/.well-known/security.txt", f"https://{SITE}/robots.txt",
                                  f"https://mta-sts.{SITE}/.well-known/mta-sts.txt"]
    sec = res.attributes["security_txt"]
    expected = module_fixture("wellknown_files", "securitytxt_expected_recorded.json")["google"]
    assert sec["state"] == "present" and sec["signed"] is expected["signed"]
    assert sec["contacts"]["emails"] == ["security@google.com"] and sec["contacts"]["urls"] == ["https://g.co/vulnz"]
    assert sec["fields"]["policy"] == expected["fields"]["policy"] and sec["expired"] is False
    assert "expires_more_than_a_year_ahead" in sec["warnings"]
    emails = [p for p in res.pivots if p.relation == "contact_email"]
    assert [p.entity.value for p in emails] == ["security@google.com"] and emails[0].expand is False
    links = {p.entity.value for p in res.pivots if p.relation == "security_txt_link"}
    assert "https://services.google.com/corporate/publickey.txt" in links and "https://g.co/vrp" in links
    robots = res.attributes["robots_txt"]
    assert robots["state"] == "present" and robots["disallow"] > 20 and robots["crawl_delay"] == 2.0
    assert robots["sitemaps_foreign"] == ["https://www.google.com/sitemap.xml"]  # never fetched: another site
    paths = [p for p in res.pivots if p.relation == "robots_path"]
    assert 0 < len(paths) <= W.MAX_ROBOTS_PIVOTS and all(p.expand is False for p in paths)
    assert all(p.entity.value.startswith(f"https://{SITE}/") for p in paths)
    assert "/?hl=*&" in robots["patterns"]  # wildcard rules stay patterns
    sts = res.attributes["mta_sts_policy"]
    assert sts["valid"] is True and sts["mode"] == "enforce" and sts["mx"] == ["mx1.example.com", "*.mail.example.com"]
    assert res.findings == []


def test_absent_files_need_a_normal_404_and_the_legacy_path_is_tried():
    http = site()
    absent(http, "/.well-known/security.txt", "/security.txt", "/robots.txt", "/sitemap.xml")
    res = run(http)
    assert res.status is Status.EMPTY
    assert target_calls(http) == [f"https://{SITE}/.well-known/security.txt", f"https://{SITE}/security.txt", f"https://{SITE}/robots.txt",
                                  f"https://{SITE}/sitemap.xml"]
    assert res.attributes["mta_sts_policy"]["state"] == "not_published"  # no TXT record: no policy fetch


def test_a_sitemap_that_could_not_be_read_is_never_an_empty_run():
    http = site()
    absent(http, "/.well-known/security.txt", "/security.txt", "/robots.txt")
    http.add("GET", f"https://{SITE}/sitemap.xml", status=503, text="upstream unavailable")
    res = run(http)
    assert res.status is Status.ERROR and "could not verify" in res.error  # never EMPTY (rule 5)
    assert res.attributes["wellknown_files"]["sitemaps_failed"]


def test_a_404_challenge_page_is_blocked_not_absent():
    page = module_fixture("wellknown_files", "securitytxt_proxy_404_synthetic.json")
    blocked = module_fixture("wellknown_files", "securitytxt_blocked_403_synthetic.json")
    http = site()
    http.add("GET", f"https://{SITE}/.well-known/security.txt", status=page["status"], text=page["body"])
    http.add("GET", f"https://{SITE}/robots.txt", status=blocked["status"], text=blocked["body"], headers={"server": "cloudflare"})
    http.add("GET", f"https://{SITE}/sitemap.xml", status=blocked["status"], text=blocked["body"], headers={"server": "cloudflare"})
    res = run(http)
    assert res.attributes["security_txt"]["state"] == "blocked"
    assert f"https://{SITE}/security.txt" not in target_calls(http)  # blocked is never read as 'absent'
    assert res.status is Status.BLOCKED and "could not verify" in res.error


def test_soft_404_security_txt_is_decided_from_content():
    http = site()
    http.add("GET", f"https://{SITE}/.well-known/security.txt", text=(FX / "securitytxt_soft404_synthetic.html").read_text())
    absent(http, "/robots.txt", "/sitemap.xml")
    res = run(http)
    assert res.attributes["security_txt"]["state"] == "soft404"
    assert not [p for p in res.pivots if p.relation == "contact_email"]
    no_contact = W.parse_security_txt((FX / "securitytxt_no_contact_synthetic.txt").read_text(), headers=TXT)
    assert no_contact["present"] is False and no_contact["state"] == "soft404"


def test_signed_and_expired_security_txt_gives_one_info_finding():
    http = site()
    http.add("GET", f"https://{SITE}/.well-known/security.txt", text=(FX / "securitytxt_signed_expired_synthetic.txt").read_text(), headers=TXT)
    absent(http, "/robots.txt", "/sitemap.xml")
    res = run(http)
    sec = res.attributes["security_txt"]
    assert sec["signed"] is True and sec["expired"] is True
    assert sec["contacts"]["phones"] == ["+55-11-5555-0100"]  # role number: attribute only, never a pivot
    assert not [p for p in res.pivots if p.entity.type.value == "phone"]
    (finding,) = res.findings
    assert finding.title == "security.txt expired" and finding.severity is Severity.INFO


# ---------------------------------------------------------------------------------- sitemaps (c4)


def test_sitemap_index_one_level_and_five_files_at_most():
    http = site()
    absent(http, "/.well-known/security.txt", "/security.txt")
    http.add("GET", f"https://{SITE}/robots.txt", text=f"User-agent: *\nDisallow: /admin/\nSitemap: https://www.{SITE}/sitemap_index.xml\n", headers=TXT)
    http.add("GET", f"https://www.{SITE}/sitemap_index.xml", text=(FX / "sitemap_index_synthetic.xml").read_text(), headers=XML)
    urlset = (FX / "sitemap_urlset_synthetic.xml").read_text()
    for n in range(1, 5):
        http.add("GET", f"https://www.{SITE}/sitemap-{n}.xml", text=urlset, headers=XML)
    res = run(http)
    files = res.attributes["sitemaps"]["files"]
    fetched = [f["url"] for f in files if f["state"] == "present"]
    assert len(fetched) == 5  # the index + 4 children: 5 files in total (P065 c2/c4)
    assert [f["url"] for f in files if f["state"] == "not_fetched"] == [f"https://www.{SITE}/sitemap-{n}.xml" for n in (5, 6, 7)]
    assert "https://sitemaps.example.net/other.xml" not in target_calls(http)  # another site: never fetched
    urls = [p for p in res.pivots if p.relation == "sitemap_url"]
    assert urls and all(p.expand is False for p in urls)
    assert len({p.entity.value for p in urls}) == len(urls)  # deduplicated across files
    assert not any("sitemap-1.xml" in u for u in [p.entity.value for p in urls])


def test_sitemap_pivots_are_capped_at_200():
    many = "<urlset>" + "".join(f"<url><loc>https://{SITE}/p/{i}</loc></url>" for i in range(500)) + "</urlset>"
    parsed = W.parse_sitemap(many, SITE)
    assert len(parsed["urls"]) == 200 and parsed["capped"] is True


def test_xml_bomb_sitemap_is_refused_without_expansion():
    http = site()
    absent(http, "/.well-known/security.txt", "/security.txt", "/robots.txt")
    http.add("GET", f"https://{SITE}/sitemap.xml", text=(FX / "sitemap_xml_bomb_synthetic.xml").read_text(), headers=XML)
    res = run(http)
    (row,) = res.attributes["sitemaps"]["files"]
    assert row["state"] == "refused" and row["reason"] == "xml_dtd_refused"
    assert not [p for p in res.pivots if p.relation == "sitemap_url"]


def test_gzip_bomb_stops_at_the_decompression_cap_quickly():
    started = time.monotonic()
    parsed = W.parse_sitemap((FX / "sitemap_gzip_bomb_synthetic.xml.gz").read_bytes(), SITE)
    assert parsed["ok"] is False and parsed["reason"] == "gzip_bomb"
    assert time.monotonic() - started < 2.0
    ok = W.parse_sitemap((FX / "sitemap_urlset_synthetic.xml.gz").read_bytes(), "www.example.com")
    assert ok["ok"] is True and ok["urls"]


def test_plain_text_and_malformed_sitemaps():
    text = W.parse_sitemap((FX / "sitemap_text_synthetic.txt").read_text(), "www.example.com")
    assert text["kind"] == "text" and text["urls"]
    bad = W.parse_sitemap((FX / "sitemap_malformed_synthetic.xml").read_text(), "www.example.com")
    assert bad["ok"] is False or bad["reason"] == "truncated XML"


# ---------------------------------------------------------------------------------- robots and MTA-STS parsers


def test_robots_soft_404_and_empty():
    assert W.parse_robots((FX / "robots_html_soft404_synthetic.html").read_text())["valid"] is False
    empty = W.parse_robots((FX / "robots_empty_synthetic.txt").read_text())
    assert empty["valid"] is True and empty["disallow"] == []


@pytest.mark.parametrize(("name", "valid", "mode"), [("mta_sts_ok_synthetic.txt", True, "enforce"),
                                                     ("mta_sts_testing_synthetic.txt", True, "testing"),
                                                     ("mta_sts_invalid_synthetic.txt", False, "enforce")])
def test_mta_sts_parser(name, valid, mode):
    parsed = W.parse_mta_sts((FX / name).read_text(), headers=TXT)
    assert parsed["valid"] is valid and parsed["mode"] == mode
    soft = W.parse_mta_sts((FX / "mta_sts_soft404_synthetic.html").read_text(), headers={"content-type": "text/html"})
    assert soft["valid"] is False and soft["state"] == "soft404"
    assert W.mta_sts_mx_matches("*.mail.example.com", "mx1.mail.example.com")
    assert not W.mta_sts_mx_matches("*.mail.example.com", "a.b.mail.example.com")


# ---------------------------------------------------------------------------------- safety


def test_redirects_are_followed_only_inside_the_seed():
    http = site()
    http.add("GET", f"https://{SITE}/.well-known/security.txt", status=301, headers={"location": f"https://www.{SITE}/.well-known/security.txt"})
    http.add("GET", f"https://www.{SITE}/.well-known/security.txt", text=(FX / "securitytxt_ok_recorded.txt").read_text(), headers=TXT)
    http.add("GET", f"https://{SITE}/robots.txt", status=302, headers={"location": "https://evil.example.net/robots.txt"})
    http.add("GET", f"https://{SITE}/sitemap.xml", status=302, headers={"location": "http://10.0.0.5/sitemap.xml"})
    res = run(http)
    assert res.attributes["security_txt"]["state"] == "present"
    assert res.attributes["robots_txt"]["state"] == "refused"
    assert res.attributes["sitemaps"]["files"][0]["state"] == "refused"
    assert not any("evil.example.net" in u or "10.0.0.5" in u for u in target_calls(http))


def test_never_runs_on_a_pivot():
    http = site()
    res = run(http, is_seed=False)
    assert res.status is Status.SKIPPED and res.reason_code == "scope"
    assert target_calls(http) == []


def test_the_light_budget_stops_the_run_partial():
    http = site()
    rt = make_runtime(http)
    rt.http.ceilings.charge("light", SITE, n=24)  # 24 of the 25 LIGHT requests per host of the scan are used
    http.add("GET", f"https://{SITE}/.well-known/security.txt", text=(FX / "securitytxt_ok_recorded.txt").read_text(), headers=TXT)
    res = run(http, runtime=rt)
    assert res.partial is True and res.stop_reason == "request_cap"
    assert res.attributes["security_txt"]["state"] == "present"
    assert target_calls(http) == [f"https://{SITE}/.well-known/security.txt"]


def test_kill_switch_stops_before_any_request():
    http = site()
    rt = make_runtime(http)
    rt.cancel("test kill switch")
    run(http, runtime=rt)
    assert target_calls(http) == []


def test_offline_selftest_and_contract_metadata():
    hc = WellknownFiles.health_check()
    assert hc.offline is True and hc.selftest(None).status == "ok"
    assert WellknownFiles.opsec is Opsec.LIGHT and WellknownFiles.disclosure == "target"
    assert WellknownFiles.default_enabled is False and WellknownFiles.run_on == "seeds" and WellknownFiles.max_rate <= 1.0
