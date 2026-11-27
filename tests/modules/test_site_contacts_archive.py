"""site_contacts_archive (P077, PASSIVE): offline tests.

Fixtures in tests/fixtures/site_contacts_archive/: the real Wayback availability answers of the P059 web_archives
fixtures (``wayback_available_ok.json`` / ``_empty.json``) and the synthetic home/contact pages of
tests/fixtures/site_contacts/ served as archived ``id_`` snapshots (documentation values only).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from tests.fakes import FakeHttp, module_fixture, run_module
from v3lum.core.models import Opsec, Status
from v3lum.modules.url_web.site_contacts import SiteContactsArchive

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "site_contacts_archive"
AVAIL = "https://archive.org/wayback/available?" + urlencode({"url": "http://example.com/"})
TS = "20261126034206"
MINIMAL = "<html><head><title>Example</title></head><body><p>Texto.</p></body></html>"


def snap(url: str) -> str:
    return f"https://web.archive.org/web/{TS}id_/{url}"


def fx(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def archive(http: FakeHttp) -> None:
    http.add("GET", AVAIL, json=module_fixture(SiteContactsArchive, "wayback_available_ok.json"))
    http.add("GET", snap("https://example.com/"), text=fx("archived_home_synthetic.html"))
    http.add("GET", snap("https://example.com/sobre-nos"), status=404, text="not archived")
    http.add("GET", snap("https://example.com/institucional/quem-somos"), text=MINIMAL)
    http.add("GET", snap("https://example.com/contato"), text=fx("archived_contato_synthetic.html"))
    http.add("GET", snap("https://example.com/politica-de-privacidade"), text=MINIMAL)


def test_metadata_passive_opt_in():
    cls = SiteContactsArchive
    assert cls.opsec is Opsec.PASSIVE and cls.disclosure == "third_party" and cls.default_enabled is False
    assert cls.hosts == ("archive.org", "web.archive.org") and cls.terms == "open"


def test_archived_pages_give_role_contacts_and_count_personal_ones():
    http = FakeHttp()
    archive(http)
    res = run_module(SiteContactsArchive, "domain:example.com", http)
    assert res.status is Status.OK, res.error
    emails = {e["address"] for e in res.attributes["site_contacts"]["emails"]}
    assert {"contato@example.com", "sac@example.com", "dpo@example.com"} <= emails
    assert res.attributes["third_party_counts"]["personal_emails"] == 1
    assert "fulana" not in json.dumps(res.attributes, ensure_ascii=False) + json.dumps(res.raw, ensure_ascii=False, default=str)
    assert all(p.expand is False for p in res.pivots)
    summary = res.attributes["crawl_summary"]
    assert summary["pages_fetched"] <= 5 and "https://example.com/contato" in summary["pages"]
    # no target contact: only the archive hosts, at most 5 archived pages + the availability lookup
    http.assert_hosts_within(SiteContactsArchive)
    assert len(http.calls) <= SiteContactsArchive.max_requests
    assert not [c for c in http.calls if c["url"].startswith("https://example.com")]


def test_no_capture_is_empty():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(SiteContactsArchive, "wayback_available_empty.json"))
    assert run_module(SiteContactsArchive, "domain:example.com", http).status is Status.EMPTY


def test_429_and_error_in_200():
    http = FakeHttp()
    http.add("GET", AVAIL, status=429, text="slow down")
    assert run_module(SiteContactsArchive, "domain:example.com", http).status is Status.RATE_LIMITED
    http2 = FakeHttp()
    http2.add("GET", AVAIL, text="Error: no url parameter", headers={"content-type": "text/plain"})
    assert run_module(SiteContactsArchive, "domain:example.com", http2).status is Status.ERROR


def test_archive_5xx_on_the_home_snapshot_is_could_not_verify():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(SiteContactsArchive, "wayback_available_ok.json"))
    http.add("GET", snap("https://example.com/"), status=503, text="busy")
    res = run_module(SiteContactsArchive, "domain:example.com", http)
    assert res.status is Status.ERROR


def test_archived_home_error_or_block_page_is_could_not_verify_not_empty():
    zscaler = (Path(__file__).resolve().parents[1] / "fixtures" / "web_fingerprint" / "corporate_block_zscaler_synthetic.html").read_text(encoding="utf-8")
    for status, body in ((404, "not archived"), (200, zscaler), (403, "<html><title>Forbidden</title></html>")):
        http = FakeHttp()
        http.add("GET", AVAIL, json=module_fixture(SiteContactsArchive, "wayback_available_ok.json"))
        http.add("GET", snap("https://example.com/"), status=status, text=body)
        res = run_module(SiteContactsArchive, "domain:example.com", http)
        assert res.status in (Status.ERROR, Status.BLOCKED), (status, res.status, res.error)


def test_archived_non_html_home_is_empty():
    http = FakeHttp()
    http.add("GET", AVAIL, json=module_fixture(SiteContactsArchive, "wayback_available_ok.json"))
    http.add("GET", snap("https://example.com/"), json={"api": "v1"})
    res = run_module(SiteContactsArchive, "domain:example.com", http)
    assert res.status is Status.EMPTY
