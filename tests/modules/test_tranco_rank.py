"""tranco_rank (P010): local Tranco top-1M list, on-disk index, shared platforms, PSL private suffixes.

Fixtures in tests/fixtures/tranco_rank/: a trimmed slice of the real daily list 947P2 (ranks 1-10 plus
31 selected rows, recorded 2026-11-26) as CSV and zipped like the daily zip (one member top-1m.csv),
the real /top-1m-id answer and a derived challenge page (tranco-list.eu sits behind Cloudflare).
The list is installed through the real dataset manager (FakeHttp serves the zip behind the observed
relative 307 redirect), so the core safe_extract and the refresh-time index build are exercised.
"""

from __future__ import annotations

import inspect
import sqlite3

import pytest

from tests.fakes import FIXTURES, FakeHttp, make_runtime, module_fixture, run_module
from v3lum.core import datasets, policy
from v3lum.core.context import RunInfo, ScanOptions
from v3lum.core.entities import Entity
from v3lum.core.entities import EntityType as T
from v3lum.core.models import Status
from v3lum.modules.domain_dns import tranco_rank as TR
from v3lum.modules.domain_dns.tranco_rank import TrancoRank

ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
DAILY_URL = "https://tranco-list.eu/download/daily/top-1m.csv.zip"
ID_URL = "https://tranco-list.eu/top-1m-id"
SLICE_ZIP = (FIXTURES / "tranco_rank" / "list_slice.zip").read_bytes()


@pytest.fixture()
def slice_floors(monkeypatch):
    """The real floors (5 MB, 900,000 rows, ranks 1..1000 in order) reject the trimmed slice (ranks 1-10
    then selected rows): lower them for the tests."""
    monkeypatch.setattr(TR, "MIN_ROWS", 0)
    monkeypatch.setattr(TR, "CHECK_ROWS", 10)
    monkeypatch.setitem(datasets.DATASETS[TR.LIST_DATASET], "min_bytes", 1)


def tranco_http(*, zip_body: bytes = SLICE_ZIP, list_id: str | None = None) -> FakeHttp:
    http = FakeHttp()
    # observed 2026-11-26: the latest-zip URL answers a relative 307 to the daily zip on the same host
    http.add("GET", ZIP_URL, status=307, redirect_to="/download/daily/top-1m.csv.zip")
    http.add("GET", DAILY_URL, body=zip_body, headers={"content-type": "application/zip"})
    if list_id is not None:
        http.add("GET", ID_URL, body=list_id.encode(), headers={"content-type": "text/plain"})
    return http


def installed_runtime(*, with_id: bool = True):
    """A runtime whose datasets were refreshed like `v3lum data update` does (zip, then the list id)."""
    http = tranco_http(list_id=module_fixture(TrancoRank, "top1m_id.txt") if with_id else None)
    rt = make_runtime(http)
    assert rt.data.update(TR.LIST_DATASET).status == "updated"
    if with_id:
        assert rt.data.update(TR.ID_DATASET).status == "updated"
    return rt, http


def run(rt, entity):
    res = run_module(TrancoRank, entity, runtime=rt)
    assert res.findings == []  # P010 c6: context only, never a finding by itself
    return res


# ------------------------------------------------------------------ metadata (P010 c1, c2, c7)
def test_metadata_offline_open_trusted_dataset_only():
    cls = TrancoRank
    assert (cls.disclosure, cls.hosts, cls.provider) == ("none", (), "")
    assert cls.sources == ("tranco.top1m", "tranco.list_id") and cls.terms == "open"
    assert cls.default_enabled is True and cls.shares_input is False
    assert cls.max_tlp.value_str == "red"  # runs under TLP:RED (disclosure none)
    reg = datasets.DATASETS[TR.LIST_DATASET]
    assert reg["large"] is True and reg["archive"] == "zip" and reg["member"] == "top-1m.csv"
    assert reg["source"] == "tranco.top1m" and reg["terms_class"] == "open"
    assert "NDSS 2019" in reg["attribution"] and "Le Pochat" in reg["attribution"]  # P010 c7
    assert datasets.DATASETS[TR.ID_DATASET]["large"] is False


def test_no_ranks_api_fallback_exists_in_code():
    """P010 c2: the module never builds the ranks API URL; only the list and its id are datasets."""
    source = inspect.getsource(TR)
    assert "api/ranks" not in source and "/api/" not in source


def test_missing_list_is_unavailable_dataset_never_a_download():
    http = FakeHttp()  # no route: any request would fail the test
    res = run_module(TrancoRank, "domain:google.com", http)
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset")
    assert "v3lum data update tranco_rank.top1m" in res.error
    assert http.calls == []


def test_policy_gate_reports_the_missing_large_dataset_before_running():
    rt = make_runtime(FakeHttp())
    pctx = policy.make_context(rt, ScanOptions(), path="scan")
    ent = Entity.make(T.DOMAIN, "google.com")
    decision = policy.decide(TrancoRank, ent, pctx, run=RunInfo(entity=ent, is_seed=True))
    assert (decision.allowed, decision.status, decision.reason_code) == (False, Status.UNAVAILABLE, "dataset")


def test_red_tlp_is_allowed_for_the_offline_lookup(slice_floors):
    rt, _http = installed_runtime()
    pctx = policy.make_context(rt, ScanOptions(tlp="red"), path="scan")
    ent = Entity.make(T.DOMAIN, "google.com")
    assert policy.decide(TrancoRank, ent, pctx, run=RunInfo(entity=ent, is_seed=True, tlp="red")).allowed


# ------------------------------------------------------------------ refresh: safe_extract + on-disk index (P010 c1)
def test_refresh_extracts_validates_and_indexes_on_disk(slice_floors):
    rt, http = installed_runtime()
    assert http.urls()[:2] == [ZIP_URL, DAILY_URL]  # relative 307 followed on the same host
    info = rt.data.info(TR.LIST_DATASET)
    assert info.present and info.sha256
    path = TR.index_path(info.sha256)
    assert path.is_file()  # built at refresh time by the validator, before any lookup
    con = sqlite3.connect(str(path))
    try:
        ddl = con.execute("SELECT sql FROM sqlite_master WHERE name = 'tranco'").fetchone()[0]
        assert "WITHOUT ROWID" in ddl and "PRIMARY KEY" in ddl
        assert con.execute("SELECT rank FROM tranco WHERE domain = 'google.com'").fetchone() == (1,)
        assert con.execute("SELECT count(*) FROM tranco").fetchone() == (41,)
    finally:
        con.close()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_lookups_never_load_the_list_into_memory(slice_floors, monkeypatch):
    """P010 c1: one indexed SELECT per lookup; the CSV is never read during a run."""
    rt, _http = installed_runtime()
    real_open = open

    def guarded_open(file, *a, **kw):
        assert not str(file).endswith(TR.LIST_DATASET), "the list itself must not be read during a lookup"
        return real_open(file, *a, **kw)

    monkeypatch.setattr("builtins.open", guarded_open)
    res = run(rt, "domain:google.com")
    assert res.attributes["tranco_rank"] == 1


def test_index_rebuilt_once_when_missing(slice_floors):
    rt, _http = installed_runtime()
    path = TR.index_path(rt.data.info(TR.LIST_DATASET).sha256)
    path.unlink()
    assert run(rt, "domain:github.com").attributes["tranco_rank"] == 33
    assert path.is_file()


def test_refresh_rejects_a_challenge_page_and_keeps_nothing(slice_floors):
    page = module_fixture(TrancoRank, "challenge_page_derived.html").encode()
    http = FakeHttp().add("GET", ZIP_URL, status=200, body=page, headers={"content-type": "text/html"})
    rt = make_runtime(http)
    result = rt.data.update(TR.LIST_DATASET)
    assert result.status == "failed"
    assert not rt.data.info(TR.LIST_DATASET).present
    res = run_module(TrancoRank, "domain:google.com", runtime=rt)
    assert (res.status, res.reason_code) == (Status.UNAVAILABLE, "dataset")


def test_validator_checks_the_head_and_size(tmp_path, monkeypatch):
    lines = module_fixture(TrancoRank, "list_slice.csv").splitlines()
    assert TR.check_head(lines, min_rows=0, check_rows=10) is None
    assert TR.check_head(lines, min_rows=0, check_rows=11) == "non-monotonic rank at row 11"
    assert "only 41 rows" in TR.check_head(lines, check_rows=10)  # the real floor is 900,000 rows
    assert TR.check_head(["2,google.com"], min_rows=0) == "the first row is not rank 1"
    assert TR.check_head([], min_rows=0) == "empty list"
    page = module_fixture(TrancoRank, "challenge_page_derived.html")
    assert "HTML" in TR.check_head(page.splitlines(), min_rows=0)
    bad = tmp_path / "list.csv"
    bad.write_text("1,google.com\n3,example.com\n", encoding="utf-8")
    monkeypatch.setattr(TR, "MIN_ROWS", 0)
    with pytest.raises(ValueError):
        TR.validate_list(bad)
    ok_id = tmp_path / "id.txt"
    ok_id.write_text("947P2\n", encoding="utf-8")
    assert TR.validate_list_id(ok_id) is True
    ok_id.write_text("<html>nope</html>", encoding="utf-8")
    with pytest.raises(ValueError):
        TR.validate_list_id(ok_id)


# ------------------------------------------------------------------ exact lookup, provenance, display (c2, c3, c6)
def test_exact_registrable_domain_lookup_with_provenance(slice_floors):
    rt, http = installed_runtime()
    calls = len(http.calls)
    res = run(rt, "domain:google.com")
    assert res.status is Status.OK
    assert len(http.calls) == calls  # disclosure none: no request at lookup time
    attrs = res.attributes
    assert attrs["tranco_rank"] == 1 and attrs["tranco_popularity"] == "popular"
    assert attrs["tranco_lookup_domain"] == "google.com"
    assert attrs["tranco_context"] == "Tranco #1 - popular (list 947P2, 2026-11-25)"
    listing = attrs["tranco_list"]
    assert listing["list_id"] == "947P2" and listing["list_date"] == "2026-11-25"
    assert listing["sha256"] == rt.data.info(TR.LIST_DATASET).sha256
    assert attrs["tranco_dampener"]["dampen"] is True and attrs["tranco_dampener"]["factor"] == 0.6
    assert res.raw["provenance"]["list_id"] == "947P2" and "NDSS 2019" in res.raw["citation"]
    assert {d["name"] for d in res.datasets} >= {TR.LIST_DATASET, TR.ID_DATASET}
    assert "known_good" not in str(res.to_dict()) and not any(f.tags for f in res.findings)  # c3: never an allow-list


def test_rank_bands_and_long_tail_never_dampen(slice_floors):
    rt, _http = installed_runtime()
    established = run(rt, "domain:registro.br").attributes
    assert established["tranco_rank"] == 25132 and established["tranco_popularity"] == "established"
    assert established["tranco_dampener"]["factor"] == 0.8
    tail = run(rt, "domain:foot24.st").attributes
    assert tail["tranco_popularity"] == "long tail" and tail["tranco_dampener"] == {
        "dampen": False, "factor": 1.0, "reason": "long_tail", "scope": "domain"}
    assert tail["tranco_context"].startswith("Tranco #1,000,000 - long tail")


def test_not_in_top_1m_is_context_only(slice_floors):
    rt, _http = installed_runtime()
    res = run(rt, "domain:unranked-shop.example")
    assert res.status is Status.OK and res.findings == []
    assert "tranco_rank" not in res.attributes
    assert res.attributes["tranco_popularity"] == "not in top 1M"
    assert res.attributes["tranco_context"] == "not in top 1M (list 947P2, 2026-11-25)"
    assert res.attributes["tranco_dampener"]["reason"] == "not_ranked"


def test_subdomain_shows_the_parent_rank_but_is_never_dampened(slice_floors):
    rt, _http = installed_runtime()
    attrs = run(rt, "domain:mail.github.com").attributes
    assert attrs["tranco_rank"] == 33 and attrs["tranco_lookup_domain"] == "github.com"
    assert "via github.com" in attrs["tranco_context"]
    assert attrs["tranco_dampener"]["dampen"] is False and attrs["tranco_dampener"]["reason"] == "subdomain_of_ranked_domain"


# ------------------------------------------------------------------ c4: shared platforms, c8 phishing URL
def test_phishing_url_on_a_top_shared_platform_keeps_its_full_score(slice_floors):
    """P010 c8: sites.google.com shows google.com's rank but a URL there is never dampened."""
    rt, _http = installed_runtime()
    url = run(rt, "url:https://sites.google.com/view/secure-login-update/home").attributes
    assert url["tranco_rank"] == 1 and url["shared_platform"] == {"platform": "sites.google.com", "category": "site_builders"}
    assert url["tranco_dampener"] == {"dampen": False, "factor": 1.0, "reason": "url_level_verdict", "scope": "domain"}
    host = run(rt, "domain:sites.google.com").attributes
    assert host["tranco_dampener"]["reason"] == "shared_platform" and host["tranco_dampener"]["dampen"] is False
    assert "shared platform sites.google.com" in host["tranco_context"]
    for platform in ("forms.gle", "1drv.ms", "dropbox.com", "sharepoint.com", "bit.ly", "duckdns.org"):
        attrs = run(rt, f"domain:{platform}").attributes
        assert attrs["tranco_dampener"] == {"dampen": False, "factor": 1.0, "reason": "shared_platform", "scope": "domain"}, platform
        assert attrs["tranco_rank"] > 0  # the rank is still shown


def test_shared_platform_list_ships_the_condition_hosts():
    data = TR.load_shared_platforms(datasets.DataStore.bundled_json("shared_platforms.json"))
    for host in ("sharepoint.com", "onedrive.live.com", "1drv.ms", "sites.google.com", "docs.google.com", "drive.google.com",
                 "forms.gle", "storage.googleapis.com", "s3.amazonaws.com", "blob.core.windows.net", "dropbox.com",
                 "notion.site", "forms.office.com", "000webhostapp.com", "duckdns.org", "bit.ly"):
        assert host in data, host
    assert TR.shared_platform("tenant.sharepoint.com", data) == {"platform": "sharepoint.com", "category": "file_sharing"}
    assert TR.shared_platform("notsharepoint.com", data) is None  # label boundary, never a string suffix


# ------------------------------------------------------------------ c5: PSL private suffixes
def test_psl_private_suffix_host_is_ranked_per_registrable_domain(slice_floors):
    """evil.github.io is looked up as evil.github.io, never by github.io's rank (#129)."""
    rt, _http = installed_runtime()
    attrs = run(rt, "domain:evil.github.io").attributes
    assert attrs["tranco_lookup_domain"] == "evil.github.io" and "tranco_rank" not in attrs
    assert attrs["tranco_popularity"] == "not in top 1M"
    for host in ("phish.pages.dev", "login.web.app", "x.workers.dev", "a.netlify.app", "b.vercel.app", "c.firebaseapp.com"):
        res = run(rt, f"domain:{host}").attributes
        assert res["tranco_lookup_domain"] == host and "tranco_rank" not in res, host
    platform = run(rt, "domain:github.io").attributes
    assert platform["tranco_rank"] == 129 and "public suffix github.io itself" in platform["tranco_context"]
    assert platform["tranco_dampener"]["dampen"] is False


def test_ip_urls_and_single_labels_are_not_applicable(slice_floors):
    rt, _http = installed_runtime()
    res = run_module(TrancoRank, "url:http://203.0.113.5/login", runtime=rt)
    assert (res.status, res.reason_code) == (Status.SKIPPED, "not_applicable")


def test_missing_list_id_keeps_the_rank_without_an_invented_id(slice_floors):
    rt, _http = installed_runtime(with_id=False)
    attrs = run(rt, "domain:microsoft.com").attributes
    assert attrs["tranco_rank"] == 8
    assert "list_id" not in attrs["tranco_list"] and attrs["tranco_list"]["list_date"] == "2026-11-25"
    assert attrs["tranco_context"] == "Tranco #8 - popular (2026-11-25)"


def test_list_date_follows_the_daily_publication_time():
    assert TR.list_date_of("2026-11-26T05:57:46Z") == "2026-11-25"
    assert TR.list_date_of("2026-11-25T23:10:00+00:00") == "2026-11-25"
    assert TR.list_date_of("2026-11-25T22:05:00+00:00") == "2026-11-24"  # the new list may not be out yet
    assert TR.list_date_of("garbage") == ""


# ------------------------------------------------------------------ AR21 golden-path routes (section 19)
def test_acceptance_routes_are_empty_for_the_offline_lookup(slice_floors):
    """tests/fixtures/acceptance/{domain,url}/tranco_rank.json hold no route: disclosure 'none', the lookup is
    local (the list is installed by `v3lum data update`, never during a scan)."""
    from tests.fakes import fixture

    rt, http = installed_runtime()
    calls = len(http.calls)
    for etype, value in (("domain", "example.com"), ("url", "https://example.com/")):
        doc = fixture(f"acceptance/{etype}/tranco_rank.json")
        assert (doc["schema"], doc["module"], doc["routes"]) == ("v3lum.acceptance_routes/1", "tranco_rank", [])
        res = run(rt, f"{etype}:{value}")
        assert res.status is Status.OK and res.attributes["tranco_lookup_domain"] == "example.com"
    assert len(http.calls) == calls
